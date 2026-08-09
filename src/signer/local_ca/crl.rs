//! The revocation ledger and the CRL built from it.
//!
//! Separated from issuance because the two share only the
//! `Issuer<'static, CaSigningKey>` they sign with. The durable form of what
//! this CA has revoked is a JSON sidecar next to `crl_path` — never the CRL's
//! own DER round-tripped back, which would make a parser bug into data loss.

use std::fs;
use std::path::PathBuf;

use rcgen::{
    CertificateRevocationListParams, Issuer, KeyIdMethod, RevocationReason, RevokedCertParams,
    SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::CLOCK_SKEW_ALLOWANCE;
use super::key::CaSigningKey;

#[derive(Clone)]
pub(super) struct CrlPaths {
    pub(super) crl_path: PathBuf,
    pub(super) revoked_path: PathBuf,
}

/// The durable source of truth for what this CA has revoked, plus a cached
/// copy of the current signed CRL derived from it. `entries` is what gets
/// persisted/reloaded (see [`init_ledger`]); `crl_der` is rebuilt fresh from
/// `entries` on every change and on every startup, never itself parsed back.
pub(super) struct RevokedLedger {
    pub(super) entries: Vec<RevokedEntry>,
    pub(super) crl_der: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct RevokedEntry {
    pub(super) serial_hex: String,
    /// Unix seconds.
    pub(super) revoked_at: i64,
    pub(super) reason: Option<u32>,
}

/// How long a generated CRL claims to remain current (RFC 5280's `nextUpdate`).
/// Regenerated fresh on every revocation and on every startup, so this is a
/// ceiling on staleness, not a promise a client actually waits out.
const CRL_VALIDITY_DAYS: i64 = 7;

/// Builds a signed CRL from the ledger `entries`. Shared by initial
/// generation (empty, at construction) and every subsequent revocation.
pub(super) fn build_crl(
    entries: &[RevokedEntry],
    issuer: &Issuer<'static, CaSigningKey>,
) -> anyhow::Result<rcgen::CertificateRevocationList> {
    // A serial that is not hex can only come from the JSON ledger sidecar on
    // disk, which is an operator-editable file. This used to `expect`, which
    // meant a corrupted or hand-edited ledger panicked — and not only at
    // startup: `revoke` calls this too, so it was a panic in a request task,
    // taking the `Mutex` poisoned with it and turning every later `GET /crl`
    // into a panic of its own. Naming the bad entry is something an operator
    // can act on.
    let revoked_certs = entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let serial = hex::decode(&e.serial_hex).map_err(|error| {
                anyhow::anyhow!(
                    "revoked ledger entry {index}: serial `{}` is not hex: {error}",
                    e.serial_hex
                )
            })?;
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&serial),
                revocation_time: OffsetDateTime::from_unix_timestamp(e.revoked_at)
                    .unwrap_or_else(|_| OffsetDateTime::now_utc()),
                reason_code: e.reason.and_then(reason_from_u32),
                invalidity_date: None,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let now = OffsetDateTime::now_utc();
    CertificateRevocationListParams {
        this_update: now - CLOCK_SKEW_ALLOWANCE,
        next_update: now + Duration::days(CRL_VALIDITY_DAYS),
        crl_number: SerialNumber::from(entries.len() as u64 + 1),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .map_err(Into::into)
}

/// Maps an RFC 5280 §5.3.1 `CRLReason` code to rcgen's enum. `post_revoke_cert`/
/// `admin::revoke_order` already validate against
/// [`crate::cert::ALLOWED_REVOCATION_REASONS`] before a reason ever reaches
/// here, so `None` (an unrecognized code) should not occur in practice; it is
/// treated as "no reason recorded" rather than a hard error, since refusing to
/// revoke a certificate over a cosmetic reason-code mismatch would be worse.
pub(super) fn reason_from_u32(code: u32) -> Option<RevocationReason> {
    match code {
        0 => Some(RevocationReason::Unspecified),
        1 => Some(RevocationReason::KeyCompromise),
        2 => Some(RevocationReason::CaCompromise),
        3 => Some(RevocationReason::AffiliationChanged),
        4 => Some(RevocationReason::Superseded),
        5 => Some(RevocationReason::CessationOfOperation),
        6 => Some(RevocationReason::CertificateHold),
        8 => Some(RevocationReason::RemoveFromCrl),
        9 => Some(RevocationReason::PrivilegeWithdrawn),
        10 => Some(RevocationReason::AaCompromise),
        _ => None,
    }
}

/// Loads the revoked-certificate ledger from `paths` (if given and its
/// sidecar file exists) — else starts empty — and builds the matching signed
/// CRL. Shared by [`LocalCa::load_or_generate`] and
/// [`LocalCa::generate_in_memory`], mirroring the existing `generate_ca`
/// shared-helper pattern.
pub(super) fn init_ledger(
    paths: Option<&CrlPaths>,
    issuer: &Issuer<'static, CaSigningKey>,
) -> anyhow::Result<RevokedLedger> {
    let entries: Vec<RevokedEntry> = match paths {
        Some(p) if p.revoked_path.exists() => {
            serde_json::from_str(&fs::read_to_string(&p.revoked_path)?)?
        }
        _ => Vec::new(),
    };

    let crl = build_crl(&entries, issuer)?;
    if let Some(p) = paths {
        // Rewritten on every startup too, so `thisUpdate`/`nextUpdate` never
        // go stale after a long-idle restart even with no new revocation.
        fs::write(&p.crl_path, crl.pem()?)?;
    }
    Ok(RevokedLedger {
        entries,
        crl_der: crl.der().to_vec(),
    })
}
