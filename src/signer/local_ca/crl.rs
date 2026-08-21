//! The revocation ledger and the CRL built from it.
//!
//! Separated from issuance because the two share only the
//! `Issuer<'static, CaSigningKey>` they sign with. The durable form of what
//! this CA has revoked is a JSON sidecar next to `crl_path` — never the CRL's
//! own DER round-tripped back, which would make a parser bug into data loss.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use rcgen::{
    CertificateRevocationListParams, Issuer, KeyIdMethod, RevocationReason, RevokedCertParams,
    SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::info;

use super::CLOCK_SKEW_ALLOWANCE;
use super::key::CaSigningKey;
use crate::signer::{CrlPruner, SignerError};

#[derive(Clone)]
pub(super) struct CrlPaths {
    pub(super) crl_path: PathBuf,
    pub(super) revoked_path: PathBuf,
}

impl CrlPaths {
    /// The [`CarriedState`](crate::signer::CarriedState) key this CA's ledger
    /// lives under.
    ///
    /// Keyed on `crl_path` and defined once here rather than spelled out at the
    /// two call sites, because the two spellings agreeing is the entire
    /// correctness of the handover: a rebuilt CA that looked under a key nobody
    /// wrote would silently start from the sidecar and lose whatever the
    /// outgoing instance revoked while the reload was building.
    pub(super) fn state_key(&self) -> String {
        format!("local_ca.ledger:{}", self.crl_path.display())
    }
}

/// The durable source of truth for what this CA has revoked, plus a cached
/// copy of the current signed CRL derived from it. `entries` and `crl_number`
/// are what get persisted/reloaded (see [`init_ledger`]); `crl_der` is rebuilt
/// fresh from them on every change and on every startup, never itself parsed
/// back.
pub(super) struct RevokedLedger {
    pub(super) entries: Vec<RevokedEntry>,
    /// The number the *last* CRL was signed with. Bumped by
    /// [`RevokedLedger::next_crl_number`] before every build, and durable, so
    /// the sequence survives a restart — see [`Sidecar`].
    pub(super) crl_number: u64,
    pub(super) crl_der: Vec<u8>,
}

impl RevokedLedger {
    /// Claims the next CRL number.
    ///
    /// **Every build takes one, and every build persists it.** RFC 5280 §5.2.3
    /// requires `crlNumber` to increase monotonically, and a client that meets a
    /// lower one than it has cached treats the new CRL as the older of the two —
    /// i.e. it keeps trusting a certificate this CA has since revoked. Skipping
    /// numbers is legal and happens whenever a persist fails between the bump
    /// and the write; going backwards is not, which is why this is a durable
    /// counter rather than anything derived from `entries.len()`.
    pub(super) fn next_crl_number(&mut self) -> u64 {
        self.crl_number += 1;
        self.crl_number
    }

    /// The bytes to persist beside the CRL, for the current state.
    pub(super) fn sidecar_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&SidecarRef {
            version: SIDECAR_VERSION,
            crl_number: self.crl_number,
            entries: &self.entries,
        })
    }
}

/// The ledger, the key that signs CRLs over it, and where both are persisted —
/// everything the write path needs and nothing else.
///
/// Split out of `LocalCa` so it can be handed to the periodic sweep as an
/// `Arc<dyn CrlPruner>`: [`SignerBackend::crl_pruner`](crate::signer::SignerBackend::crl_pruner)
/// takes `&self` and so cannot produce an `Arc<LocalCa>`, and a `Weak` back-reference
/// to make it able to would be a cycle to maintain for one caller. `LocalCa` holds
/// one of these and reaches its ledger through it.
pub(super) struct LedgerStore {
    /// An `Arc` rather than a plain `Mutex` because this exact cell is what
    /// `SignerBackend::carried_state` hands to the CA that replaces this one on
    /// a reload — see the note on `LocalCa::assemble`.
    pub(super) revoked: Arc<Mutex<RevokedLedger>>,
    issuer: Arc<Issuer<'static, CaSigningKey>>,
    paths: Option<CrlPaths>,
}

impl LedgerStore {
    pub(super) fn new(
        revoked: Arc<Mutex<RevokedLedger>>,
        issuer: Arc<Issuer<'static, CaSigningKey>>,
        paths: Option<CrlPaths>,
    ) -> Self {
        Self {
            revoked,
            issuer,
            paths,
        }
    }

    /// Signs a fresh CRL over `ledger`'s current entries and persists both it
    /// and the sidecar, then updates the served copy.
    ///
    /// Extracted from `LocalCa::revoke`, which was the only caller until the
    /// periodic prune needed the identical sequence minus the append. The
    /// caller holds the ledger's `tokio::sync::Mutex` guard across this, which
    /// is what makes the whole read-modify-write-persist one critical section.
    pub(super) async fn rebuild_and_persist(
        &self,
        ledger: &mut RevokedLedger,
    ) -> Result<(), SignerError> {
        let number = ledger.next_crl_number();
        let ledger_json = ledger
            .sidecar_json()
            .map_err(|error| SignerError::Internal(error.to_string()))?;
        // Cloned rather than borrowed: the closure below outlives this scope as
        // far as the compiler is concerned, and a ledger is a handful of short
        // strings — nothing next to signing a CRL.
        let entries = ledger.entries.clone();
        let issuer = self.issuer.clone();
        let paths = self.paths.clone();

        // Signing the CRL and the two file writes, all off the runtime worker.
        //
        // The writes were already here; `build_crl` was not, and it is the part
        // that signs — with a PKCS#11 key that is a token round trip, which has
        // no business happening on a thread expected to poll every other
        // connection meanwhile. The file writes are short, but they are still
        // blocking syscalls.
        let crl_der = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let crl = build_crl(&entries, number, &issuer)?;
            let crl_der = crl.der().to_vec();

            if let Some(paths) = &paths {
                let crl_pem = crl.pem()?;
                // The ledger before the CRL: the ledger is the authoritative
                // record and the CRL is derived from it at every startup, so a
                // crash between the two loses nothing.
                //
                // `0600` on the ledger — it decides what the CRL says, and it
                // is not public material the way the CRL itself is.
                crate::pemfile::write_atomic(&paths.revoked_path, ledger_json.as_bytes(), 0o600)?;
                crate::pemfile::write_atomic(&paths.crl_path, crl_pem.as_bytes(), 0o644)?;
            }
            Ok(crl_der)
        })
        .await
        .map_err(|error| SignerError::Internal(format!("revocation persist panicked: {error}")))?
        .map_err(|error| SignerError::Internal(error.to_string()))?;

        // Only after the write succeeded: a revocation this process believes in
        // but never persisted would vanish at the next restart, and the caller
        // reporting an error while having already updated the served CRL is the
        // more confusing half of that.
        ledger.crl_der = crl_der;
        Ok(())
    }
}

#[async_trait]
impl CrlPruner for LedgerStore {
    fn state_key(&self) -> String {
        self.paths.as_ref().map_or_else(
            || "local_ca.ledger:<memory>".to_string(),
            CrlPaths::state_key,
        )
    }

    /// Drops expired entries and re-signs the CRL if any went. See
    /// [`prune_expired`] for which entries go.
    ///
    /// **Returns early when nothing was pruned**, which is the common case and
    /// is why it is worth checking: rebuilding regardless would advance
    /// `crl_number` and rewrite two files every single day on a CA that has
    /// revoked nothing.
    async fn prune_expired(&self) -> Result<usize, SignerError> {
        let mut ledger = self.revoked.lock().await;
        // Kept so a failed persist can put them back. Dropping entries in
        // memory while the sidecar and the served CRL still list them would
        // leave this CA disagreeing with itself about what it has revoked
        // until something else happened to trigger a successful rebuild —
        // and *fewer* revocations in memory is the unsafe direction of that
        // disagreement.
        let before = ledger.entries.clone();
        let removed = prune_expired(&mut ledger.entries, OffsetDateTime::now_utc());
        if removed == 0 {
            return Ok(0);
        }
        if let Err(error) = self.rebuild_and_persist(&mut ledger).await {
            ledger.entries = before;
            return Err(error);
        }
        Ok(removed)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct RevokedEntry {
    pub(super) serial_hex: String,
    /// Unix seconds.
    pub(super) revoked_at: i64,
    pub(super) reason: Option<u32>,
    /// The revoked certificate's own `notAfter`, in unix seconds — what lets
    /// [`prune_expired`] drop the entry once RFC 5280 §3.3 permits it.
    ///
    /// `None` on an entry loaded from a v1 sidecar, and on one whose DER would
    /// not parse at revocation time. **An unknown expiry is never treated as an
    /// expired one**, so such an entry stays on the CRL for ever; that is the
    /// safe direction, and it is why this is an `Option` rather than a `0`
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) not_after: Option<i64>,
}

/// The version this build writes. v1 was a bare top-level array of
/// [`RevokedEntry`] with no envelope, no counter and no expiries; see
/// [`load_sidecar`], which still reads it.
const SIDECAR_VERSION: u32 = 2;

/// The persisted form of a [`RevokedLedger`], as it is read back.
#[derive(Deserialize)]
struct Sidecar {
    /// Read but not acted on: an older binary meeting a newer file should fail
    /// on the fields it cannot understand rather than on a number, and a newer
    /// one has nothing yet to branch on. It exists so the *next* format change
    /// has something to dispatch over besides the shape of the JSON.
    #[allow(dead_code)]
    version: u32,
    crl_number: u64,
    entries: Vec<RevokedEntry>,
}

/// The same, as it is written. Borrowed rather than owned so persisting does
/// not clone the whole ledger.
#[derive(Serialize)]
struct SidecarRef<'a> {
    version: u32,
    crl_number: u64,
    entries: &'a [RevokedEntry],
}

/// How long a generated CRL claims to remain current (RFC 5280's `nextUpdate`).
/// Regenerated fresh on every revocation and on every startup, so this is a
/// ceiling on staleness, not a promise a client actually waits out.
const CRL_VALIDITY_DAYS: i64 = 7;

/// Builds a signed CRL from the ledger `entries`, numbered `crl_number`.
/// Shared by initial generation (empty, at construction), every subsequent
/// revocation, and the periodic prune.
pub(super) fn build_crl(
    entries: &[RevokedEntry],
    crl_number: u64,
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
        crl_number: SerialNumber::from(crl_number),
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

/// Drops every entry whose certificate has already expired, returning how many
/// went. RFC 5280 §3.3: an entry MAY be removed once the certificate itself is
/// past its own `notAfter`, since nothing can present it any more — which is
/// what stops this ledger, and the CRL every relying party downloads from it,
/// growing for the life of the deployment.
///
/// Two rules, both load-bearing:
///
/// - **An entry with no `not_after` is never dropped.** That is a v1 sidecar's
///   entry, or one whose certificate would not parse at revocation time, and an
///   *unknown* expiry is not an expired one.
/// - **The cutoff is backdated by [`CLOCK_SKEW_ALLOWANCE`]**, the same
///   allowance issuance already grants. A relying party whose clock is behind
///   ours still considers the certificate valid for a little longer, and
///   dropping the entry the instant we think it expired is exactly the window
///   in which it would accept a certificate this CA revoked.
pub(super) fn prune_expired(entries: &mut Vec<RevokedEntry>, now: OffsetDateTime) -> usize {
    let cutoff = (now - CLOCK_SKEW_ALLOWANCE).unix_timestamp();
    let before = entries.len();
    entries.retain(|entry| match entry.not_after {
        Some(not_after) => not_after >= cutoff,
        None => true,
    });
    before - entries.len()
}

/// Reads the sidecar, in either format it has ever had.
///
/// Dispatch is on the **shape of the JSON** rather than through
/// `#[serde(untagged)]`: an untagged enum collapses every field-level error into
/// one "did not match any variant", and this file is operator-editable — the
/// same reason [`build_crl`] names the offending entry instead of `expect`ing.
fn load_sidecar(path: &Path) -> anyhow::Result<(Vec<RevokedEntry>, u64)> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if value.is_array() {
        // v1: a bare array, no envelope and no counter. The highest number that
        // format could ever have emitted was `entries.len() + 1`, so starting
        // there — and bumping before the first build, as every build does —
        // puts the first v2 CRL strictly above the last v1 one. Monotonicity
        // has to hold across the upgrade too, not only after it.
        let entries: Vec<RevokedEntry> = serde_json::from_value(value)?;
        let crl_number = entries.len() as u64 + 1;
        return Ok((entries, crl_number));
    }
    let sidecar: Sidecar = serde_json::from_value(value)?;
    Ok((sidecar.entries, sidecar.crl_number))
}

/// Loads the revoked-certificate ledger from `paths` (if given and its
/// sidecar file exists) — else starts empty — prunes what has expired, and
/// builds the matching signed CRL. Shared by [`LocalCa::load_or_generate`] and
/// [`LocalCa::generate_in_memory`], mirroring the existing `generate_ca`
/// shared-helper pattern.
///
/// Unlike its previous form this **writes the sidecar as well as the CRL**: the
/// counter it just advanced is only durable if it is written down, and the
/// prune above may have changed the entries. The CRL write was already here, so
/// this is no new class of startup failure.
pub(super) fn init_ledger(
    paths: Option<&CrlPaths>,
    issuer: &Issuer<'static, CaSigningKey>,
) -> anyhow::Result<RevokedLedger> {
    let (entries, crl_number) = match paths {
        Some(p) if p.revoked_path.exists() => load_sidecar(&p.revoked_path)?,
        _ => (Vec::new(), 0),
    };

    let mut ledger = RevokedLedger {
        entries,
        crl_number,
        crl_der: Vec::new(),
    };
    let removed = prune_expired(&mut ledger.entries, OffsetDateTime::now_utc());
    if removed > 0 {
        info!(
            event = "local_ca_crl_pruned",
            outcome = "success",
            rows_removed = removed,
            "dropped revocation entries whose certificates have expired"
        );
    }

    // Rewritten on every startup, so `thisUpdate`/`nextUpdate` never go stale
    // after a long-idle restart even with no new revocation.
    let number = ledger.next_crl_number();
    let crl = build_crl(&ledger.entries, number, issuer)?;
    if let Some(p) = paths {
        // The ledger before the CRL, and each at the permissions `revoke`
        // writes them with — see the ordering note there.
        crate::pemfile::write_atomic(&p.revoked_path, ledger.sidecar_json()?.as_bytes(), 0o600)?;
        crate::pemfile::write_atomic(&p.crl_path, crl.pem()?.as_bytes(), 0o644)?;
    }
    ledger.crl_der = crl.der().to_vec();
    Ok(ledger)
}
