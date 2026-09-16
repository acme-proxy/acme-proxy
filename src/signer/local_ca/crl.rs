//! The revocation ledger and the CRL built from it.
//!
//! Separated from issuance because the two share only the
//! `Issuer<'static, CaSigningKey>` they sign with. The durable form of what
//! this CA has revoked is a JSON sidecar next to `crl_path` — never the CRL's
//! own DER round-tripped back, which would make a parser bug into data loss.
//!
//! **More than one process writes these files.** `acme-proxy order revoke`
//! builds its own `LocalCa` over the same paths a running `serve` holds, each
//! with its own in-memory ledger. Every write therefore happens under an
//! exclusive lock on a third file beside the other two, and re-reads the
//! sidecar first, merging what the other instance persisted into its own copy
//! before changing anything. Without that, the server's next revocation or
//! prune rewrote both files from memory: the CLI's serial silently left the
//! CRL, and the server published a `crl_number` *lower* than the CLI's.
//!
//! What this does not fix is the CRL a running server *serves*, which is
//! still its in-memory copy until its own next write — the next revocation,
//! the daily prune, or a restart. Moving the ledger into the database is what
//! closes that.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
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
    /// Held exclusively across every read-merge-write of the other two.
    ///
    /// A file of its own rather than a lock on the sidecar: `write_atomic`
    /// renames a new inode over `revoked_path`, so a lock taken on the sidecar
    /// guards an inode that is gone after the first write, and the next
    /// process opens the replacement and locks it without waiting. Nothing is
    /// ever written to this one, so it is never replaced.
    pub(super) lock_path: PathBuf,
}

impl CrlPaths {
    /// The three files one CA's revocation state spans, all derived from
    /// `crl_path`: the CRL (`ca.crl`), its ledger (`ca.json`) and the lock
    /// serialising writers of both (`ca.json.lock`).
    pub(super) fn beside(crl_path: &str) -> Self {
        let crl_path = PathBuf::from(crl_path);
        Self {
            revoked_path: crl_path.with_extension("json"),
            lock_path: crl_path.with_extension("json.lock"),
            crl_path,
        }
    }

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
}

/// The bytes to persist beside the CRL, for `entries` numbered `crl_number`.
fn sidecar_json(entries: &[RevokedEntry], crl_number: u64) -> Result<String, serde_json::Error> {
    serde_json::to_string(&SidecarRef {
        version: SIDECAR_VERSION,
        crl_number,
        entries,
    })
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

    /// Applies `mutate` to the ledger as persisted *now*, and re-signs and
    /// persists the CRL if anything changed. Returns what `mutate` returned —
    /// the number of entries it added or removed.
    ///
    /// One pass, under the lock file for its whole length:
    ///
    /// 1. re-read the sidecar and [`merge`] it into a copy of this instance's
    ///    entries, taking the larger `crl_number` of the two;
    /// 2. run `mutate` over the merged copy;
    /// 3. if neither step changed anything, stop — no signature, no write;
    /// 4. otherwise bump the number, sign, write the sidecar, write the CRL.
    ///
    /// **The in-memory ledger is replaced only once all of that succeeded.**
    /// A failure leaves it exactly as it was, so there is nothing to roll back
    /// — the way this used to be written pushed a revocation into memory before
    /// persisting it, and a failed persist then made the retry an in-memory
    /// "already revoked" that never reached the disk.
    ///
    /// The caller holds the ledger's `tokio::sync::Mutex` guard across this,
    /// which serialises this instance's own callers; the lock file serialises
    /// every other instance, in this process or another (a `flock` belongs to
    /// the open file, so two opens in one process exclude each other too).
    /// Always taken in that order.
    pub(super) async fn update<F>(
        &self,
        ledger: &mut RevokedLedger,
        mutate: F,
    ) -> Result<usize, SignerError>
    where
        F: FnOnce(&mut Vec<RevokedEntry>) -> usize + Send + 'static,
    {
        // Cloned rather than borrowed: the closure below outlives this scope as
        // far as the compiler is concerned, and a ledger is a handful of short
        // strings — nothing next to signing a CRL.
        let mut entries = ledger.entries.clone();
        let mut crl_number = ledger.crl_number;
        let issuer = self.issuer.clone();
        let paths = self.paths.clone();

        // The lock, the read, signing the CRL and the two file writes, all off
        // the runtime worker. Signing with a PKCS#11 key is a token round trip,
        // and waiting on the lock can take as long as another process's own
        // signature; neither has any business on a thread expected to poll
        // every other connection meanwhile.
        let pass = tokio::task::spawn_blocking(move || -> anyhow::Result<Pass> {
            // Released when this closure returns, i.e. after both writes.
            let _lock = paths
                .as_ref()
                .map(|paths| lock_ledger(&paths.lock_path))
                .transpose()?;

            let merged = match &paths {
                Some(paths) if paths.revoked_path.exists() => {
                    let (persisted, persisted_number) =
                        load_sidecar(&paths.revoked_path).map_err(|error| {
                            anyhow::anyhow!(
                                "reading the ledger `{}` before writing it: {error}",
                                paths.revoked_path.display()
                            )
                        })?;
                    crl_number = crl_number.max(persisted_number);
                    merge(&mut entries, persisted)
                }
                _ => 0,
            };
            let changed = mutate(&mut entries);
            if merged == 0 && changed == 0 {
                return Ok(Pass {
                    entries,
                    crl_number,
                    crl_der: None,
                    merged,
                    changed,
                });
            }

            crl_number += 1;
            let crl = build_crl(&entries, crl_number, &issuer)?;
            if let Some(paths) = &paths {
                // The ledger before the CRL: the ledger is the authoritative
                // record and the CRL is derived from it at every startup, so a
                // crash between the two loses nothing.
                //
                // `0600` on the ledger — it decides what the CRL says, and it
                // is not public material the way the CRL itself is.
                let ledger_json = sidecar_json(&entries, crl_number)?;
                crate::pemfile::write_atomic(&paths.revoked_path, ledger_json.as_bytes(), 0o600)?;
                crate::pemfile::write_atomic(&paths.crl_path, crl.pem()?.as_bytes(), 0o644)?;
            }
            Ok(Pass {
                entries,
                crl_number,
                crl_der: Some(crl.der().to_vec()),
                merged,
                changed,
            })
        })
        .await
        .map_err(|error| SignerError::Internal(format!("revocation persist panicked: {error}")))?
        .map_err(|error| SignerError::Internal(error.to_string()))?;

        ledger.entries = pass.entries;
        ledger.crl_number = pass.crl_number;
        if let Some(crl_der) = pass.crl_der {
            ledger.crl_der = crl_der;
        }
        if pass.merged > 0 {
            info!(
                event = "local_ca_ledger_merged",
                outcome = "success",
                rows_merged = pass.merged,
                ledger = %self.state_key(),
                "took in revocations another process wrote to this CA's ledger"
            );
        }
        Ok(pass.changed)
    }
}

/// What one [`LedgerStore::update`] pass leaves behind, carried out of the
/// blocking task.
struct Pass {
    entries: Vec<RevokedEntry>,
    crl_number: u64,
    /// `None` when nothing changed and so nothing was signed.
    crl_der: Option<Vec<u8>>,
    merged: usize,
    changed: usize,
}

/// Opens `path` and takes an exclusive lock on it, blocking until any other
/// holder lets go. The lock lasts as long as the returned `File`.
///
/// An advisory `flock`: every writer of the ledger goes through here, and the
/// kernel releases it when the descriptor closes — including when a process
/// holding it dies, so a crashed `order revoke` cannot wedge the server. It
/// serialises processes on **one host**; on a network filesystem it may not
/// hold at all.
///
/// Refuses anything at `path` that is not a regular file, the caution
/// `pemfile::write_atomic` takes and for its reason: an open that follows a
/// planted symlink creates a file wherever the link points.
fn lock_ledger(path: &Path) -> anyhow::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            anyhow::bail!(
                "the ledger lock `{}` exists and is not a regular file",
                path.display()
            );
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            anyhow::bail!("the ledger lock `{}`: {error}", path.display());
        }
        _ => {}
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| {
        anyhow::anyhow!("opening the ledger lock `{}`: {error}", path.display())
    })?;
    file.lock()
        .map_err(|error| anyhow::anyhow!("locking `{}`: {error}", path.display()))?;
    Ok(file)
}

/// Folds entries another instance persisted into `entries`, returning how many
/// of `entries` that added or changed.
///
/// A **union** by serial, never a replacement: nothing but a prune ever takes
/// an entry out, and a prune runs after this, over the merged list — so an
/// entry one instance pruned and another still holds comes back, listed a
/// little longer than it had to be, which is the safe direction. Where both
/// sides hold a serial they describe one certificate, so the first revocation
/// is the one kept (its time and its reason) and a known expiry fills an
/// unknown one.
pub(super) fn merge(entries: &mut Vec<RevokedEntry>, persisted: Vec<RevokedEntry>) -> usize {
    let mut position: HashMap<String, usize> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.serial_hex.clone(), index))
        .collect();
    let mut changed = 0;
    for theirs in persisted {
        let Some(&index) = position.get(&theirs.serial_hex) else {
            position.insert(theirs.serial_hex.clone(), entries.len());
            entries.push(theirs);
            changed += 1;
            continue;
        };
        let ours = &mut entries[index];
        let mut touched = false;
        if theirs.revoked_at < ours.revoked_at {
            ours.revoked_at = theirs.revoked_at;
            ours.reason = theirs.reason;
            touched = true;
        }
        if ours.not_after.is_none() && theirs.not_after.is_some() {
            ours.not_after = theirs.not_after;
            touched = true;
        }
        changed += usize::from(touched);
    }
    changed
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
    /// **Signs and writes nothing when nothing was pruned**, which is the
    /// common case and is why it is worth checking: rebuilding regardless would
    /// advance `crl_number` and rewrite two files every single day on a CA that
    /// has revoked nothing. The one exception is a sidecar holding revocations
    /// this instance has not seen — another process's `order revoke` — which
    /// this pass takes in and re-signs over, so the served CRL is at most a day
    /// behind a revocation made from the command line.
    ///
    /// A failed persist leaves the entries in memory untouched, since
    /// [`LedgerStore::update`] replaces them only on success: *fewer*
    /// revocations in memory than in the sidecar and the served CRL would be
    /// the unsafe direction of that disagreement.
    async fn prune_expired(&self) -> Result<usize, SignerError> {
        let mut ledger = self.revoked.lock().await;
        self.update(&mut ledger, |entries| {
            prune_expired(entries, OffsetDateTime::now_utc())
        })
        .await
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
///
/// Under the ledger lock, like every other write: this runs in each process
/// that builds the CA — `serve` at startup, and `order revoke` every time — so
/// without it two starts interleaving would each rewrite the files from what
/// they read before the other wrote.
pub(super) fn init_ledger(
    paths: Option<&CrlPaths>,
    issuer: &Issuer<'static, CaSigningKey>,
) -> anyhow::Result<RevokedLedger> {
    // Released when this function returns, i.e. after both writes.
    let _lock = paths.map(|p| lock_ledger(&p.lock_path)).transpose()?;
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
        crate::pemfile::write_atomic(
            &p.revoked_path,
            sidecar_json(&ledger.entries, ledger.crl_number)?.as_bytes(),
            0o600,
        )?;
        crate::pemfile::write_atomic(&p.crl_path, crl.pem()?.as_bytes(), 0o644)?;
    }
    ledger.crl_der = crl.der().to_vec();
    Ok(ledger)
}
