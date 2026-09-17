//! The revocation state and the CRL signed over it.
//!
//! Separated from issuance because the two share only the
//! `Issuer<'static, CaSigningKey>` they sign with.
//!
//! **The database is the only store.** What this CA has revoked is the
//! `revocations` rows under its issuer id ([`crate::cert::issuer_id`]), and the
//! CRL it serves is its `crls` row. Every process over one database therefore
//! sees one CA: `acme-proxy order revoke` beside a running `serve` lands a row
//! the server's very next `GET /crl` already reflects. That is what this module
//! used to get wrong with a JSON sidecar and an in-memory copy per process.
//!
//! Three things keep that correct under concurrency:
//!
//! - **`crl_number` only moves through a compare-and-swap.** A writer reads the
//!   stored CRL and the revocations in one snapshot, signs outside any
//!   transaction (a PKCS#11 signature is a token round trip), then stores with
//!   [`StoredCrl::replace_if_number`]. A writer that lost re-reads and signs
//!   again, so no CRL is ever stored over a snapshot older than the one it
//!   replaces.
//! - **A revocation is covered once *some* stored CRL lists it**, whoever
//!   signed it. A loser whose serial the winner already included is done, which
//!   is what keeps a burst of concurrent revocations from spending its retries.
//! - **Initialisation is one transaction keyed on the `crls` row.** The first
//!   CRL for an issuer is stored together with whatever the old sidecar held,
//!   so a sidecar is imported exactly once, and no revocation can be recorded
//!   under an issuer before its import has happened.
//!
//! `crl_path` survives as an **export**: every stored CRL is written there as
//! PEM, for operators who publish it from a static web server, and nothing ever
//! reads it back. The sidecar beside it (`ca.json`) is read once, at import,
//! and never written again.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::prelude::*;
use rcgen::{
    CertificateRevocationListParams, Issuer, KeyIdMethod, RevocationReason, RevokedCertParams,
    SerialNumber,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tokio::sync::{Mutex, OnceCell};
use tracing::{error, info, warn};

use super::CLOCK_SKEW_ALLOWANCE;
use super::key::CaSigningKey;
use crate::signer::{CrlRefresher, SignerError};
use crate::sqlite::crl::StoredCrl;
use crate::sqlite::db::Database;
use crate::sqlite::revocation::Revocation;

/// The files beside a file-backed CA's CRL, all derived from `crl_path`.
#[derive(Clone)]
pub(super) struct CrlPaths {
    /// Where the current CRL is exported, as PEM.
    pub(super) crl_path: PathBuf,
    /// The pre-database ledger (`ca.json`), read once at import.
    pub(super) revoked_path: PathBuf,
    /// Held exclusively across every export, so two processes writing
    /// `crl_path` cannot leave an older CRL in place of a newer one.
    ///
    /// A file of its own rather than a lock on the export: `write_atomic`
    /// renames a new inode over `crl_path`, so a lock taken on it guards an
    /// inode that is gone after the first write. Nothing is ever written to
    /// this one, so it is never replaced. Its name predates the database and
    /// is kept, since an operator's tooling may already expect the file.
    pub(super) lock_path: PathBuf,
}

impl CrlPaths {
    /// `ca.crl` → `ca.json` and `ca.json.lock` beside it.
    pub(super) fn beside(crl_path: &str) -> Self {
        let crl_path = PathBuf::from(crl_path);
        Self {
            revoked_path: crl_path.with_extension("json"),
            lock_path: crl_path.with_extension("json.lock"),
            crl_path,
        }
    }
}

/// How long a generated CRL claims to remain current (RFC 5280's `nextUpdate`).
const CRL_VALIDITY_DAYS: i64 = 7;

/// How many times one regeneration re-reads and re-signs after another writer
/// stored a CRL first. Each loss means somebody else's CRL was stored, which is
/// progress; running out means this CA is being revoked against faster than it
/// can sign, and the caller hears about it rather than looping.
const MAX_REGENERATION_ATTEMPTS: usize = 5;

/// A CA's revocation state: where it is stored, what signs over it, and where
/// the result is exported.
///
/// What [`SignerBackend::crl_refresher`](crate::signer::SignerBackend::crl_refresher)
/// hands the daily sweep, and what `LocalCa` revokes and serves through. Holds
/// nothing a second instance over the same database would disagree with: the
/// only in-memory state is whether *this* instance has initialised, and a lock
/// serialising its own regenerations.
pub(super) struct CrlStore {
    database: Arc<Database>,
    issuer_id: String,
    signer: Arc<Issuer<'static, CaSigningKey>>,
    /// `None` for an in-memory CA, which exports nothing and imports nothing.
    paths: Option<CrlPaths>,
    /// Set once this CA's `crls` row is known to exist. Not set by a failed
    /// attempt, so the next caller tries again.
    initialized: OnceCell<()>,
    /// Serialises this instance's own regenerations: two of its revocations
    /// signing over the same snapshot would only have one of them lose the
    /// compare-and-swap. Other instances are what the swap is for.
    regenerating: Mutex<()>,
}

impl CrlStore {
    pub(super) fn new(
        database: Arc<Database>,
        issuer_id: String,
        signer: Arc<Issuer<'static, CaSigningKey>>,
        paths: Option<CrlPaths>,
    ) -> Self {
        Self {
            database,
            issuer_id,
            signer,
            paths,
            initialized: OnceCell::new(),
            regenerating: Mutex::new(()),
        }
    }

    /// The key this CA's revocation state is stored under.
    pub(super) fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Makes sure this CA has a stored CRL, importing the old sidecar the first
    /// time any process meets it.
    ///
    /// Every read and write of the revocation state goes through here first.
    /// That ordering is the import's correctness: a revocation recorded before
    /// the sidecar was imported would make "the table already has rows" a lie,
    /// which is why the import is keyed on the `crls` row rather than on
    /// `revocations` being empty.
    pub(super) async fn ensure_initialized(&self) -> Result<(), SignerError> {
        self.initialized
            .get_or_try_init(|| async {
                self.initialize().await.inspect_err(|error| {
                    error!(
                        event = "local_ca_crl_initialization_failed",
                        outcome = "failure",
                        issuer = %self.issuer_id,
                        error = %error,
                    );
                })
            })
            .await
            .map(|_| ())
    }

    async fn initialize(&self) -> Result<(), SignerError> {
        let existing = self.stored().await?;
        if existing.is_some() {
            return Ok(());
        }

        // The sidecar, if this CA kept one before the database did. Read and
        // signed over off the runtime, the way every signature here is.
        let paths = self.paths.clone();
        let signer = self.signer.clone();
        let issuer_id = self.issuer_id.clone();
        let (imported, initial) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(Option<Vec<Revocation>>, StoredCrl)> {
                let (entries, number) = match &paths {
                    Some(paths) if paths.revoked_path.exists() => {
                        let (entries, number) =
                            load_sidecar(&paths.revoked_path).map_err(|error| {
                                anyhow::anyhow!(
                                    "importing the revocation ledger `{}`: {error}",
                                    paths.revoked_path.display()
                                )
                            })?;
                        let rows = entries
                            .into_iter()
                            .map(|entry| entry.into_revocation(&issuer_id))
                            .collect();
                        (Some(rows), number)
                    }
                    _ => (None, 0),
                };
                let rows: &[Revocation] = entries.as_deref().unwrap_or_default();
                let crl = sign(rows, number + 1, &signer, &issuer_id)?;
                Ok((entries, crl))
            },
        )
        .await
        .map_err(|error| SignerError::Internal(format!("CRL initialisation panicked: {error}")))?
        .map_err(|error| SignerError::Internal(error.to_string()))?;

        let mut tx = self
            .database
            .transaction()
            .await
            .map_err(database_failure)?;
        // First, so it is what takes the write lock: a second process racing
        // this one waits here and then finds the row already stored.
        if !initial
            .insert_initial(&mut *tx)
            .await
            .map_err(database_failure)?
        {
            return Ok(());
        }
        for row in imported.iter().flatten() {
            row.insert_if_absent(&mut *tx)
                .await
                .map_err(database_failure)?;
        }
        tx.commit().await.map_err(database_failure)?;

        if let Some(rows) = &imported {
            info!(
                event = "local_ca_ledger_imported",
                outcome = "success",
                issuer = %self.issuer_id,
                rows_imported = rows.len(),
                crl_number = initial.crl_number,
                ledger = ?self.paths.as_ref().map(|paths| paths.revoked_path.display().to_string()),
                "the revocation ledger now lives in the database; the sidecar is no longer \
                 read or written and may be archived",
            );
        }
        self.export().await;
        Ok(())
    }

    /// Records `serial` as revoked and makes sure a stored CRL lists it.
    ///
    /// Idempotent. A serial already recorded is not recorded again — the first
    /// revocation's time and reason stand — but its CRL is still checked, and
    /// signed if it does not list the serial yet: that is the retry of a
    /// revocation whose row landed and whose CRL did not.
    pub(super) async fn revoke(&self, revocation: Revocation) -> Result<bool, SignerError> {
        self.ensure_initialized().await?;
        let mut tx = self
            .database
            .transaction()
            .await
            .map_err(database_failure)?;
        let inserted = revocation
            .insert_if_absent(&mut *tx)
            .await
            .map_err(database_failure)?;
        tx.commit().await.map_err(database_failure)?;
        self.regenerate(None, Some(&revocation.serial)).await?;
        Ok(inserted)
    }

    /// The CRL to serve.
    pub(super) async fn current_der(&self) -> Result<Vec<u8>, SignerError> {
        self.ensure_initialized().await?;
        self.stored().await?.map(|crl| crl.der).ok_or_else(|| {
            error!(
                event = "local_ca_crl_missing",
                outcome = "failure",
                issuer = %self.issuer_id,
            );
            SignerError::Internal("this CA has no stored CRL".to_string())
        })
    }

    /// Signs and stores a new CRL, retrying from a fresh snapshot while other
    /// writers keep storing first. Returns how many revocations the prune took.
    ///
    /// `cutoff`, when given, first deletes the revocations whose certificates
    /// expired before it (RFC 5280 §3.3). `covering` names a serial that must
    /// end up listed: if the stored CRL already lists it — because another
    /// writer's CRL included it — nothing is signed.
    async fn regenerate(
        &self,
        cutoff: Option<i64>,
        covering: Option<&str>,
    ) -> Result<u64, SignerError> {
        let _serialised = self.regenerating.lock().await;

        let removed = match cutoff {
            Some(cutoff) => {
                let mut tx = self
                    .database
                    .transaction()
                    .await
                    .map_err(database_failure)?;
                let removed = Revocation::prune_expired(&self.issuer_id, cutoff, &mut *tx)
                    .await
                    .map_err(database_failure)?;
                tx.commit().await.map_err(database_failure)?;
                removed
            }
            None => 0,
        };

        for _ in 0..MAX_REGENERATION_ATTEMPTS {
            // One read transaction, so the number and the rows come from the
            // same snapshot; closed before signing, so no lock is held across it.
            let mut tx = self
                .database
                .transaction()
                .await
                .map_err(database_failure)?;
            let current = StoredCrl::find(&self.issuer_id, &mut *tx)
                .await
                .map_err(database_failure)?
                .ok_or_else(|| {
                    SignerError::Internal("this CA has no stored CRL to replace".to_string())
                })?;
            let rows = Revocation::list_for_issuer(&self.issuer_id, &mut *tx)
                .await
                .map_err(database_failure)?;
            drop(tx);

            if covering.is_some_and(|serial| lists_serial(&current.der, serial)) {
                return Ok(removed);
            }

            let signer = self.signer.clone();
            let issuer_id = self.issuer_id.clone();
            let number = current.crl_number + 1;
            let next = tokio::task::spawn_blocking(move || sign(&rows, number, &signer, &issuer_id))
                .await
                .map_err(|error| {
                    error!(event = "local_ca_crl_signing_panicked", outcome = "failure", error = %error);
                    SignerError::Internal(format!("CRL signing panicked: {error}"))
                })?
                .map_err(|error| {
                    error!(event = "local_ca_crl_signing_failed", outcome = "failure", issuer = %self.issuer_id, error = %error);
                    SignerError::Internal(error.to_string())
                })?;

            if next
                .replace_if_number(current.crl_number, &self.database)
                .await
                .map_err(database_failure)?
            {
                self.export().await;
                return Ok(removed);
            }
        }

        error!(
            event = "local_ca_crl_regeneration_contended",
            outcome = "failure",
            issuer = %self.issuer_id,
            attempts = MAX_REGENERATION_ATTEMPTS,
        );
        Err(SignerError::Internal(format!(
            "another writer stored a CRL first {MAX_REGENERATION_ATTEMPTS} times in a row"
        )))
    }

    /// Writes the stored CRL to `crl_path`, logging rather than failing.
    ///
    /// The database is authoritative and has already answered by the time this
    /// runs, so an unwritable export must not turn a recorded revocation into
    /// an error the caller would retry. The daily sweep exports again.
    ///
    /// The row is read **under the lock**, not handed in: two processes that
    /// each stored a CRL would otherwise race to write their own, and the
    /// slower one could leave the older CRL on disk. Whoever holds the lock
    /// writes whatever is newest at that moment.
    async fn export(&self) {
        let Some(paths) = self.paths.clone() else {
            return;
        };
        if let Err(error) = self.try_export(paths.clone()).await {
            error!(
                event = "local_ca_crl_export_failed",
                outcome = "failure",
                issuer = %self.issuer_id,
                crl_path = %paths.crl_path.display(),
                error = %error,
            );
        }
    }

    async fn try_export(&self, paths: CrlPaths) -> anyhow::Result<()> {
        let lock_path = paths.lock_path.clone();
        let lock = tokio::task::spawn_blocking(move || lock_export(&lock_path)).await??;
        let Some(crl) = self.stored().await? else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || {
            crate::pemfile::write_atomic(&paths.crl_path, crl_pem(&crl.der).as_bytes(), 0o644)?;
            drop(lock);
            anyhow::Ok(())
        })
        .await??;
        Ok(())
    }

    /// This CA's stored CRL, if it has one yet.
    async fn stored(&self) -> Result<Option<StoredCrl>, SignerError> {
        let mut tx = self
            .database
            .transaction()
            .await
            .map_err(database_failure)?;
        StoredCrl::find(&self.issuer_id, &mut *tx)
            .await
            .map_err(database_failure)
    }
}

#[async_trait]
impl CrlRefresher for CrlStore {
    fn issuer(&self) -> &str {
        &self.issuer_id
    }

    /// Drops the revocations whose certificates have expired, and re-signs when
    /// any went **or** when less than half the stored CRL's validity is left.
    ///
    /// The second condition is what keeps a CA that revokes nothing serving a
    /// CRL that has not lapsed: nothing else re-signs one any more — startup
    /// used to, when every process rebuilt the CRL from its own copy. A CA
    /// with nothing expired and a fresh CRL signs nothing, and only exports,
    /// so a missing or stale `crl_path` catches up within a day.
    async fn refresh(&self) -> Result<u64, SignerError> {
        self.ensure_initialized().await?;
        let now = OffsetDateTime::now_utc();
        let cutoff = (now - CLOCK_SKEW_ALLOWANCE).unix_timestamp();

        let expired = Revocation::count_expired(&self.issuer_id, cutoff, &self.database)
            .await
            .map_err(database_failure)?;
        let current = self.stored().await?;
        let half_life = Duration::days(CRL_VALIDITY_DAYS).whole_seconds() / 2;
        let stale = current.is_none_or(|crl| now.unix_timestamp() + half_life >= crl.next_update);

        if expired > 0 || stale {
            return self.regenerate(Some(cutoff), None).await;
        }
        self.export().await;
        Ok(0)
    }
}

/// Maps a storage error, logging it where it is built.
fn database_failure(error: sqlx::Error) -> SignerError {
    error!(event = "local_ca_database_query_failed", outcome = "failure", error = %error);
    SignerError::Internal(format!("revocation state: {error}"))
}

/// Opens `path` and takes an exclusive lock on it, blocking until any other
/// holder lets go. The lock lasts as long as the returned `File`.
///
/// An advisory `flock`, released by the kernel when the descriptor closes —
/// including when a process holding it dies. It serialises writers on **one
/// host**, which is all an export to a local path needs.
///
/// Refuses anything at `path` that is not a regular file, the caution
/// `pemfile::write_atomic` takes and for its reason: an open that follows a
/// planted symlink creates a file wherever the link points.
fn lock_export(path: &Path) -> anyhow::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            anyhow::bail!(
                "the CRL export lock `{}` exists and is not a regular file",
                path.display()
            );
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            anyhow::bail!("the CRL export lock `{}`: {error}", path.display());
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
        anyhow::anyhow!("opening the CRL export lock `{}`: {error}", path.display())
    })?;
    file.lock()
        .map_err(|error| anyhow::anyhow!("locking `{}`: {error}", path.display()))?;
    Ok(file)
}

/// Signs a CRL listing `rows`, numbered `crl_number`, as the row to store.
fn sign(
    rows: &[Revocation],
    crl_number: u64,
    issuer: &Issuer<'static, CaSigningKey>,
    issuer_id: &str,
) -> anyhow::Result<StoredCrl> {
    let now = OffsetDateTime::now_utc();
    let this_update = now - CLOCK_SKEW_ALLOWANCE;
    let next_update = now + Duration::days(CRL_VALIDITY_DAYS);
    let crl = build_crl(rows, crl_number, issuer, this_update, next_update)?;
    Ok(StoredCrl {
        issuer: issuer_id.to_string(),
        crl_number,
        der: crl.der().to_vec(),
        this_update: this_update.unix_timestamp(),
        next_update: next_update.unix_timestamp(),
    })
}

/// Builds a signed CRL over `rows`, numbered `crl_number`.
pub(super) fn build_crl(
    rows: &[Revocation],
    crl_number: u64,
    issuer: &Issuer<'static, CaSigningKey>,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
) -> anyhow::Result<rcgen::CertificateRevocationList> {
    // A serial that is not hex can only arrive from the sidecar import — an
    // operator-editable file — since every row this CA writes itself comes
    // from `cert_serial_and_spki`. Naming the entry is something an operator
    // can act on; the `expect` this replaced was a panic in a request task.
    let revoked_certs = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let serial = hex::decode(&row.serial).map_err(|error| {
                anyhow::anyhow!(
                    "revoked ledger entry {index}: serial `{}` is not hex: {error}",
                    row.serial
                )
            })?;
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&serial),
                revocation_time: OffsetDateTime::from_unix_timestamp(row.revoked_at)
                    .unwrap_or(this_update),
                reason_code: row.reason.and_then(reason_from_u32),
                invalidity_date: None,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .map_err(Into::into)
}

/// Whether the CRL `der` lists `serial` (hex, either case).
///
/// A CRL that does not parse lists nothing, which makes the caller sign a new
/// one — the safe answer for bytes this CA stored itself and cannot read.
fn lists_serial(der: &[u8], serial: &str) -> bool {
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;

    match CertificateRevocationList::from_der(der) {
        Ok((_, crl)) => crl
            .iter_revoked_certificates()
            .any(|revoked| hex::encode(revoked.raw_serial()).eq_ignore_ascii_case(serial)),
        Err(error) => {
            warn!(event = "local_ca_crl_unparsable", outcome = "failure", error = %error);
            false
        }
    }
}

/// `der` as a PEM `X509 CRL` block — the format `crl_path` has always held.
fn crl_pem(der: &[u8]) -> String {
    let body = BASE64_STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN X509 CRL-----\n");
    for line in body.as_bytes().chunks(64) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END X509 CRL-----\n");
    pem
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

/// One entry of the pre-database sidecar, as it is read for import.
#[derive(Deserialize)]
struct SidecarEntry {
    serial_hex: String,
    /// Unix seconds.
    revoked_at: i64,
    reason: Option<u32>,
    /// Absent in a v1 sidecar, and then never pruned.
    #[serde(default)]
    not_after: Option<i64>,
}

impl SidecarEntry {
    fn into_revocation(self, issuer_id: &str) -> Revocation {
        Revocation {
            issuer: issuer_id.to_string(),
            serial: self.serial_hex,
            revoked_at: self.revoked_at,
            reason: self.reason,
            not_after: self.not_after,
        }
    }
}

/// The v2 sidecar envelope.
#[derive(Deserialize)]
struct Sidecar {
    crl_number: u64,
    entries: Vec<SidecarEntry>,
}

/// Reads the sidecar, in either format it has ever had.
///
/// Dispatch is on the **shape of the JSON** rather than through
/// `#[serde(untagged)]`: an untagged enum collapses every field-level error into
/// one "did not match any variant", and this file is operator-editable.
fn load_sidecar(path: &Path) -> anyhow::Result<(Vec<SidecarEntry>, u64)> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if value.is_array() {
        // v1: a bare array, no envelope and no counter. The highest number that
        // format could ever have emitted was `entries.len() + 1`, so the first
        // CRL the database stores — numbered one above what this returns — sits
        // strictly above the last one v1 published.
        let entries: Vec<SidecarEntry> = serde_json::from_value(value)?;
        let crl_number = entries.len() as u64 + 1;
        return Ok((entries, crl_number));
    }
    let sidecar: Sidecar = serde_json::from_value(value)?;
    Ok((sidecar.entries, sidecar.crl_number))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Something other than a regular file where the lock belongs is refused
    /// by name, rather than followed or locked as if it were one.
    #[test]
    fn a_lock_path_that_is_not_a_regular_file_is_refused() {
        let dir = crate::testutil::TempDir::new("crl-lock");
        let lock = dir.join("ca.json.lock");
        fs::create_dir(&lock).unwrap();

        let error = lock_export(&lock).unwrap_err().to_string();
        assert!(
            error.contains("ca.json.lock"),
            "the refusal names the lock: {error}"
        );
    }

    /// The export is standard PEM: 64-column base64 between the `X509 CRL`
    /// armour, decoding back to the exact bytes.
    #[test]
    fn the_export_is_pem_that_decodes_to_the_der() {
        let der: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let pem = crl_pem(&der);

        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN X509 CRL-----"));
        assert_eq!(lines.last(), Some(&"-----END X509 CRL-----"));
        assert!(
            lines[1..lines.len() - 1]
                .iter()
                .all(|line| line.len() <= 64)
        );
        let body: String = lines[1..lines.len() - 1].concat();
        assert_eq!(BASE64_STANDARD.decode(body).unwrap(), der);
    }

    /// Bytes that are not a CRL list nothing, so the caller signs a new one
    /// rather than trusting what it cannot read.
    #[test]
    fn an_unparsable_crl_lists_nothing() {
        assert!(!lists_serial(b"not a crl", "01"));
    }
}
