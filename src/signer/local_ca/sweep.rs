//! The daily CRL refresh, as a job.
//!
//! RFC 5280 §3.3 permits dropping a revocation once the certificate itself has
//! expired, and a CRL claims to be current only until its `nextUpdate`. Doing
//! either only on revocation would be proportional to the wrong thing: a CA
//! that revokes a batch and then goes quiet never sheds anything, and its CRL
//! lapses while nobody is looking. So once a day, every CA prunes what has
//! expired and re-signs when that took anything or its CRL is due — see
//! [`crate::signer::CrlRefresher::refresh`].
//!
//! Deliberately **not** in [`crate::jobs::sweep`], whose `SweepTarget` is a
//! `DELETE` per table and needs nothing but a
//! [`Database`](crate::sqlite::db::Database). This one signs with the CA key.
//!
//! Two shapes it borrows from that module and one it does not:
//!
//! - [`JobOutcome::Reschedule`] is how periodic work is spelled here, and
//! - `run` **never returns [`JobOutcome::Failed`]** — a retired periodic job
//!   does not re-enqueue itself, so one unreachable database or unsignable CRL
//!   would stop the refresh for the life of the process rather than for one day.
//! - But there is **one handler over every CA**, not one per CA. See
//!   [`SignerBackend::crl_refresher`](crate::signer::SignerBackend::crl_refresher):
//!   [`JobRegistry::register`](crate::jobs::JobRegistry::register) refuses two
//!   handlers for one `kind`, and two profiles with different
//!   `[signer.local_ca]` sections are two backends, so the alternative would
//!   make a supported configuration a startup error.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info};

use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::signer::CrlRefresher;
use crate::sqlite::job::Job;

/// The `jobs.kind` the CRL prune runs under.
pub const CRL_SWEEP_KIND: &str = "local_ca_crl_sweep";

/// The one row's `dedup_key`. A constant, like the table sweeps': there is one
/// occurrence, and it walks every CA rather than there being one row each.
///
/// That is not only tidiness. A per-CA row would outlive the profile that named
/// it — unmount a profile and its row keeps being claimed, by a handler that no
/// longer has anything to hand it.
const SWEEP_KEY: &str = "all";

/// How often the refresh runs.
///
/// A certificate's `notAfter` has a resolution of seconds but its *lifetime* is
/// measured in days, so an entry lingering a few hours past the point it could
/// have gone is nobody's problem — and this may sign a CRL per CA, which is not
/// work to do hourly. A CRL is valid for a week and re-signed once half of that
/// is left, so a daily pass always catches it in time.
const DAILY: Duration = Duration::from_secs(24 * 60 * 60);

/// Refreshes every local CA's CRL, once a day.
pub struct CrlSweepJob {
    refreshers: Vec<Arc<dyn CrlRefresher>>,
    interval: Duration,
}

impl CrlSweepJob {
    /// One handler over every CA in the process.
    ///
    /// Registered by `server::generation::build_generation` only when
    /// `refreshers` is non-empty, the way `SweepJob::audit` is registered only
    /// for a non-zero retention: a deployment with no local CA has nothing to
    /// refresh, and an always-present row that always finds nothing is a row an
    /// operator has to learn to ignore.
    #[must_use]
    pub fn new(refreshers: Vec<Arc<dyn CrlRefresher>>) -> Self {
        Self {
            refreshers,
            interval: DAILY,
        }
    }

    /// How often this sweep runs.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Refreshes each CA in turn, logging what went and swallowing failures.
    ///
    /// Sequential rather than concurrent, and one failure does not stop the
    /// rest: these are independent CAs, and the whole point of not returning
    /// `Failed` is that one CA's failure must not take the others down with it.
    async fn sweep(&self) {
        for refresher in &self.refreshers {
            match refresher.refresh().await {
                Ok(0) => {}
                Ok(removed) => info!(
                    event = "local_ca_crl_pruned",
                    outcome = "success",
                    rows_removed = removed,
                    issuer = %refresher.issuer(),
                    "dropped revocation entries whose certificates have expired"
                ),
                Err(error) => error!(
                    event = "local_ca_crl_prune_failed",
                    outcome = "failure",
                    issuer = %refresher.issuer(),
                    error = %error
                ),
            }
        }
    }
}

#[async_trait]
impl JobHandler for CrlSweepJob {
    fn kind(&self) -> &'static str {
        CRL_SWEEP_KIND
    }

    async fn run(&self, _job: &Job) -> JobOutcome {
        self.sweep().await;
        // **Never `Failed`**, whatever happened above — see the module docs.
        JobOutcome::Reschedule(self.interval)
    }

    /// Puts the single occurrence back in the queue at startup, which is also
    /// what performs the first refresh: `run_at` is now, so the runner claims
    /// it on its first pass. That first pass is also where a CA meeting the
    /// database for the first time imports its old sidecar, so a sidecar that
    /// will not import is reported at startup rather than at the first
    /// revocation.
    ///
    /// Harmless to run again — the identity index refuses a second live row for
    /// this kind, so a restart resumes the existing schedule rather than
    /// resetting it.
    async fn recover(&self, queue: &JobQueue) {
        queue
            .enqueue_or_log(JobSpec::now(self.kind(), SWEEP_KEY))
            .await;
    }
}

/// The `jobs.kind` a revocation recorded without the CA's key asks for.
pub const CRL_REGENERATE_KIND: &str = "local_ca_crl_regenerate";

/// The row that asks the process holding `issuer`'s key to sign the CRL.
///
/// Keyed on the issuer, so a burst of revocations of one CA queues one row
/// while it waits: the signing that row does covers every revocation recorded
/// before it runs.
#[must_use]
pub fn regenerate_spec(issuer: &str) -> JobSpec {
    JobSpec::now(CRL_REGENERATE_KIND, issuer)
}

/// Signs the revocations recorded without a key into their CA's CRL.
///
/// The host CLI records a local-CA revocation as a `revocations` row and never
/// loads the key, so this is where it reaches the CRL. **One handler over
/// every CA**, for [`CrlSweepJob`]'s reason, picking the CA by the row's key.
pub struct CrlRegenerateJob {
    refreshers: Vec<Arc<dyn CrlRefresher>>,
}

impl CrlRegenerateJob {
    #[must_use]
    pub fn new(refreshers: Vec<Arc<dyn CrlRefresher>>) -> Self {
        Self { refreshers }
    }
}

#[async_trait]
impl JobHandler for CrlRegenerateJob {
    fn kind(&self) -> &'static str {
        CRL_REGENERATE_KIND
    }

    /// `Retry` rather than `Failed` for a CA this process does not serve: a
    /// row queued against a configuration another process — or the next
    /// generation of this one — does serve must not be thrown away. The
    /// attempt budget still ends it, and the daily refresh signs whatever it
    /// would have.
    async fn run(&self, job: &Job) -> JobOutcome {
        let issuer = job.dedup_key.as_str();
        let Some(refresher) = self
            .refreshers
            .iter()
            .find(|refresher| refresher.issuer() == issuer)
        else {
            return JobOutcome::Retry(format!("no local CA with issuer {issuer} is served here"));
        };
        match refresher.republish().await {
            Ok(true) => {
                info!(
                    event = "local_ca_crl_republished",
                    outcome = "success",
                    issuer = %issuer,
                    "signed revocations recorded without the CA key into the CRL"
                );
                JobOutcome::Done
            }
            Ok(false) => JobOutcome::Done,
            Err(error) => JobOutcome::Retry(error.to_string()),
        }
    }

    async fn abandon(&self, job: &Job, reason: &str) {
        error!(
            event = "local_ca_crl_republish_abandoned",
            outcome = "failure",
            issuer = %job.dedup_key,
            reason = %reason,
            "the daily refresh will sign the missing revocations instead"
        );
    }
}
