//! The periodic CRL prune, as a job.
//!
//! RFC 5280 §3.3 permits dropping a revocation entry once the certificate
//! itself has expired, and [`crl::prune_expired`](super::crl::prune_expired) is
//! what decides which. Doing it only on revocation would be proportional to the
//! wrong thing: a CA that revokes a batch and then goes quiet never sheds
//! anything, and it is precisely the quiet CA whose CRL nobody notices growing.
//!
//! Deliberately **not** in [`crate::jobs::sweep`], whose `SweepTarget` is four
//! `DELETE`s over four tables and needs nothing but a
//! [`Database`](crate::sqlite::db::Database). This one holds signer state, signs
//! with the CA key, and touches no database at all.
//!
//! Two shapes it borrows from that module and one it does not:
//!
//! - [`JobOutcome::Reschedule`] is how periodic work is spelled here, and
//! - `run` **never returns [`JobOutcome::Failed`]** — a retired periodic job
//!   does not re-enqueue itself, so one unwritable directory would stop the
//!   prune for the life of the process rather than for one day.
//! - But there is **one handler over every CA**, not one per CA. See
//!   [`SignerBackend::crl_pruner`](crate::signer::SignerBackend::crl_pruner):
//!   [`JobRegistry::register`](crate::jobs::JobRegistry::register) refuses two
//!   handlers for one `kind`, and two profiles with different
//!   `[signer.local_ca]` sections are two backends, so the alternative would
//!   make a supported configuration a startup error.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info};

use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::signer::CrlPruner;
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

/// How often the prune runs.
///
/// A certificate's `notAfter` has a resolution of seconds but its *lifetime* is
/// measured in days, so an entry lingering a few hours past the point it could
/// have gone is nobody's problem — and this signs a CRL per CA that had
/// something to drop, which is not work to do hourly.
const DAILY: Duration = Duration::from_secs(24 * 60 * 60);

/// Prunes every local CA's revocation ledger, once a day.
pub struct CrlSweepJob {
    pruners: Vec<Arc<dyn CrlPruner>>,
    interval: Duration,
}

impl CrlSweepJob {
    /// One handler over every CA in the process.
    ///
    /// Registered by `cli::build_generation` only when `pruners` is non-empty,
    /// the way `SweepJob::audit` is registered only for a non-zero retention: a
    /// deployment with no local CA has nothing to prune, and an always-present
    /// row that always finds nothing is a row an operator has to learn to
    /// ignore.
    #[must_use]
    pub fn new(pruners: Vec<Arc<dyn CrlPruner>>) -> Self {
        Self {
            pruners,
            interval: DAILY,
        }
    }

    /// How often this sweep runs.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Prunes each ledger in turn, logging what went and swallowing failures.
    ///
    /// Sequential rather than concurrent, and one failure does not stop the
    /// rest: these are independent CAs, and the whole point of not returning
    /// `Failed` is that one CA's unwritable `crl_path` must not take the others
    /// down with it.
    async fn sweep(&self) {
        for pruner in &self.pruners {
            match pruner.prune_expired().await {
                Ok(0) => {}
                Ok(removed) => info!(
                    event = "local_ca_crl_pruned",
                    outcome = "success",
                    rows_removed = removed,
                    ledger = %pruner.state_key(),
                    "dropped revocation entries whose certificates have expired"
                ),
                Err(error) => error!(
                    event = "local_ca_crl_prune_failed",
                    outcome = "failure",
                    ledger = %pruner.state_key(),
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
    /// what performs the first prune: `run_at` is now, so the runner claims it
    /// on its first pass.
    ///
    /// Harmless to run again — the identity index refuses a second live row for
    /// this kind, so a restart resumes the existing schedule rather than
    /// resetting it.
    ///
    /// Note this is *not* the only thing that prunes at startup:
    /// [`init_ledger`](super::crl::init_ledger) does too, on its way to building
    /// the CRL it must rewrite anyway. This one is what covers the process that
    /// then stays up for months.
    async fn recover(&self, queue: &JobQueue) {
        queue
            .enqueue_or_log(JobSpec::now(self.kind(), SWEEP_KEY))
            .await;
    }
}
