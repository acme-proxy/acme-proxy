//! The durable job runner: background work that survives the process.
//!
//! ## Why this is not a `tokio::spawn`
//!
//! A spawned task is a promise the process makes to itself, and a restart breaks
//! it. That was tolerable while exactly one subsystem needed one — the `relay`
//! signer backend, whose state lived on its own `upstream_orders` row and whose
//! `resume` sweep re-created the task at startup — but it bought only *recovery*,
//! never *retry*: with nowhere to record that an attempt had failed and should
//! happen again, every failure had to be terminal. A five-second upstream blip
//! therefore invalidated an order the client then had to place again.
//!
//! Here the schedule is a row. An attempt that fails writes its next `run_at`
//! and goes back in the queue; a process that dies leaves a lease that expires
//! and a row another runner takes. Both are the same table and the same loop, so
//! the next subsystem that wants a queue — expiry reminders, a CRL sweep, an
//! OCSP refresh — registers a handler rather than writing this again.
//!
//! ## The three things a handler must know
//!
//! 1. **`run` may be called again from scratch.** The runner promises nothing
//!    about what a previous attempt did. `signer::relay::flow` is the worked
//!    example: it re-reads the upstream order and skips every authorization that
//!    is no longer `pending`, so re-entering at any point is safe by
//!    construction rather than by checkpointing.
//! 2. **[`JobOutcome::Retry`] and [`JobOutcome::Failed`] are a real
//!    distinction.** `Retry` is "the network, the nameserver, a 503"; `Failed` is
//!    "the CA stated a reason" or "this payload can never parse". Classifying a
//!    permanent failure as retryable wastes the budget and delays the client's
//!    real answer; the reverse throws away the retry this module exists for.
//! 3. **[`JobHandler::abandon`] fires exactly once**, when the job is retired for
//!    good — and never between retries. It is where a handler tells its *subject*
//!    what happened, so a client polling through a transient blip keeps seeing
//!    work in progress rather than a terminal failure it must start over from.
//!
//! ## Wake-up is in-process
//!
//! [`JobQueue::enqueue`] notifies the runner directly, so a job queued by a
//! request starts within microseconds rather than waiting for
//! `jobs.poll_interval_ms`. That matters because the ACME client that triggered
//! it is already polling its order. The notification is a
//! [`tokio::sync::Notify`], which is process-local: with two processes over one
//! database, the second sees the first's enqueue at its next tick. That is a
//! deliberate limit and not a bug — the *claim* is race-free across processes,
//! only the wake-up is not.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Notify;
use tracing::error;

use crate::config::JobsConfig;
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;
use crate::sqlite::nonce::now_secs;

pub mod registry;
pub mod runner;
pub mod sweep;

pub use registry::JobRegistry;
pub use runner::spawn_runner;
pub use sweep::SweepJob;

/// How one attempt ended.
#[derive(Debug)]
pub enum JobOutcome {
    /// Finished. Terminal, and nothing else runs.
    Done,
    /// This attempt failed for a reason that may not recur: schedule another
    /// after the backoff, unless the attempts or the deadline have run out.
    Retry(String),
    /// This will never succeed. Terminal, and [`JobHandler::abandon`] is called.
    Failed(String),
    /// This *occurrence* is finished; run again after the given delay.
    ///
    /// The row stays live, so its identity stays taken and nothing can queue a
    /// second copy — which is what makes a periodic job one row rather than a
    /// growing pile of them, with no cron table to keep in step.
    Reschedule(Duration),
}

/// What to queue.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// Which handler runs it.
    pub kind: &'static str,
    /// The identity of the work within its kind. A live job holds it; a settled
    /// one releases it.
    pub key: String,
    /// The *identity* of the subject, never a snapshot of its state — a snapshot
    /// goes stale across a retry.
    pub payload: Value,
    /// Not before this instant, epoch seconds. `now_secs()` for immediate.
    pub run_at: i64,
    /// The outer bound on retrying, epoch seconds. `None` for no deadline.
    pub deadline: Option<i64>,
    /// Overrides `jobs.max_attempts` for this one job.
    pub max_attempts: Option<u32>,
}

impl JobSpec {
    /// A job to run as soon as the runner can take it.
    #[must_use]
    pub fn now(kind: &'static str, key: impl Into<String>) -> Self {
        Self {
            kind,
            key: key.into(),
            payload: json!({}),
            run_at: now_secs(),
            deadline: None,
            max_attempts: None,
        }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Option<i64>) -> Self {
        self.deadline = deadline;
        self
    }

    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.run_at = now_secs().saturating_add(seconds(delay));
        self
    }
}

/// One kind of background work.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// The `jobs.kind` this handler answers for. One handler per kind — the
    /// registry refuses a second, since two would each get half the rows.
    fn kind(&self) -> &'static str;

    /// Runs one attempt.
    ///
    /// Must be safe to run again from scratch: see the module documentation.
    async fn run(&self, job: &Job) -> JobOutcome;

    /// How long one attempt may take, and therefore how long the lease is held.
    ///
    /// `None` takes `jobs.lease_seconds`. The runner enforces it with a timeout
    /// and writes a lease slightly longer, so the in-process deadline always
    /// fires before another runner could steal the row.
    fn lease(&self) -> Option<Duration> {
        None
    }

    /// Called exactly once when the runner retires this job permanently — the
    /// handler said [`JobOutcome::Failed`], the attempts ran out, or the deadline
    /// passed.
    ///
    /// This is where a handler tells its subject what happened. Deliberately not
    /// called between retries: a client polling an order must not be told it
    /// failed while the server is still trying.
    async fn abandon(&self, _job: &Job, _reason: &str) {}

    /// Re-derives work a previous process left unfinished. Run once, at startup,
    /// before the loop begins.
    ///
    /// The generic replacement for the old `SignerBackend::resume`: an enqueue
    /// rather than a spawn, and safely repeatable because the identity index
    /// refuses a duplicate.
    async fn recover(&self, _queue: &JobQueue) {}
}

/// The enqueue side of the queue, plus the runner's wake-up.
///
/// Cloneable and cheap to hold: everything inside is an `Arc` or a scalar. A
/// subsystem that queues work holds one of these and never sees the runner.
#[derive(Clone)]
pub struct JobQueue {
    database: Arc<Database>,
    notify: Arc<Notify>,
    default_max_attempts: u32,
}

impl JobQueue {
    #[must_use]
    pub fn new(database: Arc<Database>, config: &JobsConfig) -> Self {
        Self {
            database,
            notify: Arc::new(Notify::new()),
            default_max_attempts: config.max_attempts,
        }
    }

    /// Queues one job.
    ///
    /// `Ok(false)` means a live job already holds this `(kind, key)` — not an
    /// error, but the answer two racing callers must both survive. The caller
    /// reads it the way `RelaySigner::issue` reads `UpstreamOrder::create`'s
    /// `Ok(None)`: somebody else is already on it.
    pub async fn enqueue(&self, spec: JobSpec) -> Result<bool, sqlx::Error> {
        let max_attempts = i64::from(spec.max_attempts.unwrap_or(self.default_max_attempts));
        let queued = Job::enqueue(
            &uuid::Uuid::new_v4().to_string(),
            spec.kind,
            &spec.key,
            &spec.payload,
            spec.run_at,
            spec.deadline,
            max_attempts,
            &self.database,
        )
        .await?;

        if queued {
            // Wakes the runner now rather than at its next tick: the request
            // that queued this is often one an ACME client is already polling.
            self.notify.notify_one();
        }
        Ok(queued)
    }

    /// [`JobQueue::enqueue`], logging rather than returning a database failure.
    ///
    /// For the callers with nowhere to report one — `recover`, which the trait
    /// defines as best-effort, and any path where refusing to queue is worse
    /// than the error it would surface.
    pub async fn enqueue_or_log(&self, spec: JobSpec) -> bool {
        let kind = spec.kind;
        let key = spec.key.clone();
        match self.enqueue(spec).await {
            Ok(queued) => queued,
            Err(error) => {
                error!(
                    event = "job_enqueue_failed",
                    outcome = "failure",
                    job_kind = %kind,
                    dedup_key = %key,
                    error = %error,
                );
                false
            }
        }
    }

    /// The database this queue writes to, for a handler that needs one and would
    /// otherwise have to be handed a second copy.
    #[must_use]
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }
}

/// A `Duration` as whole seconds, saturating.
///
/// Job schedules are epoch seconds — the column type the whole schema uses — so
/// every `Duration` crossing that boundary goes through here rather than through
/// a bare `as` cast at four call sites.
pub(crate) fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn queue() -> JobQueue {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        JobQueue::new(database, &JobsConfig::default())
    }

    #[tokio::test]
    async fn enqueue_reports_whether_it_took_the_identity() {
        let queue = queue().await;
        assert!(queue.enqueue(JobSpec::now("test", "k")).await.unwrap());
        assert!(
            !queue.enqueue(JobSpec::now("test", "k")).await.unwrap(),
            "a second live job for one key is refused, not duplicated"
        );
        assert!(queue.enqueue(JobSpec::now("test", "other")).await.unwrap());
    }

    #[tokio::test]
    async fn a_spec_carries_its_payload_deadline_and_attempt_budget() {
        let queue = queue().await;
        let deadline = now_secs() + 60;
        let spec = JobSpec {
            max_attempts: Some(9),
            ..JobSpec::now("test", "k")
                .with_payload(json!({"order_id": "ord-1"}))
                .with_deadline(Some(deadline))
        };
        assert!(queue.enqueue(spec).await.unwrap());

        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.payload, json!({"order_id": "ord-1"}));
        assert_eq!(job.deadline, Some(deadline));
        assert_eq!(job.max_attempts, 9);
    }

    #[tokio::test]
    async fn a_spec_with_no_budget_of_its_own_takes_the_configured_one() {
        let queue = queue().await;
        assert!(queue.enqueue(JobSpec::now("test", "k")).await.unwrap());
        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            job.max_attempts,
            i64::from(JobsConfig::default().max_attempts)
        );
    }

    #[tokio::test]
    async fn with_delay_pushes_the_run_time_out() {
        let queue = queue().await;
        let spec = JobSpec::now("test", "k").with_delay(Duration::from_secs(600));
        assert!(spec.run_at >= now_secs() + 599);
        assert!(queue.enqueue(spec).await.unwrap());
    }

    /// The failure path a `recover` implementation relies on: a closed pool is
    /// logged and reported as "not queued", never propagated into a caller with
    /// nowhere to put it.
    #[tokio::test]
    async fn enqueue_or_log_swallows_a_database_failure() {
        let queue = queue().await;
        queue.database().pool.close().await;
        assert!(!queue.enqueue_or_log(JobSpec::now("test", "k")).await);
    }

    #[test]
    fn seconds_saturates_rather_than_wrapping() {
        assert_eq!(seconds(Duration::from_secs(90)), 90);
        assert_eq!(seconds(Duration::MAX), i64::MAX);
    }
}
