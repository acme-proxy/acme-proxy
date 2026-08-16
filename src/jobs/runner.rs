//! The loop that drains the queue: claim, run, settle, back off.
//!
//! One task for the process, holding a registry and a concurrency permit pool.
//! Everything it does to a row is a guarded statement in [`crate::sqlite::job`],
//! so two runners over one database — a rolling restart's overlap, or a second
//! process someone starts by mistake — cannot both run one job.
//!
//! No `#[instrument]` anywhere in this module, the rule `src/webadmin/` keeps
//! and for both of its reasons: there is no request span here to enrich, and the
//! attribute moves a body into a generated async block that reports almost no
//! coverage — on precisely the timing code that is hardest to cover anyway.

use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::{JobHandler, JobOutcome, JobQueue, JobRegistry, seconds};
use crate::config::JobsConfig;
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;
use crate::sqlite::nonce::now_secs;

/// How much longer than its own timeout a job's lease runs.
///
/// The in-process deadline must always fire first, or a second runner could
/// claim a row this one is still working. Thirty seconds covers the settling
/// statement plus any scheduler delay between the timeout elapsing and the write
/// landing.
const LEASE_SLACK: Duration = Duration::from_secs(30);

/// How long a graceful stop waits for in-flight jobs before releasing leases.
///
/// A `const` rather than a configuration key: it is the cost of a clean exit,
/// not a policy. A job that outlives it is not lost — its lease is released and
/// the next process claims it. This is what replaced the notify subsystem's own
/// bounded shutdown drain, which had the same budget and, unlike this, genuinely
/// did lose whatever ran past it.
const DRAIN_BUDGET: Duration = Duration::from_secs(5);

/// Timing derived from `[jobs]` once, so the loop never re-reads the config.
struct RunnerConfig {
    poll_interval: Duration,
    lease: Duration,
    retry_base: Duration,
    retry_max: Duration,
}

impl RunnerConfig {
    fn from(config: &JobsConfig) -> Self {
        Self {
            poll_interval: Duration::from_millis(config.poll_interval_ms),
            lease: Duration::from_secs(config.lease_seconds),
            retry_base: Duration::from_secs(config.retry_base_seconds),
            retry_max: Duration::from_secs(config.retry_max_seconds),
        }
    }
}

/// Starts the runner. The returned handle is aborted on drop by the caller.
///
/// `shutdown` is the same `watch` both listeners take, so one signal stops
/// everything. A stop is graceful: the runner takes no new work, waits
/// [`DRAIN_BUDGET`] for what is running, then releases its leases so the next
/// process claims them immediately instead of waiting one out.
pub fn spawn_runner(
    queue: JobQueue,
    registry: Arc<JobRegistry>,
    config: &JobsConfig,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let runner = RunnerConfig::from(config);
    let permits = Arc::new(Semaphore::new(config.max_concurrent.max(1)));
    let max_concurrent = config.max_concurrent;
    tokio::spawn(async move {
        run_loop(queue, registry, runner, permits, max_concurrent, shutdown).await;
    })
}

async fn run_loop(
    queue: JobQueue,
    registry: Arc<JobRegistry>,
    config: RunnerConfig,
    permits: Arc<Semaphore>,
    max_concurrent: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    let runner_id = uuid::Uuid::new_v4().to_string();
    let database = queue.database().clone();
    let kinds = registry.kinds();

    info!(
        event = "job_runner_started",
        outcome = "progress",
        runner_id = %runner_id,
        job_kinds = ?kinds,
        max_concurrent = max_concurrent,
    );

    // Before the loop: every handler gets one chance to re-derive work a
    // previous process left unfinished. An enqueue, not a spawn — and safely
    // repeatable, because the identity index refuses a duplicate.
    for handler in registry.handlers() {
        handler.recover(&queue).await;
    }

    loop {
        // Rows whose runner died holding the lease. Runs before claiming so a
        // crashed process's work is eligible on this pass rather than the next.
        if let Err(error) = Job::reclaim_expired(now_secs(), &database).await {
            error!(event = "job_reclaim_failed", outcome = "failure", error = %error);
        }

        drain_ready(&queue, &registry, &config, &permits, &runner_id).await;

        // Idle: whichever comes first. `notified()` is what keeps a job queued
        // by a request from waiting on `poll_interval`.
        tokio::select! {
            () = queue.notify.notified() => {}
            () = tokio::time::sleep(config.poll_interval) => {}
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
    }

    stop(&runner_id, &database, &permits, max_concurrent).await;
}

/// Claims and starts everything currently eligible, up to the permit pool.
///
/// The permit is acquired **before** the claim, and that order is the trap worth
/// naming: claiming first would start every backlogged row's lease ticking while
/// it sat waiting for a permit, and each would then be reclaimed as "crashed"
/// having never run.
async fn drain_ready(
    queue: &JobQueue,
    registry: &Arc<JobRegistry>,
    config: &RunnerConfig,
    permits: &Arc<Semaphore>,
    runner_id: &str,
) {
    let kinds = registry.kinds();
    if kinds.is_empty() {
        return;
    }
    let database = queue.database().clone();

    loop {
        let Ok(permit) = Arc::clone(permits).acquire_owned().await else {
            return; // the semaphore is closed: the runner is going away
        };

        // The lease is the *longest* any registered handler may take, because
        // which handler will answer is not known until the row comes back. It is
        // narrowed to the handler's own budget the moment it is.
        let lease = config.lease + LEASE_SLACK;
        let now = now_secs();
        let claimed = Job::claim_next(
            runner_id,
            &kinds,
            now.saturating_add(seconds(lease)),
            now,
            &database,
        )
        .await;

        let job = match claimed {
            Ok(Some(job)) => job,
            Ok(None) => return, // nothing eligible; `permit` drops here
            Err(error) => {
                error!(event = "job_claim_failed", outcome = "failure", error = %error);
                return;
            }
        };

        let Some(handler) = registry.get(&job.kind).cloned() else {
            // Unreachable: the claim filters on the registry's own kinds. If it
            // ever happens the row must not be left leased for a full lease.
            warn!(event = "job_kind_unknown", outcome = "failure", job_id = %job.id, job_kind = %job.kind);
            let _ = Job::retry(&job.id, runner_id, now_secs(), "no handler", &database).await;
            continue;
        };

        let queue = queue.clone();
        let runner_id = runner_id.to_string();
        let budget = handler.lease().unwrap_or(config.lease);
        let retry = (config.retry_base, config.retry_max);
        tokio::spawn(async move {
            run_one(job, handler, &queue, &runner_id, budget, retry).await;
            drop(permit);
        });
    }
}

/// Runs the handler under its own budget, on its own task.
///
/// The task is what contains a **panic**: without it, a handler that panics
/// unwinds this whole future, nothing settles the row, and the job sits
/// `running` until its lease expires — up to `jobs.lease_seconds` of a
/// concurrency slot spent on work that has already failed. Caught here it is an
/// ordinary retry, and the panic is logged as the bug it always is.
///
/// A timeout **aborts** the task rather than merely dropping the handle, which
/// would detach it and let it run on past its budget. Abort drops the handler's
/// future at its next suspension point, so cancellation-time cleanup still
/// runs — `signer::relay::http01`'s `PublishedToken` guard, whose whole purpose
/// is retracting a key authorization when a relay is cut short, depends on that.
async fn run_attempt(job: &Job, handler: &Arc<dyn JobHandler>, budget: Duration) -> JobOutcome {
    let handler = handler.clone();
    let owned = job.clone();
    let mut task = tokio::spawn(async move { handler.run(&owned).await });

    match tokio::time::timeout(budget, &mut task).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) if error.is_panic() => {
            error!(
                event = "job_run_panicked",
                outcome = "failure",
                job_id = %job.id,
                job_kind = %job.kind,
                attempts = job.attempts,
            );
            JobOutcome::Retry("the handler panicked".to_string())
        }
        // Cancelled: only reachable if something aborted the task from
        // elsewhere, which nothing does. Retryable rather than terminal, since
        // nothing about the *work* was decided.
        Ok(Err(_)) => JobOutcome::Retry("the attempt was cancelled".to_string()),
        Err(_) => {
            task.abort();
            JobOutcome::Retry(format!("the attempt timed out after {}s", budget.as_secs()))
        }
    }
}

/// Runs one claimed job and writes what happened.
async fn run_one(
    job: Job,
    handler: Arc<dyn JobHandler>,
    queue: &JobQueue,
    runner_id: &str,
    budget: Duration,
    retry: (Duration, Duration),
) {
    let database = queue.database().clone();
    let now = now_secs();

    // A job claimed after its deadline is retired without running: the work is
    // pointless by definition, and this is where a row that sat through an
    // outage is cleared rather than attempted.
    if job.deadline.is_some_and(|deadline| deadline < now) {
        warn!(
            event = "job_deadline_passed",
            outcome = "failure",
            job_id = %job.id,
            job_kind = %job.kind,
            attempts = job.attempts,
        );
        retire(
            &job,
            &handler,
            runner_id,
            "the job's deadline passed",
            &database,
        )
        .await;
        return;
    }

    let started = std::time::Instant::now();
    let outcome = run_attempt(&job, &handler, budget).await;
    let elapsed = crate::millis(started.elapsed());

    match outcome {
        JobOutcome::Done => {
            let settled = Job::complete(&job.id, runner_id, &database).await;
            report_settlement(&job, settled);
            info!(
                event = "job_run_completed",
                outcome = "success",
                job_id = %job.id,
                job_kind = %job.kind,
                attempts = job.attempts,
                duration_ms = elapsed,
            );
        }
        JobOutcome::Reschedule(delay) => {
            let run_at = now_secs().saturating_add(seconds(delay));
            let settled = Job::reschedule(&job.id, runner_id, run_at, &database).await;
            report_settlement(&job, settled);
            debug!(
                event = "job_run_rescheduled",
                outcome = "success",
                job_id = %job.id,
                job_kind = %job.kind,
                run_at = run_at,
                duration_ms = elapsed,
            );
        }
        JobOutcome::Failed(reason) => {
            retire(&job, &handler, runner_id, &reason, &database).await;
        }
        JobOutcome::Retry(reason) => {
            let delay = backoff(job.attempts, retry.0, retry.1);
            let run_at = now_secs().saturating_add(seconds(delay));
            let exhausted = job.attempts >= job.max_attempts;
            let past_deadline = job.deadline.is_some_and(|deadline| run_at > deadline);

            if exhausted || past_deadline {
                let why = if exhausted {
                    format!("{reason} (no attempts left after {})", job.attempts)
                } else {
                    format!("{reason} (the next attempt would fall past the deadline)")
                };
                retire(&job, &handler, runner_id, &why, &database).await;
                return;
            }

            let settled = Job::retry(&job.id, runner_id, run_at, &reason, &database).await;
            report_settlement(&job, settled);
            warn!(
                event = "job_run_retried",
                outcome = "failure",
                job_id = %job.id,
                job_kind = %job.kind,
                attempts = job.attempts,
                max_attempts = job.max_attempts,
                run_at = run_at,
                duration_ms = elapsed,
                reason = %reason,
            );
        }
    }
}

/// Retires a job permanently and tells its handler, exactly once.
///
/// The `abandon` call is **after** the row is settled and only when the
/// settlement took: a runner whose lease was reclaimed must not tell a subject
/// its work failed while another runner is still doing it.
async fn retire(
    job: &Job,
    handler: &Arc<dyn JobHandler>,
    runner_id: &str,
    reason: &str,
    database: &Database,
) {
    let settled = Job::abandon(&job.id, runner_id, reason, database).await;
    if !report_settlement(job, settled) {
        return;
    }
    error!(
        event = "job_run_abandoned",
        outcome = "failure",
        job_id = %job.id,
        job_kind = %job.kind,
        attempts = job.attempts,
        reason = %reason,
    );
    handler.abandon(job, reason).await;
}

/// Whether a settlement actually landed, logging the two ways it might not.
fn report_settlement(job: &Job, settled: Result<bool, sqlx::Error>) -> bool {
    match settled {
        Ok(true) => true,
        Ok(false) => {
            // The lease expired and another runner reclaimed the row. Not an
            // error — this runner overran, and the guard did its job — but the
            // work this attempt did is now somebody else's to repeat.
            warn!(
                event = "job_lease_lost",
                outcome = "advisory",
                job_id = %job.id,
                job_kind = %job.kind,
            );
            false
        }
        Err(error) => {
            error!(
                event = "job_settle_failed",
                outcome = "failure",
                job_id = %job.id,
                job_kind = %job.kind,
                error = %error,
            );
            false
        }
    }
}

/// The graceful stop: drain what is running, then release the leases.
async fn stop(runner_id: &str, database: &Database, permits: &Arc<Semaphore>, capacity: usize) {
    // Every permit back means every spawned job has finished. A timeout here is
    // not a failure: the lease release below is what makes an unfinished job the
    // next process's rather than a lost one.
    let drained = tokio::time::timeout(
        DRAIN_BUDGET,
        permits.acquire_many(u32::try_from(capacity.max(1)).unwrap_or(u32::MAX)),
    )
    .await
    .is_ok();

    // Released rather than settled, and `attempts` is deliberately left as it
    // is: the attempt really did run, and a counter rewritten to look better
    // would let a job that crashes the process loop for ever. The cost is that a
    // restart during a long job spends one of its attempts.
    let released = Job::release_owned(runner_id, database).await.unwrap_or(0);

    info!(
        event = "job_runner_stopped",
        outcome = "success",
        runner_id = %runner_id,
        drained = drained,
        rows_released = released,
    );
}

/// The delay before attempt `attempts + 1`: exponential, capped, jittered.
///
/// The jitter is not decoration. A backlog of jobs that failed together against
/// one upstream would otherwise retry in lockstep for ever, turning one outage
/// into a repeating thundering herd against the service that is already
/// struggling. A quarter of the window is enough to spread a few hundred rows.
///
/// It only ever subtracts, so `jobs.retry_max_seconds` is an honest ceiling: a
/// key documented as "where the doubling stops" must not be exceeded by the
/// jitter that follows it, and a retry that comes marginally early costs
/// nothing.
fn backoff(attempts: i64, base: Duration, max: Duration) -> Duration {
    let steps = u32::try_from(attempts.max(1) - 1)
        .unwrap_or(u32::MAX)
        .min(32);
    let scaled = base.saturating_mul(2_u32.saturating_pow(steps));
    let capped = scaled.min(max);

    let millis = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX);
    let spread = millis / 4;
    if spread == 0 {
        return capped;
    }

    let mut bytes = [0_u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // Unreachable in practice; an unjittered retry is still a correct one.
        return capped;
    }
    Duration::from_millis(millis.saturating_sub(u64::from_be_bytes(bytes) % spread))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::JobSpec;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A handler whose every attempt is scripted, counting runs and abandons.
    ///
    /// The counters are the only thing that can tell a skipped call from a
    /// silent one: `abandon` firing twice and firing once leave the same row.
    struct Scripted {
        kind: &'static str,
        script: Vec<Script>,
        runs: AtomicUsize,
        abandons: AtomicUsize,
        last_reason: std::sync::Mutex<String>,
        budget: Option<Duration>,
    }

    enum Script {
        Done,
        Retry,
        Failed,
        Reschedule(Duration),
        Sleep(Duration),
        Panic,
    }

    impl Scripted {
        fn new(kind: &'static str, script: Vec<Script>) -> Arc<Self> {
            Arc::new(Self {
                kind,
                script,
                runs: AtomicUsize::new(0),
                abandons: AtomicUsize::new(0),
                last_reason: std::sync::Mutex::new(String::new()),
                budget: None,
            })
        }

        fn with_budget(kind: &'static str, script: Vec<Script>, budget: Duration) -> Arc<Self> {
            let mut handler = Self {
                kind,
                script,
                runs: AtomicUsize::new(0),
                abandons: AtomicUsize::new(0),
                last_reason: std::sync::Mutex::new(String::new()),
                budget: None,
            };
            handler.budget = Some(budget);
            Arc::new(handler)
        }

        fn runs(&self) -> usize {
            self.runs.load(Ordering::SeqCst)
        }

        fn abandons(&self) -> usize {
            self.abandons.load(Ordering::SeqCst)
        }

        fn reason(&self) -> String {
            self.last_reason.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl JobHandler for Scripted {
        fn kind(&self) -> &'static str {
            self.kind
        }

        fn lease(&self) -> Option<Duration> {
            self.budget
        }

        async fn run(&self, _job: &Job) -> JobOutcome {
            let index = self.runs.fetch_add(1, Ordering::SeqCst);
            match self.script.get(index).unwrap_or(&Script::Done) {
                Script::Done => JobOutcome::Done,
                Script::Retry => JobOutcome::Retry("transient".to_string()),
                Script::Failed => JobOutcome::Failed("permanent".to_string()),
                Script::Reschedule(delay) => JobOutcome::Reschedule(*delay),
                Script::Sleep(delay) => {
                    tokio::time::sleep(*delay).await;
                    JobOutcome::Done
                }
                Script::Panic => panic!("this handler panics on purpose"),
            }
        }

        async fn abandon(&self, _job: &Job, reason: &str) {
            self.abandons.fetch_add(1, Ordering::SeqCst);
            *self.last_reason.lock().unwrap() = reason.to_string();
        }
    }

    async fn queue_with(config: &JobsConfig) -> JobQueue {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        JobQueue::new(database, config)
    }

    /// Runs the loop's body once, synchronously, so a test asserts on a settled
    /// row rather than racing a background task.
    async fn tick(queue: &JobQueue, handler: Arc<dyn JobHandler>, config: &JobsConfig) {
        let mut registry = JobRegistry::new();
        registry.register(handler).unwrap();
        let registry = Arc::new(registry);
        let runner = RunnerConfig::from(config);
        let permits = Arc::new(Semaphore::new(config.max_concurrent.max(1)));

        Job::reclaim_expired(now_secs(), queue.database())
            .await
            .unwrap();
        drain_ready(queue, &registry, &runner, &permits, "runner-test").await;

        // Every permit back means every spawned job has settled.
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            permits.acquire_many(u32::try_from(config.max_concurrent.max(1)).unwrap()),
        )
        .await;
    }

    fn fast() -> JobsConfig {
        JobsConfig {
            poll_interval_ms: 5,
            retry_base_seconds: 0,
            retry_max_seconds: 0,
            ..JobsConfig::default()
        }
    }

    #[tokio::test]
    async fn a_successful_job_is_done_and_is_never_abandoned() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Done]);
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 1);
        assert_eq!(handler.abandons(), 0);
        let job = Job::find_by_id(
            &Job::find_live("test", "k", queue.database())
                .await
                .unwrap()
                .map_or_else(|| "gone".to_string(), |job| job.id),
            queue.database(),
        )
        .await
        .unwrap();
        assert!(job.is_none(), "a done job holds no identity");
    }

    /// The property the whole retry design turns on: a transient failure must
    /// leave the subject alone, because the server is still trying.
    #[tokio::test]
    async fn a_retry_requeues_the_job_and_does_not_abandon_it() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Retry, Script::Done]);
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;
        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .expect("a retried job is still live");
        assert_eq!(job.status, "ready");
        assert_eq!(job.attempts, 1);
        assert_eq!(job.last_error.as_deref(), Some("transient"));
        assert_eq!(handler.abandons(), 0, "a retry must never abandon");

        tick(&queue, handler.clone(), &config).await;
        assert_eq!(handler.runs(), 2);
        assert_eq!(handler.abandons(), 0);
        assert!(
            Job::find_live("test", "k", queue.database())
                .await
                .unwrap()
                .is_none(),
            "the second attempt succeeded"
        );
    }

    #[tokio::test]
    async fn a_permanent_failure_is_abandoned_after_one_attempt() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Failed]);
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 1, "a permanent failure is not retried");
        assert_eq!(handler.abandons(), 1);
        assert_eq!(handler.reason(), "permanent");
    }

    #[tokio::test]
    async fn retrying_stops_at_max_attempts_and_abandons_exactly_once() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Retry, Script::Retry, Script::Retry]);
        queue
            .enqueue(JobSpec {
                max_attempts: Some(2),
                ..JobSpec::now("test", "k")
            })
            .await
            .unwrap();

        tick(&queue, handler.clone(), &config).await;
        assert_eq!(handler.abandons(), 0);
        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 2);
        assert_eq!(handler.abandons(), 1, "abandon fires exactly once");
        assert!(
            handler.reason().contains("no attempts left"),
            "the reason names the budget: {}",
            handler.reason()
        );
        assert!(
            Job::find_live("test", "k", queue.database())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_job_claimed_past_its_deadline_is_retired_without_running() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Done]);
        queue
            .enqueue(JobSpec::now("test", "k").with_deadline(Some(now_secs() - 1)))
            .await
            .unwrap();

        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 0, "the work is pointless by definition");
        assert_eq!(handler.abandons(), 1);
        assert!(handler.reason().contains("deadline"));
    }

    /// The deadline bounds the calendar where `max_attempts` bounds the effort:
    /// a retry that would land past it retires now instead.
    #[tokio::test]
    async fn a_retry_that_would_fall_past_the_deadline_retires_instead() {
        let config = JobsConfig {
            retry_base_seconds: 600,
            retry_max_seconds: 600,
            ..fast()
        };
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Retry]);
        queue
            .enqueue(JobSpec::now("test", "k").with_deadline(Some(now_secs() + 30)))
            .await
            .unwrap();

        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 1);
        assert_eq!(handler.abandons(), 1);
        assert!(
            handler.reason().contains("past the deadline"),
            "the reason distinguishes this from an exhausted budget: {}",
            handler.reason()
        );
    }

    #[tokio::test]
    async fn a_rescheduled_job_stays_live_with_a_fresh_attempt_count() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new(
            "test",
            vec![
                Script::Retry,
                Script::Reschedule(Duration::from_secs(3_600)),
            ],
        );
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;
        tick(&queue, handler.clone(), &config).await;

        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .expect("a rescheduled job stays live, so nothing queues a second copy");
        assert_eq!(job.status, "ready");
        assert_eq!(job.attempts, 0, "a fresh occurrence starts fresh");
        assert!(job.last_error.is_none());
        assert!(job.run_at >= now_secs() + 3_500);
        assert_eq!(handler.abandons(), 0);
    }

    /// A panic must land as an ordinary retry **immediately**, not wedge the
    /// lease until it expires. Without the task boundary in `run_attempt` the
    /// unwind takes the runner's own future with it, nothing settles the row,
    /// and a concurrency slot is spent for a full `lease_seconds` on work that
    /// has already failed.
    #[tokio::test]
    async fn a_panicking_handler_is_retried_without_waiting_out_its_lease() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Panic, Script::Done]);
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;

        // No `reclaim_expired` here, and that is the assertion: the row is back
        // in the queue on its own.
        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .expect("the job survives its handler panicking");
        assert_eq!(job.status, "ready");
        assert!(
            job.lease_owner.is_none(),
            "the lease was released, not left"
        );
        assert_eq!(job.attempts, 1, "the attempt was spent and is recorded");
        assert_eq!(job.last_error.as_deref(), Some("the handler panicked"));
        assert_eq!(handler.abandons(), 0, "a panic is not a permanent failure");

        tick(&queue, handler.clone(), &config).await;
        assert!(
            Job::find_live("test", "k", queue.database())
                .await
                .unwrap()
                .is_none(),
            "the retry after the panic succeeds"
        );
    }

    #[tokio::test]
    async fn a_handler_that_exceeds_its_lease_is_retried() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::with_budget(
            "test",
            vec![Script::Sleep(Duration::from_secs(30))],
            Duration::from_millis(50),
        );
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;

        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .expect("a timed-out attempt is retryable, not terminal");
        assert_eq!(job.status, "ready");
        assert!(
            job.last_error
                .as_deref()
                .unwrap_or("")
                .contains("timed out"),
            "the reason names the budget: {:?}",
            job.last_error
        );
        assert_eq!(handler.abandons(), 0);
    }

    #[tokio::test]
    async fn a_kind_no_handler_is_registered_for_is_left_alone() {
        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Done]);
        queue.enqueue(JobSpec::now("other", "k")).await.unwrap();

        tick(&queue, handler.clone(), &config).await;

        assert_eq!(handler.runs(), 0);
        let job = Job::find_live("other", "k", queue.database())
            .await
            .unwrap()
            .expect("an unregistered kind stays queued for a build that knows it");
        assert_eq!(job.status, "ready");
        assert_eq!(job.attempts, 0, "it was never claimed");
    }

    /// The whole reason `enqueue` notifies: a job queued by a request must not
    /// wait for a poll tick, because a client is already polling for its result.
    #[tokio::test]
    async fn an_enqueue_wakes_the_runner_without_waiting_for_a_tick() {
        let config = JobsConfig {
            // Long enough that a tick cannot be what ran the job.
            poll_interval_ms: 60_000,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Done]);
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();

        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner(queue.clone(), Arc::new(registry), &config, rx);

        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();
        for _ in 0..200 {
            if handler.runs() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(handler.runs(), 1, "the enqueue must have woken the runner");

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
    }

    /// A graceful stop returns work to the queue rather than holding it for a
    /// full lease, so a restart picks up its own jobs immediately.
    #[tokio::test]
    async fn shutdown_releases_the_leases_this_runner_holds() {
        let config = JobsConfig {
            poll_interval_ms: 5,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Sleep(Duration::from_secs(30))]);
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();

        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner(queue.clone(), Arc::new(registry), &config, rx);
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();
        for _ in 0..200 {
            if handler.runs() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(20), runner).await;

        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .expect("the job is not lost");
        assert_eq!(job.status, "ready", "the lease was released, not settled");
        assert!(job.lease_owner.is_none());
    }

    #[tokio::test]
    async fn a_runner_with_no_handlers_idles_without_claiming_anything() {
        let config = fast();
        let queue = queue_with(&config).await;
        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();

        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner(queue.clone(), Arc::new(JobRegistry::new()), &config, rx);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;

        let job = Job::find_live("test", "k", queue.database())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.attempts, 0);
    }

    /// `recover` runs once, before the loop, and is an enqueue — so a handler
    /// that re-derives the same work twice queues it once.
    #[tokio::test]
    async fn recover_runs_at_startup_and_is_safely_repeatable() {
        struct Recovering(AtomicUsize);

        #[async_trait]
        impl JobHandler for Recovering {
            fn kind(&self) -> &'static str {
                "recovering"
            }
            async fn run(&self, _job: &Job) -> JobOutcome {
                self.0.fetch_add(1, Ordering::SeqCst);
                JobOutcome::Reschedule(Duration::from_secs(3_600))
            }
            async fn recover(&self, queue: &JobQueue) {
                assert!(
                    queue
                        .enqueue_or_log(JobSpec::now("recovering", "one"))
                        .await
                );
                assert!(
                    !queue
                        .enqueue_or_log(JobSpec::now("recovering", "one"))
                        .await,
                    "the identity index makes a repeated recovery harmless"
                );
            }
        }

        let config = fast();
        let queue = queue_with(&config).await;
        let handler = Arc::new(Recovering(AtomicUsize::new(0)));
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();

        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner(queue.clone(), Arc::new(registry), &config, rx);
        for _ in 0..200 {
            if handler.0.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;

        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_doubles_from_the_base_and_stops_at_the_ceiling() {
        let base = Duration::from_secs(30);
        let max = Duration::from_secs(3_600);

        // The jitter only ever subtracts, so each expectation is the window
        // `(centre * 3/4, centre]` rather than a single value.
        for (attempts, centre) in [(1_i64, 30_u64), (2, 60), (3, 120), (4, 240), (5, 480)] {
            let delay = backoff(attempts, base, max).as_secs();
            assert!(
                delay >= centre * 3 / 4 && delay <= centre,
                "attempt {attempts}: {delay}s is outside the jitter window below {centre}s"
            );
        }
    }

    /// `retry_max_seconds` is documented as where the doubling stops, so no
    /// amount of jitter or attempts may produce a delay past it.
    #[test]
    fn backoff_never_exceeds_the_ceiling_however_many_attempts_have_gone() {
        let base = Duration::from_secs(30);
        let max = Duration::from_secs(3_600);

        for attempts in [1_i64, 5, 10, 20, 40, 1_000, i64::MAX] {
            let delay = backoff(attempts, base, max);
            assert!(
                delay <= max,
                "attempt {attempts}: {delay:?} is past the ceiling {max:?}"
            );
        }
        // And the exponent really does reach the ceiling rather than overflowing
        // back down to something small.
        assert!(backoff(20, base, max).as_secs() >= 2_700);
    }

    #[test]
    fn backoff_of_zero_stays_zero_rather_than_dividing_by_it() {
        assert_eq!(
            backoff(1, Duration::ZERO, Duration::ZERO),
            Duration::ZERO,
            "a zero base is what the tests use to retry immediately"
        );
    }

    #[test]
    fn backoff_treats_a_zeroth_attempt_as_the_first() {
        // `claim_next` increments before the handler runs, so `attempts` is
        // never 0 here — but an underflow would be a panic, not a wrong delay.
        let delay = backoff(0, Duration::from_secs(30), Duration::from_secs(3_600));
        assert!(delay.as_secs() >= 22 && delay.as_secs() <= 30);
    }
}
