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

/// The pacing derived from `[jobs]`, re-derived on every pass of the loop.
///
/// Held by value rather than read through the cell at each use, so one pass
/// cannot claim a job under one lease and settle it under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunnerConfig {
    poll_interval: Duration,
    lease: Duration,
    retry_base: Duration,
    retry_max: Duration,
    max_concurrent: usize,
}

impl RunnerConfig {
    fn from(config: &JobsConfig) -> Self {
        Self {
            poll_interval: Duration::from_millis(config.poll_interval_ms),
            lease: Duration::from_secs(config.lease_seconds),
            retry_base: Duration::from_secs(config.retry_base_seconds),
            retry_max: Duration::from_secs(config.retry_max_seconds),
            // Clamped rather than trusted: `Semaphore` panics above its own
            // ceiling, and this value now arrives from a reload as well as from
            // startup — a panic taking the runner down mid-flight is a great
            // deal worse than one at startup, where at least nothing was
            // running yet.
            max_concurrent: config.max_concurrent.clamp(1, Semaphore::MAX_PERMITS),
        }
    }
}

/// The concurrency pool, and how large it currently actually is.
///
/// A [`Semaphore`] has no `resize`, and the asymmetry between its two halves is
/// the whole reason this type exists: `add_permits` always lands, but
/// `forget_permits` can only take back permits that are *free*, and reports how
/// many it got. So a reload that lowers `jobs.max_concurrent` while every slot
/// is busy takes what it can now and converges as running jobs return theirs —
/// in-flight work is never cancelled to reach a number.
///
/// [`capacity`](Permits::capacity) is therefore what this pool has really
/// issued, which may still be above the configured target. That is the number a
/// graceful stop must wait for: draining against the target would return before
/// the permits above it came back.
struct Permits {
    semaphore: Arc<Semaphore>,
    capacity: usize,
}

impl Permits {
    fn new(capacity: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
        }
    }

    /// Moves the pool towards `target`, as far as it can go right now.
    fn resize(&mut self, target: usize) {
        match target.cmp(&self.capacity) {
            std::cmp::Ordering::Greater => {
                self.semaphore.add_permits(target - self.capacity);
                self.capacity = target;
            }
            std::cmp::Ordering::Less => {
                self.capacity -= self.semaphore.forget_permits(self.capacity - target);
            }
            std::cmp::Ordering::Equal => {}
        }
    }
}

/// Starts the runner over a registry that never changes.
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
    // Two channels whose senders are dropped on the spot. A dropped sender does
    // **not** mean `changed()` stops firing — it means it returns `Err` at once
    // and for ever, which in a `select!` is a permanently ready arm and a loop
    // that spins. So the loop treats that `Err` as "this cell is fixed" and
    // disables the arm; these two lines are then exactly "nothing here reloads"
    // without a second code path through the loop.
    let (_registry_sender, registry_rx) = watch::channel(registry);
    let (_config_sender, config_rx) = watch::channel(Arc::new(config.clone()));
    spawn_runner_watching(queue, registry_rx, config_rx, shutdown)
}

/// Starts the runner over a registry and a `[jobs]` section the caller can
/// replace.
///
/// The reload path publishes into both cells rather than restarting the runner,
/// and they carry different halves of `[jobs]`. The **registry** carries the
/// values a handler captured: sweep cutoffs (`nonce.ttl_seconds`,
/// `audit.retention_days`, `jobs.retention_days`) are built into `SweepJob`s, so
/// a changed retention only takes effect through a new registry — and one going
/// `0 → N` registers a handler that did not exist at all, which is why
/// [`recover`](JobHandler::recover) runs again for kinds the previous generation
/// did not have. The **config** cell carries the runner's own pacing, which it
/// re-derives on each pass; see [`RunnerConfig`] and [`Permits`].
pub fn spawn_runner_watching(
    queue: JobQueue,
    registry: watch::Receiver<Arc<JobRegistry>>,
    config: watch::Receiver<Arc<JobsConfig>>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_loop(queue, registry, config, shutdown).await;
    })
}

async fn run_loop(
    queue: JobQueue,
    mut registry_rx: watch::Receiver<Arc<JobRegistry>>,
    mut config_rx: watch::Receiver<Arc<JobsConfig>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let runner_id = uuid::Uuid::new_v4().to_string();
    let database = queue.database().clone();
    let mut registry = registry_rx.borrow_and_update().clone();
    let mut config = RunnerConfig::from(&config_rx.borrow_and_update());
    let mut permits = Permits::new(config.max_concurrent);

    info!(
        event = "job_runner_started",
        outcome = "progress",
        runner_id = %runner_id,
        job_kinds = ?registry.kinds(),
        max_concurrent = config.max_concurrent,
    );

    // Before the loop: every handler gets one chance to re-derive work a
    // previous process left unfinished. An enqueue, not a spawn — and safely
    // repeatable, because the identity index refuses a duplicate.
    let mut recovered: Vec<&'static str> = registry.kinds();
    for handler in registry.handlers() {
        handler.recover(&queue).await;
    }

    // Whether the last pass ran out of slots, which arms the permit arm below.
    let mut saturated;

    loop {
        // Both cells are read at the **top of the pass**, not in the arms that
        // wake on them. An arm can only apply what it caught, and a pass can be
        // entered from five different wake-ups; reading here is what makes "the
        // loop always runs on the newest generation" true by construction rather
        // than by every arm remembering to do it.
        registry = registry_rx.borrow_and_update().clone();
        recover_new_kinds(&queue, &registry, &mut recovered).await;

        let next = RunnerConfig::from(&config_rx.borrow_and_update());
        if next != config {
            config = next;
            retuned(&runner_id, config);
        }

        // A cell whose last sender has gone must have its arm **disabled**, not
        // merely handled: `changed()` on a closed channel returns `Err` at once
        // and for ever, which in a `select!` is a permanently ready arm and a
        // loop that spins rather than sleeps. `has_changed` asks without
        // consuming the marker the `borrow_and_update`s above rely on, and asking
        // once per pass is what keeps `spawn_runner`'s fixed cells free — see
        // there for why they are dropped senders in the first place.
        let watching_registry = registry_rx.has_changed().is_ok();
        let watching_config = config_rx.has_changed().is_ok();

        // Rows whose runner died holding the lease. Runs before claiming so a
        // crashed process's work is eligible on this pass rather than the next.
        if let Err(error) = Job::reclaim_expired(now_secs(), &database).await {
            error!(event = "job_reclaim_failed", outcome = "failure", error = %error);
        }

        saturated = drain_ready(&queue, &registry, &config, &mut permits, &runner_id).await;

        // Idle: whichever comes first. `notified()` is what keeps a job queued
        // by a request from waiting on `poll_interval`; the two cell arms are
        // what make a *lowered* `poll_interval_ms` land at once rather than
        // after one more sleep at the old, longer value; and the permit arm is
        // how a saturated pool resumes the moment a slot frees.
        //
        // That last arm is why `drain_ready` never waits for a permit itself. It
        // used to, and a full pool therefore parked this loop — so under exactly
        // the sustained backlog that makes an operator want to raise
        // `jobs.max_concurrent`, neither the raise nor a shutdown would have been
        // noticed until the queue went quiet on its own.
        tokio::select! {
            () = queue.notify.notified() => {}
            () = tokio::time::sleep(config.poll_interval) => {}
            () = permit_available(&permits.semaphore), if saturated => {}
            // Both are pure wake-ups: what they carry is read at the top of the
            // next pass, not here. A sender dropped between the check above and
            // this point costs one spurious pass and is disabled by the next
            // check, which is as much as a race here can be worth.
            _ = registry_rx.changed(), if watching_registry => {}
            _ = config_rx.changed(), if watching_config => {}
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
    }

    stop(&runner_id, &database, &permits).await;
}

/// Resolves once the pool has a slot free.
///
/// The permit is taken and dropped on the spot: this is a readiness signal, not
/// a claim on a slot — [`drain_ready`] takes the real one on the pass that
/// follows. Cancel-safe, which it has to be to sit in a `select!`: losing the
/// place in the queue costs nothing when the thing being waited for is only
/// "somebody finished".
async fn permit_available(semaphore: &Semaphore) {
    let _ = semaphore.acquire().await;
}

/// Says a reload moved this runner's pacing, and to what.
///
/// The one line that tells an operator a `[jobs]` edit actually landed — the
/// supervisor's `server_config_reloaded` says a generation was published, not
/// that the runner picked it up. Only emitted when the derived pacing really
/// moved, so a reload of some unrelated section is silent here.
fn retuned(runner_id: &str, config: RunnerConfig) {
    info!(
        event = "job_runner_retuned",
        outcome = "success",
        runner_id = %runner_id,
        poll_interval_ms = crate::millis(config.poll_interval),
        lease_seconds = config.lease.as_secs(),
        retry_base_seconds = config.retry_base.as_secs(),
        retry_max_seconds = config.retry_max.as_secs(),
        max_concurrent = config.max_concurrent,
    );
}

/// Runs `recover` for handlers this runner has not yet recovered for.
///
/// Restricted to *new* kinds rather than the whole registry, because `recover`
/// is not uniformly cheap: a sweep's is one guarded enqueue, but
/// `RelayJob::recover` queries the database and logs a line about resuming
/// in-flight orders — which would be untrue, and noise, on every reload.
async fn recover_new_kinds(
    queue: &JobQueue,
    registry: &JobRegistry,
    recovered: &mut Vec<&'static str>,
) {
    for handler in registry.handlers() {
        let kind = handler.kind();
        if recovered.contains(&kind) {
            continue;
        }
        recovered.push(kind);
        handler.recover(queue).await;
        // After the pass, not before: `_recovered` claims the work is done, and
        // `recover` is the one place a new generation's handler re-derives what
        // it is owed.
        info!(
            event = "job_handler_recovered",
            outcome = "success",
            job_kind = kind,
        );
    }
}

/// Claims and starts everything currently eligible, up to the permit pool.
///
/// The permit is acquired **before** the claim, and that order is the trap worth
/// naming: claiming first would start every backlogged row's lease ticking while
/// it sat waiting for a permit, and each would then be reclaimed as "crashed"
/// having never run.
///
/// The pool is resized here rather than once per pass, and that is where a
/// lowered `jobs.max_concurrent` gets its teeth: the moment before handing out a
/// slot is the moment to give back the ones this runner owes, so a shrink cannot
/// be overtaken by the very admissions it was meant to stop.
///
/// Returns whether it stopped because the pool was full rather than because the
/// queue was empty — the caller arms `permit_available` on that, and the reason
/// it must **never wait for a permit here** is in `run_loop`'s `select!`.
async fn drain_ready(
    queue: &JobQueue,
    registry: &Arc<JobRegistry>,
    config: &RunnerConfig,
    permits: &mut Permits,
    runner_id: &str,
) -> bool {
    let kinds = registry.kinds();
    if kinds.is_empty() {
        return false;
    }
    let database = queue.database().clone();

    loop {
        permits.resize(config.max_concurrent);
        let permit = match Arc::clone(&permits.semaphore).try_acquire_owned() {
            Ok(permit) => permit,
            // Every slot is busy: this pass is over and the caller waits on a
            // slot rather than on the clock.
            Err(tokio::sync::TryAcquireError::NoPermits) => return true,
            // Closed: the runner is going away, and there is nothing to wait for.
            Err(tokio::sync::TryAcquireError::Closed) => return false,
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
            Ok(None) => return false, // nothing eligible; `permit` drops here
            Err(error) => {
                error!(event = "job_claim_failed", outcome = "failure", error = %error);
                return false;
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
async fn stop(runner_id: &str, database: &Database, permits: &Permits) {
    // Every permit back means every spawned job has finished. A timeout here is
    // not a failure: the lease release below is what makes an unfinished job the
    // next process's rather than a lost one.
    //
    // Against the pool's *issued* capacity, not against `jobs.max_concurrent`: a
    // shrink that has not finished converging leaves the two different, and
    // waiting on the smaller of them would return while jobs were still running.
    let drained = tokio::time::timeout(
        DRAIN_BUDGET,
        permits
            .semaphore
            .acquire_many(u32::try_from(permits.capacity.max(1)).unwrap_or(u32::MAX)),
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
        recovers: AtomicUsize,
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
                recovers: AtomicUsize::new(0),
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
                recovers: AtomicUsize::new(0),
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

        fn recovers(&self) -> usize {
            self.recovers.load(Ordering::SeqCst)
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

        async fn recover(&self, _queue: &JobQueue) {
            self.recovers.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A handler that records how many of its own attempts ever overlapped.
    ///
    /// The peak is the only thing that can answer "did `jobs.max_concurrent`
    /// reach the pool?" — the *number of jobs run* is the same either way, and
    /// only how many ran at once is different.
    struct Concurrent {
        kind: &'static str,
        work: Duration,
        live: AtomicUsize,
        peak: AtomicUsize,
    }

    impl Concurrent {
        fn new(kind: &'static str, work: Duration) -> Self {
            Self {
                kind,
                work,
                live: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JobHandler for Concurrent {
        fn kind(&self) -> &'static str {
            self.kind
        }

        async fn run(&self, _job: &Job) -> JobOutcome {
            let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(live, Ordering::SeqCst);
            tokio::time::sleep(self.work).await;
            self.live.fetch_sub(1, Ordering::SeqCst);
            JobOutcome::Done
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
        let mut permits = Permits::new(runner.max_concurrent);

        Job::reclaim_expired(now_secs(), queue.database())
            .await
            .unwrap();
        drain_ready(queue, &registry, &runner, &mut permits, "runner-test").await;

        // Every permit back means every spawned job has settled.
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            permits
                .semaphore
                .acquire_many(u32::try_from(permits.capacity).unwrap()),
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

    /// A configuration reload publishes a new registry rather than restarting
    /// the runner, and this is what that has to buy: a kind that did not exist
    /// in the previous generation is claimed after the swap.
    ///
    /// The row is queued *before* the swap on purpose — that is the case a
    /// retention key going `0 → N` produces, where the sweep handler is new but
    /// its work may already be waiting.
    #[tokio::test]
    async fn a_swapped_registry_claims_a_kind_the_previous_one_did_not_have() {
        let config = JobsConfig {
            // Long enough that a poll tick cannot be what noticed the swap.
            poll_interval_ms: 60_000,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let old = Scripted::new("old", vec![Script::Done]);
        let new = Scripted::new("new", vec![Script::Done]);

        let mut first = JobRegistry::new();
        first.register(old.clone()).unwrap();
        let (registry_tx, registry_rx) = watch::channel(Arc::new(first));

        let (tx, rx) = watch::channel(false);
        let (_config_tx, config_rx) = watch::channel(Arc::new(config.clone()));
        let runner = spawn_runner_watching(queue.clone(), registry_rx, config_rx, rx);

        queue.enqueue(JobSpec::now("new", "k")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(new.runs(), 0, "the kind is not registered yet");
        assert_eq!(old.recovers(), 1, "the startup pass ran once");

        let mut second = JobRegistry::new();
        second.register(old.clone()).unwrap();
        second.register(new.clone()).unwrap();
        registry_tx.send_replace(Arc::new(second));

        for _ in 0..200 {
            if new.runs() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(new.runs(), 1, "the swapped-in handler must claim its row");

        // `recover` is per kind, not per generation: the newcomer gets its one
        // pass, and the handler carried across the swap is not asked again.
        assert_eq!(new.recovers(), 1, "a new kind recovers once");
        assert_eq!(old.recovers(), 1, "a carried kind must not recover again");

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
    }

    /// The half of a `jobs.max_concurrent` reload that has no waiting to do, and
    /// the half that does.
    ///
    /// Growing is a plain `add_permits` and lands whole. Shrinking can only take
    /// back slots that are *free*, so the interesting case is the one this pins:
    /// asking for fewer while every slot is busy takes what it can now, leaves
    /// `capacity` honest about what is still out there, and converges on a later
    /// pass as jobs return theirs. Nothing running is ever cancelled to reach the
    /// number.
    #[tokio::test]
    async fn resize_grows_at_once_and_shrinks_as_slots_come_back() {
        let mut permits = Permits::new(2);

        permits.resize(5);
        assert_eq!(permits.capacity, 5);
        assert_eq!(permits.semaphore.available_permits(), 5);

        // Every slot busy: a shrink has nothing to take yet.
        let mut held: Vec<_> = (0..5)
            .map(|_| Arc::clone(&permits.semaphore).try_acquire_owned().unwrap())
            .collect();
        permits.resize(1);
        assert_eq!(
            permits.capacity, 5,
            "a shrink must not pretend to have taken back a slot somebody is using",
        );

        // Two jobs finish; the next pass reclaims exactly those two.
        held.truncate(3);
        permits.resize(1);
        assert_eq!(permits.capacity, 3, "it converges by whatever came back");
        assert_eq!(permits.semaphore.available_permits(), 0);

        // The rest finish: the pool finally reaches the configured size.
        drop(held);
        permits.resize(1);
        assert_eq!(permits.capacity, 1);
        assert_eq!(permits.semaphore.available_permits(), 1);
    }

    /// A lowered `jobs.poll_interval_ms` must not have to wait out the old one.
    ///
    /// This is the whole reason the config cell has a `select!` arm rather than
    /// only being read at the top of the pass: an operator who drops the interval
    /// from a minute to a moment did it because something is waiting *now*, and
    /// making them wait the old minute to find out would be the reload landing
    /// too late to be the thing they asked for.
    ///
    /// The job is queued with a delay so that its own `notify` is spent before it
    /// is eligible — leaving the sleep as the only other way the runner could
    /// have noticed it.
    #[tokio::test]
    async fn a_lowered_poll_interval_lands_without_waiting_out_the_old_one() {
        let config = JobsConfig {
            poll_interval_ms: 600_000,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", vec![Script::Done]);
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();
        let (_registry_tx, registry_rx) = watch::channel(Arc::new(registry));

        let (config_tx, config_rx) = watch::channel(Arc::new(config));
        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner_watching(queue.clone(), registry_rx, config_rx, rx);

        // Eligible a second from now, so the enqueue's own wake-up is spent on a
        // pass that finds nothing.
        queue
            .enqueue(JobSpec::now("test", "k").with_delay(Duration::from_secs(1)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(
            handler.runs(),
            0,
            "the runner is asleep on the old interval, which is the premise",
        );

        config_tx.send_replace(Arc::new(JobsConfig {
            poll_interval_ms: 5,
            ..JobsConfig::default()
        }));

        for _ in 0..200 {
            if handler.runs() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(handler.runs(), 1, "the swapped config must wake the loop");

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
    }

    /// A raised `jobs.max_concurrent` has to reach a pool that is already full,
    /// which is the only state anybody raises it from.
    ///
    /// It is also the state the loop used to be unable to observe anything in:
    /// `drain_ready` waited for a permit itself, so a saturated pool parked the
    /// whole loop and neither this reload nor a shutdown was seen until the
    /// backlog cleared on its own.
    #[tokio::test]
    async fn a_raised_max_concurrent_reaches_a_saturated_pool() {
        let config = JobsConfig {
            poll_interval_ms: 600_000,
            max_concurrent: 1,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let handler = Arc::new(Concurrent::new("test", Duration::from_millis(400)));
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();
        let (_registry_tx, registry_rx) = watch::channel(Arc::new(registry));

        let (config_tx, config_rx) = watch::channel(Arc::new(config));
        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner_watching(queue.clone(), registry_rx, config_rx, rx);

        for key in ["a", "b", "c", "d"] {
            queue.enqueue(JobSpec::now("test", key)).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(handler.peak(), 1, "one slot means one job at a time");

        config_tx.send_replace(Arc::new(JobsConfig {
            poll_interval_ms: 600_000,
            max_concurrent: 4,
            ..JobsConfig::default()
        }));

        for _ in 0..200 {
            if handler.peak() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            handler.peak() >= 3,
            "the raise must widen a pool that is already full, not the next one: \
             peak was {}",
            handler.peak(),
        );

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), runner).await;
    }

    /// A runner over cells nobody will ever write to must be *idle*, not merely
    /// correct.
    ///
    /// `spawn_runner` builds both cells and drops their senders on the spot, and
    /// a dropped `watch` sender does not make `changed()` stop firing — it makes
    /// it return `Err` immediately and for ever, which in a `select!` is an arm
    /// that is always ready. The loop would then spin, re-running
    /// `reclaim_expired` and a claim query as fast as the runtime allowed. So the
    /// loop disables an arm whose sender has gone, and this counts passes to
    /// prove it: an always-retrying handler with no backoff runs once per pass,
    /// and the poll interval here is ten minutes.
    #[tokio::test]
    async fn a_runner_over_fixed_cells_does_not_spin() {
        let config = JobsConfig {
            poll_interval_ms: 600_000,
            retry_base_seconds: 0,
            retry_max_seconds: 0,
            ..JobsConfig::default()
        };
        let queue = queue_with(&config).await;
        let handler = Scripted::new("test", (0..64).map(|_| Script::Retry).collect());
        let mut registry = JobRegistry::new();
        registry.register(handler.clone()).unwrap();

        let (tx, rx) = watch::channel(false);
        let runner = spawn_runner(queue.clone(), Arc::new(registry), &config, rx);

        queue.enqueue(JobSpec::now("test", "k")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let runs = handler.runs();
        assert!(
            runs <= 2,
            "a spinning loop re-claims every pass; {runs} runs in 300ms means the \
             dropped senders left their `select!` arms armed",
        );

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
