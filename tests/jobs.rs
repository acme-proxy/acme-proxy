//! The durable job runner, end to end against a real database.
//!
//! The inline suites cover the pieces: `src/sqlite/job.rs` pins every guarded
//! statement, and `src/jobs/runner.rs` drives the outcome table with a scripted
//! handler. What can only be checked here is the property the lease exists for —
//! **two runners over one database never run one job twice** — because it needs
//! two independent runners racing on the same rows rather than one loop driven
//! by hand.
//!
//! The other thing this file pins is the crash path in the shape a deployment
//! meets it: a row left `running` by a process that died, reclaimed by whoever
//! comes next. The inline tests reach that state by calling `reclaim_expired`;
//! here it is reached by a runner starting up and finding it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acme_proxy::config::JobsConfig;
use acme_proxy::jobs::{
    JobHandler, JobOutcome, JobQueue, JobRegistry, JobSpec, SweepJob, spawn_runner,
};
use acme_proxy::notify::{
    BackendSlot, NotifyBackend, NotifyDispatcher, NotifyError, NotifyEvent, NotifyJob,
    ProfileMountedData,
};
use acme_proxy::sqlite::db::Database;
use acme_proxy::sqlite::job::Job;
use async_trait::async_trait;
use tokio::sync::watch;

/// Epoch seconds, the representation every schedule column uses.
///
/// Spelled out rather than reaching for `sqlite::nonce::now_secs`, which is
/// `pub(crate)` — an integration test links against the crate from outside and
/// sees only its public surface, which is the point of testing from here.
fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Counts every run it is given, so "ran twice" is observable at all — two
/// completions leave exactly the same row as one.
struct Counting {
    kind: &'static str,
    runs: AtomicUsize,
    delay: Duration,
}

impl Counting {
    fn new(kind: &'static str, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            kind,
            runs: AtomicUsize::new(0),
            delay,
        })
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JobHandler for Counting {
    fn kind(&self) -> &'static str {
        self.kind
    }

    async fn run(&self, _job: &Job) -> JobOutcome {
        self.runs.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        JobOutcome::Done
    }
}

fn fast_config() -> JobsConfig {
    JobsConfig {
        poll_interval_ms: 5,
        lease_seconds: 60,
        ..JobsConfig::default()
    }
}

async fn database() -> Arc<Database> {
    Arc::new(Database::connect_in_memory().await.unwrap())
}

/// A runner started over `queue`, plus the sender that stops it.
fn start(
    queue: &JobQueue,
    handler: Arc<dyn JobHandler>,
    config: &JobsConfig,
) -> watch::Sender<bool> {
    let mut registry = JobRegistry::new();
    registry.register(handler).unwrap();
    let (shutdown, receiver) = watch::channel(false);
    spawn_runner(queue.clone(), Arc::new(registry), config, receiver);
    shutdown
}

/// Waits for `condition`, so an assertion is not a race against the runner.
async fn until(mut condition: impl FnMut() -> bool) {
    for _ in 0..400 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never became true");
}

/// Waits for the live job holding `(kind, key)` to disappear — i.e. settle.
async fn until_settled(kind: &str, key: &str, database: &Database) {
    for _ in 0..400 {
        if Job::find_live(kind, key, database).await.unwrap().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the job never settled");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_queued_job_is_claimed_run_and_settled() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);
    let handler = Counting::new("e2e", Duration::ZERO);
    let _stop = start(&queue, handler.clone(), &config);

    assert!(queue.enqueue(JobSpec::now("e2e", "one")).await.unwrap());

    until(|| handler.runs() == 1).await;
    until_settled("e2e", "one", &database).await;
}

/// The property the whole lease design exists for. Both runners are draining
/// the same table as fast as they can; the guarded claim is the only thing
/// stopping them from each taking the same row.
#[tokio::test(flavor = "multi_thread")]
async fn two_runners_over_one_database_never_run_one_job_twice() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);

    // A separate handler per runner, so the counts are attributable — one
    // shared counter could not tell "each ran ten" from "one ran twenty".
    let first = Counting::new("e2e", Duration::from_millis(5));
    let second = Counting::new("e2e", Duration::from_millis(5));
    let _stop_first = start(&queue, first.clone(), &config);
    let _stop_second = start(&queue, second.clone(), &config);

    const JOBS: usize = 25;
    for n in 0..JOBS {
        assert!(
            queue
                .enqueue(JobSpec::now("e2e", n.to_string()))
                .await
                .unwrap()
        );
    }

    until(|| first.runs() + second.runs() >= JOBS).await;
    // Settle: give any duplicate a chance to show up before asserting it did not.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        first.runs() + second.runs(),
        JOBS,
        "every job ran exactly once ({} + {})",
        first.runs(),
        second.runs()
    );
}

/// The crash path as a deployment meets it: a previous process died holding the
/// lease, and the row must not sit `running` for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_stranded_by_a_dead_process_is_reclaimed_and_finished() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);
    assert!(
        queue
            .enqueue(JobSpec::now("e2e", "stranded"))
            .await
            .unwrap()
    );

    // Stand in for the dead process: claim the row with a lease that has
    // already expired, and never settle it.
    let claimed = Job::claim_next(
        "dead-runner",
        &["e2e"],
        now_secs() - 1,
        now_secs(),
        &database,
    )
    .await
    .unwrap()
    .expect("the job must be claimable");
    assert_eq!(claimed.status, "running");
    assert_eq!(claimed.attempts, 1);

    let handler = Counting::new("e2e", Duration::ZERO);
    let _stop = start(&queue, handler.clone(), &config);

    until(|| handler.runs() == 1).await;
    let settled = Job::find_by_id(&claimed.id, &database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.status, "done");
    assert_eq!(
        settled.attempts, 2,
        "the dead process's attempt is still counted: a job that kills whatever \
         runs it must not loop for ever"
    );
}

/// A kind no handler is registered for belongs to some other build, or to a
/// subsystem that is switched off. It must be left where it is rather than
/// claimed and stranded.
#[tokio::test(flavor = "multi_thread")]
async fn a_kind_this_build_does_not_know_is_left_untouched() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);
    let handler = Counting::new("e2e", Duration::ZERO);
    let _stop = start(&queue, handler.clone(), &config);

    assert!(
        queue
            .enqueue(JobSpec::now("from-a-newer-build", "one"))
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(handler.runs(), 0);
    let job = Job::find_live("from-a-newer-build", "one", &database)
        .await
        .unwrap()
        .expect("the row survives for a build that knows the kind");
    assert_eq!(job.status, "ready");
    assert_eq!(job.attempts, 0, "it was never claimed");
}

/// A notification, end to end through the queue: dispatched by one component,
/// delivered by the runner, settled on its row.
///
/// The inline suites cover the two halves — `src/notify/mod.rs` proves
/// `dispatch` writes a row per wanting backend, `src/notify/job.rs` proves the
/// handler maps a delivery onto an outcome. What only this file can show is that
/// they are the same row: that nothing in between has to be woken by hand, and
/// that a delivered notification leaves no live job behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_dispatched_notification_is_delivered_through_the_queue() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);

    let delivered = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingNotifier(delivered.clone()));
    let every: Vec<String> = acme_proxy::config::ALL_NOTIFY_EVENTS
        .iter()
        .map(|kind| (*kind).to_string())
        .collect();
    let dispatcher = Arc::new(NotifyDispatcher::new(
        "le",
        vec![BackendSlot::new("counting", backend, &every)],
        queue.clone(),
    ));
    let mut dispatchers = std::collections::HashMap::new();
    dispatchers.insert("le".to_string(), dispatcher.clone());

    let _stop = start(
        &queue,
        Arc::new(NotifyJob::new(Arc::new(dispatchers))),
        &config,
    );

    dispatcher
        .dispatch(NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: "le".to_string(),
        }))
        .await;

    until(|| delivered.load(Ordering::SeqCst) == 1).await;

    // Delivered exactly once, and nothing is still owed. The settle is a second
    // write after the delivery, so the row is read after a beat rather than the
    // instant the counter moved.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    assert_eq!(
        Job::count_live("notify_deliver", &database).await.unwrap(),
        0,
        "a delivered notification leaves no live row"
    );
}

/// A backend counting its deliveries, so "delivered twice" is observable.
struct CountingNotifier(Arc<AtomicUsize>);

#[async_trait]
impl NotifyBackend for CountingNotifier {
    fn name(&self) -> &'static str {
        "counting"
    }

    async fn send(&self, _event: &NotifyEvent) -> Result<(), NotifyError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The sweeps, through a real runner: `recover` queues the single occurrence,
/// the runner performs it, and the row goes straight back to `ready` with a
/// future `run_at` rather than settling.
///
/// That last part is what makes a periodic job one row instead of a growing pile
/// of them, and it is the difference from every other kind in the queue.
#[tokio::test(flavor = "multi_thread")]
async fn a_sweep_reschedules_itself_rather_than_settling() {
    let database = database().await;
    let config = fast_config();
    let queue = JobQueue::new(database.clone(), &config);

    // A nonce sweep, whose interval is the shortest of the four.
    let _stop = start(
        &queue,
        Arc::new(SweepJob::nonces(database.clone(), Duration::from_secs(300))),
        &config,
    );

    // `recover` runs before the loop, so the row appears without an enqueue
    // here. Waiting for a `run_at` in the future is what proves it has already
    // run once rather than merely been queued.
    let mut job = None;
    for _ in 0..400 {
        let live = Job::find_live("nonce_sweep", "all", &database)
            .await
            .unwrap();
        if let Some(live) = live
            && live.run_at > now_secs()
        {
            job = Some(live);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let job = job.expect("the sweep never ran and rescheduled itself");

    assert_eq!(job.status, "ready", "still live, not settled");
    assert_eq!(job.attempts, 0, "`Reschedule` resets the attempt count");
    assert!(
        job.run_at >= now_secs() + 100,
        "the next occurrence is a whole interval away, not immediate"
    );
    assert_eq!(
        Job::count_live("nonce_sweep", &database).await.unwrap(),
        1,
        "one row, however many times it has run"
    );
}
