//! The periodic table sweeps, as jobs.
//!
//! Four tables accumulate rows nobody deletes on the way past — spent nonces,
//! audit rows past their retention, expired admin sessions, and the queue's own
//! settled jobs. Each used to be its own `tokio::spawn` + `tokio::time::interval`
//! loop, and each was a near-copy of the others: the same
//! `MissedTickBehavior::Delay`, the same skipped first tick, the same
//! `match cleanup(...)` arms. Only the fourth was ever a job.
//!
//! They are all one handler now, over a [`SweepTarget`] that says which table.
//! Three things come out of that beyond the deletion of three spawn functions:
//!
//! - **A sweep that dies is reclaimed.** An interval loop that panicked was gone
//!   until the next restart, and nothing said so. A lease expires and another
//!   runner takes the row.
//! - **The schedule survives a restart.** A server restarting more often than
//!   once a day used to skip the daily sweeps for ever, because each start reset
//!   the interval. The row keeps its own `run_at`.
//! - **One mechanism.** [`JobOutcome::Reschedule`] is how periodic work is
//!   spelled here, and there is no longer a second answer to "how do I run
//!   something every N seconds".
//!
//! What it costs is a dependency: the sweeps stop if the runner does. That is
//! the trade, and it is the reason `run` **never returns
//! [`JobOutcome::Failed`]** — a retired periodic job does not re-enqueue itself,
//! so a single transient database error would silently stop a sweep for the life
//! of the process.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use super::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;

/// The one row's `dedup_key`, for every sweep.
///
/// A constant, because there is exactly one occurrence of each — and the partial
/// identity index is what turns that sentence into a guarantee.
const SWEEP_KEY: &str = "all";

/// The `jobs.kind` the queue's own retention sweep runs under.
///
/// Named for the job it has always been rather than renamed to match its three
/// new siblings: rows already carry this string, and the freeze on `migrations/`
/// is not the only place a stored value outlives the code that wrote it.
pub const RETENTION_JOB_KIND: &str = "job_retention_sweep";

/// The `jobs.kind` the expired-nonce sweep runs under.
pub const NONCE_SWEEP_KIND: &str = "nonce_sweep";

/// The `jobs.kind` the audit-retention sweep runs under.
pub const AUDIT_SWEEP_KIND: &str = "audit_sweep";

/// The `jobs.kind` the admin-session sweep runs under.
pub const ADMIN_SESSION_SWEEP_KIND: &str = "admin_session_sweep";

/// How often the daily sweeps run.
///
/// Both settings behind them have a resolution of days, so anything finer is
/// work for nothing — and an audit row a few hours past a 90-day retention is
/// nobody's problem.
const DAILY: Duration = Duration::from_secs(24 * 60 * 60);

/// Which table a sweep deletes from, and what it needs to know to do it.
#[derive(Debug, Clone, Copy)]
enum SweepTarget {
    /// Expired nonces.
    Nonces { ttl: Duration },
    /// Audit rows past `audit.retention_days`.
    AuditLog { retention_days: u64 },
    /// Admin sessions past their absolute or idle deadline.
    AdminSessions { idle_timeout: Duration },
    /// Settled job rows past `jobs.retention_days`.
    Jobs { retention_days: u64 },
}

/// One periodic table sweep.
pub struct SweepJob {
    target: SweepTarget,
    interval: Duration,
    database: Arc<Database>,
}

impl SweepJob {
    /// The expired-nonce sweep.
    ///
    /// Runs every half TTL rather than every TTL: sweeping once per lifetime
    /// leaves a row alive for up to *twice* its TTL, so the table sits at roughly
    /// two TTLs' worth of traffic. Halving that costs one query per period.
    /// Floored at 30s so a very short `nonce.ttl_seconds` cannot turn this into a
    /// busy loop taking the WAL writer lock.
    #[must_use]
    pub fn nonces(database: Arc<Database>, ttl: Duration) -> Self {
        Self {
            target: SweepTarget::Nonces { ttl },
            interval: (ttl / 2).max(Duration::from_secs(30)),
            database,
        }
    }

    /// The audit-retention sweep. Registered only when
    /// `audit.retention_days` is non-zero — `0` means "keep everything", which
    /// is a handler not registered rather than a `DELETE` with a cutoff at the
    /// epoch.
    #[must_use]
    pub fn audit(database: Arc<Database>, retention_days: u64) -> Self {
        Self {
            target: SweepTarget::AuditLog { retention_days },
            interval: DAILY,
            database,
        }
    }

    /// The admin-session sweep, registered only when the admin listener exists.
    ///
    /// Often enough that a revoked session's row does not linger for hours,
    /// rarely enough to be invisible.
    #[must_use]
    pub fn admin_sessions(
        database: Arc<Database>,
        idle_timeout: Duration,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            target: SweepTarget::AdminSessions { idle_timeout },
            interval: Duration::from_secs((ttl_seconds / 4).max(60)),
            database,
        }
    }

    /// The queue's own sweep. Registered only when `jobs.retention_days` is
    /// non-zero, for the same reason as the audit one.
    #[must_use]
    pub fn jobs(database: Arc<Database>, retention_days: u64) -> Self {
        Self {
            target: SweepTarget::Jobs { retention_days },
            interval: DAILY,
            database,
        }
    }

    /// How often this sweep runs.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Deletes one table's worth, logging what went and swallowing a failure.
    ///
    /// The event names are the ones these sweeps have always emitted, from back
    /// when each was its own reaper task: an operator's dashboards and
    /// `doc/src/operations/monitoring.md` name them, and the mechanism changing
    /// underneath is not a reason to make them re-learn the vocabulary.
    async fn sweep(&self) {
        match self.target {
            SweepTarget::Nonces { ttl } => {
                match crate::sqlite::nonce::Nonce::cleanup(&self.database, ttl).await {
                    Ok(removed) => debug!(
                        event = "nonce_reaper_swept",
                        outcome = "success",
                        rows_removed = removed
                    ),
                    Err(error) => {
                        error!(event = "nonce_reaper_failed", outcome = "failure", error = %error);
                    }
                }
            }
            SweepTarget::AuditLog { retention_days } => {
                // The same cutoff arithmetic `audit cleanup --older-than` uses,
                // so "older than N days" means one thing in the process.
                let cutoff = crate::admin::ops::audit_cutoff(retention_days);
                match crate::sqlite::audit::AuditEntry::cleanup(cutoff, &self.database).await {
                    Ok(removed) => info!(
                        event = "audit_reaper_swept",
                        outcome = "success",
                        rows_removed = removed,
                        cutoff
                    ),
                    Err(error) => {
                        error!(event = "audit_reaper_failed", outcome = "failure", error = %error);
                    }
                }
            }
            SweepTarget::AdminSessions { idle_timeout } => {
                match crate::sqlite::admin_session::AdminSession::cleanup(
                    idle_timeout,
                    &self.database,
                )
                .await
                {
                    Ok(removed) => debug!(
                        event = "admin_session_reaper_swept",
                        outcome = "success",
                        rows_removed = removed
                    ),
                    Err(error) => {
                        error!(event = "admin_session_reaper_failed", outcome = "failure", error = %error);
                    }
                }
            }
            SweepTarget::Jobs { retention_days } => {
                let cutoff = crate::admin::ops::audit_cutoff(retention_days);
                if let Err(error) = Job::cleanup(cutoff, &self.database).await {
                    warn!(event = "job_retention_sweep_failed", outcome = "failure", error = %error);
                }
            }
        }
    }
}

#[async_trait]
impl JobHandler for SweepJob {
    fn kind(&self) -> &'static str {
        match self.target {
            SweepTarget::Nonces { .. } => NONCE_SWEEP_KIND,
            SweepTarget::AuditLog { .. } => AUDIT_SWEEP_KIND,
            SweepTarget::AdminSessions { .. } => ADMIN_SESSION_SWEEP_KIND,
            SweepTarget::Jobs { .. } => RETENTION_JOB_KIND,
        }
    }

    async fn run(&self, _job: &Job) -> JobOutcome {
        self.sweep().await;
        // **Never `Failed`**, whatever happened above — see the module docs.
        JobOutcome::Reschedule(self.interval)
    }

    /// Puts the single occurrence back in the queue at startup, which is also
    /// what performs the first sweep: `run_at` is now, so the runner claims it
    /// on its first pass and there is no separate startup sweep to write.
    ///
    /// Harmless to run again — the identity index refuses a second live row for
    /// this kind, so a restart resumes the existing schedule rather than
    /// resetting it, and a server restarting more often than the interval no
    /// longer skips the sweep for ever.
    async fn recover(&self, queue: &JobQueue) {
        queue
            .enqueue_or_log(JobSpec::now(self.kind(), SWEEP_KEY))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JobsConfig;
    use crate::sqlite::nonce::{Nonce, now_secs};
    use serde_json::json;

    async fn setup() -> (Arc<Database>, JobQueue) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let queue = JobQueue::new(database.clone(), &JobsConfig::default());
        (database, queue)
    }

    /// A claimed row, as the runner would hand one to `run`.
    fn row(kind: &str) -> Job {
        Job {
            id: "sweep".to_string(),
            kind: kind.to_string(),
            dedup_key: SWEEP_KEY.to_string(),
            payload: json!({}),
            status: "running".to_string(),
            run_at: now_secs(),
            attempts: 1,
            max_attempts: 5,
            deadline: None,
            lease_until: None,
            lease_owner: None,
            last_error: None,
            created_at: now_secs(),
            updated_at: now_secs(),
        }
    }

    /// Every sweep answers a distinct kind, or two of them would claim each
    /// other's rows — the registry refuses a duplicate, so this would be a
    /// startup failure rather than silent, but it is cheaper to assert here.
    #[tokio::test]
    async fn each_target_answers_its_own_kind() {
        let (database, _queue) = setup().await;
        let kinds = [
            SweepJob::nonces(database.clone(), Duration::from_secs(300)).kind(),
            SweepJob::audit(database.clone(), 7).kind(),
            SweepJob::admin_sessions(database.clone(), Duration::from_secs(3600), 43200).kind(),
            SweepJob::jobs(database, 7).kind(),
        ];
        let unique: std::collections::BTreeSet<_> = kinds.iter().collect();
        assert_eq!(unique.len(), kinds.len(), "{kinds:?}");
    }

    /// The intervals the three former reapers were derived at, which moved here
    /// with them. The floors are what stop a short TTL becoming a busy loop
    /// taking the WAL writer lock on every tick.
    #[tokio::test]
    async fn the_intervals_keep_their_floors() {
        let (database, _queue) = setup().await;

        // Half the TTL, floored at 30s.
        assert_eq!(
            SweepJob::nonces(database.clone(), Duration::from_secs(300)).interval(),
            Duration::from_secs(150)
        );
        assert_eq!(
            SweepJob::nonces(database.clone(), Duration::from_secs(10)).interval(),
            Duration::from_secs(30)
        );

        // A quarter of the session TTL, floored at 60s.
        assert_eq!(
            SweepJob::admin_sessions(database.clone(), Duration::from_secs(3600), 43200).interval(),
            Duration::from_secs(10800)
        );
        assert_eq!(
            SweepJob::admin_sessions(database.clone(), Duration::from_secs(3600), 4).interval(),
            Duration::from_secs(60)
        );

        // Daily, both of them.
        assert_eq!(SweepJob::audit(database.clone(), 7).interval(), DAILY);
        assert_eq!(SweepJob::jobs(database, 7).interval(), DAILY);
    }

    #[tokio::test]
    async fn the_nonce_sweep_removes_expired_rows_and_reschedules() {
        let (database, _queue) = setup().await;
        let ttl = Duration::from_secs(300);

        let fresh = Nonce::new();
        fresh.save(&database).await.unwrap();
        sqlx::query("INSERT INTO nonces (value, created_at) VALUES ('stale', ?);")
            .bind(now_secs() - 3600)
            .execute(&database.pool)
            .await
            .unwrap();

        let handler = SweepJob::nonces(database.clone(), ttl);
        match handler.run(&row(NONCE_SWEEP_KIND)).await {
            JobOutcome::Reschedule(delay) => assert_eq!(delay, Duration::from_secs(150)),
            other => panic!("{other:?}"),
        }

        assert!(
            !Nonce::verify("stale".to_string(), &database, ttl)
                .await
                .unwrap(),
            "the expired nonce is gone"
        );
        assert!(
            Nonce::verify(fresh.value.clone(), &database, ttl)
                .await
                .unwrap(),
            "a fresh nonce survives its own sweep"
        );
    }

    #[tokio::test]
    async fn the_audit_sweep_removes_rows_past_the_retention() {
        let (database, _queue) = setup().await;
        // Written through the model, then backdated: the row's shape is the
        // production one, and only its age is a fixture.
        crate::sqlite::audit::AuditEntry::insert(
            crate::audit::AuditRecord::new(
                crate::audit::AuditEvent::CertificateIssued,
                "default",
                crate::audit::Actor::system(),
            ),
            &database,
        )
        .await
        .unwrap();
        let stale = now_secs() - 30 * 24 * 60 * 60;
        sqlx::query("UPDATE audit_log SET created_at = ?;")
            .bind(stale)
            .execute(&database.pool)
            .await
            .unwrap();

        let handler = SweepJob::audit(database.clone(), 7);
        assert!(matches!(
            handler.run(&row(AUDIT_SWEEP_KIND)).await,
            JobOutcome::Reschedule(_)
        ));

        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn the_admin_session_sweep_removes_expired_rows() {
        let (database, _queue) = setup().await;
        crate::sqlite::admin_user::AdminUser::create("ops", "hash", &database)
            .await
            .unwrap();
        let user = crate::sqlite::admin_user::AdminUser::find_by_username("ops", &database)
            .await
            .unwrap()
            .unwrap();
        crate::sqlite::admin_session::AdminSession::create(
            crate::sqlite::admin_session::NewSession {
                user_id: &user.id,
                token_hash: "hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            Duration::from_secs(3600),
            &database,
        )
        .await
        .unwrap();
        // Backdated past its own absolute deadline, which is what the sweep
        // deletes on.
        sqlx::query("UPDATE admin_sessions SET expires_at = ?;")
            .bind(now_secs() - 60)
            .execute(&database.pool)
            .await
            .unwrap();

        let handler = SweepJob::admin_sessions(database.clone(), Duration::from_secs(3600), 43200);
        assert!(matches!(
            handler.run(&row(ADMIN_SESSION_SWEEP_KIND)).await,
            JobOutcome::Reschedule(_)
        ));

        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_sessions;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn the_queue_sweep_removes_settled_rows() {
        let (database, _queue) = setup().await;
        let stale = now_secs() - 30 * 24 * 60 * 60;
        sqlx::query(
            "INSERT INTO jobs (id, kind, dedup_key, payload, status, run_at, attempts, \
             max_attempts, created_at, updated_at) \
             VALUES ('old', 'test', 'k', '{}', 'failed', ?, 1, 1, ?, ?);",
        )
        .bind(stale)
        .bind(stale)
        .bind(stale)
        .execute(&database.pool)
        .await
        .unwrap();

        let handler = SweepJob::jobs(database.clone(), 7);
        match handler.run(&row(RETENTION_JOB_KIND)).await {
            JobOutcome::Reschedule(delay) => assert_eq!(delay, DAILY),
            other => panic!("{other:?}"),
        }
        assert!(Job::find_by_id("old", &database).await.unwrap().is_none());
    }

    /// One row, whatever happens: the property that makes a periodic job a queue
    /// row rather than a growing pile of them.
    #[tokio::test]
    async fn recovery_queues_one_occurrence_however_often_it_runs() {
        let (database, queue) = setup().await;
        let handler = SweepJob::nonces(database.clone(), Duration::from_secs(300));

        handler.recover(&queue).await;
        handler.recover(&queue).await;
        handler.recover(&queue).await;

        assert_eq!(
            Job::count_live(NONCE_SWEEP_KIND, &database).await.unwrap(),
            1
        );
    }

    /// The law the whole module rests on: a sweep that could not reach the
    /// database must still be scheduled again. A `Failed` here would retire the
    /// row, and a retired periodic job never re-enqueues itself — so one
    /// transient error would stop that sweep for the life of the process.
    #[tokio::test]
    async fn no_target_ever_retires_itself_on_a_failure() {
        let (database, _queue) = setup().await;
        database.pool.close().await;

        for handler in [
            SweepJob::nonces(database.clone(), Duration::from_secs(300)),
            SweepJob::audit(database.clone(), 7),
            SweepJob::admin_sessions(database.clone(), Duration::from_secs(3600), 43200),
            SweepJob::jobs(database.clone(), 7),
        ] {
            let kind = handler.kind();
            assert!(
                matches!(handler.run(&row(kind)).await, JobOutcome::Reschedule(_)),
                "{kind} must reschedule rather than retire"
            );
        }
    }
}
