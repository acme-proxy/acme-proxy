//! The queue's own housekeeping: deleting settled rows once they are old.
//!
//! Deliberately a [`JobHandler`] rather than a fourth `spawn_*_reaper` beside
//! the nonce, audit and admin-session ones. Two reasons, and the second is the
//! point:
//!
//! - It is the worked example of [`JobOutcome::Reschedule`]. A periodic job is
//!   one row that puts itself back in the queue, so there is no cron table to
//!   keep in step with the handlers, and the identity index means one occurrence
//!   exists at a time however many times recovery runs.
//! - It costs about thirty lines where a reaper costs a spawn function, an
//!   interval helper and its own test for the zero-period busy-loop hazard.
//!
//! The three existing reapers stay as they are: they sweep tables with no
//! durability requirement, and moving them here would add a database row to
//! schedule a database delete.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use super::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;

/// The `jobs.kind` the sweep runs under.
pub const RETENTION_JOB_KIND: &str = "job_retention_sweep";

/// The one row's `dedup_key`. A constant, because there is exactly one sweep —
/// and the identity index is what turns that sentence into a guarantee.
const RETENTION_JOB_KEY: &str = "all";

/// How often the sweep runs.
///
/// Daily, matching the `audit.retention_days` sweep: the setting's resolution is
/// days, so anything finer is work for nothing.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Deletes settled job rows older than `retention_days`.
pub struct JobRetention {
    database: Arc<Database>,
    retention_days: u64,
}

impl JobRetention {
    #[must_use]
    pub fn new(database: Arc<Database>, retention_days: u64) -> Self {
        Self {
            database,
            retention_days,
        }
    }
}

#[async_trait]
impl JobHandler for JobRetention {
    fn kind(&self) -> &'static str {
        RETENTION_JOB_KIND
    }

    async fn run(&self, _job: &Job) -> JobOutcome {
        // The same cutoff arithmetic `audit cleanup --older-than` and the audit
        // sweep share, so "older than N days" means one thing in the process.
        let cutoff = crate::admin::ops::audit_cutoff(self.retention_days);
        if let Err(error) = Job::cleanup(cutoff, &self.database).await {
            warn!(event = "job_retention_sweep_failed", outcome = "failure", error = %error);
        }

        // **Never `Failed`**, whatever went wrong above. A retired periodic job
        // does not re-enqueue itself, so one transient database error would
        // silently stop the sweep for the life of the process. The next
        // occurrence is a day away and will simply try again.
        JobOutcome::Reschedule(SWEEP_INTERVAL)
    }

    /// Puts the single occurrence back in the queue at startup.
    ///
    /// Harmless to run again: the identity index refuses a second live row for
    /// this kind, so a restart resumes the existing schedule rather than
    /// resetting it — which also means a server restarting more often than once
    /// a day does not skip the sweep for ever.
    async fn recover(&self, queue: &JobQueue) {
        queue
            .enqueue_or_log(JobSpec::now(RETENTION_JOB_KIND, RETENTION_JOB_KEY))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JobsConfig;
    use crate::sqlite::nonce::now_secs;
    use serde_json::json;

    async fn setup() -> (Arc<Database>, JobQueue) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let queue = JobQueue::new(database.clone(), &JobsConfig::default());
        (database, queue)
    }

    /// One row, whatever happens: the property that makes a periodic job a queue
    /// row rather than a growing pile of them.
    #[tokio::test]
    async fn recovery_queues_one_occurrence_however_often_it_runs() {
        let (database, queue) = setup().await;
        let handler = JobRetention::new(database.clone(), 7);

        handler.recover(&queue).await;
        handler.recover(&queue).await;
        handler.recover(&queue).await;

        let live = Job::find_live(RETENTION_JOB_KIND, RETENTION_JOB_KEY, &database)
            .await
            .unwrap();
        assert!(live.is_some());
    }

    #[tokio::test]
    async fn the_sweep_removes_settled_rows_and_reschedules_itself() {
        let (database, _queue) = setup().await;
        let handler = JobRetention::new(database.clone(), 7);

        // A settled row well past the retention window.
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

        let job = Job {
            id: "sweep".to_string(),
            kind: RETENTION_JOB_KIND.to_string(),
            dedup_key: RETENTION_JOB_KEY.to_string(),
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
        };

        match handler.run(&job).await {
            JobOutcome::Reschedule(delay) => assert_eq!(delay, SWEEP_INTERVAL),
            other => panic!("the sweep must reschedule itself, got {other:?}"),
        }
        assert!(
            Job::find_by_id("old", &database).await.unwrap().is_none(),
            "the stale row is gone"
        );
    }

    /// A sweep that cannot reach the database must still be scheduled again: a
    /// `Failed` here would stop the sweep for the life of the process.
    #[tokio::test]
    async fn a_failing_sweep_reschedules_rather_than_retiring() {
        let (database, _queue) = setup().await;
        let handler = JobRetention::new(database.clone(), 7);
        database.pool.close().await;

        let job = Job {
            id: "sweep".to_string(),
            kind: RETENTION_JOB_KIND.to_string(),
            dedup_key: RETENTION_JOB_KEY.to_string(),
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
        };

        assert!(matches!(handler.run(&job).await, JobOutcome::Reschedule(_)));
    }
}
