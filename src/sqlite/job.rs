//! The `jobs` model: the durable queue behind [`crate::jobs`].
//!
//! Every statement here is written so the *database* decides a race, never a
//! read-then-write in Rust. Two shapes carry all of it:
//!
//! - **`INSERT OR IGNORE` + `rows_affected() == 0`** for enqueue, against the
//!   partial unique index on `(kind, dedup_key)`. A `0` means a live job already
//!   holds that identity — the same guard [`crate::sqlite::upstream_order::UpstreamOrder::create`]
//!   takes on its primary key.
//! - **A guarded `UPDATE … RETURNING`** for the claim, and a guarded `UPDATE`
//!   for every settlement, each carrying `AND status = 'running' AND lease_owner
//!   = ?`. A runner whose lease expired and was reclaimed therefore cannot
//!   overwrite the row a second runner now owns: its write affects zero rows and
//!   says so.
//!
//! See `migrations/20260815120000_add_jobs.sql` for why the table has no foreign
//! key, why `kind` carries no `CHECK`, and why the identity index is partial.

use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::status::JobStatus;

/// One stored job row.
///
/// `status` and `kind` come back as the strings they were stored as, for the
/// reason [`crate::sqlite::audit::AuditEntry`] keeps `event` a `String`: an
/// older binary meeting a row a newer one wrote should render it, not refuse to
/// load. The runner never claims a `kind` its registry does not hold, so an
/// unrecognised one is simply left alone.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: Uuid,
    pub kind: String,
    pub dedup_key: String,
    pub payload: Value,
    pub status: String,
    pub run_at: i64,
    pub attempts: i64,
    pub max_attempts: i64,
    pub deadline: Option<i64>,
    pub lease_until: Option<i64>,
    pub lease_owner: Option<String>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Every column, in one place: the claim's `RETURNING` and the single-row read
/// must select the same set or `from_row` fails on whichever forgot one.
const COLUMNS: &str = "id, kind, dedup_key, payload, status, run_at, attempts, max_attempts, \
                       deadline, lease_until, lease_owner, last_error, created_at, updated_at";

/// The columns [`Job::enqueue`] writes.
///
/// A struct rather than eight positional parameters — which needed
/// `#[allow(clippy::too_many_arguments)]`, and put four `&str`/`i64` values in
/// a row where transposing two would still compile. `JobSpec` (the
/// `src/jobs/` half) is the caller-facing shape and this is the row it becomes;
/// they are deliberately separate, so the storage layer names no `src/jobs/`
/// type.
#[derive(Debug)]
pub struct NewJob<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub dedup_key: &'a str,
    pub payload: &'a Value,
    pub run_at: i64,
    pub deadline: Option<i64>,
    /// Frozen onto the row here rather than read per attempt, so raising
    /// `jobs.max_attempts` applies to new work and not to a waiting backlog.
    pub max_attempts: i64,
}

/// The filters and page window [`Job::search`] applies.
///
/// `JobQuery { limit, offset, .. }` alone is "the newest page across every
/// kind". `status` is a [`JobStatus`] because both front ends refuse an unknown
/// `--status` / `?status=` by name before this layer is reached; `kind` stays a
/// free `String` because a job kind is an open set (the migration puts no
/// `CHECK` on the column on purpose), so a value matching nothing is an
/// acceptable answer rather than one worth an error.
///
/// [`JobStatus`]: crate::sqlite::status::JobStatus
#[derive(Debug, Clone, Default)]
pub struct JobQuery {
    pub kind: Option<String>,
    pub status: Option<crate::sqlite::status::JobStatus>,
    /// The caller clamps this (`admin.page_size_max` on the HTTP side, the CLI
    /// window otherwise); this layer takes what it is given.
    pub limit: i64,
    pub offset: i64,
}

impl JobQuery {
    /// Appends the `WHERE` clause shared by the page query and the count — one
    /// function so a filter applied to only one cannot report a total the rows
    /// disagree with. Every value goes through `push_bind`.
    fn push_predicates(&self, builder: &mut sqlx::QueryBuilder<sqlx::Sqlite>) {
        crate::sqlite::query::push_equalities(
            builder,
            crate::sqlite::query::WHERE,
            &[
                ("kind = ", self.kind.as_deref()),
                ("status = ", self.status.map(JobStatus::as_str)),
            ],
        );
    }
}

impl Job {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let payload_json: String = row.try_get("payload")?;
        let payload: Value = serde_json::from_str(&payload_json)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        Ok(Self {
            id: row.try_get("id")?,
            kind: row.try_get("kind")?,
            dedup_key: row.try_get("dedup_key")?,
            payload,
            status: row.try_get("status")?,
            run_at: row.try_get("run_at")?,
            attempts: row.try_get("attempts")?,
            max_attempts: row.try_get("max_attempts")?,
            deadline: row.try_get("deadline")?,
            lease_until: row.try_get("lease_until")?,
            lease_owner: row.try_get("lease_owner")?,
            last_error: row.try_get("last_error")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    /// Queues one job, unless a live one already holds `(kind, dedup_key)`.
    ///
    /// `Ok(false)` is "already queued", not an error: it is what two racing
    /// callers must both be able to survive, and the partial unique index is
    /// what decides which of them won. A job that already reached `done` or
    /// `failed` releases the identity, so the same key can be queued again —
    /// which is what makes a retried order and a periodic sweep both expressible
    /// without a second table.
    pub async fn enqueue(row: NewJob<'_>, database: &Database) -> Result<bool, sqlx::Error> {
        let now = now_secs();
        let queued = sqlx::query(
            "INSERT OR IGNORE INTO jobs \
             (id, kind, dedup_key, payload, status, run_at, attempts, max_attempts, \
              deadline, created_at, updated_at) \
             VALUES (?, ?, ?, ?, 'ready', ?, 0, ?, ?, ?, ?);",
        )
        .bind(row.id)
        .bind(row.kind)
        .bind(row.dedup_key)
        .bind(row.payload.to_string())
        .bind(row.run_at)
        .bind(row.max_attempts)
        .bind(row.deadline)
        .bind(now)
        .bind(now)
        .execute(&database.pool)
        .await?
        .rows_affected()
            == 1;

        if queued {
            debug!(
                event = "db_job_enqueued",
                outcome = "success",
                job_id = %row.id,
                job_kind = %row.kind,
                dedup_key = %row.dedup_key,
                run_at = row.run_at,
            );
        }
        Ok(queued)
    }

    /// Claims the oldest eligible job of one of `kinds`, or `None`.
    ///
    /// One statement, and that is the point: the subselect picks a candidate and
    /// the outer `AND status = 'ready'` is what makes the pick binding, so two
    /// runners choosing the same row end with exactly one write. `None` collapses
    /// "the queue was empty" and "somebody else won" — which is correct, because
    /// the caller does the same thing either way.
    ///
    /// `attempts` increments here rather than at completion: a job that reliably
    /// kills the process must still exhaust its budget, and nothing reports back
    /// from a process that died.
    ///
    /// **`deadline` is deliberately not filtered here.** Skipping a dead row
    /// would leave it `ready` and re-read on every tick for ever; the runner
    /// claims it and retires it on the spot.
    pub async fn claim_next(
        runner_id: &str,
        kinds: &[&str],
        lease_until: i64,
        now: i64,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        if kinds.is_empty() {
            return Ok(None);
        }

        // sqlx has no array binding for SQLite, so the IN list is built from one
        // placeholder per kind — never from the values themselves. Same shape as
        // `UpstreamOrder::list_processing`, and `AssertSqlSafe` for the same
        // reason: sqlx refuses a non-`'static` query string, and the only
        // runtime part of this one is the count of `?`.
        let placeholders = std::iter::repeat_n("?", kinds.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE jobs \
             SET status = 'running', attempts = attempts + 1, lease_owner = ?, \
                 lease_until = ?, updated_at = ? \
             WHERE id = (SELECT id FROM jobs \
                          WHERE status = 'ready' AND run_at <= ? AND kind IN ({placeholders}) \
                          ORDER BY run_at ASC, created_at ASC LIMIT 1) \
               AND status = 'ready' \
             RETURNING {COLUMNS};"
        );

        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(runner_id)
            .bind(lease_until)
            .bind(now)
            .bind(now);
        for kind in kinds {
            query = query.bind(*kind);
        }
        let row = query.fetch_optional(&database.pool).await?;
        let job = row.map(Self::from_row).transpose()?;

        if let Some(job) = &job {
            debug!(
                event = "db_job_claimed",
                outcome = "success",
                job_id = %job.id,
                job_kind = %job.kind,
                attempts = job.attempts,
                lease_until = lease_until,
            );
        }
        Ok(job)
    }

    /// Marks a claimed job finished. `Ok(false)` means the lease was lost.
    pub async fn complete(
        id: Uuid,
        runner_id: &str,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        Self::settle(id, runner_id, "done", None, None, false, database).await
    }

    /// Returns a claimed job to the queue, to run again at `run_at`.
    pub async fn retry(
        id: Uuid,
        runner_id: &str,
        run_at: i64,
        error: &str,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        Self::settle(
            id,
            runner_id,
            "ready",
            Some(run_at),
            Some(error),
            false,
            database,
        )
        .await
    }

    /// Returns a claimed job to the queue as a *fresh* occurrence: the attempt
    /// counter goes back to zero and the last error is cleared.
    ///
    /// That reset is what separates a periodic job from a retried one. A sweep
    /// that runs every day for a year must not accumulate 365 attempts and
    /// retire itself, and a successful occurrence must not leave the previous
    /// failure's text sitting on the row as though it were current.
    pub async fn reschedule(
        id: Uuid,
        runner_id: &str,
        run_at: i64,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        Self::settle(id, runner_id, "ready", Some(run_at), None, true, database).await
    }

    /// Retires a claimed job permanently, recording why.
    pub async fn abandon(
        id: Uuid,
        runner_id: &str,
        error: &str,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        Self::settle(id, runner_id, "failed", None, Some(error), false, database).await
    }

    /// The one guarded write every settlement goes through.
    ///
    /// `AND status = 'running' AND lease_owner = ?` is the guard, and it is why
    /// these four are one function: a settlement that forgot it would let a
    /// runner whose lease had already been reclaimed overwrite the row a second
    /// runner was working, and the four call sites would each have had to
    /// remember. `rows_affected() == 1` is the caller's answer.
    async fn settle(
        id: Uuid,
        runner_id: &str,
        status: &str,
        run_at: Option<i64>,
        error: Option<&str>,
        reset_attempts: bool,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        let now = now_secs();
        let sql = format!(
            "UPDATE jobs \
             SET status = ?, last_error = ?, lease_owner = NULL, lease_until = NULL, \
                 run_at = COALESCE(?, run_at), updated_at = ?{} \
             WHERE id = ? AND status = 'running' AND lease_owner = ?;",
            if reset_attempts { ", attempts = 0" } else { "" }
        );
        let settled = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(status)
            .bind(error)
            .bind(run_at)
            .bind(now)
            .bind(id)
            .bind(runner_id)
            .execute(&database.pool)
            .await?
            .rows_affected()
            == 1;
        Ok(settled)
    }

    /// Returns to the queue every job whose runner died holding its lease.
    ///
    /// `attempts` is deliberately left alone: the attempt really was spent, and
    /// a counter rewritten to look better would let a job that crashes the
    /// process loop for ever.
    pub async fn reclaim_expired(now: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let reclaimed = sqlx::query(
            "UPDATE jobs SET status = 'ready', lease_owner = NULL, lease_until = NULL, \
             updated_at = ? WHERE status = 'running' AND lease_until <= ?;",
        )
        .bind(now)
        .bind(now)
        .execute(&database.pool)
        .await?
        .rows_affected();

        if reclaimed > 0 {
            warn!(
                event = "db_job_leases_reclaimed",
                outcome = "advisory",
                rows_reclaimed = reclaimed,
            );
        }
        Ok(reclaimed)
    }

    /// Releases every lease this runner holds, without settling the jobs.
    ///
    /// What a graceful shutdown runs, so a restart re-claims its own work
    /// immediately instead of waiting out a full lease.
    pub async fn release_owned(runner_id: &str, database: &Database) -> Result<u64, sqlx::Error> {
        let released = sqlx::query(
            "UPDATE jobs SET status = 'ready', lease_owner = NULL, lease_until = NULL, \
             updated_at = ? WHERE status = 'running' AND lease_owner = ?;",
        )
        .bind(now_secs())
        .bind(runner_id)
        .execute(&database.pool)
        .await?
        .rows_affected();

        if released > 0 {
            debug!(
                event = "db_job_leases_released",
                outcome = "success",
                rows_released = released,
            );
        }
        Ok(released)
    }

    /// One row by id.
    pub async fn find_by_id(id: Uuid, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        // A `QueryBuilder` rather than `sqlx::query`, which takes only
        // `&'static str` and so cannot be handed the shared `COLUMNS`. `id`
        // still goes through `push_bind`, so nothing is interpolated.
        let mut query = sqlx::QueryBuilder::new(format!("SELECT {COLUMNS} FROM jobs WHERE id = "));
        query.push_bind(id);
        let row = query.build().fetch_optional(&database.pool).await?;
        row.map(Self::from_row).transpose()
    }

    /// The live job holding `(kind, dedup_key)`, if there is one.
    pub async fn find_live(
        kind: &str,
        dedup_key: &str,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut query = sqlx::QueryBuilder::new(format!(
            "SELECT {COLUMNS} FROM jobs \
             WHERE status IN ('ready', 'running') AND kind = "
        ));
        query.push_bind(kind);
        query.push(" AND dedup_key = ");
        query.push_bind(dedup_key);
        let row = query.build().fetch_optional(&database.pool).await?;
        row.map(Self::from_row).transpose()
    }

    /// How many live jobs of `kind` are queued or running.
    ///
    /// The kind-wide counterpart to [`Self::find_live`], for the callers that
    /// want "is there work of this sort outstanding?" without naming a
    /// `dedup_key` — a `notify_deliver` key is a per-occurrence uuid, so there
    /// is no single key to ask about.
    pub async fn count_live(kind: &str, database: &Database) -> Result<i64, sqlx::Error> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('ready', 'running') AND kind = ?;",
        )
        .bind(kind)
        .fetch_one(&database.pool)
        .await?;
        Ok(count)
    }

    /// One page of jobs matching `query`, plus the total the same predicates
    /// match unpaged. The only cross-kind listing this model offers, for the
    /// operator surface (`acme-proxy jobs list`, `GET /api/jobs`).
    ///
    /// Built with a [`sqlx::QueryBuilder`] rather than `sqlx::query`, which
    /// takes only `&'static str` and so cannot be handed the shared `COLUMNS`
    /// — the same reason [`Self::find_by_id`] does. Every value goes through
    /// `push_bind`, so nothing operator-supplied is interpolated.
    ///
    /// **No index covers `WHERE kind = ? AND status = ? ORDER BY created_at`.**
    /// This table stays small by construction: [`Self::cleanup`] deletes
    /// terminal rows past `jobs.retention_days`, and the partial identity index
    /// admits at most one live row per `(kind, dedup_key)`. A dedicated
    /// `(kind, created_at)` index is a future migration if a deployment ever
    /// says otherwise — the `Order::find_expiring` tradeoff exactly.
    pub async fn search(
        query: &JobQuery,
        database: &Database,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        debug!(
            event = "db_job_search_started",
            outcome = "progress",
            job_kind = ?query.kind,
            status = ?query.status,
            limit = query.limit,
            offset = query.offset,
        );

        let mut page = sqlx::QueryBuilder::new(format!("SELECT {COLUMNS} FROM jobs"));
        query.push_predicates(&mut page);
        // Newest first, `id` breaking the tie: `created_at` is whole seconds,
        // and a v7 id sorts chronologically within one, so two jobs written in
        // the same second cannot swap between pages.
        page.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        page.push_bind(query.limit);
        page.push(" OFFSET ");
        page.push_bind(query.offset);

        let rows = page.build().fetch_all(&database.pool).await?;
        let jobs: Vec<Self> = rows
            .into_iter()
            .map(Self::from_row)
            .collect::<Result<_, _>>()?;

        let mut count = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM jobs");
        query.push_predicates(&mut count);
        let total: i64 = count
            .build()
            .fetch_one(&database.pool)
            .await?
            .try_get::<i64, _>(0)?;

        Ok((jobs, total))
    }

    /// The most recent job for `(kind, dedup_key)` whatever its status.
    ///
    /// [`Self::find_live`]'s counterpart for a cross-link that must still
    /// resolve after the job reached a terminal state — a relay job's
    /// `dedup_key` is the local order id, and the operator surface links a
    /// `done`/`failed` relay job to its `upstream_orders` row and back.
    pub async fn find_latest_by_dedup(
        kind: &str,
        dedup_key: &str,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut query =
            sqlx::QueryBuilder::new(format!("SELECT {COLUMNS} FROM jobs WHERE kind = "));
        query.push_bind(kind);
        query.push(" AND dedup_key = ");
        query.push_bind(dedup_key);
        query.push(" ORDER BY created_at DESC, id DESC LIMIT 1");
        let row = query.build().fetch_optional(&database.pool).await?;
        row.map(Self::from_row).transpose()
    }

    /// Retires a job at an operator's request, **from one named status**:
    /// `from` → `cancelled`.
    ///
    /// `Ok(Some(job))` is the row as it now stands; `Ok(None)` means it was not
    /// in `from` — the guard decided, not a read-then-write. `running` is never
    /// a legal `from`: a runner owns such a row, and its lease will expire or it
    /// will settle.
    ///
    /// **The status is a parameter rather than the `IN ('ready','failed')` this
    /// used to guard on**, and that is what lets the caller act on *which* of
    /// the two it was. `RETURNING` hands back the row after the write, so a
    /// single statement over both cannot say which state it came from — and the
    /// difference matters exactly once: a `ready` relay job is in flight and
    /// its order still has to be abandoned, while a `failed` one was already
    /// abandoned by `runner::retire`, so repeating that would write a second
    /// `certificate_issue_failed` row and overwrite `upstream_orders.error`
    /// with a cancellation message, destroying the upstream's own diagnosis.
    /// See `admin::ops::cancel_job`.
    pub async fn cancel_row(
        id: Uuid,
        from: JobStatus,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        debug_assert_ne!(
            from,
            JobStatus::Running,
            "a running job is the runner's; cancelling it would strand a lease"
        );
        let sql = format!(
            "UPDATE jobs \
             SET status = 'cancelled', updated_at = ?, lease_owner = NULL, lease_until = NULL \
             WHERE id = ? AND status = ? \
             RETURNING {COLUMNS};"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(now_secs())
            .bind(id)
            .bind(from.as_str())
            .fetch_optional(&database.pool)
            .await?;
        let job = row.map(Self::from_row).transpose()?;
        if job.is_some() {
            info!(event = "db_job_cancelled", outcome = "success", job_id = %id, from = from.as_str());
        }
        Ok(job)
    }

    /// Pulls a live `ready` job's `run_at` forward to now. `Ok(None)` if it is
    /// not `ready`. The runner picks the change up within `jobs.poll_interval_ms`
    /// — this does not wake it.
    pub async fn advance_row(id: Uuid, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        let now = now_secs();
        let sql = format!(
            "UPDATE jobs SET run_at = ?, updated_at = ? \
             WHERE id = ? AND status = 'ready' RETURNING {COLUMNS};"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(now)
            .bind(now)
            .bind(id)
            .fetch_optional(&database.pool)
            .await?;
        let job = row.map(Self::from_row).transpose()?;
        if job.is_some() {
            info!(event = "db_job_advanced", outcome = "success", job_id = %id);
        }
        Ok(job)
    }

    /// Revives a permanently-failed job for exactly one more attempt: `failed`
    /// → `ready`, `run_at` now, `attempts` set to `max_attempts - 1`.
    /// `Ok(None)` if the row is not `failed`.
    ///
    /// `max_attempts - 1` rather than `0` is the whole point: the operator is
    /// asking for one retry, not a fresh budget — if that attempt also fails
    /// the job is `failed` again and stays there without another nudge.
    /// `last_error` is left in place as the record of why it stopped, until the
    /// next claim overwrites it. `MAX(…, 0)` guards a `max_attempts = 0` row
    /// (the column carries no `CHECK`).
    pub async fn revive_row(id: Uuid, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        let now = now_secs();
        let sql = format!(
            "UPDATE jobs \
             SET status = 'ready', run_at = ?, updated_at = ?, \
                 attempts = MAX(max_attempts - 1, 0), \
                 lease_owner = NULL, lease_until = NULL \
             WHERE id = ? AND status = 'failed' RETURNING {COLUMNS};"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(now)
            .bind(now)
            .bind(id)
            .fetch_optional(&database.pool)
            .await?;
        let job = row.map(Self::from_row).transpose()?;
        if let Some(job) = &job {
            info!(
                event = "db_job_revived",
                outcome = "success",
                job_id = %id,
                attempts = job.attempts,
            );
        }
        Ok(job)
    }

    /// Deletes terminal rows settled before `cutoff`, returning how many went.
    ///
    /// Only terminal ones: a `ready` job scheduled far in the future is not old,
    /// however long ago it was written, and a `running` one is somebody's work.
    pub async fn cleanup(cutoff: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let deleted = sqlx::query(
            "DELETE FROM jobs \
             WHERE status IN ('done', 'failed', 'cancelled') AND updated_at < ?;",
        )
        .bind(cutoff)
        .execute(&database.pool)
        .await?
        .rows_affected();
        info!(
            event = "db_job_cleanup_completed",
            outcome = "success",
            rows_removed = deleted,
            cutoff = cutoff,
        );
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// A stable id for a fixture, derived from a readable name.
    ///
    /// Ids are UUIDs, so a fixture cannot spell one inline and stay legible --
    /// and minting one per row would move the name out of the assertion, which
    /// is where it does the explaining. The bytes are the name itself, padded:
    /// distinct names give distinct ids, which is the whole of what a fixture
    /// needs from them.
    fn job_id(name: &str) -> Uuid {
        let mut bytes = [0u8; 16];
        let name = name.as_bytes();
        let take = name.len().min(16);
        bytes[..take].copy_from_slice(&name[..take]);
        Uuid::from_bytes(bytes)
    }

    /// Queues one job with sensible defaults, returning whether it was queued.
    async fn enqueue(id: Uuid, key: &str, run_at: i64, database: &Database) -> bool {
        Job::enqueue(
            NewJob {
                id,
                kind: "test",
                dedup_key: key,
                payload: &json!({"n": 1}),
                run_at,
                deadline: None,
                max_attempts: 3,
            },
            database,
        )
        .await
        .unwrap()
    }

    async fn claim(runner: &str, database: &Database) -> Option<Job> {
        Job::claim_next(runner, &["test"], now_secs() + 60, now_secs(), database)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_queued_job_round_trips_through_every_column() {
        let database = db().await;
        let deadline = now_secs() + 900;
        assert!(
            Job::enqueue(
                NewJob {
                    id: job_id("job-1"),
                    kind: "relay",
                    dedup_key: "ord-1",
                    payload: &json!({"order_id": "ord-1"}),
                    run_at: 1_234,
                    deadline: Some(deadline),
                    max_attempts: 7,
                },
                &database,
            )
            .await
            .unwrap()
        );

        let job = Job::find_by_id(job_id("job-1"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.kind, "relay");
        assert_eq!(job.dedup_key, "ord-1");
        assert_eq!(job.payload, json!({"order_id": "ord-1"}));
        assert_eq!(job.status, "ready");
        assert_eq!(job.run_at, 1_234);
        assert_eq!(job.attempts, 0);
        assert_eq!(job.max_attempts, 7);
        assert_eq!(job.deadline, Some(deadline));
        assert!(job.lease_until.is_none());
        assert!(job.lease_owner.is_none());
        assert!(job.last_error.is_none());
    }

    /// The partial index's whole point: an identity is held by a *live* job and
    /// released the moment one settles.
    #[tokio::test]
    async fn a_live_job_holds_its_identity_and_a_settled_one_releases_it() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "ord-1", now_secs(), &database).await);
        assert!(
            !enqueue(job_id("job-2"), "ord-1", now_secs(), &database).await,
            "a second live job must not take an identity already held"
        );

        // Claimed is still live.
        let job = claim("runner-a", &database).await.unwrap();
        assert!(
            !enqueue(job_id("job-3"), "ord-1", now_secs(), &database).await,
            "'running' holds the identity exactly as 'ready' does"
        );

        Job::complete(job.id, "runner-a", &database).await.unwrap();
        assert!(
            enqueue(job_id("job-4"), "ord-1", now_secs(), &database).await,
            "a settled job releases its identity"
        );
    }

    #[tokio::test]
    async fn claiming_takes_the_oldest_eligible_row_and_only_once() {
        let database = db().await;
        assert!(enqueue(job_id("job-new"), "b", now_secs() - 10, &database).await);
        assert!(enqueue(job_id("job-old"), "a", now_secs() - 100, &database).await);

        let first = claim("runner-a", &database).await.unwrap();
        assert_eq!(first.id, job_id("job-old"), "oldest `run_at` first");
        assert_eq!(first.attempts, 1, "the counter moves at claim");
        assert_eq!(first.lease_owner.as_deref(), Some("runner-a"));

        let second = claim("runner-b", &database).await.unwrap();
        assert_eq!(second.id, job_id("job-new"));
        assert!(
            claim("runner-c", &database).await.is_none(),
            "a claimed row is not claimable again"
        );
    }

    #[tokio::test]
    async fn claiming_skips_a_job_whose_run_at_has_not_arrived() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs() + 3_600, &database).await);
        assert!(claim("runner-a", &database).await.is_none());
    }

    #[tokio::test]
    async fn claiming_skips_a_kind_the_runner_does_not_hold() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);

        let claimed = Job::claim_next(
            "runner-a",
            &["something-else"],
            now_secs() + 60,
            now_secs(),
            &database,
        )
        .await
        .unwrap();
        assert!(
            claimed.is_none(),
            "an unregistered kind is left alone, not mis-run"
        );
    }

    #[tokio::test]
    async fn claiming_with_no_registered_kinds_asks_the_database_nothing() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        assert!(
            Job::claim_next("runner-a", &[], now_secs() + 60, now_secs(), &database)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The guard that makes a reclaimed lease safe: the runner that lost it
    /// writes nothing, rather than overwriting the row somebody else now owns.
    #[tokio::test]
    async fn a_settlement_from_a_runner_that_lost_the_lease_writes_nothing() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        let job = claim("runner-a", &database).await.unwrap();

        for settled in [
            Job::complete(job.id, "runner-b", &database).await.unwrap(),
            Job::retry(job.id, "runner-b", now_secs(), "x", &database)
                .await
                .unwrap(),
            Job::reschedule(job.id, "runner-b", now_secs(), &database)
                .await
                .unwrap(),
            Job::abandon(job.id, "runner-b", "x", &database)
                .await
                .unwrap(),
        ] {
            assert!(!settled, "the lease guard must refuse a foreign settlement");
        }

        let after = Job::find_by_id(job_id("job-1"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "running");
        assert_eq!(after.lease_owner.as_deref(), Some("runner-a"));
    }

    #[tokio::test]
    async fn retry_returns_the_job_at_its_new_time_and_keeps_the_attempt_count() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        let job = claim("runner-a", &database).await.unwrap();

        assert!(
            Job::retry(job.id, "runner-a", 9_999, "upstream timed out", &database)
                .await
                .unwrap()
        );

        let after = Job::find_by_id(job_id("job-1"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "ready");
        assert_eq!(after.run_at, 9_999);
        assert_eq!(after.attempts, 1, "a retry does not forgive the attempt");
        assert_eq!(after.last_error.as_deref(), Some("upstream timed out"));
        assert!(after.lease_owner.is_none());
    }

    #[tokio::test]
    async fn reschedule_resets_the_attempt_count_and_clears_the_last_error() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        let job = claim("runner-a", &database).await.unwrap();
        Job::retry(job.id, "runner-a", now_secs(), "a failure", &database)
            .await
            .unwrap();
        let job = claim("runner-a", &database).await.unwrap();
        assert_eq!(job.attempts, 2);

        assert!(
            Job::reschedule(job.id, "runner-a", 5_000, &database)
                .await
                .unwrap()
        );

        let after = Job::find_by_id(job_id("job-1"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "ready");
        assert_eq!(after.run_at, 5_000);
        assert_eq!(after.attempts, 0, "a fresh occurrence starts fresh");
        assert!(after.last_error.is_none());
    }

    #[tokio::test]
    async fn abandon_is_terminal_and_records_why() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        let job = claim("runner-a", &database).await.unwrap();

        assert!(
            Job::abandon(job.id, "runner-a", "the order no longer exists", &database)
                .await
                .unwrap()
        );

        let after = Job::find_by_id(job_id("job-1"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "failed");
        assert_eq!(
            after.last_error.as_deref(),
            Some("the order no longer exists")
        );
    }

    #[tokio::test]
    async fn reclaim_takes_only_leases_that_have_expired() {
        let database = db().await;
        assert!(enqueue(job_id("job-live"), "a", now_secs(), &database).await);
        assert!(enqueue(job_id("job-dead"), "b", now_secs(), &database).await);

        // One long lease, one already expired.
        Job::claim_next(
            "runner-a",
            &["test"],
            now_secs() + 600,
            now_secs(),
            &database,
        )
        .await
        .unwrap();
        Job::claim_next("runner-a", &["test"], now_secs() - 1, now_secs(), &database)
            .await
            .unwrap();

        assert_eq!(
            Job::reclaim_expired(now_secs(), &database).await.unwrap(),
            1
        );

        let reclaimed = Job::find_by_id(job_id("job-dead"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.status, "ready");
        assert!(reclaimed.lease_owner.is_none());
        assert_eq!(
            reclaimed.attempts, 1,
            "the attempt was spent, and the row must keep saying so"
        );

        let held = Job::find_by_id(job_id("job-live"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.status, "running");
    }

    #[tokio::test]
    async fn release_owned_is_scoped_to_one_runner() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "a", now_secs(), &database).await);
        assert!(enqueue(job_id("job-2"), "b", now_secs(), &database).await);
        claim("runner-a", &database).await.unwrap();
        claim("runner-b", &database).await.unwrap();

        assert_eq!(Job::release_owned("runner-a", &database).await.unwrap(), 1);
        assert_eq!(
            Job::find_by_id(job_id("job-1"), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            "ready"
        );
        assert_eq!(
            Job::find_by_id(job_id("job-2"), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            "running"
        );
    }

    #[tokio::test]
    async fn find_live_sees_a_queued_job_and_not_a_settled_one() {
        let database = db().await;
        assert!(enqueue(job_id("job-1"), "ord-1", now_secs(), &database).await);
        assert!(
            Job::find_live("test", "ord-1", &database)
                .await
                .unwrap()
                .is_some()
        );

        let job = claim("runner-a", &database).await.unwrap();
        Job::complete(job.id, "runner-a", &database).await.unwrap();
        assert!(
            Job::find_live("test", "ord-1", &database)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn cleanup_removes_settled_rows_strictly_older_than_the_cutoff() {
        let database = db().await;
        assert!(enqueue(job_id("job-done"), "a", now_secs(), &database).await);
        assert!(enqueue(job_id("job-live"), "b", now_secs() + 3_600, &database).await);
        let job = claim("runner-a", &database).await.unwrap();
        Job::complete(job.id, "runner-a", &database).await.unwrap();

        // The cutoff is `updated_at`, which `complete` has just stamped. Read it
        // back off the row rather than asking the clock again: a second boundary
        // falling between the two makes `now_secs()` one past the stamp, and the
        // row this line asserts is kept would be deleted.
        let settled = Job::find_by_id(job_id("job-done"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Job::cleanup(settled.updated_at, &database).await.unwrap(),
            0
        );
        assert_eq!(
            Job::cleanup(settled.updated_at + 1, &database)
                .await
                .unwrap(),
            1
        );
        assert!(
            Job::find_by_id(job_id("job-done"), &database)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Job::find_by_id(job_id("job-live"), &database)
                .await
                .unwrap()
                .is_some(),
            "a job still queued is not old, however long ago it was written"
        );
    }

    #[tokio::test]
    async fn an_unknown_status_is_refused_by_the_check_constraint() {
        let database = db().await;
        let error = sqlx::query(
            "INSERT INTO jobs (id, kind, dedup_key, payload, status, run_at, attempts, \
             max_attempts, created_at, updated_at) \
             VALUES ('x', 'test', 'k', '{}', 'halfway', 0, 0, 1, 0, 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap_err();
        assert!(error.to_string().contains("CHECK constraint failed"));
    }

    // --- the operator surface: `JobQuery`/`search` and the guarded mutations --

    use crate::sqlite::status::JobStatus;

    /// Queues one job of a named kind with `max_attempts` and `run_at` chosen.
    async fn enqueue_kind(
        id: Uuid,
        kind: &str,
        key: &str,
        run_at: i64,
        max_attempts: i64,
        database: &Database,
    ) -> bool {
        Job::enqueue(
            NewJob {
                id,
                kind,
                dedup_key: key,
                payload: &json!({}),
                run_at,
                deadline: None,
                max_attempts,
            },
            database,
        )
        .await
        .unwrap()
    }

    /// One job at `failed` with `max_attempts`, `attempts = 1` and a
    /// `last_error` — the state the runner leaves after a single failed
    /// attempt. A direct `UPDATE` rather than claim+abandon because a test
    /// seeding several jobs of one kind cannot say *which* one `claim_next`
    /// takes (it takes the oldest); `abandon`'s own path is covered by
    /// `abandon_is_terminal_and_records_why`.
    async fn failed_job_max(
        id: Uuid,
        kind: &str,
        key: &str,
        max_attempts: i64,
        database: &Database,
    ) -> Job {
        assert!(enqueue_kind(id, kind, key, now_secs(), max_attempts, database).await);
        sqlx::query(
            "UPDATE jobs SET status = 'failed', attempts = 1, \
             last_error = 'upstream said no', updated_at = ? WHERE id = ?;",
        )
        .bind(now_secs())
        .bind(id)
        .execute(&database.pool)
        .await
        .unwrap();
        Job::find_by_id(id, database).await.unwrap().unwrap()
    }

    async fn failed_job(id: Uuid, kind: &str, key: &str, database: &Database) -> Job {
        failed_job_max(id, kind, key, 3, database).await
    }

    #[tokio::test]
    async fn search_filters_kind_and_status_and_pages_without_overlap() {
        let database = db().await;
        // Three `relay` jobs, two `sweep` jobs; drive one relay job to `failed`.
        for i in 0..3 {
            assert!(
                enqueue_kind(
                    job_id(&format!("relay-{i}")),
                    "relay",
                    &format!("ord-{i}"),
                    now_secs() - i64::from(10 - i),
                    3,
                    &database,
                )
                .await
            );
        }
        for i in 0..2 {
            assert!(
                enqueue_kind(
                    job_id(&format!("sweep-{i}")),
                    "sweep",
                    &format!("s-{i}"),
                    now_secs(),
                    3,
                    &database,
                )
                .await
            );
        }
        failed_job(job_id("relay-failed"), "relay", "ord-f", &database).await;

        // Kind narrows page and total together.
        let (rows, total) = Job::search(
            &JobQuery {
                kind: Some("relay".to_string()),
                limit: 50,
                ..JobQuery::default()
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(total, 4);
        assert_eq!(rows.len(), 4);

        // Kind + status together.
        let (rows, total) = Job::search(
            &JobQuery {
                kind: Some("relay".to_string()),
                status: Some(JobStatus::Failed),
                limit: 50,
                offset: 0,
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].id, job_id("relay-failed"));

        // Three single-row pages over the four `relay` jobs see each once, and
        // the total stays unpaged on every page.
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..4 {
            let (rows, total) = Job::search(
                &JobQuery {
                    kind: Some("relay".to_string()),
                    limit: 1,
                    offset,
                    ..JobQuery::default()
                },
                &database,
            )
            .await
            .unwrap();
            assert_eq!(total, 4);
            assert_eq!(rows.len(), 1);
            assert!(seen.insert(rows[0].id), "a row appeared on two pages");
        }
        assert_eq!(seen.len(), 4);
    }

    #[tokio::test]
    async fn a_kind_filter_value_is_bound_not_interpolated() {
        let database = db().await;
        assert!(enqueue_kind(job_id("job-1"), "relay", "k", now_secs(), 3, &database).await);
        let (rows, total) = Job::search(
            &JobQuery {
                kind: Some("' OR 1=1 --".to_string()),
                limit: 50,
                ..JobQuery::default()
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());
        // The table is still there.
        assert!(
            Job::find_by_id(job_id("job-1"), &database)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancel_row_moves_ready_and_failed_and_refuses_the_rest() {
        let database = db().await;

        // ready -> cancelled.
        assert!(enqueue_kind(job_id("ready"), "test", "a", now_secs(), 3, &database).await);
        let cancelled = Job::cancel_row(job_id("ready"), JobStatus::Ready, &database)
            .await
            .unwrap()
            .expect("a ready job cancels");
        assert_eq!(cancelled.status, "cancelled");
        // A second cancel finds nothing to do.
        assert!(
            Job::cancel_row(job_id("ready"), JobStatus::Ready, &database)
                .await
                .unwrap()
                .is_none()
        );

        // failed -> cancelled.
        failed_job(job_id("failed"), "test", "b", &database).await;
        assert!(
            Job::cancel_row(job_id("failed"), JobStatus::Failed, &database)
                .await
                .unwrap()
                .is_some()
        );

        // running is refused, row untouched.
        assert!(enqueue_kind(job_id("running"), "test", "c", now_secs(), 3, &database).await);
        Job::claim_next("r", &["test"], now_secs() + 60, now_secs(), &database)
            .await
            .unwrap();
        assert!(
            Job::cancel_row(job_id("running"), JobStatus::Ready, &database)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            Job::find_by_id(job_id("running"), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            "running"
        );

        // done is refused.
        assert!(enqueue_kind(job_id("done"), "test", "d", now_secs(), 3, &database).await);
        let job = Job::claim_next("r", &["test"], now_secs() + 60, now_secs(), &database)
            .await
            .unwrap()
            .unwrap();
        Job::complete(job.id, "r", &database).await.unwrap();
        assert!(
            Job::cancel_row(job_id("done"), JobStatus::Ready, &database)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn advance_row_nudges_a_ready_job_and_refuses_a_running_one() {
        let database = db().await;
        assert!(
            enqueue_kind(
                job_id("ready"),
                "test",
                "a",
                now_secs() + 3_600,
                3,
                &database
            )
            .await
        );
        let advanced = Job::advance_row(job_id("ready"), &database)
            .await
            .unwrap()
            .expect("a ready job advances");
        assert!(advanced.run_at <= now_secs() + 1);
        assert_eq!(advanced.attempts, 0, "advancing does not spend an attempt");

        // running / failed / done all refuse.
        Job::claim_next("r", &["test"], now_secs() + 60, now_secs(), &database)
            .await
            .unwrap();
        assert!(
            Job::advance_row(job_id("ready"), &database)
                .await
                .unwrap()
                .is_none()
        );

        failed_job(job_id("failed"), "test", "b", &database).await;
        assert!(
            Job::advance_row(job_id("failed"), &database)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn revive_row_sets_attempts_to_max_minus_one_and_refuses_a_live_job() {
        let database = db().await;

        let failed = failed_job(job_id("failed"), "test", "a", &database).await;
        assert_eq!(failed.max_attempts, 3);
        let revived = Job::revive_row(job_id("failed"), &database)
            .await
            .unwrap()
            .expect("a failed job revives");
        assert_eq!(revived.status, "ready");
        assert_eq!(revived.attempts, 2, "exactly one attempt left");
        assert!(revived.run_at <= now_secs() + 1);
        assert_eq!(
            revived.last_error.as_deref(),
            Some("upstream said no"),
            "the last error stays as the record of why it stopped"
        );

        // A live `ready` job is refused.
        assert!(enqueue_kind(job_id("ready"), "test", "b", now_secs(), 3, &database).await);
        assert!(
            Job::revive_row(job_id("ready"), &database)
                .await
                .unwrap()
                .is_none()
        );

        // max_attempts = 1 -> attempts back to 0 (a full single attempt).
        let one = failed_job_max(job_id("one"), "test", "c", 1, &database).await;
        assert_eq!(one.max_attempts, 1);
        let revived = Job::revive_row(job_id("one"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revived.attempts, 0);
    }

    #[tokio::test]
    async fn find_latest_by_dedup_sees_a_settled_job_where_find_live_does_not() {
        let database = db().await;
        assert!(enqueue_kind(job_id("job-1"), "relay", "ord-1", now_secs(), 3, &database).await);
        let job = Job::claim_next("r", &["relay"], now_secs() + 60, now_secs(), &database)
            .await
            .unwrap()
            .unwrap();
        Job::complete(job.id, "r", &database).await.unwrap();

        assert!(
            Job::find_live("relay", "ord-1", &database)
                .await
                .unwrap()
                .is_none()
        );
        let latest = Job::find_latest_by_dedup("relay", "ord-1", &database)
            .await
            .unwrap()
            .expect("the settled job is still resolvable");
        assert_eq!(latest.id, job_id("job-1"));
        assert_eq!(latest.status, "done");
    }

    #[tokio::test]
    async fn revive_then_a_second_failure_stays_failed_without_another_nudge() {
        let database = db().await;
        failed_job(job_id("j"), "test", "a", &database).await;
        Job::revive_row(job_id("j"), &database)
            .await
            .unwrap()
            .unwrap();
        // Claim (attempts -> 3 = max) and abandon again.
        let job = Job::claim_next("r", &["test"], now_secs() + 60, now_secs(), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.attempts, 3);
        Job::abandon(job.id, "r", "again", &database).await.unwrap();

        let after = Job::find_by_id(job_id("j"), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "failed");
        // advance_row does nothing to a failed job; revive still works.
        assert!(
            Job::advance_row(job_id("j"), &database)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Job::revive_row(job_id("j"), &database)
                .await
                .unwrap()
                .is_some()
        );
    }
}
