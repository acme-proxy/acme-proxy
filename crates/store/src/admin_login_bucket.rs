//! The `admin_login_buckets` table: the web admin's failed-login counter.
//!
//! In the database rather than in the admin process so that several admin
//! processes behind one load balancer share **one** budget per client address
//! — the reasoning is in `migrations/20261011120000_admin_login_buckets.sql`
//! and ADR 0008. `webadmin::session::LoginLimiter` is the only user, and owns
//! the policy (the bucket key, the scopes, what counts as a failure); this
//! module owns the arithmetic, which has to be one statement per step to stay
//! race-free across processes.
//!
//! **Every counter change is a single conditional `UPDATE`.** A read followed by
//! a write would be the check-then-act race the in-memory limiter already had
//! to close once: a burst of parallel requests all passing the check before the
//! first recorded anything. Both engines serialise writers on the row, and
//! PostgreSQL re-evaluates the `WHERE` against the row it finally locks, so the
//! comparison and the increment are one step on either backend.

use tracing::debug;

use crate::db::Database;

/// What [`AdminLoginBucket::begin`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// A slot was taken; settle it with [`AdminLoginBucket::settle`].
    Reserved,
    /// The bucket is full: retry after this many seconds (at least one).
    Refused { retry_after: u64 },
}

/// One `(scope, bucket)` counter.
pub struct AdminLoginBucket;

impl AdminLoginBucket {
    /// Reserves an attempt in `(scope, bucket)`, or refuses once failures plus
    /// attempts in flight reach `max_attempts` within `window_seconds`.
    ///
    /// A window that has run out starts over **with both counters**, the
    /// in-flight one included. That is what bounds a slot leaked by a process
    /// that died between `begin` and `settle` to one window; the cost is that an
    /// attempt straddling the boundary releases a slot of the new window when it
    /// settles, once.
    pub async fn begin(
        scope: &str,
        bucket: &str,
        max_attempts: u32,
        window_seconds: u64,
        now: i64,
        database: &Database,
    ) -> Result<Reservation, sqlx::Error> {
        let window = i64::try_from(window_seconds).unwrap_or(i64::MAX);
        let cutoff = now.saturating_sub(window);

        crate::sql::query(
            "INSERT INTO admin_login_buckets (scope, bucket, failures, in_flight, window_started) \
             VALUES (?, ?, 0, 0, ?) ON CONFLICT (scope, bucket) DO NOTHING;",
        )
        .bind(scope)
        .bind(bucket)
        .bind(now)
        .execute(database)
        .await?;

        // Every right-hand side reads the row as it was before this statement,
        // on both engines, so the three `CASE`s agree on whether the window
        // has run out.
        let reserved = crate::sql::query(
            "UPDATE admin_login_buckets SET \
                 failures = CASE WHEN window_started <= ? THEN 0 ELSE failures END, \
                 in_flight = CASE WHEN window_started <= ? THEN 1 ELSE in_flight + 1 END, \
                 window_started = CASE WHEN window_started <= ? THEN ? ELSE window_started END \
             WHERE scope = ? AND bucket = ? \
               AND (CASE WHEN window_started <= ? THEN 0 ELSE failures + in_flight END) < ?;",
        )
        .bind(cutoff)
        .bind(cutoff)
        .bind(cutoff)
        .bind(now)
        .bind(scope)
        .bind(bucket)
        .bind(cutoff)
        .bind(i64::from(max_attempts))
        .execute(database)
        .await?
        .rows_affected()
            == 1;
        if reserved {
            return Ok(Reservation::Reserved);
        }

        // Refused: the row exists (the insert above saw to that) and its
        // window is current, so what is left of it is the honest `Retry-After`.
        let started: i64 = crate::sql::query(
            "SELECT window_started FROM admin_login_buckets WHERE scope = ? AND bucket = ?;",
        )
        .bind(scope)
        .bind(bucket)
        .fetch_one(database)
        .await?
        .try_get("window_started")?;
        let left = window.saturating_sub(now.saturating_sub(started)).max(1);
        Ok(Reservation::Refused {
            retry_after: u64::try_from(left).unwrap_or(1),
        })
    }

    /// Gives back a slot [`begin`](Self::begin) reserved, counting it as a
    /// failure when `failed`. A bucket the sweep has since removed is a no-op.
    pub async fn settle(
        scope: &str,
        bucket: &str,
        failed: bool,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        crate::sql::query(
            "UPDATE admin_login_buckets SET \
                 in_flight = CASE WHEN in_flight > 0 THEN in_flight - 1 ELSE 0 END, \
                 failures = failures + ? \
             WHERE scope = ? AND bucket = ?;",
        )
        .bind(i64::from(failed))
        .bind(scope)
        .bind(bucket)
        .execute(database)
        .await?;
        Ok(())
    }

    /// Forgets `(scope, bucket)`'s failures after a completed sign-in. Attempts
    /// still in flight keep their slots: their guards settle against them.
    pub async fn clear_failures(
        scope: &str,
        bucket: &str,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        crate::sql::query(
            "UPDATE admin_login_buckets SET failures = 0 WHERE scope = ? AND bucket = ?;",
        )
        .bind(scope)
        .bind(bucket)
        .execute(database)
        .await?;
        Ok(())
    }

    /// Deletes every bucket whose window started at or before `cutoff`,
    /// returning how many.
    ///
    /// Nothing is lost: an expired window starts over on its next `begin`
    /// anyway, and a late `settle` against a removed row does nothing.
    pub async fn cleanup(cutoff: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let result =
            crate::sql::query("DELETE FROM admin_login_buckets WHERE window_started <= ?;")
                .bind(cutoff)
                .execute(database)
                .await?;
        debug!(
            event = "db_admin_login_bucket_cleanup_completed",
            outcome = "success",
            rows_removed = result.rows_affected(),
            cutoff,
        );
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    async fn begin(database: &Database, max: u32, now: i64) -> Reservation {
        AdminLoginBucket::begin("password", "192.0.2.1", max, 300, now, database)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn failures_and_attempts_in_flight_both_spend_the_budget() {
        let database = Database::connect_for_test().await.unwrap();

        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        AdminLoginBucket::settle("password", "192.0.2.1", true, &database)
            .await
            .unwrap();
        // One failure, one slot in flight: full.
        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        assert_eq!(
            begin(&database, 2, NOW + 10).await,
            Reservation::Refused { retry_after: 290 }
        );

        // Giving the slot back uncounted frees it.
        AdminLoginBucket::settle("password", "192.0.2.1", false, &database)
            .await
            .unwrap();
        assert_eq!(begin(&database, 2, NOW + 10).await, Reservation::Reserved);
    }

    #[tokio::test]
    async fn scopes_and_buckets_are_separate_budgets() {
        let database = Database::connect_for_test().await.unwrap();

        assert_eq!(begin(&database, 1, NOW).await, Reservation::Reserved);
        assert!(matches!(
            begin(&database, 1, NOW).await,
            Reservation::Refused { .. }
        ));
        for (scope, bucket) in [("oidc_start", "192.0.2.1"), ("password", "192.0.2.2")] {
            assert_eq!(
                AdminLoginBucket::begin(scope, bucket, 1, 300, NOW, &database)
                    .await
                    .unwrap(),
                Reservation::Reserved,
                "{scope}/{bucket}"
            );
        }
    }

    #[tokio::test]
    async fn an_expired_window_starts_over_with_both_counters() {
        let database = Database::connect_for_test().await.unwrap();

        // A failure and a slot leaked by a process that never settled it.
        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        AdminLoginBucket::settle("password", "192.0.2.1", true, &database)
            .await
            .unwrap();
        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        assert!(matches!(
            begin(&database, 2, NOW + 299).await,
            Reservation::Refused { retry_after: 1 }
        ));

        // Past the window both are forgotten: two fresh slots.
        assert_eq!(begin(&database, 2, NOW + 300).await, Reservation::Reserved);
        assert_eq!(begin(&database, 2, NOW + 300).await, Reservation::Reserved);
        assert!(matches!(
            begin(&database, 2, NOW + 300).await,
            Reservation::Refused { retry_after: 300 }
        ));
    }

    #[tokio::test]
    async fn clearing_failures_keeps_the_slots_in_flight() {
        let database = Database::connect_for_test().await.unwrap();

        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        AdminLoginBucket::settle("password", "192.0.2.1", true, &database)
            .await
            .unwrap();
        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);

        AdminLoginBucket::clear_failures("password", "192.0.2.1", &database)
            .await
            .unwrap();
        // The failure is gone, the slot in flight is not.
        assert_eq!(begin(&database, 2, NOW).await, Reservation::Reserved);
        assert!(matches!(
            begin(&database, 2, NOW).await,
            Reservation::Refused { .. }
        ));
    }

    /// The property the table exists for: a burst of concurrent `begin`s gets
    /// exactly `max_attempts` slots, however the statements interleave.
    #[tokio::test]
    async fn a_concurrent_burst_gets_exactly_the_limit() {
        let database = std::sync::Arc::new(Database::connect_for_test().await.unwrap());

        let burst: Vec<_> = (0..20)
            .map(|_| {
                let database = database.clone();
                tokio::spawn(async move { begin(&database, 5, NOW).await })
            })
            .collect();
        let mut reserved = 0;
        for attempt in burst {
            if attempt.await.unwrap() == Reservation::Reserved {
                reserved += 1;
            }
        }
        assert_eq!(reserved, 5);
    }

    #[tokio::test]
    async fn cleanup_removes_expired_windows_only() {
        let database = Database::connect_for_test().await.unwrap();

        assert_eq!(begin(&database, 1, NOW).await, Reservation::Reserved);
        AdminLoginBucket::begin("password", "192.0.2.9", 1, 300, NOW + 100, &database)
            .await
            .unwrap();

        assert_eq!(AdminLoginBucket::cleanup(NOW, &database).await.unwrap(), 1);
        // The survivor is still full; the removed one starts afresh.
        assert!(matches!(
            AdminLoginBucket::begin("password", "192.0.2.9", 1, 300, NOW + 100, &database)
                .await
                .unwrap(),
            Reservation::Refused { .. }
        ));
        assert_eq!(begin(&database, 1, NOW).await, Reservation::Reserved);
        // A late settle against a removed row is harmless.
        AdminLoginBucket::cleanup(NOW, &database).await.unwrap();
        AdminLoginBucket::settle("password", "192.0.2.1", true, &database)
            .await
            .unwrap();
    }
}
