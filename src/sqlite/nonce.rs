use std::time::{Duration, SystemTime};

use sqlx::Row;
use tracing::{debug, info};
use uuid::Uuid;

use crate::sqlite::db::Database;

/// A replay nonce used for ACME protocol anti-replay protection.
///
/// ## ACME Protocol Compliance
///
/// According to RFC 8555, nonces are used to prevent replay attacks:
/// - Each nonce is a UUID v4 string
/// - Nonces are generated for every response
/// - Clients must include a valid nonce in their requests
/// - Nonces are single-use and expire after a TTL period
///
/// ## Security Considerations
///
/// - Nonces are stored in the database with timestamps
/// - Expired nonces are automatically cleaned up
/// - Single-use enforcement prevents replay attacks
/// - Time-to-live limits prevent indefinite nonce accumulation
///
/// ## Database Storage
///
/// Nonces are stored in the `nonces` table with:
/// - `value`: The UUID string of the nonce
/// - `created_at`: Unix timestamp when the nonce was created
///
/// ## Lifecycle
///
/// 1. New nonce created for each response
/// 2. Nonce saved to database
/// 3. Client uses nonce in subsequent request
/// 4. Nonce verified and consumed (single-use)
/// 5. Expired nonces automatically cleaned up
#[derive(Debug)]
pub struct Nonce {
    pub value: String,
    pub created_at: i64,
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

/// A short, non-reusable stand-in for a nonce value, for logs.
///
/// A nonce is a bearer credential: until it is consumed, anyone holding it can
/// sign a request with it. `Nonce::save` runs from the response middleware, so
/// logging the value there put *every nonce this server has minted* into the
/// log stream while it was still live and unused — a log reader could lift one
/// straight out. Eight characters of a UUID v4 are enough to follow one request
/// across lines and far too few to replay.
#[must_use]
pub fn fingerprint(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

/// Seconds since the Unix epoch, saturating to `0` for the pre-1970 clocks that
/// should never occur in practice.
pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Nonce {
    #[must_use]
    pub fn new() -> Self {
        Nonce {
            value: Uuid::new_v4().to_string(),
            created_at: now_secs(),
        }
    }

    pub async fn save(&self, database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO nonces VALUES (?, ?);")
            .bind(self.value.clone())
            .bind(self.created_at)
            .execute(&database.pool)
            .await?;
        // At `debug`, and a fingerprint rather than the value: this runs from
        // the response middleware, so it is the one log line in the server that
        // would otherwise publish a live, unconsumed credential on every single
        // response.
        debug!(event = "db_nonce_saved",
               outcome = "success",
               nonce_fp = %fingerprint(&self.value),
               created_at = ?self.created_at);
        Ok(())
    }

    /// Consumes `nonce` if it is live: a single `DELETE` whose `rows_affected`
    /// decides, so two concurrent replays cannot both succeed.
    ///
    /// Takes `&str` rather than `String` — it only ever binds a reference, and
    /// this runs on every signed POST, which is the hottest path in the server.
    pub async fn verify(
        nonce: &str,
        database: &Database,
        ttl: Duration,
    ) -> Result<bool, sqlx::Error> {
        // Saturating subtraction avoids the panic `SystemTime - Duration` raises
        // when `ttl` reaches back past the epoch.
        let cutoff = now_secs().saturating_sub(ttl.as_secs() as i64);

        let result = sqlx::query("DELETE FROM nonces WHERE value = ? AND created_at > ?;")
            .bind(nonce)
            .bind(cutoff)
            .execute(&database.pool)
            .await?;

        // A verified nonce is spent, so logging it would leak nothing — but a
        // *rejected* one may simply have been sent to the wrong endpoint and
        // still be live elsewhere, and one rule is easier to keep than two.
        // Two arms rather than one `event = if …`: the name has to stay a bare
        // literal, or neither spelling is greppable from a log back to here.
        let is_valid = result.rows_affected() == 1;
        if is_valid {
            debug!(
                event = "db_nonce_verified_valid",
                outcome = "success",
                nonce_fp = %fingerprint(nonce),
                cutoff = cutoff,
                ttl_seconds = ttl.as_secs(),
            );
        } else {
            debug!(
                event = "db_nonce_verified_invalid",
                outcome = "failure",
                nonce_fp = %fingerprint(nonce),
                cutoff = cutoff,
                ttl_seconds = ttl.as_secs(),
            );
        }
        Ok(is_valid)
    }

    /// How many nonce rows exist right now.
    ///
    /// The one thing worth showing about this table: individual values are
    /// bearer credentials and are never listed (see the note on
    /// [`fingerprint`]), but the *count* is a useful health signal — it should
    /// hover around the request rate times the TTL, and a number far above
    /// that means the reaper is not running.
    pub async fn count(database: &Database) -> Result<i64, sqlx::Error> {
        sqlx::query("SELECT COUNT(*) FROM nonces;")
            .fetch_one(&database.pool)
            .await?
            .try_get(0)
    }

    pub async fn cleanup(database: &Database, ttl: Duration) -> Result<u64, sqlx::Error> {
        let cutoff = now_secs().saturating_sub(ttl.as_secs() as i64);

        let result = sqlx::query("DELETE FROM nonces WHERE created_at <= ?;")
            .bind(cutoff)
            .execute(&database.pool)
            .await?;

        info!(event = "db_nonce_cleanup_completed",
              outcome = "success",
              rows_removed = ?result.rows_affected(),
              cutoff = ?cutoff,
              ttl_seconds = ?ttl.as_secs());
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Matches the default `nonce.ttl_seconds` (5 minutes).
    const TTL: Duration = Duration::from_secs(300);

    async fn nonce_count(database: &Arc<Database>) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nonces;")
            .fetch_one(&database.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn verify_accepts_fresh_nonce_exactly_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        let nonce = Nonce::new();
        let value = nonce.value.clone();
        nonce.save(&database).await.unwrap();

        // First use succeeds…
        assert!(Nonce::verify(&value, &database, TTL).await.unwrap());
        // …and the nonce is single-use: the row is gone, so a replay fails.
        assert!(!Nonce::verify(&value, &database, TTL).await.unwrap());
    }

    #[tokio::test]
    async fn verify_rejects_unknown_nonce() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        assert!(!Nonce::verify("never-issued", &database, TTL).await.unwrap());
    }

    #[tokio::test]
    async fn verify_rejects_expired_nonce() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        // 10 minutes old — outside the 5-minute freshness window.
        Nonce {
            value: "stale".to_string(),
            created_at: now_secs() - 600,
        }
        .save(&database)
        .await
        .unwrap();

        assert!(!Nonce::verify("stale", &database, TTL).await.unwrap());
    }

    #[tokio::test]
    async fn verify_accepts_nonce_near_edge_of_window() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        // Just inside the freshness window — pins the `created_at > cutoff`
        // acceptance boundary (2s margin avoids the exact-second tick flaking).
        #[allow(clippy::cast_possible_wrap)]
        let created_at = now_secs() - (TTL.as_secs() as i64 - 2);
        Nonce {
            value: "edge".to_string(),
            created_at,
        }
        .save(&database)
        .await
        .unwrap();

        assert!(Nonce::verify("edge", &database, TTL).await.unwrap());
    }

    #[tokio::test]
    async fn verify_rejects_nonce_at_exact_cutoff_boundary() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        // Pinned at exactly the cutoff — age == TTL, so the nonce is expired
        // under the strict `> cutoff` check.
        #[allow(clippy::cast_possible_wrap)]
        let created_at = now_secs() - TTL.as_secs() as i64;
        Nonce {
            value: "boundary".to_string(),
            created_at,
        }
        .save(&database)
        .await
        .unwrap();

        assert!(!Nonce::verify("boundary", &database, TTL).await.unwrap());
    }

    #[tokio::test]
    async fn cleanup_removes_only_stale_nonces() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        Nonce {
            value: "stale".to_string(),
            created_at: now_secs() - 600,
        }
        .save(&database)
        .await
        .unwrap();

        let fresh = Nonce::new();
        let fresh_value = fresh.value.clone();
        fresh.save(&database).await.unwrap();

        assert_eq!(nonce_count(&database).await, 2);

        let removed = Nonce::cleanup(&database, TTL).await.unwrap();
        assert_eq!(removed, 1);

        // Only the fresh nonce survives, and it is still usable.
        assert_eq!(nonce_count(&database).await, 1);
        assert!(Nonce::verify(&fresh_value, &database, TTL).await.unwrap());
    }

    /// `Default` exists so `Nonce` composes where one is expected; it must
    /// agree with `new`, which is what every call site actually uses.
    #[test]
    fn the_default_nonce_is_a_fresh_one() {
        let nonce = Nonce::default();
        assert!(!nonce.value.is_empty());
        assert_ne!(nonce.value, Nonce::default().value, "each must be unique");
    }

    #[tokio::test]
    async fn count_reports_the_table_size_and_follows_cleanup() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert_eq!(Nonce::count(&db).await.unwrap(), 0);

        for _ in 0..3 {
            Nonce::new().save(&db).await.unwrap();
        }
        assert_eq!(Nonce::count(&db).await.unwrap(), 3);

        // A stale row, swept: the count is what makes a stalled reaper visible.
        let stale = Nonce {
            value: "stale".to_string(),
            created_at: now_secs() - 10_000,
        };
        stale.save(&db).await.unwrap();
        assert_eq!(Nonce::count(&db).await.unwrap(), 4);
        Nonce::cleanup(&db, TTL).await.unwrap();
        assert_eq!(Nonce::count(&db).await.unwrap(), 3);
    }
}
