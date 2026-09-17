//! The `http01_tokens` table: key authorizations the `relay` backend publishes
//! for its upstream CA to fetch (RFC 8555 §8.3).
//!
//! In the database rather than in the backend's memory so the process serving
//! `/.well-known/acme-challenge/{token}` need not be the one whose relay job
//! published it. `signer::relay::http01` is the only user.

use sqlx::Row;
use tracing::{debug, info};

use crate::sqlite::db::Database;

/// One published key authorization.
pub struct Http01Token;

impl Http01Token {
    /// Makes `key_authorization` servable under `token` until `expires_at`.
    ///
    /// An upsert: a re-run of the attempt that published it — after a crash,
    /// or a retry — publishes the same token again, and the newer deadline is
    /// the one that should stand.
    pub async fn publish(
        token: &str,
        key_authorization: &str,
        now: i64,
        expires_at: i64,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO http01_tokens (token, key_authorization, created_at, expires_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (token) DO UPDATE SET \
             key_authorization = excluded.key_authorization, expires_at = excluded.expires_at;",
        )
        .bind(token)
        .bind(key_authorization)
        .bind(now)
        .bind(expires_at)
        .execute(&database.pool)
        .await?;
        debug!(event = "db_http_01_token_published", outcome = "success", token = %token, expires_at);
        Ok(())
    }

    /// Stops serving `token`. Idempotent.
    pub async fn retract(token: &str, database: &Database) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM http01_tokens WHERE token = ?;")
            .bind(token)
            .execute(&database.pool)
            .await?;
        debug!(
            event = "db_http_01_token_retracted",
            outcome = "success",
            token = %token,
            rows_removed = result.rows_affected(),
        );
        Ok(())
    }

    /// The key authorization to serve for `token`, unless it has expired.
    pub async fn lookup(
        token: &str,
        now: i64,
        database: &Database,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query(
            "SELECT key_authorization FROM http01_tokens WHERE token = ? AND expires_at > ?;",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&database.pool)
        .await?
        .map(|row| row.try_get("key_authorization"))
        .transpose()
    }

    /// Deletes every token at or past its `expires_at`, returning how many.
    pub async fn cleanup(now: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM http01_tokens WHERE expires_at <= ?;")
            .bind(now)
            .execute(&database.pool)
            .await?;
        info!(
            event = "db_http_01_token_cleanup_completed",
            outcome = "success",
            rows_removed = result.rows_affected(),
            cutoff = now,
        );
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_published_token_is_looked_up_until_retracted() {
        let database = Database::connect_in_memory().await.unwrap();
        assert_eq!(
            Http01Token::lookup("tok", 10, &database).await.unwrap(),
            None
        );

        Http01Token::publish("tok", "tok.one", 10, 100, &database)
            .await
            .unwrap();
        assert_eq!(
            Http01Token::lookup("tok", 10, &database).await.unwrap(),
            Some("tok.one".to_string())
        );

        Http01Token::retract("tok", &database).await.unwrap();
        Http01Token::retract("tok", &database).await.unwrap();
        assert_eq!(
            Http01Token::lookup("tok", 10, &database).await.unwrap(),
            None
        );
    }

    /// A re-publish replaces the key authorization and moves the deadline on.
    #[tokio::test]
    async fn publishing_again_replaces_the_row() {
        let database = Database::connect_in_memory().await.unwrap();
        Http01Token::publish("tok", "tok.one", 10, 20, &database)
            .await
            .unwrap();
        Http01Token::publish("tok", "tok.two", 15, 200, &database)
            .await
            .unwrap();

        assert_eq!(
            Http01Token::lookup("tok", 100, &database).await.unwrap(),
            Some("tok.two".to_string())
        );
    }

    /// An expired row is never served, and the sweep takes exactly those.
    #[tokio::test]
    async fn an_expired_token_is_not_served_and_is_swept() {
        let database = Database::connect_in_memory().await.unwrap();
        Http01Token::publish("old", "old.ka", 0, 50, &database)
            .await
            .unwrap();
        Http01Token::publish("live", "live.ka", 0, 500, &database)
            .await
            .unwrap();

        assert_eq!(
            Http01Token::lookup("old", 50, &database).await.unwrap(),
            None
        );
        assert_eq!(Http01Token::cleanup(50, &database).await.unwrap(), 1);
        assert_eq!(
            Http01Token::lookup("live", 50, &database).await.unwrap(),
            Some("live.ka".to_string())
        );
    }
}
