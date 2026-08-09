use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::rfc3339;

/// An External Account Binding credential (RFC 8555 §7.3.4): a pre-shared
/// `kid` + HMAC secret an operator issues out-of-band, presented by a client
/// at `newAccount` to prove it was authorized to register.
///
/// Reusable: the same key can bind more than one account, until revoked (see
/// the migration). There is therefore no "used" status, only
/// `active`/`revoked`.
///
/// ## Methods
///
/// - `create`: generate a fresh key and persist it, `active`
/// - `find_by_kid`: lookup by kid (the request-time verification path)
/// - `list_all`: list every key, oldest first (admin CLI)
/// - `revoke`: move to the terminal `revoked` state
/// - `to_json`: admin-facing rendering (never includes the secret)
#[derive(Debug)]
pub struct Eab {
    pub kid: String,
    pub secret: Vec<u8>,
    pub label: Option<String>,
    /// Which ACME endpoint the credential is good for. `None` means every
    /// profile -- the default, for an operator who does not care to scope it.
    pub profile: Option<String>,
    pub status: String,
    pub created_at: i64,
}

/// Length, in bytes, of a freshly generated HMAC secret: 32 (256 bits),
/// matching HS256's key size.
const SECRET_LEN: usize = 32;

/// A fresh high-entropy HMAC secret. RNG failure is unrecoverable, so this
/// panics rather than threading an error through -- the same trade-off
/// `authz::generate_token` makes for challenge tokens.
fn generate_secret() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; SECRET_LEN];
    rng.fill(&mut bytes).expect("system RNG unavailable");
    bytes
}

impl Eab {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Eab {
            kid: row.try_get("kid")?,
            secret: row.try_get("secret")?,
            label: row.try_get("label")?,
            profile: row.try_get("profile")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Generates a fresh key (random UUID `kid` + random 32-byte secret) and
    /// persists it `active`. Returns the created row so the caller (the
    /// `eab create` admin command) can print the secret **once** -- this is
    /// the only time it is meant to leave the database in plaintext form.
    pub async fn create(
        label: Option<String>,
        profile: Option<String>,
        database: &Database,
    ) -> Result<Eab, sqlx::Error> {
        let eab = Eab {
            kid: Uuid::new_v4().to_string(),
            secret: generate_secret(),
            label,
            profile,
            status: "active".to_string(),
            created_at: now_secs(),
        };

        debug!(event = "eab_create_started", kid = ?eab.kid, profile = ?eab.profile);
        sqlx::query(
            "INSERT INTO eab_keys (kid, secret, label, profile, status, created_at) \
             VALUES (?, ?, ?, ?, ?, ?);",
        )
        .bind(&eab.kid)
        .bind(&eab.secret)
        .bind(&eab.label)
        .bind(&eab.profile)
        .bind(&eab.status)
        .bind(eab.created_at)
        .execute(&database.pool)
        .await?;

        info!(event = "eab_created", kid = ?eab.kid);
        Ok(eab)
    }

    /// Looks a credential up for use at `profile`. A row scoped to another
    /// profile is *not* returned: to the endpoint asking, it does not exist.
    /// A row with no profile at all matches everywhere.
    pub async fn find_by_kid(
        kid: &str,
        profile: &str,
        database: &Database,
    ) -> Result<Option<Eab>, sqlx::Error> {
        debug!(event = "eab_find_by_kid_started", kid = ?kid, profile = %profile);
        let row = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys \
             WHERE kid = ? AND (profile IS NULL OR profile = ?);",
        )
        .bind(kid)
        .bind(profile)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Eab::from_row).transpose()
    }

    /// Looks a credential up by kid regardless of the profile it is scoped to
    /// -- the admin CLI's `eab show`/`eab revoke`, where the operator holds the
    /// kid and wants to see it whatever it is bound to. Never the request path,
    /// which must use [`Eab::find_by_kid`].
    pub async fn find_any_by_kid(
        kid: &str,
        database: &Database,
    ) -> Result<Option<Eab>, sqlx::Error> {
        debug!(event = "eab_find_any_by_kid_started", kid = ?kid);
        let row = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys WHERE kid = ?;",
        )
        .bind(kid)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Eab::from_row).transpose()
    }

    /// Lists every key, oldest first -- the admin CLI's `eab list`.
    pub async fn list_all(database: &Database) -> Result<Vec<Eab>, sqlx::Error> {
        debug!(event = "eab_list_all_started");
        let rows = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys ORDER BY created_at ASC;",
        )
        .fetch_all(&database.pool)
        .await?;

        rows.into_iter().map(Eab::from_row).collect()
    }

    /// Moves the key to the terminal-for-new-use `revoked` state. Existing
    /// accounts bound under it are unaffected (see the migration's note on
    /// `accounts.eab_kid`). Idempotent: revoking an already-revoked key still
    /// matches the row and reports `true`. Returns whether a row existed.
    pub async fn revoke(kid: &str, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "eab_revoke_started", kid = ?kid);
        let result = sqlx::query("UPDATE eab_keys SET status = 'revoked' WHERE kid = ?;")
            .bind(kid)
            .execute(&database.pool)
            .await?;

        let updated = result.rows_affected() > 0;
        if updated {
            info!(event = "eab_revoked", kid = ?kid);
        } else {
            debug!(event = "eab_revoke_missing", kid = ?kid);
        }
        Ok(updated)
    }

    /// Whether this key may still be used to bind a new account.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// The admin-facing rendering: `kid`, `label`, `profile`, `status`,
    /// `createdAt`.
    /// **Never** includes the secret -- that is shown once, by `eab create`,
    /// via `admin::render_eab_created_json`/`render_eab_created_text`, never
    /// again from `show`/`list`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "kid": self.kid,
            "label": self.label,
            "profile": self.profile,
            "status": self.status,
            "createdAt": rfc3339(self.created_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn create_persists_an_active_key_with_a_32_byte_secret() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("team-a".to_string()), None, &db)
            .await
            .unwrap();
        assert_eq!(eab.status, "active");
        assert_eq!(eab.secret.len(), 32);
        assert_eq!(eab.label.as_deref(), Some("team-a"));
    }

    #[tokio::test]
    async fn find_by_kid_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let created = Eab::create(None, None, &db).await.unwrap();
        let found = Eab::find_by_kid(&created.kid, "default", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.secret, created.secret);
        assert!(found.label.is_none());
    }

    #[tokio::test]
    async fn find_by_kid_of_unknown_returns_none() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(
            Eab::find_by_kid("nope", "default", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_all_orders_oldest_first_and_empty_is_empty() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Eab::list_all(&db).await.unwrap().is_empty());

        let first = Eab::create(None, None, &db).await.unwrap();
        let second = Eab::create(None, None, &db).await.unwrap();
        let all = Eab::list_all(&db).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].kid, first.kid);
        assert_eq!(all[1].kid, second.kid);
    }

    #[tokio::test]
    async fn revoke_marks_revoked_reports_true_and_is_idempotent() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        assert!(Eab::revoke(&eab.kid, &db).await.unwrap());
        assert!(
            !Eab::find_by_kid(&eab.kid, "default", &db)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        // Revoking again still matches the row.
        assert!(Eab::revoke(&eab.kid, &db).await.unwrap());
    }

    #[tokio::test]
    async fn revoke_of_unknown_kid_reports_false() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(!Eab::revoke("nope", &db).await.unwrap());
    }

    #[tokio::test]
    async fn to_json_never_includes_the_secret() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("x".to_string()), None, &db).await.unwrap();
        let json = eab.to_json();
        assert!(json.get("secret").is_none());
        assert!(json.get("hmacKey").is_none());
        assert_eq!(json["kid"], eab.kid);
        assert_eq!(json["status"], "active");
        assert_eq!(json["label"], "x");
    }
}
