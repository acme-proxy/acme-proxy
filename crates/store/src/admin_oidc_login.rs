//! The `admin_oidc_logins` table: one OpenID Connect sign-in between the
//! redirect to the provider and the callback that brings the browser back.
//!
//! A row is **consumed** by the callback -- [`AdminOidcLogin::take`] deletes it
//! and returns it in one statement -- so a `state` value answers exactly one
//! callback, and two callbacks racing on it see one winner. In the database
//! rather than in a signed cookie for ADR 0008's reason: the admin process the
//! browser returns to need not be the one that sent it out.
//!
//! The keys are hashes (`state` travels in a URL; the binding secret in a
//! cookie), so a database read yields nothing a callback would accept. The
//! callers are in `admin::identity::oidc`; the migration
//! (`20261009120000_admin_external_identities.sql`) argues each column.

use tracing::debug;

use crate::db::Database;
use crate::sql::Row;

/// One sign-in in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOidcLogin {
    /// hex(SHA-256(`state`)).
    pub state_hash: String,
    /// The `[admin.auth.oidc.<name>]` table the browser was sent to.
    pub provider: String,
    /// hex(SHA-256(the browser-binding cookie)).
    pub binding_hash: String,
    /// The ID token's expected `nonce`.
    pub nonce: String,
    /// RFC 7636's `code_verifier`, sent with the authorization code.
    pub pkce_verifier: String,
    pub created_at: i64,
    /// Epoch seconds; [`AdminOidcLogin::take`] refuses a row at or past it.
    pub expires_at: i64,
}

impl AdminOidcLogin {
    fn from_row(row: Row) -> Result<Self, sqlx::Error> {
        Ok(Self {
            state_hash: row.try_get("state_hash")?,
            provider: row.try_get("provider")?,
            binding_hash: row.try_get("binding_hash")?,
            nonce: row.try_get("nonce")?,
            pkce_verifier: row.try_get("pkce_verifier")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }

    /// Records the sign-in. `state_hash` is 256 bits of CSPRNG output hashed,
    /// so a collision is a primary-key violation nobody will ever see.
    pub async fn create(&self, database: &Database) -> Result<(), sqlx::Error> {
        crate::sql::query(
            "INSERT INTO admin_oidc_logins \
             (state_hash, provider, binding_hash, nonce, pkce_verifier, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(&self.state_hash)
        .bind(&self.provider)
        .bind(&self.binding_hash)
        .bind(&self.nonce)
        .bind(&self.pkce_verifier)
        .bind(self.created_at)
        .bind(self.expires_at)
        .execute(database)
        .await?;
        debug!(event = "db_admin_oidc_login_created", outcome = "success", provider = %self.provider, expires_at = self.expires_at);
        Ok(())
    }

    /// Consumes the sign-in keyed `state_hash`: deletes it and returns it,
    /// unless it has expired.
    ///
    /// One `DELETE ... RETURNING`, which is what makes a `state` single-use
    /// under a race -- the `Nonce::verify` primitive. An expired row is deleted
    /// too (it can never be good again) but answers `None`.
    pub async fn take(
        state_hash: &str,
        now: i64,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        let row = crate::sql::query(
            "DELETE FROM admin_oidc_logins WHERE state_hash = ? \
             RETURNING state_hash, provider, binding_hash, nonce, pkce_verifier, \
             created_at, expires_at;",
        )
        .bind(state_hash)
        .fetch_optional(database)
        .await?;
        let Some(login) = row.map(Self::from_row).transpose()? else {
            return Ok(None);
        };
        Ok((login.expires_at > now).then_some(login))
    }

    /// Deletes every sign-in at or past its `expires_at`, returning how many.
    pub async fn cleanup(now: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let result = crate::sql::query("DELETE FROM admin_oidc_logins WHERE expires_at <= ?;")
            .bind(now)
            .execute(database)
            .await?;
        // Debug: the sweep reports the pass that called this.
        debug!(
            event = "db_admin_oidc_login_cleanup_completed",
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

    fn login(state_hash: &str, expires_at: i64) -> AdminOidcLogin {
        AdminOidcLogin {
            state_hash: state_hash.to_string(),
            provider: "corp".to_string(),
            binding_hash: "binding".to_string(),
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            created_at: 0,
            expires_at,
        }
    }

    /// A `state` answers one callback: the second `take` finds nothing.
    #[tokio::test]
    async fn take_consumes_the_sign_in_once() {
        let database = Database::connect_for_test().await.unwrap();
        let created = login("state", 100);
        created.create(&database).await.unwrap();

        assert_eq!(
            AdminOidcLogin::take("state", 10, &database).await.unwrap(),
            Some(created)
        );
        assert_eq!(
            AdminOidcLogin::take("state", 10, &database).await.unwrap(),
            None
        );
    }

    /// An expired sign-in is refused, and deleted all the same.
    #[tokio::test]
    async fn an_expired_sign_in_is_refused_and_gone() {
        let database = Database::connect_for_test().await.unwrap();
        login("state", 100).create(&database).await.unwrap();

        assert_eq!(
            AdminOidcLogin::take("state", 100, &database).await.unwrap(),
            None
        );
        assert_eq!(AdminOidcLogin::cleanup(1_000, &database).await.unwrap(), 0);
    }

    /// The sweep takes exactly the rows past their deadline.
    #[tokio::test]
    async fn cleanup_removes_only_expired_sign_ins() {
        let database = Database::connect_for_test().await.unwrap();
        login("old", 50).create(&database).await.unwrap();
        login("live", 500).create(&database).await.unwrap();

        assert_eq!(AdminOidcLogin::cleanup(50, &database).await.unwrap(), 1);
        assert!(
            AdminOidcLogin::take("live", 50, &database)
                .await
                .unwrap()
                .is_some()
        );
    }
}
