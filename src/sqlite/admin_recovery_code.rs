use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{info, warn};

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::rfc3339;

/// One single-use recovery code of an [`crate::sqlite::admin_user::AdminUser`].
///
/// **This layer never sees a plaintext code.** `code_hash` arrives already
/// hashed from `admin::mfa`, through the very same
/// [`crate::admin::password`] this crate hashes operator passwords with -- a
/// recovery code is only ever compared, never needed back, so a read of this
/// table yields nothing replayable. That is the opposite of
/// `admin_users.totp_secret`, which verification needs in the clear.
///
/// ## Methods
///
/// - `replace_all`: mint a set, superseding the previous one, in one transaction
/// - `list_unused` / `count_unused`: what verification walks, and what the panel shows
/// - `consume`: spend one, single-use decided by the database
/// - `delete_for_user`: what removing the factor takes with it
#[derive(Debug, Clone)]
pub struct AdminRecoveryCode {
    pub id: String,
    pub user_id: String,
    /// `<algo>$<params>$<salt>$<hash>`, exactly a `password_hash`.
    pub code_hash: String,
    pub created_at: i64,
    /// When it was spent. `None` is the only usable state.
    pub used_at: Option<i64>,
}

impl AdminRecoveryCode {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(AdminRecoveryCode {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            code_hash: row.try_get("code_hash")?,
            created_at: row.try_get("created_at")?,
            used_at: row.try_get("used_at")?,
        })
    }

    /// Replaces this user's whole set with `hashes`.
    ///
    /// One transaction, and that is the point: a regeneration that failed
    /// halfway between the DELETE and the INSERTs would leave the operator
    /// holding a printed set that no longer works, or -- worse -- half the old
    /// set still live alongside the new one.
    ///
    /// Deletes the *used* rows too. They are an audit trail of the set being
    /// superseded, not of anything still reachable, and keeping them would make
    /// "10 minted, 7 remaining" a sum over sets.
    pub async fn replace_all(
        user_id: &str,
        hashes: &[String],
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        let mut tx = database.pool.begin().await?;

        sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = ?;")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        for hash in hashes {
            sqlx::query(
                "INSERT INTO admin_recovery_codes (id, user_id, code_hash, created_at, used_at) \
                 VALUES (?, ?, ?, ?, NULL);",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(hash)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        info!(
            event = "admin_recovery_codes_replaced",
            user_id = %user_id,
            minted = hashes.len()
        );
        Ok(())
    }

    /// The unspent codes, oldest first -- what `admin::mfa` walks one PBKDF2
    /// run at a time when a submission is not a TOTP code.
    pub async fn list_unused(
        user_id: &str,
        database: &Database,
    ) -> Result<Vec<AdminRecoveryCode>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, user_id, code_hash, created_at, used_at \
             FROM admin_recovery_codes WHERE user_id = ? AND used_at IS NULL \
             ORDER BY created_at ASC, id ASC;",
        )
        .bind(user_id)
        .fetch_all(&database.pool)
        .await?;

        rows.into_iter().map(AdminRecoveryCode::from_row).collect()
    }

    /// How many are left -- the "7 of 10 remaining" the panel and
    /// `admin user totp status` both show.
    pub async fn count_unused(user_id: &str, database: &Database) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS total FROM admin_recovery_codes \
             WHERE user_id = ? AND used_at IS NULL;",
        )
        .bind(user_id)
        .fetch_one(&database.pool)
        .await?;

        row.try_get("total")
    }

    /// Spends one code. `false` means it was already spent, or gone.
    ///
    /// The `used_at IS NULL` test lives in the `WHERE` clause rather than in a
    /// read the caller does first: two submissions of one code racing must not
    /// both succeed, and `rows_affected` is what decides which one did. Same
    /// primitive as `Nonce::verify`.
    ///
    /// Stamps rather than deletes -- see the migration's comment: "this code was
    /// spent, at T" is the audit trail a recovery-code use exists to leave.
    pub async fn consume(id: &str, database: &Database) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE admin_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL;",
        )
        .bind(now_secs())
        .bind(id)
        .execute(&database.pool)
        .await?;

        let consumed = result.rows_affected() == 1;
        if !consumed {
            // Only reachable from a race or a double-submit, both of which are
            // worth seeing: the caller already matched the hash, so this is a
            // correct code arriving a second time.
            warn!(event = "admin_recovery_code_already_used", code_id = %id);
        }
        Ok(consumed)
    }

    /// Drops every code of one user -- what removing the second factor takes
    /// with it, since a recovery code recovers access to a factor that no
    /// longer exists.
    pub async fn delete_for_user(user_id: &str, database: &Database) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = ?;")
            .bind(user_id)
            .execute(&database.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// The admin-facing rendering. **Never** `code_hash`: it is a password
    /// hash, and no front end has a reason to see one.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "createdAt": rfc3339(self.created_at),
            "usedAt": self.used_at.map(rfc3339),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_user::AdminUser;
    use std::sync::Arc;

    async fn db_with_user() -> (Arc<Database>, AdminUser) {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let user = AdminUser::create("alice", "hash", &db).await.unwrap();
        (db, user)
    }

    fn hashes(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("hash-{index}")).collect()
    }

    #[tokio::test]
    async fn replace_all_mints_a_set_and_supersedes_the_previous_one() {
        let (db, user) = db_with_user().await;

        AdminRecoveryCode::replace_all(&user.id, &hashes(10), &db)
            .await
            .unwrap();
        assert_eq!(
            AdminRecoveryCode::count_unused(&user.id, &db)
                .await
                .unwrap(),
            10
        );

        // Spend one, then regenerate: the old set must be gone entirely --
        // both the eight still live and the one already spent, or "remaining"
        // would be a sum over sets.
        let first = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap()[0]
            .id
            .clone();
        assert!(AdminRecoveryCode::consume(&first, &db).await.unwrap());
        assert_eq!(
            AdminRecoveryCode::count_unused(&user.id, &db)
                .await
                .unwrap(),
            9
        );

        AdminRecoveryCode::replace_all(&user.id, &hashes(10), &db)
            .await
            .unwrap();
        let after = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap();
        assert_eq!(after.len(), 10);
        assert!(
            after.iter().all(|code| code.id != first),
            "no row of the superseded set may survive"
        );
    }

    /// The single-use guard, which is the whole reason this is a table and not
    /// a JSON column.
    #[tokio::test]
    async fn a_code_can_be_consumed_exactly_once() {
        let (db, user) = db_with_user().await;
        AdminRecoveryCode::replace_all(&user.id, &hashes(3), &db)
            .await
            .unwrap();

        let code = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap()[0].clone();

        assert!(AdminRecoveryCode::consume(&code.id, &db).await.unwrap());
        assert!(
            !AdminRecoveryCode::consume(&code.id, &db).await.unwrap(),
            "a second consumption of one code must fail, whatever raced it"
        );
        assert!(
            !AdminRecoveryCode::consume("no-such-code", &db)
                .await
                .unwrap()
        );

        // And it leaves the audit stamp rather than the row.
        let remaining = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|other| other.id != code.id));
    }

    #[tokio::test]
    async fn deleting_the_operator_cascades_to_their_codes() {
        let (db, user) = db_with_user().await;
        AdminRecoveryCode::replace_all(&user.id, &hashes(10), &db)
            .await
            .unwrap();

        assert!(AdminUser::delete(&user.id, &db).await.unwrap());
        assert_eq!(
            AdminRecoveryCode::count_unused(&user.id, &db)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn delete_for_user_removes_the_whole_set() {
        let (db, user) = db_with_user().await;
        AdminRecoveryCode::replace_all(&user.id, &hashes(10), &db)
            .await
            .unwrap();

        assert_eq!(
            AdminRecoveryCode::delete_for_user(&user.id, &db)
                .await
                .unwrap(),
            10
        );
        assert_eq!(
            AdminRecoveryCode::count_unused(&user.id, &db)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn to_json_leaks_no_hash() {
        let (db, user) = db_with_user().await;
        AdminRecoveryCode::replace_all(&user.id, &["a-secret-hash".to_string()], &db)
            .await
            .unwrap();

        let code = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap()[0].clone();
        let rendered = code.to_json().to_string();

        assert!(!rendered.contains("a-secret-hash"));
        assert!(!rendered.contains("codeHash"));
        assert!(rendered.contains(&code.id));
        assert!(rendered.contains("\"usedAt\":null"));
    }
}
