use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::random::random_bytes;
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
/// - `search`: one page of the listing, newest first, plus the unpaged total --
///   the only listing of this table, read by `eab list`, `/ui/eab` and
///   `GET /api/eab` alike
/// - `revoke`: move to the terminal `revoked` state
/// - `to_json`: admin-facing rendering (never includes the secret)
#[derive(Debug)]
pub struct Eab {
    pub kid: Uuid,
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
            kid: crate::sqlite::id::mint(),
            secret: random_bytes::<SECRET_LEN>().to_vec(),
            label,
            profile,
            status: "active".to_string(),
            created_at: now_secs(),
        };

        debug!(event = "db_eab_create_started", outcome = "progress", kid = ?eab.kid, profile = ?eab.profile);
        sqlx::query(
            "INSERT INTO eab_keys (kid, secret, label, profile, status, created_at) \
             VALUES (?, ?, ?, ?, ?, ?);",
        )
        .bind(eab.kid)
        .bind(&eab.secret)
        .bind(&eab.label)
        .bind(&eab.profile)
        .bind(&eab.status)
        .bind(eab.created_at)
        .execute(&database.pool)
        .await?;

        info!(event = "db_eab_created", outcome = "success", kid = ?eab.kid);
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
        debug!(event = "db_eab_find_by_kid_started", outcome = "progress", kid = ?kid, profile = %profile);
        let Some(kid) = crate::sqlite::id::parse(kid) else {
            return Ok(None);
        };
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
        debug!(event = "db_eab_find_any_by_kid_started", outcome = "progress", kid = ?kid);
        let Some(kid) = crate::sqlite::id::parse(kid) else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys WHERE kid = ?;",
        )
        .bind(kid)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Eab::from_row).transpose()
    }

    /// One page of the listing, plus the total the table holds unpaged.
    ///
    /// The **only** listing of this table: `GET /api/eab`, `/ui/eab` and
    /// `eab list` all read it, which is what stops the three describing one
    /// credential set differently.
    ///
    /// **Newest first**, like `Account::search` and `Order::search`. It was
    /// oldest first while the page and the command still read an unpaged
    /// `list_all` — the reason recorded here was that flipping it would make
    /// the API disagree with them — and that reason expired when both moved
    /// onto this query. What settles the direction now is the mint form:
    /// `pages::eab::create_eab` re-renders the table out of band so a new
    /// credential appears without a reload, and the only page it can sensibly
    /// render is the first, so the new row has to be on it. `kid` breaks the
    /// `created_at` tie for `Account::search`'s reason — whole-second
    /// timestamps would otherwise let two rows swap between pages, and one of
    /// them would never be seen — and it breaks it **`DESC`**, following the
    /// primary key rather than opposing it: a `kid` is a UUID v7, so an `ASC`
    /// tiebreak would hand back the *oldest* of the credentials minted inside
    /// one second, which is exactly the second the mint form re-renders in.
    pub async fn search(
        limit: i64,
        offset: i64,
        database: &Database,
    ) -> Result<(Vec<Eab>, i64), sqlx::Error> {
        debug!(
            event = "db_eab_search_started",
            outcome = "progress",
            limit = limit,
            offset = offset
        );
        let rows = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys \
             ORDER BY created_at DESC, kid DESC LIMIT ? OFFSET ?;",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&database.pool)
        .await?;
        let total: i64 = sqlx::query("SELECT COUNT(*) FROM eab_keys;")
            .fetch_one(&database.pool)
            .await?
            .try_get(0)?;

        let keys = rows
            .into_iter()
            .map(Eab::from_row)
            .collect::<Result<_, _>>()?;
        Ok((keys, total))
    }

    /// Moves the key to the terminal-for-new-use `revoked` state. Existing
    /// accounts bound under it are unaffected (see the migration's note on
    /// `accounts.eab_kid`). Idempotent: revoking an already-revoked key still
    /// matches the row and reports `true`. Returns whether a row existed.
    pub async fn revoke(kid: &str, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "db_eab_revoke_started", outcome = "progress", kid = ?kid);
        let Some(kid) = crate::sqlite::id::parse(kid) else {
            return Ok(false);
        };
        let result = sqlx::query("UPDATE eab_keys SET status = 'revoked' WHERE kid = ?;")
            .bind(kid)
            .execute(&database.pool)
            .await?;

        let updated = result.rows_affected() > 0;
        if updated {
            info!(event = "db_eab_revoked", outcome = "success", kid = ?kid);
        } else {
            debug!(event = "db_eab_revoke_missing", outcome = "success", kid = ?kid);
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
        let found = Eab::find_by_kid(created.kid.to_string().as_str(), "default", &db)
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

    /// Every key comes back, newest first, and an empty table is empty rather
    /// than an error.
    ///
    /// `created_at` is a whole second, so two keys minted in one test share it
    /// and the `kid` tie-break decides. That used to be a random uuid, and this
    /// test could say nothing about which came first; a `kid` is now a UUID v7
    /// (`sqlite::id::mint`), so the tie-break is insertion order -- the same
    /// observable `list_all_returns_every_user_and_empty_is_empty`
    /// (`sqlite::admin_user`) asserts, and for the same reason. It holds only
    /// for rows minted since that change, nothing having been backfilled.
    ///
    /// The direction is what `pages::eab::create_eab` rests on: it re-renders
    /// the first page out of band, so a credential minted a moment ago has to
    /// be its first row.
    #[tokio::test]
    async fn search_returns_every_key_newest_first_and_empty_is_empty() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Eab::search(50, 0, &db).await.unwrap().0.is_empty());

        let first = Eab::create(None, None, &db).await.unwrap();
        let second = Eab::create(None, None, &db).await.unwrap();
        let (all, total) = Eab::search(50, 0, &db).await.unwrap();
        assert_eq!((all.len(), total), (2, 2));
        let kids: Vec<String> = all.iter().map(|eab| eab.kid.to_string()).collect();
        assert_eq!(kids, [second.kid.to_string(), first.kid.to_string()]);
    }

    /// The window `GET /api/eab` hands down. Every row created inside one
    /// second here, which is exactly the case the `kid` tie-break exists for:
    /// without it two rows could swap between pages and one would never be
    /// seen.
    #[tokio::test]
    async fn search_pages_without_overlap_and_reports_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert_eq!(Eab::search(50, 0, &db).await.unwrap().1, 0);

        let created: Vec<String> = {
            let mut kids = Vec::new();
            for _ in 0..5 {
                kids.push(Eab::create(None, None, &db).await.unwrap().kid);
            }
            kids.into_iter().map(|v| v.to_string()).collect()
        };

        let (first, total) = Eab::search(2, 0, &db).await.unwrap();
        let (second, also_total) = Eab::search(2, 2, &db).await.unwrap();
        let (third, _) = Eab::search(2, 4, &db).await.unwrap();

        assert_eq!(total, 5);
        assert_eq!(also_total, 5, "the total is the table, not the page");
        assert_eq!((first.len(), second.len(), third.len()), (2, 2, 1));

        // Walked end to end, the pages are the table exactly once — which is
        // both "no overlap" and "nothing skipped" in one assertion.
        let walked: Vec<String> = first
            .iter()
            .chain(second.iter())
            .chain(third.iter())
            .map(|eab| eab.kid.to_string())
            .collect();
        assert_eq!(walked.len(), created.len());
        for kid in &created {
            assert_eq!(
                walked.iter().filter(|seen| *seen == kid).count(),
                1,
                "{kid} was not on exactly one page"
            );
        }
    }

    #[tokio::test]
    async fn revoke_marks_revoked_reports_true_and_is_idempotent() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        assert!(
            Eab::revoke(eab.kid.to_string().as_str(), &db)
                .await
                .unwrap()
        );
        assert!(
            !Eab::find_by_kid(eab.kid.to_string().as_str(), "default", &db)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        // Revoking again still matches the row.
        assert!(
            Eab::revoke(eab.kid.to_string().as_str(), &db)
                .await
                .unwrap()
        );
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
        assert_eq!(json["kid"], eab.kid.to_string());
        assert_eq!(json["status"], "active");
        assert_eq!(json["label"], "x");
    }
}
