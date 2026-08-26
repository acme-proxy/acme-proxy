use std::time::Duration;
use uuid::Uuid;

use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};

use crate::sqlite::db::Database;
use crate::sqlite::nonce::{fingerprint, now_secs};
use crate::sqlite::order::rfc3339;

/// One logged-in browser session of an [`crate::sqlite::admin_user::AdminUser`].
///
/// **This layer never sees the session token.** `token_hash` arrives already
/// hashed from `webadmin::session`, which is the only place the plaintext
/// exists: it goes into a `Set-Cookie` and is never written down. A read of
/// this table -- a backup, a `.dump`, an injection -- therefore yields nothing
/// that can be replayed. That is also why there is no `find_by_id`: the hash
/// *is* the lookup key, and knowing it means already holding the token.
///
/// ## Methods
///
/// - `create`: persist a session for a user
/// - `find_by_token_hash`: the per-request resolution path
/// - `touch`: advance the idle deadline
/// - `delete` / `delete_for_user` / `delete_for_user_except`: logout, revoke all,
///   and the "keep the session doing the changing" case a password change needs
/// - `list_all`: admin CLI visibility
/// - `cleanup`: the reaper's sweep
/// - `to_json`: admin-facing rendering (never the token hash or the CSRF token)
#[derive(Debug, Clone)]
pub struct AdminSession {
    /// Hex-encoded SHA-256 of the cookie's bearer token.
    pub token_hash: String,
    pub user_id: Uuid,
    /// Per-session CSRF token, plaintext: it authorises nothing on its own.
    pub csrf_token: String,
    /// `active`, or `pending_mfa` once a second factor exists to be outstanding.
    pub state: String,
    /// Second-factor codes rejected against this session. Advanced only by
    /// [`AdminSession::record_mfa_failure`], which is where the reasoning is.
    pub mfa_attempts: i64,
    pub created_at: i64,
    /// Absolute deadline. Never extended.
    pub expires_at: i64,
    /// Idle deadline, advanced by [`AdminSession::touch`].
    pub last_seen_at: i64,
    /// Forensics only -- never compared against the request being served.
    pub created_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Everything a new session row needs from its caller.
///
/// A struct rather than three positional `&str`s, and that is a security
/// property rather than a style one: `token_hash` and `csrf_token` were
/// adjacent same-typed parameters, so transposing them at a call site compiled
/// cleanly and produced a session whose CSRF token *is* its session token hash
/// — a value that has already crossed the wire in a cookie. Named fields make
/// that unwriteable.
///
/// It also retires two `#[allow(clippy::too_many_arguments)]`.
#[derive(Debug, Clone)]
pub struct NewSession<'a> {
    pub user_id: Uuid,
    /// Hex-encoded SHA-256 of the cookie token. Minted by the caller: this
    /// layer holds no RNG and so cannot accidentally reuse one.
    pub token_hash: &'a str,
    pub csrf_token: &'a str,
    /// Forensics only -- see the `created_ip` column.
    pub created_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Every column of `admin_sessions`, in one place: each read must select the same set
/// or `from_row` fails on whichever forgot one.
///
/// A `macro_rules!` rather than a `const` so the expansion is a string
/// *literal*, which is what `sqlx::query`'s `SqlSafeStr` bound requires.
macro_rules! columns {
    () => {
        "token_hash, user_id, csrf_token, state, mfa_attempts, created_at, \
         expires_at, last_seen_at, created_ip, user_agent"
    };
}

impl AdminSession {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(AdminSession {
            token_hash: row.try_get("token_hash")?,
            user_id: row.try_get("user_id")?,
            csrf_token: row.try_get("csrf_token")?,
            state: row.try_get("state")?,
            mfa_attempts: row.try_get("mfa_attempts")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            created_ip: row.try_get("created_ip")?,
            user_agent: row.try_get("user_agent")?,
        })
    }

    /// Persists a fresh `active` session expiring `ttl` from now.
    pub async fn create(
        new: NewSession<'_>,
        ttl: Duration,
        database: &Database,
    ) -> Result<AdminSession, sqlx::Error> {
        Self::create_with_state("active", new, ttl, database).await
    }

    /// Persists a fresh **`pending_mfa`** session: a password was accepted and
    /// nothing more.
    ///
    /// `ttl` is `webadmin::session::PENDING_MFA_TTL`, not the configured session
    /// lifetime -- a half-authenticated row should not outlive the tab that
    /// created it, and that short absolute deadline is one of the two bounds on
    /// how long an attacker holding a password may keep guessing codes (the
    /// other is [`AdminSession::record_mfa_failure`]).
    ///
    /// The reaper needs no special case for these: `expires_at` is set the same
    /// way, so `cleanup`'s existing `expires_at <= ?` sweeps them.
    pub async fn create_pending(
        new: NewSession<'_>,
        ttl: Duration,
        database: &Database,
    ) -> Result<AdminSession, sqlx::Error> {
        Self::create_with_state("pending_mfa", new, ttl, database).await
    }

    /// The body both constructors share. Private: `state` is not a parameter
    /// any caller outside this file gets to choose, and there is deliberately no
    /// setter for it -- see [`AdminSession::promote`].
    async fn create_with_state(
        state: &str,
        new: NewSession<'_>,
        ttl: Duration,
        database: &Database,
    ) -> Result<AdminSession, sqlx::Error> {
        let now = now_secs();
        let session = AdminSession {
            token_hash: new.token_hash.to_string(),
            user_id: new.user_id,
            csrf_token: new.csrf_token.to_string(),
            state: state.to_string(),
            mfa_attempts: 0,
            created_at: now,
            // Saturating, for the same reason `Nonce::verify`'s cutoff is: a
            // configured TTL large enough to overflow must not panic.
            expires_at: now.saturating_add(ttl.as_secs() as i64),
            last_seen_at: now,
            created_ip: new.created_ip,
            user_agent: new.user_agent,
        };

        sqlx::query(
            "INSERT INTO admin_sessions (token_hash, user_id, csrf_token, state, created_at, \
             expires_at, last_seen_at, created_ip, user_agent) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(&session.token_hash)
        .bind(session.user_id)
        .bind(&session.csrf_token)
        .bind(&session.state)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_seen_at)
        .bind(&session.created_ip)
        .bind(&session.user_agent)
        .execute(&database.pool)
        .await?;

        // A fingerprint of the *hash*, not the token -- enough to follow one
        // session across log lines, and derived from something already useless
        // to a reader.
        info!(event = "db_admin_session_created",
              outcome = "success",
              session_fp = %fingerprint(&session.token_hash),
              user_id = %session.user_id,
              state = %session.state);
        Ok(session)
    }

    /// Replaces a `pending_mfa` session with a fresh `active` one: a new token,
    /// a new CSRF token, a full `ttl`, and the same user and forensics.
    ///
    /// A **rotation**, not an `UPDATE state`. The pending token is a real bearer
    /// token that a browser stored and that has crossed the wire, minted before
    /// authentication completed; its privilege level changing means its value
    /// changes -- the same rule that makes `sign_in` delete whatever session the
    /// request already carried. The CSRF token rotates for free, which matters
    /// because the challenge page had to be handed one.
    ///
    /// One transaction, and the DELETE's `rows_affected` is the concurrency
    /// guard: two submissions of one code promote exactly once. `None` means
    /// nothing pending sat under `pending_token_hash` -- already promoted,
    /// already swept, or never there.
    ///
    /// The side effect worth having: with no setter for `state` anywhere, the
    /// column is write-once at INSERT, so no code path can move a session
    /// between states in place.
    pub async fn promote(
        pending_token_hash: &str,
        new_token_hash: &str,
        new_csrf_token: &str,
        ttl: Duration,
        database: &Database,
    ) -> Result<Option<AdminSession>, sqlx::Error> {
        let mut tx = database.pool.begin().await?;

        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_sessions WHERE token_hash = ? AND state = 'pending_mfa';"
        ))
        .bind(pending_token_hash)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(pending) = row.map(AdminSession::from_row).transpose()? else {
            return Ok(None);
        };

        // The DELETE, not the SELECT, is what makes this exclusive: two
        // transactions can both read the pending row, but only one removes it.
        let removed = sqlx::query("DELETE FROM admin_sessions WHERE token_hash = ?;")
            .bind(pending_token_hash)
            .execute(&mut *tx)
            .await?;
        if removed.rows_affected() != 1 {
            return Ok(None);
        }

        let now = now_secs();
        let session = AdminSession {
            token_hash: new_token_hash.to_string(),
            user_id: pending.user_id,
            csrf_token: new_csrf_token.to_string(),
            state: "active".to_string(),
            // Deliberately not carried over: the promoted session is a fresh
            // one, and the counter only ever bounded the pending row it
            // replaced.
            mfa_attempts: 0,
            created_at: now,
            expires_at: now.saturating_add(ttl.as_secs() as i64),
            last_seen_at: now,
            created_ip: pending.created_ip,
            user_agent: pending.user_agent,
        };

        sqlx::query(
            "INSERT INTO admin_sessions (token_hash, user_id, csrf_token, state, created_at, \
             expires_at, last_seen_at, created_ip, user_agent) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(&session.token_hash)
        .bind(session.user_id)
        .bind(&session.csrf_token)
        .bind(&session.state)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_seen_at)
        .bind(&session.created_ip)
        .bind(&session.user_agent)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        info!(event = "db_admin_session_promoted",
              outcome = "success",
              session_fp = %fingerprint(&session.token_hash),
              replaced = %fingerprint(pending_token_hash),
              user_id = %session.user_id);
        Ok(Some(session))
    }

    /// Counts one rejected second-factor code against this session, returning
    /// the new total.
    ///
    /// **The bound an attacker cannot shed.** `webadmin::session::LoginLimiter`
    /// keys on the peer address, and a `pending_mfa` cookie is valid from any
    /// address on purpose (see `created_ip`: pinning breaks CGNAT and mobile).
    /// Somebody holding a correct password could therefore mint one pending
    /// session and spend `admin.login_max_attempts` guesses per source address,
    /// which a single IPv6 /64 supplies 2^64 of. This counter travels with the
    /// session instead, so rotating addresses buys nothing.
    ///
    /// One `UPDATE ... RETURNING`, which is also what makes it race-free: this
    /// listener carries no admission control by design, so a read-then-write
    /// would let K concurrent submissions all observe zero and each get a free
    /// guess. `None` means the row is already gone -- swept, promoted, or
    /// deleted by a concurrent submission that hit the cap first.
    pub async fn record_mfa_failure(
        token_hash: &str,
        database: &Database,
    ) -> Result<Option<i64>, sqlx::Error> {
        let row = sqlx::query(
            "UPDATE admin_sessions SET mfa_attempts = mfa_attempts + 1 \
             WHERE token_hash = ? RETURNING mfa_attempts;",
        )
        .bind(token_hash)
        .fetch_optional(&database.pool)
        .await?;

        let attempts = row
            .map(|row| row.try_get::<i64, _>("mfa_attempts"))
            .transpose()?;
        if let Some(attempts) = attempts {
            debug!(event = "db_admin_session_mfa_failure_recorded",
                   outcome = "success",
                   session_fp = %fingerprint(token_hash),
                   attempts);
        }
        Ok(attempts)
    }

    /// The per-request resolution path. Returns the row whatever its state --
    /// expiry, idleness and `state` are the caller's to judge, since each maps
    /// to a different refusal.
    pub async fn find_by_token_hash(
        token_hash: &str,
        database: &Database,
    ) -> Result<Option<AdminSession>, sqlx::Error> {
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_sessions WHERE token_hash = ?;"
        ))
        .bind(token_hash)
        .fetch_optional(&database.pool)
        .await?;

        row.map(AdminSession::from_row).transpose()
    }

    /// Advances the idle deadline. Callers rate-limit this -- see
    /// `webadmin::session::SESSION_TOUCH_INTERVAL` -- because a polling page
    /// would otherwise take the WAL writer lock on every request.
    pub async fn touch(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?;")
            .bind(now)
            .bind(&self.token_hash)
            .execute(&database.pool)
            .await?;

        self.last_seen_at = now;
        Ok(())
    }

    /// Logout. Returns whether a row existed.
    pub async fn delete(token_hash: &str, database: &Database) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE token_hash = ?;")
            .bind(token_hash)
            .execute(&database.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            info!(event = "db_admin_session_deleted", outcome = "success", session_fp = %fingerprint(token_hash));
        }
        Ok(deleted)
    }

    /// Revokes every session of one user -- `admin session revoke --user`, and
    /// the "log me out everywhere" case. Returns how many went.
    pub async fn delete_for_user(user_id: Uuid, database: &Database) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE user_id = ?;")
            .bind(user_id)
            .execute(&database.pool)
            .await?;

        info!(event = "db_admin_sessions_revoked",
              outcome = "success",
              scope = "user",
              user_id = %user_id,
              rows_removed = result.rows_affected());
        Ok(result.rows_affected())
    }

    /// Revokes every session of one user *except* the one named -- what a
    /// password change needs, so the operator making it is not logged out by
    /// their own action while every other browser is.
    pub async fn delete_for_user_except(
        user_id: Uuid,
        keep_token_hash: &str,
        database: &Database,
    ) -> Result<u64, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM admin_sessions WHERE user_id = ? AND token_hash != ?;")
                .bind(user_id)
                .bind(keep_token_hash)
                .execute(&database.pool)
                .await?;

        info!(event = "db_admin_sessions_revoked",
              outcome = "success",
              scope = "user_except_current",
              user_id = %user_id,
              rows_removed = result.rows_affected());
        Ok(result.rows_affected())
    }

    /// Revokes every session on the server -- `admin session revoke --all`,
    /// the "log everybody out" lever after a scare. Returns how many went.
    pub async fn delete_all(database: &Database) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM admin_sessions;")
            .execute(&database.pool)
            .await?;

        // `scope` rather than the `user_id = "*"` this used to carry: three
        // different operations shared this event name, and a magic value in a
        // field is not a thing an operator can filter on.
        info!(
            event = "db_admin_sessions_revoked",
            outcome = "success",
            scope = "all",
            rows_removed = result.rows_affected()
        );
        Ok(result.rows_affected())
    }

    /// Every session, or every session of one user, newest first.
    pub async fn list_all(
        user_id: Option<Uuid>,
        database: &Database,
    ) -> Result<Vec<AdminSession>, sqlx::Error> {
        // Two literal statements rather than one built up: `sqlx::query` takes
        // only `&'static str`, which is what stops a column list or a
        // predicate ever being interpolated in.
        let rows = match user_id {
            Some(id) => sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM admin_sessions WHERE user_id = ? ORDER BY created_at DESC, token_hash ASC;"
            ))
            .bind(id)
            .fetch_all(&database.pool)
            .await?,
            None => {
                sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM admin_sessions ORDER BY created_at DESC, token_hash ASC;"
                ))
                .fetch_all(&database.pool)
                .await?
            }
        };

        rows.into_iter().map(AdminSession::from_row).collect()
    }

    /// The reaper's sweep: everything past its absolute deadline, plus
    /// everything idle longer than `idle_timeout`. Unlike nonces, sessions
    /// outlive a restart, so a startup-only sweep would leak.
    pub async fn cleanup(idle_timeout: Duration, database: &Database) -> Result<u64, sqlx::Error> {
        let now = now_secs();
        let idle_cutoff = now.saturating_sub(idle_timeout.as_secs() as i64);

        let result =
            sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= ? OR last_seen_at <= ?;")
                .bind(now)
                .bind(idle_cutoff)
                .execute(&database.pool)
                .await?;

        debug!(
            event = "db_admin_session_cleanup_completed",
            outcome = "success",
            rows_removed = result.rows_affected(),
            idle_cutoff = idle_cutoff
        );
        Ok(result.rows_affected())
    }

    /// Past its absolute deadline.
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// Unused for longer than `idle_timeout`.
    #[must_use]
    pub fn is_idle(&self, now: i64, idle_timeout: Duration) -> bool {
        now.saturating_sub(self.last_seen_at) >= idle_timeout.as_secs() as i64
    }

    /// Whether the session has completed authentication. A `pending_mfa`
    /// session has a valid password behind it and nothing more.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }

    /// The admin-facing rendering. **Never** the token hash (it is the lookup
    /// key, and printing it in `admin session list` would put every live
    /// session's key on a terminal) nor the CSRF token.
    ///
    /// `id` is a fingerprint of the hash: enough to name one session to
    /// `admin session revoke`, not enough to reconstruct the key.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": fingerprint(&self.token_hash),
            "userId": self.user_id,
            "state": self.state,
            "createdAt": rfc3339(self.created_at),
            "expiresAt": rfc3339(self.expires_at),
            "lastSeenAt": rfc3339(self.last_seen_at),
            "createdIp": self.created_ip,
            "userAgent": self.user_agent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_user::AdminUser;
    use std::sync::Arc;

    const TTL: Duration = Duration::from_secs(43_200);
    const IDLE: Duration = Duration::from_secs(3_600);

    async fn db_with_user() -> (Arc<Database>, AdminUser) {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let user = AdminUser::create("alice", "hash", &db).await.unwrap();
        (db, user)
    }

    async fn session(db: Arc<Database>, user: &AdminUser, token_hash: &str) -> AdminSession {
        AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash,
                csrf_token: "csrf",
                created_ip: Some("192.0.2.1".to_string()),
                user_agent: Some("curl/8".to_string()),
            },
            TTL,
            &db,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn create_persists_an_active_session_and_round_trips() {
        let (db, user) = db_with_user().await;
        let created = session(db.clone(), &user, "aaaa").await;
        assert!(created.is_active());
        assert_eq!(
            created.expires_at,
            created.created_at + TTL.as_secs() as i64
        );
        assert_eq!(created.last_seen_at, created.created_at);

        let found = AdminSession::find_by_token_hash("aaaa", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, user.id);
        assert_eq!(found.csrf_token, "csrf");
        assert_eq!(found.created_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(found.user_agent.as_deref(), Some("curl/8"));
    }

    #[tokio::test]
    async fn find_by_unknown_token_hash_returns_none() {
        let (db, _user) = db_with_user().await;
        assert!(
            AdminSession::find_by_token_hash("nope", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_session_for_an_unknown_user_is_refused_by_the_foreign_key() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let error = AdminSession::create(
            NewSession {
                user_id: crate::sqlite::id::mint(),
                token_hash: "aaaa",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            TTL,
            &db,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("foreign key"),
            "expected a FOREIGN KEY violation, got: {error}"
        );
    }

    #[tokio::test]
    async fn the_state_check_refuses_a_value_outside_the_schema() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "aaaa").await;
        let error =
            sqlx::query("UPDATE admin_sessions SET state = 'whatever' WHERE token_hash = ?;")
                .bind("aaaa")
                .execute(&db.pool)
                .await
                .unwrap_err();
        assert!(error.to_string().to_lowercase().contains("check"));
    }

    #[tokio::test]
    async fn touch_advances_the_idle_deadline_and_persists() {
        let (db, user) = db_with_user().await;
        let mut created = session(db.clone(), &user, "aaaa").await;
        // Backdate so the advance is observable within one clock second.
        sqlx::query("UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?;")
            .bind(created.created_at - 500)
            .bind("aaaa")
            .execute(&db.pool)
            .await
            .unwrap();

        created.touch(&db).await.unwrap();
        let reloaded = AdminSession::find_by_token_hash("aaaa", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.last_seen_at, created.last_seen_at);
        assert!(reloaded.last_seen_at > created.created_at - 500);
    }

    #[tokio::test]
    async fn delete_reports_whether_a_row_existed() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "aaaa").await;
        assert!(AdminSession::delete("aaaa", &db).await.unwrap());
        assert!(!AdminSession::delete("aaaa", &db).await.unwrap());
    }

    #[tokio::test]
    async fn delete_for_user_removes_every_session_of_that_user_only() {
        let (db, alice) = db_with_user().await;
        let bob = AdminUser::create("bob", "hash", &db).await.unwrap();
        session(db.clone(), &alice, "a1").await;
        session(db.clone(), &alice, "a2").await;
        session(db.clone(), &bob, "b1").await;

        assert_eq!(
            AdminSession::delete_for_user(alice.id, &db).await.unwrap(),
            2
        );
        assert!(
            AdminSession::find_by_token_hash("b1", &db)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_for_user_except_keeps_the_named_session() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "keep").await;
        session(db.clone(), &user, "drop1").await;
        session(db.clone(), &user, "drop2").await;

        assert_eq!(
            AdminSession::delete_for_user_except(user.id, "keep", &db)
                .await
                .unwrap(),
            2
        );
        assert!(
            AdminSession::find_by_token_hash("keep", &db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            AdminSession::find_by_token_hash("drop1", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_cascades_to_their_sessions() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "aaaa").await;
        assert!(AdminUser::delete(user.id, &db).await.unwrap());
        assert!(
            AdminSession::find_by_token_hash("aaaa", &db)
                .await
                .unwrap()
                .is_none(),
            "ON DELETE CASCADE needs `foreign_keys` on, which connect_in_memory pins"
        );
    }

    #[tokio::test]
    async fn list_all_filters_by_user_and_is_empty_when_there_are_none() {
        let (db, alice) = db_with_user().await;
        assert!(AdminSession::list_all(None, &db).await.unwrap().is_empty());

        let bob = AdminUser::create("bob", "hash", &db).await.unwrap();
        session(db.clone(), &alice, "a1").await;
        session(db.clone(), &bob, "b1").await;

        assert_eq!(AdminSession::list_all(None, &db).await.unwrap().len(), 2);
        let alices = AdminSession::list_all(Some(alice.id), &db).await.unwrap();
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].token_hash, "a1");
    }

    #[tokio::test]
    async fn cleanup_removes_expired_and_idle_rows_and_leaves_live_ones() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "live").await;
        session(db.clone(), &user, "expired").await;
        session(db.clone(), &user, "idle").await;

        let now = now_secs();
        sqlx::query("UPDATE admin_sessions SET expires_at = ? WHERE token_hash = 'expired';")
            .bind(now - 1)
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = 'idle';")
            .bind(now - IDLE.as_secs() as i64 - 1)
            .execute(&db.pool)
            .await
            .unwrap();

        assert_eq!(AdminSession::cleanup(IDLE, &db).await.unwrap(), 2);
        let left = AdminSession::list_all(None, &db).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].token_hash, "live");
    }

    const PENDING_TTL: Duration = Duration::from_secs(300);

    #[tokio::test]
    async fn create_pending_writes_the_half_authenticated_state() {
        let (db, user) = db_with_user().await;
        let pending = AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "pending-hash",
                csrf_token: "csrf",
                created_ip: Some("192.0.2.1".to_string()),
                user_agent: Some("curl".to_string()),
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();

        assert_eq!(pending.state, "pending_mfa");
        assert!(!pending.is_active());
        assert!(
            pending.expires_at - pending.created_at <= PENDING_TTL.as_secs() as i64,
            "a half-authenticated row must not get the full session lifetime"
        );

        let reloaded = AdminSession::find_by_token_hash("pending-hash", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.state, "pending_mfa");
        assert_eq!(reloaded.created_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(reloaded.mfa_attempts, 0);
    }

    /// The counter the address-keyed limiter cannot provide, and the reason it
    /// is one `UPDATE ... RETURNING` rather than a read-then-write.
    #[tokio::test]
    async fn mfa_failures_accumulate_on_the_session_row() {
        let (db, user) = db_with_user().await;
        AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "pending-hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();

        for expected in 1..=3 {
            assert_eq!(
                AdminSession::record_mfa_failure("pending-hash", &db)
                    .await
                    .unwrap(),
                Some(expected),
                "the new total comes back, so the caller needs no second read"
            );
        }

        let reloaded = AdminSession::find_by_token_hash("pending-hash", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.mfa_attempts, 3);

        // A row that is already gone -- swept, promoted, or deleted by whoever
        // hit the cap first -- is `None`, not an error.
        AdminSession::delete("pending-hash", &db).await.unwrap();
        assert_eq!(
            AdminSession::record_mfa_failure("pending-hash", &db)
                .await
                .unwrap(),
            None
        );
    }

    /// A promoted session starts clean: the counter only ever bounded the
    /// pending row it replaced.
    #[tokio::test]
    async fn promotion_does_not_carry_the_attempt_counter_across() {
        let (db, user) = db_with_user().await;
        AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "pending",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();
        AdminSession::record_mfa_failure("pending", &db)
            .await
            .unwrap();

        let promoted = AdminSession::promote("pending", "active", "csrf2", TTL, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(promoted.mfa_attempts, 0);
    }

    #[tokio::test]
    async fn promote_rotates_the_token_and_can_only_happen_once() {
        let (db, user) = db_with_user().await;
        AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "pending-hash",
                csrf_token: "pending-csrf",
                created_ip: Some("192.0.2.1".to_string()),
                user_agent: Some("curl".to_string()),
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();

        let promoted =
            AdminSession::promote("pending-hash", "active-hash", "active-csrf", TTL, &db)
                .await
                .unwrap()
                .expect("a pending row must promote");

        // A rotation, not an UPDATE: a new bearer token and a new CSRF token.
        assert_eq!(promoted.token_hash, "active-hash");
        assert_ne!(promoted.csrf_token, "pending-csrf");
        assert_eq!(promoted.state, "active");
        assert_eq!(promoted.user_id, user.id);
        // Forensics follow the operator, not the token.
        assert_eq!(promoted.created_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(promoted.user_agent.as_deref(), Some("curl"));
        assert!(promoted.expires_at - promoted.created_at > PENDING_TTL.as_secs() as i64);

        // The old token is gone the moment the new one exists.
        assert!(
            AdminSession::find_by_token_hash("pending-hash", &db)
                .await
                .unwrap()
                .is_none()
        );

        // The concurrency guard: a second submission of one code promotes
        // nothing, rather than minting a second session.
        assert!(
            AdminSession::promote("pending-hash", "second-hash", "c", TTL, &db)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            AdminSession::list_all(Some(user.id), &db)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// An `active` session is not something to promote, and must not be
    /// consumed by an attempt to.
    #[tokio::test]
    async fn promote_refuses_a_session_that_is_already_active() {
        let (db, user) = db_with_user().await;
        session(db.clone(), &user, "active-hash").await;

        assert!(
            AdminSession::promote("active-hash", "new-hash", "c", TTL, &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            AdminSession::find_by_token_hash("active-hash", &db)
                .await
                .unwrap()
                .is_some(),
            "the existing session must survive a refused promotion"
        );
    }

    /// The reaper needs no `pending_mfa` special case, and this is what says so:
    /// a pending row's own short `expires_at` is what sweeps it.
    #[tokio::test]
    async fn cleanup_sweeps_an_abandoned_pending_session_and_leaves_a_fresh_one() {
        let (db, user) = db_with_user().await;
        AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "fresh",
                csrf_token: "c",
                created_ip: None,
                user_agent: None,
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();
        AdminSession::create_pending(
            NewSession {
                user_id: user.id,
                token_hash: "abandoned",
                csrf_token: "c",
                created_ip: None,
                user_agent: None,
            },
            PENDING_TTL,
            &db,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE admin_sessions SET expires_at = ? WHERE token_hash = 'abandoned';")
            .bind(now_secs() - 1)
            .execute(&db.pool)
            .await
            .unwrap();

        assert_eq!(AdminSession::cleanup(IDLE, &db).await.unwrap(), 1);
        let left = AdminSession::list_all(None, &db).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].token_hash, "fresh");
    }

    #[test]
    fn expiry_and_idleness_are_judged_at_the_boundary_second() {
        let base = AdminSession {
            token_hash: "aaaa".to_string(),
            user_id: crate::sqlite::id::mint(),
            csrf_token: "c".to_string(),
            state: "active".to_string(),
            mfa_attempts: 0,
            created_at: 1_000,
            expires_at: 2_000,
            last_seen_at: 1_000,
            created_ip: None,
            user_agent: None,
        };

        assert!(!base.is_expired(1_999));
        assert!(
            base.is_expired(2_000),
            "the deadline second is already past"
        );

        assert!(!base.is_idle(1_000 + 3_599, IDLE));
        assert!(base.is_idle(1_000 + 3_600, IDLE));
    }

    #[tokio::test]
    async fn to_json_never_leaks_the_token_hash_or_the_csrf_token() {
        let (db, user) = db_with_user().await;
        let created = AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: "0123456789abcdef0123456789abcdef",
                csrf_token: "the-csrf-token",
                created_ip: None,
                user_agent: None,
            },
            TTL,
            &db,
        )
        .await
        .unwrap();

        let json = created.to_json();
        let rendered = json.to_string();
        assert!(!rendered.contains("0123456789abcdef0123456789abcdef"));
        assert!(!rendered.contains("the-csrf-token"));
        assert_eq!(json["id"], "01234567");
        assert_eq!(json["userId"], user.id.to_string());
        assert_eq!(json["state"], "active");
        assert_eq!(json["createdIp"], Value::Null);
    }
}
