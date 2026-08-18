//! Operator management for the web admin: create, list, re-password, enable,
//! disable, delete, and the password check the login path runs.
//!
//! The operation layer, not a front end: no printing, no HTTP, no terminal.
//! `src/cli/webadmin.rs` and `src/webadmin/handlers/session.rs` both dispatch
//! here, which is what keeps the password policy, the duplicate check and the
//! rehash-on-login identical between them.

use std::io::BufRead;
use std::sync::Arc;

use tracing::{info, warn};

use crate::admin::ops::DeleteOutcome;
use crate::admin::password;
use crate::admin::prompt::confirm;
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::db::Database;

/// Why creating or re-passwording an operator failed.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("database error: {0}")]
    Database(sqlx::Error),
    /// The password did not satisfy [`password::check_password_policy`]. The
    /// string is the operator-facing reason.
    #[error("{0}")]
    Policy(String),
    /// A user by that name already exists. Caught before the INSERT so the
    /// operator reads a sentence rather than a UNIQUE violation.
    #[error("an admin user named `{0}` already exists")]
    DuplicateUsername(String),
}

impl From<sqlx::Error> for UserError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// The result of checking a username and password.
///
/// Every variant but [`AuthOutcome::Authenticated`] must be reported to the
/// client identically -- one `invalid_credentials`, never "no such user" --
/// but they are kept apart here so the *log* can say which happened. A caller
/// that collapses them into the response and not into the log is doing the
/// right thing with both.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Password verified and the account is usable.
    Authenticated(Box<AdminUser>),
    /// No such username. The KDF ran anyway -- see [`authenticate`].
    UnknownUser,
    /// The username exists; the password did not match.
    WrongPassword(Box<AdminUser>),
    /// The password was right, but the account is `disabled`.
    Disabled(Box<AdminUser>),
}

/// Creates an operator.
///
/// Order matters: the policy is checked before the duplicate lookup, and the
/// duplicate lookup before the (expensive) hash, so a rejected request never
/// pays 600 000 iterations.
pub async fn create_user(
    username: &str,
    plaintext: &str,
    database: Arc<Database>,
) -> Result<AdminUser, UserError> {
    password::check_password_policy(plaintext).map_err(UserError::Policy)?;

    let normalized = username.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(UserError::Policy("username must not be empty".to_string()));
    }
    if AdminUser::find_by_username(&normalized, &database)
        .await?
        .is_some()
    {
        return Err(UserError::DuplicateUsername(normalized));
    }

    let hash = password::hash_password(plaintext);
    Ok(AdminUser::create(&normalized, &hash, &database).await?)
}

/// Every operator, oldest first.
pub async fn list_users(database: Arc<Database>) -> Result<Vec<AdminUser>, sqlx::Error> {
    AdminUser::list_all(&database).await
}

/// Replaces an operator's password and **revokes every session they hold**.
///
/// The revocation is the point: a password changed because it may have leaked,
/// that left the leaked session alive, would be a change in name only. Returns
/// `None` when there is no such user.
pub async fn set_password(
    username: &str,
    plaintext: &str,
    database: Arc<Database>,
) -> Result<Option<AdminUser>, UserError> {
    password::check_password_policy(plaintext).map_err(UserError::Policy)?;

    let Some(mut user) = AdminUser::find_by_username(username, &database).await? else {
        return Ok(None);
    };

    let hash = password::hash_password(plaintext);
    user.set_password_hash(&hash, &database).await?;
    AdminSession::delete_for_user(&user.id, &database).await?;
    Ok(Some(user))
}

/// Moves an operator between `active` and `disabled`.
///
/// Disabling also drops their sessions: leaving them live would mean a
/// disabled operator kept working until their cookie happened to expire.
pub async fn set_status(
    username: &str,
    status: &str,
    database: Arc<Database>,
) -> Result<Option<AdminUser>, sqlx::Error> {
    let Some(mut user) = AdminUser::find_by_username(username, &database).await? else {
        return Ok(None);
    };

    user.set_status(status, &database).await?;
    if status == "disabled" {
        AdminSession::delete_for_user(&user.id, &database).await?;
    }
    Ok(Some(user))
}

/// Revokes every session one operator holds, without touching the account.
/// `None` when there is no such user.
pub async fn revoke_sessions(
    username: &str,
    database: Arc<Database>,
) -> Result<Option<u64>, sqlx::Error> {
    let Some(user) = AdminUser::find_by_username(username, &database).await? else {
        return Ok(None);
    };
    Ok(Some(
        AdminSession::delete_for_user(&user.id, &database).await?,
    ))
}

/// Deletes an operator, cascading to their sessions. `false` when there was no
/// such user.
///
/// The bare form, for a caller with nobody to ask -- see the note above the
/// deletes in [`crate::admin::ops`].
pub async fn delete_user(username: &str, database: Arc<Database>) -> Result<bool, sqlx::Error> {
    let Some(user) = AdminUser::find_by_username(username, &database).await? else {
        return Ok(false);
    };
    AdminUser::delete(&user.id, &database).await
}

/// [`delete_user`], asking first and naming what goes with it.
pub async fn confirm_delete_user(
    username: &str,
    assume_yes: bool,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<DeleteOutcome, sqlx::Error> {
    let Some(user) = AdminUser::find_by_username(username, &database).await? else {
        return Ok(DeleteOutcome::NotFound);
    };
    let sessions = AdminSession::list_all(Some(&user.id), &database)
        .await?
        .len();
    let prompt = format!(
        "Delete admin user {} (status: {}, {sessions} session(s) will cascade)?",
        user.username, user.status
    );
    if !confirm(&prompt, assume_yes, reader) {
        return Ok(DeleteOutcome::Cancelled);
    }
    AdminUser::delete(&user.id, &database).await?;
    Ok(DeleteOutcome::Deleted)
}

/// Checks a username and password, re-hashing the stored digest if it was
/// written under parameters this build has moved past.
///
/// **The KDF runs even when the username is unknown**, against
/// [`password::dummy_hash`]. Without that, an unknown user answers in
/// microseconds and a known one in a quarter-second, and login latency
/// enumerates the operator table.
///
/// Does **not** stamp `last_login_at` or create a session: a login is not
/// complete until a session exists, which for a user with a second factor is
/// two requests away. The caller decides when that happened.
pub async fn authenticate(
    username: &str,
    plaintext: &str,
    database: Arc<Database>,
) -> Result<AuthOutcome, sqlx::Error> {
    let Some(mut user) = AdminUser::find_by_username(username, &database).await? else {
        // Deliberately discarded: the point is the time it took.
        let _ = password::verify_password(password::dummy_hash(), plaintext);
        return Ok(AuthOutcome::UnknownUser);
    };

    let verified = match password::verify_password(&user.password_hash, plaintext) {
        Ok(verified) => verified,
        Err(error) => {
            // A corrupt row is not a wrong password. Refuse the login, but say
            // so loudly -- nobody will ever guess this from a 401, and the
            // account is unusable until `admin user passwd` rewrites it.
            warn!(event = "admin_password_hash_unreadable",
                  outcome = "failure",
                  user_id = %user.id,
                  username = %user.username,
                  error = %error,
                  "stored password hash could not be decoded; \
                   run `acme-proxy admin user passwd` to rewrite it");
            return Ok(AuthOutcome::WrongPassword(Box::new(user)));
        }
    };

    if !verified {
        return Ok(AuthOutcome::WrongPassword(Box::new(user)));
    }
    if !user.is_active() {
        return Ok(AuthOutcome::Disabled(Box::new(user)));
    }

    // The one place a stored hash is ever upgraded. Doing it here, on a
    // verified password, is the only moment the plaintext is available to
    // re-derive from.
    if password::needs_rehash(&user.password_hash) {
        let rehashed = password::hash_password(plaintext);
        user.set_password_hash(&rehashed, &database).await?;
        info!(event = "admin_password_rehashed", outcome = "success", user_id = %user.id);
    }

    Ok(AuthOutcome::Authenticated(Box::new(user)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_session::NewSession;

    const GOOD: &str = "a-long-enough-password";

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// Writes a row whose hash is cheap, so the tests that only care about
    /// *which branch* `authenticate` takes do not each pay 600 000 iterations.
    /// The stored form is the real one; only the cost differs.
    async fn user_with_cheap_password(
        username: &str,
        plaintext: &str,
        database: Arc<Database>,
    ) -> AdminUser {
        // 1 iteration, but encoded exactly as production encodes it -- which
        // also means `needs_rehash` reports true, so any test using this and
        // then authenticating successfully is exercising the rehash path.
        let salt = [3u8; 16];
        let mut digest = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(1).unwrap(),
            &salt,
            plaintext.as_bytes(),
            &mut digest,
        );
        let encoded = format!(
            "pbkdf2-sha256$1${}${}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, salt),
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest),
        );
        AdminUser::create(username, &encoded, &database)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn create_user_normalizes_and_hashes() {
        let db = db().await;
        let user = create_user("  Alice ", GOOD, db.clone()).await.unwrap();
        assert_eq!(user.username, "alice");
        assert!(user.is_active());
        // Stored one-way: the plaintext appears nowhere.
        assert!(!user.password_hash.contains(GOOD));
        assert_eq!(
            password::verify_password(&user.password_hash, GOOD),
            Ok(true)
        );
    }

    #[tokio::test]
    async fn create_user_refuses_a_password_below_the_policy() {
        let db = db().await;
        let error = create_user("alice", "short", db.clone()).await.unwrap_err();
        assert!(matches!(error, UserError::Policy(_)));
        assert!(error.to_string().contains("at least 12"));
        // Nothing was written.
        assert!(list_users(db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_user_refuses_an_empty_username() {
        let db = db().await;
        let error = create_user("   ", GOOD, db).await.unwrap_err();
        assert!(error.to_string().contains("username must not be empty"));
    }

    #[tokio::test]
    async fn create_user_refuses_a_duplicate_in_words_not_a_unique_violation() {
        let db = db().await;
        create_user("alice", GOOD, db.clone()).await.unwrap();
        let error = create_user("ALICE", GOOD, db).await.unwrap_err();
        assert!(matches!(error, UserError::DuplicateUsername(_)));
        assert_eq!(
            error.to_string(),
            "an admin user named `alice` already exists"
        );
    }

    #[tokio::test]
    async fn set_password_revokes_every_session_of_that_user() {
        let db = db().await;
        let user = user_with_cheap_password("alice", "old-password", db.clone()).await;
        AdminSession::create(
            NewSession {
                user_id: &user.id,
                token_hash: "hash-a",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(60),
            &db,
        )
        .await
        .unwrap();

        assert!(
            set_password("alice", GOOD, db.clone())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            AdminSession::list_all(Some(&user.id), &db)
                .await
                .unwrap()
                .is_empty(),
            "a password change that left sessions alive would be a change in name only"
        );

        let reloaded = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            password::verify_password(&reloaded.password_hash, GOOD),
            Ok(true)
        );
    }

    #[tokio::test]
    async fn set_password_of_an_unknown_user_is_none_and_checks_the_policy_first() {
        let db = db().await;
        assert!(
            set_password("nobody", GOOD, db.clone())
                .await
                .unwrap()
                .is_none()
        );
        // The policy is checked before the lookup, so a bad password for an
        // unknown user is a policy error rather than a silent `None`.
        assert!(matches!(
            set_password("nobody", "short", db).await.unwrap_err(),
            UserError::Policy(_)
        ));
    }

    #[tokio::test]
    async fn disabling_a_user_drops_their_sessions_but_enabling_does_not() {
        let db = db().await;
        let user = user_with_cheap_password("alice", "pw", db.clone()).await;
        AdminSession::create(
            NewSession {
                user_id: &user.id,
                token_hash: "hash-a",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(60),
            &db,
        )
        .await
        .unwrap();

        set_status("alice", "disabled", db.clone()).await.unwrap();
        assert!(
            AdminSession::list_all(Some(&user.id), &db)
                .await
                .unwrap()
                .is_empty()
        );

        // Re-enabling is just a status change; there is nothing to drop.
        let reenabled = set_status("alice", "active", db.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(reenabled.is_active());
        assert!(
            set_status("nobody", "disabled", db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn revoke_sessions_counts_what_it_removed() {
        let db = db().await;
        let user = user_with_cheap_password("alice", "pw", db.clone()).await;
        for hash in ["a", "b"] {
            AdminSession::create(
                NewSession {
                    user_id: &user.id,
                    token_hash: hash,
                    csrf_token: "csrf",
                    created_ip: None,
                    user_agent: None,
                },
                std::time::Duration::from_secs(60),
                &db,
            )
            .await
            .unwrap();
        }

        assert_eq!(revoke_sessions("alice", db.clone()).await.unwrap(), Some(2));
        assert_eq!(revoke_sessions("alice", db.clone()).await.unwrap(), Some(0));
        assert_eq!(revoke_sessions("nobody", db).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_user_removes_the_row_and_reports_whether_it_existed() {
        let db = db().await;
        user_with_cheap_password("alice", "pw", db.clone()).await;
        assert!(delete_user("alice", db.clone()).await.unwrap());
        assert!(!delete_user("alice", db).await.unwrap());
    }

    #[tokio::test]
    async fn confirm_delete_user_covers_its_three_outcomes() {
        let db = db().await;
        let mut empty: &[u8] = &[];
        assert_eq!(
            confirm_delete_user("nobody", true, &mut empty, db.clone())
                .await
                .unwrap(),
            DeleteOutcome::NotFound
        );

        user_with_cheap_password("alice", "pw", db.clone()).await;
        let mut no = b"n\n".as_slice();
        assert_eq!(
            confirm_delete_user("alice", false, &mut no, db.clone())
                .await
                .unwrap(),
            DeleteOutcome::Cancelled
        );
        assert!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .is_some()
        );

        let mut empty: &[u8] = &[];
        assert_eq!(
            confirm_delete_user("alice", true, &mut empty, db.clone())
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn authenticate_accepts_the_right_password() {
        let db = db().await;
        user_with_cheap_password("alice", "the-password", db.clone()).await;
        let outcome = authenticate("alice", "the-password", db).await.unwrap();
        assert!(matches!(outcome, AuthOutcome::Authenticated(_)));
    }

    #[tokio::test]
    async fn authenticate_distinguishes_its_failures_for_the_log() {
        let db = db().await;
        user_with_cheap_password("alice", "the-password", db.clone()).await;

        assert!(matches!(
            authenticate("alice", "wrong", db.clone()).await.unwrap(),
            AuthOutcome::WrongPassword(_)
        ));
        assert!(matches!(
            authenticate("nobody", "the-password", db.clone())
                .await
                .unwrap(),
            AuthOutcome::UnknownUser
        ));

        set_status("alice", "disabled", db.clone()).await.unwrap();
        assert!(matches!(
            authenticate("alice", "the-password", db).await.unwrap(),
            AuthOutcome::Disabled(_)
        ));
    }

    #[tokio::test]
    async fn authenticate_is_case_insensitive_in_the_username() {
        let db = db().await;
        user_with_cheap_password("alice", "the-password", db.clone()).await;
        assert!(matches!(
            authenticate("ALICE", "the-password", db).await.unwrap(),
            AuthOutcome::Authenticated(_)
        ));
    }

    #[tokio::test]
    async fn a_successful_login_rehashes_a_row_written_under_older_parameters() {
        let db = db().await;
        let before = user_with_cheap_password("alice", "the-password", db.clone()).await;
        assert!(password::needs_rehash(&before.password_hash));

        let outcome = authenticate("alice", "the-password", db.clone())
            .await
            .unwrap();
        let AuthOutcome::Authenticated(user) = outcome else {
            panic!("expected a successful authentication");
        };
        assert!(!password::needs_rehash(&user.password_hash));

        // Persisted, not just updated in memory -- and the new digest still
        // verifies against the same password.
        let reloaded = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert!(!password::needs_rehash(&reloaded.password_hash));
        assert_eq!(
            password::verify_password(&reloaded.password_hash, "the-password"),
            Ok(true)
        );
    }

    #[tokio::test]
    async fn a_corrupt_stored_hash_refuses_the_login_rather_than_erroring() {
        let db = db().await;
        AdminUser::create("alice", "not-a-valid-encoded-hash", &db)
            .await
            .unwrap();
        // Not an Err: a mangled row must not take the whole login endpoint
        // down, and it must not read as "correct password" either.
        assert!(matches!(
            authenticate("alice", "anything", db).await.unwrap(),
            AuthOutcome::WrongPassword(_)
        ));
    }

    #[test]
    fn every_user_error_renders() {
        assert!(
            UserError::Database(sqlx::Error::RowNotFound)
                .to_string()
                .starts_with("database error:")
        );
        assert_eq!(
            UserError::Policy("too short".to_string()).to_string(),
            "too short"
        );
        assert_eq!(
            UserError::DuplicateUsername("bob".to_string()).to_string(),
            "an admin user named `bob` already exists"
        );
    }
}
