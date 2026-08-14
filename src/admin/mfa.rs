//! The second-factor operations, which both front ends dispatch to and neither
//! owns.
//!
//! The same split [`crate::admin::users`] makes: no printing, no HTTP, no
//! terminal. `src/cli/webadmin.rs` (`admin user totp …`) and
//! `src/webadmin/handlers/mfa.rs` both come here, which is what keeps the replay
//! guard, the session revocation and the "shown once" rule identical between
//! them.
//!
//! The pure halves live next door -- [`crate::admin::totp`] for RFC 6238 and
//! [`crate::admin::recovery`] for the codes. This file is where they meet a
//! database.

use std::sync::Arc;

use tracing::{info, warn};

use crate::admin::{password, recovery, totp};
use crate::sqlite::admin_recovery_code::AdminRecoveryCode;
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;

/// Which of the two things an accepted submission was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
    RecoveryCode,
}

impl MfaMethod {
    /// The `method` field of `admin_mfa_verified`. A literal, so it stays
    /// greppable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MfaMethod::Totp => "totp",
            MfaMethod::RecoveryCode => "recovery_code",
        }
    }
}

/// The result of checking a second-factor submission.
///
/// Every variant but [`MfaOutcome::Accepted`] must reach the client as one
/// `invalid_credentials`, exactly as [`crate::admin::users::AuthOutcome`]'s
/// three failures do -- they are kept apart here so the *log* can say which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaOutcome {
    Accepted {
        via: MfaMethod,
        /// Unspent recovery codes after this submission. The panel shows it;
        /// a low number is the nudge to regenerate.
        recovery_codes_left: i64,
    },
    /// Neither a valid code for this moment nor an unspent recovery code.
    Rejected,
    /// A *correct* TOTP code, resubmitted inside its own 30-second window
    /// (RFC 6238 §5.2). Refused, and worth its own name: it is what somebody
    /// replaying an observed code looks like.
    Replayed,
    /// No confirmed factor to verify against. Reachable only if a factor was
    /// removed between the password step and this one.
    NotEnrolled,
}

impl MfaOutcome {
    /// The `reason` field of `admin_mfa_failed`, or `""` when it succeeded.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            MfaOutcome::Accepted { .. } => "",
            MfaOutcome::Rejected => "wrong_code",
            MfaOutcome::Replayed => "replayed",
            MfaOutcome::NotEnrolled => "no_factor",
        }
    }
}

/// Checks a submission against this operator's factor, then against their
/// recovery codes.
///
/// **Order matters.** A TOTP check is three HMACs; a recovery check is up to ten
/// PBKDF2 runs and a write. The cheap and overwhelmingly common path goes
/// first, and a submission that cannot be a recovery code by shape never starts
/// the scan at all.
///
/// On success the TOTP path claims its time step
/// ([`AdminUser::claim_totp_step`]) and the recovery path spends its code
/// ([`AdminRecoveryCode::consume`]) -- in both cases the database, not this
/// function, is what makes it single-use.
pub async fn verify_second_factor(
    user: &mut AdminUser,
    submitted: &str,
    database: Arc<Database>,
) -> Result<MfaOutcome, sqlx::Error> {
    let Some(secret) = user.totp_secret.clone() else {
        return Ok(MfaOutcome::NotEnrolled);
    };

    let trimmed = submitted.trim();
    if let Some(step) = totp::verify(&secret, trimmed, now_secs()) {
        if !user.claim_totp_step(step, &database).await? {
            return Ok(MfaOutcome::Replayed);
        }
        let left = AdminRecoveryCode::count_unused(&user.id, &database).await?;
        return Ok(MfaOutcome::Accepted {
            via: MfaMethod::Totp,
            recovery_codes_left: left,
        });
    }

    let candidate = recovery::normalize(trimmed);
    if !recovery::is_well_formed(&candidate) {
        return Ok(MfaOutcome::Rejected);
    }

    for code in AdminRecoveryCode::list_unused(&user.id, &database).await? {
        match password::verify_password(&code.code_hash, &candidate) {
            Ok(true) => {
                if !AdminRecoveryCode::consume(&code.id, &database).await? {
                    // Lost the race to a concurrent submission of this very
                    // code. Refusing is the correct answer for the loser.
                    return Ok(MfaOutcome::Rejected);
                }
                let left = AdminRecoveryCode::count_unused(&user.id, &database).await?;
                warn!(event = "admin_mfa_recovery_code_used",
                      outcome = "success",
                      user_id = %user.id,
                      username = %user.username,
                      remaining = left);
                return Ok(MfaOutcome::Accepted {
                    via: MfaMethod::RecoveryCode,
                    recovery_codes_left: left,
                });
            }
            Ok(false) => {}
            Err(error) => {
                // A corrupt row is not a wrong code -- the same distinction
                // `users::authenticate` draws. Skip it and say so; the operator
                // has nine others and no way to guess this from a 401.
                warn!(event = "admin_recovery_code_hash_unreadable",
                      outcome = "failure",
                      user_id = %user.id,
                      code_id = %code.id,
                      error = %error);
            }
        }
    }

    Ok(MfaOutcome::Rejected)
}

/// Mints a secret and stores it as *pending*, returning the two representations
/// the enrolment page shows exactly once.
///
/// Nothing about the operator's current factor changes here: an enrolment that
/// is started and abandoned leaves a live factor live, which is what makes
/// "set up a new phone" safe to begin from an authenticated session.
pub async fn begin_totp_enrolment(
    user: &mut AdminUser,
    base_url: &str,
    database: Arc<Database>,
) -> Result<totp::Enrolment, sqlx::Error> {
    let account = totp::account_label(&user.username, base_url);
    let enrolment = totp::begin_enrolment(totp::ISSUER, &account);
    user.set_totp_pending(&enrolment.secret, &database).await?;
    Ok(enrolment)
}

/// Re-renders an enrolment already begun, or begins one.
///
/// A page reload must not invalidate the secret the operator has just scanned
/// into an app, so the pending bytes are shown again rather than replaced. The
/// two other representations are derived, not stored -- the database keeps only
/// the secret.
pub async fn resume_or_begin_totp_enrolment(
    user: &mut AdminUser,
    base_url: &str,
    database: Arc<Database>,
) -> Result<totp::Enrolment, sqlx::Error> {
    let Some(secret) = user.totp_pending_secret.clone() else {
        return begin_totp_enrolment(user, base_url, database).await;
    };

    let account = totp::account_label(&user.username, base_url);
    let secret_base32 = totp::base32_encode(&secret);
    let uri = totp::provisioning_uri(&secret_base32, totp::ISSUER, &account);
    Ok(totp::Enrolment {
        secret,
        secret_base32,
        uri,
    })
}

/// Confirms a pending enrolment against a code the authenticator produced.
///
/// On success: the pending secret becomes the real one, a fresh recovery set is
/// issued and returned **once**, and every other session this operator holds is
/// revoked. `None` is a wrong code, and leaves `totp_secret` exactly as it was.
///
/// `keep_session` is the token hash of the session doing the enrolling, so the
/// operator is not logged out by their own action; `None` revokes every session,
/// which is what a change made on their behalf should do.
pub async fn confirm_totp_enrolment(
    user: &mut AdminUser,
    code: &str,
    keep_session: Option<&str>,
    database: Arc<Database>,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    let Some(pending) = user.totp_pending_secret.clone() else {
        return Ok(None);
    };

    let Some(step) = totp::verify(&pending, code.trim(), now_secs()) else {
        return Ok(None);
    };

    user.confirm_totp(&database).await?;
    // The code that proved the enrolment must not also work as the first login
    // code. `confirm_totp` cleared the guard, so this is the first claim.
    user.claim_totp_step(step, &database).await?;

    let codes = issue_recovery_codes(user, database.clone()).await?;
    revoke_other_sessions(user, keep_session, database).await?;

    info!(event = "admin_mfa_enabled",
          outcome = "success",
          user_id = %user.id,
          username = %user.username,
          recovery_codes = codes.len());
    Ok(Some(codes))
}

/// Removes the factor, any half-finished enrolment, the replay guard and every
/// recovery code -- a code that recovers access to a factor that no longer
/// exists is just a second password.
///
/// Revokes sessions on the same rule as [`confirm_totp_enrolment`]: a security
/// control removed that left every other browser signed in would be a change in
/// name only, which is `users::set_password`'s argument verbatim.
pub async fn disable_totp(
    user: &mut AdminUser,
    keep_session: Option<&str>,
    database: Arc<Database>,
) -> Result<(), sqlx::Error> {
    user.clear_totp(&database).await?;
    AdminRecoveryCode::delete_for_user(&user.id, &database).await?;
    revoke_other_sessions(user, keep_session, database).await?;

    info!(event = "admin_mfa_disabled", outcome = "success", user_id = %user.id, username = %user.username);
    Ok(())
}

/// Mints a fresh recovery set, superseding the previous one, and returns it
/// **once**. Nothing stores or logs the plaintext.
pub async fn regenerate_recovery_codes(
    user: &AdminUser,
    database: Arc<Database>,
) -> Result<Vec<String>, sqlx::Error> {
    let codes = issue_recovery_codes(user, database).await?;
    info!(event = "admin_mfa_recovery_codes_regenerated",
          outcome = "success",
          user_id = %user.id,
          username = %user.username,
          minted = codes.len());
    Ok(codes)
}

/// How many unspent recovery codes this operator holds.
pub async fn recovery_codes_remaining(
    user_id: &str,
    database: Arc<Database>,
) -> Result<i64, sqlx::Error> {
    AdminRecoveryCode::count_unused(user_id, &database).await
}

/// How many operators have no confirmed factor -- what the startup warning
/// under `admin.require_mfa` counts.
pub async fn operators_without_a_factor(database: Arc<Database>) -> Result<usize, sqlx::Error> {
    Ok(AdminUser::list_all(&database)
        .await?
        .iter()
        .filter(|user| !user.has_totp())
        .count())
}

async fn issue_recovery_codes(
    user: &AdminUser,
    database: Arc<Database>,
) -> Result<Vec<String>, sqlx::Error> {
    let codes = recovery::generate_codes();
    // Stored the way they are compared: normalised, so the grouping an operator
    // reads off the screen never has to survive into the hash.
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| password::hash_generated_secret(&recovery::normalize(code)))
        .collect();
    AdminRecoveryCode::replace_all(&user.id, &hashes, &database).await?;
    Ok(codes)
}

async fn revoke_other_sessions(
    user: &AdminUser,
    keep_session: Option<&str>,
    database: Arc<Database>,
) -> Result<u64, sqlx::Error> {
    match keep_session {
        Some(token_hash) => {
            AdminSession::delete_for_user_except(&user.id, token_hash, &database).await
        }
        None => AdminSession::delete_for_user(&user.id, &database).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::totp::{DIGITS, step_at, totp_at};
    use crate::sqlite::admin_session::NewSession;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    async fn operator(database: Arc<Database>) -> AdminUser {
        AdminUser::create("alice", "hash", &database).await.unwrap()
    }

    /// An operator with a confirmed factor, returning the secret so a test can
    /// compute codes against it.
    async fn enrolled(database: Arc<Database>) -> (AdminUser, Vec<u8>) {
        let mut user = operator(database.clone()).await;
        let enrolment = begin_totp_enrolment(&mut user, "http://localhost:3001", database.clone())
            .await
            .unwrap();
        let code = totp_at(&enrolment.secret, step_at(now_secs()), DIGITS);
        let codes = confirm_totp_enrolment(&mut user, &code, None, database)
            .await
            .unwrap()
            .expect("a freshly generated code must confirm its own enrolment");
        assert_eq!(codes.len(), recovery::CODE_COUNT);
        (user, enrolment.secret)
    }

    #[tokio::test]
    async fn an_operator_with_no_factor_is_not_enrolled() {
        let db = db().await;
        let mut user = operator(db.clone()).await;

        assert_eq!(
            verify_second_factor(&mut user, "123456", db).await.unwrap(),
            MfaOutcome::NotEnrolled
        );
    }

    #[tokio::test]
    async fn enrolment_is_two_steps_and_a_wrong_code_finishes_neither() {
        let db = db().await;
        let mut user = operator(db.clone()).await;

        let enrolment = begin_totp_enrolment(&mut user, "http://localhost:3001", db.clone())
            .await
            .unwrap();
        assert!(
            !user.has_totp(),
            "a pending enrolment is not a second factor"
        );
        assert!(user.has_pending_totp());

        // A wrong code leaves the pending secret pending and mints no codes.
        assert!(
            confirm_totp_enrolment(&mut user, "000000", None, db.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(!user.has_totp());
        assert!(user.has_pending_totp());
        assert_eq!(
            recovery_codes_remaining(&user.id, db.clone())
                .await
                .unwrap(),
            0
        );

        let code = totp_at(&enrolment.secret, step_at(now_secs()), DIGITS);
        let codes = confirm_totp_enrolment(&mut user, &code, None, db.clone())
            .await
            .unwrap()
            .unwrap();

        assert!(user.has_totp());
        assert!(
            !user.has_pending_totp(),
            "confirming must clear the pending column, not leave two secrets live"
        );
        assert_eq!(codes.len(), recovery::CODE_COUNT);
        assert_eq!(
            recovery_codes_remaining(&user.id, db).await.unwrap(),
            recovery::CODE_COUNT as i64
        );
    }

    /// RFC 6238 §5.2. The code that proved the enrolment must not also be the
    /// first login code, and no code may be spent twice inside its window.
    #[tokio::test]
    async fn a_correct_code_is_accepted_once_and_replayed_thereafter() {
        let db = db().await;
        let (mut user, secret) = enrolled(db.clone()).await;

        // The enrolment already claimed a step, so the code for *that* step is
        // a replay -- which is the point. Read it back rather than recomputing
        // it from the clock: the two would disagree whenever the enrolment and
        // this line straddle a 30-second boundary.
        let claimed = user.totp_last_step.expect("enrolment claims its own step");
        let code = totp_at(&secret, claimed, DIGITS);
        assert_eq!(
            verify_second_factor(&mut user, &code, db.clone())
                .await
                .unwrap(),
            MfaOutcome::Replayed
        );

        // The next step's code is accepted, then it too is spent.
        let next = totp_at(&secret, step_at(now_secs()) + 1, DIGITS);
        assert_eq!(
            verify_second_factor(&mut user, &next, db.clone())
                .await
                .unwrap(),
            MfaOutcome::Accepted {
                via: MfaMethod::Totp,
                recovery_codes_left: recovery::CODE_COUNT as i64,
            }
        );
        assert_eq!(
            verify_second_factor(&mut user, &next, db).await.unwrap(),
            MfaOutcome::Replayed
        );
    }

    #[tokio::test]
    async fn a_wrong_code_is_rejected_without_touching_the_replay_guard() {
        let db = db().await;
        let (mut user, secret) = enrolled(db.clone()).await;
        let claimed = user.totp_last_step;

        for wrong in ["000000", "12345", "abcdef", ""] {
            assert_eq!(
                verify_second_factor(&mut user, wrong, db.clone())
                    .await
                    .unwrap(),
                MfaOutcome::Rejected,
                "submission {wrong:?}"
            );
        }
        assert_eq!(
            user.totp_last_step, claimed,
            "a wrong code must not advance the guard, or it would lock out the right one"
        );

        // And the guard really is where it was: the next step still works.
        let next = totp_at(&secret, step_at(now_secs()) + 1, DIGITS);
        assert!(matches!(
            verify_second_factor(&mut user, &next, db).await.unwrap(),
            MfaOutcome::Accepted { .. }
        ));
    }

    #[tokio::test]
    async fn a_recovery_code_is_accepted_once_and_decrements_the_count() {
        let db = db().await;
        let mut user = operator(db.clone()).await;
        let enrolment = begin_totp_enrolment(&mut user, "http://localhost:3001", db.clone())
            .await
            .unwrap();
        let code = totp_at(&enrolment.secret, step_at(now_secs()), DIGITS);
        let codes = confirm_totp_enrolment(&mut user, &code, None, db.clone())
            .await
            .unwrap()
            .unwrap();

        // Submitted exactly as the page rendered it, separator and all.
        assert_eq!(
            verify_second_factor(&mut user, &codes[0], db.clone())
                .await
                .unwrap(),
            MfaOutcome::Accepted {
                via: MfaMethod::RecoveryCode,
                recovery_codes_left: recovery::CODE_COUNT as i64 - 1,
            }
        );
        assert_eq!(
            verify_second_factor(&mut user, &codes[0], db.clone())
                .await
                .unwrap(),
            MfaOutcome::Rejected,
            "single-use: a spent code is worth nothing"
        );

        // And retyped the ways a human retypes one.
        assert_eq!(
            verify_second_factor(&mut user, &codes[1].to_lowercase(), db.clone())
                .await
                .unwrap(),
            MfaOutcome::Accepted {
                via: MfaMethod::RecoveryCode,
                recovery_codes_left: recovery::CODE_COUNT as i64 - 2,
            }
        );
        assert_eq!(
            verify_second_factor(&mut user, &codes[2].replace('-', " "), db.clone())
                .await
                .unwrap(),
            MfaOutcome::Accepted {
                via: MfaMethod::RecoveryCode,
                recovery_codes_left: recovery::CODE_COUNT as i64 - 3,
            }
        );

        assert_eq!(
            recovery_codes_remaining(&user.id, db).await.unwrap(),
            recovery::CODE_COUNT as i64 - 3
        );
    }

    #[tokio::test]
    async fn regenerating_supersedes_the_previous_set() {
        let db = db().await;
        let (mut user, _) = enrolled(db.clone()).await;

        let first = AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap();
        let second = regenerate_recovery_codes(&user, db.clone()).await.unwrap();
        assert_eq!(second.len(), recovery::CODE_COUNT);

        // A code from the old set is worth nothing now. Verify through the
        // stored hashes rather than the plaintext, which the first call never
        // returned.
        for code in AdminRecoveryCode::list_unused(&user.id, &db).await.unwrap() {
            assert!(first.iter().all(|old| old.id != code.id));
        }
        assert_eq!(
            verify_second_factor(&mut user, &second[0], db.clone())
                .await
                .unwrap(),
            MfaOutcome::Accepted {
                via: MfaMethod::RecoveryCode,
                recovery_codes_left: recovery::CODE_COUNT as i64 - 1,
            }
        );
    }

    #[tokio::test]
    async fn disabling_clears_every_column_and_every_code() {
        let db = db().await;
        let (mut user, _) = enrolled(db.clone()).await;
        assert!(user.has_totp());

        disable_totp(&mut user, None, db.clone()).await.unwrap();

        assert!(!user.has_totp());
        assert!(!user.has_pending_totp());
        assert_eq!(user.totp_last_step, None);
        assert_eq!(
            recovery_codes_remaining(&user.id, db.clone())
                .await
                .unwrap(),
            0,
            "a recovery code for a factor that no longer exists is a second password"
        );

        // Re-read from the database: the in-memory sync must not be the only
        // place this happened.
        let reloaded = AdminUser::find_by_id(&user.id, &db).await.unwrap().unwrap();
        assert!(!reloaded.has_totp());
        assert!(!reloaded.has_pending_totp());
        assert_eq!(reloaded.totp_last_step, None);
    }

    #[tokio::test]
    async fn a_factor_change_revokes_every_other_session() {
        let db = db().await;
        let mut user = operator(db.clone()).await;

        let kept = AdminSession::create(
            NewSession {
                user_id: &user.id,
                token_hash: "kept-hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(3600),
            &db,
        )
        .await
        .unwrap();
        AdminSession::create(
            NewSession {
                user_id: &user.id,
                token_hash: "other-hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(3600),
            &db,
        )
        .await
        .unwrap();

        let enrolment = begin_totp_enrolment(&mut user, "http://localhost:3001", db.clone())
            .await
            .unwrap();
        let code = totp_at(&enrolment.secret, step_at(now_secs()), DIGITS);
        confirm_totp_enrolment(&mut user, &code, Some(&kept.token_hash), db.clone())
            .await
            .unwrap()
            .unwrap();

        let live = AdminSession::list_all(Some(&user.id), &db).await.unwrap();
        assert_eq!(live.len(), 1, "every other browser must be signed out");
        assert_eq!(live[0].token_hash, "kept-hash");

        // And disabling takes the last one too, when nothing is kept.
        disable_totp(&mut user, None, db.clone()).await.unwrap();
        assert!(
            AdminSession::list_all(Some(&user.id), &db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn every_outcome_names_itself_for_the_log() {
        assert_eq!(
            MfaOutcome::Accepted {
                via: MfaMethod::Totp,
                recovery_codes_left: 10
            }
            .reason(),
            ""
        );
        assert_eq!(MfaOutcome::Rejected.reason(), "wrong_code");
        assert_eq!(MfaOutcome::Replayed.reason(), "replayed");
        assert_eq!(MfaOutcome::NotEnrolled.reason(), "no_factor");
        assert_eq!(MfaMethod::Totp.as_str(), "totp");
        assert_eq!(MfaMethod::RecoveryCode.as_str(), "recovery_code");
    }

    #[tokio::test]
    async fn the_startup_count_sees_only_confirmed_factors() {
        let db = db().await;
        let mut alice = operator(db.clone()).await;
        AdminUser::create("bob", "hash", &db).await.unwrap();
        assert_eq!(operators_without_a_factor(db.clone()).await.unwrap(), 2);

        // A pending enrolment is not a factor, so it does not clear the count.
        let enrolment = begin_totp_enrolment(&mut alice, "http://localhost:3001", db.clone())
            .await
            .unwrap();
        assert_eq!(operators_without_a_factor(db.clone()).await.unwrap(), 2);

        let code = totp_at(&enrolment.secret, step_at(now_secs()), DIGITS);
        confirm_totp_enrolment(&mut alice, &code, None, db.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operators_without_a_factor(db).await.unwrap(), 1);
    }
}
