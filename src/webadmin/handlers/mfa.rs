//! `/api/mfa` — enrol, confirm, disable, and reissue recovery codes.
//!
//! The counterpart to [`super::session`], which owns the two *login* steps.
//! Everything here acts on a session that already exists, in one of two states:
//! `active` (an operator managing their own factor) or `pending_mfa` with no
//! factor yet (`admin.require_mfa` forcing enrolment before the session becomes
//! usable). [`crate::webadmin::session::EnrolWrite`] is what tells those two
//! apart, and what refuses the third case -- a `pending_mfa` session that owes a
//! *code*, which must never reach an enrolment route.

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::admin::{mfa, totp};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::session::finish_enrolment;
use crate::webadmin::session::{AdminClientIp, Authenticated, AuthenticatedWrite, EnrolWrite};

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub code: String,
}

/// The body of every route that *changes* a second factor rather than proving
/// one. `password` is required only when a factor already exists — see
/// [`check_step_up`].
#[derive(Debug, Default, Deserialize)]
pub struct StepUpRequest {
    #[serde(default)]
    pub password: String,
}

/// Re-authenticates an operator who is about to replace or remove an existing
/// second factor.
///
/// A live session is not sufficient authority for this, and the reason is the
/// blast radius rather than the change itself: `confirm_totp_enrolment` and
/// `disable_totp` both call `revoke_other_sessions` and supersede the recovery
/// codes. So somebody holding a stolen cookie can enrol *their* authenticator
/// over the operator's, end every one of the operator's other sessions, and
/// void the codes that would let them back in — converting a stolen session
/// into a lockout that only `acme-proxy admin user totp reset` on the host can
/// undo.
///
/// Only when a factor already exists. A first enrolment protects nothing, and
/// demanding a password there would put one in the way of the `require_mfa`
/// bootstrap, whose whole design is that enrolling must stay reachable.
///
/// The refusal is `invalid_credentials`, the same answer sign-in gives, so this
/// is not a second oracle for whether a password is right.
pub(crate) fn check_step_up(
    user: &crate::sqlite::admin_user::AdminUser,
    password: &str,
    client: Option<std::net::IpAddr>,
    logins: &crate::webadmin::session::LoginLimiter,
) -> Result<(), AdminError> {
    if !user.has_totp() {
        return Ok(());
    }
    verify_current_password(user, password, client, logins)
}

/// The part of step-up that always applies: proves the caller still knows the
/// account password, rate-limited against the sign-in bucket.
///
/// [`check_step_up`] adds "only once there is something to protect" on top of
/// this for the MFA routes, where a first enrolment protects nothing. A
/// password change carries no such exemption -- ASVS V6.2.3 asks for the
/// current password on *every* change of it, whether or not a second factor
/// exists -- so `handlers::account::change_password` and its `/ui` twin call
/// this directly instead of `check_step_up`.
pub(crate) fn verify_current_password(
    user: &crate::sqlite::admin_user::AdminUser,
    password: &str,
    client: Option<std::net::IpAddr>,
    logins: &crate::webadmin::session::LoginLimiter,
) -> Result<(), AdminError> {
    // Checked **before** the KDF, which is `sign_in`'s reasoning verbatim: 600 000
    // PBKDF2 iterations is a denial-of-service lever, and until this ran here an
    // authenticated caller could pull it as fast as it could send requests.
    // Guessing was unbounded too, which mattered more — this is the one check
    // standing between a stolen cookie and the factor takeover the doc comment
    // above describes.
    //
    // **The sign-in bucket, deliberately, not one of its own.** It is literally
    // the same secret, and the panel already shares one bucket between the
    // password step and the code step; a second budget here would hand an
    // attacker `2 × login_max_attempts` guesses per window against one password.
    // The cost is that a lockout earned on the account card also refuses sign-in
    // from that address until `login_window_seconds` rolls over — already true
    // of the code step, and the same remedy.
    //
    // What this does *not* bound: an `active` cookie is valid from any address
    // on purpose (`created_ip` is forensics, never compared), so somebody
    // rotating source addresses still gets `login_max_attempts` guesses each.
    // Closing that needs a per-session counter, i.e. a column on
    // `admin_sessions` — deliberately not done, because unlike a six-digit code
    // a password behind 85 ms of PBKDF2 per guess is not reachable that way, and
    // the address bucket already removes the DoS lever.
    if let Err(retry_after) = logins.check(client) {
        warn!(
            event = "admin_mfa_step_up_refused",
            outcome = "failure",
            username = %user.username,
            reason = "rate_limited"
        );
        return Err(AdminError::rate_limited(retry_after));
    }

    match crate::admin::password::verify_password(&user.password_hash, password) {
        Ok(true) => {
            // No `record_success`. `sign_in` moved its own to the *promotion*
            // past the second factor for exactly this reason: clearing the
            // bucket on a correct password would let whoever holds one reset it
            // at will and brute-force the six digits behind it. A step-up caller
            // is in that position by definition.
            Ok(())
        }
        Ok(false) => {
            logins.record_failure(client);
            warn!(event = "admin_mfa_step_up_refused", outcome = "failure", username = %user.username, reason = "wrong_password");
            Err(AdminError::invalid_credentials())
        }
        Err(error) => {
            // A stored hash this process cannot parse is a corrupt row, not a
            // wrong password. Refuse rather than let the change through.
            //
            // No `record_failure`: `decode` failed before the KDF ran, so
            // nothing was guessed and no work was spent. Counting it would let
            // one corrupt row lock its own owner out of sign-in as well — the
            // one account that most needs to reach an operator.
            //
            // `warn`, matching `admin::users::authenticate`'s report of the
            // same condition: one name emits at one level.
            warn!(event = "admin_password_hash_unreadable",
                  outcome = "failure",
                  username = %user.username,
                  error = %error);
            Err(AdminError::invalid_credentials())
        }
    }
}

/// `GET /api/mfa` — this operator's second-factor state.
///
/// Never the secret, and never a recovery code: only whether one exists and how
/// many are left.
pub async fn get_mfa(
    State(state): State<AdminState>,
    auth: Authenticated,
) -> Result<Json<serde_json::Value>, AdminError> {
    let remaining = mfa::recovery_codes_remaining(auth.user.id, state.database).await?;
    Ok(Json(json!({
        "totpEnabled": auth.user.has_totp(),
        "enrolmentPending": auth.user.has_pending_totp(),
        "recoveryCodesRemaining": remaining,
    })))
}

/// `POST /api/mfa/totp` — begin an enrolment.
///
/// **The response is the only time the secret is readable.** It is stored as
/// `totp_pending_secret` and never rendered again -- `GET /api/mfa` reports
/// `enrolmentPending`, not the bytes. Starting a second enrolment overwrites the
/// pending one and leaves any *confirmed* factor untouched, which is what makes
/// "move to a new phone" safe to begin.
///
/// Requires the account password when a factor already exists: see
/// [`check_step_up`]. `confirm` deliberately does not, since it can only
/// confirm a secret this route already gated.
pub async fn begin_totp(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    enrol: EnrolWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let mut user = enrol.user;
    check_step_up(
        &user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;
    let enrolment = mfa::begin_totp_enrolment(
        &mut user,
        &state.config.admin.base_url,
        state.database.clone(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "secret": enrolment.secret_base32,
            "uri": enrolment.uri,
            "algorithm": "SHA1",
            "digits": totp::DIGITS,
            "period": totp::PERIOD_SECONDS,
        })),
    )
        .into_response())
}

/// `POST /api/mfa/totp/confirm` — prove a code against the pending enrolment.
///
/// On success the pending secret becomes the real one and a fresh recovery set
/// is returned **once**. When the session was still `pending_mfa` -- the
/// `require_mfa` bootstrap -- this also completes the login, so the answer
/// carries a rotated cookie: setting a factor up *is* the second step for an
/// operator who had none.
pub async fn confirm_totp(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    enrol: EnrolWrite,
    Json(body): Json<ConfirmRequest>,
) -> Result<Response, AdminError> {
    let mut user = enrol.user;
    let keep = enrol.session.token_hash.clone();

    let Some(codes) =
        mfa::confirm_totp_enrolment(&mut user, &body.code, Some(&keep), state.database.clone())
            .await?
    else {
        return Err(AdminError::bad_request(
            "that code does not match the pending enrolment",
        ));
    };

    let body = json!({ "recoveryCodes": codes });

    if !enrol.pending {
        return Ok((StatusCode::OK, Json(body)).into_response());
    }

    // The `require_mfa` bootstrap: this confirmation completed the login, so it
    // owes everything the code path owes. `finish_enrolment` is the one place
    // that knows what, and the pages side calls the same function.
    let (_, cookie) =
        finish_enrolment(&state, client, &mut user, &enrol.session.token_hash).await?;
    Ok((StatusCode::OK, [(header::SET_COOKIE, cookie)], Json(body)).into_response())
}

/// `DELETE /api/mfa/totp` — remove the factor and every recovery code.
///
/// Refused while `admin.require_mfa` is on: the operator would be made to enrol
/// again on their very next sign-in, so the only thing removing it achieves is
/// a locked panel between the two.
///
/// Requires the account password ([`check_step_up`]) — removing a factor is the
/// most consequential thing a stolen cookie could do here.
pub async fn disable_totp(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    if state.config.admin.require_mfa {
        return Err(AdminError::conflict(
            "mfa_required",
            "admin.require_mfa is on: this server requires a second factor of every operator",
        ));
    }

    let mut user = auth.user;
    check_step_up(
        &user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;
    mfa::disable_totp(
        &mut user,
        Some(&auth.session.token_hash),
        state.database.clone(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/mfa/recovery-codes` — mint a fresh set, **shown once**.
///
/// The previous set stops working the moment this answers, which is why it
/// takes the account password ([`check_step_up`]): superseding the set a stolen
/// session's owner would use to recover is the same lockout as replacing the
/// factor.
pub async fn regenerate_recovery_codes(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    if !auth.user.has_totp() {
        return Err(AdminError::conflict(
            "mfa_not_enabled",
            "there is no second factor for these codes to recover access to",
        ));
    }
    check_step_up(
        &auth.user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;

    let codes = mfa::regenerate_recovery_codes(&auth.user, state.database).await?;
    Ok(Json(json!({ "recoveryCodes": codes })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_user::AdminUser;

    fn user_with(password_hash: &str, totp: Option<&[u8]>) -> AdminUser {
        AdminUser {
            id: crate::testutil::ADMIN_FIXTURE_ID,
            username: "alice".to_string(),
            password_hash: password_hash.to_string(),
            status: "active".to_string(),
            totp_secret: totp.map(<[u8]>::to_vec),
            totp_pending_secret: None,
            totp_last_step: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            last_login_at: None,
        }
    }

    use crate::webadmin::session::LoginLimiter;
    use std::net::IpAddr;

    const MAX_ATTEMPTS: u32 = 5;

    fn limiter() -> LoginLimiter {
        LoginLimiter::new(MAX_ATTEMPTS, 300)
    }

    fn client() -> Option<IpAddr> {
        Some("198.51.100.7".parse().expect("a literal address"))
    }

    /// The encoded form is self-describing, so a cheaper cost still exercises
    /// every branch here at a fraction of the wall clock — which matters,
    /// because these tests deliberately run the KDF several times over.
    fn cheap_hash(password: &str) -> String {
        crate::admin::password::hash_generated_secret(password)
    }

    /// The gate is scoped to operators who *have* something to protect.
    #[test]
    fn a_factorless_operator_passes_without_a_password() {
        let user = user_with("not-even-a-valid-hash", None);
        let logins = limiter();
        assert!(check_step_up(&user, "", client(), &logins).is_ok());
        assert!(check_step_up(&user, "anything", client(), &logins).is_ok());
    }

    /// The inverse of the test above: `verify_current_password` carries no
    /// `has_totp()` exemption, since a password change needs the current
    /// password proven whether or not a second factor exists.
    #[test]
    fn verify_current_password_runs_even_for_a_factorless_operator() {
        let hash = cheap_hash("correct horse battery staple");
        let user = user_with(&hash, None);
        let logins = limiter();

        assert!(
            verify_current_password(&user, "correct horse battery staple", client(), &logins)
                .is_ok()
        );
        let error = verify_current_password(&user, "wrong", client(), &logins)
            .expect_err("a wrong password must refuse even with no factor enrolled");
        assert_eq!(error.code, AdminError::invalid_credentials().code);
    }

    #[test]
    fn a_live_factor_needs_the_right_password() {
        let hash = cheap_hash("correct horse battery staple");
        let user = user_with(&hash, Some(b"secret"));
        let logins = limiter();

        assert!(check_step_up(&user, "correct horse battery staple", client(), &logins).is_ok());
        for wrong in ["", "Correct horse battery staple", "wrong"] {
            let Err(error) = check_step_up(&user, wrong, client(), &logins) else {
                panic!("{wrong:?} must be refused");
            };
            // Byte-identical to a wrong password at sign-in, so this is not a
            // second oracle for whether one is right.
            assert_eq!(error.code, AdminError::invalid_credentials().code);
            assert_eq!(error.status, AdminError::invalid_credentials().status);
        }
    }

    /// A stored hash this process cannot parse is a corrupt row, not a correct
    /// password. It must refuse rather than let the factor change through.
    #[test]
    fn an_unreadable_stored_hash_refuses_rather_than_admits() {
        let user = user_with("pbkdf2-sha256$not-a-number$salt$digest", Some(b"secret"));
        let logins = limiter();
        let error = check_step_up(&user, "anything", client(), &logins)
            .expect_err("a corrupt hash must refuse");
        assert_eq!(error.code, AdminError::invalid_credentials().code);
    }

    /// Guessing the password here is bounded by the same budget sign-in uses.
    ///
    /// The assertion that matters is the *last* one: once the address is locked
    /// out the **correct** password is refused too, which is the only thing that
    /// can prove the limiter runs before the KDF rather than after it. Checking
    /// it afterwards would bound nothing — the expensive work would already be
    /// done, and that expense is the denial-of-service lever `sign_in` runs its
    /// own check ahead of.
    #[test]
    fn a_wrong_password_counts_against_the_login_limiter() {
        let hash = cheap_hash("correct horse battery staple");
        let user = user_with(&hash, Some(b"secret"));
        let logins = limiter();

        for _ in 0..MAX_ATTEMPTS {
            let error = check_step_up(&user, "wrong", client(), &logins)
                .expect_err("a wrong password must refuse");
            assert_eq!(error.code, AdminError::invalid_credentials().code);
        }

        let error = check_step_up(&user, "correct horse battery staple", client(), &logins)
            .expect_err("the budget is spent, so even a correct password waits");
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// A correct password does **not** clear the bucket.
    ///
    /// `sign_in` moved its own `record_success` past the second factor for
    /// exactly this reason: somebody holding a correct password must not be able
    /// to reset the budget at will and brute-force the six digits behind it. A
    /// step-up caller holds a session, so they are in that position by
    /// definition.
    #[test]
    fn a_correct_password_does_not_clear_the_bucket() {
        let hash = cheap_hash("correct horse battery staple");
        let user = user_with(&hash, Some(b"secret"));
        let logins = limiter();

        for _ in 0..MAX_ATTEMPTS - 1 {
            assert!(check_step_up(&user, "wrong", client(), &logins).is_err());
        }
        assert!(check_step_up(&user, "correct horse battery staple", client(), &logins).is_ok());

        // One guess left, not a fresh five.
        assert!(check_step_up(&user, "wrong", client(), &logins).is_err());
        let error = check_step_up(&user, "wrong", client(), &logins)
            .expect_err("the budget survives a correct password");
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// An operator with no factor never spends the budget, since the gate
    /// returns before any KDF runs — there is nothing to bound, and charging
    /// them would let a factorless account lock its own address out of sign-in.
    #[test]
    fn a_factorless_operator_never_touches_the_limiter() {
        let user = user_with("not-even-a-valid-hash", None);
        let logins = limiter();

        for _ in 0..MAX_ATTEMPTS + 1 {
            assert!(check_step_up(&user, "anything", client(), &logins).is_ok());
        }
        assert!(logins.check(client()).is_ok());
    }

    /// A corrupt row refuses, but must not lock its own owner out of sign-in:
    /// `decode` failed before the KDF ran, so nothing was guessed and no work
    /// was spent.
    #[test]
    fn an_unreadable_stored_hash_does_not_lock_the_address_out() {
        let user = user_with("pbkdf2-sha256$not-a-number$salt$digest", Some(b"secret"));
        let logins = limiter();

        for _ in 0..MAX_ATTEMPTS + 1 {
            assert!(check_step_up(&user, "anything", client(), &logins).is_err());
        }
        assert!(logins.check(client()).is_ok());
    }
}
