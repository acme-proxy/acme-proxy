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
use tracing::{error, warn};

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
) -> Result<(), AdminError> {
    if !user.has_totp() {
        return Ok(());
    }
    match crate::admin::password::verify_password(&user.password_hash, password) {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!(event = "admin_mfa_step_up_refused", username = %user.username);
            Err(AdminError::invalid_credentials())
        }
        Err(error) => {
            // A stored hash this process cannot parse is a corrupt row, not a
            // wrong password. Refuse rather than let the change through.
            error!(event = "admin_password_hash_unreadable",
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
    let remaining = mfa::recovery_codes_remaining(&auth.user.id, state.database).await?;
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
    enrol: EnrolWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let mut user = enrol.user;
    check_step_up(&user, &body.unwrap_or_default().password)?;
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
    check_step_up(&user, &body.unwrap_or_default().password)?;
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
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    if !auth.user.has_totp() {
        return Err(AdminError::conflict(
            "mfa_not_enabled",
            "there is no second factor for these codes to recover access to",
        ));
    }
    check_step_up(&auth.user, &body.unwrap_or_default().password)?;

    let codes = mfa::regenerate_recovery_codes(&auth.user, state.database).await?;
    Ok(Json(json!({ "recoveryCodes": codes })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_user::AdminUser;

    fn user_with(password_hash: &str, totp: Option<&[u8]>) -> AdminUser {
        AdminUser {
            id: "11111111-2222-3333-4444-555555555555".to_string(),
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

    /// The gate is scoped to operators who *have* something to protect.
    #[test]
    fn a_factorless_operator_passes_without_a_password() {
        let user = user_with("not-even-a-valid-hash", None);
        assert!(check_step_up(&user, "").is_ok());
        assert!(check_step_up(&user, "anything").is_ok());
    }

    #[test]
    fn a_live_factor_needs_the_right_password() {
        let hash = crate::admin::password::hash_password("correct horse battery staple");
        let user = user_with(&hash, Some(b"secret"));

        assert!(check_step_up(&user, "correct horse battery staple").is_ok());
        for wrong in ["", "Correct horse battery staple", "wrong"] {
            let Err(error) = check_step_up(&user, wrong) else {
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
        let error = check_step_up(&user, "anything").expect_err("a corrupt hash must refuse");
        assert_eq!(error.code, AdminError::invalid_credentials().code);
    }
}
