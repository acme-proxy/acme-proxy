//! `/ui/account` — the operator's own page, which is only ever about their
//! second factor.
//!
//! Everything here acts on whoever is holding the cookie, which is why no path
//! carries an id. Managing *other* operators stays a shell command on the host:
//! this panel has no sign-up page and no user administration, deliberately.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::admin::{mfa, totp};
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::mfa::check_step_up;
use crate::webadmin::pages::auth::{PageEnrolWrite, PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, respond, respond_fragment};

#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    pub code: String,
}

/// The `/ui` twin of [`crate::webadmin::handlers::mfa::StepUpRequest`]: the
/// password the card's own field collects, pulled in by `hx-include`.
#[derive(Debug, Default, Deserialize)]
pub struct StepUpForm {
    #[serde(default)]
    pub password: String,
}

/// [`check_step_up`] with the refusal rendered as this card's banner.
///
/// The module's rule -- "the row's state is a banner, the server's problem is a
/// page" -- puts a wrong password on the banner side: the session is live and
/// the page is the right page, only this one action was refused.
async fn refuse_without_password(
    state: &AdminState,
    user: &AdminUser,
    csrf_token: &str,
    password: &str,
) -> Result<Option<Response>, PageError> {
    if check_step_up(user, password).is_ok() {
        return Ok(None);
    }
    let mut context = card_context(state, user, csrf_token).await?;
    context.insert(
        "flash".to_string(),
        super::flash_error("invalid_credentials", "That password is not correct."),
    );
    Ok(Some(
        (
            StatusCode::UNAUTHORIZED,
            respond_fragment(state, "account/_mfa.html", context)?,
        )
            .into_response(),
    ))
}

/// `GET /ui/account` — the second-factor status card.
pub async fn get_account(
    State(state): State<AdminState>,
    session: PageSession,
) -> Result<Response, PageError> {
    let mut context = chrome(&session, "account", "Your account");
    context.insert("mfa".to_string(), status(&state, &session.auth.user).await?);
    context.insert(
        "require_mfa".to_string(),
        Value::Bool(state.config.admin.require_mfa),
    );
    context.insert("period".to_string(), json!(totp::PERIOD_SECONDS));

    Ok(respond(
        &state,
        session.hx,
        "account/index.html",
        "account/_mfa.html",
        context,
    )?
    .into_response())
}

/// `POST /ui/account/mfa/totp` — begin (or resume) an enrolment.
///
/// Resumes rather than restarts when one is already pending: an operator who
/// reloads after scanning the secret into an app must not be handed a different
/// one.
///
/// Takes the account password when a factor already exists — the card's own
/// field, pulled in by `hx-include`. See [`check_step_up`].
pub async fn begin_totp(
    State(state): State<AdminState>,
    session: PageEnrolWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let mut user = session.enrol.user;
    if let Some(refusal) = refuse_without_password(
        &state,
        &user,
        &session.enrol.session.csrf_token,
        &body.password,
    )
    .await?
    {
        return Ok(refusal);
    }

    let enrolment = mfa::resume_or_begin_totp_enrolment(
        &mut user,
        &state.config.admin.base_url,
        state.database.clone(),
    )
    .await?;

    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.enrol.session.csrf_token.clone()),
    );
    context.insert(
        "enrolment".to_string(),
        json!({
            "secret": enrolment.secret_base32,
            "uri": enrolment.uri,
            "algorithm": "SHA1",
            "digits": totp::DIGITS,
            "period": totp::PERIOD_SECONDS,
        }),
    );

    Ok(respond_fragment(&state, "account/_enrol.html", context)?.into_response())
}

/// `POST /ui/account/mfa/totp/confirm` — prove a code, and receive the recovery
/// codes once.
///
/// A wrong code is a banner on the enrolment step, not an error page: the row's
/// state is a banner, the server's problem is a page.
pub async fn confirm_totp(
    State(state): State<AdminState>,
    session: PageEnrolWrite,
    axum::Form(body): axum::Form<ConfirmForm>,
) -> Result<Response, PageError> {
    let mut user = session.enrol.user;
    let keep = session.enrol.session.token_hash.clone();

    let Some(codes) =
        mfa::confirm_totp_enrolment(&mut user, &body.code, Some(&keep), state.database.clone())
            .await?
    else {
        // Re-render the enrolment step with the same secret still pending, so
        // the operator can simply try the next code their app shows.
        let enrolment = mfa::resume_or_begin_totp_enrolment(
            &mut user,
            &state.config.admin.base_url,
            state.database.clone(),
        )
        .await?;

        let mut context = Map::new();
        context.insert(
            "csrf_token".to_string(),
            Value::String(session.enrol.session.csrf_token.clone()),
        );
        context.insert(
            "enrolment".to_string(),
            json!({
                "secret": enrolment.secret_base32,
                "uri": enrolment.uri,
                "algorithm": "SHA1",
                "digits": totp::DIGITS,
                "period": totp::PERIOD_SECONDS,
            }),
        );
        context.insert(
            "flash".to_string(),
            super::flash_error("bad_request", "That code did not match. Try the next one."),
        );

        return Ok((
            StatusCode::BAD_REQUEST,
            respond_fragment(&state, "account/_enrol.html", context)?,
        )
            .into_response());
    };

    let mut context = card_context(&state, &user, &session.enrol.session.csrf_token).await?;
    context.insert("recovery_codes".to_string(), json!(codes));
    Ok(respond_fragment(&state, "account/_codes.html", context)?.into_response())
}

/// `POST /ui/account/mfa/totp/disable` — turn the factor off.
///
/// Takes the account password ([`check_step_up`]): this is the most
/// consequential thing a stolen cookie could do here.
pub async fn disable_totp(
    State(state): State<AdminState>,
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    if state.config.admin.require_mfa {
        // A banner, not a page: the refusal is about this card's own state.
        let mut context =
            card_context(&state, &session.auth.user, &session.auth.session.csrf_token).await?;
        context.insert(
            "flash".to_string(),
            super::flash_error(
                "mfa_required",
                "This server requires a second factor of every operator.",
            ),
        );
        return Ok((
            StatusCode::CONFLICT,
            respond_fragment(&state, "account/_mfa.html", context)?,
        )
            .into_response());
    }

    let mut user = session.auth.user;
    if let Some(refusal) = refuse_without_password(
        &state,
        &user,
        &session.auth.session.csrf_token,
        &body.password,
    )
    .await?
    {
        return Ok(refusal);
    }

    mfa::disable_totp(
        &mut user,
        Some(&session.auth.session.token_hash),
        state.database.clone(),
    )
    .await?;

    let mut context = card_context(&state, &user, &session.auth.session.csrf_token).await?;
    context.insert(
        "flash".to_string(),
        super::flash(
            "warn",
            "Two-factor authentication is off. Your recovery codes were destroyed \
             and every other session of yours was signed out.",
        ),
    );
    Ok(respond_fragment(&state, "account/_mfa.html", context)?.into_response())
}

/// `POST /ui/account/mfa/recovery-codes` — mint a fresh set, **shown once**.
///
/// Takes the account password ([`check_step_up`]): superseding the set the
/// rightful operator would recover with is the same lockout as replacing the
/// factor itself.
pub async fn regenerate_recovery_codes(
    State(state): State<AdminState>,
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    if !session.auth.user.has_totp() {
        let mut context =
            card_context(&state, &session.auth.user, &session.auth.session.csrf_token).await?;
        context.insert(
            "flash".to_string(),
            super::flash_error(
                "mfa_not_enabled",
                "There is no second factor for these codes to recover access to.",
            ),
        );
        return Ok((
            StatusCode::CONFLICT,
            respond_fragment(&state, "account/_mfa.html", context)?,
        )
            .into_response());
    }

    if let Some(refusal) = refuse_without_password(
        &state,
        &session.auth.user,
        &session.auth.session.csrf_token,
        &body.password,
    )
    .await?
    {
        return Ok(refusal);
    }

    let codes = mfa::regenerate_recovery_codes(&session.auth.user, state.database.clone()).await?;
    let mut context =
        card_context(&state, &session.auth.user, &session.auth.session.csrf_token).await?;
    context.insert("recovery_codes".to_string(), json!(codes));

    Ok(respond_fragment(&state, "account/_codes.html", context)?.into_response())
}

/// What `GET /api/mfa` answers, for the template.
async fn status(state: &AdminState, user: &AdminUser) -> Result<Value, PageError> {
    let remaining = mfa::recovery_codes_remaining(&user.id, state.database.clone()).await?;
    Ok(json!({
        "totpEnabled": user.has_totp(),
        "enrolmentPending": user.has_pending_totp(),
        "recoveryCodesRemaining": remaining,
    }))
}

/// Everything `account/_card.html` reads.
///
/// A fragment is rendered standalone, so it cannot inherit the `hx-headers` on
/// `<body>` — the `csrf_token` has to be inserted by hand or every control in
/// the swapped fragment answers `403`. Same rule as `pages::accounts::card`.
async fn card_context(
    state: &AdminState,
    user: &AdminUser,
    csrf_token: &str,
) -> Result<Map<String, Value>, PageError> {
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(csrf_token.to_string()),
    );
    context.insert(
        "user".to_string(),
        crate::admin::render_admin_user_json(user),
    );
    context.insert("mfa".to_string(), status(state, user).await?);
    context.insert(
        "require_mfa".to_string(),
        Value::Bool(state.config.admin.require_mfa),
    );
    context.insert("period".to_string(), json!(totp::PERIOD_SECONDS));
    Ok(context)
}

// No `not_found` here, unlike every sibling in this directory: none of these
// routes takes an id. There is exactly one account this page can be about, and
// the session names it.
