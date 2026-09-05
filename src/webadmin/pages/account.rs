//! `/ui/account` — the operator's own page: password, second factor, and
//! their own live sessions.
//!
//! Everything here acts on whoever is holding the cookie, which is why no path
//! carries an id — the one apparent exception, `/ui/account/sessions/{id}`,
//! still names only *which session*, never a different account. Managing
//! *another* operator is `pages::operators`, not this module: the two are kept
//! apart because every route there sits behind a password re-entry
//! (`check_step_up`) this operator's own actions never need. `create`/`passwd`
//! stay a shell command on the host either way — this panel has no sign-up
//! page, and minting a credential is where that line is drawn.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::admin;
use crate::admin::password::PasswordContext;
use crate::admin::users::{self, UserError};
use crate::admin::{mfa, totp};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::mfa::{check_step_up, verify_current_password};
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageEnrolWrite, PageSelfServiceWrite, PageSession};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, respond, respond_fragment};
use crate::webadmin::session::{AdminClientIp, clearing_cookie};

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
/// the page is the right page, only this one action was refused. The same now
/// holds for the rate limit `check_step_up` applies, which is why the status and
/// the wording are taken from the error rather than hardcoded: a lockout renders
/// at 429 and says how long to wait, exactly as `post_login` re-renders its own
/// refusals at their real status.
async fn refuse_without_password(
    state: &AdminState,
    user: &AdminUser,
    csrf_token: &str,
    password: &str,
    client: Option<std::net::IpAddr>,
) -> Result<Option<Response>, PageError> {
    let Err(error) = check_step_up(user, password, client, &state.logins) else {
        return Ok(None);
    };
    // The wrong-password case keeps this page's own wording: `AdminError`'s is
    // "invalid username or password", which is a script's answer to a sign-in
    // and names a field this card does not have. Every other refusal — today
    // only the rate limit — carries its own message through, because that one
    // says how long to wait and no fixed string here could.
    let message = if error.status == StatusCode::UNAUTHORIZED {
        "That password is not correct.".to_string()
    } else {
        error.message.clone()
    };
    let mut context = card_context(state, user, csrf_token).await?;
    context.insert("flash".to_string(), super::flash_error(error.code, message));
    Ok(Some(
        (
            error.status,
            respond_fragment(state, "account/_mfa.html", context)?,
        )
            .into_response(),
    ))
}

/// `GET /ui/account` — the second-factor status card, the password card, and
/// this operator's own live sessions.
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
    context.insert(
        "min_password_length".to_string(),
        json!(crate::admin::password::MIN_PASSWORD_LEN),
    );
    insert_own_sessions(&mut context, &state, &session.auth).await?;

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
    AdminClientIp(client): AdminClientIp,
    session: PageEnrolWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let mut user = session.enrol.user;
    if let Some(refusal) = refuse_without_password(
        &state,
        &user,
        &session.enrol.session.csrf_token,
        &body.password,
        client,
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
    AdminClientIp(client): AdminClientIp,
    session: PageSelfServiceWrite,
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
        client,
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
    AdminClientIp(client): AdminClientIp,
    session: PageSelfServiceWrite,
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
        client,
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

#[derive(Debug, Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
}

/// Everything `account/_password_card.html` reads. Unlike [`card_context`]
/// there is no second-factor state to report, but the `csrf_token` rule is
/// the same: a fragment rendered standalone cannot inherit `<body>`'s
/// `hx-headers`, so this card's own form carries it explicitly.
fn password_card_context(csrf_token: &str) -> Map<String, Value> {
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(csrf_token.to_string()),
    );
    // A client-side hint only -- `check_password_policy` is what actually
    // enforces it, so tying the two together is about the message staying
    // true rather than about anything security-relevant.
    context.insert(
        "min_password_length".to_string(),
        json!(crate::admin::password::MIN_PASSWORD_LEN),
    );
    context
}

/// [`verify_current_password`] with the refusal rendered as the password
/// card's own banner. Unlike [`refuse_without_password`] this runs
/// unconditionally: ASVS V6.2.3 asks for the current password on every
/// change of it, whether or not a second factor exists, so there is no
/// `has_totp()` exemption to inherit from `check_step_up` here.
async fn refuse_without_current_password(
    state: &AdminState,
    csrf_token: &str,
    user: &AdminUser,
    password: &str,
    client: Option<std::net::IpAddr>,
) -> Result<Option<Response>, PageError> {
    let Err(error) = verify_current_password(user, password, client, &state.logins) else {
        return Ok(None);
    };
    let message = if error.status == StatusCode::UNAUTHORIZED {
        "That password is not correct.".to_string()
    } else {
        error.message.clone()
    };
    let mut context = password_card_context(csrf_token);
    context.insert("flash".to_string(), super::flash_error(error.code, message));
    Ok(Some(
        (
            error.status,
            respond_fragment(state, "account/_password.html", context)?,
        )
            .into_response(),
    ))
}

/// `POST /ui/account/password` — change this operator's own password.
///
/// Takes the current password ([`refuse_without_current_password`]) and the
/// new one; on success every *other* session of this operator is revoked
/// ([`users::change_own_password`]) and the one making this request stays
/// signed in.
pub async fn change_password(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    session: PageSelfServiceWrite,
    axum::Form(body): axum::Form<ChangePasswordForm>,
) -> Result<Response, PageError> {
    let mut user = session.auth.user;
    let csrf_token = session.auth.session.csrf_token.clone();

    if let Some(refusal) =
        refuse_without_current_password(&state, &csrf_token, &user, &body.current_password, client)
            .await?
    {
        return Ok(refusal);
    }

    let context = PasswordContext::from_config(&state.config, &user.username);
    let mut fragment_context = password_card_context(&csrf_token);

    match users::change_own_password(
        &mut user,
        &body.new_password,
        &context,
        &session.auth.session.token_hash,
        state.database.clone(),
    )
    .await
    {
        Ok(()) => {
            fragment_context.insert(
                "flash".to_string(),
                super::flash(
                    "ok",
                    "Your password was changed. Every other session of yours was signed out.",
                ),
            );
            Ok(
                respond_fragment(&state, "account/_password.html", fragment_context)?
                    .into_response(),
            )
        }
        Err(UserError::Policy(message)) => {
            // Same code the API answers for the identical policy failure
            // (`AdminError::bad_request`), so the two front ends never
            // describe one refusal differently.
            fragment_context.insert(
                "flash".to_string(),
                super::flash_error("bad_request", message),
            );
            Ok((
                StatusCode::BAD_REQUEST,
                respond_fragment(&state, "account/_password.html", fragment_context)?,
            )
                .into_response())
        }
        Err(UserError::Database(error)) => Err(error.into()),
        Err(UserError::DuplicateUsername(_)) => {
            // `change_own_password` never constructs this variant; the arm
            // exists only because `UserError` is shared with `create_user`.
            Err(PageError::internal())
        }
    }
}

/// `POST /ui/account/sessions/{id}/revoke` — end one of this operator's own
/// sessions.
///
/// No step-up: the same trust level as `/ui/logout` (sign out here, or
/// everywhere), not the operators surface's "act on someone else's account".
/// Revoking the session making *this* request is not a special case to guard
/// against — it behaves exactly like `/ui/logout` without `?all=true`, landing
/// back on the sign-in page with the cookie cleared, rather than re-rendering a
/// fragment for a session that no longer exists.
pub async fn revoke_own_session(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSelfServiceWrite,
) -> Result<Response, PageError> {
    let target =
        AdminSession::find_by_user_and_fingerprint(session.auth.user.id, &id, &state.database)
            .await?
            .ok_or_else(|| session_not_found(&id))?;
    let was_current = target.token_hash == session.auth.session.token_hash;
    AdminSession::delete(&target.token_hash, &state.database).await?;

    tracing::info!(event = "admin_session_revoked",
                   outcome = "success",
                   surface = "ui",
                   scope = "self",
                   username = %session.auth.user.username,
                   session_fp = %id);

    if was_current {
        let mut response = crate::webadmin::pages::error::redirect(
            crate::webadmin::pages::error::LOGIN_PATH,
            session.hx,
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&clearing_cookie()) {
            response
                .headers_mut()
                .insert(axum::http::header::SET_COOKIE, value);
        }
        return Ok(response);
    }

    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    insert_own_sessions(&mut context, &state, &session.auth).await?;
    context.insert("flash".to_string(), super::flash("ok", "Session revoked."));
    Ok(respond_fragment(&state, "account/_sessions.html", context)?.into_response())
}

fn session_not_found(id: &str) -> PageError {
    PageError::not_found(format!("no such session: {id}"))
}

/// Everything `partials/_sessions_table.html` reads for this operator's own
/// sessions -- newest first, each marked whether it is the one making the
/// current request (see [`admin::render_admin_session_detail_json`]), and no
/// step-up prefix: revoking one's own session sits at "sign out" trust level,
/// not the operators surface's.
///
/// One page's worth: an operator accumulates a handful of browser sessions,
/// never enough to need the pager the CLI's unbounded `admin session list`
/// does.
async fn insert_own_sessions(
    context: &mut Map<String, Value>,
    state: &AdminState,
    auth: &crate::webadmin::session::Authenticated,
) -> Result<(), PageError> {
    let page = PageParams::default().resolve(&state.config);
    let (sessions, _total) =
        AdminSession::search(Some(auth.user.id), page.limit, page.offset, &state.database).await?;
    let rows: Vec<Value> = sessions
        .iter()
        .map(|s| admin::render_admin_session_detail_json(s, &auth.session.token_hash))
        .collect();

    context.insert("sessions".to_string(), Value::Array(rows));
    context.insert(
        "sessions_revoke_prefix".to_string(),
        Value::String("/ui/account/sessions".to_string()),
    );
    context.insert(
        "sessions_target".to_string(),
        Value::String("#account-sessions".to_string()),
    );
    Ok(())
}

/// What `GET /api/mfa` answers, for the template.
async fn status(state: &AdminState, user: &AdminUser) -> Result<Value, PageError> {
    let remaining = mfa::recovery_codes_remaining(user.id, state.database.clone()).await?;
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
