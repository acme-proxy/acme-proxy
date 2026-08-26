//! `/ui/login` and `/ui/logout` — the sign-in page and its counterpart.
//!
//! The only page routes reachable without a session, and the only ones that use
//! a plain HTML form rather than htmx: there is no CSRF token to send until a
//! session exists, and signing in should work before a byte of JavaScript has
//! loaded. What protects the route instead is `check_origin`, run inside
//! [`crate::webadmin::handlers::session::sign_in`] — the same gate, the same
//! function, as `POST /api/session`.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};

use crate::admin::mfa;
use crate::sqlite::admin_session::AdminSession;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::session::{
    LoginRequest, LogoutQuery, MfaRequest, finish_enrolment, finish_mfa, sign_in,
};
use crate::webadmin::pages::auth::{PageMfaPending, PageMfaSubmit, PageSessionWrite};
use crate::webadmin::pages::error::{LOGIN_PATH, PageError, redirect};
use crate::webadmin::pages::templates;
use crate::webadmin::session::{AdminClientIp, MfaStep, PendingMfa, clearing_cookie};

/// Where a successful sign-in lands.
const PANEL_PATH: &str = "/ui/";

/// Where a sign-in that still owes a second factor lands.
pub(crate) const MFA_PATH: &str = "/ui/login/mfa";

/// `GET /ui/login` — the sign-in form.
///
/// Rendered unconditionally, including for someone who already has a live
/// session: checking would mean a second session-resolution path beside
/// `resolve_session`, and the whole cost of not checking is that a signed-in
/// operator who navigates here sees a form.
pub async fn get_login(State(state): State<AdminState>) -> Result<Response, PageError> {
    Ok(page(&state, None, None)?.into_response())
}

/// `POST /ui/login` — exchange a username and password for a session cookie.
///
/// A form body where `POST /api/session` takes JSON; everything that makes a
/// sign-in safe is in [`sign_in`] and shared between them.
pub async fn post_login(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    Form(credentials): Form<LoginRequest>,
) -> Result<Response, PageError> {
    match sign_in(&state, client, &headers, &credentials).await {
        // A pending sign-in goes to the challenge page instead of the panel;
        // everything else about the answer, cookie included, is the same.
        Ok(signed_in) => Ok((
            StatusCode::SEE_OTHER,
            [
                (
                    header::LOCATION,
                    if signed_in.pending.is_some() {
                        MFA_PATH.to_string()
                    } else {
                        PANEL_PATH.to_string()
                    },
                ),
                (header::SET_COOKIE, signed_in.cookie),
            ],
        )
            .into_response()),
        // Re-rendered rather than redirected, so the browser keeps the typed
        // username and the reason is visible. The status is the real one --
        // `401` for a refused credential, `429` for the limiter -- because a
        // sign-in page answering `200` to a failed attempt is a lie a script
        // would believe.
        Err(error) => {
            let status = error.status;
            let flash = super::flash_error(error.code, error.message);
            Ok((
                status,
                page(&state, Some(flash), Some(&credentials.username))?,
            )
                .into_response())
        }
    }
}

/// `GET /ui/login/mfa` — the second half of signing in.
///
/// Two shapes behind one URL, chosen off `step`: prove a code, or -- when
/// `admin.require_mfa` is on and this operator has no factor -- set one up
/// first. Both are the same half-authenticated session, and only
/// `user.has_totp()` tells them apart.
pub async fn get_login_mfa(
    State(state): State<AdminState>,
    session: PageMfaPending,
) -> Result<Response, PageError> {
    Ok(challenge(&state, session.pending, None)
        .await?
        .into_response())
}

/// `POST /ui/login/mfa` — finish the sign-in with a code.
///
/// A plain form, like `/ui/login` and for the same reason, so there is no CSRF
/// token; [`crate::webadmin::session::PendingMfaSubmit`] runs the origin gate in
/// its place.
pub async fn post_login_mfa(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    session: PageMfaSubmit,
    Form(body): Form<MfaRequest>,
) -> Result<Response, PageError> {
    // Under `require_mfa`, an operator with no factor finishes their login by
    // *setting one up* rather than by proving one — so this same URL confirms an
    // enrolment. Which of the two is `step`, and nothing else.
    if session.pending.step == MfaStep::Enrol {
        return confirm_enrolment(&state, client, session.pending, &body.code).await;
    }

    // Kept for the re-render: `finish_mfa` consumes the pending session.
    let step = session.pending.step;
    let expires_at = session.pending.session.expires_at;

    match finish_mfa(&state, client, session.pending, &body.code).await {
        Ok(signed_in) => Ok((
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, PANEL_PATH.to_string()),
                // The rotated cookie. Without setting it here the browser would
                // keep the pending token, which `promote` has already deleted.
                (header::SET_COOKIE, signed_in.cookie),
            ],
        )
            .into_response()),
        // Re-rendered at the real status, exactly as `post_login` does.
        Err(error) => {
            let status = error.status;
            let flash = super::flash_error(error.code, error.message);
            let mut context = Map::new();
            context.insert("step".to_string(), Value::String(step.as_str().to_string()));
            context.insert(
                "expiresAt".to_string(),
                Value::String(crate::sqlite::order::rfc3339(expires_at)),
            );
            context.insert("flash".to_string(), flash);
            Ok((status, render_challenge(&state, context)?).into_response())
        }
    }
}

/// The `enrol` half of `POST /ui/login/mfa`.
///
/// Answers with the recovery codes rather than a `303`, and that is the point:
/// they exist for exactly one moment and a redirect would spend it. The rotated
/// cookie rides along, so the "Continue" link on that page is already an
/// authenticated navigation.
async fn confirm_enrolment(
    state: &AdminState,
    client: Option<std::net::IpAddr>,
    pending: PendingMfa,
    code: &str,
) -> Result<Response, PageError> {
    let mut user = pending.user;
    let keep = pending.session.token_hash.clone();

    let Some(codes) =
        mfa::confirm_totp_enrolment(&mut user, code, Some(&keep), state.database.clone()).await?
    else {
        let mut context = Map::new();
        context.insert("step".to_string(), Value::String("enrol".to_string()));
        context.insert(
            "flash".to_string(),
            super::flash_error("bad_request", "That code did not match. Try the next one."),
        );
        context.insert(
            "enrolment".to_string(),
            enrolment_context(state, &mut user).await?,
        );
        return Ok((StatusCode::UNAUTHORIZED, render_challenge(state, context)?).into_response());
    };

    // Completes the login, so it goes through the same function the API side
    // does -- promotion plus `mark_logged_in`, `record_success` and the
    // `admin_login_succeeded` line. Doing it by hand here is how the two front
    // ends drifted the first time.
    let (_, cookie) =
        finish_enrolment(state, client, &mut user, &pending.session.token_hash).await?;

    let mut context = Map::new();
    context.insert("recovery_codes".to_string(), serde_json::json!(codes));
    let body = templates::render(
        &state.templates,
        "mfa/enrolled.html",
        minijinja::Value::from_serialize(Value::Object(context)),
    )?;

    let mut response = (StatusCode::OK, body).into_response();
    if let Ok(value) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    Ok(response)
}

/// `POST /ui/logout[?all=true]` — sign out here, or everywhere.
pub async fn post_logout(
    State(state): State<AdminState>,
    Query(query): Query<LogoutQuery>,
    session: PageSessionWrite,
) -> Result<Response, PageError> {
    let scope = if query.all {
        AdminSession::delete_for_user(session.auth.user.id, &state.database).await?;
        "all"
    } else {
        AdminSession::delete(&session.auth.session.token_hash, &state.database).await?;
        "one"
    };

    tracing::info!(event = "admin_logout",
                   outcome = "success",
                   surface = "ui",
                   username = %session.auth.user.username,
                   scope = scope);

    // The redirect and the cookie together: leaving the cookie behind would
    // send the browser to the sign-in page still carrying a token the server
    // has already forgotten.
    let mut response = redirect(LOGIN_PATH, session.hx);
    if let Ok(value) = header::HeaderValue::from_str(&clearing_cookie()) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    Ok(response)
}

/// Renders the sign-in page, optionally with a banner and a username to keep.
fn page(
    state: &AdminState,
    flash: Option<Value>,
    username: Option<&str>,
) -> Result<axum::response::Html<String>, PageError> {
    let mut context = Map::new();
    if let Some(flash) = flash {
        context.insert("flash".to_string(), flash);
    }
    if let Some(username) = username {
        context.insert("username".to_string(), Value::String(username.to_string()));
    }
    templates::render(
        &state.templates,
        "login.html",
        minijinja::Value::from_serialize(Value::Object(context)),
    )
}

/// Renders the challenge page for a pending session, optionally with a banner.
///
/// On the `enrol` step this also mints (or resumes) the pending secret, since
/// there is nothing to show otherwise. Resuming is what stops a page reload
/// handing the operator a different secret from the one they have just scanned.
async fn challenge(
    state: &AdminState,
    pending: PendingMfa,
    flash: Option<Value>,
) -> Result<axum::response::Html<String>, PageError> {
    let mut context = Map::new();
    context.insert(
        "step".to_string(),
        Value::String(pending.step.as_str().to_string()),
    );
    context.insert(
        "expiresAt".to_string(),
        Value::String(crate::sqlite::order::rfc3339(pending.session.expires_at)),
    );
    if let Some(flash) = flash {
        context.insert("flash".to_string(), flash);
    }
    if pending.step == MfaStep::Enrol {
        let mut user = pending.user;
        context.insert(
            "enrolment".to_string(),
            enrolment_context(state, &mut user).await?,
        );
    }
    render_challenge(state, context)
}

/// The `enrolment` object `mfa/_setup.html` reads.
async fn enrolment_context(
    state: &AdminState,
    user: &mut crate::sqlite::admin_user::AdminUser,
) -> Result<Value, PageError> {
    let enrolment = mfa::resume_or_begin_totp_enrolment(
        user,
        &state.config.admin.base_url,
        state.database.clone(),
    )
    .await?;

    Ok(serde_json::json!({
        "secret": enrolment.secret_base32,
        "uri": enrolment.uri,
        "algorithm": "SHA1",
        "digits": crate::admin::totp::DIGITS,
        "period": crate::admin::totp::PERIOD_SECONDS,
    }))
}

fn render_challenge(
    state: &AdminState,
    context: Map<String, Value>,
) -> Result<axum::response::Html<String>, PageError> {
    templates::render(
        &state.templates,
        "mfa/challenge.html",
        minijinja::Value::from_serialize(Value::Object(context)),
    )
}
