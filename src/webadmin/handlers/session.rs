//! `POST`/`GET`/`DELETE /api/session` — sign in, whoami, sign out.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tracing::{info, warn};

use crate::admin::mfa::MfaOutcome;
use crate::admin::users::{self, AuthOutcome};
use crate::sqlite::admin_session::{AdminSession, NewSession};
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::session::{
    AdminClientIp, Authenticated, AuthenticatedWrite, MfaStep, PENDING_MFA_TTL, PendingMfa,
    PendingMfaSubmit, check_origin, clearing_cookie, cookie_value, hash_token, log_login,
    mint_csrf_token, mint_token, session_cookie,
};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct LogoutQuery {
    /// Sign out of every browser, not just this one.
    #[serde(default)]
    pub all: bool,
}

/// The submission that finishes a login: a TOTP code, or a recovery code. One
/// field, because the operator types whichever they have into the same box.
#[derive(Debug, Deserialize)]
pub struct MfaRequest {
    pub code: String,
}

/// A sign-in: the two rows it produced, and the cookie to set.
pub(crate) struct SignedIn {
    pub user: AdminUser,
    pub session: AdminSession,
    /// The `Set-Cookie` value, built once here so the token itself — which is
    /// never stored — does not have to travel any further than this.
    pub cookie: String,
    /// `None` is a *completed* login and an `active` session — the shape every
    /// caller had before there was a second factor.
    pub pending: Option<MfaStep>,
}

/// Everything a sign-in is, independent of how the credentials arrived.
///
/// Called by [`post_session`] with a JSON body and by
/// [`crate::webadmin::pages::session::post_login`] with a form body. The two
/// front ends must not drift on any of this: the origin gate, the limiter
/// running *before* the 600 000-iteration hash, the indistinguishable failures,
/// or the session-fixation delete.
pub(crate) async fn sign_in(
    state: &AdminState,
    client: Option<std::net::IpAddr>,
    headers: &axum::http::HeaderMap,
    credentials: &LoginRequest,
) -> Result<SignedIn, AdminError> {
    let body = credentials;
    check_origin(headers, &state.config.admin.base_url)?;

    if let Err(retry_after) = state.logins.check(client) {
        log_login(false, &body.username, client, "rate_limited");
        return Err(AdminError::rate_limited(retry_after));
    }

    let outcome =
        users::authenticate(&body.username, &body.password, state.database.clone()).await?;

    // Every failure answers identically; only the log says which.
    let mut user = match outcome {
        AuthOutcome::Authenticated(user) => *user,
        other => {
            let reason = match other {
                AuthOutcome::UnknownUser => "unknown_user",
                AuthOutcome::WrongPassword(_) => "wrong_password",
                AuthOutcome::Disabled(_) => "account_disabled",
                AuthOutcome::Authenticated(_) => unreachable!("handled above"),
            };
            state.logins.record_failure(client);
            log_login(false, &body.username, client, reason);
            return Err(AdminError::invalid_credentials());
        }
    };

    // What still stands between this password and a usable session. An
    // operator who *has* a factor is challenged whether `require_mfa` is set or
    // not: the flag governs only the operator who has none.
    let step = if user.has_totp() {
        Some(MfaStep::Verify)
    } else if state.config.admin.require_mfa {
        Some(MfaStep::Enrol)
    } else {
        None
    };

    // Session fixation: whatever session this request already carried is gone,
    // whether or not it was valid. A login must never keep an attacker-planted
    // cookie alive.
    if let Some(existing) = cookie_value(headers) {
        AdminSession::delete(&hash_token(&existing), &state.database).await?;
    }

    let minted = mint_token();
    let csrf_token = mint_csrf_token();
    let created_ip = client.map(|ip| ip.to_string());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(step) = step else {
        let ttl = Duration::from_secs(state.config.admin.session_ttl_seconds);
        let session = AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: &minted.token_hash,
                csrf_token: &csrf_token,
                created_ip,
                user_agent,
            },
            ttl,
            &state.database,
        )
        .await?;

        user.mark_logged_in(&state.database).await?;
        state.logins.record_success(client);
        log_login(true, &user.username, client, "");

        return Ok(SignedIn {
            user,
            session,
            cookie: session_cookie(&minted.token, ttl),
            pending: None,
        });
    };

    // Half-authenticated. Three things deliberately do **not** happen here, and
    // each would be a real hole:
    //
    // - `record_success`: it clears this address's limiter bucket, so leaving
    //   it here would let somebody holding a correct password reset their own
    //   budget on every attempt and then guess six-digit codes without limit.
    // - `mark_logged_in`: `last_login_at` should mean "completed a login", not
    //   "typed the right password".
    // - `log_login(true, …)`: the login has not succeeded yet.
    //
    // No `record_failure` either: the password *was* right.
    let session = AdminSession::create_pending(
        NewSession {
            user_id: user.id,
            token_hash: &minted.token_hash,
            csrf_token: &csrf_token,
            created_ip,
            user_agent,
        },
        PENDING_MFA_TTL,
        &state.database,
    )
    .await?;

    info!(event = "admin_login_mfa_pending",
          outcome = "success",
          username = %user.username,
          client_ip = ?client,
          step = step.as_str());

    Ok(SignedIn {
        user,
        session,
        // The cookie's Max-Age follows the row, not the configured session
        // lifetime: a browser holding it for twelve hours after the row died in
        // five minutes only produces a confusing refusal.
        cookie: session_cookie(&minted.token, PENDING_MFA_TTL),
        pending: Some(step),
    })
}

/// Everything finishing a login is, independent of how the code arrived.
///
/// [`sign_in`]'s twin, and shared by [`post_session_mfa`] and
/// `pages::session::post_login_mfa` for the same reason: the limiter, the
/// indistinguishable failures and the token rotation must not drift between the
/// two front ends.
pub(crate) async fn finish_mfa(
    state: &AdminState,
    client: Option<std::net::IpAddr>,
    pending: PendingMfa,
    submitted: &str,
) -> Result<SignedIn, AdminError> {
    // The origin gate already ran, in `PendingMfaSubmit`'s extractor -- it is
    // what stands in for the CSRF token this route cannot have.
    if let Err(retry_after) = state.logins.check(client) {
        log_login(false, &pending.user.username, client, "rate_limited");
        return Err(AdminError::rate_limited(retry_after));
    }

    let mut user = pending.user;
    let outcome =
        crate::admin::mfa::verify_second_factor(&mut user, submitted, state.database.clone())
            .await?;

    let MfaOutcome::Accepted { via, .. } = outcome else {
        state.logins.record_failure(client);

        // The bound the address-keyed limiter cannot provide. A `pending_mfa`
        // cookie is valid from any address on purpose, so without this an
        // attacker holding the password gets `login_max_attempts` fresh guesses
        // per source address -- 2^64 of them from one IPv6 /64, against a
        // six-digit code with a three-step window. The counter lives on the
        // session, so rotating addresses buys nothing, and it is incremented by
        // a single `UPDATE ... RETURNING`, so concurrent submissions cannot
        // each observe zero.
        let spent = AdminSession::record_mfa_failure(&pending.session.token_hash, &state.database)
            .await?
            .is_some_and(|attempts| attempts >= i64::from(state.config.admin.login_max_attempts));

        if spent {
            // Past the cap the half-authenticated session is over, not merely
            // refused: producing the password again is the only way back to a
            // pending row, and `sign_in`'s limiter bounds *that*.
            AdminSession::delete(&pending.session.token_hash, &state.database).await?;
            warn!(event = "admin_mfa_attempts_exhausted",
                  outcome = "failure",
                  username = %user.username,
                  client_ip = ?client,
                  max_attempts = state.config.admin.login_max_attempts);
        }

        warn!(event = "admin_mfa_failed",
              outcome = "failure",
              username = %user.username,
              client_ip = ?client,
              reason = outcome.reason());
        // The same answer a wrong password gets, and for the same reason: a
        // wrong code, a spent recovery code and a replayed one are one refusal
        // to the client, and only the log says which. Exhausting the attempts
        // is deliberately not a distinguishable answer either -- the next
        // request will simply find no session.
        return Err(AdminError::invalid_credentials());
    };

    let (session, cookie) = promote_pending(state, &pending.session.token_hash).await?;

    user.mark_logged_in(&state.database).await?;
    state.logins.record_success(client);
    info!(event = "admin_mfa_verified",
          outcome = "success",
          username = %user.username,
          method = via.as_str());
    log_login(true, &user.username, client, "");

    Ok(SignedIn {
        user,
        session,
        cookie,
        pending: None,
    })
}

/// Rotates a `pending_mfa` session into a fresh `active` one, returning the row
/// and the `Set-Cookie` carrying its new token.
///
/// Shared by [`finish_mfa`] and the enrolment-confirm handler, which is the
/// other way a half-authenticated session becomes usable: under
/// `admin.require_mfa`, an operator with no factor finishes their login by
/// *setting one up*, not by proving one.
pub(crate) async fn promote_pending(
    state: &AdminState,
    pending_token_hash: &str,
) -> Result<(AdminSession, String), AdminError> {
    let ttl = Duration::from_secs(state.config.admin.session_ttl_seconds);
    let minted = mint_token();
    let csrf_token = mint_csrf_token();

    let Some(session) = AdminSession::promote(
        pending_token_hash,
        &minted.token_hash,
        &csrf_token,
        ttl,
        &state.database,
    )
    .await?
    else {
        // Lost the race to a concurrent submission, or the row expired between
        // the extractor and here. Either way there is nothing to promote.
        return Err(AdminError::session_invalid());
    };

    Ok((session, session_cookie(&minted.token, ttl)))
}

/// [`finish_mfa`]'s twin for the other way a login completes: setting a factor
/// up rather than proving one.
///
/// Under `admin.require_mfa` an operator with no factor lands on the enrolment
/// page and their session stays `pending_mfa` until they confirm a code. That
/// confirmation **is** a completed sign-in, and it owes the same three pieces of
/// bookkeeping the code path owes:
///
/// - `mark_logged_in`, so `last_login_at` means "completed a login";
/// - `record_success`, so the operator does not leave their own limiter bucket
///   dirty after signing in;
/// - `log_login(true, …)`, without which a first sign-in — the one that hands
///   out a first factor — produces no `admin_login_succeeded` event at all.
///
/// It exists as a shared function for the reason [`finish_mfa`] does: the JSON
/// and HTML front ends each call it, and before it they had drifted, the API
/// side doing none of the three and the pages side one of them.
pub(crate) async fn finish_enrolment(
    state: &AdminState,
    client: Option<std::net::IpAddr>,
    user: &mut crate::sqlite::admin_user::AdminUser,
    pending_token_hash: &str,
) -> Result<(AdminSession, String), AdminError> {
    let (session, cookie) = promote_pending(state, pending_token_hash).await?;
    user.mark_logged_in(&state.database).await?;
    state.logins.record_success(client);
    info!(event = "admin_mfa_enrolled", outcome = "success", username = %user.username);
    log_login(true, &user.username, client, "");
    Ok((session, cookie))
}

/// `POST /api/session` — exchange a username and password for a session cookie.
///
/// The one route that is reachable without a session, so it carries its own
/// protections: the origin gate (there is no CSRF token yet to check) and the
/// rate limiter, which runs **before** the password hash so a flood does not
/// cost 600 000 iterations per attempt. Both live in [`sign_in`], which the
/// sign-in *page* calls too.
pub async fn post_session(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, AdminError> {
    let signed_in = sign_in(&state, client, &headers, &body).await?;
    Ok(signed_in_response(&signed_in))
}

/// `GET /api/session/mfa` — what this half-authenticated cookie still owes.
///
/// Unreachable with an `active` session, and with none at all: `PendingMfa` is
/// `Authenticated`'s exact mirror image.
pub async fn get_session_mfa(pending: PendingMfa) -> Json<serde_json::Value> {
    Json(json!({
        "step": pending.step.as_str(),
        "expiresAt": crate::sqlite::order::rfc3339(pending.session.expires_at),
    }))
}

/// `POST /api/session/mfa` — finish a login with a code.
///
/// Takes the submission whichever it is: the TOTP code is tried first and the
/// recovery codes after, because one is an HMAC and the other is up to ten
/// PBKDF2 runs.
///
/// Deliberately **not** CSRF-checked — see [`PendingMfaSubmit`], whose extractor
/// runs the origin gate in its place.
pub async fn post_session_mfa(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    PendingMfaSubmit(pending): PendingMfaSubmit,
    Json(body): Json<MfaRequest>,
) -> Result<Response, AdminError> {
    let signed_in = finish_mfa(&state, client, pending, &body.code).await?;
    Ok(signed_in_response(&signed_in))
}

/// The `200` both login steps answer with.
///
/// A pending answer carries **no `user` member**: a half-authenticated session
/// must not read operator metadata. It is not a `401` either -- the password
/// *was* right, and a script has to be able to tell those two apart.
fn signed_in_response(signed_in: &SignedIn) -> Response {
    let body = match signed_in.pending {
        None => session_body(&signed_in.user, &signed_in.session),
        Some(step) => json!({
            "mfaRequired": true,
            "step": step.as_str(),
            "csrfToken": signed_in.session.csrf_token,
            "expiresAt": crate::sqlite::order::rfc3339(signed_in.session.expires_at),
        }),
    };

    (
        StatusCode::OK,
        [(header::SET_COOKIE, signed_in.cookie.clone())],
        Json(body),
    )
        .into_response()
}

/// `GET /api/session` — who am I, and what is my CSRF token.
///
/// The CSRF token is returned here as well as at login so a page reloaded on a
/// still-live cookie can pick it up without signing in again.
pub async fn get_session(auth: Authenticated) -> Json<serde_json::Value> {
    Json(session_body(&auth.user, &auth.session))
}

/// `DELETE /api/session[?all=true]` — sign out.
pub async fn delete_session(
    State(state): State<AdminState>,
    Query(query): Query<LogoutQuery>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<Response, AdminError> {
    let scope = if query.all {
        AdminSession::delete_for_user(auth.user.id, &state.database).await?;
        "all"
    } else {
        AdminSession::delete(&auth.session.token_hash, &state.database).await?;
        "one"
    };

    tracing::info!(event = "admin_logout", outcome = "success", surface = "api", username = %auth.user.username, scope = scope);
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clearing_cookie())],
    )
        .into_response())
}

/// The body both `POST` and `GET /api/session` return.
fn session_body(user: &AdminUser, session: &AdminSession) -> serde_json::Value {
    json!({
        "user": crate::admin::render_admin_user_json(user),
        "csrfToken": session.csrf_token,
        "expiresAt": crate::sqlite::order::rfc3339(session.expires_at),
    })
}
