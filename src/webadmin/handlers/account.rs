//! `/api/account` — the operator's own account, distinct from `/api/mfa`'s
//! second factor: the password, and (see `sessions`) the caller's own live
//! sessions.
//!
//! No id on `/api/account/password` for the same reason `/api/mfa` has none:
//! there is exactly one account this session can be about. `/api/account/
//! sessions/{id}` is the one exception, and it is not really one — `{id}` names
//! *which session*, not which account; the account is still only ever "this
//! one", which is what keeps this module distinct from `/api/operators`
//! (`handlers::operators`), where `{username}` genuinely selects a target.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::admin::password::PasswordContext;
use crate::admin::users::{self, UserError};
use crate::sqlite::admin_session::AdminSession;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::mfa::verify_current_password;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::{AdminClientIp, Authenticated, AuthenticatedWrite, clearing_cookie};

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// `POST /api/account/password` — change this operator's own password.
///
/// ASVS V6.2.3: takes the *current* password and verifies it
/// ([`verify_current_password`]) before writing a new hash, unlike
/// `acme-proxy admin user passwd` on the host, which already runs as the
/// process trusted to rewrite the row. Every other session this operator
/// holds is revoked ([`users::change_own_password`]); the one making this
/// request survives, or the panel would sign its own operator out mid-edit.
pub async fn change_password(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, AdminError> {
    let mut user = auth.user;
    verify_current_password(&user, &body.current_password, client, &state.logins)?;

    let context = PasswordContext::from_config(&state.config, &user.username);
    users::change_own_password(
        &mut user,
        &body.new_password,
        &context,
        &auth.session.token_hash,
        state.database.clone(),
    )
    .await
    .map_err(|error| match error {
        UserError::Policy(message) => AdminError::bad_request(message),
        UserError::Database(_) | UserError::DuplicateUsername(_) => AdminError::internal(),
    })?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/account/sessions?limit=&offset=` — this operator's own live
/// sessions, newest first, over the same [`AdminSession::search`] `admin
/// session list` uses. The literal "nothing in between" the panel had: the
/// only other lever on this account was "sign out everywhere"
/// (`DELETE /api/session?all=true`).
///
/// [`admin::render_admin_session_detail_json`] marks whichever row is the
/// session making this request, so a caller can tell "sign out here" from
/// "revoke an old one" without comparing hashes itself.
pub async fn list_own_sessions(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = params.resolve(&state.config);
    let (sessions, total) =
        AdminSession::search(Some(auth.user.id), page.limit, page.offset, &state.database).await?;
    let items: Vec<Value> = sessions
        .iter()
        .map(|session| admin::render_admin_session_detail_json(session, &auth.session.token_hash))
        .collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `POST /api/account/sessions/{id}/revoke` — end one of this operator's own
/// sessions.
///
/// No [`crate::webadmin::handlers::mfa::check_step_up`] here: this is the same
/// trust level as `DELETE /api/session` (sign out here, or everywhere), not
/// the operators surface's "act on someone else's account". `id` is resolved
/// via [`AdminSession::find_by_user_and_fingerprint`] scoped to the caller's
/// own `user_id`, so this route can never reach another operator's session —
/// a wrong or foreign `id` is `404`, identically to one that never existed.
///
/// Revoking the session making *this* request is not a special case to guard
/// against — it is the one-session form of signing out, so it clears the
/// cookie exactly as `DELETE /api/session` (without `all`) does.
pub async fn revoke_own_session(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<Response, AdminError> {
    let session = AdminSession::find_by_user_and_fingerprint(auth.user.id, &id, &state.database)
        .await?
        .ok_or_else(|| session_not_found(&id))?;
    let was_current = session.token_hash == auth.session.token_hash;
    AdminSession::delete(&session.token_hash, &state.database).await?;

    tracing::info!(event = "admin_session_revoked",
                   outcome = "success",
                   surface = "api",
                   scope = "self",
                   username = %auth.user.username,
                   session_fp = %id);

    if was_current {
        return Ok((
            StatusCode::NO_CONTENT,
            [(axum::http::header::SET_COOKIE, clearing_cookie())],
        )
            .into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn session_not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such session: {id}"))
}
