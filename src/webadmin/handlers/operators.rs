//! `/api/operators` — every operator this process has, and acting on one
//! *other* than the caller: disable, enable, reset their second factor, list
//! and revoke their sessions.
//!
//! Distinct from `/api/account` (`handlers::account`), which is the same
//! operator managing themselves. That split is the trust boundary this module
//! exists to enforce: every mutating route here runs
//! [`crate::webadmin::handlers::mfa::check_step_up`], and every one refuses a
//! `username` that resolves to the caller — self-management stays on
//! `/api/account`, which already owns it, and never needs a password re-typed
//! to reach it.
//!
//! `create`/`passwd` are deliberately absent, on both this surface and the
//! page it backs: those mint a credential, which is where "no sign-up page"
//! already draws the line — see `acme-proxy admin user create`/`passwd` on the
//! host.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::admin;
use crate::admin::{mfa, users};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::mfa::{StepUpRequest, check_step_up};
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::{AdminClientIp, Authenticated, AuthenticatedWrite};

/// `GET /api/operators?limit=&offset=` — every operator, oldest first.
///
/// The same [`AdminUser::search`] `admin user list` reads, so the panel and the
/// terminal cannot come to describe the operator set differently.
pub async fn list_operators(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = params.resolve(&state.config);
    let (operators, total) = users::list_users(page.limit, page.offset, state.database).await?;
    let items: Vec<Value> = operators
        .iter()
        .map(admin::render_admin_user_json)
        .collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/operators/{username}` — one operator's detail, `admin user
/// show`'s shape.
pub async fn get_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let user = find(&username, &state).await?;
    let remaining = mfa::recovery_codes_remaining(user.id, state.database.clone()).await?;
    Ok(Json(admin::render_admin_user_detail_json(&user, remaining)))
}

/// `GET /api/operators/{username}/sessions?limit=&offset=` — one operator's
/// live sessions, `admin session list --username`'s shape. No `current`
/// marker: the caller viewing another operator's sessions has none of their
/// own in this list, unlike `GET /api/account/sessions`.
pub async fn list_operator_sessions(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    Query(params): Query<PageParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let user = find(&username, &state).await?;
    let page = params.resolve(&state.config);
    let (sessions, total) =
        AdminSession::search(Some(user.id), page.limit, page.offset, &state.database).await?;
    let items: Vec<Value> = sessions
        .iter()
        .map(admin::render_admin_session_json)
        .collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `POST /api/operators/{username}/disable`
pub async fn disable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&auth.user, &target)?;
    check_step_up(
        &auth.user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;

    users::set_status(&target.username, "disabled", state.database.clone()).await?;
    tracing::info!(event = "admin_operator_disabled",
                   outcome = "success",
                   surface = "api",
                   username = %auth.user.username,
                   target_username = %target.username);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/enable`
pub async fn enable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&auth.user, &target)?;
    check_step_up(
        &auth.user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;

    users::set_status(&target.username, "active", state.database.clone()).await?;
    tracing::info!(event = "admin_operator_enabled",
                   outcome = "success",
                   surface = "api",
                   username = %auth.user.username,
                   target_username = %target.username);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/totp/reset` — the web twin of
/// `acme-proxy admin user totp reset`: removes the factor, every recovery
/// code, and every session the operator holds.
pub async fn reset_operator_totp(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let mut target = find(&username, &state).await?;
    refuse_self_target(&auth.user, &target)?;
    check_step_up(
        &auth.user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;

    // `None`: this is being done to a *different* operator's factor, from a
    // session that is not theirs, so there is no session of the target's to
    // keep — the same `acme-proxy admin user totp reset` call makes.
    mfa::disable_totp(&mut target, None, state.database.clone()).await?;
    tracing::info!(event = "admin_operator_totp_reset",
                   outcome = "success",
                   surface = "api",
                   username = %auth.user.username,
                   target_username = %target.username);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/sessions/{id}/revoke`
pub async fn revoke_operator_session(
    State(state): State<AdminState>,
    Path((username, id)): Path<(String, String)>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&auth.user, &target)?;
    check_step_up(
        &auth.user,
        &body.unwrap_or_default().password,
        client,
        &state.logins,
    )?;

    let session = AdminSession::find_by_user_and_fingerprint(target.id, &id, &state.database)
        .await?
        .ok_or_else(|| session_not_found(&id))?;
    AdminSession::delete(&session.token_hash, &state.database).await?;

    tracing::info!(event = "admin_operator_session_revoked",
                   outcome = "success",
                   surface = "api",
                   username = %auth.user.username,
                   target_username = %target.username,
                   session_fp = %id);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Refuses a route on this surface when its target is the caller.
///
/// Checked before [`check_step_up`] runs, so a self-target is refused without
/// making the caller type their password to be told no — every one of these
/// actions already has a self-service home on `/api/account` or `/ui/account`.
pub(crate) fn refuse_self_target(caller: &AdminUser, target: &AdminUser) -> Result<(), AdminError> {
    if caller.id == target.id {
        return Err(AdminError::bad_request(
            "manage your own account from /ui/account, not the operators surface",
        ));
    }
    Ok(())
}

pub(crate) async fn find(username: &str, state: &AdminState) -> Result<AdminUser, AdminError> {
    AdminUser::find_by_username(username, &state.database)
        .await?
        .ok_or_else(|| operator_not_found(username))
}

fn operator_not_found(username: &str) -> AdminError {
    AdminError::not_found(format!("no such operator: {username}"))
}

fn session_not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such session: {id}"))
}
