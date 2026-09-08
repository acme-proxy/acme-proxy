//! `/api/operators` — every operator this process has, and acting on one
//! *other* than the caller: disable, enable, reset their second factor, list
//! and revoke their sessions.
//!
//! Distinct from `/api/account` (`handlers::account`), which is the same
//! operator managing themselves. That split is the trust boundary this module
//! exists to enforce: every mutating route here runs
//! [`crate::webadmin::handlers::mfa::verify_current_password`], and every one
//! refuses a `username` that resolves to the caller — self-management stays on
//! `/api/account`, which already owns it, and never needs a password re-typed
//! to reach it.
//!
//! **`verify_current_password`, not `check_step_up`.** The latter passes
//! unconditionally for an operator with no second factor, which is right where
//! it was written — a first enrolment protects nothing, and a password there
//! would stand in front of the `require_mfa` bootstrap. It is wrong here: this
//! surface's blast radius is a *colleague's* account, which exists whether or
//! not the caller has enrolled, so a password-only admin holding a stolen
//! cookie could otherwise disable every other admin and wipe their factors
//! without typing anything. `handlers::account::change_password` already made
//! exactly this choice for its own ASVS V6.2.3 reason.
//!
//! The tail of every mutation — the write, the audit row, the log line and the
//! notification — is [`apply_operator_action`], shared with the `/ui` twin
//! (`crate::webadmin::pages::operators`). Only the extractors, the `surface`
//! field and the response shape differ between the two, and writing that tail
//! out twice is what let `/ui` drift away from `/api` before.
//!
//! `create`/`passwd` are deliberately absent, on both this surface and the
//! page it backs: those mint a credential, which is where "no sign-up page"
//! already draws the line — see `acme-proxy admin user create`/`passwd` on the
//! host.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::admin;
use crate::admin::{mfa, users};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::{AdminStatus, AdminUser};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::mfa::{StepUpRequest, verify_current_password};
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::{AdminClientIp, AdminRead, AdminWrite};

/// `GET /api/operators?limit=&offset=` — every operator, oldest first.
///
/// The same [`AdminUser::search`] `admin user list` reads, so the panel and the
/// terminal cannot come to describe the operator set differently.
pub async fn list_operators(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    _auth: AdminRead,
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
    _auth: AdminRead,
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
    _auth: AdminRead,
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
    headers: HeaderMap,
    AdminWrite(auth): AdminWrite,
    request_context: crate::audit::RequestContext,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    act(
        &state,
        &auth.user,
        &username,
        &body.unwrap_or_default().password,
        client,
        &headers,
        &request_context,
        OperatorAction::SetStatus { active: false },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/enable`
pub async fn enable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    AdminWrite(auth): AdminWrite,
    request_context: crate::audit::RequestContext,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    act(
        &state,
        &auth.user,
        &username,
        &body.unwrap_or_default().password,
        client,
        &headers,
        &request_context,
        OperatorAction::SetStatus { active: true },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/totp/reset` — the web twin of
/// `acme-proxy admin user totp reset`: removes the factor, every recovery
/// code, and every session the operator holds.
pub async fn reset_operator_totp(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    AdminWrite(auth): AdminWrite,
    request_context: crate::audit::RequestContext,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    act(
        &state,
        &auth.user,
        &username,
        &body.unwrap_or_default().password,
        client,
        &headers,
        &request_context,
        OperatorAction::ResetTotp,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/operators/{username}/sessions/{id}/revoke`
pub async fn revoke_operator_session(
    State(state): State<AdminState>,
    Path((username, id)): Path<(String, String)>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    AdminWrite(auth): AdminWrite,
    request_context: crate::audit::RequestContext,
    body: Option<Json<StepUpRequest>>,
) -> Result<Response, AdminError> {
    act(
        &state,
        &auth.user,
        &username,
        &body.unwrap_or_default().password,
        client,
        &headers,
        &request_context,
        OperatorAction::RevokeSession { fingerprint: &id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The `/api` spelling of the shared sequence: resolve the target, refuse a
/// self-target, re-prove the caller's own password, then
/// [`apply_operator_action`].
///
/// The `/ui` twin runs the same four steps but renders the password refusal as
/// the operator card's own banner, so it calls the pieces itself rather than
/// this wrapper.
#[allow(clippy::too_many_arguments)]
async fn act(
    state: &AdminState,
    caller: &AdminUser,
    username: &str,
    password: &str,
    client: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    request_context: &crate::audit::RequestContext,
    action: OperatorAction<'_>,
) -> Result<(), AdminError> {
    let mut target = find(username, state).await?;
    refuse_self_target(caller, &target)?;
    verify_current_password(caller, password, client, &state.logins)?;
    apply_operator_action(
        state,
        caller,
        &mut target,
        action,
        client,
        headers,
        request_context,
        "api",
    )
    .await
}

/// One colleague-management action, named once so the two front ends cannot
/// come to disagree about what each of them does.
#[derive(Debug)]
pub(crate) enum OperatorAction<'a> {
    /// Disable (`active: false`) or re-enable the operator. Disabling revokes
    /// every session they hold, inside `users::set_status`.
    SetStatus { active: bool },
    /// Remove their second factor, every recovery code, and every session.
    ResetTotp,
    /// End one of their sessions, named by the fingerprint the listing prints.
    RevokeSession { fingerprint: &'a str },
}

/// Performs `action` and everything that owes: the write, the audit row(s), the
/// log line, and — where a credential of the operator's changed — the
/// notification to them.
///
/// Shared by `/api` and `/ui` so a row or a notification cannot be written on
/// one surface and forgotten on the other, which is what happened while each
/// spelled this tail out for itself. The caller has already resolved `target`,
/// refused a self-target and re-proved its own password; `surface` is the only
/// thing it contributes here.
///
/// `target` is updated in place, so the page front end re-renders its card from
/// it rather than reading the row back.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_operator_action(
    state: &AdminState,
    caller: &AdminUser,
    target: &mut AdminUser,
    action: OperatorAction<'_>,
    client: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    request_context: &crate::audit::RequestContext,
    surface: &'static str,
) -> Result<(), AdminError> {
    match action {
        OperatorAction::SetStatus { active } => {
            let status = if active {
                AdminStatus::Active
            } else {
                AdminStatus::Disabled
            };
            // The `Option` is the raced-delete answer: the row was found a
            // moment ago and is gone now, so this reports "no such operator"
            // rather than a `204` with no write behind it.
            let (updated, revoked) =
                users::set_status(&target.username, status, state.database.clone())
                    .await?
                    .ok_or_else(|| operator_not_found(&target.username))?;
            *target = updated;
            state
                .record_admin_action(request_context, &caller.username, |actor, ctx| {
                    crate::audit::admin::operator_status_changed(
                        actor,
                        ctx,
                        &target.username,
                        active,
                    )
                })
                .await;
            // Disabling drops every session the operator held. That is a
            // second thing that happened, so it is a second row: the status
            // change alone does not say how much access was withdrawn.
            if revoked > 0 {
                state
                    .record_admin_action(request_context, &caller.username, |actor, ctx| {
                        crate::audit::admin::session_revoked(
                            actor,
                            ctx,
                            crate::audit::admin::SessionScope::AllOf(target.username.clone()),
                            revoked,
                        )
                    })
                    .await;
            }
            if active {
                tracing::info!(event = "admin_operator_enabled",
                               outcome = "success",
                               surface = surface,
                               username = %caller.username,
                               target_username = %target.username);
            } else {
                tracing::info!(event = "admin_operator_disabled",
                               outcome = "success",
                               surface = surface,
                               username = %caller.username,
                               target_username = %target.username,
                               sessions_revoked = revoked);
            }
        }
        OperatorAction::ResetTotp => {
            // `None`: this is being done to a *different* operator's factor,
            // from a session that is not theirs, so there is no session of the
            // target's to keep — the same call `admin user totp reset` makes.
            mfa::disable_totp(target, None, state.database.clone()).await?;
            // The row and the message together: the operator whose factor was
            // reset should hear about it, the change having been made from a
            // session that is not theirs — hence `by_self = false`.
            state
                .record_credential_change(
                    request_context,
                    &caller.username,
                    target,
                    crate::notify::AdminCredentialChange::SecondFactorDisabled,
                    false,
                    client,
                    crate::webadmin::user_agent_of(headers),
                )
                .await;
            tracing::info!(event = "admin_operator_totp_reset",
                           outcome = "success",
                           surface = surface,
                           username = %caller.username,
                           target_username = %target.username);
        }
        OperatorAction::RevokeSession { fingerprint } => {
            let session =
                AdminSession::find_by_user_and_fingerprint(target.id, fingerprint, &state.database)
                    .await?
                    .ok_or_else(|| session_not_found(fingerprint))?;
            AdminSession::delete(&session.token_hash, &state.database).await?;
            state
                .record_admin_action(request_context, &caller.username, |actor, ctx| {
                    crate::audit::admin::session_revoked(
                        actor,
                        ctx,
                        crate::audit::admin::SessionScope::OneOf(target.username.clone()),
                        1,
                    )
                })
                .await;
            tracing::info!(event = "admin_operator_session_revoked",
                           outcome = "success",
                           surface = surface,
                           username = %caller.username,
                           target_username = %target.username,
                           session_fp = %fingerprint);
        }
    }
    Ok(())
}

/// Refuses a route on this surface when its target is the caller.
///
/// Checked before [`verify_current_password`] runs, so a self-target is refused
/// without making the caller type their password to be told no — every one of
/// these actions already has a self-service home on `/api/account` or
/// `/ui/account`.
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
