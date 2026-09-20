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
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::Caller;
use crate::webadmin::handlers::mfa::verify_current_password;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::{AdminClientIp, Authenticated, SelfServiceWrite, clearing_cookie};
use acme_proxy_store::admin_session::AdminSession;

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// The body of `POST /api/account/contact`. An absent, `null` or blank
/// `contact` clears the address.
#[derive(Debug, Default, Deserialize)]
pub struct ChangeContactRequest {
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub contact: Option<String>,
}

/// `POST /api/account/contact` — set or clear the address this operator's own
/// security notifications go to.
///
/// The address is not a credential and no session is revoked, but the current
/// password is still re-proved ([`verify_current_password`]): it is where the
/// alarms go, so a stolen cookie that could change it silently would switch off
/// the one signal that the cookie was stolen. For the same reason the address
/// it replaces is told
/// ([`acme_proxy_jobs::notify::AdminCredentialChange::ContactAddress`]).
pub async fn change_contact(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    headers: axum::http::HeaderMap,
    SelfServiceWrite(auth): SelfServiceWrite,
    request_context: acme_proxy_core::audit::RequestContext,
    body: Option<Json<ChangeContactRequest>>,
) -> Result<Response, AdminError> {
    let body = body.unwrap_or_default();
    let caller = auth.user;
    verify_current_password(&caller, &body.current_password, client, &state.logins)?;

    let mut target = caller.clone();
    super::operators::apply_contact_change(
        &state,
        &caller,
        &mut target,
        body.contact.as_deref(),
        client,
        &headers,
        &request_context,
        "api",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
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
    headers: axum::http::HeaderMap,
    SelfServiceWrite(auth): SelfServiceWrite,
    request_context: acme_proxy_core::audit::RequestContext,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, AdminError> {
    let mut user = auth.user;
    change_own_password_for(
        &state,
        &request_context,
        &mut user,
        &body.current_password,
        &body.new_password,
        &auth.session.token_hash,
        client,
        crate::webadmin::user_agent_of(&headers).as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The password change itself, the one function both front ends call: the
/// current password, the policy, the write that revokes this operator's other
/// sessions, and the notification and audit row that follow it.
///
/// What stays with each front end is the rendering — a `204`, or the password
/// card with a banner. A refusal is an [`AdminError`] either way, so the policy
/// message a script reads and the one a browser shows are the same sentence.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn change_own_password_for(
    state: &AdminState,
    request: &acme_proxy_core::audit::RequestContext,
    user: &mut acme_proxy_store::admin_user::AdminUser,
    current_password: &str,
    new_password: &str,
    keep: &str,
    client: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<(), AdminError> {
    verify_current_password(user, current_password, client, &state.logins)?;

    let context = PasswordContext::from_config(&state.config, &user.username);
    users::change_own_password(user, new_password, &context, keep, state.database.clone())
        .await
        .map_err(|error| match error {
            // `change_own_password` never builds `InvalidContact`; it is here
            // because the shared `UserError` carries it, and a 400 is what it
            // would mean.
            UserError::Policy(message) | UserError::InvalidContact(message) => {
                AdminError::bad_request(message)
            }
            UserError::Database(_) | UserError::DuplicateUsername(_) => AdminError::internal(),
        })?;

    state
        .record_credential_change(
            request,
            &user.username,
            user,
            acme_proxy_jobs::notify::AdminCredentialChange::Password,
            true,
            client,
            user_agent.map(str::to_string),
        )
        .await;
    Ok(())
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
    SelfServiceWrite(auth): SelfServiceWrite,
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Response, AdminError> {
    let was_current =
        apply_revoke_own_session(&state, &Caller::api(&auth, &request_context), &id).await?;

    if was_current {
        return Ok((
            StatusCode::NO_CONTENT,
            [(axum::http::header::SET_COOKIE, clearing_cookie())],
        )
            .into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Ends one of the caller's own sessions, found by fingerprint **within the
/// caller's own `user_id`**, so a foreign id is `404` exactly like one that
/// never existed. Answers whether it was the session making this request,
/// which the front end then signs out of.
pub(crate) async fn apply_revoke_own_session(
    state: &AdminState,
    caller: &Caller<'_>,
    id: &str,
) -> Result<bool, AdminError> {
    let session =
        AdminSession::find_by_user_and_fingerprint(caller.auth.user.id, id, &state.database)
            .await?
            .ok_or_else(|| session_not_found(id))?;
    let was_current = session.token_hash == caller.auth.session.token_hash;
    AdminSession::delete(&session.token_hash, &state.database).await?;

    let scope = if was_current {
        acme_proxy_jobs::auditor::admin::SessionScope::OwnCurrent
    } else {
        acme_proxy_jobs::auditor::admin::SessionScope::OwnOther
    };
    state
        .record_admin_action(caller.request, caller.username(), |actor, ctx| {
            acme_proxy_jobs::auditor::admin::session_revoked(actor, ctx, scope, 1)
        })
        .await;
    tracing::info!(event = "admin_session_revoked",
                   outcome = "success",
                   surface = caller.surface,
                   scope = "self",
                   username = %caller.username(),
                   session_fp = %id);
    Ok(was_current)
}

fn session_not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such session: {id}"))
}
