//! `/ui/operators` — every operator this process has, and acting on one
//! *other* than the caller.
//!
//! [`crate::webadmin::handlers::operators`]'s page twin, the `handlers`/`pages`
//! split every other resource in this tree follows: both call the same
//! `src/admin/` operations, this one renders HTML. Managing *yourself* stays on
//! `/ui/account`, which is why `GET /ui/operators/{username}` redirects there
//! the moment `username` resolves to the caller rather than rendering a
//! half-disabled copy of this page's own template.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::admin::{mfa, users};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::mfa::verify_current_password;
use crate::webadmin::handlers::operators::{
    OperatorAction, apply_operator_action, find, refuse_self_target,
};
use crate::webadmin::handlers::paging::{Page, PageParams};
use crate::webadmin::pages::auth::{PageAdminRead, PageAdminWrite};
use crate::webadmin::pages::error::{PageError, redirect};
use crate::webadmin::pages::{chrome, flash, page_value, pager, respond, respond_fragment};
use crate::webadmin::session::AdminClientIp;

/// The `/ui` twin of [`crate::webadmin::handlers::mfa::StepUpRequest`] — the
/// password a form field collects, pulled in by `hx-include`, the
/// `account::StepUpForm` precedent.
#[derive(Debug, Default, Deserialize)]
pub struct StepUpForm {
    #[serde(default)]
    pub password: String,
}

/// `GET /ui/operators?limit=&offset=`
pub async fn list_operators(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    session: PageAdminRead,
) -> Result<Html<String>, PageError> {
    let page = params.resolve(&state.config);
    let (operators, total) = rows(page, &state).await?;

    let mut context = chrome(&session, "operators", "Operators");
    context.insert("page".to_string(), page_value(operators, total));
    context.insert(
        "pager".to_string(),
        pager(page, total, "/ui/operators", &[], "#operators-table"),
    );

    respond(
        &state,
        session.hx,
        "operators/list.html",
        "operators/_table.html",
        context,
    )
}

/// `GET /ui/operators/{username}` — redirects to `/ui/account` when `username`
/// is the caller.
pub async fn get_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    session: PageAdminRead,
) -> Result<Response, PageError> {
    let target = find(&username, &state).await?;
    if target.id == session.auth.user.id {
        return Ok(redirect("/ui/account", session.hx));
    }

    let mut context = chrome(&session, "operators", "Operator");
    for (key, value) in detail_context(&state, &target).await? {
        context.insert(key, value);
    }

    Ok(respond(
        &state,
        session.hx,
        "operators/detail.html",
        "operators/_card.html",
        context,
    )?
    .into_response())
}
/// `POST /ui/operators/{username}/disable`
pub async fn disable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    session: PageAdminWrite,
    request_context: crate::audit::RequestContext,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    act(
        &state,
        &session,
        &username,
        &body.password,
        client,
        &headers,
        &request_context,
        OperatorAction::SetStatus { active: false },
        flash("ok", "Operator disabled. Their sessions were revoked."),
    )
    .await
}

/// `POST /ui/operators/{username}/enable`
pub async fn enable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    session: PageAdminWrite,
    request_context: crate::audit::RequestContext,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    act(
        &state,
        &session,
        &username,
        &body.password,
        client,
        &headers,
        &request_context,
        OperatorAction::SetStatus { active: true },
        flash("ok", "Operator enabled."),
    )
    .await
}

/// `POST /ui/operators/{username}/totp/reset`
pub async fn reset_operator_totp(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    session: PageAdminWrite,
    request_context: crate::audit::RequestContext,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    act(
        &state,
        &session,
        &username,
        &body.password,
        client,
        &headers,
        &request_context,
        OperatorAction::ResetTotp,
        flash(
            "warn",
            "Their second factor and recovery codes were removed. They can \
             sign in with a password alone until they enrol again.",
        ),
    )
    .await
}

/// `POST /ui/operators/{username}/sessions/{id}/revoke`
pub async fn revoke_operator_session(
    State(state): State<AdminState>,
    Path((username, id)): Path<(String, String)>,
    AdminClientIp(client): AdminClientIp,
    headers: HeaderMap,
    session: PageAdminWrite,
    request_context: crate::audit::RequestContext,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    act(
        &state,
        &session,
        &username,
        &body.password,
        client,
        &headers,
        &request_context,
        OperatorAction::RevokeSession { fingerprint: &id },
        flash("ok", "Session revoked."),
    )
    .await
}

/// The `/ui` spelling of the shared sequence — the twin of
/// [`crate::webadmin::handlers::operators`]'s own `act`.
///
/// Identical up to two things, which is the whole of what separates the two
/// front ends here: the password refusal is rendered as the operator card's own
/// banner rather than returned as an error document, and success re-renders
/// that card instead of answering `204`.
#[allow(clippy::too_many_arguments)]
async fn act(
    state: &AdminState,
    session: &PageAdminWrite,
    username: &str,
    password: &str,
    client: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    request_context: &crate::audit::RequestContext,
    action: OperatorAction<'_>,
    banner: Value,
) -> Result<Response, PageError> {
    let mut target = find(username, state).await?;
    refuse_self_target(&session.auth.user, &target)?;
    if let Some(refusal) =
        refuse_without_password(state, session, &target, password, client).await?
    {
        return Ok(refusal);
    }

    apply_operator_action(
        state,
        &session.auth.user,
        &mut target,
        action,
        client,
        headers,
        request_context,
        "ui",
    )
    .await?;

    respond_card(state, &target, banner).await
}

/// [`verify_current_password`] with the refusal rendered as the operator card's
/// own banner — the `account::refuse_without_password` shape: the session is
/// live and the page is the right page, only this one action was refused.
///
/// `verify_current_password`, not `check_step_up`: see
/// [`crate::webadmin::handlers::operators`]'s module doc for why this surface
/// asks even of a caller who has enrolled no second factor.
async fn refuse_without_password(
    state: &AdminState,
    session: &PageAdminWrite,
    target: &AdminUser,
    password: &str,
    client: Option<std::net::IpAddr>,
) -> Result<Option<Response>, PageError> {
    let Err(error) = verify_current_password(&session.auth.user, password, client, &state.logins)
    else {
        return Ok(None);
    };
    let context = detail_context(state, target).await?;
    Ok(Some(super::refuse_with_card(
        state,
        "operators/_card.html",
        context,
        &error,
    )?))
}

/// Re-renders the operator card after a successful mutation.
///
/// Renders from the `target` [`apply_operator_action`] updated in place rather
/// than re-reading the row: the two would agree, and the extra read is a second
/// answer waiting to disagree. The sessions table inside it *is* re-read, since
/// a disable or a revoke is exactly what changed it.
async fn respond_card(
    state: &AdminState,
    target: &AdminUser,
    banner: Value,
) -> Result<Response, PageError> {
    let mut context = detail_context(state, target).await?;
    context.insert("flash".to_string(), banner);
    Ok(respond_fragment(state, "operators/_card.html", context)?.into_response())
}

async fn rows(page: Page, state: &AdminState) -> Result<(Vec<Value>, i64), PageError> {
    let (operators, total) =
        users::list_users(page.limit, page.offset, state.database.clone()).await?;
    Ok((
        operators
            .iter()
            .map(admin::render_admin_user_json)
            .collect(),
        total,
    ))
}

/// Everything `operators/_card.html` reads, minus `csrf_token` and `flash` --
/// both are per-call (the token because a fragment rendered standalone cannot
/// inherit `<body>`'s `hx-headers`, the banner because it differs by action).
async fn detail_context(
    state: &AdminState,
    target: &AdminUser,
) -> Result<Map<String, Value>, PageError> {
    let remaining = mfa::recovery_codes_remaining(target.id, state.database.clone()).await?;
    let mut context = Map::new();
    context.insert(
        "operator".to_string(),
        admin::render_admin_user_detail_json(target, remaining),
    );
    context.insert(
        "sessions".to_string(),
        Value::Array(operator_sessions(state, target.id).await?),
    );
    context.insert(
        "sessions_revoke_prefix".to_string(),
        Value::String(format!("/ui/operators/{}/sessions", target.username)),
    );
    context.insert(
        "sessions_target".to_string(),
        Value::String("#operator-detail".to_string()),
    );
    // Present, unlike the account page's own sessions card: every mutation on
    // this surface -- including revoking one of *another* operator's sessions
    // -- re-proves the caller's own password. `#operator-step-up-password` is
    // the field `operators/_card.html` renders once, shared by every button.
    context.insert(
        "sessions_step_up".to_string(),
        Value::String("#operator-step-up-password".to_string()),
    );
    Ok(context)
}

/// One operator's live sessions, newest first, unmarked -- see
/// [`crate::webadmin::handlers::operators::list_operator_sessions`] for why
/// there is no `current` member here.
async fn operator_sessions(
    state: &AdminState,
    user_id: uuid::Uuid,
) -> Result<Vec<Value>, PageError> {
    let page = PageParams::default().resolve(&state.config);
    let (sessions, _total) =
        AdminSession::search(Some(user_id), page.limit, page.offset, &state.database).await?;
    Ok(sessions
        .iter()
        .map(admin::render_admin_session_json)
        .collect())
}
