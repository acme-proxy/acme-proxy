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
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::admin::{mfa, users};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::mfa::check_step_up;
use crate::webadmin::handlers::operators::{find, refuse_self_target};
use crate::webadmin::handlers::paging::{Page, PageParams};
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
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
    session: PageSession,
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
    session: PageSession,
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
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&session.auth.user, &target)?;
    if let Some(refusal) =
        refuse_without_step_up(&state, &session, &target, &body.password, client).await?
    {
        return Ok(refusal);
    }

    users::set_status(&target.username, "disabled", state.database.clone()).await?;
    tracing::info!(event = "admin_operator_disabled",
                   outcome = "success",
                   surface = "ui",
                   username = %session.auth.user.username,
                   target_username = %target.username);

    respond_card(
        &state,
        &session,
        &target,
        flash("ok", "Operator disabled. Their sessions were revoked."),
    )
    .await
}

/// `POST /ui/operators/{username}/enable`
pub async fn enable_operator(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&session.auth.user, &target)?;
    if let Some(refusal) =
        refuse_without_step_up(&state, &session, &target, &body.password, client).await?
    {
        return Ok(refusal);
    }

    users::set_status(&target.username, "active", state.database.clone()).await?;
    tracing::info!(event = "admin_operator_enabled",
                   outcome = "success",
                   surface = "ui",
                   username = %session.auth.user.username,
                   target_username = %target.username);

    respond_card(&state, &session, &target, flash("ok", "Operator enabled.")).await
}

/// `POST /ui/operators/{username}/totp/reset`
pub async fn reset_operator_totp(
    State(state): State<AdminState>,
    Path(username): Path<String>,
    AdminClientIp(client): AdminClientIp,
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let mut target = find(&username, &state).await?;
    refuse_self_target(&session.auth.user, &target)?;
    if let Some(refusal) =
        refuse_without_step_up(&state, &session, &target, &body.password, client).await?
    {
        return Ok(refusal);
    }

    // `None`: this is being done to a *different* operator's factor, from a
    // session that is not theirs.
    mfa::disable_totp(&mut target, None, state.database.clone()).await?;
    tracing::info!(event = "admin_operator_totp_reset",
                   outcome = "success",
                   surface = "ui",
                   username = %session.auth.user.username,
                   target_username = %target.username);

    respond_card(
        &state,
        &session,
        &target,
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
    session: PageSessionWrite,
    axum::Form(body): axum::Form<StepUpForm>,
) -> Result<Response, PageError> {
    let target = find(&username, &state).await?;
    refuse_self_target(&session.auth.user, &target)?;
    if let Some(refusal) =
        refuse_without_step_up(&state, &session, &target, &body.password, client).await?
    {
        return Ok(refusal);
    }

    let found = AdminSession::find_by_user_and_fingerprint(target.id, &id, &state.database)
        .await?
        .ok_or_else(|| session_not_found(&id))?;
    AdminSession::delete(&found.token_hash, &state.database).await?;

    tracing::info!(event = "admin_operator_session_revoked",
                   outcome = "success",
                   surface = "ui",
                   username = %session.auth.user.username,
                   target_username = %target.username,
                   session_fp = %id);

    respond_card(&state, &session, &target, flash("ok", "Session revoked.")).await
}

/// [`check_step_up`] with the refusal rendered as the operator card's own
/// banner — the `account::refuse_without_password` shape: the session is
/// live and the page is the right page, only this one action was refused.
async fn refuse_without_step_up(
    state: &AdminState,
    session: &PageSessionWrite,
    target: &AdminUser,
    password: &str,
    client: Option<std::net::IpAddr>,
) -> Result<Option<Response>, PageError> {
    let Err(error) = check_step_up(&session.auth.user, password, client, &state.logins) else {
        return Ok(None);
    };
    let message = if error.status == axum::http::StatusCode::UNAUTHORIZED {
        "That password is not correct.".to_string()
    } else {
        error.message.clone()
    };
    let mut context = detail_context(state, target).await?;
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("flash".to_string(), super::flash_error(error.code, message));
    Ok(Some(
        (
            error.status,
            respond_fragment(state, "operators/_card.html", context)?,
        )
            .into_response(),
    ))
}

async fn respond_card(
    state: &AdminState,
    session: &PageSessionWrite,
    target: &AdminUser,
    banner: Value,
) -> Result<Response, PageError> {
    // The row may have just changed under `target.username` (disable/enable
    // do not rename it, but re-reading keeps this honest if that ever
    // changes) -- reload rather than trust the caller's copy.
    let reloaded = find(&target.username, state).await?;
    let mut context = detail_context(state, &reloaded).await?;
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("flash".to_string(), banner);
    Ok(respond_fragment(state, "operators/_card.html", context)?.into_response())
}

fn session_not_found(id: &str) -> PageError {
    PageError::not_found(format!("no such session: {id}"))
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
