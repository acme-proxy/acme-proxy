//! `/ui/accounts` — the account list, one account, and the three things an
//! operator can do to it.
//!
//! Every handler here is a few lines over an `admin::` operation and a
//! template. The query parameters are `handlers::accounts`' own types, reused
//! rather than redeclared: the two front ends must accept the same filters, or
//! a URL copied between them stops meaning the same thing.

use axum::extract::{Path, Query, State};
use axum::response::{Html, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::sqlite::account::Account;
use crate::sqlite::order::{Order, OrderQuery};
use crate::webadmin::AdminState;
use crate::webadmin::handlers::accounts::AccountListParams;
use crate::webadmin::handlers::orders::render_orders;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::{PageError, redirect};
use crate::webadmin::pages::{chrome, flash, page_value, pager, respond, respond_fragment};

/// The contact editor posts a textarea, not a JSON array.
#[derive(Debug, Deserialize)]
pub struct ContactForm {
    /// One URI per line. Blank lines are dropped, so clearing the box clears
    /// the contact list — which is the only way to express "no contact" in a
    /// textarea.
    pub contact: String,
}

/// `GET /ui/accounts?profile=&limit=&offset=`
pub async fn list_accounts(
    State(state): State<AdminState>,
    Query(params): Query<AccountListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let profile = params.profile.clone().unwrap_or_default();

    let (accounts, total) = Account::search(
        params.profile.as_deref(),
        page.limit,
        page.offset,
        &state.database,
    )
    .await?;

    let items: Vec<Value> = accounts
        .iter()
        .map(|account| admin::render_account_json(account, &state.config.server.base_url))
        .collect();

    let mut context = chrome(&session, "accounts", "Accounts");
    context.insert("page".to_string(), page_value(items, total));
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/accounts",
            &[("profile", &profile)],
            "#accounts-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({ "profile": profile }),
    );
    context.insert(
        "profiles".to_string(),
        Value::Array(crate::webadmin::handlers::misc::profile_rows(&state)),
    );

    respond(
        &state,
        session.hx,
        "accounts/list.html",
        "accounts/_table.html",
        context,
    )
}

/// `GET /ui/accounts/{id}`
///
/// The account and its orders in one response. A separate lazy fetch for the
/// orders would trade a spinner for the answer an operator is usually here to
/// get, which is often "none".
pub async fn get_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(params): Query<PageParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let account = load(&id, &state).await?;
    let page = params.resolve(&state.config);

    let (orders, total) = Order::search(
        &OrderQuery {
            account_id: Some(id.clone()),
            limit: page.limit,
            offset: page.offset,
            ..OrderQuery::default()
        },
        &state.database,
    )
    .await?;
    let items = render_orders(&orders, &state).await?;

    let mut context = chrome(&session, "accounts", "Account");
    context.insert("account".to_string(), account);
    context.insert("page".to_string(), page_value(items, total));
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            &format!("/ui/accounts/{id}"),
            &[],
            "#orders-table",
        ),
    );

    respond(
        &state,
        session.hx,
        "accounts/detail.html",
        "accounts/_card.html",
        context,
    )
}

/// `POST /ui/accounts/{id}/contact`
pub async fn post_account_contact(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    axum::Form(form): axum::Form<ContactForm>,
) -> Result<Html<String>, PageError> {
    let contact: Vec<String> = form
        .contact
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    // The same validator `newAccount` and `PATCH /api/accounts/{id}` call, so
    // three front doors cannot come to disagree on what a valid contact is.
    // The refusal is a banner rather than an error page: the operator is
    // looking at the box they need to correct.
    if let Some(rejection) = crate::handlers::helpers::contact_shape_error(&contact) {
        let account = load(&id, &state).await?;
        return card(
            &state,
            &session,
            account,
            super::flash_error("bad_request", rejection.detail),
        );
    }

    let account = admin::update_account_contact(&id, contact, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    tracing::info!(event = "admin_account_contact_updated",
                   outcome = "success",
                   account_id = %id,
                   username = %session.auth.user.username);

    let rendered = admin::render_account_json(&account, &state.config.server.base_url);
    card(&state, &session, rendered, flash("ok", "Contact updated."))
}

/// `POST /ui/accounts/{id}/deactivate`
pub async fn deactivate_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
) -> Result<Html<String>, PageError> {
    let account = admin::deactivate_account(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    tracing::info!(event = "admin_account_deactivated",
                   outcome = "success",
                   account_id = %id,
                   username = %session.auth.user.username);

    let rendered = admin::render_account_json(&account, &state.config.server.base_url);
    card(
        &state,
        &session,
        rendered,
        flash(
            "ok",
            "Account deactivated. It can no longer request issuance.",
        ),
    )
}

/// `DELETE /ui/accounts/{id}`
///
/// Answers with a redirect rather than a fragment: the page the button lives on
/// is the thing that just stopped existing.
pub async fn delete_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
) -> Result<Response, PageError> {
    let deleted = admin::delete_account(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    tracing::info!(event = "admin_account_deleted",
                   outcome = "success",
                   surface = "ui",
                   account_id = %id,
                   username = %session.auth.user.username,
                   cascaded_orders = deleted.cascaded);

    Ok(redirect("/ui/accounts", session.hx))
}

/// The account card, with a banner — the answer to every account mutation that
/// leaves the account in place.
fn card(
    state: &AdminState,
    session: &PageSessionWrite,
    account: Value,
    banner: Value,
) -> Result<Html<String>, PageError> {
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("account".to_string(), account);
    context.insert("flash".to_string(), banner);
    respond_fragment(state, "accounts/_card.html", context)
}

async fn load(id: &str, state: &AdminState) -> Result<Value, PageError> {
    let account = Account::find_any_by_id(id, &state.database)
        .await?
        .ok_or_else(|| not_found(id))?;
    Ok(admin::render_account_json(
        &account,
        &state.config.server.base_url,
    ))
}

fn not_found(id: &str) -> PageError {
    PageError::not_found(format!("no such account: {id}"))
}
