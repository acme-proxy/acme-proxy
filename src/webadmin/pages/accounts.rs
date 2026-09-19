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
use crate::webadmin::AdminState;
use crate::webadmin::handlers::accounts::AccountListParams;
use crate::webadmin::handlers::orders::render_orders;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::{PageError, redirect};
use crate::webadmin::pages::{
    ListFilters, chrome, flash, page_value, pager, respond, respond_fragment,
};
use acme_proxy_jobs::auditor::admin as audit_admin;
use acme_proxy_store::account::Account;
use acme_proxy_store::order::Order;
use acme_proxy_store::order::OrderQuery;

/// The contact editor posts a textarea, not a JSON array.
#[derive(Debug, Deserialize)]
pub struct ContactForm {
    /// One URI per line. Blank lines are dropped, so clearing the box clears
    /// the contact list — which is the only way to express "no contact" in a
    /// textarea.
    pub contact: String,
}

/// `GET /ui/accounts?profile=&eabKid=&limit=&offset=`
pub async fn list_accounts(
    State(state): State<AdminState>,
    Query(params): Query<AccountListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let filters = ListFilters::new()
        .with("profile", params.profile.as_deref())
        .with("eabKid", params.eab_kid.as_deref());

    let (accounts, total) = Account::search(
        params.profile.as_deref(),
        params.eab_kid.as_deref(),
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
            &filters.pairs(),
            "#accounts-table",
        ),
    );
    context.insert("filters".to_string(), filters.to_value());
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
    let context = account_page_context(&state, &id, params, &session).await?;
    respond(
        &state,
        session.hx,
        "accounts/detail.html",
        "accounts/_card.html",
        context,
    )
}

/// `GET /ui/accounts/{id}/orders?limit=&offset=` — one account's orders.
///
/// The swap target of the pager under the account card. It could not be
/// `GET /ui/accounts/{id}` itself: that URL's fragment is the *card*, so a page
/// step there swapped a second `#account-card` into `#orders-table`. A
/// navigation to this URL still gets the whole account page, so the one-URL,
/// bookmarkable rule holds; the pager simply does not push it, since the
/// address bar belongs to the account.
pub async fn list_account_orders(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(params): Query<PageParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let context = account_page_context(&state, &id, params, &session).await?;
    respond(
        &state,
        session.hx,
        "accounts/detail.html",
        "orders/_table.html",
        context,
    )
}

/// The account, one page of its orders, and a pager over them — everything
/// both account routes above render, whichever half of it they swap.
async fn account_page_context(
    state: &AdminState,
    id: &str,
    params: PageParams,
    session: &PageSession,
) -> Result<Map<String, Value>, PageError> {
    let account = load(id, state).await?;
    let page = params.resolve(&state.config);

    let (orders, total) = Order::search(
        &OrderQuery {
            account_id: Some(id.to_string()),
            limit: page.limit,
            offset: page.offset,
            ..OrderQuery::default()
        },
        &state.database,
    )
    .await?;
    let items = render_orders(&orders, state).await?;

    let mut pager = pager(
        page,
        total,
        &format!("/ui/accounts/{id}/orders"),
        &[],
        "#orders-table",
    );
    pager["push"] = Value::Bool(false);

    let mut context = chrome(session, "accounts", "Account");
    context.insert("account".to_string(), account);
    context.insert("page".to_string(), page_value(items, total));
    context.insert("order_count".to_string(), Value::from(total));
    context.insert(
        "live_certificates".to_string(),
        Value::from(live_certificates(id, state).await?),
    );
    context.insert("pager".to_string(), pager);
    Ok(context)
}

/// `POST /ui/accounts/{id}/contact`
pub async fn post_account_contact(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    request_context: acme_proxy_core::audit::RequestContext,
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
    if let Some(rejection) = crate::acme::rules::contact_shape_error(&contact) {
        let account = load(&id, &state).await?;
        return card(
            &state,
            &session,
            account,
            super::flash_error("bad_request", rejection.detail),
        )
        .await;
    }

    let account = admin::update_account_contact(&id, contact, state.database.clone())
        .await
        .map_err(crate::webadmin::handlers::accounts::contact_error)?
        .ok_or_else(|| not_found(&id))?;

    state
        .record_admin_action(
            &request_context,
            &session.auth.user.username,
            |actor, client| {
                audit_admin::account_contact_updated(actor, client, &account, &account.contact)
            },
        )
        .await;
    tracing::info!(event = "admin_account_contact_updated",
                   outcome = "success",
                   account_id = %id,
                   username = %session.auth.user.username);

    let rendered = admin::render_account_json(&account, &state.config.server.base_url);
    card(&state, &session, rendered, flash("ok", "Contact updated.")).await
}

/// `POST /ui/accounts/{id}/deactivate`
pub async fn deactivate_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Html<String>, PageError> {
    let account = admin::deactivate_account(
        &id,
        state.database.clone(),
        |profile| state.notifiers.get(profile),
        request_context
            .ip
            .map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
    )
    .await?
    .ok_or_else(|| not_found(&id))?;

    state
        .record_admin_action(
            &request_context,
            &session.auth.user.username,
            |actor, client| audit_admin::account_deactivated(actor, client, &account),
        )
        .await;
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
    .await
}

/// `DELETE /ui/accounts/{id}`
///
/// Answers with a redirect rather than a fragment: the page the button lives on
/// is the thing that just stopped existing.
pub async fn delete_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Response, PageError> {
    let subject = Account::find_any_by_id(&id, &state.database).await?;
    let deleted = match admin::delete_account(&id, state.database.clone()).await? {
        admin::Deletion::NotFound => return Err(not_found(&id)),
        // The card, with the refusal beside the button that was pressed: the
        // account is still there, and so is every order that has to be revoked
        // before it can go.
        admin::Deletion::LiveCertificates(live) => {
            let context = card_context(&state, &session, load(&id, &state).await?).await?;
            return super::refuse_with_card(
                &state,
                "accounts/_card.html",
                context,
                &crate::webadmin::error::AdminError::conflict(
                    "live_certificates",
                    admin::live_certificates_refusal(&format!("account {id}"), live),
                ),
            );
        }
        admin::Deletion::Deleted(deleted) => deleted,
    };

    if let Some(account) = subject {
        state
            .record_admin_action(
                &request_context,
                &session.auth.user.username,
                |actor, client| {
                    audit_admin::account_deleted(actor, client, &account, deleted.cascaded)
                },
            )
            .await;
    }

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
async fn card(
    state: &AdminState,
    session: &PageSessionWrite,
    account: Value,
    banner: Value,
) -> Result<Html<String>, PageError> {
    let mut context = card_context(state, session, account).await?;
    context.insert("flash".to_string(), banner);
    respond_fragment(state, "accounts/_card.html", context)
}

/// Everything the account card reads besides the banner.
async fn card_context(
    state: &AdminState,
    session: &PageSessionWrite,
    account: Value,
) -> Result<Map<String, Value>, PageError> {
    let id = account["id"].as_str().unwrap_or_default().to_string();
    let mut context = super::fragment_context(&session.auth);
    context.insert("account".to_string(), account);
    context.insert(
        "order_count".to_string(),
        Value::from(order_count(&id, state).await?),
    );
    context.insert(
        "live_certificates".to_string(),
        Value::from(live_certificates(&id, state).await?),
    );
    Ok(context)
}

/// How many live certificates the account holds — any of which disables the
/// card's delete button. The handler refuses regardless; this only spares the
/// operator a button that can only say no.
async fn live_certificates(id: &str, state: &AdminState) -> Result<u64, PageError> {
    let Some(account_id) = acme_proxy_store::id::parse(id) else {
        return Ok(0);
    };
    Ok(Account::count_live_certificates(account_id, &state.database).await?)
}

/// How many orders a delete of this account would take with it — what the
/// card's confirmation names, as `account delete`'s prompt does.
async fn order_count(id: &str, state: &AdminState) -> Result<i64, PageError> {
    let (_, total) = Order::search(
        &OrderQuery {
            account_id: Some(id.to_string()),
            limit: 1,
            ..OrderQuery::default()
        },
        &state.database,
    )
    .await?;
    Ok(total)
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
