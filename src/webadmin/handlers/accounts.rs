//! `/api/accounts` — the ACME accounts across every mounted endpoint.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::admin;
use crate::sqlite::account::Account;
use crate::sqlite::order::{Order, OrderQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};

/// Note the window fields are declared inline rather than `#[serde(flatten)]`
/// over a [`PageParams`]: flatten forces serde through `deserialize_any`, and
/// a query string yields every value as a *string*, so `limit=10` then fails
/// to deserialize as an `i64`. Pinned by
/// `a_limit_over_the_ceiling_is_clamped_rather_than_refused`.
#[derive(Debug, Deserialize, Default)]
pub struct AccountListParams {
    pub profile: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAccount {
    pub contact: Vec<String>,
}

/// `GET /api/accounts?profile=&limit=&offset=`
pub async fn list_accounts(
    State(state): State<AdminState>,
    Query(params): Query<AccountListParams>,
    _auth: Authenticated,
) -> Result<Json<serde_json::Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let (accounts, total) = Account::search(
        params.profile.as_deref(),
        page.limit,
        page.offset,
        &state.database,
    )
    .await?;

    let items = accounts
        .iter()
        .map(|account| admin::render_account_json(account, &state.config.server.base_url))
        .collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/accounts/{id}`
///
/// `find_any_by_id` — the deliberately **unscoped** admin lookup. An operator
/// holding an id wants the account whatever endpoint it was registered at;
/// only the request path needs the profile predicate that keeps a `kid` minted
/// at one endpoint from working at another.
pub async fn get_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    _auth: Authenticated,
) -> Result<Json<serde_json::Value>, AdminError> {
    let account = Account::find_any_by_id(&id, &state.database)
        .await?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(admin::render_account_json(
        &account,
        &state.config.server.base_url,
    )))
}

/// `GET /api/accounts/{id}/orders?limit=&offset=`
pub async fn list_account_orders(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(params): Query<PageParams>,
    _auth: Authenticated,
) -> Result<Json<serde_json::Value>, AdminError> {
    // Confirm the account exists first, so an unknown id is a 404 rather than
    // an empty page that looks like "this account has no orders".
    if Account::find_any_by_id(&id, &state.database)
        .await?
        .is_none()
    {
        return Err(not_found(&id));
    }

    let page = params.resolve(&state.config);
    let query = OrderQuery {
        account_id: Some(id),
        limit: page.limit,
        offset: page.offset,
        ..OrderQuery::default()
    };
    let (orders, total) = Order::search(&query, &state.database).await?;

    let items = super::orders::render_orders(&orders, &state).await?;
    Ok(Json(page_envelope(items, total, page)))
}

/// `PATCH /api/accounts/{id}` — replace the contact list.
///
/// The contacts are validated with the **same** check `newAccount` applies, so
/// the admin API cannot write a contact the ACME side would have refused.
pub async fn patch_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    AuthenticatedWrite(_auth): AuthenticatedWrite,
    Json(body): Json<UpdateAccount>,
) -> Result<Json<serde_json::Value>, AdminError> {
    if let Some(rejection) = crate::handlers::helpers::contact_shape_error(&body.contact) {
        return Err(AdminError::bad_request(rejection.detail));
    }

    let account = admin::update_account_contact(&id, body.contact, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(admin::render_account_json(
        &account,
        &state.config.server.base_url,
    )))
}

/// `POST /api/accounts/{id}/deactivate`
pub async fn deactivate_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    AuthenticatedWrite(_auth): AuthenticatedWrite,
) -> Result<Json<serde_json::Value>, AdminError> {
    let account = admin::deactivate_account(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(admin::render_account_json(
        &account,
        &state.config.server.base_url,
    )))
}

/// `DELETE /api/accounts/{id}` — hard delete, cascading to the orders.
///
/// Answers `200` with what it removed rather than a bare `204`: an operator
/// deleting an account should see how many orders went with it, and the count
/// is already known.
pub async fn delete_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<Response, AdminError> {
    let deleted = admin::delete_account(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    tracing::info!(event = "admin_account_deleted",
                   outcome = "success",
                   surface = "api",
                   account_id = %id,
                   username = %auth.user.username,
                   cascaded_orders = deleted.cascaded);
    Ok((
        StatusCode::OK,
        Json(json!({ "deleted": { "orders": deleted.cascaded } })),
    )
        .into_response())
}

fn not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such account: {id}"))
}
