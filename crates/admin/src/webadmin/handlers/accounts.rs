//! `/api/accounts` — the ACME accounts across every mounted endpoint.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::Caller;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};
use acme_proxy_jobs::auditor::admin as audit_admin;
use acme_proxy_store::account::Account;
use acme_proxy_store::order::Order;
use acme_proxy_store::order::OrderQuery;

/// Note the window fields are declared inline rather than `#[serde(flatten)]`
/// over a [`PageParams`]: flatten forces serde through `deserialize_any`, and
/// a query string yields every value as a *string*, so `limit=10` then fails
/// to deserialize as an `i64`. Pinned by
/// `a_limit_over_the_ceiling_is_clamped_rather_than_refused`.
#[derive(Debug, Deserialize, Default)]
pub struct AccountListParams {
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub profile: Option<String>,
    /// The accounts one EAB credential bound.
    #[serde(default, rename = "eabKid", deserialize_with = "empty_is_absent")]
    pub eab_kid: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAccount {
    pub contact: Vec<String>,
}

/// `GET /api/accounts?profile=&eabKid=&limit=&offset=`
pub async fn list_accounts(
    State(state): State<AdminState>,
    Query(params): Query<AccountListParams>,
    _auth: Authenticated,
) -> Result<Json<serde_json::Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let (accounts, total) = Account::search(
        params.profile.as_deref(),
        params.eab_kid.as_deref(),
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
    AuthenticatedWrite(auth): AuthenticatedWrite,
    request_context: acme_proxy_core::audit::RequestContext,
    Json(body): Json<UpdateAccount>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let account = apply_update_account_contact(
        &state,
        &Caller::api(&auth, &request_context),
        &id,
        body.contact,
    )
    .await?;
    Ok(Json(admin::render_account_json(
        &account,
        &state.config.server.base_url,
    )))
}

/// How a refused or failed contact update reads to an admin client.
pub(crate) fn contact_error(error: admin::ContactError) -> AdminError {
    match error {
        admin::ContactError::Invalid(detail) => AdminError::bad_request(detail),
        admin::ContactError::Database(error) => AdminError::from(error),
    }
}

/// `POST /api/accounts/{id}/deactivate`
pub async fn deactivate_account(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Json<serde_json::Value>, AdminError> {
    let account =
        apply_deactivate_account(&state, &Caller::api(&auth, &request_context), &id).await?;
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
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Response, AdminError> {
    let cascaded = apply_delete_account(&state, &Caller::api(&auth, &request_context), &id).await?;
    Ok((
        StatusCode::OK,
        Json(json!({ "deleted": { "orders": cascaded } })),
    )
        .into_response())
}

/// Replaces an account's contact list, refused (`400`) where `newAccount`
/// would refuse it: the **same** check, so no admin surface can write a
/// contact the ACME side would not have taken.
pub(crate) async fn apply_update_account_contact(
    state: &AdminState,
    caller: &Caller<'_>,
    id: &str,
    contact: Vec<String>,
) -> Result<Account, AdminError> {
    if let Some(rejection) = acme_proxy_protocol::acme::rules::contact_shape_error(&contact) {
        return Err(AdminError::bad_request(rejection.detail));
    }

    let account = admin::update_account_contact(id, contact, state.database.clone())
        .await
        .map_err(contact_error)?
        .ok_or_else(|| not_found(id))?;
    state
        .record_admin_action(caller.request, caller.username(), |actor, client| {
            audit_admin::account_contact_updated(actor, client, &account, &account.contact)
        })
        .await;
    tracing::info!(event = "admin_account_contact_updated",
                   outcome = "success",
                   surface = caller.surface,
                   account_id = %id,
                   username = %caller.username());
    Ok(account)
}

/// Deactivates an account, which queues its `account_deactivated`
/// notification naming the operator's address.
pub(crate) async fn apply_deactivate_account(
    state: &AdminState,
    caller: &Caller<'_>,
    id: &str,
) -> Result<Account, AdminError> {
    let account = admin::deactivate_account(
        id,
        state.database.clone(),
        |profile| state.notifiers.get(profile),
        caller
            .request
            .ip
            .map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
    )
    .await?
    .ok_or_else(|| not_found(id))?;
    state
        .record_admin_action(caller.request, caller.username(), |actor, client| {
            audit_admin::account_deactivated(actor, client, &account)
        })
        .await;
    tracing::info!(event = "admin_account_deactivated",
                   outcome = "success",
                   surface = caller.surface,
                   account_id = %id,
                   username = %caller.username());
    Ok(account)
}

/// Hard-deletes an account and its orders, answering how many orders went
/// with it. `409 live_certificates` while any of them holds one.
pub(crate) async fn apply_delete_account(
    state: &AdminState,
    caller: &Caller<'_>,
    id: &str,
) -> Result<u64, AdminError> {
    // Captured before the delete so the audit row can name the account's own
    // profile and id; `delete_account` returns only the cascade count.
    let subject = Account::find_any_by_id(id, &state.database).await?;
    let deleted = match admin::delete_account(id, state.database.clone()).await? {
        admin::Deletion::NotFound => return Err(not_found(id)),
        admin::Deletion::LiveCertificates(live) => {
            return Err(AdminError::conflict(
                "live_certificates",
                admin::live_certificates_refusal(&format!("account {id}"), live),
            ));
        }
        admin::Deletion::Deleted(deleted) => deleted,
    };

    if let Some(account) = subject {
        state
            .record_admin_action(caller.request, caller.username(), |actor, client| {
                audit_admin::account_deleted(actor, client, &account, deleted.cascaded)
            })
            .await;
    }
    tracing::info!(event = "admin_account_deleted",
                   outcome = "success",
                   surface = caller.surface,
                   account_id = %id,
                   username = %caller.username(),
                   cascaded_orders = deleted.cascaded);
    Ok(deleted.cascaded)
}

fn not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such account: {id}"))
}
