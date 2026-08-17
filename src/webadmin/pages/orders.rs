//! `/ui/orders` — the order list, one order with its authorizations, and the
//! two things an operator can do to it.

use axum::extract::{Path, Query, State};
use axum::response::{Html, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::admin::ops::RevokeOutcome;
use crate::sqlite::order::{Order, OrderQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::orders::{OrderListParams, render_orders, revoke_error};
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::{PageError, redirect};
use crate::webadmin::pages::{chrome, flash, flash_error, pager, respond, respond_fragment};

/// The revoke control posts a `<select>`, whose empty option means "no reason".
#[derive(Debug, Deserialize, Default)]
pub struct RevokeForm {
    /// Empty when the operator left the reason at "unspecified"; `serde` would
    /// otherwise refuse to parse `reason=` into an `Option<u32>`.
    #[serde(default)]
    pub reason: String,
}

/// `GET /ui/orders?profile=&accountId=&status=&limit=&offset=`
pub async fn list_orders(
    State(state): State<AdminState>,
    Query(params): Query<OrderListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let profile = params.profile.clone().unwrap_or_default();
    let account_id = params.account_id.clone().unwrap_or_default();
    let status = params.status.clone().unwrap_or_default();
    // Same refusal the API gives, rendered as a page rather than as JSON.
    let parsed = params
        .parsed_status()
        .map_err(|error| PageError::bad_request(error.to_string()))?;

    let (orders, total) = Order::search(
        &OrderQuery {
            profile: params.profile.clone(),
            account_id: params.account_id.clone(),
            status: parsed,
            limit: page.limit,
            offset: page.offset,
        },
        &state.database,
    )
    .await?;
    let items = render_orders(&orders, &state).await?;

    let mut context = chrome(&session, "orders", "Orders");
    context.insert(
        "page".to_string(),
        serde_json::json!({ "items": items, "total": total }),
    );
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/orders",
            &[
                ("profile", &profile),
                ("status", &status),
                ("accountId", &account_id),
            ],
            "#orders-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({
            "profile": profile,
            "status": status,
            "accountId": account_id,
        }),
    );
    context.insert(
        "profiles".to_string(),
        Value::Array(crate::webadmin::handlers::misc::profile_rows(&state)),
    );

    respond(
        &state,
        session.hx,
        "orders/list.html",
        "orders/_table.html",
        context,
    )
}

/// `GET /ui/orders/{id}`
pub async fn get_order(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let detail = load(&id, &state).await?;

    let mut context = chrome(&session, "orders", "Order");
    context.insert("detail".to_string(), detail);

    respond(
        &state,
        session.hx,
        "orders/detail.html",
        "orders/_card.html",
        context,
    )
}

/// `POST /ui/orders/{id}/revoke`
///
/// The operator-side equivalent of `POST /revokeCert`, and it resolves *that
/// order's own* profile's signer — revoking against whichever backend happened
/// to be first would write the serial into the wrong CA's CRL.
///
/// ## Why a refusal is usually a banner and not a page
///
/// A `409` here means the row is in a state that does not allow what was asked
/// (`already_revoked`, `order_not_issued`): the answer belongs beside the
/// button, with the order still on screen. A `5xx` is not about this order at
/// all, so it replaces the page. The rule is "the row's state is a banner, the
/// server's problem is a page".
pub async fn revoke_order(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    request_context: crate::audit::RequestContext,
    session: PageSessionWrite,
    // A plain `Form`, not `Option<Form>`: axum implements the optional
    // extractor for `Json` but not for `Form`, and every caller here is a
    // browser form that always sends a body.
    axum::Form(form): axum::Form<RevokeForm>,
) -> Result<Html<String>, PageError> {
    let reason = match form.reason.trim() {
        "" => None,
        raw => Some(raw.parse::<u32>().map_err(|_| {
            PageError::from(AdminError::bad_request(format!(
                "revocation reason `{raw}` is not a number"
            )))
        })?),
    };

    let banner = match crate::webadmin::handlers::resolve_order_signer(&state, &id).await {
        Err(error) => flash_error(error.code, error.message),
        Ok(signer) => {
            // The operator, not the certificate's owner — see the API twin.
            match admin::revoke_order(
                &id,
                reason,
                crate::audit::Actor::admin(&session.auth.user.username),
                state.audit.client(&request_context).await,
                state.database.clone(),
                signer,
            )
            .await
            {
                Ok(RevokeOutcome::Revoked(order)) => {
                    tracing::info!(event = "admin_order_revoked",
                                   outcome = "success",
                                   surface = "ui",
                                   order_id = %id,
                                   profile = %order.profile,
                                   reason = ?reason,
                                   username = %session.auth.user.username);
                    flash("ok", "Certificate revoked. The CRL has been regenerated.")
                }
                Ok(RevokeOutcome::NotFound) => return Err(not_found(&id)),
                Ok(RevokeOutcome::NotIssued) => flash_error(
                    "order_not_issued",
                    format!("Order {id} has no certificate to revoke."),
                ),
                Ok(RevokeOutcome::AlreadyRevoked) => flash_error(
                    "already_revoked",
                    format!("Order {id} was already revoked."),
                ),
                Err(error) => {
                    let error = revoke_error(error);
                    if error.status.is_server_error() {
                        return Err(error.into());
                    }
                    flash_error(error.code, error.message)
                }
            }
        }
    };

    // Re-read rather than reuse: the revocation stamped columns the card shows,
    // and re-rendering from the pre-revocation row would tell the operator
    // nothing happened.
    let detail = load(&id, &state).await?;
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("detail".to_string(), detail);
    context.insert("flash".to_string(), banner);
    respond_fragment(&state, "orders/_card.html", context)
}

/// `DELETE /ui/orders/{id}`
pub async fn delete_order(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
) -> Result<Response, PageError> {
    let deleted = admin::delete_order(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    tracing::info!(event = "admin_order_deleted",
                   outcome = "success",
                   surface = "ui",
                   order_id = %id,
                   username = %session.auth.user.username,
                   cascaded_authorizations = deleted.cascaded);

    Ok(redirect("/ui/orders", session.hx))
}

async fn load(id: &str, state: &AdminState) -> Result<Value, PageError> {
    let detail = admin::load_order_detail(id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(id))?;
    Ok(admin::render_order_detail_json(
        &detail,
        &state.config.server.base_url,
    ))
}

fn not_found(id: &str) -> PageError {
    PageError::not_found(format!("no such order: {id}"))
}
