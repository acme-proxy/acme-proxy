//! `/ui/upstream-orders` — the relay signer's per-order upstream state.
//!
//! Read-only, like its API twin: there is no route here that writes or
//! deletes, which is why this file contributes nothing to
//! `tests/admin_pages.rs::mutating_page_endpoints()`. Abandoning an in-flight
//! relay is done through `/ui/jobs/{id}/cancel` on the `signer_relay_issue`
//! job. See [`crate::webadmin::handlers::upstream_orders`] for why.

use axum::extract::{Path, Query, State};
use axum::response::Html;
use serde_json::Value;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::handlers::upstream_orders::UpstreamOrderListParams;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{ListFilters, chrome, page_value, pager, respond, vocabulary};
use acme_proxy_store::status::UpstreamOrderStatus;
use acme_proxy_store::upstream_order::UpstreamOrder;

/// `GET /ui/upstream-orders?profile=&status=&limit=&offset=`
pub async fn list_upstream_orders(
    State(state): State<AdminState>,
    Query(params): Query<UpstreamOrderListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let filters = ListFilters::new()
        .with("profile", params.profile.as_deref())
        .with("status", params.status.as_deref());
    // The API's own query, so a bad `status=` is its `invalid_status`.
    let query = crate::webadmin::handlers::upstream_orders::upstream_order_query(&params, page)?;
    let (rows, total) = UpstreamOrder::search(&query, &state.database).await?;
    let items: Vec<Value> = rows.iter().map(admin::render_upstream_order_json).collect();

    let mut context = chrome(&session, "upstream_orders", "Upstream orders");
    context.insert("page".to_string(), page_value(items, total));
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/upstream-orders",
            &filters.pairs(),
            "#upstream-orders-table",
        ),
    );
    context.insert("filters".to_string(), filters.to_value());
    context.insert(
        "statuses".to_string(),
        vocabulary(UpstreamOrderStatus::ALL, |status| status.as_str()),
    );
    context.insert(
        "profiles".to_string(),
        Value::Array(crate::webadmin::handlers::misc::profile_rows(&state)),
    );

    respond(
        &state,
        session.hx,
        "upstream_orders/list.html",
        "upstream_orders/_table.html",
        context,
    )
}

/// `GET /ui/upstream-orders/{id}` — by the **local** order id.
pub async fn get_upstream_order(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let detail = admin::load_upstream_order_detail(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;

    let mut context = chrome(&session, "upstream_orders", "Upstream order");
    context.insert(
        "detail".to_string(),
        admin::render_upstream_order_detail_json(&detail),
    );
    respond(
        &state,
        session.hx,
        "upstream_orders/detail.html",
        "upstream_orders/_card.html",
        context,
    )
}

fn not_found(id: &str) -> PageError {
    AdminError::not_found(format!("no upstream order for local order {id}")).into()
}
