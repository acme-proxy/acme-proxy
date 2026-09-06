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
use crate::sqlite::status::UpstreamOrderStatus;
use crate::sqlite::upstream_order::{UpstreamOrder, UpstreamOrderQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::handlers::upstream_orders::UpstreamOrderListParams;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, pager, respond};

/// `GET /ui/upstream-orders?profile=&status=&limit=&offset=`
pub async fn list_upstream_orders(
    State(state): State<AdminState>,
    Query(params): Query<UpstreamOrderListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let profile = params.profile.clone().unwrap_or_default();
    let status = params.status.clone().unwrap_or_default();
    let parsed = params
        .parsed_status()
        .map_err(|error| PageError::bad_request(error.to_string()))?;

    let (rows, total) = UpstreamOrder::search(
        &UpstreamOrderQuery {
            profile: params.profile.clone(),
            status: parsed,
            limit: page.limit,
            offset: page.offset,
        },
        &state.database,
    )
    .await?;
    let items: Vec<Value> = rows.iter().map(admin::render_upstream_order_json).collect();

    let mut context = chrome(&session, "upstream_orders", "Upstream orders");
    context.insert(
        "page".to_string(),
        serde_json::json!({ "items": items, "total": total }),
    );
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/upstream-orders",
            &[("profile", &profile), ("status", &status)],
            "#upstream-orders-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({ "profile": profile, "status": status }),
    );
    context.insert(
        "statuses".to_string(),
        Value::Array(
            UpstreamOrderStatus::ALL
                .iter()
                .map(|s| Value::from(s.as_str()))
                .collect(),
        ),
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
