//! `/api/upstream-orders` — the relay signer's per-order upstream state,
//! read-only.
//!
//! There is no mutating route in this file and there is not meant to be one.
//! Abandoning an in-flight relay is done through `POST /api/jobs/{id}/cancel`
//! on the `signer_relay_issue` job, which owns the state machine. Neither
//! handler here takes
//! [`AuthenticatedWrite`](crate::webadmin::session::AuthenticatedWrite), and
//! `tests/admin_api.rs::mutating_endpoints()` has no entry for
//! `/api/upstream-orders`.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::sqlite::status::{UnknownStatus, UpstreamOrderStatus};
use crate::sqlite::upstream_order::{UpstreamOrder, UpstreamOrderQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::jobs::bad_status;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::Authenticated;

/// The window fields are inline, not `#[serde(flatten)]` — see the note on
/// [`super::accounts::AccountListParams`].
#[derive(Debug, Deserialize, Default)]
pub struct UpstreamOrderListParams {
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub profile: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl UpstreamOrderListParams {
    /// Refused by name so `/api` and `/ui` reject a bad `?status=` identically.
    pub fn parsed_status(&self) -> Result<Option<UpstreamOrderStatus>, UnknownStatus> {
        self.status.as_deref().map(str::parse).transpose()
    }
}

/// `GET /api/upstream-orders?profile=&status=&limit=&offset=`
pub async fn list_upstream_orders(
    State(state): State<AdminState>,
    Query(params): Query<UpstreamOrderListParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let status = params.parsed_status().map_err(bad_status)?;
    let query = UpstreamOrderQuery {
        profile: params.profile,
        status,
        limit: page.limit,
        offset: page.offset,
    };
    let (rows, total) = UpstreamOrder::search(&query, &state.database).await?;
    let items = rows.iter().map(admin::render_upstream_order_json).collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/upstream-orders/{id}` — by the **local** order id, cross-linked to
/// the relay job.
pub async fn get_upstream_order(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let detail = admin::load_upstream_order_detail(&id, state.database.clone())
        .await?
        .ok_or_else(|| AdminError::not_found(format!("no upstream order for local order {id}")))?;
    Ok(Json(admin::render_upstream_order_detail_json(&detail)))
}
