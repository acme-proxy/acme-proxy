//! `/api/audit` — the CA's audit trail, read-only.
//!
//! There is no mutating route in this file and there is not meant to be one.
//! The trail is pruned from the host (`acme-proxy audit cleanup`) or by
//! `audit.retention_days`; a panel session that could delete audit history
//! would make the history prove nothing, since the first thing a stolen session
//! would do is use it. That is also why neither handler here takes
//! [`AuthenticatedWrite`](crate::webadmin::session::AuthenticatedWrite) and why
//! `tests/admin_api.rs::mutating_endpoints()` has no entry for `/api/audit`.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::sqlite::audit::{AuditEntry, AuditQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::Authenticated;

/// The window fields are inline, not `#[serde(flatten)]` — see the note on
/// [`super::accounts::AccountListParams`].
#[derive(Debug, Deserialize, Default)]
pub struct AuditListParams {
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub profile: Option<String>,
    #[serde(rename = "accountId", default, deserialize_with = "empty_is_absent")]
    pub account_id: Option<String>,
    #[serde(rename = "orderId", default, deserialize_with = "empty_is_absent")]
    pub order_id: Option<String>,
    #[serde(rename = "certSerial", default, deserialize_with = "empty_is_absent")]
    pub cert_serial: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub event: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub outcome: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// `GET /api/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=`
pub async fn list_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditListParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let query = AuditQuery {
        profile: params.profile,
        account_id: params.account_id,
        order_id: params.order_id,
        cert_serial: params.cert_serial,
        event: params.event,
        outcome: params.outcome,
        // No `since` on this surface: a browser filters by picking a page, and
        // a date parser is a second definition of "how far back" the CLI
        // already has. Add one when a page control needs it, not before.
        since: None,
        limit: page.limit,
        offset: page.offset,
    };
    let (entries, total) = admin::list_audit(&query, state.database.clone()).await?;
    let items = entries.iter().map(AuditEntry::to_json).collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/audit/{id}`
pub async fn get_audit(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let entry = admin::find_audit(id, state.database.clone())
        .await?
        .ok_or_else(|| AdminError::not_found(format!("audit row {id} not found")))?;
    Ok(Json(entry.to_json()))
}
