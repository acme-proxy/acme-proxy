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
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{Page, PageParams, page_envelope};
use crate::webadmin::handlers::params::{empty_is_absent, empty_is_absent_serial};
use crate::webadmin::session::Authenticated;
use acme_proxy_store::audit::AuditEntry;
use acme_proxy_store::audit::AuditQuery;

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
    #[serde(
        rename = "certSerial",
        default,
        deserialize_with = "empty_is_absent_serial"
    )]
    pub cert_serial: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub event: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub outcome: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl AuditListParams {
    /// The query both `/api/audit` and `/ui/audit` run, one builder so a filter
    /// cannot reach one surface and not the other.
    pub fn query(&self, page: Page) -> AuditQuery {
        AuditQuery {
            profile: self.profile.clone(),
            account_id: self.account_id.clone(),
            order_id: self.order_id.clone(),
            cert_serial: self.cert_serial.clone(),
            event: self.event.clone(),
            outcome: self.outcome.clone(),
            // No `since` on this surface: a browser filters by picking a page,
            // and a date parser is a second definition of "how far back" the
            // CLI already has. Add one when a page control needs it, not before.
            since: None,
            limit: page.limit,
            offset: page.offset,
        }
    }
}

/// Renders [`admin::AuditListError`] for both web surfaces.
impl From<admin::AuditListError> for AdminError {
    fn from(error: admin::AuditListError) -> Self {
        match error {
            admin::AuditListError::Invalid(detail) => AdminError::bad_request(detail),
            admin::AuditListError::Database(error) => AdminError::from(error),
        }
    }
}

/// `GET /api/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=`
pub async fn list_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditListParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let query = params.query(page);
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
