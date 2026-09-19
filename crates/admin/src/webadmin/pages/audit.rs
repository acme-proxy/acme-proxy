//! `/ui/audit` — the CA's audit trail, and one row in full.
//!
//! Read-only, like its API twin: there is no route here that writes or deletes
//! an audit row, which is why this file contributes nothing to
//! `tests/admin_pages.rs::mutating_page_endpoints()`. See
//! [`crate::webadmin::handlers::audit`] for why.

use axum::extract::{Path, Query, State};
use axum::response::Html;
use serde_json::Value;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::audit::AuditListParams;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{ListFilters, chrome, pager, respond};
use acme_proxy_core::audit::ALL_AUDIT_EVENTS;
use acme_proxy_store::audit::AuditEntry;
use acme_proxy_store::audit::AuditQuery;

/// `GET /ui/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=`
pub async fn list_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    // Every filter the query below applies, and no other: a filter missing here
    // is dropped by the next page step and by the next change to the form.
    let filters = ListFilters::new()
        .with("profile", params.profile.as_deref())
        .with("event", params.event.as_deref())
        .with("outcome", params.outcome.as_deref())
        .with("accountId", params.account_id.as_deref())
        .with("orderId", params.order_id.as_deref())
        .with("certSerial", params.cert_serial.as_deref());

    let (entries, total) = admin::list_audit(
        &AuditQuery {
            profile: params.profile.clone(),
            account_id: params.account_id.clone(),
            order_id: params.order_id.clone(),
            cert_serial: params.cert_serial.clone(),
            event: params.event.clone(),
            outcome: params.outcome.clone(),
            since: None,
            limit: page.limit,
            offset: page.offset,
        },
        state.database.clone(),
    )
    .await?;

    let items: Vec<Value> = entries.iter().map(AuditEntry::to_json).collect();
    let mut context = chrome(&session, "audit", "Audit");
    context.insert(
        "page".to_string(),
        serde_json::json!({ "items": items, "total": total }),
    );
    context.insert(
        "pager".to_string(),
        pager(page, total, "/ui/audit", &filters.pairs(), "#audit-table"),
    );
    context.insert("filters".to_string(), filters.to_value());
    context.insert(
        "events".to_string(),
        Value::Array(
            ALL_AUDIT_EVENTS
                .iter()
                .map(|event| Value::from(event.as_str()))
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
        "audit/list.html",
        "audit/_table.html",
        context,
    )
}

/// `GET /ui/audit/{id}`
pub async fn get_audit(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let entry = admin::find_audit(id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(id))?;

    let mut context = chrome(&session, "audit", &format!("Audit {id}"));
    context.insert("entry".to_string(), entry.to_json());
    respond(
        &state,
        session.hx,
        "audit/detail.html",
        "audit/_card.html",
        context,
    )
}

fn not_found(id: i64) -> PageError {
    AdminError::not_found(format!("audit row {id} not found")).into()
}
