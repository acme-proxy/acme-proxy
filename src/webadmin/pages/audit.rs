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
use crate::audit::ALL_AUDIT_EVENTS;
use crate::sqlite::audit::{AuditEntry, AuditQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::audit::AuditListParams;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, pager, respond};

/// `GET /ui/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=`
pub async fn list_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let profile = params.profile.clone().unwrap_or_default();
    let account_id = params.account_id.clone().unwrap_or_default();
    let event = params.event.clone().unwrap_or_default();
    let outcome = params.outcome.clone().unwrap_or_default();

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
        pager(
            page,
            total,
            "/ui/audit",
            &[
                ("profile", &profile),
                ("event", &event),
                ("outcome", &outcome),
                ("accountId", &account_id),
            ],
            "#audit-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({
            "profile": profile,
            "event": event,
            "outcome": outcome,
            "accountId": account_id,
        }),
    );
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
