//! `/ui/expiring` — what lapses soon, and whether anything has replaced it.
//!
//! Read-only, like its API twin, and for that twin's reason rather than the
//! audit trail's: renewal is the client's own ACME flow, so there is nothing
//! here for a route to write. This file therefore contributes nothing to
//! `tests/admin_pages.rs::mutating_page_endpoints()`. See
//! [`crate::webadmin::handlers::expiring`].

use axum::extract::{Query, State};
use axum::response::Html;
use serde_json::Value;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::expiring::ExpiringListParams;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, pager, respond};

/// `GET /ui/expiring?profile=&days=&superseded=&limit=&offset=`
pub async fn list_expiring(
    State(state): State<AdminState>,
    Query(params): Query<ExpiringListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let profile = params.profile.clone().unwrap_or_default();
    let days = params.lead_days(&state.config);
    let include_superseded = params.include_superseded();

    let query = admin::ExpiringQuery {
        profile: params.profile.clone(),
        before: admin::expiring_horizon(days),
        include_superseded,
        limit: page.limit,
        offset: page.offset,
    };
    let (entries, total, hidden) = admin::list_expiring(&query, state.database.clone()).await?;

    let items: Vec<Value> = entries.iter().map(admin::render_expiring_json).collect();
    let mut context = chrome(&session, "expiring", "Expiring");
    // `hidden` travels beside `total` rather than being folded into it: the
    // annotation is not a SQL predicate, so the count cannot follow the filter
    // down. The template says so where an operator can see it, which is better
    // than a pager whose arithmetic quietly disagrees with its own rows.
    context.insert(
        "page".to_string(),
        serde_json::json!({ "items": items, "total": total, "hidden": hidden }),
    );

    // The `superseded` round-trip is the *stored* spelling, not the one that
    // arrived: anything but `hide` shows, so echoing an arbitrary query value
    // back into the pager's links would keep a typo alive across every page
    // step while meaning nothing.
    let superseded = if include_superseded { "" } else { "hide" };
    let days_text = days.to_string();
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/expiring",
            &[
                ("profile", &profile),
                ("days", &days_text),
                ("superseded", superseded),
            ],
            "#expiring-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({
            "profile": profile,
            "days": days,
            "hideSuperseded": !include_superseded,
        }),
    );
    context.insert(
        "profiles".to_string(),
        Value::Array(crate::webadmin::handlers::misc::profile_rows(&state)),
    );

    respond(
        &state,
        session.hx,
        "expiring/list.html",
        "expiring/_table.html",
        context,
    )
}
