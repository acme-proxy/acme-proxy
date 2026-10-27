//! `/ui/endpoints/{name}/filter` — the policy behind one endpoint.
//!
//! Read-only, like its API twin and for the same two reasons: a policy is
//! configuration, so there is nothing here for a route to write, and
//! `filter explain` deliberately has no web surface at all. This file
//! therefore contributes nothing to
//! `tests/admin_pages.rs::mutating_page_endpoints()`. See
//! [`crate::webadmin::handlers::filter`] for both arguments in full, including
//! why this shows the *live* policy where the CLI rebuilds one.

use axum::extract::{Path, State};
use axum::response::Html;

use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::misc::endpoint_row;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, respond};
use acme_proxy_policy::filter::explain::policy_json;

/// `GET /ui/endpoints/{name}/filter` — every check, and every rule in
/// evaluation order with its condition re-parenthesized.
pub async fn get_endpoint_filter(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let endpoint = state.endpoints.get(&name).ok_or_else(|| not_found(&name))?;

    let mut context = chrome(
        &session,
        "endpoints",
        &format!("Filter policy: {}", endpoint.name),
    );
    context.insert("endpoint".to_string(), endpoint_row(endpoint));
    context.insert(
        "policy".to_string(),
        policy_json(&endpoint.name, &endpoint.filter),
    );

    // A whole page or nothing. There is no pager, no filter control and no
    // mutation here, so nothing on it would ever issue an htmx request -- the
    // same call `misc::get_index` and `misc::list_endpoints` make, and the
    // reason this route contributes no entry to the fragment table.
    respond(
        &state,
        false,
        "endpoints/filter.html",
        "endpoints/filter.html",
        context,
    )
}

fn not_found(name: &str) -> PageError {
    AdminError::not_found(crate::admin::subject::Subject::Endpoint.missing(name)).into()
}
