//! `/ui/profiles/{name}/filter` — the policy behind one endpoint.
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

use crate::filter::explain::policy_json;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::misc::profile_row;
use crate::webadmin::pages::auth::PageSession;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, respond};

/// `GET /ui/profiles/{name}/filter` — every check, and every rule in
/// evaluation order with its condition re-parenthesized.
pub async fn get_profile_filter(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let profile = state.profiles.get(&name).ok_or_else(|| not_found(&name))?;

    let mut context = chrome(
        &session,
        "profiles",
        &format!("Filter policy: {}", profile.name),
    );
    context.insert("endpoint".to_string(), profile_row(profile));
    context.insert(
        "policy".to_string(),
        policy_json(&profile.name, &profile.filter),
    );

    // A whole page or nothing. There is no pager, no filter control and no
    // mutation here, so nothing on it would ever issue an htmx request -- the
    // same call `misc::get_index` and `misc::list_profiles` make, and the
    // reason this route contributes no entry to the fragment table.
    respond(
        &state,
        false,
        "profiles/filter.html",
        "profiles/filter.html",
        context,
    )
}

fn not_found(name: &str) -> PageError {
    AdminError::not_found(format!("no profile named `{name}` is mounted")).into()
}
