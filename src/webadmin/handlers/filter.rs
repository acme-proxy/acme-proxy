//! `GET /api/profiles/{name}/filter` — one endpoint's resolved access policy.
//!
//! **`show`, never `explain`.** [`crate::filter::explain::explain`] executes
//! the operator's `custom` scripts and issues real IPAM and DNS requests
//! against an address and names the *caller* chose; behind a session that is
//! script execution plus SSRF from one stolen cookie, on a listener that
//! deliberately carries no filter chain and no admission control. That refusal
//! stands, and there is no route for it here. This one builds a document from
//! [`crate::filter::explain::policy_json`], which calls four accessors on a
//! [`FilterPolicy`](crate::filter::FilterPolicy) and reaches nothing outside
//! the process — it is not even `async` under the handler's own `async`.
//!
//! Read-only, so this file contributes nothing to
//! `tests/admin_api.rs::mutating_endpoints()`: a policy is configuration, and
//! configuration is changed by editing the file and reloading, never through a
//! browser session.
//!
//! **The policy served here is the *live* one** — read from `state.profiles`,
//! which is what this process is enforcing right now — where `acme-proxy
//! filter show` rebuilds it from configuration on purpose, so that every
//! startup refusal reaches an operator at the terminal. `[filter]` reloads on
//! `SIGHUP` and the whole policy is swapped, so between an edit and its reload
//! the two front ends legitimately disagree, and a configuration that would be
//! *refused* is caught by the CLI while this one still serves the last good
//! policy. That is the correct answer on both sides, and comparing them is how
//! an operator finds out which state they are in.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use crate::filter::explain::policy_json;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::session::Authenticated;

/// `GET /api/profiles/{name}/filter` — the resolved access policy.
///
/// The `profile` member comes from the mounted profile rather than from the
/// path, the same habit `orders::download_chain` keeps for its filename: the
/// two are equal by construction, and the one that is not caller-supplied is
/// the one to interpolate.
pub async fn get_profile_filter(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let profile = state.profiles.get(&name).ok_or_else(|| not_found(&name))?;
    Ok(Json(policy_json(&profile.name, &profile.filter)))
}

/// A `404`, not the `409 profile_not_mounted` an order's missing profile
/// raises: there the resource exists and its endpoint does not, which is a
/// conflict, and here the endpoint *is* the resource being asked for.
fn not_found(name: &str) -> AdminError {
    AdminError::not_found(format!("no profile named `{name}` is mounted"))
}
