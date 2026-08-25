//! `/api/nonces` and `/api/profiles` — the two small read surfaces.

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

use crate::admin;
use crate::sqlite::nonce::Nonce;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};

#[derive(Debug, Deserialize, Default)]
pub struct CleanupRequest {
    /// Age past which a nonce is swept. Absent means `nonce.ttl_seconds`.
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
}

/// `GET /api/nonces` — how many rows the table holds.
///
/// A count and nothing else: a nonce is a bearer credential until it is
/// consumed, so listing values would put live ones on a screen. The count is
/// the useful part — it should sit near the request rate times the TTL, and a
/// number far above that says the reaper is not running.
pub async fn get_nonces(
    State(state): State<AdminState>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let count = Nonce::count(&state.database).await?;
    Ok(Json(json!({
        "count": count,
        "ttlSeconds": state.config.nonce.ttl_seconds,
    })))
}

/// `POST /api/nonces/cleanup` — sweep now, rather than waiting for the reaper.
pub async fn cleanup_nonces(
    State(state): State<AdminState>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<CleanupRequest>>,
) -> Result<Json<Value>, AdminError> {
    let seconds = body
        .and_then(|Json(body)| body.ttl_seconds)
        .unwrap_or(state.config.nonce.ttl_seconds);

    let removed =
        admin::cleanup_nonces(Duration::from_secs(seconds), state.database.clone()).await?;
    tracing::info!(event = "admin_nonces_cleaned",
                   outcome = "success",
                   surface = "api",
                   rows_removed = removed,
                   ttl_seconds = seconds,
                   username = %auth.user.username);
    Ok(Json(json!({ "removed": removed })))
}

/// `GET /api/profiles` — the endpoints this process is serving.
///
/// Read straight from the mounted [`crate::Profile`]s rather than from
/// configuration, so it describes what is actually running: a profile parked
/// with `enabled = false` is absent here, which is the honest answer.
pub async fn list_profiles(State(state): State<AdminState>, _auth: Authenticated) -> Json<Value> {
    Json(Value::Array(profile_rows(&state)))
}

/// The mounted endpoints, name-sorted.
///
/// Shared with the `/ui` pages, which show the same list on the overview, on
/// its own page, and in the profile filter of every list -- one assembly, so
/// the two front ends cannot come to describe an endpoint differently.
pub(crate) fn profile_rows(state: &AdminState) -> Vec<Value> {
    let mut names: Vec<&String> = state.profiles.keys().collect();
    names.sort();

    names
        .into_iter()
        .filter_map(|name| state.profiles.get(name))
        .map(|profile| profile_row(profile))
        .collect()
}

/// One endpoint, as every surface describes it.
///
/// Split out of [`profile_rows`] for the filter-policy page, which shows one
/// endpoint rather than the list and still has to say the same things about it
/// -- `challengeBypass` above all, since that page is where the warning
/// matters most.
pub(crate) fn profile_row(profile: &crate::Profile) -> Value {
    json!({
        "name": profile.name,
        "baseUrl": profile.base_url,
        "directory": profile.directory_url(),
        "challengeBypass": profile.challenges.is_bypassed(),
        "eabEnabled": profile.eab.enabled,
    })
}
