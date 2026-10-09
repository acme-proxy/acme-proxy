//! The routes a client calls before it holds an account: the directory
//! (RFC 8555 §7.1.1), `newNonce` (§7.2) in all three of its methods, and the
//! health and readiness checks.
//!
//! Every `newNonce` answer carries [`NO_STORE`]: a cached nonce is a nonce
//! that will be refused as already used.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::extractors::acme::AcmePostAsGet;
use crate::router::AppState;
use acme_proxy_core::routes;
use acme_proxy_store::db::Database;

/// The `Cache-Control` RFC 8555 §7.2 requires on `newNonce` responses: a cached
/// nonce is a nonce that will be rejected as already used.
pub const NO_STORE: (header::HeaderName, &str) = (header::CACHE_CONTROL, "no-store");

/// Health check endpoint that returns a simple JSON response indicating the server is running.
pub async fn get_health_check() -> Json<Value> {
    debug!(event = "server_health_requested", outcome = "progress");
    Json(json!({
        "healthy": true,
    }))
}

/// How long [`readiness`] waits for the database before answering `503`.
///
/// Shorter than any probe interval a load balancer would sensibly use, and
/// than the pool's five-second acquire timeout: a probe that hangs is read by
/// most balancers as a failure anyway, only later and less clearly.
pub const READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The readiness answer: `200 {"ready": true}` when the database answers a
/// `SELECT 1` within [`READINESS_TIMEOUT`], `503 {"ready": false}` otherwise.
///
/// Readiness, not liveness — which is why it is not `/health`. A process whose
/// database is gone should be taken out of a load balancer's rotation, not
/// restarted: a restart does not bring the database back, and an orchestrator
/// restarting every instance at once during a database switchover turns a
/// blip into an outage. Shared by both listeners, so they cannot disagree on
/// what "ready" means.
pub async fn readiness(database: &Database) -> Response {
    debug!(event = "server_readiness_requested", outcome = "progress");
    let failure = match tokio::time::timeout(READINESS_TIMEOUT, database.ping()).await {
        Ok(Ok(())) => return Json(json!({ "ready": true })).into_response(),
        Ok(Err(error)) => error.to_string(),
        Err(_) => format!("no answer within {}ms", READINESS_TIMEOUT.as_millis()),
    };
    warn!(event = "server_readiness_failed", outcome = "failure", error = %failure);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ready": false })),
    )
        .into_response()
}

/// `GET /ready` on the ACME listener — see [`readiness`].
pub async fn get_readiness(State(database): State<Arc<Database>>) -> Response {
    readiness(&database).await
}

/// ACME Directory endpoint that lists supported ACME endpoints.
pub async fn get_directory(State(state): State<AppState>) -> Json<Value> {
    debug!(event = "directory_requested", outcome = "progress");
    // Every advertised URL is the *endpoint's* own, prefix included: this is
    // where a client learns which profile it is talking to.
    let base = &state.profile.base_url;
    // Every path comes from `acme_proxy_core::routes`, the same constants `build_router`
    // mounts: a directory advertising something nothing serves is a client that
    // fails on its first request.
    let mut directory = json!({
        "newNonce": format!("{base}{}", routes::NEW_NONCE),
        "newAccount": format!("{base}{}", routes::NEW_ACCOUNT),
        "newOrder": format!("{base}{}", routes::NEW_ORDER),
        "revokeCert": format!("{base}{}", routes::REVOKE_CERT),
        "keyChange": format!("{base}{}", routes::KEY_CHANGE),
        "renewalInfo": format!("{base}{}", routes::RENEWAL_INFO),
    });
    // RFC 8555 §7.1.1's `meta`, assembled from whatever this endpoint actually
    // has to say. Every member is optional and an unset one is omitted rather
    // than sent empty — `"website": ""` says less than saying nothing.
    let meta = &state.profile.meta;
    let mut object = serde_json::Map::new();
    if state.profile.eab.enabled {
        object.insert("externalAccountRequired".to_string(), json!(true));
    }
    if !meta.terms_of_service.is_empty() {
        object.insert(
            "termsOfService".to_string(),
            json!(meta.terms_of_service.clone()),
        );
    }
    if !meta.website.is_empty() {
        object.insert("website".to_string(), json!(meta.website.clone()));
    }
    if !meta.caa_identities.is_empty() {
        object.insert(
            "caaIdentities".to_string(),
            json!(meta.caa_identities.clone()),
        );
    }
    if !object.is_empty() {
        directory["meta"] = Value::Object(object);
    }

    Json(directory)
}

/// POST-as-GET form of the directory (RFC 8555 §6.3).
///
/// §6.3 requires the directory and `newNonce` to answer a plain `GET` *and* a
/// POST-as-GET, so a client that speaks only the signed form can still
/// bootstrap. The [`AcmePostAsGet`] extractor does the whole §6.2/§6.4/§6.5
/// preamble; the body is then identical to [`get_directory`]'s.
pub async fn post_directory(state: State<AppState>, _: AcmePostAsGet) -> Json<Value> {
    get_directory(state).await
}

/// HEAD request handler for newNonce endpoint.
pub async fn head_new_nonce() -> impl IntoResponse {
    debug!(event = "nonce_new_head_requested", outcome = "progress");
    (StatusCode::OK, [NO_STORE])
}

/// GET request handler for newNonce endpoint.
pub async fn get_new_nonce() -> impl IntoResponse {
    debug!(event = "nonce_new_get_requested", outcome = "progress");
    (StatusCode::NO_CONTENT, [NO_STORE])
}

/// POST-as-GET form of `newNonce` (RFC 8555 §6.3), the second resource §6.3
/// requires to answer both forms.
///
/// Answers `200` rather than [`get_new_nonce`]'s `204`: this response has been
/// through the JWS extractor and consumed the client's previous nonce, so it is
/// a normal ACME response — and §7.2 only pins the `204` for the `GET` form.
/// The `Replay-Nonce` itself comes from the response middleware either way.
pub async fn post_new_nonce(_: AcmePostAsGet) -> impl IntoResponse {
    debug!(event = "nonce_new_post_requested", outcome = "progress");
    (StatusCode::OK, [NO_STORE])
}
