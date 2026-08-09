use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::debug;

use crate::AppState;
use crate::extractors::acme::AcmePostAsGet;
use crate::routes;

/// The `Cache-Control` RFC 8555 §7.2 requires on `newNonce` responses: a cached
/// nonce is a nonce that will be rejected as already used.
pub const NO_STORE: (header::HeaderName, &str) = (header::CACHE_CONTROL, "no-store");

/// Health check endpoint that returns a simple JSON response indicating the server is running.
pub async fn get_health_check() -> Json<Value> {
    debug!(event = "health_check_requested");
    Json(json!({
        "healthy": true,
    }))
}

/// ACME Directory endpoint that lists supported ACME endpoints.
pub async fn get_directory(State(state): State<AppState>) -> Json<Value> {
    debug!(event = "directory_endpoint_requested");
    // Every advertised URL is the *endpoint's* own, prefix included: this is
    // where a client learns which profile it is talking to.
    let base = &state.profile.base_url;
    // Every path comes from `crate::routes`, the same constants `build_router`
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
    debug!(event = "new_nonce_head_requested");
    (StatusCode::OK, [NO_STORE])
}

/// GET request handler for newNonce endpoint.
pub async fn get_new_nonce() -> impl IntoResponse {
    debug!(event = "new_nonce_get_requested");
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
    debug!(event = "new_nonce_post_requested");
    (StatusCode::OK, [NO_STORE])
}
