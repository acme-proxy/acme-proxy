//! The `http-01` responder: serving the challenge file an *upstream* CA
//! fetches, when the `relay` signer backend is proving domain control to
//! it over HTTP.
//!
//! This is the only route in the server that is not an ACME resource and not a
//! health probe, and it is the inverse of everything else here: the rest of
//! `handlers/` answers clients asking *this* server for certificates, while
//! this one answers the CA *this* server is asking for one. See
//! [`acme_proxy_signer::relay::http01`] for why the key authorization can only
//! come from this server and not from the original client.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::debug;

use acme_proxy_signer::Http01TokenStore;

/// The stores `GET /.well-known/acme-challenge/{token}` answers from.
///
/// A `Vec` rather than one store because two profiles may relay to two
/// different upstreams and so carry two backends; see
/// `crate::http01_stores`, which builds it.
#[derive(Clone)]
pub struct Http01Stores(pub Arc<Vec<Arc<dyn Http01TokenStore>>>);

/// Serves the key authorization the upstream CA is about to fetch
/// (RFC 8555 §8.3).
///
/// Mounted on the **root** router, outside every profile — so it is
/// unauthenticated and unfiltered, mints no `Replay-Nonce` and carries no
/// `Link: rel="index"`, exactly like `GET /health`. That is correct rather than
/// an oversight: the fetcher is a CA that holds no account here, and the path
/// is fixed by the RFC rather than by this server's URL namespace.
///
/// Deliberately ignores `Host`. The request arrives through whatever forwarder
/// or redirect the operator put in front of it, so its authority is not
/// something this server can predict — and §8.3 makes the token, not the name,
/// the secret.
pub async fn get_challenge_file(
    State(stores): State<Http01Stores>,
    Path(token): Path<String>,
) -> Response {
    let mut unreadable = false;
    let mut found = None;
    for store in stores.0.iter() {
        match store.lookup(&token).await {
            Ok(Some(key_authorization)) => {
                found = Some(key_authorization);
                break;
            }
            Ok(None) => {}
            // Logged by the store. Remembered rather than returned at once: a
            // second store may still hold the token.
            Err(_) => unreadable = true,
        }
    }
    match found {
        Some(key_authorization) => {
            debug!(event = "http_01_responder_served", outcome = "success", token = %token);
            (
                StatusCode::OK,
                // §8.3 recommends application/octet-stream. Nothing in reach
                // actually checks it — this crate's own validator, Boulder and
                // Pebble all trim the body and compare — so it is served
                // because the RFC says to, not because anything depends on it.
                [(header::CONTENT_TYPE, "application/octet-stream")],
                // Verbatim, with no trailing newline: §8.3's body *is* the key
                // authorization. Validators trim, but there is no reason to
                // make them.
                key_authorization,
            )
                .into_response()
        }
        // A store that could not be read is not a store without the token: a
        // `404` tells the upstream this server has nothing to show, which it
        // records as a failed validation. A `500` is what a transient failure
        // looks like to a CA that retries its fetch.
        None if unreadable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Internal Server Error",
        )
            .into_response(),
        None => {
            debug!(event = "http_01_responder_unknown_token", outcome = "failure", token = %token);
            // Deliberately not a `Problem`: this route is a public file, not an
            // ACME resource, and an `application/problem+json` carrying a
            // `urn:ietf:params:acme:error:` type would tell anyone who probes
            // the path otherwise.
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "Not Found",
            )
                .into_response()
        }
    }
}
