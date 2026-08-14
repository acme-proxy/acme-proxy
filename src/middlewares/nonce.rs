//! ACME Nonce Management Middleware
//!
//! This module implements the Replay-Nonce middleware for ACME protocol compliance.
//! The middleware automatically adds Replay-Nonce headers to all responses and
//! ensures nonce management for anti-replay protection.
//!
//! ## ACME Protocol Requirements
//!
//! According to RFC 8555, the server must:
//! - Generate a new nonce for each response
//! - Include a `Replay-Nonce` header in all responses
//! - Validate that received nonces are valid and not replayed
//!
//! ## Behavior
//!
//! The middleware:
//! 1. Generates a new UUID nonce for each request
//! 2. Saves the nonce to the database
//! 3. Adds the nonce to the `Replay-Nonce` header in the response
//! 4. Handles database errors gracefully by logging and omitting the header
//!
//! ## Security Considerations
//!
//! - Nonces are single-use and are removed after validation
//! - Expired nonces are automatically cleaned up
//! - Failed nonce persistence does not break the request flow
//! - Nonce TTL (Time To Live) prevents indefinite accumulation

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Method, Request, header::HeaderName},
    middleware::Next,
    response::IntoResponse,
};

use crate::sqlite::{self, db::Database};

const REPLAY_NONCE: HeaderName = HeaderName::from_static("replay-nonce");

/// Whether this exchange is one RFC 8555 asks for a fresh nonce on.
///
/// §6.5: "The server MUST include a `Replay-Nonce` header field in every
/// successful response to a POST request, and SHOULD provide it in error
/// responses as well." Plus `newNonce` itself, whose entire purpose is handing
/// one out — in all three of its forms, since §6.3 requires GET and POST-as-GET
/// and §7.2 adds HEAD.
///
/// Nothing else. Minting on every response meant an unauthenticated
/// `GET /directory`, a `GET /crl`, a `GET /renewalInfo/{id}` and both fallbacks
/// each cost an INSERT — a committed write, with its own fsync — for a nonce no
/// client asked for and almost none would read. On a real deployment those are
/// the requests that dominate: reverse-proxy health checks and directory polls.
/// The nonce table already grows a row per signed request and is swept on a
/// timer; there is no reason to also grow it per unauthenticated GET.
///
/// The path here is the profile-relative one: `Router::nest` strips
/// `/profile/<name>` before this layer sees the request, the same reason
/// `verify_jws` can reconstruct the §6.4 URL from `base_url + path`.
fn mints_nonce(method: &Method, path: &str) -> bool {
    method == Method::POST || path == crate::routes::NEW_NONCE
}

pub async fn add_nonce_middleware(
    State(database): State<Arc<Database>>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let wanted = mints_nonce(request.method(), request.uri().path());
    let mut response = next.run(request).await;
    if !wanted {
        return response;
    }

    let nonce = sqlite::nonce::Nonce::new();

    // Only advertise a nonce we actually persisted: if the insert fails, log and
    // leave the header off rather than handing the client a nonce that will
    // never verify (or panicking the request task).
    match nonce.save(&database).await {
        Ok(()) => {
            if let Ok(header_value) = HeaderValue::from_str(&nonce.value) {
                response.headers_mut().insert(REPLAY_NONCE, header_value);
            } else {
                // Unreachable for a base64url nonce, but the client sees the
                // same thing either way — a response with no `Replay-Nonce` —
                // so it must not be the one branch that says nothing.
                tracing::error!(event = "nonce_header_invalid", outcome = "failure");
            }
        }
        Err(error) => {
            tracing::error!(event = "nonce_persist_failed", outcome = "failure", error = %error);
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exchanges_rfc8555_asks_for_mint_a_nonce() {
        // §6.5: every response to a POST, whatever the resource or outcome.
        for path in [
            "/newAccount",
            "/newOrder",
            "/chall/x",
            "/directory",
            "/nope",
        ] {
            assert!(mints_nonce(&Method::POST, path), "POST {path}");
        }

        // §7.2 / §6.3: newNonce hands one out in all three of its forms.
        for method in [Method::GET, Method::HEAD, Method::POST] {
            assert!(mints_nonce(&method, "/newNonce"), "{method} /newNonce");
        }

        // Everything else is an unauthenticated read that no client expects a
        // nonce from, and that used to cost a database write anyway.
        for path in ["/directory", "/crl", "/renewalInfo/abc.def", "/nope"] {
            assert!(!mints_nonce(&Method::GET, path), "GET {path}");
            assert!(!mints_nonce(&Method::HEAD, path), "HEAD {path}");
        }
    }
}
