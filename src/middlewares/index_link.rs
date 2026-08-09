//! `Link: rel="index"` response middleware (RFC 8555 §7.1).
//!
//! §7.1: "The `index` link relation is present on all resources other than the
//! directory and indicates the URL of the directory." It is how a client that
//! holds only a resource URL — an order it stored months ago, say — finds its
//! way back to the endpoint that minted it.
//!
//! Two properties are load-bearing:
//!
//! - **The header is appended, never set.** `post_challenge` already sends
//!   `Link: …;rel="up"` (RFC 8555 §7.5.1), which certbot's `acme` library
//!   requires; overwriting it would break challenge validation for every
//!   client that reads it.
//! - **The directory itself is skipped**, per the "other than the directory"
//!   half of §7.1 — a directory pointing at itself says nothing.
//!
//! Living in the profile router means the path seen here is already
//! prefix-stripped by `Router::nest`, the same convention `verify_jws` relies
//! on, so the comparison is against the bare `/directory`.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, header},
    middleware::Next,
    response::IntoResponse,
};

/// The one resource that does not carry the link.
const DIRECTORY_PATH: &str = "/directory";

pub async fn add_index_link_middleware(
    State(link_value): State<HeaderValue>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let is_directory = request.uri().path() == DIRECTORY_PATH;

    let mut response = next.run(request).await;

    if !is_directory {
        response.headers_mut().append(header::LINK, link_value);
    }

    response
}
