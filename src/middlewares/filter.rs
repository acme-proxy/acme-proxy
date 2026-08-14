//! Request-filtering middleware.
//!
//! Runs the connection stage of the configured [`FilterPolicy`] before the
//! request reaches a handler, and records the client address so the handlers
//! can pass it to the identifier stage later in the flow.
//!
//! There is no exempt-path branch: a path that should skip the policy is a
//! `type = "path"` check plus a rule, which can also combine the path with an
//! address and can glob where the old `filter.exempt_paths` list could only
//! compare exact strings.
//!
//! ## Layer order
//!
//! This sits **inside** the `Replay-Nonce` middleware. `tower`'s `.layer()`
//! wraps what was added before it, so the nonce layer — added last in
//! [`build_router`](crate::build_router) — stays outermost and still stamps a
//! fresh nonce onto a 403 produced here. An ACME client that gets refused
//! therefore still has a usable nonce, and retries with a corrected
//! configuration rather than a `badNonce` loop.
//!
//! ## The client address is always recorded
//!
//! [`ClientIp`] goes into the request extensions on *every* request, including
//! exempt paths and when no filter is configured. Handlers can then read it
//! unconditionally, and the value is present in tests driving the router
//! through `oneshot` (where it is `None`, since there is no socket).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{instrument, warn};

use crate::error::Problem;
use crate::filter::{ClientIp, ConnectionContext, FilterPolicy, Outcome};

#[instrument(name = "add_filter_middleware", skip_all, fields(path = %request.uri().path()))]
pub async fn add_filter_middleware(
    State(policy): State<Arc<FilterPolicy>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let client_ip = policy.proxy().resolve(peer, request.headers());
    request.extensions_mut().insert(ClientIp(client_ip));

    let path = request.uri().path().to_string();
    let context = ConnectionContext {
        client_ip,
        method: request.method(),
        path: &path,
    };

    // No exempt-path branch: a path that should skip the policy is a
    // `type = "path"` check and a rule, which can also combine the path with an
    // address and can glob where the old exact-match list could not.
    match policy.check_connection(&context).await {
        Outcome::Allow => next.run(request).await,
        outcome => problem_for(&outcome, client_ip, &path).into_response(),
    }
}

/// Maps a connection-stage refusal to its ACME error document.
///
/// A refusal is a decision about the client (403); an unknown means the server
/// could not decide, which is its problem and not the client's, so it gets a
/// 500 the client may retry.
///
/// The policy has already logged the decision; this line adds the request path,
/// which the policy does not see.
fn problem_for(outcome: &Outcome, client_ip: Option<IpAddr>, path: &str) -> Problem {
    match outcome {
        Outcome::Deny(detail) => {
            warn!(event = "filter_request_blocked", outcome = "failure", client_ip = ?client_ip, path, %detail);
            Problem::access_denied(detail.clone())
        }
        // The detail is deliberately generic: a resolver outage is server
        // internals, and the specifics are already in the logs.
        Outcome::Undecided(_) | Outcome::Allow => {
            Problem::server_internal("Request filtering failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn a_refusal_becomes_a_403_naming_the_reason() {
        let response = problem_for(
            &Outcome::Deny("address 1.2.3.4 is not allowed".to_string()),
            None,
            "/newOrder",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A policy the server could not evaluate is the server's problem, not the
    /// client's: a 500 it may retry rather than a refusal it would believe.
    #[test]
    fn an_unknown_becomes_a_500() {
        let response = problem_for(&Outcome::Undecided("resolver down".to_string()), None, "/x")
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
