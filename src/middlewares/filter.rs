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
//!
//! It is also recorded onto the server-wide `request` span, overwriting the
//! peer address [`middlewares::access`](crate::middlewares::access) seeded
//! there — so the access line names the client rather than the reverse proxy
//! wherever `filter.trusted_proxies` says one is in front. That record is why
//! this middleware carries no `#[instrument]`; see the call site.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{Span, field, warn};

use crate::error::Problem;
use crate::filter::{ClientIp, ConnectionContext, FilterPolicy, Outcome};

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

    // Overwrites the peer address `middlewares::access` seeded onto the
    // `request` span. This is the first layer that knows
    // `filter.trusted_proxies`, so it is the first that can name the client
    // rather than the reverse proxy in front of it.
    //
    // `Span::current()` is the `request` span itself, which is why this
    // function carries no `#[instrument]`: the attribute would open a child
    // span, and the record would land on a span that never declared the field
    // and be silently dropped — the bug the module doc of `access` describes
    // `request_id` having had.
    if let Some(ip) = client_ip {
        Span::current().record("client_ip", field::display(ip));
    }

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
    use axum::{Router, middleware, routing::get};
    use tower::ServiceExt;

    use crate::filter::{Effect, ProxyPolicy};

    /// The two layers as `build_router` stacks them: the access middleware
    /// outermost (it owns the `request` span), this one inside it.
    fn app(trusted: &[String]) -> Router {
        let proxy = ProxyPolicy::new(trusted, "x-forwarded-for").expect("policy must build");
        let policy = Arc::new(FilterPolicy::new(
            Vec::new(),
            Vec::new(),
            Effect::Allow,
            proxy,
        ));

        Router::new()
            .route("/x", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                policy,
                add_filter_middleware,
            ))
            .layer(middleware::from_fn(
                crate::middlewares::access::add_access_middleware,
            ))
    }

    fn request(peer: [u8; 4], forwarded: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/x");
        if let Some(value) = forwarded {
            builder = builder.header("x-forwarded-for", value);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 4711))));
        request
    }

    /// The whole point of recording here rather than in the access layer:
    /// behind a trusted reverse proxy, the peer address names the proxy, and an
    /// access line naming the proxy on every request identifies nobody.
    #[tokio::test]
    async fn a_trusted_proxys_forwarded_client_replaces_the_peer_on_the_span() {
        let app = app(&["10.0.0.0/8".to_string()]);
        let fields = crate::testutil::capture_request_span(
            app.oneshot(request([10, 0, 0, 1], Some("198.51.100.9"))),
        )
        .await;

        assert_eq!(fields.get("client_ip").as_deref(), Some("198.51.100.9"));
    }

    /// The converse, and the one that would otherwise pass for the wrong
    /// reason: an untrusted peer's header is not believed, so the seeded peer
    /// address stands.
    #[tokio::test]
    async fn an_untrusted_peers_forwarded_header_is_ignored() {
        let app = app(&[]);
        let fields = crate::testutil::capture_request_span(
            app.oneshot(request([203, 0, 113, 5], Some("198.51.100.9"))),
        )
        .await;

        assert_eq!(fields.get("client_ip").as_deref(), Some("203.0.113.5"));
    }

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
