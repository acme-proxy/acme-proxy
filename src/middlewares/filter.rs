//! Request-filtering middleware.
//!
//! Runs the connection hook of every configured [`Filter`](crate::filter::Filter)
//! before the request reaches a handler, and records the client address so the
//! handlers can pass it to the identifier hook later in the flow.
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
use crate::filter::{ClientIp, ConnectionContext, FilterChain, FilterError};

#[instrument(name = "add_filter_middleware", skip_all, fields(path = %request.uri().path()))]
pub async fn add_filter_middleware(
    State(chain): State<Arc<FilterChain>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let client_ip = chain.proxy().resolve(peer, request.headers());
    request.extensions_mut().insert(ClientIp(client_ip));

    let path = request.uri().path().to_string();
    if chain.is_exempt(&path) {
        return next.run(request).await;
    }

    let context = ConnectionContext {
        client_ip,
        method: request.method(),
        path: &path,
    };

    if let Err(error) = chain.check_connection(&context).await {
        return problem_for(error, client_ip, &path).into_response();
    }

    next.run(request).await
}

/// Maps a connection-hook refusal to its ACME error document.
///
/// A denial is a decision about the client (403); an `Internal` means the
/// server could not decide, which is its problem and not the client's, so it
/// gets a 500 the client may retry.
fn problem_for(error: FilterError, client_ip: Option<IpAddr>, path: &str) -> Problem {
    match error {
        FilterError::Denied(detail) => {
            warn!(event = "request_blocked", client_ip = ?client_ip, path, %detail);
            Problem::access_denied(detail)
        }
        // The detail is deliberately generic: a resolver outage is server
        // internals, and the specifics are already in the logs.
        FilterError::Internal(_) => Problem::server_internal("Request filtering failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Filter, ProxyPolicy};
    use async_trait::async_trait;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    struct Denying;

    #[async_trait]
    impl Filter for Denying {
        fn name(&self) -> &'static str {
            "denying"
        }
        async fn check_connection(&self, _ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
            Err(FilterError::Denied("nope".to_string()))
        }
    }

    #[test]
    fn a_denial_becomes_a_403_naming_the_reason() {
        let response = problem_for(
            FilterError::Denied("address 1.2.3.4 is not allowed".to_string()),
            None,
            "/newOrder",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn an_internal_failure_becomes_a_500() {
        let response = problem_for(
            FilterError::Internal("resolver down".to_string()),
            None,
            "/x",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn exempt_paths_are_recognised() {
        let chain = FilterChain::new(
            vec![Arc::new(Denying)],
            vec!["/health".to_string()],
            ProxyPolicy::default(),
        );
        assert!(chain.is_exempt("/health"));
        assert!(!chain.is_exempt("/directory"));
    }
}
