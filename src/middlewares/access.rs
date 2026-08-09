//! Request correlation and access logging.
//!
//! Assigns or propagates an `x-request-id` header, opens the `request` span
//! every other log line of that request is nested under, and emits the one
//! access line per request (`event = "request_completed"`).
//!
//! Both halves live in one middleware on purpose. They used to be two — this
//! `x-request-id` layer plus a `tower_http::trace::TraceLayer` built inside
//! each profile's router — and the split cost three things:
//!
//! - the id never reached the span. `Span::current().record("request_id", …)`
//!   ran here, *outside* the span `TraceLayer` had not created yet, so it wrote
//!   to nothing;
//! - the root routes (`/health`, `/`, the http-01 responder) and the
//!   admission-control layer sat outside the profile routers entirely, so
//!   `request_shed` and `request_deadline_exceeded` — the two events an
//!   operator most wants to correlate — carried no id at all;
//! - `DefaultOnResponse` emits under the `tower_http::trace::on_response`
//!   target, which the shipped `logging.filter` set to `warn`. The access line
//!   was configured at `INFO` and silenced by default.
//!
//! Writing the access line by hand also buys what `TraceLayer` structurally
//! cannot: `on_response` receives `(&Response, Latency, &Span)` and never the
//! request, so it cannot vary its level by path — and a liveness probe once a
//! second must not drown the info stream.

use std::time::Instant;

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request},
    middleware::Next,
    response::IntoResponse,
};
use tracing::{Instrument, debug, field, info, info_span, warn};
use uuid::Uuid;

pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Extension wrapper for the HTTP Request ID.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Returns true for the probe routes whose access line belongs at `debug`.
///
/// `/health` is polled by a load balancer, `/` only redirects to it. Neither
/// says anything about ACME, and at one probe per second per node they would
/// be most of the log.
fn is_probe(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD) && matches!(path, "/health" | "/")
}

pub async fn add_access_middleware(mut request: Request<Body>, next: Next) -> impl IntoResponse {
    let id_str = match request.headers().get(&X_REQUEST_ID) {
        Some(value) => match value.to_str() {
            Ok(value) => value.trim().to_string(),
            Err(_) => {
                // Non-ASCII bytes in the header. Falling back to a fresh id is
                // right — but silently, an operator correlating with the
                // reverse proxy's own logs would find nothing and have no clue
                // why.
                debug!(event = "request_id_header_invalid");
                String::new()
            }
        },
        None => String::new(),
    };

    let id_str = if id_str.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        id_str
    };

    request.extensions_mut().insert(RequestId(id_str.clone()));

    let probe = is_probe(request.method(), request.uri().path());

    // `profile` is filled in by each profile router (see `build_router`): this
    // layer is server-wide and mounted above the `/profile/<name>` nesting, so
    // it is not yet known here.
    let span = info_span!(
        "request",
        method = %request.method(),
        uri = %request.uri(),
        version = ?request.version(),
        request_id = %id_str,
        profile = field::Empty,
    );

    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let latency_ms = crate::millis(started.elapsed());
    let status = response.status().as_u16();

    span.in_scope(|| {
        if response.status().is_server_error() {
            warn!(event = "request_completed", status, latency_ms);
        } else if probe {
            debug!(event = "request_completed", status, latency_ms);
        } else {
            info!(event = "request_completed", status, latency_ms);
        }
    });

    if let Ok(header_val) = HeaderValue::from_str(&id_str) {
        response.headers_mut().insert(X_REQUEST_ID, header_val);
    } else {
        // Only reachable for a client-supplied id: a generated UUID is always a
        // valid header value.
        debug!(event = "request_id_header_not_returned", request_id = %id_str);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, middleware, routing::get};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .route("/health", get(|| async { "ok" }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
            .layer(middleware::from_fn(add_access_middleware))
    }

    #[tokio::test]
    async fn request_id_header_generated_when_absent() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let res = app().oneshot(req).await.unwrap();

        assert!(res.headers().contains_key(&X_REQUEST_ID));
    }

    #[tokio::test]
    async fn request_id_header_preserved_when_present() {
        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", "custom-req-id-123")
            .body(Body::empty())
            .unwrap();

        let res = app().oneshot(req).await.unwrap();

        let id = res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap();
        assert_eq!(id, "custom-req-id-123");
    }

    /// A header whose bytes are not ASCII cannot be read back as a string, so
    /// the middleware falls back to a generated id rather than propagating a
    /// value it cannot echo.
    #[tokio::test]
    async fn a_non_ascii_request_id_is_replaced() {
        let req = Request::builder()
            .uri("/test")
            .header(
                "x-request-id",
                HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
            )
            .body(Body::empty())
            .unwrap();

        let res = app().oneshot(req).await.unwrap();

        let id = res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap();
        assert_eq!(id.len(), Uuid::new_v4().to_string().len());
    }

    /// Whitespace-only is as good as absent — otherwise the id echoed back is
    /// an empty string, which correlates nothing.
    #[tokio::test]
    async fn a_blank_request_id_is_replaced() {
        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", "   ")
            .body(Body::empty())
            .unwrap();

        let res = app().oneshot(req).await.unwrap();

        let id = res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap();
        assert!(!id.trim().is_empty());
    }

    /// The three access-line levels, driven end to end. Nothing here asserts on
    /// the emitted record — the point is that each branch runs.
    #[tokio::test]
    async fn every_access_line_level_is_reachable() {
        for (uri, expected) in [
            ("/test", StatusCode::OK),
            ("/health", StatusCode::OK),
            ("/boom", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let res = app().oneshot(req).await.unwrap();
            assert_eq!(res.status(), expected);
        }
    }

    #[test]
    fn probe_routes_are_recognized() {
        assert!(is_probe(&Method::GET, "/health"));
        assert!(is_probe(&Method::HEAD, "/health"));
        assert!(is_probe(&Method::GET, "/"));
        assert!(!is_probe(&Method::POST, "/health"));
        assert!(!is_probe(&Method::GET, "/directory"));
    }
}
