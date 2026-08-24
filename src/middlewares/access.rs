//! Request correlation and access logging.
//!
//! Assigns or propagates an `x-request-id` header, opens the `request` span
//! every other log line of that request is nested under, and emits the one
//! access line per request (`event = "request_completed"`).
//!
//! The span names the client twice over, and both halves are load-bearing. This
//! layer seeds `client_ip` from the peer address, which is the only source the
//! routes outside every profile router have — `/health`, the http-01 responder
//! and the admission-control refusals. The per-profile filter middleware then
//! overwrites it with the address `ProxyPolicy` resolved, since
//! `filter.trusted_proxies` is per-profile configuration and a request through
//! a trusted reverse proxy would otherwise be attributed to the proxy.
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

use std::net::SocketAddr;
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
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

/// Longest `x-request-id` accepted from a caller.
///
/// `crate::audit::USER_AGENT_MAX`'s reasoning, for a header that goes further:
/// a UUID is 36 characters and the longest correlation id any reverse proxy
/// generates is well inside this, while the value reaches the `request` span
/// (so every log line of the request), the response header, and the
/// `request_id` column of both `audit_log` and `upstream_orders`. Unbounded, an
/// unauthenticated caller decides how large all four of those get.
const REQUEST_ID_MAX: usize = 128;

/// Whether `value` is safe to adopt as this request's correlation id.
///
/// Deliberately narrower than "printable": the id is interpolated into the
/// non-JSON `tracing` format as `request_id=<value>`, where a space or an `=`
/// lets a caller write fields that were never emitted. Restricting to the
/// characters correlation ids actually use costs nothing real and takes the
/// question away.
fn usable_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REQUEST_ID_MAX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub async fn add_access_middleware(mut request: Request<Body>, next: Next) -> impl IntoResponse {
    let id_str = match request.headers().get(&X_REQUEST_ID) {
        Some(value) => match value.to_str() {
            Ok(value) => {
                let value = value.trim();
                if usable_request_id(value) {
                    value.to_string()
                } else {
                    // Too long, empty, or carrying characters that would let
                    // the caller forge log structure. A fresh id rather than a
                    // truncation: half of somebody's correlation id correlates
                    // with nothing and reads like a real one.
                    debug!(event = "request_id_header_invalid", outcome = "failure");
                    String::new()
                }
            }
            Err(_) => {
                // Non-ASCII bytes in the header. Falling back to a fresh id is
                // right — but silently, an operator correlating with the
                // reverse proxy's own logs would find nothing and have no clue
                // why.
                debug!(event = "request_id_header_invalid", outcome = "failure");
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

    // The peer address, canonicalized the way `ProxyPolicy::resolve` does, so
    // the two sources of this field never disagree on the spelling of a
    // v4-mapped v6 address (the dual-stack `[::]:3000` bind sees every IPv4
    // client as `::ffff:…`).
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| crate::filter::canonical(addr.ip()));

    // `profile` is filled in by each profile router (see `build_router`): this
    // layer is server-wide and mounted above the `/profile/<name>` nesting, so
    // it is not yet known here.
    //
    // `client_ip` is seeded here with the *peer* and overwritten by the filter
    // middleware with the `ProxyPolicy`-resolved address, because
    // `filter.trusted_proxies` is per-profile configuration this layer cannot
    // see. Seeding it is not redundant: `/health`, the http-01 responder and
    // every admission-control refusal sit outside all profile routers, so
    // without it the routes that never reach a filter would name nobody.
    let span = info_span!(
        "request",
        method = %request.method(),
        uri = %request.uri(),
        version = ?request.version(),
        request_id = %id_str,
        profile = field::Empty,
        client_ip = field::Empty,
    );
    if let Some(peer) = peer {
        span.record("client_ip", field::display(peer));
    }

    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let latency_ms = crate::millis(started.elapsed());
    let status = response.status().as_u16();

    span.in_scope(|| {
        // The one event name emitted at three levels, and the one whose
        // `outcome` is the response status rather than the name: a 5xx is this
        // server failing, and every other status is it answering.
        if response.status().is_server_error() {
            warn!(
                event = "request_completed",
                outcome = "failure",
                status,
                latency_ms
            );
        } else if probe {
            debug!(
                event = "request_completed",
                outcome = "success",
                status,
                latency_ms
            );
        } else {
            info!(
                event = "request_completed",
                outcome = "success",
                status,
                latency_ms
            );
        }
    });

    if let Ok(header_val) = HeaderValue::from_str(&id_str) {
        response.headers_mut().insert(X_REQUEST_ID, header_val);
    } else {
        // Only reachable for a client-supplied id: a generated UUID is always a
        // valid header value.
        debug!(event = "request_id_header_not_returned", outcome = "success", request_id = %id_str);
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

    /// Drives one request under a subscriber capturing the `request` span, and
    /// returns what it recorded.
    async fn fields_for(request: Request<Body>) -> crate::testutil::SpanFields {
        crate::testutil::capture_request_span(app().oneshot(request)).await
    }

    /// The seeded half: with no filter middleware in front, the peer address is
    /// the only thing that can name the client — this is what `/health` and the
    /// http-01 responder get.
    #[tokio::test]
    async fn the_peer_address_is_recorded_as_the_client() {
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 4711))));

        let fields = fields_for(req).await;

        assert_eq!(fields.get("client_ip").as_deref(), Some("192.0.2.7"));
    }

    /// The dual-stack `[::]:3000` bind sees IPv4 clients as `::ffff:…`. The
    /// access line must spell them the same way `ProxyPolicy::resolve` does, or
    /// one address reads as two across the two layers that write this field.
    #[tokio::test]
    async fn a_v4_mapped_peer_is_canonicalized() {
        let mapped: std::net::IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((mapped, 4711))));

        let fields = fields_for(req).await;

        assert_eq!(fields.get("client_ip").as_deref(), Some("192.0.2.7"));
    }

    /// A router driven through `oneshot` has no socket, so there is no peer to
    /// name. The field stays empty rather than being recorded as some
    /// placeholder an operator would read as an address.
    #[tokio::test]
    async fn no_connect_info_leaves_the_client_unnamed() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let fields = fields_for(req).await;

        assert_eq!(fields.get("client_ip"), None);
        // The span was captured at all — otherwise the assertion above passes
        // for the wrong reason.
        assert!(fields.get("request_id").is_some());
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

    /// An oversized id is not truncated but replaced.
    ///
    /// The value reaches the `request` span, the response header and two
    /// database columns, so an unauthenticated caller must not decide how large
    /// any of them get. Truncating would be worse than replacing: half of
    /// somebody's correlation id still looks like one and correlates with
    /// nothing.
    #[tokio::test]
    async fn an_oversized_request_id_is_replaced() {
        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", "a".repeat(REQUEST_ID_MAX + 1))
            .body(Body::empty())
            .unwrap();

        let res = app().oneshot(req).await.unwrap();

        let id = res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap();
        assert_eq!(id.len(), Uuid::new_v4().to_string().len());

        // The boundary itself is accepted, so the ceiling is a ceiling and not
        // an off-by-one.
        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", "b".repeat(REQUEST_ID_MAX))
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(
            res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap(),
            "b".repeat(REQUEST_ID_MAX)
        );
    }

    /// A caller must not be able to write log *structure*.
    ///
    /// Under the non-JSON `tracing` format the id is rendered as
    /// `request_id=<value>`, so a space or an `=` in the value lets the caller
    /// append fields that were never emitted — and a newline lets it write a
    /// whole line. Each of these is replaced by a generated id.
    #[tokio::test]
    async fn a_request_id_that_could_forge_log_structure_is_replaced() {
        let generated = Uuid::new_v4().to_string().len();
        for forged in [
            "abc outcome=success",
            "abc=def",
            "abc\tstatus=200",
            "abc\"quoted\"",
        ] {
            let Ok(header) = HeaderValue::from_str(forged) else {
                continue;
            };
            let req = Request::builder()
                .uri("/test")
                .header("x-request-id", header)
                .body(Body::empty())
                .unwrap();

            let res = app().oneshot(req).await.unwrap();
            let id = res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap();
            assert_eq!(
                id.len(),
                generated,
                "`{forged}` must not be adopted verbatim"
            );
        }
    }

    /// The shapes a real correlation id takes are still adopted unchanged: a
    /// UUID, a hyphenated token, and the `trace:span` spelling some proxies use.
    #[tokio::test]
    async fn ordinary_correlation_ids_are_still_honoured() {
        for ordinary in [
            "550e8400-e29b-41d4-a716-446655440000",
            "custom-req-id-123",
            "trace.4bf92f:span_1",
        ] {
            let req = Request::builder()
                .uri("/test")
                .header("x-request-id", ordinary)
                .body(Body::empty())
                .unwrap();

            let res = app().oneshot(req).await.unwrap();
            assert_eq!(
                res.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap(),
                ordinary
            );
        }
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
