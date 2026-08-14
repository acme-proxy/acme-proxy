//! Admission control and a request deadline for the ACME routes.
//!
//! ## Why not `tower`'s own layers
//!
//! `GlobalConcurrencyLimitLayer` — which this replaces — acquires its permit in
//! `poll_ready` and *waits*. Past the limit a request does not fail, it queues,
//! however long that takes: a client that gave up minutes ago still costs a
//! permit, a connection and a SQLite handle when its turn finally comes. With
//! `axum::serve` accepting connections without bound, the knob that looks like
//! backpressure is an unbounded queue. What is wanted is "absorb a burst, then
//! refuse", which a bare `LoadShedLayer` cannot express — it sheds the instant
//! the inner service is not ready — and which `LoadShedLayer` +
//! `HandleErrorLayer` reaches only through error-type gymnastics.
//!
//! The deadline is here rather than in `tower_http`'s timeout layer for the
//! reason the two fallbacks in `build_router` exist: every refusal this server
//! makes is an `application/problem+json` document, and that layer's is an empty
//! body. One `from_fn` gives both, composes with the four already in the router,
//! and needs no new crate feature.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    http::{Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::Semaphore;
use tracing::warn;

use crate::error::Problem;

/// The shared state of the admission middleware: a fixed number of slots, and
/// the two budgets that decide what happens when they are all taken.
#[derive(Clone)]
pub struct Admission {
    permits: Arc<Semaphore>,
    wait: Duration,
    deadline: Duration,
}

impl Admission {
    #[must_use]
    pub fn new(max_concurrent: usize, wait_ms: u64, deadline_ms: u64) -> Self {
        // A limit of zero would refuse every request forever, which is never
        // what an operator meant by writing it.
        let max_concurrent = max_concurrent.max(1);
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent)),
            wait: Duration::from_millis(wait_ms),
            deadline: Duration::from_millis(deadline_ms),
        }
    }

    /// Slots currently free. Test-facing.
    #[must_use]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// How long a shed client is asked to wait. Small and fixed: the condition is
/// transient by construction — a slot frees as soon as any in-flight request
/// finishes — and a longer hint would push a legitimate renewal past its
/// deadline for no reason.
const RETRY_AFTER_SECONDS: &str = "5";

pub async fn admission_middleware(
    State(admission): State<Admission>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let Ok(Ok(_permit)) = tokio::time::timeout(
        admission.wait,
        Arc::clone(&admission.permits).acquire_owned(),
    )
    .await
    else {
        warn!(event = "request_shed", outcome = "failure", method = %method, path = %path);
        let mut response = Problem::service_unavailable(
            "The server is at capacity and did not process this request; retry shortly",
        )
        .into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_static(RETRY_AFTER_SECONDS),
        );
        return response;
    };

    // The permit is held for the whole of `next.run`, and dropped with
    // `_permit` on every path out of this function — including the timeout
    // below, where the handler's future is dropped rather than awaited.
    match tokio::time::timeout(admission.deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            warn!(
                event = "request_deadline_exceeded",
                outcome = "failure",
                method = %method,
                path = %path,
                deadline_ms = crate::millis(admission.deadline),
            );
            Problem::server_internal("The request took too long to process").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::{Router, body::to_bytes, middleware, routing::get};
    use tower::ServiceExt;

    fn app(admission: Admission, handler_delay_ms: u64) -> Router {
        Router::new()
            .route(
                "/slow",
                get(move || async move {
                    tokio::time::sleep(Duration::from_millis(handler_delay_ms)).await;
                    "done"
                }),
            )
            .layer(middleware::from_fn_with_state(
                admission,
                admission_middleware,
            ))
    }

    async fn get_slow(app: &Router) -> Response {
        app.clone()
            .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_request_that_fits_is_served_normally() {
        let response = get_slow(&app(Admission::new(1, 50, 10_000), 0)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The whole point: past the limit a request is *refused*, not parked.
    ///
    /// `admission_wait_ms = 0` so the second request does not wait for the
    /// first, which is what makes this deterministic rather than a race.
    #[tokio::test]
    async fn a_request_past_the_limit_is_shed_rather_than_queued() {
        let app = app(Admission::new(1, 0, 10_000), 300);

        let first = tokio::spawn({
            let app = app.clone();
            async move { get_slow(&app).await }
        });
        // Let the first request take the only permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let shed = get_slow(&app).await;
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            shed.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "a refusal must still be a problem document"
        );
        assert_eq!(
            shed.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some(RETRY_AFTER_SECONDS)
        );
        let body = to_bytes(shed.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["status"], 503);
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:serverInternal");

        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    }

    /// A burst shorter than `admission_wait_ms` is absorbed rather than refused
    /// — the difference between this and a bare load-shedder.
    #[tokio::test]
    async fn a_short_burst_waits_for_a_slot_instead_of_being_refused() {
        let app = app(Admission::new(1, 1_000, 10_000), 100);

        let first = tokio::spawn({
            let app = app.clone();
            async move { get_slow(&app).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(get_slow(&app).await.status(), StatusCode::OK);
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_past_its_deadline_answers_a_problem_document() {
        let response = get_slow(&app(Admission::new(4, 50, 30), 5_000)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
        );
    }

    /// A shed or timed-out request must give its slot back, or the limit walks
    /// down to zero and the server never recovers.
    #[tokio::test]
    async fn a_timed_out_request_releases_its_slot() {
        let admission = Admission::new(1, 50, 30);
        let app = app(admission.clone(), 5_000);

        assert_eq!(
            get_slow(&app).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // The permit is released when the guard drops, which happens as this
        // returns — not when the abandoned handler future eventually finishes.
        assert_eq!(admission.available(), 1);
    }

    #[tokio::test]
    async fn a_limit_of_zero_still_serves_requests() {
        assert_eq!(Admission::new(0, 50, 10_000).available(), 1);
    }
}
