//! Admission control through the real router: what the server does when more
//! ACME requests arrive than it will serve at once, and what it does with one
//! that runs too long.
//!
//! The limit used to *queue*, so none of this was observable — a request past
//! the limit simply waited, forever if need be. These tests are about the three
//! properties that replaced that: a refusal is a problem document rather than a
//! hang, `/health` answers while the ACME endpoints are saturated, and a slot is
//! always given back.
//!
//! Every test holds a real `GET /crl` open against a read side that parks
//! inside `crl_der`, because that is what this server still does *inside* a
//! request: a `custom` signer's `crl` and `renewal_info` script hooks, the one
//! pair `check_request_timeout` still refuses a short deadline for. So a gated
//! read side holds a genuine ACME request open rather than simulating one.
//!
//! It used to be a blocking `POST /chall/{id}`, then a blocking finalize: each
//! was an inline hook until it moved into the job queue — a probe of a
//! client-chosen host, then the signing itself, which now happens only in the
//! process holding the key. Neither holds an admission permit any more, and
//! with each the suite lost a subject.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt;

mod common;
use acme_proxy::filter::FilterPolicy;
use common::{
    GatedCrlSigner, body_json, challenges_with, default_challenges, no_notifications, p,
    test_app_full, test_app_with_challenges,
};

use acme_proxy_core::config::Config;

async fn post(app: &Router, path: &str, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// A config with the admission knobs set for a test, everything else default.
fn admission_config(max_concurrent: usize, wait_ms: u64, timeout_ms: u64) -> Config {
    let mut config = Config::default();
    config.server.max_concurrent_requests = max_concurrent;
    config.server.admission_wait_ms = wait_ms;
    config.server.request_timeout_ms = timeout_ms;
    config
}

/// The full router over `backend`, with the admission knobs a test set.
///
/// `test_app_with_signer` takes no `Config`, and every test here turns one of
/// those knobs down, so this goes through `test_app_full` directly.
async fn gated_app(
    config: Config,
    backend: GatedCrlSigner,
) -> (Router, std::sync::Arc<acme_proxy::sqlite::db::Database>) {
    test_app_full(
        config,
        Arc::new(backend),
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications().await,
    )
    .await
}

/// Sends a `GET /crl` that parks inside the read side, holding its slot.
fn hold_a_slot(app: &Router) -> tokio::task::JoinHandle<Response> {
    let app = app.clone();
    tokio::spawn(async move { get(&app, &p("/crl")).await })
}

/// Past the limit, a request is refused with a problem document — not parked.
#[tokio::test]
async fn a_request_past_the_limit_is_refused_with_a_problem_document() {
    let backend = GatedCrlSigner::new().await;
    let (gate, entered) = backend.handles();
    // One slot, and no willingness to wait for it, so this is deterministic.
    let (app, _db) = gated_app(admission_config(1, 0, 30_000), backend).await;

    let held = hold_a_slot(&app);
    // Wait for it to be genuinely inside the read holding the only slot,
    // rather than for a duration and a hope.
    let _ = entered.acquire().await.unwrap();

    let shed = get(&app, &p("/directory")).await;
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        shed.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
    );
    assert!(
        shed.headers().contains_key("retry-after"),
        "a shed client must be told when to come back"
    );
    let problem = body_json(shed).await;
    assert_eq!(problem["status"], 503);

    gate.add_permits(1);
    assert_eq!(held.await.unwrap().status(), StatusCode::OK);
}

/// The point of moving `/health` out of the limit: a probe must answer *while*
/// the ACME endpoints are saturated, or a load balancer learns nothing from it
/// exactly when it needs to.
#[tokio::test]
async fn health_answers_while_the_acme_endpoints_are_saturated() {
    let backend = GatedCrlSigner::new().await;
    let (gate, entered) = backend.handles();
    let (app, _db) = gated_app(admission_config(1, 0, 30_000), backend).await;

    let held = hold_a_slot(&app);
    let _ = entered.acquire().await.unwrap();

    // The ACME side is full…
    assert_eq!(
        get(&app, &p("/directory")).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // …and the health probe is unaffected.
    assert_eq!(get(&app, "/health").await.status(), StatusCode::OK);

    gate.add_permits(1);
    held.await.unwrap();
}

/// A slot taken by a request that timed out has to come back, or the limit
/// walks down to zero and the server never recovers.
#[tokio::test]
async fn a_slot_is_released_after_a_request_exceeds_its_deadline() {
    let backend = GatedCrlSigner::new().await;
    let (gate, entered) = backend.handles();
    // One slot; a deadline short enough that the parked read trips it.
    let (app, _db) = gated_app(admission_config(1, 500, 200), backend).await;

    let timed_out = get(&app, &p("/crl")).await;
    assert_eq!(timed_out.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // The deadline came from the parked read and not from somewhere else on
    // the way in — otherwise the slot being free below proves nothing about
    // the case this test is named for.
    assert_eq!(
        entered.available_permits(),
        1,
        "the request must have reached the read side before its deadline fired"
    );
    assert_eq!(
        timed_out
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
        "even a deadline is answered as a problem document, not an empty body",
    );

    // The slot is free again: an ordinary request goes straight through.
    assert_eq!(get(&app, &p("/directory")).await.status(), StatusCode::OK);
    gate.add_permits(1);
}

/// A body larger than `server.max_body_bytes` is refused before it is parsed.
#[tokio::test]
async fn an_oversized_request_body_is_refused() {
    let mut config = admission_config(100, 50, 30_000);
    config.server.max_body_bytes = 1024;
    let (app, _db) = test_app_with_challenges(config, challenges_with(&["http-01"], vec![])).await;

    let body = "x".repeat(64 * 1024);
    let res = post(&app, &p("/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
