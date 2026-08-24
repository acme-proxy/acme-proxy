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
//! Every test drives a real `POST /chall/{id}`, because challenge validation is
//! one of the two things this server does *inside* a request — so a blocking
//! validator holds a genuine ACME request open rather than simulating one.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    BlockingValidator, EcSigner, TestSigner, body_json, challenges_with, fetch_nonce, p,
    test_app_with_challenges,
};

use acme_proxy::config::Config;

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";

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

/// Registers an account, opens an order and returns the URL of its first
/// challenge — the request that will block once triggered.
async fn ready_challenge(app: &Router, signer: &EcSigner) -> (String, String) {
    let nonce = fetch_nonce(app).await;
    let res = post(
        app,
        &p("/newAccount"),
        signer.sign(
            NEW_ACCOUNT_URL,
            &nonce,
            &json!({ "termsOfServiceAgreed": true }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let account_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let nonce = fetch_nonce(app).await;
    let order = body_json(
        post(
            app,
            &p("/newOrder"),
            signer.sign_kid(
                &account_url,
                NEW_ORDER_URL,
                &nonce,
                &json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] }),
            ),
        )
        .await,
    )
    .await;

    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let nonce = fetch_nonce(app).await;
    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let authz: Value = body_json(
        post(
            app,
            authz_path,
            signer.sign_kid_empty(&account_url, &authz_url, &nonce),
        )
        .await,
    )
    .await;

    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
    (account_url, challenge_url)
}

async fn trigger(app: &Router, signer: &EcSigner, account_url: &str, url: &str) -> Response {
    let (path, body) = signed_trigger(app, signer, account_url, url).await;
    post(app, &path, body).await
}

/// The path and signed body of a challenge trigger, ready to send later.
async fn signed_trigger(
    app: &Router,
    signer: &EcSigner,
    account_url: &str,
    url: &str,
) -> (String, String) {
    let nonce = fetch_nonce(app).await;
    let path = url.strip_prefix(common::HOST).unwrap().to_string();
    (path, signer.sign_kid(account_url, url, &nonce, &json!({})))
}

/// Past the limit, a request is refused with a problem document — not parked.
#[tokio::test]
async fn a_request_past_the_limit_is_refused_with_a_problem_document() {
    let validator = BlockingValidator::new("http-01");
    let (_calls, gate, entered) = validator.handles();
    // One slot, and no willingness to wait for it, so this is deterministic.
    let (app, _db) = test_app_with_challenges(
        admission_config(1, 0, 30_000),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;

    let signer = EcSigner::new();
    let (account_url, challenge_url) = ready_challenge(&app, &signer).await;

    // The JWS is built here rather than in the task: `EcSigner` is not `Clone`,
    // and signing needs a nonce, which needs a request — which would itself
    // need a slot.
    let (path, body) = signed_trigger(&app, &signer, &account_url, &challenge_url).await;
    let held = tokio::spawn({
        let app = app.clone();
        async move { post(&app, &path, body).await }
    });
    // Wait for it to be genuinely inside the validator holding the only slot,
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
    let validator = BlockingValidator::new("http-01");
    let (_calls, gate, entered) = validator.handles();
    let (app, _db) = test_app_with_challenges(
        admission_config(1, 0, 30_000),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;

    let signer = EcSigner::new();
    let (account_url, challenge_url) = ready_challenge(&app, &signer).await;

    // The JWS is built here rather than in the task: `EcSigner` is not `Clone`,
    // and signing needs a nonce, which needs a request — which would itself
    // need a slot.
    let (path, body) = signed_trigger(&app, &signer, &account_url, &challenge_url).await;
    let held = tokio::spawn({
        let app = app.clone();
        async move { post(&app, &path, body).await }
    });
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
    let validator = BlockingValidator::new("http-01");
    let (_calls, gate, entered) = validator.handles();
    // One slot; a deadline short enough that the blocked validation trips it.
    let (app, _db) = test_app_with_challenges(
        admission_config(1, 500, 200),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;

    let signer = EcSigner::new();
    let (account_url, challenge_url) = ready_challenge(&app, &signer).await;

    let timed_out = trigger(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(timed_out.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // The deadline came from the blocked validation and not from somewhere
    // else on the way in — otherwise the slot being free below proves nothing
    // about the case this test is named for.
    assert_eq!(
        entered.available_permits(),
        1,
        "the request must have reached the validator before its deadline fired"
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
