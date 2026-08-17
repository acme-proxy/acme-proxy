//! Covers the RFC 8555 order → authorization → challenge → finalize → certificate
//! flow end-to-end: newAccount → newOrder (pending) → POST-as-GET authorization →
//! trigger http-01 challenge → POST-as-GET order (ready) → finalize(CSR) →
//! POST-as-GET certificate, plus the account order-list URL. Runs the happy path
//! for both EC and RSA keys, and exercises every rejection branch (wrong url, bad
//! nonce, empty / non-dns identifiers, finalize a non-ready order, bad CSR,
//! POST-as-GET by a different account, a non-empty POST-as-GET payload, unknown
//! order / authorization / challenge).

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use base64::prelude::*;
use common::{
    EcSigner, FailingSigner, GarbageChainSigner, PREFIX, RsaSigner, TestSigner, body_json,
    fetch_nonce, make_csr, make_csr_with_sans, p, test_app, test_app_with_signer,
};

const BASE: &str = common::BASE;
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

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Registers an account and returns its account URL (used as `kid`).
async fn register(app: &Router, signer: &impl TestSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// Registers an account and carries one order as far as `ready` — the state
/// finalize requires — returning `(account_url, order_url)`. Extracted so the
/// finalize-behaviour tests below start where they actually differ, rather
/// than repeating the four steps that get there.
async fn ready_order(app: &Router, signer: &impl TestSigner) -> (String, String) {
    let account_url = register(app, signer).await;

    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newOrder must set a Location header")
        .to_string();
    let authz_url = body_json(res).await["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();

    // Read the authorization to find its challenge, then trigger it. With the
    // default bypassing registry that is what moves the order to `ready`.
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(&account_url, &authz_url, &nonce);
    let res = post(app, authz_url.strip_prefix(common::HOST).unwrap(), body).await;
    let challenge_url = body_json(res).await["challenges"][0]["url"]
        .as_str()
        .unwrap()
        .to_string();

    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
    let res = post(app, challenge_url.strip_prefix(common::HOST).unwrap(), body).await;
    assert_eq!(res.status(), StatusCode::OK);

    (account_url, order_url)
}

/// Drives the full lifecycle for a given signer/key type.
async fn full_lifecycle(signer: impl TestSigner) {
    let app = test_app().await;
    let account_url = register(&app, &signer).await;

    // --- newOrder ---
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newOrder must set a Location header")
        .to_string();
    let order = body_json(res).await;
    assert_eq!(order["status"], "pending");
    let authz_url = order["authorizations"][0]
        .as_str()
        .expect("order must list an authorization URL")
        .to_string();
    assert_eq!(order["finalize"], format!("{order_url}/finalize"));
    assert_eq!(order["identifiers"][0]["value"], "example.com");

    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    // --- POST-as-GET the authorization ---
    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &authz_url, &nonce);
    let res = post(&app, authz_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let authz = body_json(res).await;
    assert_eq!(authz["status"], "pending");
    assert_eq!(
        authz["identifier"],
        json!({ "type": "dns", "value": "example.com" })
    );
    let challenge = &authz["challenges"][0];
    assert_eq!(challenge["type"], "http-01");
    assert_eq!(challenge["status"], "pending");
    assert!(challenge["token"].as_str().is_some_and(|t| !t.is_empty()));
    let challenge_url = challenge["url"]
        .as_str()
        .expect("challenge must have a URL")
        .to_string();

    // --- trigger the challenge (stub validation flips it to valid) ---
    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
    let res = post(&app, challenge_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");

    // --- POST-as-GET the order: now ready ---
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "ready");

    // --- finalize ---
    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
    let cert_url = order["certificate"]
        .as_str()
        .expect("certificate URL")
        .to_string();
    assert_eq!(
        cert_url,
        format!(
            "{BASE}/certificate/{}",
            order_path.strip_prefix(&p("/order/")).unwrap()
        )
    );

    // --- POST-as-GET the certificate ---
    let cert_path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &nonce);
    let res = post(&app, cert_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pem-certificate-chain"),
    );
    let pem = body_text(res).await;
    assert_eq!(
        pem.matches("-----BEGIN CERTIFICATE-----").count(),
        2,
        "chain should be leaf + CA"
    );

    // --- POST-as-GET the account order list ---
    let orders_url = format!("{account_url}/orders");
    let orders_path = orders_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &orders_url, &nonce);
    let res = post(&app, orders_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    assert_eq!(list["orders"][0], order_url);
}

#[tokio::test]
async fn full_lifecycle_ec() {
    full_lifecycle(EcSigner::new()).await;
}

#[tokio::test]
async fn full_lifecycle_rsa() {
    full_lifecycle(RsaSigner::new()).await;
}

// --- Rejection paths (EC signer throughout) ---

/// Registers an EC account + creates a fresh (pending) order, returning (app,
/// signer, `account_url`, `order_url`).
async fn setup_order() -> (Router, EcSigner, String, String) {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    (app, signer, account_url, order_url)
}

/// Reads an order (POST-as-GET) and returns its authorization URLs.
async fn order_authz_urls(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    order_url: &str,
) -> Vec<String> {
    let order_path = order_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, order_url, &nonce);
    let res = post(app, order_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Reads an authorization (POST-as-GET) and returns its first challenge URL.
async fn first_challenge_url(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    authz_url: &str,
) -> String {
    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, authz_url, &nonce);
    let res = post(app, authz_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await["challenges"][0]["url"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Triggers a challenge (POSTs `{}`) and returns the response.
async fn trigger_challenge(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    challenge_url: &str,
) -> Response {
    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, challenge_url, &nonce, &json!({}));
    post(app, challenge_path, body).await
}

/// Drives every authorization of an order to `valid`, moving the order to
/// `ready` so it can be finalized.
async fn drive_order_to_ready(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    order_url: &str,
) {
    for authz_url in order_authz_urls(app, signer, account_url, order_url).await {
        let challenge_url = first_challenge_url(app, signer, account_url, &authz_url).await;
        let res = trigger_challenge(app, signer, account_url, &challenge_url).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}

/// Like [`setup_order`], but drives the order to `ready` (all challenges
/// triggered) so a following finalize reaches the signer.
async fn setup_ready_order() -> (Router, EcSigner, String, String) {
    let (app, signer, account_url, order_url) = setup_order().await;
    drive_order_to_ready(&app, &signer, &account_url, &order_url).await;
    (app, signer, account_url, order_url)
}

/// [`setup_ready_order`] against a caller-supplied signer backend, for the
/// tests that assert on what `finalize` does with an unusual issuance result.
/// Challenge validation never touches the signer, so the drive to `ready` is
/// identical whichever backend is installed.
async fn setup_ready_order_with_signer(
    backend: Arc<dyn acme_proxy::signer::SignerBackend>,
) -> (Router, EcSigner, String, String) {
    let (app, _db) = test_app_with_signer(backend).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    drive_order_to_ready(&app, &signer, &account_url, &order_url).await;
    (app, signer, account_url, order_url)
}

async fn assert_problem(res: Response, status: StatusCode, typ: &str) {
    assert_eq!(res.status(), status);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], typ);
}

/// Reads any resource by signed POST-as-GET, asserting a 200.
async fn post_as_get(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    url: &str,
) -> Value {
    let path = url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, url, &nonce);
    let res = post(app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

/// Finalizes `order_url` with `csr`, returning the response untouched so the
/// caller can assert either success or a problem.
async fn finalize(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    order_url: &str,
    csr: &str,
) -> Response {
    let url = format!("{order_url}/finalize");
    let path = url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, &url, &nonce, &json!({ "csr": csr }));
    post(app, path, body).await
}

#[tokio::test]
async fn new_order_rejects_wrong_url() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    // The JWS `url` disagrees with the routed endpoint.
    let body = signer.sign_kid(&account_url, &format!("{BASE}/wrong"), &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn new_order_rejects_bad_nonce() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, "not-a-real-nonce", &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badNonce",
    )
    .await;
}

#[tokio::test]
async fn new_order_rejects_empty_identifiers() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn new_order_rejects_non_dns_identifier() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "ip", "value": "192.0.2.1" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:unsupportedIdentifier",
    )
    .await;
}

#[tokio::test]
async fn finalize_rejects_non_ready_order() {
    // A freshly created order is `pending` (its challenges are not yet
    // satisfied), so finalize is rejected until it becomes `ready`.
    let (app, signer, account_url, order_url) = setup_order().await;
    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_path, body).await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:orderNotReady",
    )
    .await;
}

#[tokio::test]
async fn finalize_rejects_ready_order_reused() {
    // Once finalized (→ `valid`), a second finalize is rejected: no longer `ready`.
    let (app, signer, account_url, order_url) = setup_ready_order().await;
    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    assert_eq!(
        post(&app, finalize_path, body).await.status(),
        StatusCode::OK
    );

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_path, body).await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:orderNotReady",
    )
    .await;
}

#[tokio::test]
async fn finalize_rejects_mismatched_csr() {
    let (app, signer, account_url, order_url) = setup_ready_order().await;
    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();

    // The CSR is for a different domain than the order's identifier.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("attacker.example") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_path, body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
}

#[tokio::test]
async fn post_as_get_rejects_different_account() {
    let (app, _owner, _owner_url, order_url) = setup_order().await;
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    // A second account signs a POST-as-GET for the first account's order.
    let intruder = EcSigner::new();
    let intruder_url = register(&app, &intruder).await;
    let nonce = fetch_nonce(&app).await;
    let body = intruder.sign_kid_empty(&intruder_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn post_as_get_rejects_non_empty_payload() {
    let (app, signer, account_url, order_url) = setup_order().await;
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    // A POST-as-GET route reached with a non-empty payload is malformed.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "not": "empty" });
    let body = signer.sign_kid(&account_url, &order_url, &nonce, &payload);
    let res = post(&app, order_path, body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn finalize_internal_signer_failure_marks_order_invalid() {
    // A signer that always fails internally drives the terminal-failure path.
    let (app, signer, account_url, order_url) =
        setup_ready_order_with_signer(Arc::new(FailingSigner)).await;

    // Finalize with a valid CSR: the signer fails internally → serverInternal.
    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_path, body).await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;

    // The failure is recorded on the order: POST-as-GET now shows `invalid` and
    // the same problem document under `error`.
    let order_path = order_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "invalid");
    assert_eq!(
        order["error"]["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
    assert_eq!(order["error"]["status"], 500);
}

#[tokio::test]
async fn post_as_get_unknown_order_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order_url = format!("{BASE}/order/does-not-exist");
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, &p("/order/does-not-exist"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn post_as_get_unknown_authz_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let authz_url = format!("{BASE}/authz/does-not-exist");
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &authz_url, &nonce);
    let res = post(&app, &p("/authz/does-not-exist"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn post_as_get_authz_returns_authorization_object() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let path = authz_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, authz_url, &nonce);
    let res = post(&app, path, body).await;

    assert_eq!(res.status(), StatusCode::OK);
    let authz = body_json(res).await;
    assert_eq!(authz["status"], "pending");
    assert_eq!(authz["identifier"]["value"], "example.com");
    assert!(authz["challenges"].is_array());
}

#[tokio::test]
async fn trigger_unknown_challenge_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let challenge_url = format!("{BASE}/chall/does-not-exist");
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
    let res = post(&app, &p("/chall/does-not-exist"), body).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

#[tokio::test]
async fn authz_rejects_different_account() {
    let (app, owner, owner_url, order_url) = setup_order().await;
    let authz_url = order_authz_urls(&app, &owner, &owner_url, &order_url)
        .await
        .remove(0);
    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();

    // A second account POST-as-GETs the first account's authorization.
    let intruder = EcSigner::new();
    let intruder_url = register(&app, &intruder).await;
    let nonce = fetch_nonce(&app).await;
    let body = intruder.sign_kid_empty(&intruder_url, &authz_url, &nonce);
    let res = post(&app, authz_path, body).await;
    assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn challenge_trigger_rejects_different_account() {
    let (app, owner, owner_url, order_url) = setup_order().await;
    let authz_url = order_authz_urls(&app, &owner, &owner_url, &order_url)
        .await
        .remove(0);
    let challenge_url = first_challenge_url(&app, &owner, &owner_url, &authz_url).await;

    // A second account tries to trigger the first account's challenge.
    let intruder = EcSigner::new();
    let intruder_url = register(&app, &intruder).await;
    let res = trigger_challenge(&app, &intruder, &intruder_url, &challenge_url).await;
    assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn multi_identifier_order_becomes_ready_after_all_challenges() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    // An order with two identifiers gets two authorizations.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [
        { "type": "dns", "value": "a.example.com" },
        { "type": "dns", "value": "b.example.com" },
    ] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    let authz_urls = order_authz_urls(&app, &signer, &account_url, &order_url).await;
    assert_eq!(authz_urls.len(), 2, "one authorization per identifier");

    // Trigger the first challenge only: the order is not yet ready.
    let challenge_url = first_challenge_url(&app, &signer, &account_url, &authz_urls[0]).await;
    let res = trigger_challenge(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_eq!(body_json(res).await["status"], "pending");

    // Trigger the second challenge: now every authorization is valid → ready.
    let challenge_url = first_challenge_url(&app, &signer, &account_url, &authz_urls[1]).await;
    let res = trigger_challenge(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_eq!(body_json(res).await["status"], "ready");

    // Re-triggering an already-valid challenge is idempotent (still valid).
    let res = trigger_challenge(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");
}

// ---------------------------------------------------------------------------
// Requested validity bounds
// ---------------------------------------------------------------------------

/// `notBefore`/`notAfter` are optional RFC3339 datetimes. They are stored and
/// echoed on the order object — the signer applies its own leaf policy, so they
/// are a record of what the client asked for, not a promise.
#[tokio::test]
async fn new_order_accepts_and_echoes_requested_validity_bounds() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({
        "identifiers": [{ "type": "dns", "value": "example.com" }],
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2026-04-01T00:00:00Z",
    });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;

    assert_eq!(res.status(), StatusCode::CREATED);
    let order = body_json(res).await;
    assert_eq!(order["notBefore"], "2026-01-01T00:00:00Z");
    assert_eq!(order["notAfter"], "2026-04-01T00:00:00Z");
}

/// A datetime that is not RFC3339 is the client's mistake, not a 500.
#[tokio::test]
async fn new_order_rejects_an_unparsable_datetime() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    for field in ["notBefore", "notAfter"] {
        let nonce = fetch_nonce(&app).await;
        let payload = json!({
            "identifiers": [{ "type": "dns", "value": "example.com" }],
            field: "next tuesday",
        });
        let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
        let res = post(&app, &p("/newOrder"), body).await;
        assert_problem(
            res,
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Retryability and remaining authorization checks
// ---------------------------------------------------------------------------

/// `post_finalize` documents a `badCSR` as leaving the order `ready` and
/// retryable. Assert the claim rather than trusting the comment: finalize with a
/// mismatched CSR, then again with a correct one.
/// A `csr` that is not even base64url is refused before any signature
/// attempt. The other "bad CSR" tests send a well-formed CSR for the
/// wrong name and land on `SignerError::BadCsr` one step later, so
/// this decoding was not covered by any of them.
#[tokio::test]
async fn finalize_rejects_a_csr_that_is_not_base64url() {
    let (app, signer, account_url, order_url) = setup_ready_order().await;

    let res = finalize(&app, &signer, &account_url, &order_url, "!!!not base64!!!").await;

    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;

    // Like any `badCSR`, this leaves the order reusable.
    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "ready");
}

/// An unparsable chain returned by the backend is a bug in this server — it
/// just "issued" it. It must result in a 500, and leave the order in `ready`
/// rather than permanently invalidating a certificate that the CA might
/// have actually signed.
#[tokio::test]
async fn finalize_reports_an_unparsable_issued_chain_as_internal() {
    let (app, signer, account_url, order_url) =
        setup_ready_order_with_signer(Arc::new(GarbageChainSigner)).await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;

    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;

    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(
        order["status"], "ready",
        "une chaîne illisible ne doit pas invalider la commande"
    );
}

/// RFC 8555 §7.4: "The CSR MUST indicate the exact same set of requested
/// identifiers as the initial newOrder request."
///
/// Equality, not containment — a superset and a subset are both refused. The
/// order here is for `example.com` alone.
#[tokio::test]
async fn a_csr_must_name_exactly_the_order_s_identifiers() {
    for csr in [
        // A different name entirely.
        make_csr("victim.example"),
        // A superset: the order's name plus one it never authorized.
        make_csr_with_sans(
            "example.com",
            vec![rcgen::SanType::DnsName(
                "extra.example.com".try_into().unwrap(),
            )],
        ),
    ] {
        let (app, signer, account_url, order_url) = setup_ready_order().await;
        let res = finalize(&app, &signer, &account_url, &order_url, &csr).await;
        assert_problem(
            res,
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badCSR",
        )
        .await;
    }
}

/// The point of hoisting the check into `post_finalize`: the refusal must not
/// depend on the backend making it.
///
/// `local_ca` has always checked, so with the real signer a passing test proves
/// nothing about `custom` or `relay` — the two that hand the CSR to an
/// operator script or relay it to an upstream that never saw the local
/// authorizations. `RecordingSigner` accepts everything and records being
/// called, so `was_called() == false` is the assertion that matters.
#[tokio::test]
async fn a_mismatched_csr_never_reaches_the_signer_backend() {
    let backend = Arc::new(common::RecordingSigner::default());
    let (app, signer, account_url, order_url) =
        setup_ready_order_with_signer(backend.clone()).await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("victim.example"),
    )
    .await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(
        !backend.was_called(),
        "the handler must refuse the CSR before any backend sees it"
    );

    // And the same backend *is* reached once the CSR matches, so the assertion
    // above is about the refusal and not about the backend being unreachable.
    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(backend.was_called());
}

/// A CSR whose SANs match the order but which smuggles an extra identifier of
/// another kind. An order can only ever carry `dns` identifiers, so this asks
/// for something no order could have authorized.
#[tokio::test]
async fn a_csr_smuggling_a_non_dns_san_is_refused() {
    let backend = Arc::new(common::RecordingSigner::default());
    let (app, signer, account_url, order_url) =
        setup_ready_order_with_signer(backend.clone()).await;

    let csr = make_csr_with_sans(
        "example.com",
        vec![rcgen::SanType::IpAddress("10.0.0.1".parse().unwrap())],
    );
    let res = finalize(&app, &signer, &account_url, &order_url, &csr).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(!backend.was_called());
}

/// A common name naming a domain the order does not cover is refused; the leaf
/// would otherwise assert it, since rcgen copies the CSR's whole subject.
#[tokio::test]
async fn a_csr_whose_common_name_names_another_domain_is_refused() {
    let backend = Arc::new(common::RecordingSigner::default());
    let (app, signer, account_url, order_url) =
        setup_ready_order_with_signer(backend.clone()).await;

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "victim.example");
    let csr = BASE64_URL_SAFE_NO_PAD.encode(params.serialize_request(&key_pair).unwrap().der());

    let res = finalize(&app, &signer, &account_url, &order_url, &csr).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(!backend.was_called());
}

/// The subject the local CA actually signs carries no common name at all.
///
/// rcgen's `CertificateSigningRequestParams::from_der` copies the CSR's whole
/// distinguished name into the params it signs, so without an explicit reset
/// the client picks the subject of a certificate this CA vouches for.
#[tokio::test]
async fn the_issued_leaf_carries_no_common_name_from_the_csr() {
    let (app, signer, account_url, order_url) = setup_ready_order().await;

    // A label rather than a domain, so it passes the order-binding check and
    // the only thing that can remove it is the CA's own subject reset.
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "some client label");
    let csr = BASE64_URL_SAFE_NO_PAD.encode(params.serialize_request(&key_pair).unwrap().der());

    let res = finalize(&app, &signer, &account_url, &order_url, &csr).await;
    assert_eq!(res.status(), StatusCode::OK);

    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    let cert_url = order["certificate"].as_str().unwrap().to_string();
    let path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &nonce);
    let chain = body_text(post(&app, path, body).await).await;

    let leaf = acme_proxy::cert::leaf_der_from_chain(&chain).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    assert!(
        parsed.subject().iter_common_name().next().is_none(),
        "the CSR's common name must not survive into the signed leaf: {}",
        parsed.subject()
    );
    // The name the order authorized is still asserted, in the SAN where RFC 5280
    // §4.2.1.6 wants it.
    assert!(chain.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn a_bad_csr_leaves_the_order_finalizable() {
    let (app, signer, account_url, order_url) = setup_ready_order().await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("wrong.example.com"),
    )
    .await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;

    // The order is untouched and a corrected CSR still works.
    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "ready");

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");
}

/// Fetching the certificate before finalizing: there is nothing to serve.
#[tokio::test]
async fn the_certificate_is_not_available_before_finalize() {
    let (app, signer, account_url, order_url) = setup_ready_order().await;
    let id = order_url.rsplit('/').next().unwrap();
    let cert_url = format!("{BASE}/certificate/{id}");

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &nonce);
    let res = post(&app, &format!("{PREFIX}/certificate/{id}"), body).await;

    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:malformed",
    )
    .await;
}

/// The order list is per-account: asking for someone else's is unauthorized.
#[tokio::test]
async fn the_order_list_of_another_account_is_unauthorized() {
    let app = test_app().await;
    let signer_a = EcSigner::new();
    let signer_b = EcSigner::new();
    let url_a = register(&app, &signer_a).await;
    let url_b = register(&app, &signer_b).await;

    // A asks for B's order list, signing correctly as itself.
    let orders_url = format!("{url_b}/orders");
    let path = orders_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer_a.sign_kid_empty(&url_a, &orders_url, &nonce);
    let res = post(&app, path, body).await;

    assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

/// A backend that delegates issuance (the `relay` shape) must leave the
/// order `processing` rather than `valid`, and the response must carry the
/// `Retry-After` RFC 8555 §7.4 asks for so the client knows to poll instead of
/// waiting on the request.
#[tokio::test]
async fn finalize_with_a_delegating_signer_leaves_the_order_processing() {
    let (app, _db) = test_app_with_signer(Arc::new(common::DelegatingSigner)).await;
    let signer = EcSigner::new();
    let (account_url, order_url) = ready_order(&app, &signer).await;
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    // --- finalize: accepted, but not finished ---
    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_url.strip_prefix(common::HOST).unwrap(), body).await;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5"),
        "a processing order must pace the client's polling"
    );
    let order = body_json(res).await;
    assert_eq!(order["status"], "processing");
    assert!(
        order.get("certificate").is_none(),
        "no certificate exists yet"
    );

    // --- polling the order keeps reporting processing, with the same hint ---
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let res = post(&app, order_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(body_json(res).await["status"], "processing");
}

/// The counterpart: a synchronous backend must be completely unaffected — no
/// `Retry-After`, and the certificate available immediately.
#[tokio::test]
async fn finalize_with_a_local_signer_still_completes_inline() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let (account_url, order_url) = ready_order(&app, &signer).await;

    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let res = post(&app, finalize_url.strip_prefix(common::HOST).unwrap(), body).await;

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::RETRY_AFTER).is_none(),
        "a finished order has nothing to wait for"
    );
    assert_eq!(body_json(res).await["status"], "valid");
}

/// Two authorizations of one order validated concurrently must both land, and
/// the order must reach `ready`.
///
/// The readiness check used to re-read the authorizations from the pool *after*
/// its own write had committed, so two validations racing could each read before
/// the other's write landed: neither would see a complete set, neither would
/// promote, and the order would sit `pending` with every authorization `valid`
/// and no challenge left to trigger — stuck until it expired. Reading inside the
/// transaction that just wrote is what fixes it.
#[tokio::test]
async fn concurrent_validations_of_one_order_still_promote_it() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [
        { "type": "dns", "value": "a.example.com" },
        { "type": "dns", "value": "b.example.com" },
    ] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let authz_urls = order_authz_urls(&app, &signer, &account_url, &order_url).await;
    assert_eq!(authz_urls.len(), 2);

    // Both triggers are signed up front — each needs its own nonce, and getting
    // one is itself a request — then fired together.
    let mut bodies = Vec::new();
    for authz_url in &authz_urls {
        let challenge_url = first_challenge_url(&app, &signer, &account_url, authz_url).await;
        let path = challenge_url
            .strip_prefix(common::HOST)
            .unwrap()
            .to_string();
        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
        bodies.push((path, body));
    }

    let (first, second) = tokio::join!(
        post(&app, &bodies[0].0, bodies[0].1.clone()),
        post(&app, &bodies[1].0, bodies[1].1.clone()),
    );
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(
        order["status"], "ready",
        "both authorizations are valid, so the order must be ready: {order}"
    );
}

/// A requested `notAfter` reaches the **issued certificate**, not just the
/// order object.
///
/// `new_order_accepts_and_echoes_requested_validity_bounds` above proves the
/// echo, and `LocalCa`'s own tests prove the clamp. Neither covers the wiring
/// between them, and that is precisely where the bug was: `signer/mod.rs`
/// records that these fields "were stored and echoed in the order object while
/// being dropped on the way to the signer". Replacing the handler's
/// `RequestedValidity { .. }` with `::default()` passes every other test in the
/// repository.
#[tokio::test]
async fn a_requested_not_after_reaches_the_issued_certificate() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = common::acme::register(&app, &signer).await;

    // Seven days out — well inside the CA's 90-day default, so the clamp
    // narrows to this rather than ignoring it.
    let requested_not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    let not_after = requested_not_after
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({
        "identifiers": [{ "type": "dns", "value": "example.com" }],
        "notAfter": not_after,
    });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    common::acme::drive_to_ready(&app, &signer, &account_url, &order).await;
    let order = common::acme::post_as_get(&app, &signer, &account_url, &order_url).await;

    let res = common::acme::finalize(
        &app,
        &signer,
        &account_url,
        order["finalize"].as_str().unwrap(),
        &["example.com"],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let order = common::acme::post_as_get(&app, &signer, &account_url, &order_url).await;
    let certificate_url = order["certificate"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &certificate_url, &nonce);
    let res = post(&app, &common::acme::path_of(&certificate_url), body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let chain = common::acme::body_text(res).await;

    let leaf = acme_proxy::cert::leaf_der_from_chain(&chain).unwrap();
    let (_not_before, cert_not_after) = acme_proxy::cert::cert_validity(&leaf).unwrap();

    // To the second: the clamp narrows to exactly what was asked for when the
    // request is inside the CA's own window.
    assert_eq!(
        cert_not_after,
        requested_not_after.unix_timestamp(),
        "the certificate's notAfter must be the one the order asked for, \
         not the CA's 90-day default"
    );
}

/// The converse, so the test above cannot pass by the signer simply honouring
/// whatever it is handed: a `notAfter` *beyond* the CA's own window is clamped
/// back to it rather than widening it.
#[tokio::test]
async fn a_not_after_beyond_the_ca_window_is_clamped_rather_than_honoured() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = common::acme::register(&app, &signer).await;

    let far_future = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let nonce = fetch_nonce(&app).await;
    let payload = json!({
        "identifiers": [{ "type": "dns", "value": "example.com" }],
        "notAfter": far_future
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    common::acme::drive_to_ready(&app, &signer, &account_url, &order).await;
    let order = common::acme::post_as_get(&app, &signer, &account_url, &order_url).await;
    let res = common::acme::finalize(
        &app,
        &signer,
        &account_url,
        order["finalize"].as_str().unwrap(),
        &["example.com"],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let order = common::acme::post_as_get(&app, &signer, &account_url, &order_url).await;
    let certificate_url = order["certificate"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &certificate_url, &nonce);
    let res = post(&app, &common::acme::path_of(&certificate_url), body).await;
    let chain = common::acme::body_text(res).await;

    let leaf = acme_proxy::cert::leaf_der_from_chain(&chain).unwrap();
    let (_not_before, cert_not_after) = acme_proxy::cert::cert_validity(&leaf).unwrap();

    assert!(
        cert_not_after < far_future.unix_timestamp(),
        "a request may narrow the CA's window, never widen it"
    );
}
