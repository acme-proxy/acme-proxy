//! Client-initiated authorization deactivation (RFC 8555 §7.5.2), through the
//! real router.
//!
//! §7.5.2 puts two operations behind one URL — a POST-as-GET reads the
//! authorization, a `{"status": "deactivated"}` POST relinquishes it — so most
//! of what these tests pin is that the *read* path still works unchanged and
//! that the write path cannot be used to reach a state issuance would honour:
//! "The server MUST NOT treat deactivated authorization objects as sufficient
//! for issuing certificates."

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, fetch_nonce, make_csr, p, test_app, test_app_with_challenges,
};

use acme_proxy::config::Config;
use common::{StubValidator, challenges_with};
use std::sync::Arc;

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

async fn register(app: &Router, signer: &impl TestSigner) -> String {
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
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// Creates a one-name order and returns `(order_url, authz_url)`.
async fn order_with_one_authz(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    name: &str,
) -> (String, String) {
    let nonce = fetch_nonce(app).await;
    let res = post(
        app,
        &p("/newOrder"),
        signer.sign_kid(
            account_url,
            NEW_ORDER_URL,
            &nonce,
            &json!({ "identifiers": [{ "type": "dns", "value": name }] }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    (order_url, authz_url)
}

/// Signed POST-as-GET of any resource, returning its JSON.
async fn read(app: &Router, signer: &impl TestSigner, account_url: &str, url: &str) -> Value {
    let nonce = fetch_nonce(app).await;
    let path = url.strip_prefix(common::HOST).unwrap();
    let res = post(app, path, signer.sign_kid_empty(account_url, url, &nonce)).await;
    assert_eq!(res.status(), StatusCode::OK, "POST-as-GET of {url}");
    body_json(res).await
}

/// The §7.5.2 request: a POST to the authorization URL carrying the static
/// `{"status": "deactivated"}` object.
async fn deactivate(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    authz_url: &str,
) -> Response {
    let nonce = fetch_nonce(app).await;
    let path = authz_url.strip_prefix(common::HOST).unwrap();
    post(
        app,
        path,
        signer.sign_kid(
            account_url,
            authz_url,
            &nonce,
            &json!({ "status": "deactivated" }),
        ),
    )
    .await
}

/// Triggers the first challenge of an authorization.
async fn trigger_first_challenge(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    authz_url: &str,
) -> Response {
    let authz = read(app, signer, account_url, authz_url).await;
    let url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(app).await;
    let path = url.strip_prefix(common::HOST).unwrap();
    post(
        app,
        path,
        signer.sign_kid(account_url, &url, &nonce, &json!({})),
    )
    .await
}

/// §7.5.2: "If the server accepts the deactivation, it should reply with a 200
/// (OK) status code and the updated contents of the authorization object."
#[tokio::test]
async fn deactivating_an_authorization_returns_the_updated_object() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "a.example.com").await;

    let before = read(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(before["status"], "pending");

    let res = deactivate(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    let after = body_json(res).await;
    assert_eq!(after["status"], "deactivated");
    // The response is the whole authorization object, not a bare status.
    assert_eq!(after["identifier"]["value"], "a.example.com");
    assert!(after["challenges"].is_array());

    // And it is durable: a later POST-as-GET reads the same state back.
    let reread = read(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(reread["status"], "deactivated");
}

/// The POST-as-GET half of the same URL must be untouched by the write half.
#[tokio::test]
async fn a_post_as_get_still_reads_the_authorization() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "b.example.com").await;

    let authz = read(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(authz["status"], "pending");
    assert_eq!(authz["identifier"]["value"], "b.example.com");
}

/// §7.5.2 defines exactly one payload. Anything else must be refused rather
/// than silently treated as a read — a client asking for something we do not
/// implement should hear so.
#[tokio::test]
async fn any_other_payload_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "c.example.com").await;

    for payload in [
        json!({ "status": "valid" }),
        json!({ "status": "revoked" }),
        json!({ "identifier": { "type": "dns", "value": "elsewhere.example.com" } }),
    ] {
        let nonce = fetch_nonce(&app).await;
        let path = authz_url.strip_prefix(common::HOST).unwrap();
        let res = post(
            &app,
            path,
            signer.sign_kid(&account_url, &authz_url, &nonce, &payload),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "payload {payload} should be refused"
        );
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:malformed"
        );
    }
}

/// §7.5.2: "The server MUST verify that the request is signed by the account
/// key corresponding to the account that owns the authorization."
#[tokio::test]
async fn another_account_cannot_deactivate_the_authorization() {
    let app = test_app().await;
    let owner = EcSigner::new();
    let owner_url = register(&app, &owner).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &owner, &owner_url, "d.example.com").await;

    let stranger = EcSigner::new();
    let stranger_url = register(&app, &stranger).await;

    let res = deactivate(&app, &stranger, &stranger_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // And the authorization is untouched.
    let authz = read(&app, &owner, &owner_url, &authz_url).await;
    assert_eq!(authz["status"], "pending");
}

/// The core of §7.5.2: a deactivated authorization must never carry an order to
/// issuance. Here the challenge is triggered *after* deactivation, so the only
/// thing stopping the order is the refusal to validate at all.
#[tokio::test]
async fn a_deactivated_authorization_cannot_be_validated() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "e.example.com").await;

    let res = deactivate(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::OK);

    let res = trigger_first_challenge(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a challenge under a deactivated authorization must not run"
    );
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );

    // The order therefore never becomes ready, and finalize refuses it.
    let order = read(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "pending");

    let finalize_url = order["finalize"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(&app).await;
    let path = finalize_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        &app,
        path,
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("e.example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:orderNotReady"
    );
}

/// The harder half of the same MUST: the order already reached `ready`, so
/// refusing new validations is not enough — `finalize` would still accept it.
/// Deactivating one of its authorizations has to demote the order.
#[tokio::test]
async fn deactivating_an_authorization_demotes_a_ready_order() {
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(
            &["http-01"],
            vec![Arc::new(StubValidator::passing("http-01"))],
        ),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "f.example.com").await;

    let res = trigger_first_challenge(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");

    let order = read(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "ready", "precondition: the order is ready");

    let res = deactivate(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "deactivated");

    let order = read(&app, &signer, &account_url, &order_url).await;
    assert_eq!(
        order["status"], "pending",
        "a ready order must not survive losing an authorization"
    );

    // …and finalize now refuses it, which is the property that actually matters.
    let finalize_url = order["finalize"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(&app).await;
    let path = finalize_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        &app,
        path,
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("f.example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:orderNotReady"
    );
}

/// Once the certificate exists, §7.5.2 is the wrong tool: relinquishing the
/// authorization would not un-issue anything, and revocation (§7.6) is what the
/// client actually wants. Refusing is clearer than accepting a no-op.
#[tokio::test]
async fn an_issued_order_refuses_deactivation() {
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(
            &["http-01"],
            vec![Arc::new(StubValidator::passing("http-01"))],
        ),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "g.example.com").await;

    let res = trigger_first_challenge(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::OK);

    let order = read(&app, &signer, &account_url, &order_url).await;
    let finalize_url = order["finalize"].as_str().unwrap().to_string();
    let nonce = fetch_nonce(&app).await;
    let path = finalize_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        &app,
        path,
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("g.example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");

    let res = deactivate(&app, &signer, &account_url, &authz_url).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("revoke"),
        "the refusal should point at revocation: {problem}"
    );
}

/// §7.5.2 describes a client sending the same static object to *each*
/// authorization of an identifier. A retry after a partial failure must not
/// start erroring on the ones that already went through.
#[tokio::test]
async fn deactivating_twice_is_idempotent() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "h.example.com").await;

    for attempt in 1..=2 {
        let res = deactivate(&app, &signer, &account_url, &authz_url).await;
        assert_eq!(res.status(), StatusCode::OK, "attempt {attempt}");
        assert_eq!(body_json(res).await["status"], "deactivated");
    }
}

/// The authorization URL is the one place `AcmeOptionalPayload` is used, so it
/// is the only route where "a payload arrived, but it is unreadable" is
/// reachable at all. An empty payload means a POST-as-GET read; anything else
/// has to decode, or the request is `malformed` — never silently treated as a
/// read.
#[tokio::test]
async fn an_unreadable_payload_on_the_authorization_url_is_malformed() {
    use base64::prelude::*;

    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_url, authz_url) =
        order_with_one_authz(&app, &signer, &account_url, "p.example.com").await;
    let path = authz_url.strip_prefix(common::HOST).unwrap().to_string();

    // Not base64url at all. The signature covers the literal payload field, so
    // verification passes and the request reaches the decode step.
    let nonce = fetch_nonce(&app).await;
    let protected = json!({
        "alg": "ES256",
        "kid": account_url,
        "nonce": nonce,
        "url": authz_url,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = "!!!not-base64!!!";
    let sig = signer.sign_input(format!("{protected_b64}.{payload_b64}").as_bytes());
    let res = post(
        &app,
        &path,
        common::flattened_jws(&protected_b64, payload_b64, &sig),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        problem["detail"].as_str().unwrap().contains("Base64"),
        "{problem}"
    );

    // Valid base64url, but the bytes behind it are not JSON.
    let nonce = fetch_nonce(&app).await;
    let protected = json!({
        "alg": "ES256",
        "kid": account_url,
        "nonce": nonce,
        "url": authz_url,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"this is not JSON");
    let sig = signer.sign_input(format!("{protected_b64}.{payload_b64}").as_bytes());
    let res = post(
        &app,
        &path,
        common::flattened_jws(&protected_b64, &payload_b64, &sig),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        problem["detail"].as_str().unwrap().contains("Payload"),
        "{problem}"
    );
}
