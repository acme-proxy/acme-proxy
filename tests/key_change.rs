//! `POST /keyChange` (RFC 8555 §7.3.5, Account Key Rollover): the outer JWS
//! is `kid`-signed by the *old* key and carries, as its payload, a nested
//! inner JWS self-signed by the *new* key. Covers the success path (EC→EC and
//! a cross-algorithm RSA→EC rollover, plus proof the old key stops working
//! while the new one takes over), every RFC-mandated inner-JWS check (shape,
//! signature, `url` match, `account` match, `oldKey` match), the `409
//! Conflict` + `Location` case when the new key already belongs to a
//! different account, a deactivated account being refused, and that the
//! outer JWS's generic checks (`url`, nonce) still apply to this endpoint.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{EcSigner, RsaSigner, TestSigner, body_json, fetch_nonce, p, test_app};

const BASE: &str = common::BASE;
const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const KEY_CHANGE_URL: &str = "http://localhost:3000/profile/default/keyChange";

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

async fn key_change(app: &Router, body: String) -> Response {
    post(app, &p("/keyChange"), body).await
}

/// Builds the inner keyChange JWS (self-signed by `new_signer`, embedding its
/// own JWK) as a [`Value`], ready to embed as the outer JWS's payload.
fn build_inner_value(new_signer: &impl TestSigner, url: &str, payload: &Value) -> Value {
    let inner_jws = new_signer.sign_inner(url, payload);
    serde_json::from_str(&inner_jws).unwrap()
}

/// Builds a complete, well-formed `keyChange` outer request body: the
/// `{account, oldKey}` inner JWS self-signed by `new_signer`, wrapped in an
/// outer `kid`-signed JWS from `old_signer`.
fn key_change_body(
    old_signer: &impl TestSigner,
    new_signer: &impl TestSigner,
    account_url: &str,
    nonce: &str,
) -> String {
    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(new_signer, KEY_CHANGE_URL, &inner_payload);
    old_signer.sign_kid(account_url, KEY_CHANGE_URL, nonce, &inner_value)
}

/// Asserts a 400 `malformed` problem+json and returns its body.
async fn assert_malformed(res: Response) -> Value {
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    problem
}

#[tokio::test]
async fn key_change_succeeds_ec() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = key_change_body(&old_signer, &new_signer, &account_url, &nonce);
    let res = key_change(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");

    // The old key no longer authenticates this account...
    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // ...but the new one does, proving the rollover actually took effect.
    let nonce = fetch_nonce(&app).await;
    let body = new_signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// A cross-algorithm rollover: an account registered with an RSA key rolls
/// over to a freshly generated EC key. Exercises the outer `kid` path
/// verifying against a *stored RSA* SPKI (and `spki_to_jwk` reconstructing an
/// RSA `Jwk` for the `oldKey` comparison) while the inner JWS is self-signed
/// with ES256.
#[tokio::test]
async fn key_change_succeeds_cross_algorithm_rsa_to_ec() {
    let app = test_app().await;
    let old_signer = RsaSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = key_change_body(&old_signer, &new_signer, &account_url, &nonce);
    let res = key_change(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);

    let nonce = fetch_nonce(&app).await;
    let body = new_signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn key_change_rejects_inner_missing_jwk() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let protected = json!({ "alg": "ES256", "url": KEY_CHANGE_URL });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({ "account": account_url, "oldKey": old_signer.jwk() })).unwrap(),
    );
    let inner_value = json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]),
    });

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_rejects_inner_malformed_protected_json() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_value = json!({
        "protected": BASE64_URL_SAFE_NO_PAD.encode(b"not json"),
        "payload": BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
        "signature": BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]),
    });

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_rejects_inner_malformed_protected_base64() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_value = json!({
        "protected": "!!!not-base64!!!",
        "payload": BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
        "signature": BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]),
    });

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_rejects_inner_signature_tampered() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let mut inner_value = build_inner_value(&new_signer, KEY_CHANGE_URL, &inner_payload);
    inner_value["signature"] = json!(BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]));

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    let res = key_change(&app, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn key_change_rejects_inner_url_mismatch() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(&new_signer, &format!("{BASE}/other"), &inner_payload);

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_rejects_account_mismatch() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let other_signer = EcSigner::new();
    let other_account_url = register(&app, &other_signer).await;

    // The inner payload names a different, real account than the one that
    // signed the outer JWS.
    let inner_payload = json!({ "account": other_account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(&new_signer, KEY_CHANGE_URL, &inner_payload);

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_rejects_old_key_mismatch() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    // A third, unrelated key claimed as `oldKey` -- not the key that actually
    // signed the outer JWS.
    let unrelated_signer = EcSigner::new();
    let inner_payload = json!({ "account": account_url, "oldKey": unrelated_signer.jwk() });
    let inner_value = build_inner_value(&new_signer, KEY_CHANGE_URL, &inner_payload);

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

/// RFC 8555 §7.3.5 check #9: the new key must not already belong to a
/// different account. The server responds `409 Conflict` with a `Location`
/// header naming that account -- a genuinely new assertion shape (no other
/// endpoint in this codebase puts a header on an error response).
#[tokio::test]
async fn key_change_rejects_conflicting_new_key() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let other_signer = EcSigner::new();
    let other_account_url = register(&app, &other_signer).await;

    // Ask to roll `old_signer`'s account onto `other_signer`'s already
    // registered key.
    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(&other_signer, KEY_CHANGE_URL, &inner_payload);

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, KEY_CHANGE_URL, &nonce, &inner_value);
    let res = key_change(&app, body).await;

    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, other_account_url);

    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(problem["status"], 409);
}

#[tokio::test]
async fn key_change_rejects_deactivated_account() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // Deactivate the account (RFC 8555 §7.3.6).
    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "deactivated" }),
    );
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);

    // RFC check #1: the account must be "currently active" — a deactivated
    // one cannot roll its key.
    let nonce = fetch_nonce(&app).await;
    let body = key_change_body(&old_signer, &new_signer, &account_url, &nonce);
    let res = key_change(&app, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// The outer JWS's own generic checks (RFC 8555 §6.4/§6.5) still apply here,
/// the same way `update_account.rs` re-asserts them for `POST /acct/{id}`.
#[tokio::test]
async fn key_change_wrong_outer_url_is_malformed() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(&new_signer, KEY_CHANGE_URL, &inner_payload);

    let nonce = fetch_nonce(&app).await;
    let body = old_signer.sign_kid(&account_url, &format!("{BASE}/other"), &nonce, &inner_value);
    assert_malformed(key_change(&app, body).await).await;
}

#[tokio::test]
async fn key_change_unknown_nonce_is_bad_nonce() {
    let app = test_app().await;
    let old_signer = EcSigner::new();
    let new_signer = EcSigner::new();
    let account_url = register(&app, &old_signer).await;

    let inner_payload = json!({ "account": account_url, "oldKey": old_signer.jwk() });
    let inner_value = build_inner_value(&new_signer, KEY_CHANGE_URL, &inner_payload);

    let body = old_signer.sign_kid(
        &account_url,
        KEY_CHANGE_URL,
        "00000000-0000-0000-0000-000000000000",
        &inner_value,
    );
    let res = key_change(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:badNonce"
    );
}
