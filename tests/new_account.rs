use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{EcSigner, RsaSigner, TestSigner, body_json, fetch_nonce, p, test_app};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";

fn account_payload() -> Value {
    json!({
        "contact": ["mailto:test@example.com"],
        "termsOfServiceAgreed": true,
    })
}

async fn post_new_account(app: &Router, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(p("/newAccount"))
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Asserts a 201 Created account object and returns its `Location` header.
async fn assert_created(res: Response) -> String {
    assert_eq!(res.status(), StatusCode::CREATED);
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string();
    assert!(
        location.starts_with("http://localhost:3000/profile/default/acct/"),
        "unexpected Location: {location}"
    );
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");
    location
}

#[tokio::test]
async fn valid_signed_request_with_fresh_nonce_succeeds() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // Real two-request lifecycle: get a nonce, then spend it on newAccount.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"][0], "mailto:test@example.com");
}

#[tokio::test]
async fn valid_rsa_signed_request_succeeds() {
    let app = test_app().await;
    let signer = RsaSigner::new();

    // Same lifecycle as the EC case, exercising the RSA (RS256) signature path
    // end-to-end through the extractor.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());

    assert_created(post_new_account(&app, body).await).await;
}

#[tokio::test]
async fn account_payload_without_contact_succeeds() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // `contact` is optional: a payload that omits it must still be accepted.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &payload);

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    // With no contact supplied, the account object omits the field entirely.
    let account = body_json(res).await;
    assert!(account.get("contact").is_none());
}

#[tokio::test]
async fn same_key_returns_existing_account() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // First registration creates the account (201).
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    let first_location = assert_created(post_new_account(&app, body).await).await;

    // Re-registering the same key returns the existing account with 200 and the
    // same Location (RFC 8555 §7.3 find-or-create).
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let second_location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("existing-account response must set a Location header")
        .to_string();
    assert_eq!(first_location, second_location);
}

#[tokio::test]
async fn nonce_is_consumed_and_cannot_be_replayed() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // Spend a nonce successfully…
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    assert_eq!(
        post_new_account(&app, body).await.status(),
        StatusCode::CREATED
    );

    // …then replay the very same nonce: it was deleted, so it must be rejected.
    let replay = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    let res = post_new_account(&app, replay).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");
}

#[tokio::test]
async fn unknown_nonce_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // Syntactically valid UUID that was never issued by the server.
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        "00000000-0000-0000-0000-000000000000",
        &account_payload(),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Errors are RFC 8555 problem documents.
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
    );
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");
    assert_eq!(problem["status"], 400);
}

#[tokio::test]
async fn wrong_url_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    // Correctly signed and fresh nonce, but the JWS `url` does not match the endpoint.
    let body = signer.sign(
        "http://localhost:3000/profile/default/wrongUrl",
        &nonce,
        &account_payload(),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tampered_signature_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());

    // Flip the first character of the signature: still valid base64url of the
    // right length, but no longer a valid signature over the signing input.
    let mut jws: Value = serde_json::from_str(&body).unwrap();
    let sig = jws["signature"].as_str().unwrap();
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    jws["signature"] = json!(chars.into_iter().collect::<String>());

    let res = post_new_account(&app, jws.to_string()).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

/// RFC 8555 §7.3.1: `onlyReturnExisting` asks the server to look up an account
/// and *not* create one. It used to be parsed and dropped on the floor, so a
/// client probing for an account instead got a brand-new one and a 201.
#[tokio::test]
async fn only_return_existing_does_not_create_an_account() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "onlyReturnExisting": true }),
    );
    let res = post_new_account(&app, body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );

    // And nothing was created: a plain registration afterwards is still a 201.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    assert_created(post_new_account(&app, body).await).await;
}

/// With an account already registered, the same request returns it — 200, not
/// 201, and with the `Location` header a client needs to use as its `kid`.
#[tokio::test]
async fn only_return_existing_returns_a_registered_account() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &account_payload());
    let location = assert_created(post_new_account(&app, body).await).await;

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "onlyReturnExisting": true }),
    );
    let res = post_new_account(&app, body).await;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some(location.as_str())
    );
    let account = body_json(res).await;
    assert_eq!(account["contact"][0], "mailto:test@example.com");
}
