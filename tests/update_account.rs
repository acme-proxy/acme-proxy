//! Covers `POST /acct/{id}` account update (RFC 8555 §7.3.2 / §7.3.6). A request
//! to an existing account URL authenticates with the `kid` (account URL) form of
//! JWS; the server verifies the signature against the account's stored key, then
//! updates its `contact` or deactivates it — or, for an empty payload (a
//! POST-as-GET, §6.3), answers the account unchanged. Also exercises the
//! extractor's `kid` branches (unknown account, jwk+kid, neither) and the
//! handler's authorization and error paths.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{EcSigner, RsaSigner, TestSigner, body_json, fetch_nonce, flattened_jws, p, test_app};

const BASE: &str = common::BASE;
const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";

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

/// Registers an EC account and returns its account URL (the `kid`/target of updates).
async fn register(app: &Router, signer: &EcSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "contact": ["mailto:old@example.com"], "termsOfServiceAgreed": true });
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

/// Asserts a 400 `malformed` problem+json and returns its body.
async fn assert_malformed(res: Response) -> Value {
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    problem
}

#[tokio::test]
async fn update_contact_succeeds_ec() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    // For an account update, `kid` and `url` are both the account URL.
    let payload = json!({ "contact": ["mailto:new@example.com"] });
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &payload);

    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"][0], "mailto:new@example.com");

    // The change is persisted: a subsequent signed read reflects the new
    // contact. An empty payload is a no-op update that returns the object.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let account = body_json(post(&app, path, body).await).await;
    assert_eq!(account["contact"][0], "mailto:new@example.com");
}

#[tokio::test]
async fn update_contact_succeeds_rsa() {
    let app = test_app().await;
    // Register with RSA so the `kid` path verifies against a stored RSA SPKI key.
    let signer = RsaSigner::new();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "contact": ["mailto:old@example.com"], "termsOfServiceAgreed": true });
    let res = post(
        &app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let account_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "contact": ["mailto:new@example.com"] });
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &payload);

    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["contact"][0], "mailto:new@example.com");
}

#[tokio::test]
async fn deactivate_then_further_update_is_unauthorized() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // Deactivate the account.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "deactivated" }),
    );
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["status"], "deactivated");

    // A deactivated account is terminal: any further update is rejected.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "contact": ["mailto:x@example.com"] }),
    );
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

#[tokio::test]
async fn update_signed_by_different_account_key_is_unauthorized() {
    let app = test_app().await;
    let signer_a = EcSigner::new();
    let signer_b = EcSigner::new();
    let url_a = register(&app, &signer_a).await;
    let url_b = register(&app, &signer_b).await;
    let path_b = url_b.strip_prefix(common::HOST).unwrap();

    // Sign with A's key and A's `kid` (a valid signature), but target account B.
    // The extractor verifies against A's key; the handler sees B's stored key
    // differs and rejects the cross-account update.
    let nonce = fetch_nonce(&app).await;
    let body = signer_a.sign_kid(&url_a, &url_b, &nonce, &json!({ "contact": [] }));
    let res = post(&app, path_b, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
}

#[tokio::test]
async fn update_wrong_url_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // Valid `kid`/signature, but the JWS `url` does not match the account URL.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &format!("{BASE}/acct/other"),
        &nonce,
        &json!({ "contact": [] }),
    );
    assert_malformed(post(&app, path, body).await).await;
}

#[tokio::test]
async fn update_invalid_status_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // "valid" is not a client-settable status; only "deactivated" is accepted.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "valid" }),
    );
    assert_malformed(post(&app, path, body).await).await;
}

#[tokio::test]
async fn update_unknown_nonce_is_bad_nonce() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // Syntactically valid UUID that was never issued.
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        "00000000-0000-0000-0000-000000000000",
        &json!({ "contact": [] }),
    );
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");
}

#[tokio::test]
async fn update_with_kid_for_unknown_account_is_account_does_not_exist() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let fake = format!("{BASE}/acct/00000000-0000-0000-0000-000000000000");
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&fake, &fake, &nonce, &json!({ "contact": [] }));

    let res = post(&app, &p("/acct/00000000-0000-0000-0000-000000000000"), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
}

/// A real account signing for an account URL that names nobody. The
/// extractor's `kid` lookup succeeds, and the URL is not the signer's: the same
/// `unauthorized` another account's URL gets, so a client cannot probe which
/// account ids exist.
#[tokio::test]
async fn an_update_to_an_unknown_account_url_is_unauthorized() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let account_url = register(&app, &signer).await;
    let fake_path = &p("/acct/00000000-0000-0000-0000-000000000000");
    // From the host, not from BASE: `fake_path` already carries the profile's
    // own prefix, and a doubled one would be refused by the §6.4 url check
    // before the handler ever looked the account up.
    let fake_url = format!("{}{fake_path}", common::HOST);
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &fake_url, &nonce, &json!({ "contact": [] }));

    let res = post(&app, fake_path, body).await;
    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn both_jwk_and_kid_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    // A protected header carrying both `jwk` and `kid` is rejected before any
    // signature check (RFC 8555 §6.2), so the signature can be a dummy.
    let protected = json!({
        "alg": "ES256",
        "jwk": signer.jwk(),
        "kid": account_url,
        "nonce": "n",
        "url": account_url,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
    let body = flattened_jws(&protected_b64, &payload_b64, &[0u8; 64]);

    // Matched on substance, not on the exact sentence: what matters is that the
    // refusal names the two mutually exclusive fields.
    let problem = assert_malformed(post(&app, path, body).await).await;
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("jwk") && detail.contains("kid"),
        "detail should name both fields, got {detail:?}"
    );
}

#[tokio::test]
async fn neither_jwk_nor_kid_is_malformed() {
    let app = test_app().await;

    // No `jwk` and no `kid`: rejected before any signature check.
    let protected = json!({ "alg": "ES256", "nonce": "n", "url": format!("{BASE}/acct/x") });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
    let body = flattened_jws(&protected_b64, &payload_b64, &[0u8; 64]);

    let problem = assert_malformed(post(&app, &p("/acct/x"), body).await).await;
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("jwk") && detail.contains("kid"),
        "detail should name both fields, got {detail:?}"
    );
}

/// A POST-as-GET to an account URL (RFC 8555 §6.3): a signed request with an
/// empty payload.
async fn read_account(app: &Router, signer: &EcSigner, account_url: &str) -> Response {
    let nonce = fetch_nonce(app).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    post(
        app,
        path,
        signer.sign_kid_empty(account_url, account_url, &nonce),
    )
    .await
}

#[tokio::test]
async fn an_empty_payload_reads_the_account_without_changing_it() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let first = read_account(&app, &signer, &account_url).await;
    assert_eq!(first.status(), StatusCode::OK);
    let account = body_json(first).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"], json!(["mailto:old@example.com"]));

    let second = read_account(&app, &signer, &account_url).await;
    assert_eq!(body_json(second).await, account);
}

#[tokio::test]
async fn an_empty_payload_from_another_accounts_key_is_unauthorized() {
    let app = test_app().await;
    let owner = EcSigner::new();
    let owner_url = register(&app, &owner).await;
    let stranger = EcSigner::new();
    let stranger_url = register(&app, &stranger).await;

    let nonce = fetch_nonce(&app).await;
    let body = stranger.sign_kid_empty(&stranger_url, &owner_url, &nonce);
    let path = owner_url.strip_prefix(common::HOST).unwrap();
    let res = post(&app, path, body).await;

    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn an_empty_payload_from_a_deactivated_account_is_unauthorized() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();
    let deactivate = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "deactivated" }),
    );
    assert_eq!(post(&app, path, deactivate).await.status(), StatusCode::OK);

    let res = read_account(&app, &signer, &account_url).await;

    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

/// The read starts from the same check as an update, so an account URL that
/// names nobody is `unauthorized` here too.
#[tokio::test]
async fn an_empty_payload_to_an_unknown_account_url_is_unauthorized() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let fake_path = &p("/acct/00000000-0000-0000-0000-000000000000");
    let fake_url = format!("{}{fake_path}", common::HOST);

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &fake_url, &nonce);
    let res = post(&app, fake_path, body).await;

    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

/// Only an empty payload is a read. One that arrived but does not decode is
/// `malformed` — never silently answered as a read — and changes nothing.
#[tokio::test]
async fn an_unreadable_payload_on_the_account_url_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap().to_string();

    // Not base64url at all, then valid base64url over bytes that are not JSON.
    // The signature covers the literal payload field, so verification passes
    // and the request reaches the decode step.
    let cases = [
        ("!!!not-base64!!!".to_string(), "Base64"),
        (
            BASE64_URL_SAFE_NO_PAD.encode(b"this is not JSON"),
            "Payload",
        ),
    ];
    for (payload_b64, detail) in cases {
        let nonce = fetch_nonce(&app).await;
        let protected = json!({
            "alg": "ES256",
            "kid": account_url,
            "nonce": nonce,
            "url": account_url,
        });
        let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
        let sig = signer.sign_input(format!("{protected_b64}.{payload_b64}").as_bytes());
        let res = post(
            &app,
            &path,
            flattened_jws(&protected_b64, &payload_b64, &sig),
        )
        .await;

        let problem = assert_malformed(res).await;
        assert!(
            problem["detail"].as_str().unwrap().contains(detail),
            "{problem}"
        );
    }

    let res = read_account(&app, &signer, &account_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"], json!(["mailto:old@example.com"]));
}
