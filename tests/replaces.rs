//! The `replaces` half of ACME Renewal Information (RFC 9773 §5), through the
//! real router: a newOrder that names the certificate it is renewing.
//!
//! §5 asks servers to check three things and pins the status for exactly one of
//! them ("it MUST return an HTTP 409 (Conflict) with a problem document of type
//! `alreadyReplaced`"), so most of these tests are about the *other* two being
//! enforced without being over-enforced — §5 explicitly leaves stricter
//! correspondence, "such as requiring exact identifier matching", to policy.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, fetch_nonce, first_certificate, make_csr, p, test_app,
};

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
        .unwrap()
        .to_string()
}

/// A newOrder for `names`, optionally naming a predecessor. Returns the raw
/// response so rejection tests can read the problem document.
async fn new_order(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    names: &[&str],
    replaces: Option<&str>,
) -> Response {
    let identifiers: Vec<Value> = names
        .iter()
        .map(|name| json!({ "type": "dns", "value": name }))
        .collect();
    let mut payload = json!({ "identifiers": identifiers });
    if let Some(cert_id) = replaces {
        payload["replaces"] = json!(cert_id);
    }
    let nonce = fetch_nonce(app).await;
    post(
        app,
        &p("/newOrder"),
        signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload),
    )
    .await
}

/// Signed POST-as-GET of any resource, returning its JSON.
async fn read(app: &Router, signer: &impl TestSigner, account_url: &str, url: &str) -> Value {
    let nonce = fetch_nonce(app).await;
    let path = url.strip_prefix(common::HOST).unwrap();
    let res = post(app, path, signer.sign_kid_empty(account_url, url, &nonce)).await;
    assert_eq!(res.status(), StatusCode::OK, "POST-as-GET of {url}");
    body_json(res).await
}

/// Drives one order all the way to a certificate and returns its PEM chain.
async fn issue(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    name: &str,
    replaces: Option<&str>,
) -> String {
    let res = new_order(app, signer, account_url, &[name], replaces).await;
    assert_eq!(res.status(), StatusCode::CREATED, "newOrder for {name}");
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let authz = read(app, signer, account_url, &authz_url).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let nonce = fetch_nonce(app).await;
    let path = challenge_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        app,
        path,
        signer.sign_kid(account_url, &challenge_url, &nonce, &json!({})),
    )
    .await;
    assert_eq!(body_json(res).await["status"], "valid");

    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(app).await;
    let path = finalize_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        app,
        path,
        signer.sign_kid(
            account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr(name) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let nonce = fetch_nonce(app).await;
    let path = cert_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        app,
        path,
        signer.sign_kid_empty(account_url, &cert_url, &nonce),
    )
    .await;
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The RFC 9773 §4.1 certID for an issued chain — §5 says `replaces` "is
/// constructed in the same way as the path component for GET requests described
/// in Section 4.1", so a client builds this from the certificate it holds.
fn cert_id(chain_pem: &str) -> String {
    acme_proxy::cert::ari_cert_id(&first_certificate(chain_pem)).unwrap()
}

/// §5: "If the server accepts a newOrder request with a `replaces` field, it
/// MUST reflect that field in the response **and in subsequent requests** for
/// the corresponding Order object."
#[tokio::test]
async fn an_accepted_replaces_is_reflected_now_and_on_every_later_read() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "example.com", None).await;
    let predecessor = cert_id(&chain);

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    // Reflected in the 201 body…
    assert_eq!(body_json(res).await["replaces"], predecessor);

    // …and in a later poll, which is the half a write-only echo would miss.
    let later = read(&app, &signer, &account_url, &order_url).await;
    assert_eq!(later["replaces"], predecessor);
}

/// The field is optional, and an order without one must not sprout an empty or
/// null `replaces` — RFC 8555 §7.1.3 lists no such member, and a client
/// checking `"replaces" in order` would misread it.
#[tokio::test]
async fn an_order_without_replaces_does_not_carry_the_field() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["example.com"], None).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order = body_json(res).await;
    assert!(
        order.get("replaces").is_none(),
        "an order that replaces nothing must omit the field: {order}"
    );
}

/// §5: the two must "correspond to the same ACME Account". This is also what
/// stops `replaces` becoming an oracle for another account's certificates.
#[tokio::test]
async fn replaces_naming_another_accounts_certificate_is_refused() {
    let app = test_app().await;

    let first = EcSigner::new();
    let first_url = register(&app, &first).await;
    let chain = issue(&app, &first, &first_url, "example.com", None).await;
    let predecessor = cert_id(&chain);

    let second = EcSigner::new();
    let second_url = register(&app, &second).await;

    let res = new_order(
        &app,
        &second,
        &second_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("another account"),
        "{problem}"
    );
}

/// §5: the two must "share at least one identifier".
#[tokio::test]
async fn replaces_sharing_no_identifier_is_refused() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "old.example.com", None).await;
    let predecessor = cert_id(&chain);

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["unrelated.example.net"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(res).await["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("sharing no identifier")
    );
}

/// …but only *at least one*. §5: "Correspondence checks beyond this (such as
/// requiring exact identifier matching) are left up to server policy" — and
/// adding a name at renewal is ordinary, so this server does not require more.
#[tokio::test]
async fn a_renewal_may_add_names_as_long_as_one_is_shared() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "example.com", None).await;
    let predecessor = cert_id(&chain);

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com", "www.example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "growing the name set at renewal must be allowed"
    );
    assert_eq!(body_json(res).await["replaces"], predecessor);
}

/// §5, the one case with a status of its own: "If the server rejects the
/// request because the identified certificate has already been marked as
/// replaced, it MUST return an HTTP 409 (Conflict) with a problem document of
/// type `alreadyReplaced`".
#[tokio::test]
async fn replacing_the_same_certificate_twice_is_409_already_replaced() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "example.com", None).await;
    let predecessor = cert_id(&chain);

    let first = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(second).await["type"],
        "urn:ietf:params:acme:error:alreadyReplaced"
    );
}

/// The `invalid` exclusion in §5 ("…by a different Order that is **not
/// `invalid`**") is what makes a retry possible: an order that failed never
/// produced a replacement, so it must not hold the predecessor hostage.
#[tokio::test]
async fn an_invalid_replacement_order_does_not_block_a_retry() {
    let (app, db) = common::test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "example.com", None).await;
    let predecessor = cert_id(&chain);

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let first_id = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // Whatever made it fail — a challenge that never validated, a signer error
    // at finalize — the order ends up terminal.
    sqlx::query("UPDATE orders SET status = 'invalid' WHERE id = ?")
        .bind(&first_id)
        .execute(&db.pool)
        .await
        .unwrap();

    let retry = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com"],
        Some(&predecessor),
    )
    .await;
    assert_eq!(
        retry.status(),
        StatusCode::CREATED,
        "a failed replacement must not permanently consume the predecessor"
    );
    assert_eq!(body_json(retry).await["replaces"], predecessor);
}

/// An unknown or unparsable certID is refused rather than silently ignored: a
/// client that believes it declared a renewal, and did not, gets none of the
/// treatment §5 exists to enable.
#[tokio::test]
async fn a_replaces_that_names_nothing_is_refused() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    for (name, cert_id) in [
        ("not a certID at all", "nonsense"),
        ("well-formed but unknown", "qrvM3Q.AQIDBA"),
        ("padded, which §4.1 forbids", "qrvM3Q==.AQIDBA"),
        ("empty serial half", "qrvM3Q."),
    ] {
        let res = new_order(&app, &signer, &account_url, &["example.com"], Some(cert_id)).await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{name} should be refused"
        );
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:malformed"
        );
    }
}

/// The AKI half is checked here too, for the same reason `GET /renewalInfo`
/// checks it: a serial alone does not identify a certificate.
#[tokio::test]
async fn a_replaces_with_the_wrong_key_identifier_is_refused() {
    use base64::prelude::*;

    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let chain = issue(&app, &signer, &account_url, "example.com", None).await;
    let real = cert_id(&chain);
    let serial_b64 = real.split_once('.').unwrap().1;
    let forged = format!(
        "{}.{serial_b64}",
        BASE64_URL_SAFE_NO_PAD.encode([0xFFu8; 20])
    );

    let res = new_order(&app, &signer, &account_url, &["example.com"], Some(&forged)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(res).await["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("key identifier")
    );
}
