//! Drives the challenge subsystem through the real router: which types an
//! authorization offers, what triggering one does, and what a failure looks like
//! to a client.
//!
//! The default configuration is covered too, deliberately — `challenge.bypass`
//! is on by default, so the historical single-`http-01` flow is the one most
//! deployments still take, and a regression there would be silent.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, RecordingValidator, StubValidator, TestSigner, body_json, bypassing_challenges,
    challenges_with, fetch_nonce, make_csr, p, test_app, test_app_with_challenges,
};

use acme_proxy::config::Config;
use acme_proxy::extractors::acme::jwk_thumbprint;

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

/// Registers an account and returns its account URL (used as `kid`).
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

/// Creates an order for `names`, returning the response as-is so rejection
/// tests can inspect it.
async fn new_order(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    names: &[&str],
) -> Response {
    let identifiers: Vec<Value> = names
        .iter()
        .map(|name| json!({ "type": "dns", "value": name }))
        .collect();
    let nonce = fetch_nonce(app).await;
    post(
        app,
        &p("/newOrder"),
        signer.sign_kid(
            account_url,
            NEW_ORDER_URL,
            &nonce,
            &json!({ "identifiers": identifiers }),
        ),
    )
    .await
}

/// Signed POST-as-GET of any resource, returning its JSON.
async fn read(app: &Router, signer: &impl TestSigner, account_url: &str, url: &str) -> Value {
    let nonce = fetch_nonce(app).await;
    let path = url
        .strip_prefix(common::HOST)
        .expect("URL must be under the base");
    let res = post(app, path, signer.sign_kid_empty(account_url, url, &nonce)).await;
    assert_eq!(res.status(), StatusCode::OK, "POST-as-GET of {url}");
    body_json(res).await
}

/// Triggers a challenge, returning the raw response so a test can read the
/// `Link` header as well as the body.
async fn trigger(app: &Router, signer: &impl TestSigner, account_url: &str, url: &str) -> Response {
    let nonce = fetch_nonce(app).await;
    let path = url.strip_prefix(common::HOST).unwrap();
    post(
        app,
        path,
        signer.sign_kid(account_url, url, &nonce, &json!({})),
    )
    .await
}

/// The challenge of a given type on an authorization, by URL.
fn challenge_url_of_type(authz: &Value, typ: &str) -> String {
    authz["challenges"]
        .as_array()
        .expect("challenges must be an array")
        .iter()
        .find(|challenge| challenge["type"] == typ)
        .unwrap_or_else(|| panic!("no {typ} challenge in {authz}"))["url"]
        .as_str()
        .expect("a challenge must have a URL")
        .to_string()
}

// ---------------------------------------------------------------------------
// What an authorization offers
// ---------------------------------------------------------------------------

/// The default configuration must still produce exactly what it did before the
/// subsystem existed: one `http-01` challenge, accepted without a network check.
#[tokio::test]
async fn the_default_configuration_offers_one_bypassing_http_01_challenge() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order = body_json(new_order(&app, &signer, &account_url, &["example.com"]).await).await;
    let authz = read(
        &app,
        &signer,
        &account_url,
        order["authorizations"][0].as_str().unwrap(),
    )
    .await;

    assert_eq!(authz["challenges"].as_array().unwrap().len(), 1);
    assert_eq!(authz["challenges"][0]["type"], "http-01");
    assert!(authz.get("wildcard").is_none());

    let challenge_url = challenge_url_of_type(&authz, "http-01");
    let res = trigger(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");
}

/// Every enabled type is offered, each with its own token — a key authorization
/// is derived per challenge, so sharing one would be wrong.
#[tokio::test]
async fn every_enabled_type_is_offered_with_its_own_token() {
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        bypassing_challenges(&["http-01", "dns-01", "tls-alpn-01"]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order = body_json(new_order(&app, &signer, &account_url, &["example.com"]).await).await;
    let authz = read(
        &app,
        &signer,
        &account_url,
        order["authorizations"][0].as_str().unwrap(),
    )
    .await;

    let challenges = authz["challenges"].as_array().unwrap();
    assert_eq!(challenges.len(), 3);

    let types: Vec<_> = challenges
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["http-01", "dns-01", "tls-alpn-01"]);

    let tokens: std::collections::BTreeSet<_> = challenges
        .iter()
        .map(|c| c["token"].as_str().unwrap())
        .collect();
    assert_eq!(tokens.len(), 3, "each challenge needs its own token");
    let urls: std::collections::BTreeSet<_> = challenges
        .iter()
        .map(|c| c["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls.len(), 3);
}

// ---------------------------------------------------------------------------
// Validation, success and failure
// ---------------------------------------------------------------------------

/// The whole flow with a validator that passes: challenge → authorization →
/// order `ready` → a certificate.
#[tokio::test]
async fn a_passing_validator_carries_the_order_through_to_a_certificate() {
    let validator = StubValidator::passing("http-01");
    let calls = validator.counter();
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["example.com"]).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let authz = read(&app, &signer, &account_url, &authz_url).await;
    let challenge_url = challenge_url_of_type(&authz, "http-01");

    let res = trigger(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        read(&app, &signer, &account_url, &authz_url).await["status"],
        "valid"
    );
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "ready"
    );

    // And it finalizes.
    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        finalize_url.strip_prefix(common::HOST).unwrap(),
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");
}

/// RFC 8555 §7.5.1: "The server SHOULD provide information about its retry
/// state to the client via the `Retry-After` HTTP header field" — the same
/// pacing courtesy `order_response` extends to a `processing` order.
///
/// Only while `pending`: any other status is decided, and telling a client to
/// come back for an answer it already has would be noise.
#[tokio::test]
async fn a_pending_authorization_and_challenge_carry_a_retry_after() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["example.com"]).await;
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    // The authorization, while pending.
    let nonce = fetch_nonce(&app).await;
    let path = authz_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        &app,
        path,
        signer.sign_kid_empty(&account_url, &authz_url, &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("5"),
        "a pending authorization should pace the client"
    );

    let authz = body_json(res).await;
    assert_eq!(authz["status"], "pending");
    let challenge_url = challenge_url_of_type(&authz, "http-01");

    // Triggering it decides it (bypass is on by default), so the answer that
    // comes back is `valid` — and carries no Retry-After, because there is
    // nothing left to wait for.
    let res = trigger(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "valid");

    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        path,
        signer.sign_kid_empty(&account_url, &authz_url, &nonce),
    )
    .await;
    assert!(
        res.headers().get("retry-after").is_none(),
        "a decided authorization has nothing to come back for"
    );
    assert_eq!(body_json(res).await["status"], "valid");
}

/// A failure is reported **in the challenge object**, not as an HTTP error:
/// RFC 8555 §7.5.1 makes the object the response, and certbot's `acme` library
/// reads `error` from it. A 4xx would look like a transport failure instead.
#[tokio::test]
async fn a_failing_validator_reports_the_reason_in_the_challenge_object() {
    let validator = StubValidator::failing("http-01", "served the wrong body");
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["example.com"]).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let authz = read(&app, &signer, &account_url, &authz_url).await;
    let challenge_url = challenge_url_of_type(&authz, "http-01");

    let res = trigger(&app, &signer, &account_url, &challenge_url).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a failed challenge is still a 200"
    );
    // The `up` link must survive the failure path too, or the client cannot
    // find the authorization to poll — and it must survive *alongside* the
    // `index` link RFC 8555 §7.1 puts on every resource, which is why that
    // middleware appends rather than sets. Reading only the first `Link` header
    // would not catch an overwrite, so collect them all.
    let links: Vec<&str> = res
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        links.iter().any(|link| link.contains("rel=\"up\"")),
        "the up link must survive: {links:?}"
    );
    assert!(
        links.iter().any(|link| link.contains("rel=\"index\"")),
        "the index link must be present too: {links:?}"
    );

    let challenge = body_json(res).await;
    assert_eq!(challenge["status"], "invalid");
    assert_eq!(
        challenge["error"]["type"],
        "urn:ietf:params:acme:error:incorrectResponse"
    );
    assert_eq!(challenge["error"]["detail"], "served the wrong body");
    assert!(challenge.get("validated").is_none());

    // The failure propagates: authorization and order are both terminal.
    assert_eq!(
        read(&app, &signer, &account_url, &authz_url).await["status"],
        "invalid"
    );
    let order = read(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "invalid");
    assert_eq!(order["error"], challenge["error"]);

    // And an invalid order cannot be finalized.
    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        finalize_url.strip_prefix(common::HOST).unwrap(),
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:orderNotReady"
    );
}

/// `invalid` is terminal (RFC 8555 §7.1.6): re-triggering returns the stored
/// object rather than trying again.
#[tokio::test]
async fn re_triggering_a_failed_challenge_does_not_revalidate() {
    let validator = StubValidator::failing("http-01", "still wrong");
    let calls = validator.counter();
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order = body_json(new_order(&app, &signer, &account_url, &["example.com"]).await).await;
    let authz = read(
        &app,
        &signer,
        &account_url,
        order["authorizations"][0].as_str().unwrap(),
    )
    .await;
    let challenge_url = challenge_url_of_type(&authz, "http-01");

    let first = body_json(trigger(&app, &signer, &account_url, &challenge_url).await).await;
    let second = body_json(trigger(&app, &signer, &account_url, &challenge_url).await).await;

    assert_eq!(first, second);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a decided challenge is not re-run"
    );
}

/// A client that triggers a second challenge type after the first succeeded must
/// not be able to knock the authorization back to `invalid`.
#[tokio::test]
async fn a_sibling_challenge_is_not_run_once_the_authorization_is_valid() {
    let passing = StubValidator::passing("http-01");
    let failing = StubValidator::failing("dns-01", "no TXT record");
    let dns_calls = failing.counter();

    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(
            &["http-01", "dns-01"],
            vec![Arc::new(passing), Arc::new(failing)],
        ),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order = body_json(new_order(&app, &signer, &account_url, &["example.com"]).await).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let authz = read(&app, &signer, &account_url, &authz_url).await;

    // Satisfy http-01 first.
    let http_url = challenge_url_of_type(&authz, "http-01");
    assert_eq!(
        body_json(trigger(&app, &signer, &account_url, &http_url).await).await["status"],
        "valid"
    );

    // Then trigger the dns-01 sibling, whose validator would fail.
    let dns_url = challenge_url_of_type(&authz, "dns-01");
    let challenge = body_json(trigger(&app, &signer, &account_url, &dns_url).await).await;
    assert_eq!(challenge["status"], "pending", "the sibling is left alone");
    assert_eq!(dns_calls.load(Ordering::SeqCst), 0);

    // The authorization is still proved.
    assert_eq!(
        read(&app, &signer, &account_url, &authz_url).await["status"],
        "valid"
    );
}

/// Every authorization must be satisfied before the order is `ready` — one
/// challenge per authorization, not one per order.
#[tokio::test]
async fn an_order_is_ready_only_once_every_authorization_is_valid() {
    let (app, _db) =
        test_app_with_challenges(Config::default(), bypassing_challenges(&["http-01"])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["a.example.com", "b.example.com"],
    )
    .await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_urls: Vec<String> = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect();
    assert_eq!(authz_urls.len(), 2);

    let first = read(&app, &signer, &account_url, &authz_urls[0]).await;
    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&first, "http-01"),
    )
    .await;
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "pending",
        "one authorization out of two is not enough"
    );

    let second = read(&app, &signer, &account_url, &authz_urls[1]).await;
    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&second, "http-01"),
    )
    .await;
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "ready"
    );
}

// ---------------------------------------------------------------------------
// The key authorization
// ---------------------------------------------------------------------------

/// The server must derive the key authorization the way a client does, from the
/// account's own JWK. This computes it independently from the signer's JWK and
/// compares — the in-CI stand-in for running a real ACME client.
#[tokio::test]
async fn the_key_authorization_matches_what_a_client_would_compute() {
    let validator = RecordingValidator::new("http-01");
    let seen = validator.seen();
    let (app, db) = test_app_with_challenges(
        Config::default(),
        challenges_with(&["http-01"], vec![Arc::new(validator)]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let order = body_json(new_order(&app, &signer, &account_url, &["example.com"]).await).await;
    let authz = read(
        &app,
        &signer,
        &account_url,
        order["authorizations"][0].as_str().unwrap(),
    )
    .await;
    let token = authz["challenges"][0]["token"]
        .as_str()
        .unwrap()
        .to_string();

    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&authz, "http-01"),
    )
    .await;

    // The thumbprint of the key that registered the account.
    let account_id = account_url.rsplit('/').next().unwrap();
    let account =
        acme_proxy::sqlite::account::Account::find_by_id(common::PROFILE, account_id, &db)
            .await
            .unwrap()
            .expect("the account must exist");
    let expected = format!("{token}.{}", jwk_thumbprint(&account.pubkey).unwrap());

    let recorded = seen.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    let parts: Vec<&str> = recorded[0].split('|').collect();
    assert_eq!(parts[0], "example.com");
    assert_eq!(parts[1], "false");
    assert_eq!(parts[2], token);
    assert_eq!(parts[3], expected);
}

// ---------------------------------------------------------------------------
// Wildcards
// ---------------------------------------------------------------------------

/// A wildcard order becomes a `dns-01`-only authorization on the **base** name,
/// flagged with `wildcard` (RFC 8555 §7.1.4).
#[tokio::test]
async fn a_wildcard_order_offers_dns_01_on_the_base_name() {
    let validator = RecordingValidator::new("dns-01");
    let seen = validator.seen();
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        challenges_with(&["http-01", "dns-01"], vec![Arc::new(validator)]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["*.example.com"]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    // The order keeps the wildcard form: it is what the certificate is for.
    assert_eq!(order["identifiers"][0]["value"], "*.example.com");

    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let authz = read(&app, &signer, &account_url, &authz_url).await;

    // ...while the authorization shows the base name plus the flag.
    assert_eq!(
        authz["identifier"],
        json!({ "type": "dns", "value": "example.com" })
    );
    assert_eq!(authz["wildcard"], true);
    // http-01 is enabled but cannot prove a wildcard, so it is not offered.
    let challenges = authz["challenges"].as_array().unwrap();
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0]["type"], "dns-01");

    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&authz, "dns-01"),
    )
    .await;
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "ready"
    );

    // The validator was asked about the base name, with the wildcard flag set.
    let recorded = seen.lock().unwrap();
    let parts: Vec<&str> = recorded[0].split('|').collect();
    assert_eq!(parts[0], "example.com");
    assert_eq!(parts[1], "true");
}

/// The canonical wildcard order: the bare name and the wildcard together. Two
/// authorizations, which must not collide on `UNIQUE(order_id, identifier)`.
#[tokio::test]
async fn a_name_and_its_wildcard_get_separate_authorizations() {
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        bypassing_challenges(&["http-01", "dns-01"]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(
        &app,
        &signer,
        &account_url,
        &["example.com", "*.example.com"],
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "the two must not collide"
    );
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    let authz_urls: Vec<String> = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect();
    assert_eq!(authz_urls.len(), 2);

    let plain = read(&app, &signer, &account_url, &authz_urls[0]).await;
    let wildcard = read(&app, &signer, &account_url, &authz_urls[1]).await;

    // Both name `example.com`; only one is flagged, and only one offers http-01.
    assert_eq!(plain["identifier"]["value"], "example.com");
    assert!(plain.get("wildcard").is_none());
    assert_eq!(plain["challenges"].as_array().unwrap().len(), 2);

    assert_eq!(wildcard["identifier"]["value"], "example.com");
    assert_eq!(wildcard["wildcard"], true);
    assert_eq!(wildcard["challenges"].as_array().unwrap().len(), 1);

    // Both must be satisfied before the order is ready.
    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&plain, "http-01"),
    )
    .await;
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "pending"
    );
    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&wildcard, "dns-01"),
    )
    .await;
    assert_eq!(
        read(&app, &signer, &account_url, &order_url).await["status"],
        "ready"
    );
}

/// And the certificate really carries the wildcard SAN.
#[tokio::test]
async fn a_wildcard_order_issues_a_wildcard_certificate() {
    let (app, _db) =
        test_app_with_challenges(Config::default(), bypassing_challenges(&["dns-01"])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["*.example.com"]).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz = read(
        &app,
        &signer,
        &account_url,
        order["authorizations"][0].as_str().unwrap(),
    )
    .await;
    trigger(
        &app,
        &signer,
        &account_url,
        &challenge_url_of_type(&authz, "dns-01"),
    )
    .await;

    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        finalize_url.strip_prefix(common::HOST).unwrap(),
        signer.sign_kid(
            &account_url,
            &finalize_url,
            &nonce,
            &json!({ "csr": make_csr("*.example.com") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let cert_url = body_json(res).await["certificate"]
        .as_str()
        .expect("an issued order has a certificate URL")
        .to_string();

    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        cert_url.strip_prefix(common::HOST).unwrap(),
        signer.sign_kid_empty(&account_url, &cert_url, &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let pem = String::from_utf8(
        http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let leaf = pem
        .split("-----END CERTIFICATE-----")
        .next()
        .and_then(|block| block.split("-----BEGIN CERTIFICATE-----").nth(1))
        .map(|body| {
            use base64::prelude::*;
            BASE64_STANDARD
                .decode(body.replace(['\n', '\r'], ""))
                .unwrap()
        })
        .expect("a leaf certificate");

    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let sans = &parsed
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names;
    assert!(
        matches!(&sans[0], x509_parser::extensions::GeneralName::DNSName(name)
            if *name == "*.example.com"),
        "{sans:?}"
    );
}

/// With `dns-01` off there is no challenge that could prove a wildcard, so the
/// order is refused rather than made unsatisfiable.
#[tokio::test]
async fn a_wildcard_is_refused_when_dns_01_is_not_enabled() {
    let (app, _db) = test_app_with_challenges(
        Config::default(),
        bypassing_challenges(&["http-01", "tls-alpn-01"]),
    )
    .await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, &["*.example.com"]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    assert!(problem["detail"].as_str().unwrap().contains("dns-01"));
}

/// A `*` that is not the leading `*.` is malformed, not refused by policy.
#[tokio::test]
async fn a_malformed_wildcard_is_a_400_even_with_dns_01_enabled() {
    let (app, _db) =
        test_app_with_challenges(Config::default(), bypassing_challenges(&["dns-01"])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    for value in ["*example.com", "*.*.example.com", "a.*.example.com", "*"] {
        let res = new_order(&app, &signer, &account_url, &[value]).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:malformed",
            "{value}"
        );
    }
}
