//! Drives the router with a **non-default** configuration.
//!
//! Every other test crate builds its app from `Config::default()`, so
//! `server.base_url`, `nonce.ttl_seconds`, `order.validity_seconds` and the
//! signer's leaf policy were never exercised at any other value — a bug that
//! hardcoded `http://localhost:3000` somewhere, or ignored a configured TTL,
//! would have been invisible.

use std::sync::Arc;
use std::time::Duration;

use acme_proxy::config::Config;
use acme_proxy::filter::FilterPolicy;
use acme_proxy::signer::local_ca::LocalCa;
use acme_proxy::sqlite::db::Database;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, default_challenges, first_certificate, make_csr,
    no_notifications, p, test_app_full,
};

/// The custom `server.base_url` this crate configures: the *server's* base,
/// naming the process.
const HOST: &str = "https://acme.example.test:8443";

/// The profile base URL that follows from it — `server.base_url` plus the
/// endpoint's own mount point, which is what every advertised URL is built
/// from and what a JWS `url` must name.
const BASE: &str = "https://acme.example.test:8443/profile/default";

/// A config that differs from the defaults in every value this crate asserts on.
///
/// `nonce.ttl_seconds` is deliberately *not* shortened here. It used to be `1`
/// for every test in this file, which made each of them a race against the
/// clock: a multi-request flow only had one second from each nonce being minted,
/// and under a loaded machine — the whole suite in parallel, or a compile
/// running alongside — a request would lose it and fail with `badNonce` for
/// reasons having nothing to do with what was being tested. The one test that
/// genuinely needs a short window sets it itself.
fn config() -> Config {
    let mut config = Config::default();
    config.server.base_url = HOST.to_string();
    config.order.validity_seconds = 3600;
    config.signer.local_ca.leaf_validity_days = 7;
    config
}

/// [`config`] with a nonce lifetime short enough to outlive in a test.
fn config_with_short_nonce_ttl() -> Config {
    let mut config = config();
    config.nonce.ttl_seconds = 1;
    config
}

async fn app_with(config: Config) -> (Router, Arc<Database>) {
    let leaf_days = config.signer.local_ca.leaf_validity_days;
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", leaf_days).unwrap());
    test_app_full(
        config,
        signer,
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications().await,
    )
    .await
}

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

/// A fresh nonce from the configured server.
async fn nonce(app: &Router) -> String {
    let res = app
        .clone()
        .oneshot(Request::get(p("/newNonce")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    res.headers()
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("newNonce must set Replay-Nonce")
        .to_string()
}

async fn register(app: &Router, signer: &EcSigner) -> String {
    let nonce = nonce(app).await;
    let body = signer.sign(
        &format!("{BASE}/newAccount"),
        &nonce,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(app, &p("/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string()
}

/// Every URL the server hands out is built from `server.base_url`, not from a
/// literal — the directory, the account `Location`, and the order's derived
/// `finalize`/`authorizations` URLs.
#[tokio::test]
async fn every_advertised_url_uses_the_configured_base() {
    let (app, _db) = app_with(config()).await;

    let res = app
        .clone()
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let directory: Value = body_json(res).await;
    assert_eq!(directory["newNonce"], format!("{BASE}/newNonce"));
    assert_eq!(directory["newAccount"], format!("{BASE}/newAccount"));
    assert_eq!(directory["newOrder"], format!("{BASE}/newOrder"));

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    assert!(
        account_url.starts_with(&format!("{BASE}/acct/")),
        "account Location should use the configured base: {account_url}"
    );

    // newOrder's derived URLs too.
    let n = nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, &format!("{BASE}/newOrder"), &n, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order = body_json(res).await;
    let finalize = order["finalize"].as_str().unwrap();
    assert!(finalize.starts_with(BASE), "{finalize}");
    let authz = order["authorizations"][0].as_str().unwrap();
    assert!(authz.starts_with(&format!("{BASE}/authz/")), "{authz}");
}

/// A JWS `url` naming the *default* base is refused when the server is
/// configured with another. This is the check that would silently pass if any
/// handler compared against a hardcoded literal.
#[tokio::test]
async fn a_url_for_the_default_base_is_refused() {
    let (app, _db) = app_with(config()).await;
    let signer = EcSigner::new();

    let n = nonce(&app).await;
    let body = signer.sign(
        "http://localhost:3000/profile/default/newAccount",
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(&app, &p("/newAccount"), body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
}

/// `nonce.ttl_seconds` is honoured: a nonce older than the window is refused
/// with `badNonce` rather than accepted. Only ever tested for *unknown* and
/// *replayed* nonces before, never for an expired one.
#[tokio::test]
async fn a_nonce_older_than_the_configured_ttl_is_refused() {
    // 1-second TTL, so the test can outlive it without a long sleep.
    let (app, _db) = app_with(config_with_short_nonce_ttl()).await;
    let signer = EcSigner::new();

    let n = nonce(&app).await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let body = signer.sign(
        &format!("{BASE}/newAccount"),
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(&app, &p("/newAccount"), body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");
}

/// `order.validity_seconds` sets the order's `expires`, and
/// `signer.local_ca.leaf_validity_days` the issued certificate's — two separate
/// knobs that are easy to conflate.
#[tokio::test]
async fn the_order_window_and_the_leaf_window_are_configured_separately() {
    let (app, _db) = app_with(config()).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let n = nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, &format!("{BASE}/newOrder"), &n, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    // `expires` is now + order.validity_seconds (3600), so within the hour.
    let expires = order["expires"].as_str().expect("order must carry expires");
    let expires =
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .expect("expires must be RFC3339");
    let ahead = expires - time::OffsetDateTime::now_utc();
    assert!(
        ahead <= time::Duration::seconds(3600) && ahead > time::Duration::seconds(3500),
        "expires should be ~1h out, was {ahead:?}"
    );

    // Drive to ready and finalize, then read the leaf's own validity.
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let n = nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &authz_url, &n);
    let res = post(&app, authz_url.strip_prefix(HOST).unwrap(), body).await;
    let authz = body_json(res).await;
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let n = nonce(&app).await;
    let body = signer.sign_kid(&account_url, &chall_url, &n, &json!({}));
    assert_eq!(
        post(&app, chall_url.strip_prefix(HOST).unwrap(), body)
            .await
            .status(),
        StatusCode::OK
    );

    let finalize_url = format!("{order_url}/finalize");
    let n = nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &finalize_url,
        &n,
        &json!({ "csr": make_csr("example.com") }),
    );
    let res = post(&app, finalize_url.strip_prefix(HOST).unwrap(), body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cert_url = body_json(res).await["certificate"]
        .as_str()
        .unwrap()
        .to_string();

    let n = nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &n);
    let res = post(&app, cert_url.strip_prefix(HOST).unwrap(), body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let pem = String::from_utf8(
        http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // The leaf's validity comes from `leaf_validity_days` (7), not the order's.
    let leaf = first_certificate(&pem);
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let validity = parsed.validity().not_after.to_datetime() - time::OffsetDateTime::now_utc();
    assert!(
        validity <= time::Duration::days(7) && validity > time::Duration::days(6),
        "leaf should be valid ~7 days, was {validity:?}"
    );
}
