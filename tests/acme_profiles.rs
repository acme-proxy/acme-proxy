//! ACME profiles (draft-ietf-acme-profiles) on a `local_ca` endpoint, from the
//! outside: what the directory lists, what `newOrder` accepts, refuses or
//! fills in, what the order object reports, and the lifetime the certificate
//! comes back with — issue #54's "whatever the client requests, only
//! short-lived certificates".
//!
//! The rules themselves (`AcmeProfiles::resolve`) and the configuration
//! checks are inline in `acme-proxy-signer`; the relay's pass-through and
//! forced profile are in its own tests, against the fake upstream.

use std::sync::Arc;

use acme_proxy_core::config::{Config, ConfigDuration, LocalCaConfig, LocalCaProfileConfig};
use acme_proxy_policy::filter::FilterPolicy;
use acme_proxy_signer::local_ca::LocalCa;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

mod common;
use common::acme::{
    assert_problem, await_order, body_text, drive_to_ready, finalize, location, path_of, post,
    post_as_get, register,
};
use common::{
    EcSigner, TestSigner, body_json, default_challenges, fetch_nonce, no_notifications, p,
    test_app_full,
};

const NEW_ORDER_URL: &str = "http://localhost:3000/endpoint/default/newOrder";

/// A `local_ca` configuration offering `profiles` (name, description,
/// lifetime), with `default` as its `default_profile`.
fn offering(profiles: &[(&str, &str, &str)], default: &str) -> LocalCaConfig {
    LocalCaConfig {
        leaf_validity: ConfigDuration::from_days(30),
        profiles: profiles
            .iter()
            .map(|(name, description, lifetime)| {
                (
                    (*name).to_string(),
                    LocalCaProfileConfig {
                        description: (*description).to_string(),
                        leaf_validity: ConfigDuration::parse(lifetime).unwrap(),
                    },
                )
            })
            .collect(),
        default_profile: default.to_string(),
        ..LocalCaConfig::default()
    }
}

async fn app_with(local_ca: LocalCaConfig) -> Router {
    let database = Arc::new(
        acme_proxy_store::db::Database::connect_in_memory()
            .await
            .unwrap(),
    );
    let signer = LocalCa::generate_in_memory_offering(&local_ca, database).unwrap();
    test_app_full(
        Config::default(),
        Arc::new(signer),
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications().await,
    )
    .await
    .0
}

/// The two profiles issue #54's operator would offer.
fn short_and_classic(default: &str) -> LocalCaConfig {
    offering(
        &[
            ("shortlived", "160-hour certificates", "160h"),
            ("classic", "90-day certificates", "90d"),
        ],
        default,
    )
}

async fn directory(app: &Router) -> Value {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .uri(p("/directory"))
        .body(axum::body::Body::empty())
        .unwrap();
    body_json(app.clone().oneshot(request).await.unwrap()).await
}

/// `newOrder` for `example.com` with `extra` merged into the payload.
async fn new_order_with(
    app: &Router,
    signer: &EcSigner,
    account_url: &str,
    extra: Value,
) -> axum::response::Response {
    let mut payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    for (key, value) in extra.as_object().unwrap() {
        payload[key] = value.clone();
    }
    let nonce = fetch_nonce(app).await;
    post(
        app,
        &p("/newOrder"),
        signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload),
    )
    .await
}

/// Proves, finalizes and downloads, returning the leaf's lifetime in seconds
/// (`notAfter - notBefore`, the backdate included).
async fn issued_lifetime(
    app: &Router,
    signer: &EcSigner,
    account_url: &str,
    order_url: &str,
) -> i64 {
    let order = post_as_get(app, signer, account_url, order_url).await;
    drive_to_ready(app, signer, account_url, &order).await;
    let response = finalize(
        app,
        signer,
        account_url,
        order["finalize"].as_str().unwrap(),
        &["example.com"],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "finalize");
    let order = await_order(app, signer, account_url, order_url).await;
    assert_eq!(order["status"], "valid", "{order}");

    let certificate_url = order["certificate"].as_str().unwrap();
    let nonce = fetch_nonce(app).await;
    let response = post(
        app,
        &path_of(certificate_url),
        signer.sign_kid_empty(account_url, certificate_url, &nonce),
    )
    .await;
    let chain = body_text(response).await;
    let leaf = acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap();
    let (not_before, not_after) = acme_proxy_core::cert::cert_validity(&leaf).unwrap();
    not_after - not_before
}

const HOUR: i64 = 3600;

#[tokio::test]
async fn the_directory_lists_each_offered_profile_with_its_description() {
    let app = app_with(short_and_classic("")).await;
    assert_eq!(
        directory(&app).await["meta"]["profiles"],
        json!({
            "classic": "90-day certificates",
            "shortlived": "160-hour certificates",
        })
    );
}

#[tokio::test]
async fn a_ca_offering_no_profiles_lists_none() {
    let app = app_with(offering(&[], "")).await;
    let directory = directory(&app).await;
    assert!(
        directory.pointer("/meta/profiles").is_none(),
        "absent, not empty: {directory}"
    );
}

/// The point of #54: the client picks the short-lived profile and gets a
/// certificate of that profile's lifetime, not the CA's own.
#[tokio::test]
async fn an_order_naming_a_profile_is_issued_under_it() {
    let app = app_with(short_and_classic("")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let response = new_order_with(
        &app,
        &signer,
        &account_url,
        json!({ "profile": "shortlived" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_url = location(&response);
    assert_eq!(body_json(response).await["profile"], "shortlived");
    // Reflected on every later read of the order, not only the 201.
    assert_eq!(
        post_as_get(&app, &signer, &account_url, &order_url).await["profile"],
        "shortlived"
    );

    let lifetime = issued_lifetime(&app, &signer, &account_url, &order_url).await;
    assert!((lifetime - 161 * HOUR).abs() <= 2, "{lifetime}");
}

/// An order naming no profile gets `default_profile` — and so does a client
/// that has never heard of profiles, which is how a CA offering only
/// `shortlived` issues nothing else.
#[tokio::test]
async fn an_order_naming_none_gets_the_default_profile() {
    let app = app_with(offering(&[("shortlived", "160 h", "160h")], "shortlived")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let response = new_order_with(&app, &signer, &account_url, json!({})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_url = location(&response);
    assert_eq!(body_json(response).await["profile"], "shortlived");

    let lifetime = issued_lifetime(&app, &signer, &account_url, &order_url).await;
    assert!((lifetime - 161 * HOUR).abs() <= 2, "{lifetime}");
}

/// Without a default, an order naming none is issued under the CA's own
/// `leaf_validity` and carries no profile.
#[tokio::test]
async fn without_a_default_an_order_naming_none_has_no_profile() {
    let app = app_with(short_and_classic("")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let response = new_order_with(&app, &signer, &account_url, json!({})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_url = location(&response);
    assert!(body_json(response).await.get("profile").is_none());

    let lifetime = issued_lifetime(&app, &signer, &account_url, &order_url).await;
    assert!((lifetime - (30 * 24 + 1) * HOUR).abs() <= 2, "{lifetime}");
}

#[tokio::test]
async fn an_order_naming_a_profile_not_offered_is_refused() {
    let app = app_with(offering(&[("shortlived", "160 h", "160h")], "shortlived")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let response =
        new_order_with(&app, &signer, &account_url, json!({ "profile": "classic" })).await;
    assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:invalidProfile",
    )
    .await;
}

/// A server that advertises no profiles ignores the field, as it always did:
/// a client is not refused for naming one where none are offered.
#[tokio::test]
async fn a_profile_named_where_none_are_offered_is_ignored() {
    let app = app_with(offering(&[], "")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let response = new_order_with(
        &app,
        &signer,
        &account_url,
        json!({ "profile": "shortlived" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(body_json(response).await.get("profile").is_none());
}

/// A client's `notAfter` still only shortens: a profile is the ceiling, the
/// way `leaf_validity` is.
#[tokio::test]
async fn a_requested_not_after_narrows_a_profile_but_never_widens_it() {
    let app = app_with(short_and_classic("")).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let in_a_year = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let not_after = in_a_year
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let response = new_order_with(
        &app,
        &signer,
        &account_url,
        json!({ "profile": "shortlived", "notAfter": not_after }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_url = location(&response);
    let lifetime = issued_lifetime(&app, &signer, &account_url, &order_url).await;
    assert!((lifetime - 161 * HOUR).abs() <= 2, "{lifetime}");
}
