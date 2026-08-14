//! The optional `meta` members of the directory object (RFC 8555 §7.1.1), and
//! the one that has teeth: `termsOfService` and §7.3.3's agreement requirement.
//!
//! Configured rather than defaulted, so this crate — like `config_driven.rs` —
//! builds its app from a non-default `Config`.

use std::sync::Arc;

use acme_proxy::config::Config;
use acme_proxy::filter::FilterPolicy;
use acme_proxy::signer::local_ca::LocalCa;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, default_challenges, fetch_nonce, no_notifications, p,
    test_app_full,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const TOS: &str = "https://acme.example.test/terms/v3";

async fn app_with(config: Config) -> Router {
    test_app_full(
        config,
        Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap()),
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications(),
    )
    .await
    .0
}

async fn fetch_directory(app: &Router) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

async fn register(app: &Router, signer: &impl TestSigner, agreed: bool) -> Response {
    let nonce = fetch_nonce(app).await;
    app.clone()
        .oneshot(
            Request::post(p("/newAccount"))
                .header("content-type", "application/jose+json")
                .body(Body::from(signer.sign(
                    NEW_ACCOUNT_URL,
                    &nonce,
                    &json!({ "termsOfServiceAgreed": agreed }),
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// §7.1.1 makes every `meta` member optional. An unconfigured endpoint says
/// nothing rather than advertising empty strings — `"website": ""` is worse than
/// silence, because a client cannot tell it apart from a real (broken) value.
#[tokio::test]
async fn an_unconfigured_endpoint_advertises_no_meta_at_all() {
    let directory = fetch_directory(&app_with(Config::default()).await).await;
    assert!(
        directory.get("meta").is_none(),
        "nothing configured, nothing to say: {directory}"
    );
}

/// Each member appears exactly when it is configured, and not otherwise.
#[tokio::test]
async fn configured_meta_members_are_advertised() {
    let mut config = Config::default();
    config.meta.terms_of_service = TOS.to_string();
    config.meta.website = "https://acme.example.test/".to_string();
    config.meta.caa_identities = vec!["example.test".to_string(), "acme.example.test".to_string()];

    let directory = fetch_directory(&app_with(config).await).await;
    let meta = &directory["meta"];
    assert_eq!(meta["termsOfService"], TOS);
    assert_eq!(meta["website"], "https://acme.example.test/");
    assert_eq!(
        meta["caaIdentities"],
        json!(["example.test", "acme.example.test"])
    );
    // EAB is off here, so its own member must not appear alongside them.
    assert!(meta.get("externalAccountRequired").is_none());

    // Only what was set: a partially configured endpoint advertises a partial
    // `meta`, not one padded with blanks.
    let mut config = Config::default();
    config.meta.website = "https://acme.example.test/".to_string();
    let partial = fetch_directory(&app_with(config).await).await;
    assert_eq!(partial["meta"]["website"], "https://acme.example.test/");
    assert!(partial["meta"].get("termsOfService").is_none());
    assert!(partial["meta"].get("caaIdentities").is_none());
}

/// §7.3.3: a client agrees by setting `termsOfServiceAgreed`, and §6.7's
/// `userActionRequired` is the refusal when it has not — paired with the link
/// naming what there is to agree to.
#[tokio::test]
async fn a_configured_tos_must_be_agreed_to() {
    let mut config = Config::default();
    config.meta.terms_of_service = TOS.to_string();
    let app = app_with(config).await;

    let signer = EcSigner::new();
    let res = register(&app, &signer, false).await;

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
    );
    let links: Vec<&str> = res
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        links.contains(&format!("<{TOS}>;rel=\"terms-of-service\"").as_str()),
        "the refusal must name the terms: {links:?}"
    );
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:userActionRequired"
    );

    // Agreeing works, and §7.1.2's optional member reflects it back.
    let signer = EcSigner::new();
    let res = register(&app, &signer, true).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(body_json(res).await["termsOfServiceAgreed"], true);
}

/// With no terms configured the flag is vacuous, and the account object must not
/// claim anything about it: an account created here neither agreed nor declined,
/// and `false` would misrepresent that.
#[tokio::test]
async fn without_a_configured_tos_nothing_is_required_or_claimed() {
    let app = app_with(Config::default()).await;

    for agreed in [false, true] {
        let signer = EcSigner::new();
        let res = register(&app, &signer, agreed).await;
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "agreement must not be demanded when none is advertised"
        );
        let account = body_json(res).await;
        assert!(
            account.get("termsOfServiceAgreed").is_none(),
            "nothing to agree to, nothing to reflect: {account}"
        );
    }
}
