//! `GET /.well-known/acme-challenge/{token}`: the file an *upstream* CA fetches
//! when the `relay` signer backend proves domain control to it over HTTP.
//!
//! The inverse of every other route in this suite. Elsewhere a client asks this
//! server for a certificate; here a CA asks this server to prove itself, so the
//! fetcher holds no account, sends no JWS, and must not meet a filter chain, a
//! nonce or an ACME problem document. `src/signer/relay/mod.rs`'s own tests
//! cover the relay publishing into the store — what is pinned here is the
//! **mounting**: that `build_app` exposes the route exactly when a backend has
//! tokens to serve, outside the layers a profile carries.

use std::sync::Arc;

use acme_proxy::signer::relay::http01::TokenStore;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

mod common;
use common::{
    RejectingCheck, TokenStoreSigner, default_challenges, no_notifications, test_app,
    test_app_full, test_app_with_signer,
};

use acme_proxy::config::Config;

/// The well-known path, as an upstream CA would build it.
fn well_known(token: &str) -> String {
    format!("/.well-known/acme-challenge/{token}")
}

/// A published token is served verbatim, with the content type §8.3 recommends.
#[tokio::test]
async fn a_published_token_is_served() {
    let signer = Arc::new(TokenStoreSigner::new());
    signer.0.publish("tok", "tok.thumbprint");
    let (app, _db) = test_app_with_signer(signer).await;

    let res = app
        .oneshot(Request::get(well_known("tok")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream"),
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    // Byte-equal, with no trailing newline: RFC 8555 §8.3's body *is* the key
    // authorization. Validators trim, but there is no reason to make them.
    assert_eq!(&body[..], b"tok.thumbprint");
}

/// An unknown token is a plain 404, not an ACME problem document.
///
/// This route is a public file, not an ACME resource. Answering
/// `application/problem+json` with a `urn:ietf:params:acme:error:` type would
/// tell anyone who probes the path otherwise.
#[tokio::test]
async fn an_unknown_token_is_a_plain_not_found() {
    let (app, _db) = test_app_with_signer(Arc::new(TokenStoreSigner::new())).await;

    let res = app
        .oneshot(
            Request::get(well_known("absent"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let content_type = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !content_type.contains("problem+json"),
        "a public file's 404 must not masquerade as an ACME problem: {content_type}"
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("urn:ietf:params:acme:error:"),
        "the body must not carry an ACME error type: {body}"
    );
}

/// A retracted token stops being served — the property the relay's `Drop` guard
/// exists to guarantee, seen from the route.
#[tokio::test]
async fn a_retracted_token_is_no_longer_served() {
    let signer = Arc::new(TokenStoreSigner::new());
    signer.0.publish("tok", "tok.thumbprint");
    signer.0.retract("tok");
    let (app, _db) = test_app_with_signer(signer).await;

    let res = app
        .oneshot(Request::get(well_known("tok")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// With an ordinary `local_ca` backend the route does not exist at all.
///
/// Not merely "answers 404 for every token": the path is never mounted, so a
/// deployment that never relays anywhere does not expose the surface.
#[tokio::test]
async fn the_route_is_absent_without_a_token_store() {
    let res = test_app()
        .await
        .oneshot(Request::get(well_known("tok")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // The router's own empty 404, not the handler's.
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "no handler should have run");
}

/// The route sits on the root router, so it carries none of the per-profile
/// ACME layers — the "routing splits by concern" invariant, from the one side
/// where a CA that knows nothing about ACME is the client.
#[tokio::test]
async fn the_route_carries_no_acme_layers() {
    let signer = Arc::new(TokenStoreSigner::new());
    signer.0.publish("tok", "tok.thumbprint");
    let (app, _db) = test_app_with_signer(signer).await;

    let res = app
        .oneshot(Request::get(well_known("tok")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get("replay-nonce").is_none(),
        "a CA fetching a file must not be minted an ACME nonce"
    );
    assert!(
        res.headers().get(header::LINK).is_none(),
        "nor pointed at the ACME directory"
    );

    // But the server-wide hardening layers, which wrap the merged router, do
    // still apply.
    for hardened in [
        header::STRICT_TRANSPORT_SECURITY,
        header::X_CONTENT_TYPE_OPTIONS,
        header::X_FRAME_OPTIONS,
    ] {
        assert!(
            res.headers().contains_key(&hardened),
            "missing {hardened}, so the responder was merged outside the hardening layers"
        );
    }
}

/// A profile's filter chain must not reach the responder.
///
/// The upstream CA's validation fetch comes from wherever that CA validates
/// from — several unpredictable addresses, for a multi-perspective one — and it
/// is not the client whose access the operator configured filters to control.
/// A filter that refuses it would deadlock issuance: this server cannot get a
/// certificate without being reachable by the CA it is asking.
#[tokio::test]
async fn the_route_is_not_filtered() {
    let signer = Arc::new(TokenStoreSigner::new());
    signer.0.publish("tok", "tok.thumbprint");
    // A policy that refuses every connection, so nothing but the routing
    // itself can be what lets the fetch through.
    let filter = common::policy_with(Arc::new(RejectingCheck::connections()));
    let (app, _db) = test_app_full(
        Config::default(),
        signer,
        filter,
        default_challenges(),
        no_notifications().await,
    )
    .await;

    let res = app
        .oneshot(Request::get(well_known("tok")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a filter refusing every connection must not reach the responder"
    );
}
