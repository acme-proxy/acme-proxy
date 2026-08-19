//! `GET /ca.pem`: the trust anchor a client installs to accept what this
//! profile issues. Like `GET /crl` it is CA infrastructure rather than an ACME
//! resource — unauthenticated, no JWS/nonce dance, and never advertised in the
//! directory (pinned in `tests/basic_endpoints.rs`).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use x509_parser::prelude::FromDer;

mod common;
use common::{EcSigner, FailingSigner, acme, p, test_app, test_app_with_signer};
use std::sync::Arc;

async fn get(app: axum::Router, path: &str) -> axum::response::Response {
    app.oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn the_local_cas_certificate_is_served_and_parses() {
    let res = get(test_app().await, &p("/ca.pem")).await;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        // Not `application/pem-certificate-chain`: RFC 8555 §7.4.2 defines that
        // for an *end-entity* chain, leaf first, which is the opposite of this.
        Some("application/x-pem-file"),
    );

    let pem = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    let der = acme_proxy::cert::leaf_der_from_chain(&pem)
        .expect("served bytes must parse as a PEM certificate");
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
        .expect("and as a valid X.509 certificate");

    // The whole point of the route: what a client installs has to be usable as
    // a trust anchor. A leaf served here would be silently useless.
    let constraints = cert
        .basic_constraints()
        .expect("basicConstraints must parse")
        .expect("a CA certificate carries basicConstraints");
    assert!(constraints.value.ca, "the served certificate must be a CA");
}

/// The anchor served here is byte-identical to the one already appended to
/// every issued chain.
///
/// This is what makes the route worth having rather than merely working: a
/// client that fetches `/ca.pem` and a client that reads the tail of its own
/// certificate chain must end up trusting the same bytes, or one of the two
/// paths is installing something that will not validate.
#[tokio::test]
async fn the_served_anchor_is_the_one_appended_to_an_issued_chain() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let (_account_url, _order_url, chain) =
        acme::issue_certificate(&app, &signer, &["example.com"]).await;

    let res = get(app, &p("/ca.pem")).await;
    let anchor = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(
        chain.ends_with(&anchor),
        "the issued chain must end with exactly the bytes /ca.pem serves"
    );
    assert_ne!(
        chain.trim(),
        anchor.trim(),
        "and must carry a leaf in front of it — otherwise the assertion above \
         passes for an empty anchor"
    );
}

/// A backend with no anchor of its own answers `404`, not an empty `200`.
///
/// Reachable in production for both delegating backends: `relay`'s anchor
/// belongs to the upstream CA and is published at a URL of the upstream's
/// choosing, and a `custom` script's is wherever its operator put it. Serving
/// something here on their behalf would be inventing a trust anchor, which is
/// strictly worse than saying nothing — the same reasoning that makes an
/// absent CRL a `404` rather than an empty one.
#[tokio::test]
async fn a_backend_with_no_anchor_answers_404() {
    let (app, _database) = test_app_with_signer(Arc::new(FailingSigner)).await;

    let res = get(app, &p("/ca.pem")).await;

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "no body at all, rather than something a PEM parser might accept"
    );
}
