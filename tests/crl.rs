//! `GET /crl`: the local CA's certificate revocation list (RFC 5280). Not an
//! ACME resource — plain unauthenticated infrastructure, so no JWS/nonce
//! dance, just a request. See `tests/revoke_cert.rs` for the case where a
//! revoked certificate's serial actually appears in it.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use x509_parser::prelude::FromDer;

mod common;
use common::{FailingSigner, p, test_app, test_app_with_signer};
use std::sync::Arc;

#[tokio::test]
async fn an_empty_crl_is_served_by_default() {
    let res = test_app()
        .await
        .oneshot(Request::get(p("/crl")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/pkix-crl"),
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    // A signed CRL, even with zero revoked entries, is never empty bytes.
    assert!(!body.is_empty());

    // And it must actually parse as a CRL.
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&body)
        .expect("served bytes must parse as a valid CRL");
    assert_eq!(crl.iter_revoked_certificates().count(), 0);
}

/// A backend with no CRL to offer answers `404`, **not** an empty `200`.
///
/// Reachable in production today: `signer.backend = "custom"` with
/// `supports_crl` unset, or `acme_proxy`, both of which leave `crl_der`'s
/// default "nothing to say here" in place. The distinction is the whole point
/// of the test — an empty but validly-signed CRL is a positive statement that
/// *nothing is revoked*, so serving one on behalf of a backend that was never
/// asked would tell a relying party the opposite of the truth.
#[tokio::test]
async fn a_backend_with_no_crl_answers_404_rather_than_an_empty_one() {
    let (app, _database) = test_app_with_signer(Arc::new(FailingSigner)).await;

    let res = app
        .oneshot(Request::get(p("/crl")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "no body at all, rather than something a CRL parser might accept"
    );
}
