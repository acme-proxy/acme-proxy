//! The Prometheus counters and histograms, moved by real traffic through the
//! real router.
//!
//! The unit suites in `crates/jobs/src/metrics.rs` and `crates/protocol/src/middlewares/metrics.rs` pin the
//! exposition format and the label cardinality against a synthetic router. What
//! they cannot show is that the counters are wired to anything: that an ACME
//! request really reaches the middleware, and that an issuance really reaches
//! `Auditor::record`. That is what this file is for.
//!
//! Note it never scrapes over HTTP. `/metrics` is served by a **separate
//! listener** on its own port, which `crates/server/src/tests.rs`'s three-port test
//! drives end to end — including that the route is a `404` on the ACME socket.
//! Here the registry is read directly, because what is under test is what moves
//! it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

mod common;
use common::{EcSigner, TestSigner, acme, make_csr, p, test_app_with_metrics};

/// The one series an ACME request must move, with the labels it must carry.
///
/// `/directory` rather than a signed route: this is about the middleware being
/// mounted at all, and an unsigned GET keeps the assertion about one thing.
#[tokio::test]
async fn an_acme_request_is_counted_under_its_profile_and_route() {
    let (app, _database, metrics) =
        test_app_with_metrics(Default::default(), Arc::new(common::memory_ca().await)).await;

    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "acme_proxy_requests_total{role=\"acme,admin,worker\",profile=\"default\",route=\"/directory\",status=\"200\"} 3\n"
        ),
        "{rendered}"
    );
    // Timed under the same route, without the status.
    assert!(
        rendered.contains(
            "acme_proxy_request_duration_seconds_count{role=\"acme,admin,worker\",profile=\"default\",route=\"/directory\"} 3\n"
        ),
        "{rendered}"
    );
}

/// A real issuance, driven through the whole ACME ladder.
///
/// The counter comes off the `AuditRecord` in `Auditor::record`, so this also
/// pins that the auditor the app was built with is the one carrying the
/// registry — wire that up wrong and every number here stays at zero while
/// everything else still passes.
#[tokio::test]
async fn issuing_a_certificate_moves_the_issued_counter() {
    let (app, _database, metrics) =
        test_app_with_metrics(Default::default(), Arc::new(common::memory_ca().await)).await;
    let signer = EcSigner::new();

    acme::issue_certificate(&app, &signer, &["metrics.example.com"]).await;

    let rendered = metrics.render();
    assert!(
        rendered.contains("acme_proxy_certificates_issued_total{role=\"acme,admin,worker\",profile=\"default\"} 1\n"),
        "{rendered}"
    );
    // And timed: the `signer_issue` job that signed it observed the issuance
    // histogram once, from the finalize that enqueued it.
    assert!(
        rendered.contains(
            "acme_proxy_certificate_issue_duration_seconds_count{role=\"acme,admin,worker\",profile=\"default\"} 1\n"
        ),
        "{rendered}"
    );
    // Nothing was refused, so the failure family is declared and empty — which
    // is the state a dashboard has to be able to tell from a misspelled name.
    assert!(
        rendered.contains("# TYPE acme_proxy_certificate_issue_failures counter\n"),
        "{rendered}"
    );
    assert!(
        !rendered
            .contains("acme_proxy_certificate_issue_failures_total{role=\"acme,admin,worker\","),
        "{rendered}"
    );
}

/// A CSR the CA refuses, counted under the ACME problem type it was refused
/// with.
///
/// The `reason` label is what makes the failure counter worth more than the
/// request counter's `status="400"`: it says *why*, and it says it in the same
/// vocabulary `acme-proxy audit list --event certificate_issue_failed` uses,
/// because both are rendered from one `AuditRecord`.
#[tokio::test]
async fn a_refused_csr_is_counted_with_its_reason() {
    let (app, _database, metrics) =
        test_app_with_metrics(Default::default(), Arc::new(common::memory_ca().await)).await;
    let signer = EcSigner::new();

    let (account_url, _order_url, order) =
        acme::ready_order(&app, &signer, &["wanted.example.com"]).await;
    let finalize_url = order["finalize"].as_str().unwrap().to_string();

    // A CSR for a name the order does not cover: `badCSR`, and the CA is the
    // one refusing rather than the protocol layer above it.
    let nonce = common::fetch_nonce(&app).await;
    let payload = serde_json::json!({ "csr": make_csr("other.example.com") });
    let body = signer.sign_kid(&account_url, &finalize_url, &nonce, &payload);
    let response = acme::post(&app, &acme::path_of(&finalize_url), body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "acme_proxy_certificate_issue_failures_total{role=\"acme,admin,worker\",profile=\"default\",reason=\"badCSR\"} 1\n"
        ),
        "{rendered}"
    );
    assert!(
        !rendered.contains("acme_proxy_certificates_issued_total{role=\"acme,admin,worker\","),
        "nothing was signed: {rendered}"
    );
}
