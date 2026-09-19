//! Scratch-directory and script helpers shared by the crate's unit tests.
//!
//! `TempDir` had grown seven independent copies (`tls`, `pemfile`,
//! `signer::custom`, `signer::relay`, `filter::custom`, `notify::custom`,
//! and one in the integration harness), and `write_script` four — including a
//! verbatim ten-line comment about `ETXTBSY`, which is the sort of hard-won
//! explanation that should exist in one place or it stops being maintained in
//! any of them.
//!
//! `#[cfg(test)]` rather than a real module: this is scaffolding, and shipping
//! it in the library would be shipping test code to every consumer. Integration
//! tests cannot see it for the same reason and keep their own copy under
//! `tests/common/`.

use std::sync::Arc;

/// A Prometheus registry for a test that only needs one to exist.
///
/// Every `RelaySigner::from_config` takes one because the backend counts a
/// deferred issuance through it; almost no test asserts on the counters, so
/// this keeps the noise to one call.
pub(crate) fn test_metrics(
    database: Arc<acme_proxy_store::db::Database>,
) -> Arc<crate::metrics::Metrics> {
    Arc::new(crate::metrics::Metrics::new(database))
}

/// A job queue with nothing draining it.
///
/// What every test that merely has to *construct* a signer backend wants: the
/// queue is a constructor argument since the `relay` backend defers issuance
/// into it, and a test asserting on a startup refusal or a synchronous backend
/// never enqueues anything. A test that needs the work actually done starts a
/// runner over its own queue instead — see `signer::relay::tests::TestRunner`.
pub(crate) fn idle_job_queue(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, &acme_proxy_core::config::JobsConfig::default())
}

/// The dependencies a signer backend is built from, for a test that is not about
/// any of them.
///
/// No notifiers (nothing dispatches), a registry nothing scrapes and a queue
/// nothing drains — the same three "throwaway" arguments every one of these call
/// sites used to spell out one by one before `SignerParts` gathered them.
pub(crate) fn signer_parts(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
    resolver: std::sync::Arc<dyn acme_proxy_net::dns::Resolver>,
) -> crate::signer::SignerParts {
    crate::signer::SignerParts {
        database: database.clone(),
        notifiers: std::collections::HashMap::new().into(),
        metrics: test_metrics(database.clone()),
        egress: acme_proxy_net::testutil::egress_with(resolver),
        jobs: idle_job_queue(database),
    }
}

/// The CRL `backend` serves once a worker has met it — its first CRL stored,
/// the way the startup `CrlSweepJob` pass leaves it — read through its read
/// side, which is what `GET /crl` does.
pub(crate) async fn served_crl(backend: &dyn crate::signer::SignerBackend) -> Vec<u8> {
    if let Some(refresher) = backend.crl_refresher() {
        refresher.refresh().await.unwrap();
    }
    backend
        .info()
        .crl_der()
        .await
        .unwrap()
        .expect("a local CA serves a CRL")
}
