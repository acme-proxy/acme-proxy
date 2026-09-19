//! A signer backend's construction arguments, and a local CA's served CRL,
//! for tests that are not about either.
//!
//! Compiled only under `cfg(test)` or the `test-util` feature, which the other
//! crates of this workspace turn on through their `[dev-dependencies]` alone.

/// The dependencies a signer backend is built from, for a test that is not about
/// any of them.
///
/// No notifiers (nothing dispatches), a registry nothing scrapes and a queue
/// nothing drains — the same three "throwaway" arguments every one of these call
/// sites used to spell out one by one before `SignerParts` gathered them.
pub fn signer_parts(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
    resolver: std::sync::Arc<dyn acme_proxy_net::dns::Resolver>,
) -> crate::SignerParts {
    crate::SignerParts {
        database: database.clone(),
        notifiers: std::collections::HashMap::new().into(),
        metrics: acme_proxy_jobs::testutil::test_metrics(database.clone()),
        egress: acme_proxy_net::testutil::egress_with(resolver),
        jobs: acme_proxy_jobs::testutil::idle_job_queue(database),
    }
}

/// The CRL `backend` serves once a worker has met it — its first CRL stored,
/// the way the startup `CrlSweepJob` pass leaves it — read through its read
/// side, which is what `GET /crl` does.
pub async fn served_crl(backend: &dyn crate::SignerBackend) -> Vec<u8> {
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
