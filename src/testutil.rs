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
        metrics: acme_proxy_jobs::testutil::test_metrics(database.clone()),
        egress: acme_proxy_net::testutil::egress_with(resolver),
        jobs: acme_proxy_jobs::testutil::idle_job_queue(database),
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
