//! A metrics registry and a job queue for tests that only need one to exist.
//!
//! Compiled only under `cfg(test)` or the `test-util` feature, which the other
//! crates of this workspace turn on through their `[dev-dependencies]` alone.

use std::sync::Arc;

/// A Prometheus registry for a test that only needs one to exist.
///
/// Every `RelaySigner::from_config` takes one because the backend counts a
/// deferred issuance through it; almost no test asserts on the counters, so
/// this keeps the noise to one call.
pub fn test_metrics(database: Arc<acme_proxy_store::db::Database>) -> Arc<crate::metrics::Metrics> {
    Arc::new(crate::metrics::Metrics::new(database))
}

/// A job queue with nothing draining it.
///
/// What every test that merely has to *construct* a signer backend wants: the
/// queue is a constructor argument since the `relay` backend defers issuance
/// into it, and a test asserting on a startup refusal or a synchronous backend
/// never enqueues anything. A test that needs the work actually done starts a
/// runner over its own queue instead — see `signer::relay::tests::TestRunner`.
pub fn idle_job_queue(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, &acme_proxy_core::config::JobsConfig::default())
}
