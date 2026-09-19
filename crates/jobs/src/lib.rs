//! The work acme-proxy owes itself, and the record of what it did: the
//! durable job queue ([`jobs`]), the notifications delivered through it
//! ([`notify`]), the audit trail's writer ([`auditor`]) and the Prometheus
//! counters driven off the same records ([`metrics`]).
//!
//! Below the signers, which queue their deferred work here and announce what
//! they issue, and above the storage layer every one of these writes to. An
//! internal crate of the `acme-proxy` binary, published in lockstep with it
//! and with no semver promise of its own.

pub mod auditor;
pub mod jobs;
pub mod metrics;
pub mod notify;
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
