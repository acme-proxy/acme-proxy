//! The bottom of acme-proxy's crate graph: what every layer above it speaks.
//!
//! Configuration ([`config`]), the ACME wire vocabulary ([`identifier`],
//! [`jws`], [`error`]'s problem documents, [`routes`]), the nested-JWS
//! surfaces that are pure verification ([`eab`], [`key_change`]), certificate
//! parsing ([`cert`]), the audit trail's vocabulary ([`audit`]), where a
//! request came from ([`client`]), and the small shared helpers
//! ([`logfields`], [`palette`], [`pemfile`], [`random`], [`script_hook`],
//! [`templating`]).
//!
//! Nothing here opens a database, dials a network or knows a signer; the
//! crates that do are built on it. An internal crate of the `acme-proxy`
//! binary, published in lockstep with it and with no semver promise of its
//! own.

pub mod audit;
pub mod cert;
pub mod client;
pub mod config;
pub mod eab;
pub mod error;
pub mod identifier;
pub mod jws;
pub mod key_change;
pub mod logfields;
pub mod palette;
pub mod pemfile;
pub mod random;
pub mod routes;
pub mod script_hook;
pub mod templating;
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
