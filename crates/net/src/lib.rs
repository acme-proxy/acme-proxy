//! Everything in acme-proxy that dials out or listens: DNS ([`dns`]), the
//! outbound HTTP client and its proxy selection ([`http_client`], [`proxy`]),
//! the resolver-and-proxy pair a configuration generation hands every
//! subsystem ([`egress`]), the challenge validators ([`challenge`]), TLS
//! termination ([`tls`]) and the accept loop ([`listener`]).
//!
//! Below every policy that decides *whether* to reach something and above
//! nothing but the core vocabulary. An internal crate of the `acme-proxy`
//! binary, published in lockstep with it and with no semver promise of its
//! own.

pub mod challenge;
pub mod dns;
pub mod egress;
pub mod http_client;
pub mod listener;
pub mod proxy;
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
pub mod tls;
