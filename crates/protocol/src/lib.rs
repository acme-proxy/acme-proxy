//! The ACME server itself: the domain services every front end shares
//! ([`acme`]), the extractors that verify a signed request before a handler
//! runs ([`extractors`]), the handlers ([`handlers`]), the layers around them
//! ([`middlewares`]), one endpoint's identity and subsystems ([`profile`]) and
//! the routers that serve it ([`router`]).
//!
//! Above everything a request consults — the policy, the queue, the signer's
//! read side — and below the admin surfaces and the runtime that assembles and
//! serves it. An internal crate of the `acme-proxy` binary, published in
//! lockstep with it and with no semver promise of its own.

pub mod acme;
pub mod extractors;
pub mod handlers;
pub mod middlewares;
pub mod profile;
pub mod router;
