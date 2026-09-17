//! The ACME domain: what an order, an authorization, a challenge and an account
//! may do, independent of the HTTP request that asked.
//!
//! Nothing in this module imports axum. The resource handlers in
//! [`crate::handlers`] are the HTTP edge — an extractor, a call into this module,
//! a rendered response — and the operator front ends ([`crate::admin`], the
//! relay's background settlement) reach the same rules through the same
//! functions, so a state transition has one implementation however it is
//! triggered.
//!
//! - [`rules`] — pure rules over values: the identifier shape a `dns` name must
//!   have, the CSR-to-order correspondence, the CSR projection the filters see,
//!   the `contact` shapes RFC 8555 §7.3 refuses.
//! - [`access`] — who may touch what: the signer's account, and the ownership
//!   walk from a challenge up to its order.
//! - [`policy`] — the configured policy applied to a request: the filter's
//!   identifier stage, and the problem a failed challenge validation maps to.
//!
//! Errors are still [`crate::error::Problem`] values here. `Problem` is a data
//! type as much as a response — the documents stored in `challenges.error` and
//! `orders.error` are its RFC 7807 JSON — and only its `IntoResponse` impl
//! belongs to the edge.

pub mod access;
pub mod policy;
pub mod rules;
