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
//! - [`order`] — [`OrderService`], the order state machine: deactivating an
//!   authorization, claiming and validating a challenge.
//!
//! **Logging:** whoever builds an [`Error`] logs it. The edge only maps it to a
//! response, so a refusal is one log line however many layers it crossed —
//! and every event name stayed what it was when the code lived in the handler,
//! since `monitoring.md` and the e2e lab grep for them. Nothing here carries
//! `#[instrument]`: the handler's span already covers the request, and the
//! attribute hides a body from coverage.
//!
//! Refusals the client reads as they are travel as [`crate::error::Problem`]
//! values, wrapped in [`Error`]. `Problem` is a data type as much as a response
//! — the documents stored in `challenges.error` and `orders.error` are its
//! RFC 7807 JSON — and only its `IntoResponse` impl belongs to the edge.

pub mod access;
pub mod error;
pub mod order;
pub mod policy;
pub mod rules;

pub use error::Error;
pub use order::OrderService;
