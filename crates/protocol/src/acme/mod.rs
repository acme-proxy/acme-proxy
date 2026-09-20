//! The ACME domain: what an order, an authorization, a challenge and an account
//! may do, independent of the HTTP request that asked.
//!
//! Nothing in this module routes, extracts or renders a response — the one
//! axum name it touches is `StatusCode`, which comes with `Problem`. The resource
//! handlers in
//! [`crate::handlers`] are the HTTP edge — an extractor, a call into this module,
//! a rendered response — and the operator front ends (`admin`, the
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
//! - [`order`] — [`OrderService`], the order state machine: creating an order,
//!   deactivating an authorization, claiming and validating a challenge,
//!   finalizing. The issuance bookkeeping the `signer_issue` job and the relay
//!   share — `record_issuance`, `announce_issuance`, `record_issue_failure` —
//!   is `acme_proxy_signer::issuance`, below both of them, since the relay
//!   completes an issuance with no request in scope at all.
//! - [`issue`] — the `signer_issue` job `finalize` queues: the one place a
//!   backend is asked to sign, and it runs in the `worker` role, the only one
//!   that holds a backend.
//! - [`account`] — [`AccountService`]: `newAccount` (with EAB), the account
//!   update, key rollover and the orders list, plus the deactivation and
//!   contact update the operator front ends share.
//! - [`revoke`] — certificate revocation, by certificate for an ACME client and
//!   by order for an operator, sharing one tail.
//! - [`validate`] — the `challenge_validate` job the trigger queues, since the
//!   outbound check outlives the request that asked for it.
//!
//! **Logging:** whoever builds an [`Error`] logs it. The edge only maps it to a
//! response, so a refusal is one log line however many layers it crossed —
//! and every event name stayed what it was when the code lived in the handler,
//! since `monitoring.md` and the e2e lab grep for them. Nothing here carries
//! `#[instrument]`: the handler's span already covers the request, and the
//! attribute hides a body from coverage.
//!
//! Refusals the client reads as they are travel as [`acme_proxy_core::error::Problem`]
//! values, wrapped in [`Error`]. `Problem` is a data type as much as a response
//! — the documents stored in `challenges.error` and `orders.error` are its
//! RFC 7807 JSON — and only its `IntoResponse` impl belongs to the edge.

pub mod access;
pub mod account;
pub mod error;
pub mod issue;
pub mod order;
pub mod policy;
pub mod revoke;
pub mod rules;
pub mod validate;

pub use account::AccountService;
pub use error::Error;
pub use order::OrderService;

/// The entry a process mounts under `name`, if any.
///
/// Every job handler here holds the same shape — the profiles, signers or
/// notifiers of *this* generation, as `(name, value)` pairs — and asks it the
/// same question about a row it just read. A profile that is absent is not an
/// error: another process, or the next generation of this one, may mount it,
/// which is why each caller answers `Retry` rather than `Failed`.
pub(crate) fn mounted<'a, T>(entries: &'a [(String, T)], name: &str) -> Option<&'a T> {
    entries
        .iter()
        .find(|(mounted, _)| mounted == name)
        .map(|(_, entry)| entry)
}
