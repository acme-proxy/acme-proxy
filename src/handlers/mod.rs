//! ACME resource handlers, one module per resource.
//!
//! Every signed route reaches its handler through [`crate::extractors`], which
//! has already checked the media type, the `crit` header, the JWS signature,
//! the JWS `url` and the nonce. A handler therefore starts from a verified
//! request and does only its own work — there is no four-line preamble to
//! repeat, and a new signed route cannot forget one of those checks.
//!
//! Each handler is the HTTP edge of one operation: extractor, a call into
//! [`crate::acme`] — `OrderService`, `AccountService`, `revoke::Revocations` —
//! and the response. The rules, the transactions, the audit rows and the log
//! lines are the service's, shared with the operator front ends and the relay;
//! what stays here is what only HTTP has (a `Location`, a `Retry-After`, a
//! `Link`).
//!
//! Errors are [`acme_proxy_core::error::Problem`] values, which render as RFC 8555
//! `application/problem+json`.

pub mod account;
pub mod authz;
pub mod certificate;
pub mod challenge_file;
pub mod directory;
pub mod metrics;
pub mod order;
pub mod renewal_info;

pub use account::*;
pub use authz::*;
pub use certificate::*;
pub use challenge_file::*;
pub use directory::*;
pub use metrics::*;
pub use order::*;
pub use renewal_info::*;
