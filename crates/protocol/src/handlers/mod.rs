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

/// How long a client is asked to wait before polling a resource this server has
/// not decided yet: a `pending` or `processing` challenge or authorization
/// (RFC 8555 §7.5.1, §8.2) and a `processing` order (§7.4).
///
/// One value, because it answers one question — "how long does the work this
/// server just queued usually take?" — and two copies of it would drift apart
/// while still meaning the same thing. Deliberately small: a validation runs
/// within `challenge.timeout_ms` of being triggered and a local signing is
/// immediate, so the answer is usually there by the time a client asks. A
/// relay's upstream may take longer, but its own pacing is invisible from
/// here, and an over-long hint would stall the common case.
pub(crate) const POLL_RETRY_AFTER: &str = "5";
