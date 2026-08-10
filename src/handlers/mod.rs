//! ACME resource handlers, one module per resource.
//!
//! Every signed route reaches its handler through [`crate::extractors`], which
//! has already checked the media type, the `crit` header, the JWS signature,
//! the JWS `url` and the nonce. A handler therefore starts from a verified
//! request and does only its own work — there is no four-line preamble to
//! repeat, and a new signed route cannot forget one of those checks.
//!
//! [`helpers`] holds what the resource modules share: the ownership checks
//! (`signer_account`, `load_owned_order`), the CSR-to-identifier projection the
//! filters see, and the identifier shape validators.
//!
//! Errors are [`crate::error::Problem`] values, which render as RFC 8555
//! `application/problem+json`.

pub mod account;
pub mod authz;
pub mod certificate;
pub mod challenge_file;
pub mod directory;
pub mod helpers;
pub mod order;
pub mod renewal_info;

pub use account::*;
pub use authz::*;
pub use certificate::*;
pub use challenge_file::*;
pub use directory::*;
pub use helpers::*;
pub use order::*;
pub use renewal_info::*;
