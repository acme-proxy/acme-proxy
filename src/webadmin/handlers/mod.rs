//! One module per admin resource, re-exported flat — mirroring
//! [`crate::handlers`], which does the same for the ACME resources.
//!
//! Every handler here is a few lines over [`crate::admin::ops`] and
//! [`crate::admin::render`]: this layer decides status codes and shapes,
//! nothing more. **No `#[instrument]`** anywhere in it — the access middleware
//! already opens the request span, and the attribute moves a handler body into
//! a generated async block that reports almost no coverage (see CLAUDE.md).

pub mod accounts;
pub mod audit;
pub mod eab;
pub mod mfa;
pub mod misc;
pub mod orders;
pub mod paging;
pub mod session;

pub use accounts::*;
pub use audit::*;
pub use eab::*;
pub use mfa::*;
pub use misc::*;
pub use orders::*;
pub use session::*;
