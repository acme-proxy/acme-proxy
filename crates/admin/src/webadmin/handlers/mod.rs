//! One module per admin resource, re-exported flat — mirroring
//! [`acme_proxy_protocol::handlers`], which does the same for the ACME resources.
//!
//! Every handler here is a few lines over [`crate::admin::ops`] and
//! [`crate::admin::render`]: this layer decides status codes and shapes,
//! nothing more.
//!
//! ## One write, one function, both front ends
//!
//! Every mutating action lives once, as a `pub(crate) async fn apply_*` beside
//! its `/api` handler, and the `/ui` page calls the same function. It owns
//! everything the action owes: the validation, the write, every audit row and
//! the `admin_*` log line. The two front ends keep only what really differs:
//! extracting a JSON body or a form, and answering with a status and JSON or a
//! fragment and a banner. [`Caller`] carries who acted and through which
//! surface.
//!
//! Spelled out twice, the two copies drifted: one surface logged an action the
//! other did not, or logged it without its `surface` field. **No `#[instrument]`** anywhere in it — the access middleware
//! already opens the request span, and the attribute moves a handler body into
//! a generated async block that reports almost no coverage (see the book's
//! Testing & Coverage page).

pub mod account;
pub mod accounts;
pub mod audit;
pub mod eab;
pub mod expiring;
pub mod filter;
pub mod jobs;
pub mod mfa;
pub mod misc;
pub mod operators;
pub mod orders;
pub mod paging;
pub mod params;
pub mod session;
pub mod upstream_orders;

pub use account::*;
pub use accounts::*;
pub use audit::*;
pub use eab::*;
pub use expiring::*;
pub use filter::*;
pub use jobs::*;
pub use mfa::*;
pub use misc::*;
pub use operators::*;
pub use orders::*;
pub use session::*;
pub use upstream_orders::*;

use crate::webadmin::session::Authenticated;
use acme_proxy_core::audit::RequestContext;

/// Who is performing a write, and through which front end.
///
/// Every `apply_*` action takes one. The operator names the audit row and the
/// log line, the request context resolves the client address the row records,
/// and `surface` is the one field the two front ends' log lines differ by.
pub(crate) struct Caller<'a> {
    pub(crate) auth: &'a Authenticated,
    pub(crate) request: &'a RequestContext,
    pub(crate) surface: &'static str,
}

impl<'a> Caller<'a> {
    /// A write through `/api`.
    pub(crate) fn api(auth: &'a Authenticated, request: &'a RequestContext) -> Self {
        Self {
            auth,
            request,
            surface: "api",
        }
    }

    /// A write through `/ui`.
    pub(crate) fn ui(auth: &'a Authenticated, request: &'a RequestContext) -> Self {
        Self {
            auth,
            request,
            surface: "ui",
        }
    }

    /// The operator's username, which attributes the row and the log line.
    pub(crate) fn username(&self) -> &str {
        &self.auth.user.username
    }
}
