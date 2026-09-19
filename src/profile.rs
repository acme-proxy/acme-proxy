//! [`Profile`]: one ACME endpoint — its identity, its URLs and the subsystems
//! that answer for it. How a generation builds every one it mounts is
//! `crate::server::profile`'s.

use std::sync::Arc;

use crate::notify::NotifyDispatcher;
use crate::signer::SignerInfo;
use acme_proxy_core::config;
use acme_proxy_core::routes;
use acme_proxy_core::routes::PROFILE_PREFIX;
use acme_proxy_net::challenge::ChallengeRegistry;
use acme_proxy_policy::filter::FilterPolicy;

/// One ACME endpoint: its identity, its URLs, and the three subsystems that
/// answer for it.
///
/// Everything per-endpoint lives here rather than beside the global config in
/// [`AppState`](crate::router::AppState), so a handler cannot pair one profile's signer
/// with another's base URL — the two always travel together.
pub struct Profile {
    /// The configured name (`[profiles.<name>]`), also the URL segment and the
    /// value stored in `accounts.profile` / `orders.profile`.
    pub name: String,
    /// Where the router mounts it: `/profile/<name>`.
    pub path: String,
    /// The public base for every URL this endpoint hands out and for the
    /// RFC 8555 §6.4 `url` check: `server.base_url` + [`Profile::path`].
    pub base_url: String,
    /// What this endpoint's signer publishes — its CRL, anchor, renewal
    /// opinion and `http-01` tokens — and where its revocations go. Built from
    /// public material, so every role has one.
    ///
    /// **There is deliberately no backend here.** Signing and revoking need
    /// the key, which only the `worker` role holds, and only the job handlers
    /// it runs are handed one (`GenerationParts::signers`). A profile is what
    /// a request is served from, so leaving the backend off it is what makes
    /// "a request never signs" a type error rather than a convention.
    pub signer_info: Arc<dyn SignerInfo>,
    pub filter: Arc<FilterPolicy>,
    pub challenges: Arc<ChallengeRegistry>,
    pub order: config::OrderConfig,
    pub eab: config::EabConfig,
    /// The optional `meta` members this endpoint's directory advertises
    /// (RFC 8555 §7.1.1). Per-profile, like everything else here: two endpoints
    /// on one process can have different terms of service.
    pub meta: config::MetaConfig,
    pub notify: Arc<NotifyDispatcher>,
}

/// The subsystems and per-endpoint sections a [`Profile`] is assembled from.
///
/// A struct because [`Profile::new`] took nine positional parameters, four of
/// them `Arc<dyn …>` or config sections that a reader has to count commas to
/// tell apart. It also retires the crate's last
/// `#[allow(clippy::too_many_arguments)]`.
///
/// `name` and `base_url` stay positional: they are what the constructor
/// *derives* from rather than stores, and keeping them out of here is what
/// makes "the path is never configured" visible in the signature.
pub struct ProfileParts {
    pub signer_info: Arc<dyn SignerInfo>,
    pub filter: Arc<FilterPolicy>,
    pub challenges: Arc<ChallengeRegistry>,
    pub order: config::OrderConfig,
    pub eab: config::EabConfig,
    pub meta: config::MetaConfig,
    pub notify: Arc<NotifyDispatcher>,
}

impl Profile {
    /// Assembles a profile, deriving its path and base URL from its name —
    /// the two are never configured, so they cannot drift from each other or
    /// from what the database records.
    pub fn new(name: &str, base_url: &str, parts: ProfileParts) -> Self {
        let path = format!("{PROFILE_PREFIX}/{name}");
        Self {
            name: name.to_string(),
            base_url: format!("{}{path}", base_url.trim_end_matches('/')),
            path,
            signer_info: parts.signer_info,
            filter: parts.filter,
            challenges: parts.challenges,
            order: parts.order,
            eab: parts.eab,
            meta: parts.meta,
            notify: parts.notify,
        }
    }

    /// This endpoint's directory URL — where a client starts.
    ///
    /// Derived here rather than `format!`-ed at each of the three call sites
    /// (the startup log line, the admin API's profile listing, and anything
    /// added later), all of which have to agree with what `build_router`
    /// actually mounts.
    #[must_use]
    pub fn directory_url(&self) -> String {
        format!("{}{}", self.base_url, routes::DIRECTORY)
    }
}
