//! `[endpoints.<name>]` — the per-endpoint overlay, plus `[eab]`.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::challenge::ChallengeConfig;
use super::filter::FilterConfig;
use super::ipam::IpamConfig;
use super::notify::NotifyConfig;
use super::server::{MetaConfig, OrderConfig};
use super::signer::SignerConfig;

/// One ACME endpoint's configuration: the eight sections an endpoint may carry,
/// plus the marker that declares it.
///
/// Every field is optional in the file — what an endpoint does not say, it
/// inherits from the matching global section (see `Config::resolve_endpoints`),
/// key by key. So `[endpoints.le]` alone is a complete endpoint, identical to the
/// global configuration but served under its own URL prefix.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EndpointSections {
    /// Whether to mount this endpoint at all. Defaults to `true`: an endpoint
    /// exists because it is written down. It is a bool rather than a bare
    /// marker for two reasons — an operator can park an endpoint without
    /// deleting its configuration, and an environment-only endpoint needs at
    /// least one key to exist at all (`ACME_PROXY_ENDPOINTS__LE__ENABLED=true`).
    pub enabled: bool,
    pub signer: SignerConfig,
    pub filter: FilterConfig,
    pub ipam: IpamConfig,
    pub challenge: ChallengeConfig,
    pub eab: EabConfig,
    pub order: OrderConfig,
    pub notify: NotifyConfig,
    pub meta: MetaConfig,
}

impl Default for EndpointSections {
    fn default() -> Self {
        Self {
            enabled: true,
            signer: SignerConfig::default(),
            filter: FilterConfig::default(),
            ipam: IpamConfig::default(),
            challenge: ChallengeConfig::default(),
            eab: EabConfig::default(),
            meta: MetaConfig::default(),
            order: OrderConfig::default(),
            notify: NotifyConfig::default(),
        }
    }
}
/// A named, fully resolved endpoint: its name (which is also its URL segment,
/// `/endpoint/<name>`) and the sections it ended up with after inheritance.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub name: String,
    pub sections: EndpointSections,
}
/// External Account Binding (RFC 8555 §7.3.4) requirement.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct EabConfig {
    pub enabled: bool,
}
