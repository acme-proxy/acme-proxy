//! `[profiles.<name>]` — the per-endpoint overlay, plus `[eab]`.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::challenge::ChallengeConfig;
use super::filter::FilterConfig;
use super::notify::NotifyConfig;
use super::server::{MetaConfig, OrderConfig};
use super::signer::SignerConfig;

/// One ACME endpoint's configuration: the five sections a profile may carry,
/// plus the marker that declares it.
///
/// Every field is optional in the file — what a profile does not say, it
/// inherits from the matching global section (see `Config::resolve_profiles`),
/// key by key. So `[profiles.le]` alone is a complete profile, identical to the
/// global configuration but served under its own URL prefix.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProfileSections {
    /// Whether to mount this profile at all. Defaults to `true`: a profile
    /// exists because it is written down. It is a bool rather than a bare
    /// marker for two reasons — an operator can park an endpoint without
    /// deleting its configuration, and an environment-only profile needs at
    /// least one key to exist at all (`ACME_PROXY_PROFILES__LE__ENABLED=true`).
    pub enabled: bool,
    pub signer: SignerConfig,
    pub filter: FilterConfig,
    pub challenge: ChallengeConfig,
    pub eab: EabConfig,
    pub order: OrderConfig,
    pub notify: NotifyConfig,
    pub meta: MetaConfig,
}

impl Default for ProfileSections {
    fn default() -> Self {
        Self {
            enabled: true,
            signer: SignerConfig::default(),
            filter: FilterConfig::default(),
            challenge: ChallengeConfig::default(),
            eab: EabConfig::default(),
            meta: MetaConfig::default(),
            order: OrderConfig::default(),
            notify: NotifyConfig::default(),
        }
    }
}
/// A named, fully resolved profile: its name (which is also its URL segment,
/// `/profile/<name>`) and the sections it ended up with after inheritance.
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub name: String,
    pub sections: ProfileSections,
}
/// External Account Binding (RFC 8555 §7.3.4) requirement.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct EabConfig {
    pub enabled: bool,
}
