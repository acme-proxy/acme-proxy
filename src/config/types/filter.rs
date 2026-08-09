//! `[filter]` — the access-control chain and each filter's own settings.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::empty_string_is_no_values;

/// Request-filtering configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub enabled: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub exempt_paths: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub trusted_proxies: Vec<String>,
    pub forwarded_header: String,
    pub allowed_ip: AllowedIpConfig,
    pub reverse_dns: ReverseDnsConfig,
    pub identifiers: IdentifierListConfig,
    /// Which of `custom`'s entries to run, and in what order, when `custom`
    /// is listed in `enabled` — spliced into the same all-must-pass chain as
    /// every other filter, not a nested chain of its own. A name may be
    /// defined in `custom` but left out of this list, e.g. to keep a library
    /// of scripts and pick a subset per environment through this one
    /// (ordinary, env-overridable) list rather than redefining `custom`
    /// itself. An unknown name here, or `custom` enabled with this empty, is
    /// a startup error.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub custom_enabled: Vec<String>,
    /// Named external-script configs, selected and ordered by
    /// `custom_enabled`. Each name must match `^[a-z0-9-]+$` — the same
    /// restriction [`valid_config_key_name`](crate::config::valid_config_key_name)
    /// applies to profile names, and for the same reason: the `config` crate
    /// lowercases every environment-variable key segment, so
    /// `ACME_PROXY_FILTER__CUSTOM__CheckNetwork__…` and a TOML
    /// `[filter.custom.CheckNetwork]` would silently become two different
    /// entries instead of one overriding the other.
    pub custom: BTreeMap<String, CustomFilterConfig>,
    pub netbox: NetboxConfig,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: Vec::new(),
            // Empty, unlike the days when `/health` lived inside the ACME
            // router: server-level routes are served by the root router now,
            // which no profile's filters ever see. The mechanism stays, for an
            // operator who wants to leave, say, `/directory` unfiltered.
            exempt_paths: Vec::new(),
            trusted_proxies: Vec::new(),
            forwarded_header: "x-forwarded-for".to_string(),
            allowed_ip: AllowedIpConfig::default(),
            reverse_dns: ReverseDnsConfig::default(),
            identifiers: IdentifierListConfig::default(),
            custom_enabled: Vec::new(),
            custom: BTreeMap::new(),
            netbox: NetboxConfig::default(),
        }
    }
}
/// Configuration for the `allowed_ip` filter.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AllowedIpConfig {
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allow: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub deny: Vec<String>,
}
/// Configuration for the `reverse_dns` filter.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReverseDnsConfig {
    pub require_forward_confirm: bool,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allow: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub deny: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for ReverseDnsConfig {
    fn default() -> Self {
        Self {
            require_forward_confirm: true,
            allow: Vec::new(),
            deny: Vec::new(),
            timeout_ms: 2000,
        }
    }
}
/// Configuration for the `identifiers` filter.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IdentifierListConfig {
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allowed_types: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allow: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub deny: Vec<String>,
    pub allow_wildcards: bool,
}

impl Default for IdentifierListConfig {
    fn default() -> Self {
        Self {
            allowed_types: vec!["dns".to_string(), "cn".to_string()],
            allow: Vec::new(),
            deny: Vec::new(),
            allow_wildcards: false,
        }
    }
}
/// Configuration for the `netbox` filter.
///
/// `token` is a secret, so it belongs in `ACME_PROXY_FILTER__NETBOX__TOKEN`
/// rather than in a file on disk — the same advice
/// [`super::signer::Rfc2136Config::tsig_key_secret`] carries.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetboxConfig {
    /// Base URL of the NetBox instance, e.g. `https://netbox.example.com`. Any
    /// path is kept, so an instance served under a subpath works.
    pub url: String,
    /// NetBox API token, sent as `Authorization: Token <token>`.
    pub token: String,
    /// Custom field, on the IP address or on its device/VM, holding the extra
    /// names that address may have certified.
    pub custom_field: String,
    /// Whether the IP address object's own `dns_name` counts as permitted.
    pub use_dns_name: bool,
    /// Whether to read `custom_field` from the assigned device or virtual
    /// machine when the IP address object itself carries no value for it.
    pub device_fallback: bool,
    /// Extra CA certificates (PEM) to trust on top of the public roots, for a
    /// NetBox behind an internal PKI. Ignored when `insecure_skip_verify` is on.
    pub ca_cert_path: String,
    /// Skip verification of NetBox's TLS certificate entirely.
    ///
    /// Off by default and meant as a temporary way out of an expired NetBox
    /// certificate: with it on, the answers this filter trusts could come from
    /// anyone able to intercept the connection. Startup logs a warning for as
    /// long as it is set.
    pub insecure_skip_verify: bool,
    /// Budget for the whole exchange — the address lookup plus the optional
    /// device/VM one. Reported as a server error, not a denial.
    pub timeout_ms: u64,
}

impl Default for NetboxConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            custom_field: "acme_allowed_names".to_string(),
            use_dns_name: true,
            device_fallback: true,
            ca_cert_path: String::new(),
            insecure_skip_verify: false,
            timeout_ms: 5000,
        }
    }
}
/// Configuration for the `custom` script filter.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CustomFilterConfig {
    pub script_path: String,
    pub timeout_ms: u64,
    pub pass_stdin: bool,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub args: Vec<String>,
}

impl Default for CustomFilterConfig {
    fn default() -> Self {
        Self {
            script_path: String::new(),
            timeout_ms: 5000,
            pass_stdin: true,
            args: Vec::new(),
        }
    }
}
