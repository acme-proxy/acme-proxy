//! `[ipam]` — the IP address management inventory this endpoint consults.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::empty_string_is_no_values;

/// Which inventory answers "which names does this address own?", and how long
/// it is given to answer.
///
/// Per-profile, so two endpoints may consult different inventories — but the
/// *policy* built on the answer is the `ipam` filter's, not this section's.
/// Nothing here is read unless `ipam` appears in `filter.enabled`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IpamConfig {
    /// `netbox`, `phpipam`, `custom`, or empty for no inventory at all.
    /// Anything else is a startup error rather than a silent fallback.
    pub backend: String,
    /// Budget for one whole lookup, however many requests the backend makes to
    /// answer it. Applied by the registry rather than by each backend, so a
    /// backend added later cannot forget it. This runs inline in `newOrder`
    /// and `finalize`, so it is part of those requests' worst case.
    pub timeout_ms: u64,
    pub netbox: NetboxConfig,
    pub phpipam: PhpIpamConfig,
    pub custom: CustomIpamConfig,
}

impl Default for IpamConfig {
    fn default() -> Self {
        Self {
            backend: String::new(),
            timeout_ms: 5000,
            netbox: NetboxConfig::default(),
            phpipam: PhpIpamConfig::default(),
            custom: CustomIpamConfig::default(),
        }
    }
}

/// The default `sources` both backends ship with: the address object's own
/// name, the custom field on it, and that same field on the machine it is
/// assigned to.
///
/// Exactly the behaviour of the `netbox` filter before it became an IPAM
/// backend, so an existing deployment that moves its section across sees no
/// change. The two service-address sources are deliberately *not* here: both
/// widen what a client may certify, and widening is opted into.
fn default_sources() -> Vec<String> {
    vec![
        "dns_name".to_string(),
        "custom_field".to_string(),
        "device".to_string(),
    ]
}

/// Configuration for the `netbox` IPAM backend.
///
/// `token` is a secret, so it belongs in `ACME_PROXY_IPAM__NETBOX__TOKEN`
/// rather than in a file on disk — the same advice
/// [`super::signer::Rfc2136Config::tsig_key_secret`] carries.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetboxConfig {
    /// Base URL of the NetBox instance, e.g. `https://netbox.example.com`. Any
    /// path is kept, so an instance served under a subpath works.
    pub url: String,
    /// NetBox API token. Both generations are accepted and the scheme
    /// follows the token itself: a v2 one (`nbt_<key>.<secret>`, the
    /// default since NetBox 4.5) is sent as `Authorization: Bearer …`,
    /// a legacy v1 one as `Authorization: Token …`.
    pub token: String,
    /// Custom field, on the IP address or on its device/VM, holding the extra
    /// names that address may have certified.
    pub custom_field: String,
    /// Which places a permitted name may come from. Empty, or an unknown
    /// entry, is a startup error; order is meaningless, since the result is a
    /// union. See [`crate::ipam::Source`].
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub sources: Vec<String>,
    /// Which NetBox address roles count as a service address for the `vip`
    /// source. Read only when `vip` is in `sources`, so this is *which* roles
    /// rather than whether to look at all.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub vip_roles: Vec<String>,
    /// Extra CA certificates (PEM) to trust on top of the public roots, for a
    /// NetBox behind an internal PKI. Ignored when `insecure_skip_verify` is on.
    pub ca_cert_path: String,
    /// Skip verification of NetBox's TLS certificate entirely.
    ///
    /// Off by default and meant as a temporary way out of an expired NetBox
    /// certificate: with it on, the answers this backend trusts could come from
    /// anyone able to intercept the connection. Startup logs a warning for as
    /// long as it is set.
    pub insecure_skip_verify: bool,
}

impl Default for NetboxConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            custom_field: "acme_domains".to_string(),
            sources: default_sources(),
            // The roles NetBox itself offers for a shared address. Listing them
            // all is not a widening: nothing is queried at all unless `vip` is
            // in `sources`.
            vip_roles: vec![
                "vip".to_string(),
                "vrrp".to_string(),
                "hsrp".to_string(),
                "glbp".to_string(),
                "carp".to_string(),
                "anycast".to_string(),
            ],
            ca_cert_path: String::new(),
            insecure_skip_verify: false,
        }
    }
}

/// Configuration for the `phpipam` IPAM backend.
///
/// `token` is the application's static app code and is a secret, so it belongs
/// in `ACME_PROXY_IPAM__PHPIPAM__TOKEN`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PhpIpamConfig {
    /// Base URL of the phpIPAM instance, e.g. `https://ipam.example.com`. Any
    /// path is kept, so an instance served under a subpath works.
    pub url: String,
    /// The API application's identifier, the `<app_id>` in every phpIPAM API
    /// path. Created in phpIPAM under Administration → API.
    pub app_id: String,
    /// The application's app code, sent as a `token` header.
    pub token: String,
    /// Custom field on the address (and, for the `device` source, on the
    /// device) holding the extra names it may have certified. phpIPAM prefixes
    /// custom columns with `custom_`, so the default carries that prefix.
    pub custom_field: String,
    /// Which places a permitted name may come from. phpIPAM records no
    /// redundancy groups, so `vip` and `fhrp` are refused here by name rather
    /// than quietly ignored.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub sources: Vec<String>,
    /// Extra CA certificates (PEM) to trust on top of the public roots.
    /// Ignored when `insecure_skip_verify` is on.
    pub ca_cert_path: String,
    /// Skip verification of phpIPAM's TLS certificate entirely. The
    /// counterpart of [`NetboxConfig::insecure_skip_verify`], warned about at
    /// startup for as long as it is set.
    pub insecure_skip_verify: bool,
}

impl Default for PhpIpamConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            app_id: "acme".to_string(),
            token: String::new(),
            custom_field: "custom_acme_domains".to_string(),
            sources: default_sources(),
            ca_cert_path: String::new(),
            insecure_skip_verify: false,
        }
    }
}

/// Configuration for the `custom` IPAM backend.
///
/// The one backend with no URL, no credential and no `sources`: the script is
/// the inventory, and it decides for itself where its answer comes from. It
/// also takes no `timeout_ms` of its own — [`IpamConfig::timeout_ms`] is the
/// budget the whole lookup runs under, and a second one here would contradict
/// the "one budget however many requests it takes" rule the other two follow.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CustomIpamConfig {
    /// Path to the executable answering "which names does this address own?".
    /// Empty while `backend = "custom"` is a startup error.
    pub script_path: String,
    /// Fixed arguments passed to the script before it is told anything about
    /// the request, which travels in the environment and on stdin.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub args: Vec<String>,
}
