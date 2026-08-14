//! Request-filtering abstraction.
//!
//! Pluggable policies that can refuse a request before it reaches a handler, or
//! refuse the specific names a client asks a certificate for.
//!
//! Filters answer a different question from [`challenge`](crate::challenge):
//! *who* may ask, rather than whether they control the name. Both matter, and
//! when `challenge.bypass` is on — the default — filters are the **only** thing
//! deciding who may obtain a certificate, because a triggered challenge is then
//! accepted with no network check at all.
//!
//! The shape mirrors the [`signer`](crate::signer) subsystem — a trait, an
//! error enum the caller maps to a [`Problem`](crate::error::Problem), and a
//! [`from_config`] selector building the configured set at startup.
//!
//! ## Two hook points
//!
//! Some policies decide from the connection alone (is this IP allowed? does it
//! have a valid PTR record?); others need the names being requested, which only
//! the handlers know. Rather than two traits, [`Filter`] has two methods, both
//! defaulting to "allow":
//!
//! - [`check_connection`](Filter::check_connection) runs in
//!   [`add_filter_middleware`](crate::middlewares::filter::add_filter_middleware)
//!   for every non-exempt request.
//! - [`check_identifiers`](Filter::check_identifiers) runs at `newOrder` (the
//!   order's identifiers) and again at `finalize` (the CSR's subject
//!   alternative names and common name).
//!
//! A filter implements only the hook it cares about, and therefore runs exactly
//! once per request per hook.
//!
//! ## All must pass
//!
//! Filters are evaluated in the order [`FilterConfig::enabled`] lists them, and
//! **every** one must allow the request — the first denial short-circuits. An
//! empty list is the default and makes the whole chain a no-op.
//!
//! ## Startup validation
//!
//! CIDRs and regexes are parsed once in [`from_config`], which returns an
//! `anyhow::Error` the binary treats as fatal. A typo in a netmask is a
//! configuration bug that should stop the server, not silently deny (or admit)
//! traffic at runtime.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::Method;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use tracing::{info, warn};

use crate::config::FilterConfig;
use crate::sqlite::order::Identifier;

pub mod client_ip;
pub mod custom;
pub mod identifiers;
pub mod ip_allow;
pub mod ipam;
pub mod reverse_dns;

pub use client_ip::{ClientIp, ProxyPolicy};

/// Identifier types that are subject metadata rather than a name the
/// certificate is issued *for*.
///
/// A common name is legacy subject metadata — RFC 6125 deprecated relying on
/// it, and CSR generators routinely put a human label there (`rcgen`'s own
/// default is the string `rcgen self signed cert`). Filters that decide what a
/// certificate may be issued *for* therefore leave these alone: `identifiers`
/// exempts them from its `allow` list, and `ipam` never asks an inventory to
/// confirm one. Refusals still reach them — see
/// [`identifiers`](self::identifiers) for why the two directions differ.
pub(crate) const SUBJECT_ONLY_TYPES: &[&str] = &["cn"];

/// A pluggable request-filtering policy.
///
/// Both check methods default to allowing, so an implementation writes only the
/// hook it needs. See the [module docs](self) for when each one runs.
#[async_trait]
pub trait Filter: Send + Sync {
    /// The configuration name this filter is enabled under, used in logs.
    fn name(&self) -> &'static str;

    /// Decides on the connection alone, before the handler runs.
    async fn check_connection(&self, _ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
        Ok(())
    }

    /// Decides on the names a client is asking a certificate for.
    async fn check_identifiers(&self, _ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        Ok(())
    }
}

/// What a [`Filter`] knows about a request before it is dispatched.
#[derive(Debug)]
pub struct ConnectionContext<'a> {
    /// The client address, per [`ProxyPolicy::resolve`]. `None` when the peer
    /// address is unavailable — filters that need it must fail closed.
    pub client_ip: Option<IpAddr>,
    pub method: &'a Method,
    pub path: &'a str,
}

impl ConnectionContext<'_> {
    /// The client address, canonicalized, or a refusal.
    ///
    /// An address the server cannot see is not "absent from the deny list,
    /// therefore fine" — every connection filter must fail closed on it. Having
    /// one helper say so means a filter added later gets that behavior by
    /// reaching for the address at all.
    pub fn require_client_ip(&self) -> Result<IpAddr, FilterError> {
        self.client_ip
            .map(canonical)
            .ok_or_else(|| FilterError::Denied("client address unavailable".to_string()))
    }
}

/// Where in the flow a set of identifiers is being checked.
///
/// The same names are validated twice — once as the client's stated intent,
/// once as what its CSR actually requests — and a filter may want to treat the
/// two differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierStage {
    /// The `identifiers` array of a `newOrder` payload.
    NewOrder,
    /// The subject alternative names and common name of a finalize CSR.
    Csr,
}

impl IdentifierStage {
    /// Short label for logs and problem details.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewOrder => "newOrder",
            Self::Csr => "CSR",
        }
    }
}

/// What a [`Filter`] knows about the names a client wants certified.
///
/// Carries the account as well as the client address so a policy can bind
/// names to either — for example "this network may only request names under
/// its own subdomain".
#[derive(Debug)]
pub struct IdentifierContext<'a> {
    /// The client address, as resolved by the middleware.
    pub client_ip: Option<IpAddr>,
    /// Id of the account making the request (already authenticated by the JWS
    /// extractor and checked to own the order).
    pub account_id: &'a str,
    pub stage: IdentifierStage,
    /// The requested names. At [`IdentifierStage::Csr`] these are projected
    /// from the CSR, so `typ` may be `ip`, `email`, `uri`, `other` or `cn` as
    /// well as `dns`.
    pub identifiers: &'a [Identifier],
}

impl IdentifierContext<'_> {
    /// The client address, canonicalized, or a refusal.
    ///
    /// The twin of [`ConnectionContext::require_client_ip`], and fails closed
    /// for the same reason: a filter binding names to an address cannot decide
    /// anything about an address it cannot see.
    pub fn require_client_ip(&self) -> Result<IpAddr, FilterError> {
        self.client_ip
            .map(canonical)
            .ok_or_else(|| FilterError::Denied("client address unavailable".to_string()))
    }
}

/// Why a filter refused, mapped by the caller to the right ACME error.
///
/// The split mirrors [`SignerError`](crate::signer::SignerError): a policy
/// decision about the client is not the same as being unable to reach one.
#[derive(Debug)]
pub enum FilterError {
    /// Policy refuses this request. The detail is shown to the client.
    Denied(String),
    /// The filter could not decide — a DNS timeout, a resolver outage. Maps to
    /// `Problem::server_internal` (500) so the client can retry, rather than
    /// looking like a permanent refusal.
    Internal(String),
}

/// The configured filters plus the settings the middleware needs to apply them.
///
/// Cheap to clone behind the `Arc` it is always held in.
pub struct FilterChain {
    filters: Vec<Arc<dyn Filter>>,
    exempt_paths: Vec<String>,
    proxy: ProxyPolicy,
}

impl std::fmt::Debug for FilterChain {
    /// `dyn Filter` is not `Debug`, so show the names — which is the only part
    /// worth reading anyway.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FilterChain")
            .field(
                "filters",
                &self.filters.iter().map(|f| f.name()).collect::<Vec<_>>(),
            )
            .field("exempt_paths", &self.exempt_paths)
            .field("proxy", &self.proxy)
            .finish()
    }
}

impl Default for FilterChain {
    /// An empty chain: no filters, nothing exempt, no proxy trusted.
    ///
    /// Nothing is exempt because nothing needs to be: server-level routes
    /// (`/health`) are served by the root router, which no profile's filters
    /// ever see.
    ///
    /// This is what the tests and a server with no `[filter]` section use.
    fn default() -> Self {
        Self {
            filters: Vec::new(),
            exempt_paths: Vec::new(),
            proxy: ProxyPolicy::default(),
        }
    }
}

impl FilterChain {
    /// Builds a chain directly from parts. Mostly useful to tests; production
    /// goes through [`from_config`].
    pub fn new(
        filters: Vec<Arc<dyn Filter>>,
        exempt_paths: Vec<String>,
        proxy: ProxyPolicy,
    ) -> Self {
        Self {
            filters,
            exempt_paths,
            proxy,
        }
    }

    /// How the middleware turns a peer address plus headers into a client IP.
    pub fn proxy(&self) -> &ProxyPolicy {
        &self.proxy
    }

    /// Whether `path` skips connection-level filtering.
    pub fn is_exempt(&self, path: &str) -> bool {
        self.exempt_paths.iter().any(|exempt| exempt == path)
    }

    /// Whether any filter is active.
    ///
    /// `post_finalize` uses this to skip re-parsing the CSR when nothing would
    /// look at the result. Deliberately coarse — a connection-only filter makes
    /// it true too — because a per-hook declaration on the trait would be one
    /// more thing for a filter author to get out of sync with their impl, and
    /// the cost it saves is a single CSR parse.
    pub fn is_active(&self) -> bool {
        !self.filters.is_empty()
    }

    /// Runs every filter's connection hook, stopping at the first refusal.
    pub async fn check_connection(&self, ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
        for filter in &self.filters {
            filter.check_connection(ctx).await.inspect_err(|error| {
                log_rejection(filter.name(), "connection", ctx.client_ip, error);
            })?;
        }
        Ok(())
    }

    /// Runs every filter's identifier hook, stopping at the first refusal.
    pub async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        for filter in &self.filters {
            filter.check_identifiers(ctx).await.inspect_err(|error| {
                log_rejection(filter.name(), ctx.stage.as_str(), ctx.client_ip, error);
            })?;
        }
        Ok(())
    }
}

/// One log line per refusal, at the level the reason deserves: a denial is
/// routine operation, an `Internal` is something an operator should see.
fn log_rejection(filter: &'static str, hook: &str, client_ip: Option<IpAddr>, error: &FilterError) {
    match error {
        FilterError::Denied(detail) => tracing::warn!(
            event = "filter_denied",
            outcome = "failure",
            filter,
            hook,
            client_ip = ?client_ip,
            detail = %detail,
        ),
        FilterError::Internal(detail) => tracing::error!(
            event = "filter_failed",
            outcome = "failure",
            filter,
            hook,
            client_ip = ?client_ip,
            detail = %detail,
        ),
    }
}

/// Builds the configured filter chain. Called once at startup, so it may fail
/// fast (the caller exits on error).
///
/// `dns` is [`crate::config::Config::dns`], not a field of `cfg`: `reverse_dns`
/// resolves through it the same way
/// [`challenge::from_config`](crate::challenge::from_config) does for `dns-01`,
/// since both answer the same question — which nameserver this process trusts.
/// Builds the configured filter chain.
///
/// Takes a `DnsConfig` rather than the process's shared resolver, because the
/// one filter that resolves anything builds its own **cached** one from it: a
/// PTR lookup for an address that keeps connecting is exactly what a cache is
/// for, while the shared resolver is deliberately uncached so a `dns-01` record
/// published moments before a trigger is not defeated by a cached negative.
/// Handing `reverse_dns` the uncached one would quietly turn every filtered
/// request into a fresh PTR query. (It used to take both, for `netbox`'s HTTP
/// client; that lives in [`ipam`](crate::ipam) now and is handed the shared
/// resolver there.)
///
/// `ipam` is the profile's already-built inventory — `None` when
/// `ipam.backend` is unset, which is a startup error if the `ipam` filter is
/// enabled. It is built by [`Profile::build_all`](crate::Profile::build_all)
/// rather than here because it is its own configuration section with its own
/// selector, and this chain is one of its consumers rather than its owner.
pub fn from_config(
    cfg: &FilterConfig,
    dns: &crate::config::DnsConfig,
    ipam: Option<Arc<crate::ipam::IpamRegistry>>,
) -> anyhow::Result<Arc<FilterChain>> {
    let proxy = ProxyPolicy::new(&cfg.trusted_proxies, &cfg.forwarded_header)?;

    let mut filters: Vec<Arc<dyn Filter>> = Vec::with_capacity(cfg.enabled.len());
    for name in &cfg.enabled {
        let built: Vec<Arc<dyn Filter>> = match name.as_str() {
            "allowed_ip" => vec![Arc::new(ip_allow::AllowedFromIpAddress::from_config(
                &cfg.allowed_ip,
            )?)],
            "reverse_dns" => vec![Arc::new(
                reverse_dns::ClientHasValidReverseDns::from_config(&cfg.reverse_dns, dns)?,
            )],
            "identifiers" => vec![Arc::new(identifiers::IdentifierList::from_config(
                &cfg.identifiers,
            )?)],
            "custom" => {
                crate::config::resolve_custom_entries("filter", &cfg.custom, &cfg.custom_enabled)?
                    .into_iter()
                    .map(|(_, script)| {
                        custom::CustomScriptFilter::from_config(script)
                            .map(|filter| Arc::new(filter) as Arc<dyn Filter>)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
            }
            "ipam" => {
                let registry = ipam.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "the `ipam` filter is enabled but ipam.backend is empty; set \
                         ipam.backend (`netbox` or `phpipam`) and configure the matching \
                         [ipam.<backend>] section, or remove `ipam` from filter.enabled"
                    )
                })?;
                vec![Arc::new(ipam::IpamFilter::new(registry))]
            }
            // Renamed in the release that lifted NetBox out of this chain into
            // its own subsystem. Refused by name rather than aliased, the way
            // `signer.backend = "acme_proxy"` is: the section moved too, so a
            // silent alias would leave `[filter.netbox]` being read by nothing
            // while the server came up looking configured.
            "netbox" => anyhow::bail!(
                "the `netbox` filter is now `ipam`: set filter.enabled = [\"ipam\"] and \
                 ipam.backend = \"netbox\", and move the [filter.netbox] section to \
                 [ipam.netbox] — its keys are unchanged except timeout_ms, which is now \
                 ipam.timeout_ms, and use_dns_name/device_fallback, which are now entries \
                 in ipam.netbox.sources"
            ),
            other => anyhow::bail!("unknown filter: {other}"),
        };
        filters.extend(built);
    }

    if filters.is_empty() {
        // Each `from_config` reads only its own configuration, so this says only
        // what is true of *this* one. Whether an unfiltered server is also an
        // open CA depends on `challenge.bypass`, which
        // [`challenge::from_config`](crate::challenge::from_config) warns about
        // separately and in its own words.
        warn!(
            event = "filter_disabled",
            outcome = "advisory",
            "no filters configured: every client that can reach this server may \
             request a certificate for any name (set filter.enabled)"
        );
    } else {
        info!(event = "filter_enabled", outcome = "success", filters = ?cfg.enabled, exempt_paths = ?cfg.exempt_paths);
    }

    Ok(Arc::new(FilterChain::new(
        filters,
        cfg.exempt_paths.clone(),
        proxy,
    )))
}

/// Parses one allow-list entry as a network.
///
/// Accepts both CIDR notation (`192.168.1.0/24`, `fd00::/8`) and a bare address
/// (`203.0.113.7`), the latter becoming a host route — writing a `/32` for a
/// single machine is noise an operator should not have to remember.
pub(crate) fn parse_net(entry: &str) -> anyhow::Result<IpNet> {
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    match entry.parse::<IpAddr>() {
        Ok(addr) => Ok(IpNet::from(addr)),
        Err(_) => anyhow::bail!("invalid network or address: {entry}"),
    }
}

/// Parses a list of network entries, naming the setting in any error.
pub(crate) fn parse_nets(entries: &[String], setting: &str) -> anyhow::Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| parse_net(entry).map_err(|error| anyhow::anyhow!("{setting}: {error}")))
        .collect()
}

/// Normalizes an address for comparison.
///
/// The default bind is `[::]:3000`, so an IPv4 client arrives over the
/// dual-stack socket as `::ffff:192.168.1.5` and would never match a
/// `192.168.1.0/24` rule. Canonicalizing first makes the operator's v4 rules
/// mean what they look like they mean.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Whether any network contains `ip`, comparing canonical forms.
pub(crate) fn nets_contain(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical(ip);
    nets.iter().any(|net| net.contains(&ip))
}

/// The outcome of an allow/deny pair for one value.
///
/// Distinguishing the two refusals lets each filter word its own message while
/// the decision itself stays in one place.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListVerdict {
    /// Nothing objected: either `allow` was empty, or the value matched it.
    Permitted,
    /// The value matched `deny`.
    Denied,
    /// `allow` was non-empty and the value was not in it.
    NotAllowed,
}

/// Applies an allow/deny pair to one value, given a membership test.
///
/// All three filters — the IP allowlist over `IpNet`, and the identifier and
/// reverse-DNS lists over `Regex` — share one rule, stated once here:
///
/// * **`deny` is checked first and wins.** Plain membership, not
///   longest-prefix-match: a `/32` in `allow` does not beat a `/8` in `deny`.
/// * **An empty `allow` imposes no constraint**, so a deny-only configuration
///   is a working blocklist rather than a list that refuses everything.
///
/// The rule used to be written out three times, with the invariant recorded
/// only in three doc comments; the one thing keeping them in step is that they
/// now call this.
pub(crate) fn check_lists<T>(allow: &[T], deny: &[T], matches: impl Fn(&T) -> bool) -> ListVerdict {
    if deny.iter().any(&matches) {
        return ListVerdict::Denied;
    }
    if !allow.is_empty() && !allow.iter().any(&matches) {
        return ListVerdict::NotAllowed;
    }
    ListVerdict::Permitted
}

/// Compiles allow/deny patterns, anchored and case-insensitive.
///
/// **Anchoring is not optional.** The `regex` crate searches rather than
/// matches, so an allow entry of `example\.com` would also accept
/// `example.com.evil.net` — precisely the bypass an allowlist exists to
/// prevent. Every pattern becomes `^(?:…)$`; a caller wanting a suffix match
/// writes `.*\.example\.com`.
pub(crate) fn compile_anchored(patterns: &[String], setting: &str) -> anyhow::Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            RegexBuilder::new(&format!("^(?:{pattern})$"))
                .case_insensitive(true)
                .build()
                .map_err(|error| anyhow::anyhow!("{setting}: invalid regex {pattern:?}: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{AllowedIpConfig, DnsConfig, IpamConfig};

    /// The shared resolver `Profile::build_all` supplies at startup.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    /// A profile with no inventory configured, which is the default.
    fn no_ipam() -> Option<Arc<crate::ipam::IpamRegistry>> {
        None
    }

    /// The inventory `Profile::build_all` would have built for this config.
    fn ipam_from(cfg: &IpamConfig) -> Option<Arc<crate::ipam::IpamRegistry>> {
        crate::ipam::from_config(cfg, test_resolver(), crate::testutil::no_proxies()).unwrap()
    }

    fn cfg(enabled: &[&str]) -> FilterConfig {
        FilterConfig {
            enabled: enabled
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            allowed_ip: AllowedIpConfig {
                allow: vec!["10.0.0.0/8".to_string()],
                ..AllowedIpConfig::default()
            },
            ..FilterConfig::default()
        }
    }

    #[test]
    fn default_config_builds_an_inactive_chain() {
        let chain =
            from_config(&FilterConfig::default(), &DnsConfig::default(), no_ipam()).unwrap();
        assert!(!chain.is_active());
        // Nothing is exempt by default: a profile's router only ever sees ACME
        // resources, and `/health` is served at the root, outside every chain.
        assert!(!chain.is_exempt("/health"));
        assert!(!chain.is_exempt("/directory"));
        assert!(!chain.is_exempt("/newOrder"));
    }

    #[test]
    fn from_config_builds_the_selected_filters_in_order() {
        let chain = from_config(
            &cfg(&["identifiers", "allowed_ip"]),
            &DnsConfig::default(),
            no_ipam(),
        )
        .unwrap();
        assert!(chain.is_active());
        let names: Vec<_> = chain.filters.iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["identifiers", "allowed_ip"]);
    }

    /// `reverse_dns` is built from the system resolver configuration, which a
    /// minimal container may not have — so this asserts only that the name is
    /// recognised, never that the host can resolve.
    #[test]
    fn reverse_dns_is_a_known_filter() {
        if let Err(error) = from_config(&cfg(&["reverse_dns"]), &DnsConfig::default(), no_ipam()) {
            let error = error.to_string();
            assert!(error.contains("reverse_dns"), "{error}");
            assert!(!error.contains("unknown filter"), "{error}");
        }
    }

    /// The inventory is built before the chain and handed in, so this asserts
    /// the whole arm rather than just the name.
    #[test]
    fn ipam_is_a_known_filter() {
        let ipam = IpamConfig {
            backend: "netbox".to_string(),
            netbox: crate::config::NetboxConfig {
                url: "https://netbox.example.com".to_string(),
                token: "t0ken".to_string(),
                ..crate::config::NetboxConfig::default()
            },
            ..IpamConfig::default()
        };

        let chain = from_config(&cfg(&["ipam"]), &DnsConfig::default(), ipam_from(&ipam)).unwrap();
        let names: Vec<_> = chain.filters.iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["ipam"]);
    }

    /// An enabled `ipam` filter with no inventory behind it stops the server,
    /// rather than failing every order at runtime.
    #[test]
    fn the_ipam_filter_without_a_backend_is_a_startup_error() {
        let error = from_config(&cfg(&["ipam"]), &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.backend"), "{error}");
        assert!(error.contains("netbox"), "{error}");
        assert!(error.contains("phpipam"), "{error}");
    }

    /// The old spelling is refused **by name**, not aliased and not merely
    /// "unknown": the section moved as well, so a silent alias would leave
    /// `[filter.netbox]` read by nothing while the server came up looking
    /// configured. Same treatment as `signer.backend = "acme_proxy"`.
    #[test]
    fn the_netbox_filter_is_refused_by_name() {
        let error = from_config(&cfg(&["netbox"]), &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("the `netbox` filter is now `ipam`"),
            "{error}"
        );
        assert!(error.contains("[ipam.netbox]"), "{error}");
        assert!(error.contains("ipam.timeout_ms"), "{error}");
        assert!(error.contains("ipam.netbox.sources"), "{error}");
        assert!(!error.contains("unknown filter"), "{error}");
    }

    /// `custom` in `filter.enabled` expands to one filter per configured
    /// script, in the order they were written, spliced into the same chain as
    /// every other filter rather than nested inside a single "custom" entry.
    #[test]
    fn custom_expands_to_one_filter_per_enabled_name() {
        let mut config = cfg(&["identifiers", "custom"]);
        config.custom_enabled = vec!["first".to_string(), "second".to_string()];
        config.custom = std::collections::BTreeMap::from([
            (
                "first".to_string(),
                crate::config::CustomFilterConfig {
                    script_path: "/bin/true".to_string(),
                    ..crate::config::CustomFilterConfig::default()
                },
            ),
            (
                "second".to_string(),
                crate::config::CustomFilterConfig {
                    script_path: "/bin/false".to_string(),
                    ..crate::config::CustomFilterConfig::default()
                },
            ),
        ]);

        let chain = from_config(&config, &DnsConfig::default(), no_ipam()).unwrap();
        let names: Vec<_> = chain.filters.iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["identifiers", "custom", "custom"]);
    }

    /// A name may be defined but left out of `custom_enabled` — only the
    /// listed ones, in listed order, actually run.
    #[test]
    fn custom_enabled_selects_and_orders_a_subset() {
        let mut config = cfg(&["custom"]);
        config.custom_enabled = vec!["second".to_string()];
        config.custom = std::collections::BTreeMap::from([
            (
                "first".to_string(),
                crate::config::CustomFilterConfig {
                    script_path: "/bin/true".to_string(),
                    ..crate::config::CustomFilterConfig::default()
                },
            ),
            (
                "second".to_string(),
                crate::config::CustomFilterConfig {
                    script_path: "/bin/false".to_string(),
                    ..crate::config::CustomFilterConfig::default()
                },
            ),
        ]);

        let chain = from_config(&config, &DnsConfig::default(), no_ipam()).unwrap();
        assert_eq!(chain.filters.len(), 1);
    }

    /// An enabled `custom` with an empty `custom_enabled` stops the server,
    /// rather than silently doing nothing.
    #[test]
    fn custom_without_any_enabled_scripts_is_a_startup_error() {
        let error = from_config(&cfg(&["custom"]), &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.custom_enabled"), "{error}");
    }

    /// `custom_enabled` naming an entry that isn't defined under `custom` is
    /// a startup error naming both, rather than being silently skipped.
    #[test]
    fn custom_enabled_naming_an_undefined_entry_is_a_startup_error() {
        let mut config = cfg(&["custom"]);
        config.custom_enabled = vec!["missing".to_string()];

        let error = from_config(&config, &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing"), "{error}");
        assert!(error.contains("filter.custom.missing"), "{error}");
    }

    /// A `filter.custom` name outside `[a-z0-9-]` is refused at startup: the
    /// `config` crate lowercases environment-variable segments, so an
    /// uppercase or underscored name could silently split into two entries
    /// between the file and `ACME_PROXY_FILTER__CUSTOM__…`.
    #[test]
    fn a_bad_custom_filter_name_is_a_startup_error() {
        let mut config = cfg(&["custom"]);
        config.custom_enabled = vec!["Bad_Name".to_string()];
        config.custom = std::collections::BTreeMap::from([(
            "Bad_Name".to_string(),
            crate::config::CustomFilterConfig {
                script_path: "/bin/true".to_string(),
                ..crate::config::CustomFilterConfig::default()
            },
        )]);

        let error = from_config(&config, &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.custom.Bad_Name"), "{error}");
    }

    #[test]
    fn from_config_rejects_an_unknown_filter() {
        let error = from_config(&cfg(&["nope"]), &DnsConfig::default(), no_ipam())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown filter: nope"), "{error}");
    }

    #[test]
    fn from_config_rejects_a_bad_trusted_proxy() {
        let config = FilterConfig {
            trusted_proxies: vec!["not-a-network".to_string()],
            ..FilterConfig::default()
        };
        assert!(from_config(&config, &DnsConfig::default(), no_ipam()).is_err());
    }

    #[test]
    fn parse_net_accepts_cidr_and_bare_addresses() {
        assert_eq!(
            parse_net("192.168.1.0/24").unwrap(),
            "192.168.1.0/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            parse_net("fd00::/8").unwrap(),
            "fd00::/8".parse::<IpNet>().unwrap()
        );
        // A bare address becomes a host route.
        assert_eq!(parse_net("203.0.113.7").unwrap().prefix_len(), 32);
        assert_eq!(parse_net("2001:db8::1").unwrap().prefix_len(), 128);
        assert!(parse_net("192.168.1.0/99").is_err());
        assert!(parse_net("garbage").is_err());
    }

    #[test]
    fn nets_contain_canonicalizes_ipv4_mapped_addresses() {
        let nets = parse_nets(&["192.168.1.0/24".to_string()], "test").unwrap();
        assert!(nets_contain(&nets, "192.168.1.5".parse().unwrap()));
        // The dual-stack socket hands us this form for an IPv4 client.
        assert!(nets_contain(&nets, "::ffff:192.168.1.5".parse().unwrap()));
        assert!(!nets_contain(&nets, "192.168.2.5".parse().unwrap()));
    }

    #[test]
    fn parse_nets_names_the_offending_setting() {
        let error = parse_nets(&["bad".to_string()], "filter.allowed_ip.allow")
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.allowed_ip.allow"), "{error}");
    }

    #[test]
    fn compile_anchored_prevents_suffix_bypass() {
        let regexes = compile_anchored(&[r"example\.com".to_string()], "test").unwrap();
        assert!(regexes[0].is_match("example.com"));
        // The whole point: an unanchored search would accept this.
        assert!(!regexes[0].is_match("example.com.evil.net"));
        assert!(!regexes[0].is_match("notexample.com"));
        // Anchoring does not stop an operator asking for a suffix explicitly.
        let suffix = compile_anchored(&[r".*\.example\.com".to_string()], "test").unwrap();
        assert!(suffix[0].is_match("a.b.example.com"));
        assert!(!suffix[0].is_match("example.com.evil.net"));
    }

    #[test]
    fn compile_anchored_is_case_insensitive() {
        let regexes = compile_anchored(&[r"example\.com".to_string()], "test").unwrap();
        assert!(regexes[0].is_match("EXAMPLE.CoM"));
    }

    #[test]
    fn compile_anchored_reports_a_bad_pattern() {
        let error = compile_anchored(&["[unclosed".to_string()], "filter.identifiers.allow")
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.identifiers.allow"), "{error}");
    }

    #[test]
    fn identifier_stage_labels() {
        assert_eq!(IdentifierStage::NewOrder.as_str(), "newOrder");
        assert_eq!(IdentifierStage::Csr.as_str(), "CSR");
    }

    /// The allow/deny rule all three filters share, tested once at the source
    /// rather than three times through three different value types.
    #[test]
    fn check_lists_implements_the_shared_allow_deny_rule() {
        /// Membership test: does the list contain this exact string?
        fn matches(value: &'static str) -> impl Fn(&&str) -> bool {
            move |candidate: &&str| *candidate == value
        }

        // An empty allow imposes no constraint: deny-only is a blocklist.
        assert_eq!(
            check_lists(&[], &["bad"], matches("good")),
            ListVerdict::Permitted
        );
        assert_eq!(
            check_lists(&[], &["bad"], matches("bad")),
            ListVerdict::Denied
        );

        // A non-empty allow refuses everything outside it.
        assert_eq!(
            check_lists(&["good"], &[], matches("good")),
            ListVerdict::Permitted
        );
        assert_eq!(
            check_lists(&["good"], &[], matches("other")),
            ListVerdict::NotAllowed
        );

        // Deny is checked first and wins, even over an explicit allow entry.
        assert_eq!(
            check_lists(&["both"], &["both"], matches("both")),
            ListVerdict::Denied
        );

        // Both empty permits everything — `allowed_ip` refuses that config at
        // startup precisely because this is a no-op.
        assert_eq!(
            check_lists::<&str>(&[], &[], |_| false),
            ListVerdict::Permitted
        );
    }

    /// Every connection filter must fail closed on a missing peer address.
    #[test]
    fn require_client_ip_fails_closed_and_canonicalizes() {
        let context = |client_ip| ConnectionContext {
            client_ip,
            method: &Method::POST,
            path: "/newOrder",
        };

        assert!(matches!(
            context(None).require_client_ip(),
            Err(FilterError::Denied(detail)) if detail.contains("unavailable")
        ));

        // An IPv4 client over the dual-stack default socket arrives mapped.
        let mapped: IpAddr = "::ffff:192.168.1.5".parse().unwrap();
        assert_eq!(
            context(Some(mapped)).require_client_ip().unwrap(),
            "192.168.1.5".parse::<IpAddr>().unwrap()
        );
    }

    /// `dyn Filter` is not `Debug`, so the chain renders the names and the
    /// policy around them — what a startup log is read for.
    #[test]
    fn the_chain_debug_names_its_filters_and_policy() {
        let mut config = cfg(&["allowed_ip"]);
        config.exempt_paths = vec!["/health".to_string()];
        let chain = from_config(&config, &DnsConfig::default(), no_ipam()).unwrap();

        let rendered = format!("{chain:?}");
        assert!(rendered.contains("FilterChain"), "{rendered}");
        assert!(rendered.contains("allowed_ip"), "{rendered}");
        assert!(rendered.contains("/health"), "{rendered}");

        // The default chain is empty, and says so.
        assert!(format!("{:?}", FilterChain::default()).contains("[]"));
    }
}
