//! IP address management: which names does an address own?
//!
//! One question, asked of whichever inventory an estate already keeps. It used
//! to be a filter — `filter.netbox` — which welded the question to one vendor's
//! REST API: the config lived under `[filter.netbox]`, the seam was shaped
//! around NetBox's endpoints, and the filter was named after the product. A
//! second inventory had nowhere to plug in.
//!
//! So the question lives here and the *policy* built on the answer stays in
//! [`filter::ipam`](crate::filter::ipam), which is the only consumer. The split
//! is the same one [`signer`](crate::signer) makes: a backend reports what is
//! true, a caller decides what to do about it.
//!
//! ## Denied versus Internal
//!
//! The most consequential property here, and the reason [`IpamError`] is a
//! struct rather than an enum with a "denied" variant: **an `Ipam` never denies
//! anything.** It reports what an inventory holds, and every failure to obtain
//! that — unreachable, 500, a refused token, a timeout — is this server failing
//! to reach a decision, which the filter turns into a retryable 500 rather than
//! a refusal. The only inventory-sourced denial is
//! [`AddressNames::Unknown`], which is a fact about the address rather than a
//! failure to look it up.
//!
//! That is what keeps the subsystem from ever failing open: an inventory
//! outage stops issuance instead of permitting everything.
//!
//! ## The budget lives here
//!
//! [`IpamRegistry`] wraps every lookup in a `tokio::time::timeout`, the way
//! [`ChallengeRegistry`](crate::challenge::ChallengeRegistry) wraps every
//! validation attempt. A backend may make four requests to answer one question;
//! one budget covers all of them, and a backend added later cannot forget to
//! apply it.
//!
//! ## Matching is exact
//!
//! Names are [`normalize`]d — lowercased and stripped of a trailing dot — and
//! otherwise compared literally. No suffix rule, no wildcard expansion: an
//! entry `example.com` does not permit `a.example.com`, and a request for
//! `*.example.com` requires that exact string in the inventory. The same choice
//! [`compile_anchored`](crate::filter::compile_anchored) makes for the
//! regex-based filters, for the same reason — a rule that quietly covers more
//! than it says is the bypass an allowlist exists to prevent.

pub mod http;
pub mod netbox;
pub mod phpipam;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::config::IpamConfig;

/// What an inventory knows about one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressNames {
    /// The inventory holds no record of this address at all.
    ///
    /// Distinct from `Known` with an empty set, which is "recorded, and
    /// entitled to nothing" — the two produce different refusals, and an
    /// operator reading a 403 should be able to tell them apart.
    Unknown,
    /// The names it associates with the address, already [`normalize`]d.
    Known(BTreeSet<String>),
}

impl AddressNames {
    /// A known address with no names yet; add them with [`Self::insert`].
    #[must_use]
    pub fn known() -> Self {
        Self::Known(BTreeSet::new())
    }

    /// Adds a name, normalizing it and ignoring an empty one.
    ///
    /// An unset NetBox `dns_name` comes back as `""` rather than as absent, so
    /// the empty check is load-bearing rather than defensive. Does nothing on
    /// [`Self::Unknown`].
    pub fn insert(&mut self, value: &str) {
        if let Self::Known(names) = self {
            let name = normalize(value);
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }

    /// Whether the inventory holds a record of the address.
    #[must_use]
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// The names, or an empty set for an unknown address.
    #[must_use]
    pub fn names(&self) -> &BTreeSet<String> {
        static EMPTY: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
        match self {
            Self::Known(names) => names,
            Self::Unknown => EMPTY.get_or_init(BTreeSet::new),
        }
    }
}

/// The inventory failed to reach a decision.
///
/// There is deliberately **no** "denied" variant. An [`Ipam`] reports what an
/// inventory holds; every failure to obtain that is the server's problem, never
/// the client's, and the filter is the only place a denial is decided. Keeping
/// the type unable to express a refusal is what stops a backend author from
/// accidentally turning an outage into a permanent-looking rejection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IpamError(pub String);

/// One place a permitted name may come from.
///
/// Each backend declares which of these it supports, and its `sources` key
/// lists which are actually consulted. The list is a **union of sets**, so its
/// order is meaningless — unlike `filter.enabled` (evaluation order) or
/// `challenge.enabled` (offer order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The address object's own name: NetBox's `dns_name`, phpIPAM's
    /// `hostname`.
    DnsName,
    /// The configured custom field, read from the address object itself.
    CustomField,
    /// The same custom field on the device or virtual machine the address is
    /// assigned to.
    ///
    /// A **fallback, not a union**: read only when the address object carried
    /// no value of its own. A value set on the address is the more specific
    /// statement, and an operator narrowing one address of a machine would be
    /// surprised to see the machine-wide list quietly widen it again.
    Device,
    /// Role-tagged service addresses on the same device — a VIP shared by a
    /// keepalived or CARP pair. A **union**: the member's own names and the
    /// service address's names are both true at once.
    Vip,
    /// The service addresses of an FHRP group the client's own interface is
    /// recorded as a member of. A **union**, like [`Self::Vip`].
    Fhrp,
}

impl Source {
    /// The name this source is configured under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsName => "dns_name",
            Self::CustomField => "custom_field",
            Self::Device => "device",
            Self::Vip => "vip",
            Self::Fhrp => "fhrp",
        }
    }

    /// Every source name, for an error listing what was expected.
    const ALL: &'static [Self] = &[
        Self::DnsName,
        Self::CustomField,
        Self::Device,
        Self::Vip,
        Self::Fhrp,
    ];

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == name)
    }
}

/// The `sources` a backend was configured with, after validation.
///
/// Ordered so a `Debug` rendering — which is what a startup log line and
/// `signer::build_backends`-style config keying both read — is deterministic,
/// even though the set's own meaning has no order.
pub type Sources = BTreeSet<Source>;

/// Parses and validates a `sources` list against what one backend supports.
///
/// Empty, or an unknown name, is a startup error — the `challenge.enabled`
/// rule verbatim, and for the same reason: an inventory trusted for nothing can
/// never permit a name, so it is a filter that refuses everything, and a typo
/// that silently narrows an allowlist is worse than a refusal to boot.
///
/// A name that exists but is not this backend's is refused **by name**, not
/// ignored: `fhrp` under `[ipam.phpipam]` is an operator expecting redundancy
/// groups from a product that records none, and answering that with silence
/// would leave them believing a check is running that never runs.
pub(crate) fn parse_sources(
    backend: &str,
    setting: &str,
    values: &[String],
    supported: &[Source],
) -> anyhow::Result<Sources> {
    anyhow::ensure!(
        !values.is_empty(),
        "{setting} is empty; an inventory trusted for nothing can never permit a name, so \
         every request would be refused. List at least one of: {}",
        names_of(supported)
    );

    let mut sources = Sources::new();
    for value in values {
        let name = value.trim();
        let source = Source::parse(name).ok_or_else(|| {
            anyhow::anyhow!(
                "{setting}: unknown source `{name}`; known sources are {}",
                names_of(Source::ALL)
            )
        })?;
        anyhow::ensure!(
            supported.contains(&source),
            "{setting}: `{name}` is not a source {backend} has; it supports {}",
            names_of(supported)
        );
        sources.insert(source);
    }
    Ok(sources)
}

/// `a`, `b`, `c` — the way an error should list what it expected.
fn names_of(sources: &[Source]) -> String {
    sources
        .iter()
        .map(|source| format!("`{}`", source.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The inventory this profile consults.
#[async_trait]
pub trait Ipam: Send + Sync {
    /// The product's name, as it should read in a log line or a 403 detail.
    fn name(&self) -> &'static str;

    /// Every name this inventory associates with `ip`.
    async fn names_for(&self, ip: IpAddr) -> Result<AddressNames, IpamError>;
}

/// The configured backend plus the budget every lookup runs under.
///
/// The timeout is here rather than inside each backend for the reason
/// [`ChallengeRegistry`](crate::challenge::ChallengeRegistry) keeps its there:
/// a backend may make several requests to answer one question, one budget has
/// to cover all of them, and a backend written later cannot forget to apply
/// something it never touches.
pub struct IpamRegistry {
    backend: Arc<dyn Ipam>,
    timeout: Duration,
}

impl std::fmt::Debug for IpamRegistry {
    /// `dyn Ipam` is not `Debug`; the name and the budget are the readable part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IpamRegistry")
            .field("backend", &self.backend.name())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl IpamRegistry {
    /// Wraps a backend in its budget.
    #[must_use]
    pub fn new(backend: Arc<dyn Ipam>, timeout: Duration) -> Self {
        Self { backend, timeout }
    }

    /// The backend's name, so a refusal can say which inventory refused.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// One lookup, under the configured budget.
    pub async fn names_for(&self, ip: IpAddr) -> Result<AddressNames, IpamError> {
        match tokio::time::timeout(self.timeout, self.backend.names_for(ip)).await {
            Ok(result) => result,
            Err(_) => Err(IpamError(format!(
                "{} lookup for {ip} timed out after {}ms",
                self.backend.name(),
                self.timeout.as_millis()
            ))),
        }
    }
}

/// Builds the configured inventory, or `None` when none is configured.
///
/// Called once at startup, so it may fail fast — but it contacts nothing: an
/// inventory that is down at startup is an outage, not a configuration error,
/// and stopping the server for it would turn a retryable 500 into a refusal to
/// boot.
pub fn from_config(
    cfg: &IpamConfig,
    outbound: crate::http_client::Outbound,
) -> anyhow::Result<Option<Arc<IpamRegistry>>> {
    let backend: Arc<dyn Ipam> = match cfg.backend.trim() {
        "" => return Ok(None),
        "netbox" => Arc::new(netbox::NetboxBackend::from_config(&cfg.netbox, outbound)?),
        "phpipam" => Arc::new(phpipam::PhpIpamBackend::from_config(
            &cfg.phpipam,
            outbound,
        )?),
        other => anyhow::bail!("unknown IPAM backend: {other} (expected `netbox` or `phpipam`)"),
    };

    info!(
        event = "ipam_enabled",
        outcome = "success",
        backend = backend.name(),
        timeout_ms = cfg.timeout_ms,
    );

    Ok(Some(Arc::new(IpamRegistry::new(
        backend,
        Duration::from_millis(cfg.timeout_ms),
    ))))
}

/// Lowercased and stripped of a trailing dot, the form both sides compare in.
#[must_use]
pub fn normalize(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A custom field's entries, as a list of strings.
///
/// An inventory lets a custom field be a multi-select (a JSON array) or plain
/// text (a single string); both are accepted. Anything else is a field
/// misconfigured on the inventory side, which is worth a log line but not a
/// reason to fail the request — the names simply do not come from there.
pub(crate) fn field_values(
    fields: &Map<String, Value>,
    field: &str,
    backend: &'static str,
    source: &str,
) -> Vec<String> {
    match fields.get(field) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(name) => Some(name.clone()),
                other => {
                    warn!(
                        event = "ipam_field_entry_ignored",
                        outcome = "advisory",
                        backend,
                        field,
                        source,
                        entry = %other,
                        "custom field entry is not a string"
                    );
                    None
                }
            })
            .collect(),
        Some(other) => {
            warn!(
                event = "ipam_field_ignored",
                outcome = "advisory",
                backend,
                field,
                source,
                kind = value_kind(other),
                "custom field is neither a string nor a list of strings"
            );
            Vec::new()
        }
    }
}

/// A JSON value's type name, for a log line that should not carry the value.
pub(crate) fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    fn resolver() -> Arc<dyn crate::dns::Resolver> {
        crate::challenge::build_resolver(None).unwrap()
    }

    // ------------------------------------------------------------- sources

    #[test]
    fn every_source_round_trips_through_its_name() {
        for source in Source::ALL {
            assert_eq!(Source::parse(source.as_str()), Some(*source));
        }
        assert_eq!(Source::parse("nope"), None);
    }

    #[test]
    fn sources_parse_and_deduplicate() {
        let parsed = parse_sources(
            "NetBox",
            "ipam.netbox.sources",
            &strings(&["dns_name", "custom_field", "dns_name"]),
            Source::ALL,
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&Source::DnsName));
        assert!(parsed.contains(&Source::CustomField));
    }

    /// Whitespace around an entry is an operator writing a list by hand, not a
    /// different source.
    #[test]
    fn sources_are_trimmed() {
        let parsed = parse_sources(
            "NetBox",
            "ipam.netbox.sources",
            &strings(&[" dns_name "]),
            Source::ALL,
        )
        .unwrap();
        assert!(parsed.contains(&Source::DnsName));
    }

    #[test]
    fn an_empty_sources_list_is_a_startup_error() {
        let error = parse_sources("NetBox", "ipam.netbox.sources", &[], Source::ALL).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("ipam.netbox.sources is empty"),
            "{message}"
        );
        assert!(message.contains("`dns_name`"), "{message}");
    }

    #[test]
    fn an_unknown_source_is_a_startup_error_naming_it() {
        let error = parse_sources(
            "NetBox",
            "ipam.netbox.sources",
            &strings(&["dns_name", "typo"]),
            Source::ALL,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unknown source `typo`"), "{message}");
        assert!(message.contains("`fhrp`"), "{message}");
    }

    /// The refusal a phpIPAM operator gets for asking about FHRP groups: by
    /// name, listing what the backend does have. Silence here would leave them
    /// believing a check runs that never runs.
    #[test]
    fn a_source_another_backend_has_is_refused_by_name() {
        let error = parse_sources(
            "phpIPAM",
            "ipam.phpipam.sources",
            &strings(&["dns_name", "fhrp"]),
            &[Source::DnsName, Source::CustomField, Source::Device],
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("`fhrp` is not a source phpIPAM has"),
            "{message}"
        );
        assert!(message.contains("`device`"), "{message}");
        assert!(!message.contains("`vip`"), "{message}");
    }

    // ------------------------------------------------------- AddressNames

    #[test]
    fn an_unknown_address_is_not_an_empty_one() {
        let unknown = AddressNames::Unknown;
        let empty = AddressNames::known();
        assert!(!unknown.is_known());
        assert!(empty.is_known());
        assert_eq!(unknown.names().len(), 0);
        assert_ne!(unknown, empty);
    }

    #[test]
    fn inserting_normalizes_and_skips_empties() {
        let mut names = AddressNames::known();
        names.insert("Host.Example.COM.");
        names.insert("  ");
        names.insert("");
        names.insert("host.example.com");
        assert_eq!(
            names.names().iter().cloned().collect::<Vec<_>>(),
            vec!["host.example.com".to_string()]
        );
    }

    #[test]
    fn inserting_into_an_unknown_address_does_nothing() {
        let mut names = AddressNames::Unknown;
        names.insert("host.example.com");
        assert_eq!(names, AddressNames::Unknown);
    }

    #[test]
    fn normalize_lowercases_and_strips_a_trailing_dot() {
        assert_eq!(normalize(" Host.Example.COM. "), "host.example.com");
        assert_eq!(normalize("*.Example.com"), "*.example.com");
    }

    // -------------------------------------------------------- field_values

    #[test]
    fn a_custom_field_may_be_a_string_or_a_list() {
        let fields: Map<String, Value> = serde_json::from_value(json!({
            "one": "a.example.com",
            "many": ["a.example.com", "b.example.com"],
        }))
        .unwrap();

        assert_eq!(field_values(&fields, "one", "NetBox", "address").len(), 1);
        assert_eq!(field_values(&fields, "many", "NetBox", "address").len(), 2);
    }

    /// A field of the wrong type contributes nothing and is not fatal — the
    /// names simply do not come from there.
    #[test]
    fn an_unusable_custom_field_contributes_nothing() {
        let fields: Map<String, Value> = serde_json::from_value(json!({
            "absent": Value::Null,
            "number": 7,
            "object": {"a": 1},
            "mixed": ["a.example.com", 7, {"b": 2}],
        }))
        .unwrap();

        assert!(field_values(&fields, "missing", "NetBox", "address").is_empty());
        assert!(field_values(&fields, "absent", "NetBox", "address").is_empty());
        assert!(field_values(&fields, "number", "NetBox", "address").is_empty());
        assert!(field_values(&fields, "object", "NetBox", "address").is_empty());
        assert_eq!(field_values(&fields, "mixed", "NetBox", "address").len(), 1);
    }

    #[test]
    fn value_kind_names_every_json_type() {
        assert_eq!(value_kind(&Value::Null), "null");
        assert_eq!(value_kind(&json!(true)), "bool");
        assert_eq!(value_kind(&json!(1)), "number");
        assert_eq!(value_kind(&json!("s")), "string");
        assert_eq!(value_kind(&json!([])), "array");
        assert_eq!(value_kind(&json!({})), "object");
    }

    // ---------------------------------------------------------- from_config

    #[test]
    fn no_backend_builds_nothing() {
        let cfg = IpamConfig::default();
        assert!(
            from_config(&cfg, crate::testutil::outbound_with(resolver()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn each_backend_builds() {
        let netbox = from_config(
            &IpamConfig {
                backend: "netbox".to_string(),
                netbox: crate::config::NetboxConfig {
                    url: "https://netbox.example.com".to_string(),
                    token: "t0ken".to_string(),
                    ..crate::config::NetboxConfig::default()
                },
                ..IpamConfig::default()
            },
            crate::testutil::outbound_with(resolver()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(netbox.backend_name(), "NetBox");

        let phpipam = from_config(
            &IpamConfig {
                backend: "phpipam".to_string(),
                phpipam: crate::config::PhpIpamConfig {
                    url: "https://ipam.example.com".to_string(),
                    token: "t0ken".to_string(),
                    ..crate::config::PhpIpamConfig::default()
                },
                ..IpamConfig::default()
            },
            crate::testutil::outbound_with(resolver()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(phpipam.backend_name(), "phpIPAM");
    }

    #[test]
    fn an_unknown_backend_is_a_startup_error_naming_both_valid_ones() {
        let cfg = IpamConfig {
            backend: "racktables".to_string(),
            ..IpamConfig::default()
        };
        let error = from_config(&cfg, crate::testutil::outbound_with(resolver()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("racktables"), "{error}");
        assert!(error.contains("netbox"), "{error}");
        assert!(error.contains("phpipam"), "{error}");
    }

    // ------------------------------------------------------------ registry

    struct Hanging;

    #[async_trait]
    impl Ipam for Hanging {
        fn name(&self) -> &'static str {
            "Hanging"
        }
        async fn names_for(&self, _ip: IpAddr) -> Result<AddressNames, IpamError> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!("the registry's budget expires first")
        }
    }

    struct Answering;

    #[async_trait]
    impl Ipam for Answering {
        fn name(&self) -> &'static str {
            "Answering"
        }
        async fn names_for(&self, _ip: IpAddr) -> Result<AddressNames, IpamError> {
            let mut names = AddressNames::known();
            names.insert("a.example.com");
            Ok(names)
        }
    }

    /// The whole reason the budget lives on the registry: a backend that never
    /// answers cannot pin a request — and the SQLite connection behind it —
    /// open for as long as it likes.
    #[tokio::test]
    async fn the_registry_applies_the_budget() {
        let registry = IpamRegistry::new(Arc::new(Hanging), Duration::from_millis(10));
        let error = registry
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("timed out after 10ms"), "{error}");
        assert!(error.0.contains("Hanging"), "{error}");
    }

    #[tokio::test]
    async fn a_prompt_backend_answers_through_the_registry() {
        let registry = IpamRegistry::new(Arc::new(Answering), Duration::from_secs(5));
        let names = registry
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap();
        assert!(names.names().contains("a.example.com"));
        assert_eq!(registry.backend_name(), "Answering");
        assert!(format!("{registry:?}").contains("Answering"));
    }
}
