//! The `netbox` filter: the client's address must own the names it asks for.
//!
//! The other identifier filter, [`identifiers`](super::identifiers), answers
//! "may *anyone here* have this name certified?" from a static list. This one
//! answers the narrower question the list cannot express: may **this address**
//! have **this name** certified? The answer is not configured — it is read from
//! NetBox, which in a managed estate already records it.
//!
//! ## What NetBox is asked
//!
//! One lookup, `GET /api/ipam/ip-addresses/?address=<client ip>`. What it
//! returns permits names two ways:
//!
//! - the address object's own `dns_name`, when `use_dns_name` is on;
//! - a custom field (`custom_field`, by default `acme_allowed_names`) holding
//!   the extra names that address may request.
//!
//! When the address object carries no value for that custom field and
//! `device_fallback` is on, the device or virtual machine it is assigned to is
//! read instead, so the names can be declared once per machine rather than once
//! per address. The fallback is a fallback and not a union on purpose: a value
//! set on the address is the more specific statement, and an operator narrowing
//! one address of a machine would be surprised to see the machine-wide list
//! quietly widen it again.
//!
//! ## Matching is exact
//!
//! Case-insensitive and ignoring a trailing dot, but otherwise literal: no
//! suffix rule, no wildcard expansion. An entry `example.com` does **not**
//! permit `a.example.com`, and a request for `*.example.com` requires that
//! exact string in NetBox. This is the same choice
//! [`compile_anchored`](super::compile_anchored) makes for the regex-based
//! filters, for the same reason — a rule that quietly covers more than it says
//! is the bypass an allowlist exists to prevent.
//!
//! An `ip` identifier is permitted when it *is* the connecting address (a
//! machine may always certify the address it is talking from) or when it is
//! listed like any other name. A `cn` is skipped — see
//! [`super::SUBJECT_ONLY_TYPES`]. Any other type is refused:
//! NetBox has nothing to say about an email address or a URI, and a filter
//! whose job is to confirm entitlement must refuse what it cannot confirm.
//!
//! ## Denied versus Internal
//!
//! "NetBox does not associate this name with this address" is a decision about
//! the client and denies the request. "NetBox answered 500", "the token was
//! refused", "the request timed out" are not — the server failed to reach a
//! decision, so they become [`FilterError::Internal`] and surface as a 500 the
//! client can retry. The same split [`reverse_dns`](super::reverse_dns) draws,
//! and the reason this filter never fails open: an unreachable NetBox stops
//! issuance rather than permitting everything.

pub mod client;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::{debug, info, warn};

use super::{Filter, FilterError, IdentifierContext, SUBJECT_ONLY_TYPES, canonical};
use crate::config::NetboxConfig;

/// Which kind of NetBox object an address is assigned to.
///
/// Only the two that can carry custom fields worth reading here; anything else
/// an interface may hang off is left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignedKind {
    Device,
    VirtualMachine,
}

/// A device or virtual machine an address is assigned to, enough to fetch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedRef {
    pub kind: AssignedKind,
    pub id: u64,
}

/// One NetBox `ipam/ip-addresses` object, reduced to what this filter reads.
#[derive(Debug, Clone, Default)]
pub struct NetboxIp {
    /// The object's `dns_name`, empty when unset.
    pub dns_name: String,
    /// The object's custom fields, as NetBox returned them.
    pub custom_fields: Map<String, Value>,
    /// The device or VM behind the assigned interface, when there is one.
    pub assigned: Option<AssignedRef>,
}

/// The NetBox queries this filter makes.
///
/// A trait so the policy above can be tested without a NetBox — the same seam
/// [`Resolver`](crate::dns::Resolver) gives `reverse_dns`, and errors are plain
/// `String`s for the same reason: what a caller does with a failed query does
/// not concern the transport.
#[async_trait]
pub trait NetboxApi: Send + Sync {
    /// The `ipam/ip-addresses` objects NetBox holds for this address.
    async fn ip_addresses(&self, ip: IpAddr) -> Result<Vec<NetboxIp>, String>;

    /// The custom fields of one device or virtual machine.
    async fn object_custom_fields(
        &self,
        reference: &AssignedRef,
    ) -> Result<Map<String, Value>, String>;
}

/// Requires every requested name to be one NetBox associates with the client's
/// address.
pub struct NetboxFilter {
    api: Arc<dyn NetboxApi>,
    custom_field: String,
    use_dns_name: bool,
    device_fallback: bool,
    timeout: Duration,
}

impl std::fmt::Debug for NetboxFilter {
    /// `dyn NetboxApi` is not `Debug`; the policy is the interesting part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetboxFilter")
            .field("custom_field", &self.custom_field)
            .field("use_dns_name", &self.use_dns_name)
            .field("device_fallback", &self.device_fallback)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl NetboxFilter {
    /// Builds the real NetBox client, then delegates.
    ///
    /// Nothing is contacted here: a NetBox that is down at startup is an
    /// outage, not a configuration error, and stopping the server for it would
    /// turn a retryable 500 into a refusal to boot.
    pub fn from_config(
        cfg: &NetboxConfig,
        resolver: Arc<dyn crate::dns::Resolver>,
    ) -> anyhow::Result<Self> {
        let api = Arc::new(client::NetboxClient::new(cfg, resolver)?);
        let filter = Self::with_api(cfg, api)?;

        info!(
            event = "filter_netbox_loaded",
            url = %cfg.url,
            custom_field = %cfg.custom_field,
            use_dns_name = cfg.use_dns_name,
            device_fallback = cfg.device_fallback,
            timeout_ms = cfg.timeout_ms,
        );

        // Unconditional, and deliberately not once-only: this is a temporary
        // operational state (an expired NetBox certificate being waited out),
        // and it should stay visible in the log for as long as it lasts. The
        // counterpart of `tls_disabled` and `challenge_validation_bypassed`.
        if cfg.insecure_skip_verify {
            warn!(
                event = "filter_netbox_tls_verification_disabled",
                url = %cfg.url,
                "filter.netbox.insecure_skip_verify is on: NetBox's TLS certificate is not \
                 verified, so the answers this filter trusts could come from anyone able to \
                 intercept the connection (filter.netbox.ca_cert_path is ignored while it is set)"
            );
        }

        Ok(filter)
    }

    /// Same, against a caller-supplied API. Used by tests.
    pub fn with_api(cfg: &NetboxConfig, api: Arc<dyn NetboxApi>) -> anyhow::Result<Self> {
        if cfg.custom_field.trim().is_empty() {
            anyhow::bail!(
                "filter.netbox.custom_field is empty; name the NetBox custom field holding the \
                 permitted names (default `acme_allowed_names`)"
            );
        }

        Ok(Self {
            api,
            custom_field: cfg.custom_field.clone(),
            use_dns_name: cfg.use_dns_name,
            device_fallback: cfg.device_fallback,
            timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    /// Every name NetBox associates with `client_ip`, normalized.
    async fn permitted_names(&self, client_ip: IpAddr) -> Result<BTreeSet<String>, FilterError> {
        let objects = self.api.ip_addresses(client_ip).await.map_err(|error| {
            FilterError::Internal(format!("NetBox lookup for {client_ip} failed: {error}"))
        })?;

        if objects.is_empty() {
            return Err(FilterError::Denied(format!(
                "NetBox holds no IP address object for {client_ip}"
            )));
        }

        let mut names = BTreeSet::new();
        // Whether *any* address object answered with the custom field, which is
        // what decides the device fallback below. Tracked separately from
        // `names` being non-empty, since a `dns_name` fills that too and must
        // not suppress the fallback.
        let mut custom_field_answered = false;
        let mut assigned = None;

        for object in &objects {
            if self.use_dns_name {
                insert_name(&mut names, &object.dns_name);
            }

            let values = self.field_values(&object.custom_fields, "IP address object");
            if !values.is_empty() {
                custom_field_answered = true;
            }
            for value in values {
                insert_name(&mut names, &value);
            }

            if assigned.is_none() {
                assigned.clone_from(&object.assigned);
            }
        }

        if !custom_field_answered
            && self.device_fallback
            && let Some(reference) = assigned
        {
            let fields = self
                .api
                .object_custom_fields(&reference)
                .await
                .map_err(|error| {
                    FilterError::Internal(format!(
                        "NetBox lookup of {:?} {} for {client_ip} failed: {error}",
                        reference.kind, reference.id
                    ))
                })?;
            for value in self.field_values(&fields, "assigned object") {
                insert_name(&mut names, &value);
            }
        }

        Ok(names)
    }

    /// The configured custom field's entries, as a list of strings.
    ///
    /// NetBox lets a custom field be a multi-select (a JSON array) or plain
    /// text (a single string); both are accepted. Anything else is a field
    /// misconfigured on the NetBox side, which is worth a log line but not a
    /// reason to fail the request — the names simply do not come from there.
    fn field_values(&self, fields: &Map<String, Value>, source: &str) -> Vec<String> {
        match fields.get(&self.custom_field) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(one)) => vec![one.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::String(name) => Some(name.clone()),
                    other => {
                        warn!(
                            event = "filter_netbox_field_entry_ignored",
                            field = %self.custom_field,
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
                    event = "filter_netbox_field_ignored",
                    field = %self.custom_field,
                    source,
                    kind = value_kind(other),
                    "custom field is neither a string nor a list of strings"
                );
                Vec::new()
            }
        }
    }
}

#[async_trait]
impl Filter for NetboxFilter {
    fn name(&self) -> &'static str {
        "netbox"
    }

    async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        let client_ip = ctx.require_client_ip()?;
        let stage = ctx.stage.as_str();

        // A CSR carrying nothing but a common name asks NetBox no question, so
        // it is not worth a round trip. Same reasoning as `FilterChain::is_active`.
        if ctx.identifiers.iter().all(is_subject_only) {
            return Ok(());
        }

        // One budget for the address lookup and the optional device one
        // together, so a wedged NetBox cannot pin a request — and a SQLite
        // connection — open for as long as it likes.
        let names = match tokio::time::timeout(self.timeout, self.permitted_names(client_ip)).await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(FilterError::Internal(format!(
                    "NetBox lookup for {client_ip} timed out after {}ms",
                    self.timeout.as_millis()
                )));
            }
        };

        for identifier in ctx.identifiers {
            if is_subject_only(identifier) {
                continue;
            }

            let typ = identifier.typ.to_ascii_lowercase();
            let value = normalize(&identifier.value);

            match typ.as_str() {
                "dns" => {
                    if !names.contains(&value) {
                        return Err(FilterError::Denied(format!(
                            "{stage} identifier {} is not among the names NetBox associates \
                             with {client_ip}",
                            identifier.value
                        )));
                    }
                }
                // A machine may always certify the address it is talking from;
                // any other address has to be listed like a name.
                "ip" => {
                    let is_client = value
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| canonical(ip) == client_ip);
                    if !is_client && !names.contains(&value) {
                        return Err(FilterError::Denied(format!(
                            "{stage} identifier {} is neither {client_ip} nor a name NetBox \
                             associates with it",
                            identifier.value
                        )));
                    }
                }
                other => {
                    return Err(FilterError::Denied(format!(
                        "{stage} requests a {other} identifier, which NetBox cannot confirm \
                         for {client_ip}"
                    )));
                }
            }
        }

        debug!(
            event = "filter_netbox_accepted",
            client_ip = %client_ip,
            stage,
            identifiers = ctx.identifiers.len(),
        );
        Ok(())
    }
}

/// Whether this identifier is subject metadata this filter leaves alone.
fn is_subject_only(identifier: &crate::sqlite::order::Identifier) -> bool {
    SUBJECT_ONLY_TYPES.contains(&identifier.typ.to_ascii_lowercase().as_str())
}

/// Lowercased and stripped of a trailing dot, the form both sides compare in.
fn normalize(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Adds a name to the permitted set, ignoring an empty one (an unset
/// `dns_name` comes back as `""`, not as absent).
fn insert_name(names: &mut BTreeSet<String>, value: &str) {
    let name = normalize(value);
    if !name.is_empty() {
        names.insert(name);
    }
}

/// A JSON value's type name, for a log line that should not carry the value.
fn value_kind(value: &Value) -> &'static str {
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
    use crate::filter::{ConnectionContext, IdentifierStage};
    use crate::sqlite::order::Identifier;
    use axum::http::Method;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A NetBox answering from canned maps, never touching the network.
    #[derive(Default)]
    struct StubNetbox {
        addresses: HashMap<IpAddr, Vec<NetboxIp>>,
        objects: HashMap<u64, Map<String, Value>>,
        error: Option<String>,
        hang: bool,
        /// How many times the device/VM fallback was consulted, so a test can
        /// assert it was *not*.
        object_calls: AtomicUsize,
    }

    impl StubNetbox {
        fn with_address(mut self, ip: &str, objects: Vec<NetboxIp>) -> Self {
            self.addresses.insert(ip.parse().unwrap(), objects);
            self
        }

        fn with_object(mut self, id: u64, fields: Value) -> Self {
            self.objects.insert(id, fields.as_object().unwrap().clone());
            self
        }

        fn failing(error: &str) -> Self {
            Self {
                error: Some(error.to_string()),
                ..Self::default()
            }
        }

        fn hanging() -> Self {
            Self {
                hang: true,
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl NetboxApi for StubNetbox {
        async fn ip_addresses(&self, ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
            if self.hang {
                // Outlives any timeout the tests set.
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.addresses.get(&ip).cloned().unwrap_or_default())
        }

        async fn object_custom_fields(
            &self,
            reference: &AssignedRef,
        ) -> Result<Map<String, Value>, String> {
            self.object_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.objects.get(&reference.id).cloned().unwrap_or_default())
        }
    }

    /// An address object with a `dns_name` and nothing else.
    fn with_dns_name(dns_name: &str) -> NetboxIp {
        NetboxIp {
            dns_name: dns_name.to_string(),
            ..NetboxIp::default()
        }
    }

    /// An address object whose custom field lists `names`.
    fn with_field(names: Value) -> NetboxIp {
        NetboxIp {
            custom_fields: json!({ "acme_allowed_names": names })
                .as_object()
                .unwrap()
                .clone(),
            ..NetboxIp::default()
        }
    }

    /// An address object assigned to device `id`, carrying no names itself.
    fn assigned_to_device(id: u64) -> NetboxIp {
        NetboxIp {
            assigned: Some(AssignedRef {
                kind: AssignedKind::Device,
                id,
            }),
            ..NetboxIp::default()
        }
    }

    fn config() -> NetboxConfig {
        NetboxConfig {
            url: "https://netbox.example.com".to_string(),
            token: "t0ken".to_string(),
            ..NetboxConfig::default()
        }
    }

    fn filter(cfg: &NetboxConfig, api: StubNetbox) -> NetboxFilter {
        NetboxFilter::with_api(cfg, Arc::new(api)).unwrap()
    }

    use crate::testutil::identifiers as ids;

    async fn check_from(
        filter: &NetboxFilter,
        ip: Option<&str>,
        identifiers: &[Identifier],
    ) -> Result<(), FilterError> {
        filter
            .check_identifiers(&IdentifierContext {
                client_ip: ip.map(|ip| ip.parse().unwrap()),
                account_id: "acct-1",
                stage: IdentifierStage::NewOrder,
                identifiers,
            })
            .await
    }

    async fn check(filter: &NetboxFilter, identifiers: &[Identifier]) -> Result<(), FilterError> {
        check_from(filter, Some("10.0.0.5"), identifiers).await
    }

    fn assert_denied(error: FilterError, needle: &str) {
        match error {
            FilterError::Denied(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    fn assert_internal(error: FilterError, needle: &str) {
        match error {
            FilterError::Internal(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ------------------------------------------------------- the happy paths

    #[tokio::test]
    async fn the_address_dns_name_permits_that_name() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_custom_field_permits_its_names() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![with_field(json!(["www.example.com", "api.example.com"]))],
        );
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "api.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_custom_field_holding_a_single_string_is_accepted() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_field(json!("only.example.com"))]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "only.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn matching_ignores_case_and_a_trailing_dot() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_dns_name("Host.Example.COM.")]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "HOST.example.com.")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn several_address_objects_are_pooled() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![
                with_dns_name("a.example.com"),
                with_dns_name("b.example.com"),
            ],
        );
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "b.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn every_requested_name_must_be_permitted() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![with_field(json!(["a.example.com", "b.example.com"]))],
        );
        let filter = filter(&config(), api);

        check(
            &filter,
            &ids(&[("dns", "a.example.com"), ("dns", "b.example.com")]),
        )
        .await
        .unwrap();

        let error = check(
            &filter,
            &ids(&[("dns", "a.example.com"), ("dns", "c.example.com")]),
        )
        .await
        .unwrap_err();
        assert_denied(error, "c.example.com");
    }

    // ------------------------------------------------------------- refusals

    #[tokio::test]
    async fn an_unlisted_name_is_denied_naming_it_and_the_stage() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        let error = check(&filter, &ids(&[("dns", "evil.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "newOrder identifier evil.example.com");
    }

    #[tokio::test]
    async fn an_address_netbox_does_not_know_is_denied() {
        let filter = filter(&config(), StubNetbox::default());

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "no IP address object for 10.0.0.5");
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        let error = check_from(&filter, None, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "client address unavailable");
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_is_canonicalized_before_the_lookup() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        check_from(
            &filter,
            Some("::ffff:10.0.0.5"),
            &ids(&[("dns", "host.example.com")]),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn use_dns_name_off_ignores_the_address_dns_name() {
        let cfg = NetboxConfig {
            use_dns_name: false,
            ..config()
        };
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&cfg, api);

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "host.example.com");
    }

    // --------------------------------------------------- Internal, not Denied

    #[tokio::test]
    async fn a_failed_lookup_is_internal_not_a_denial() {
        let filter = filter(&config(), StubNetbox::failing("HTTP 500"));

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_internal(error, "HTTP 500");
    }

    #[tokio::test]
    async fn a_wedged_netbox_times_out_rather_than_hanging() {
        let cfg = NetboxConfig {
            timeout_ms: 10,
            ..config()
        };
        let filter = filter(&cfg, StubNetbox::hanging());

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_internal(error, "timed out after 10ms");
    }

    // ------------------------------------------------------ device/VM fallback

    #[tokio::test]
    async fn the_device_is_consulted_when_the_address_carries_no_names() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned_to_device(3)])
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "machine.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_device_is_not_consulted_when_the_address_answered() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    assigned: Some(AssignedRef {
                        kind: AssignedKind::Device,
                        id: 3,
                    }),
                    ..with_field(json!(["own.example.com"]))
                }],
            )
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));
        let api = Arc::new(api);
        let filter = NetboxFilter::with_api(&config(), api.clone()).unwrap();

        check(&filter, &ids(&[("dns", "own.example.com")]))
            .await
            .unwrap();
        assert_eq!(api.object_calls.load(Ordering::SeqCst), 0);

        // And the machine-wide list really is out of reach while it answers.
        let error = check(&filter, &ids(&[("dns", "machine.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "machine.example.com");
    }

    #[tokio::test]
    async fn a_dns_name_alone_does_not_suppress_the_fallback() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    dns_name: "host.example.com".to_string(),
                    assigned: Some(AssignedRef {
                        kind: AssignedKind::Device,
                        id: 3,
                    }),
                    ..NetboxIp::default()
                }],
            )
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));
        let filter = filter(&config(), api);

        // Both the address's own name and the machine's list apply.
        check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap();
        check(&filter, &ids(&[("dns", "machine.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn device_fallback_off_never_consults_the_device() {
        let cfg = NetboxConfig {
            device_fallback: false,
            ..config()
        };
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned_to_device(3)])
                .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] })),
        );
        let filter = NetboxFilter::with_api(&cfg, api.clone()).unwrap();

        let error = check(&filter, &ids(&[("dns", "machine.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "machine.example.com");
        assert_eq!(api.object_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_address_assigned_to_nothing_is_refused_cleanly() {
        let api = StubNetbox::default().with_address("10.0.0.5", vec![NetboxIp::default()]);
        let filter = filter(&config(), api);

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "host.example.com");
    }

    #[tokio::test]
    async fn a_failing_device_lookup_is_internal() {
        // The shared stub's `error` would fail the *address* lookup first, so
        // the fallback is driven by a stub that only fails the second call.
        struct FallbackFails;
        #[async_trait]
        impl NetboxApi for FallbackFails {
            async fn ip_addresses(&self, _ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
                Ok(vec![assigned_to_device(3)])
            }
            async fn object_custom_fields(
                &self,
                _reference: &AssignedRef,
            ) -> Result<Map<String, Value>, String> {
                Err("HTTP 403".to_string())
            }
        }
        let filter = NetboxFilter::with_api(&config(), Arc::new(FallbackFails)).unwrap();

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_internal(error, "HTTP 403");
    }

    // -------------------------------------------------------------- wildcards

    #[tokio::test]
    async fn a_wildcard_needs_the_literal_entry() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_field(json!(["example.com"]))]);
        let filter = filter(&config(), api);

        let error = check(&filter, &ids(&[("dns", "*.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "*.example.com");
    }

    #[tokio::test]
    async fn a_literal_wildcard_entry_permits_the_wildcard() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_field(json!(["*.example.com"]))]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "*.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_wildcard_entry_does_not_expand_to_subdomains() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_field(json!(["*.example.com"]))]);
        let filter = filter(&config(), api);

        let error = check(&filter, &ids(&[("dns", "a.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "a.example.com");
    }

    // ------------------------------------------------------ identifier types

    #[tokio::test]
    async fn the_connecting_address_may_always_be_certified() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("ip", "10.0.0.5")])).await.unwrap();
    }

    #[tokio::test]
    async fn another_address_is_denied_unless_listed() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        let error = check(&filter, &ids(&[("ip", "10.0.0.9")]))
            .await
            .unwrap_err();
        assert_denied(error, "10.0.0.9");
    }

    #[tokio::test]
    async fn another_address_may_be_listed_like_any_other_name() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_field(json!(["10.0.0.9"]))]);
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("ip", "10.0.0.9")])).await.unwrap();
    }

    #[tokio::test]
    async fn a_common_name_is_left_alone() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        check(
            &filter,
            &ids(&[
                ("dns", "host.example.com"),
                ("cn", "rcgen self signed cert"),
            ]),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_request_of_common_names_alone_asks_netbox_nothing() {
        // A failing stub proves no lookup happened: if one had, it would be
        // an Internal error rather than a pass.
        let filter = filter(&config(), StubNetbox::failing("must not be called"));

        check(&filter, &ids(&[("cn", "some label")])).await.unwrap();
    }

    #[tokio::test]
    async fn a_type_netbox_cannot_speak_to_is_denied() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let filter = filter(&config(), api);

        for typ in ["email", "uri", "other"] {
            let error = check(&filter, &ids(&[(typ, "whatever")]))
                .await
                .unwrap_err();
            assert_denied(error, &format!("requests a {typ} identifier"));
        }
    }

    // --------------------------------------------- malformed NetBox answers

    #[tokio::test]
    async fn a_custom_field_of_the_wrong_type_is_ignored_not_fatal() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![NetboxIp {
                dns_name: "host.example.com".to_string(),
                custom_fields: json!({ "acme_allowed_names": 42 })
                    .as_object()
                    .unwrap()
                    .clone(),
                assigned: None,
            }],
        );
        let filter = filter(&config(), api);

        // The dns_name still works; the unusable field simply contributes nothing.
        check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn non_string_entries_of_the_custom_field_are_skipped() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![with_field(json!(["ok.example.com", 7, null]))],
        );
        let filter = filter(&config(), api);

        check(&filter, &ids(&[("dns", "ok.example.com")]))
            .await
            .unwrap();
    }

    // ------------------------------------------------------ startup + wiring

    #[test]
    fn an_empty_custom_field_is_a_startup_error() {
        let cfg = NetboxConfig {
            custom_field: "   ".to_string(),
            ..config()
        };
        let error = NetboxFilter::with_api(&cfg, Arc::new(StubNetbox::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.netbox.custom_field"), "{error}");
    }

    #[test]
    fn reports_its_config_name() {
        let filter = filter(&config(), StubNetbox::default());
        assert_eq!(filter.name(), "netbox");
    }

    #[tokio::test]
    async fn does_not_inspect_connections() {
        let filter = filter(&config(), StubNetbox::failing("must not be called"));

        filter
            .check_connection(&ConnectionContext {
                client_ip: Some("203.0.113.9".parse().unwrap()),
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
            .unwrap();
    }

    #[test]
    fn the_debug_impl_shows_the_policy_without_the_api() {
        let rendered = format!("{:?}", filter(&config(), StubNetbox::default()));
        assert!(rendered.contains("acme_allowed_names"), "{rendered}");
        assert!(rendered.contains("device_fallback"), "{rendered}");
    }
}
