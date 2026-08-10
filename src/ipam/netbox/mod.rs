//! The `netbox` IPAM backend: what NetBox associates with an address.
//!
//! ## What NetBox is asked
//!
//! One lookup always happens: `GET /api/ipam/ip-addresses/?address=<client ip>`.
//! What it returns permits names two ways — the address object's own `dns_name`
//! ([`Source::DnsName`]) and a custom field on it ([`Source::CustomField`]),
//! by default `acme_allowed_names`.
//!
//! Three more lookups are conditional on [`Source`]s that are off by default,
//! because each widens what a client may certify:
//!
//! - [`Source::Device`] — when the address object carries no value for the
//!   custom field, read it from the device or virtual machine the address is
//!   assigned to, so names can be declared once per machine rather than once
//!   per address. A **fallback and not a union** on purpose: a value set on the
//!   address is the more specific statement, and an operator narrowing one
//!   address of a machine would be surprised to see the machine-wide list
//!   quietly widen it again. (This one is on by default — it predates the
//!   others and moving an existing deployment across must change nothing.)
//! - [`Source::Vip`] — the role-tagged service addresses of the same device,
//!   `?device_id=N&role=vip&role=vrrp…`. A **union**: a keepalived member's own
//!   names and the names on the VIP it answers for are both true at once.
//! - [`Source::Fhrp`] — the addresses of an FHRP group the client's **own
//!   interface** is recorded as a member of. Also a union.
//!
//! ## The FHRP path is a membership proof, and the direction is why
//!
//! A group is only ever reached *through an assignment naming the client's own
//! interface*:
//!
//! ```text
//! client address ─▶ its interface ─▶ fhrp-group-assignments?interface_id=…
//!                                          └─▶ group ids ─▶ their addresses
//! ```
//!
//! Nothing is ever looked up by group name, by the service address, or by the
//! identifier the client asked for. So there is no query that could reach a
//! group the client is not recorded in, and the check cannot be turned into a
//! lookup of "who owns this name?" by a client choosing its request carefully.
//! An interface in no group contributes nothing and costs one request.
//!
//! ## Denied versus Internal
//!
//! Every failure here is an [`IpamError`], which the filter reports as a 500
//! the client can retry: NetBox answering 500, refusing the token or timing out
//! is this server failing to reach a decision, never a statement about the
//! client. The only thing this backend says *about* the client is
//! [`AddressNames::Unknown`] — NetBox holds no object for the address at all.
//! See the [subsystem docs](super) for why that split is what stops it failing
//! open.

pub mod client;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::{debug, info, warn};

use super::{AddressNames, Ipam, IpamError, Source, Sources, field_values, parse_sources};
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

impl AssignedKind {
    /// The `?…_id=` filter naming this object on the addresses endpoint.
    fn owner_filter(self) -> &'static str {
        match self {
            Self::Device => "device_id",
            Self::VirtualMachine => "virtual_machine_id",
        }
    }

    /// NetBox's content-type label for the interface an address hangs off.
    fn interface_type(self) -> &'static str {
        match self {
            Self::Device => client::DEVICE_INTERFACE,
            Self::VirtualMachine => client::VM_INTERFACE,
        }
    }
}

/// The machine an address is assigned to, and the interface it hangs off.
///
/// Both halves are needed and both come from the *same* list response, so
/// learning them costs no extra request: the device answers "what else is on
/// this box?" ([`Source::Device`], [`Source::Vip`]) and the interface answers
/// "which redundancy groups is this client in?" ([`Source::Fhrp`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedRef {
    pub kind: AssignedKind,
    /// The device or virtual machine.
    pub id: u64,
    /// The interface the address is configured on.
    pub interface_id: u64,
}

/// One NetBox `ipam/ip-addresses` object, reduced to what this backend reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetboxIp {
    /// The object's `dns_name`, empty when unset.
    pub dns_name: String,
    /// The object's custom fields, as NetBox returned them.
    pub custom_fields: Map<String, Value>,
    /// The device or VM behind the assigned interface, when there is one.
    pub assigned: Option<AssignedRef>,
    /// The object's `role`, e.g. `vrrp`. `None` for an ordinary address.
    pub role: Option<String>,
}

/// The NetBox queries this backend makes.
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

    /// The addresses of the same machine carrying one of `roles`.
    async fn shared_addresses(
        &self,
        reference: &AssignedRef,
        roles: &[String],
    ) -> Result<Vec<NetboxIp>, String>;

    /// The FHRP groups this **interface** is recorded as a member of.
    async fn fhrp_groups(&self, reference: &AssignedRef) -> Result<Vec<u64>, String>;

    /// The addresses assigned to those groups, in one query.
    async fn fhrp_group_addresses(&self, group_ids: &[u64]) -> Result<Vec<NetboxIp>, String>;
}

/// Reports which names NetBox associates with an address.
pub struct NetboxBackend {
    api: Arc<dyn NetboxApi>,
    custom_field: String,
    sources: Sources,
    vip_roles: Vec<String>,
}

impl std::fmt::Debug for NetboxBackend {
    /// `dyn NetboxApi` is not `Debug`; the policy is the interesting part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetboxBackend")
            .field("custom_field", &self.custom_field)
            .field("sources", &self.sources)
            .field("vip_roles", &self.vip_roles)
            .finish_non_exhaustive()
    }
}

/// Every source NetBox can answer for — which is all of them.
const SUPPORTED: &[Source] = &[
    Source::DnsName,
    Source::CustomField,
    Source::Device,
    Source::Vip,
    Source::Fhrp,
];

impl NetboxBackend {
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
        let backend = Self::with_api(cfg, api)?;

        info!(
            event = "ipam_netbox_loaded",
            url = %cfg.url,
            custom_field = %cfg.custom_field,
            sources = ?backend.sources,
            vip_roles = ?cfg.vip_roles,
        );

        // Unconditional, and deliberately not once-only: this is a temporary
        // operational state (an expired NetBox certificate being waited out),
        // and it should stay visible in the log for as long as it lasts. The
        // counterpart of `tls_disabled` and `challenge_validation_bypassed`.
        if cfg.insecure_skip_verify {
            warn!(
                event = "ipam_netbox_tls_verification_disabled",
                url = %cfg.url,
                "ipam.netbox.insecure_skip_verify is on: NetBox's TLS certificate is not \
                 verified, so the answers this server trusts could come from anyone able to \
                 intercept the connection (ipam.netbox.ca_cert_path is ignored while it is set)"
            );
        }

        Ok(backend)
    }

    /// Same, against a caller-supplied API. Used by tests.
    pub fn with_api(cfg: &NetboxConfig, api: Arc<dyn NetboxApi>) -> anyhow::Result<Self> {
        let sources = parse_sources("NetBox", "ipam.netbox.sources", &cfg.sources, SUPPORTED)?;

        // Only checked when something would read it: an operator who trusts
        // only `dns_name` has no custom field to name, and demanding one would
        // be a rule with no purpose behind it.
        if sources.contains(&Source::CustomField) || sources.contains(&Source::Device) {
            anyhow::ensure!(
                !cfg.custom_field.trim().is_empty(),
                "ipam.netbox.custom_field is empty while ipam.netbox.sources names \
                 `custom_field` or `device`; name the NetBox custom field holding the \
                 permitted names (default `acme_allowed_names`)"
            );
        }
        if sources.contains(&Source::Vip) {
            anyhow::ensure!(
                !cfg.vip_roles.is_empty(),
                "ipam.netbox.vip_roles is empty while ipam.netbox.sources names `vip`; \
                 list the NetBox address roles that mark a service address (e.g. `vrrp`), \
                 or drop `vip` from ipam.netbox.sources"
            );
        }

        Ok(Self {
            api,
            custom_field: cfg.custom_field.clone(),
            sources,
            vip_roles: cfg.vip_roles.clone(),
        })
    }

    /// Adds one address object's own names, and reports whether its custom
    /// field said anything.
    ///
    /// The return value is what decides the [`Source::Device`] fallback, and it
    /// is tracked separately from `names` being non-empty because a `dns_name`
    /// fills that too and must not suppress the fallback.
    fn add_object_names(&self, names: &mut AddressNames, object: &NetboxIp, source: &str) -> bool {
        if self.sources.contains(&Source::DnsName) {
            names.insert(&object.dns_name);
        }

        if !self.sources.contains(&Source::CustomField) {
            return false;
        }

        let values = field_values(&object.custom_fields, &self.custom_field, "NetBox", source);
        let answered = !values.is_empty();
        for value in values {
            names.insert(&value);
        }
        answered
    }

    /// The device or VM's custom field, when the address itself was silent.
    async fn add_device_names(
        &self,
        names: &mut AddressNames,
        reference: &AssignedRef,
        client_ip: IpAddr,
    ) -> Result<(), IpamError> {
        let fields = self
            .api
            .object_custom_fields(reference)
            .await
            .map_err(|error| {
                IpamError(format!(
                    "NetBox lookup of {:?} {} for {client_ip} failed: {error}",
                    reference.kind, reference.id
                ))
            })?;
        for value in field_values(&fields, &self.custom_field, "NetBox", "assigned object") {
            names.insert(&value);
        }
        Ok(())
    }

    /// The role-tagged service addresses of the same machine.
    async fn add_vip_names(
        &self,
        names: &mut AddressNames,
        reference: &AssignedRef,
        client_ip: IpAddr,
    ) -> Result<(), IpamError> {
        let objects = self
            .api
            .shared_addresses(reference, &self.vip_roles)
            .await
            .map_err(|error| {
                IpamError(format!(
                    "NetBox lookup of service addresses on {:?} {} for {client_ip} failed: \
                     {error}",
                    reference.kind, reference.id
                ))
            })?;

        for object in &objects {
            // Re-checked here as well as in the query. NetBox refuses an
            // unknown `role` choice outright, but a filter parameter this
            // server got wrong must never degrade to "every address on the
            // device" — that would widen an allowlist without saying so, which
            // is precisely the failure an allowlist exists to prevent.
            let permitted = object
                .role
                .as_deref()
                .is_some_and(|role| self.vip_roles.iter().any(|wanted| wanted == role));
            if !permitted {
                debug!(
                    event = "ipam_netbox_vip_role_ignored",
                    role = object.role.as_deref().unwrap_or(""),
                    "service address does not carry a configured role"
                );
                continue;
            }
            self.add_object_names(names, object, "service address");
        }
        Ok(())
    }

    /// The addresses of every FHRP group the client's interface belongs to.
    async fn add_fhrp_names(
        &self,
        names: &mut AddressNames,
        reference: &AssignedRef,
        client_ip: IpAddr,
    ) -> Result<(), IpamError> {
        let groups = self.api.fhrp_groups(reference).await.map_err(|error| {
            IpamError(format!(
                "NetBox lookup of FHRP group membership for interface {} ({client_ip}) failed: \
                 {error}",
                reference.interface_id
            ))
        })?;

        // An interface in no group contributes nothing, and the second query is
        // not made at all — this is the ordinary case for most of an estate.
        if groups.is_empty() {
            debug!(
                event = "ipam_netbox_fhrp_no_membership",
                interface_id = reference.interface_id,
            );
            return Ok(());
        }

        let objects = self
            .api
            .fhrp_group_addresses(&groups)
            .await
            .map_err(|error| {
                IpamError(format!(
                    "NetBox lookup of FHRP group addresses for {client_ip} failed: {error}"
                ))
            })?;

        for object in &objects {
            self.add_object_names(names, object, "FHRP group address");
        }
        Ok(())
    }
}

#[async_trait]
impl Ipam for NetboxBackend {
    fn name(&self) -> &'static str {
        "NetBox"
    }

    async fn names_for(&self, client_ip: IpAddr) -> Result<AddressNames, IpamError> {
        let objects =
            self.api.ip_addresses(client_ip).await.map_err(|error| {
                IpamError(format!("NetBox lookup for {client_ip} failed: {error}"))
            })?;

        if objects.is_empty() {
            return Ok(AddressNames::Unknown);
        }

        let mut names = AddressNames::known();
        let mut custom_field_answered = false;
        let mut assigned = None;

        for object in &objects {
            custom_field_answered |= self.add_object_names(&mut names, object, "IP address object");
            if assigned.is_none() {
                assigned.clone_from(&object.assigned);
            }
        }

        let Some(reference) = assigned else {
            // Nothing to scope the three machine-shaped lookups to.
            return Ok(names);
        };

        // A fallback: skipped entirely when the address spoke for itself. With
        // `custom_field` not among the sources nothing was read from the
        // address, so there is nothing to fall back *from* and the machine's
        // list always applies.
        if self.sources.contains(&Source::Device) && !custom_field_answered {
            self.add_device_names(&mut names, &reference, client_ip)
                .await?;
        }

        // Unions, both of them: unlike the fallback above, neither is gated on
        // what the address itself said. A member address's own names and the
        // names on the service address it answers for are both true at once.
        if self.sources.contains(&Source::Vip) {
            self.add_vip_names(&mut names, &reference, client_ip)
                .await?;
        }
        if self.sources.contains(&Source::Fhrp) {
            self.add_fhrp_names(&mut names, &reference, client_ip)
                .await?;
        }

        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ------------------------------------------------------------- the stub

    /// A NetBox answering from canned maps, never touching the network.
    #[derive(Default)]
    struct StubNetbox {
        addresses: HashMap<IpAddr, Vec<NetboxIp>>,
        objects: HashMap<u64, Map<String, Value>>,
        /// Service addresses keyed by the device/VM id they sit on.
        shared: HashMap<u64, Vec<NetboxIp>>,
        /// FHRP group ids keyed by the interface recorded as a member.
        memberships: HashMap<u64, Vec<u64>>,
        /// Addresses keyed by the FHRP group they are assigned to.
        group_addresses: HashMap<u64, Vec<NetboxIp>>,
        error: Option<String>,
        /// One counter per conditional lookup, so a test can assert a query was
        /// *not* made — which is what "this source is off" actually means.
        object_calls: AtomicUsize,
        shared_calls: AtomicUsize,
        membership_calls: AtomicUsize,
        group_address_calls: AtomicUsize,
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

        fn with_shared(mut self, device_id: u64, objects: Vec<NetboxIp>) -> Self {
            self.shared.insert(device_id, objects);
            self
        }

        fn with_membership(mut self, interface_id: u64, groups: Vec<u64>) -> Self {
            self.memberships.insert(interface_id, groups);
            self
        }

        fn with_group_address(mut self, group_id: u64, objects: Vec<NetboxIp>) -> Self {
            self.group_addresses.insert(group_id, objects);
            self
        }

        fn failing(error: &str) -> Self {
            Self {
                error: Some(error.to_string()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl NetboxApi for StubNetbox {
        async fn ip_addresses(&self, ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
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
            Ok(self.objects.get(&reference.id).cloned().unwrap_or_default())
        }

        async fn shared_addresses(
            &self,
            reference: &AssignedRef,
            _roles: &[String],
        ) -> Result<Vec<NetboxIp>, String> {
            self.shared_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.shared.get(&reference.id).cloned().unwrap_or_default())
        }

        async fn fhrp_groups(&self, reference: &AssignedRef) -> Result<Vec<u64>, String> {
            self.membership_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .memberships
                .get(&reference.interface_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn fhrp_group_addresses(&self, group_ids: &[u64]) -> Result<Vec<NetboxIp>, String> {
            self.group_address_calls.fetch_add(1, Ordering::SeqCst);
            Ok(group_ids
                .iter()
                .filter_map(|id| self.group_addresses.get(id))
                .flatten()
                .cloned()
                .collect())
        }
    }

    // ------------------------------------------------------------- fixtures

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

    /// Device 3, interface 7 — the machine every fixture here sits on.
    fn on_device() -> AssignedRef {
        AssignedRef {
            kind: AssignedKind::Device,
            id: 3,
            interface_id: 7,
        }
    }

    /// An address object assigned to device 3, carrying no names itself.
    fn assigned() -> NetboxIp {
        NetboxIp {
            assigned: Some(on_device()),
            ..NetboxIp::default()
        }
    }

    /// A service address with a role and a `dns_name`.
    fn service(role: &str, dns_name: &str) -> NetboxIp {
        NetboxIp {
            dns_name: dns_name.to_string(),
            role: Some(role.to_string()),
            ..NetboxIp::default()
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    fn config() -> NetboxConfig {
        NetboxConfig {
            url: "https://netbox.example.com".to_string(),
            token: "t0ken".to_string(),
            ..NetboxConfig::default()
        }
    }

    fn with_sources(sources: &[&str]) -> NetboxConfig {
        NetboxConfig {
            sources: strings(sources),
            ..config()
        }
    }

    fn backend(cfg: &NetboxConfig, api: StubNetbox) -> NetboxBackend {
        NetboxBackend::with_api(cfg, Arc::new(api)).unwrap()
    }

    /// Every name the backend reports for the usual client address.
    async fn names(backend: &NetboxBackend) -> AddressNames {
        backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap()
    }

    fn assert_permits(names: &AddressNames, name: &str) {
        assert!(
            names.names().contains(name),
            "{:?} lacks {name:?}",
            names.names()
        );
    }

    fn assert_refuses(names: &AddressNames, name: &str) {
        assert!(
            !names.names().contains(name),
            "{:?} unexpectedly holds {name:?}",
            names.names()
        );
    }

    // ------------------------------------------------------- the happy paths

    #[tokio::test]
    async fn the_address_dns_name_permits_that_name() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);

        assert_permits(&names(&backend(&config(), api)).await, "host.example.com");
    }

    #[tokio::test]
    async fn the_custom_field_permits_its_names() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![with_field(json!(["www.example.com", "api.example.com"]))],
        );

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "www.example.com");
        assert_permits(&names, "api.example.com");
    }

    #[tokio::test]
    async fn a_custom_field_holding_a_single_string_is_accepted() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_field(json!("only.example.com"))]);

        assert_permits(&names(&backend(&config(), api)).await, "only.example.com");
    }

    #[tokio::test]
    async fn names_are_normalized_on_the_way_in() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![with_dns_name("Host.Example.COM.")]);

        assert_permits(&names(&backend(&config(), api)).await, "host.example.com");
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

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "a.example.com");
        assert_permits(&names, "b.example.com");
    }

    // ------------------------------------------------------------- refusals

    /// The distinction the whole [`AddressNames`] enum exists for: an address
    /// NetBox has never heard of is not the same as one recorded and entitled
    /// to nothing, and the filter words the two refusals differently.
    #[tokio::test]
    async fn an_address_netbox_does_not_know_is_unknown() {
        let names = names(&backend(&config(), StubNetbox::default())).await;
        assert_eq!(names, AddressNames::Unknown);
    }

    #[tokio::test]
    async fn a_recorded_address_with_no_names_is_known_and_empty() {
        let api = StubNetbox::default().with_address("10.0.0.5", vec![NetboxIp::default()]);

        let names = names(&backend(&config(), api)).await;
        assert!(names.is_known());
        assert!(names.names().is_empty());
    }

    #[tokio::test]
    async fn a_failed_lookup_is_an_error_not_an_empty_answer() {
        let backend = backend(&config(), StubNetbox::failing("HTTP 500"));

        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 500"), "{error}");
    }

    // ------------------------------------------------------ the sources gate

    #[tokio::test]
    async fn dropping_dns_name_ignores_the_address_dns_name() {
        let api =
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]);
        let cfg = with_sources(&["custom_field", "device"]);

        assert_refuses(&names(&backend(&cfg, api)).await, "host.example.com");
    }

    #[tokio::test]
    async fn dropping_custom_field_ignores_it() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![NetboxIp {
                dns_name: "host.example.com".to_string(),
                ..with_field(json!(["www.example.com"]))
            }],
        );
        let cfg = with_sources(&["dns_name"]);

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "host.example.com");
        assert_refuses(&names, "www.example.com");
    }

    // ------------------------------------------------------ device fallback

    #[tokio::test]
    async fn the_device_is_consulted_when_the_address_carries_no_names() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));

        assert_permits(
            &names(&backend(&config(), api)).await,
            "machine.example.com",
        );
    }

    #[tokio::test]
    async fn the_device_is_not_consulted_when_the_address_answered() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address(
                    "10.0.0.5",
                    vec![NetboxIp {
                        assigned: Some(on_device()),
                        ..with_field(json!(["own.example.com"]))
                    }],
                )
                .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] })),
        );
        let backend = NetboxBackend::with_api(&config(), api.clone()).unwrap();

        let names = names(&backend).await;
        assert_permits(&names, "own.example.com");
        // The machine-wide list really is out of reach while the address speaks.
        assert_refuses(&names, "machine.example.com");
        assert_eq!(api.object_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_dns_name_alone_does_not_suppress_the_fallback() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    dns_name: "host.example.com".to_string(),
                    assigned: Some(on_device()),
                    ..NetboxIp::default()
                }],
            )
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "host.example.com");
        assert_permits(&names, "machine.example.com");
    }

    #[tokio::test]
    async fn dropping_device_never_consults_it() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned()])
                .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] })),
        );
        let cfg = with_sources(&["dns_name", "custom_field"]);
        let backend = NetboxBackend::with_api(&cfg, api.clone()).unwrap();

        assert_refuses(&names(&backend).await, "machine.example.com");
        assert_eq!(api.object_calls.load(Ordering::SeqCst), 0);
    }

    /// With `custom_field` out of the sources nothing is read from the address,
    /// so there is nothing to fall back *from* and the machine's list always
    /// applies.
    #[tokio::test]
    async fn device_without_custom_field_always_applies() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    assigned: Some(on_device()),
                    ..with_field(json!(["own.example.com"]))
                }],
            )
            .with_object(3, json!({ "acme_allowed_names": ["machine.example.com"] }));
        let cfg = with_sources(&["dns_name", "device"]);

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "machine.example.com");
        assert_refuses(&names, "own.example.com");
    }

    #[tokio::test]
    async fn an_address_assigned_to_nothing_makes_no_further_query() {
        let api = Arc::new(
            StubNetbox::default().with_address("10.0.0.5", vec![with_dns_name("host.example.com")]),
        );
        let cfg = with_sources(&["dns_name", "custom_field", "device", "vip", "fhrp"]);
        let backend = NetboxBackend::with_api(&cfg, api.clone()).unwrap();

        assert_permits(&names(&backend).await, "host.example.com");
        assert_eq!(api.object_calls.load(Ordering::SeqCst), 0);
        assert_eq!(api.shared_calls.load(Ordering::SeqCst), 0);
        assert_eq!(api.membership_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failing_device_lookup_is_an_error() {
        struct FallbackFails;
        #[async_trait]
        impl NetboxApi for FallbackFails {
            async fn ip_addresses(&self, _ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
                Ok(vec![NetboxIp {
                    assigned: Some(AssignedRef {
                        kind: AssignedKind::Device,
                        id: 3,
                        interface_id: 7,
                    }),
                    ..NetboxIp::default()
                }])
            }
            async fn object_custom_fields(
                &self,
                _reference: &AssignedRef,
            ) -> Result<Map<String, Value>, String> {
                Err("HTTP 403".to_string())
            }
            async fn shared_addresses(
                &self,
                _reference: &AssignedRef,
                _roles: &[String],
            ) -> Result<Vec<NetboxIp>, String> {
                unreachable!("the device lookup fails first")
            }
            async fn fhrp_groups(&self, _reference: &AssignedRef) -> Result<Vec<u64>, String> {
                unreachable!("the device lookup fails first")
            }
            async fn fhrp_group_addresses(
                &self,
                _group_ids: &[u64],
            ) -> Result<Vec<NetboxIp>, String> {
                unreachable!("the device lookup fails first")
            }
        }

        let backend = NetboxBackend::with_api(&config(), Arc::new(FallbackFails)).unwrap();
        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 403"), "{error}");
    }

    // ------------------------------------------------------------ vip source

    #[tokio::test]
    async fn a_service_address_on_the_same_device_lends_its_names() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_shared(3, vec![service("vrrp", "service.example.com")]);
        let cfg = with_sources(&["dns_name", "custom_field", "vip"]);

        assert_permits(&names(&backend(&cfg, api)).await, "service.example.com");
    }

    /// A union, not a fallback: unlike `device`, this fires even when the
    /// member address spoke for itself. Both statements are true at once.
    #[tokio::test]
    async fn the_vip_source_is_a_union_not_a_fallback() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    assigned: Some(on_device()),
                    ..with_field(json!(["own.example.com"]))
                }],
            )
            .with_shared(3, vec![service("vrrp", "service.example.com")]);
        let cfg = with_sources(&["dns_name", "custom_field", "vip"]);

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "own.example.com");
        assert_permits(&names, "service.example.com");
    }

    /// NetBox refuses an unknown role choice outright, but a wrong filter
    /// parameter must never degrade into "every address on this device".
    #[tokio::test]
    async fn a_service_address_of_another_role_is_dropped_client_side() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_shared(
                3,
                vec![
                    service("vrrp", "service.example.com"),
                    service("secondary", "other.example.com"),
                    // No role at all — an ordinary address the query should
                    // never have returned.
                    with_dns_name("plain.example.com"),
                ],
            );
        let cfg = NetboxConfig {
            vip_roles: strings(&["vrrp"]),
            ..with_sources(&["dns_name", "custom_field", "vip"])
        };

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "service.example.com");
        assert_refuses(&names, "other.example.com");
        assert_refuses(&names, "plain.example.com");
    }

    #[tokio::test]
    async fn dropping_vip_never_queries_service_addresses() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned()])
                .with_shared(3, vec![service("vrrp", "service.example.com")]),
        );
        let backend = NetboxBackend::with_api(&config(), api.clone()).unwrap();

        assert_refuses(&names(&backend).await, "service.example.com");
        assert_eq!(api.shared_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failing_service_address_lookup_is_an_error() {
        struct SharedFails;
        #[async_trait]
        impl NetboxApi for SharedFails {
            async fn ip_addresses(&self, _ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
                Ok(vec![NetboxIp {
                    assigned: Some(AssignedRef {
                        kind: AssignedKind::Device,
                        id: 3,
                        interface_id: 7,
                    }),
                    ..with_field(json!(["own.example.com"]))
                }])
            }
            async fn object_custom_fields(
                &self,
                _reference: &AssignedRef,
            ) -> Result<Map<String, Value>, String> {
                unreachable!("the address answered")
            }
            async fn shared_addresses(
                &self,
                _reference: &AssignedRef,
                _roles: &[String],
            ) -> Result<Vec<NetboxIp>, String> {
                Err("HTTP 502".to_string())
            }
            async fn fhrp_groups(&self, _reference: &AssignedRef) -> Result<Vec<u64>, String> {
                unreachable!("the service address lookup fails first")
            }
            async fn fhrp_group_addresses(
                &self,
                _group_ids: &[u64],
            ) -> Result<Vec<NetboxIp>, String> {
                unreachable!("the service address lookup fails first")
            }
        }

        let cfg = with_sources(&["dns_name", "custom_field", "vip"]);
        let backend = NetboxBackend::with_api(&cfg, Arc::new(SharedFails)).unwrap();
        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 502"), "{error}");
    }

    // ----------------------------------------------------------- fhrp source

    #[tokio::test]
    async fn an_interface_in_a_group_may_certify_the_groups_service_name() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_membership(7, vec![41])
            .with_group_address(41, vec![with_dns_name("service.example.com")]);
        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);

        assert_permits(&names(&backend(&cfg, api)).await, "service.example.com");
    }

    /// The security property the whole source turns on. A group is reached only
    /// through an assignment naming *this* interface, so an interface recorded
    /// in no group cannot borrow anybody's service name — and the second query
    /// is never made.
    #[tokio::test]
    async fn an_interface_in_no_group_contributes_nothing() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned()])
                // Group 41 exists and holds the name, but interface 7 is not a
                // member of it — interface 99 is.
                .with_membership(99, vec![41])
                .with_group_address(41, vec![with_dns_name("service.example.com")]),
        );
        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);
        let backend = NetboxBackend::with_api(&cfg, api.clone()).unwrap();

        assert_refuses(&names(&backend).await, "service.example.com");
        assert_eq!(api.membership_calls.load(Ordering::SeqCst), 1);
        assert_eq!(api.group_address_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn several_groups_are_resolved_in_one_query() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned()])
                .with_membership(7, vec![41, 42])
                .with_group_address(41, vec![with_dns_name("one.example.com")])
                .with_group_address(42, vec![with_dns_name("two.example.com")]),
        );
        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);
        let backend = NetboxBackend::with_api(&cfg, api.clone()).unwrap();

        let names = names(&backend).await;
        assert_permits(&names, "one.example.com");
        assert_permits(&names, "two.example.com");
        assert_eq!(api.group_address_calls.load(Ordering::SeqCst), 1);
    }

    /// A group's addresses carry custom fields like any other address object,
    /// and no role filter applies here — an address assigned to a group *is*
    /// the group's service address by construction.
    #[tokio::test]
    async fn a_group_address_custom_field_counts_and_needs_no_role() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_membership(7, vec![41])
            .with_group_address(41, vec![with_field(json!(["service.example.com"]))]);
        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);

        assert_permits(&names(&backend(&cfg, api)).await, "service.example.com");
    }

    #[tokio::test]
    async fn the_fhrp_source_is_a_union_not_a_fallback() {
        let api = StubNetbox::default()
            .with_address(
                "10.0.0.5",
                vec![NetboxIp {
                    assigned: Some(on_device()),
                    ..with_field(json!(["own.example.com"]))
                }],
            )
            .with_membership(7, vec![41])
            .with_group_address(41, vec![with_dns_name("service.example.com")]);
        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "own.example.com");
        assert_permits(&names, "service.example.com");
    }

    #[tokio::test]
    async fn dropping_fhrp_never_queries_membership() {
        let api = Arc::new(
            StubNetbox::default()
                .with_address("10.0.0.5", vec![assigned()])
                .with_membership(7, vec![41])
                .with_group_address(41, vec![with_dns_name("service.example.com")]),
        );
        let backend = NetboxBackend::with_api(&config(), api.clone()).unwrap();

        assert_refuses(&names(&backend).await, "service.example.com");
        assert_eq!(api.membership_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn both_service_address_sources_union_without_conflict() {
        let api = StubNetbox::default()
            .with_address("10.0.0.5", vec![assigned()])
            .with_shared(3, vec![service("vrrp", "role.example.com")])
            .with_membership(7, vec![41])
            .with_group_address(41, vec![with_dns_name("group.example.com")]);
        let cfg = with_sources(&["dns_name", "custom_field", "device", "vip", "fhrp"]);

        let names = names(&backend(&cfg, api)).await;
        assert_permits(&names, "role.example.com");
        assert_permits(&names, "group.example.com");
    }

    #[tokio::test]
    async fn a_failing_membership_lookup_is_an_error() {
        struct MembershipFails;
        #[async_trait]
        impl NetboxApi for MembershipFails {
            async fn ip_addresses(&self, _ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
                Ok(vec![NetboxIp {
                    assigned: Some(AssignedRef {
                        kind: AssignedKind::Device,
                        id: 3,
                        interface_id: 7,
                    }),
                    ..with_field(json!(["own.example.com"]))
                }])
            }
            async fn object_custom_fields(
                &self,
                _reference: &AssignedRef,
            ) -> Result<Map<String, Value>, String> {
                unreachable!("the address answered")
            }
            async fn shared_addresses(
                &self,
                _reference: &AssignedRef,
                _roles: &[String],
            ) -> Result<Vec<NetboxIp>, String> {
                unreachable!("vip is not among the sources")
            }
            async fn fhrp_groups(&self, _reference: &AssignedRef) -> Result<Vec<u64>, String> {
                Err("HTTP 500".to_string())
            }
            async fn fhrp_group_addresses(
                &self,
                _group_ids: &[u64],
            ) -> Result<Vec<NetboxIp>, String> {
                unreachable!("the membership lookup fails first")
            }
        }

        let cfg = with_sources(&["dns_name", "custom_field", "fhrp"]);
        let backend = NetboxBackend::with_api(&cfg, Arc::new(MembershipFails)).unwrap();
        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 500"), "{error}");
        assert!(error.0.contains("interface 7"), "{error}");
    }

    // ------------------------------------------- malformed NetBox answers

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
                ..NetboxIp::default()
            }],
        );

        // The dns_name still works; the unusable field contributes nothing.
        assert_permits(&names(&backend(&config(), api)).await, "host.example.com");
    }

    #[tokio::test]
    async fn non_string_entries_of_the_custom_field_are_skipped() {
        let api = StubNetbox::default().with_address(
            "10.0.0.5",
            vec![with_field(json!(["ok.example.com", 7, null]))],
        );

        assert_permits(&names(&backend(&config(), api)).await, "ok.example.com");
    }

    // ------------------------------------------------------ startup + wiring

    #[test]
    fn an_empty_custom_field_is_a_startup_error_when_something_reads_it() {
        let cfg = NetboxConfig {
            custom_field: "   ".to_string(),
            ..config()
        };
        let error = NetboxBackend::with_api(&cfg, Arc::new(StubNetbox::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.custom_field"), "{error}");
    }

    /// …and not otherwise: an operator trusting only `dns_name` has no custom
    /// field to name, and a rule with no purpose behind it is noise.
    #[test]
    fn an_empty_custom_field_is_fine_when_nothing_reads_it() {
        let cfg = NetboxConfig {
            custom_field: String::new(),
            ..with_sources(&["dns_name"])
        };
        NetboxBackend::with_api(&cfg, Arc::new(StubNetbox::default()))
            .expect("no source reads the custom field");
    }

    #[test]
    fn vip_without_roles_is_a_startup_error() {
        let cfg = NetboxConfig {
            vip_roles: Vec::new(),
            ..with_sources(&["dns_name", "vip"])
        };
        let error = NetboxBackend::with_api(&cfg, Arc::new(StubNetbox::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.vip_roles"), "{error}");
    }

    #[test]
    fn an_unknown_source_is_a_startup_error() {
        let cfg = with_sources(&["dns_name", "hostname"]);
        let error = NetboxBackend::with_api(&cfg, Arc::new(StubNetbox::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown source `hostname`"), "{error}");
    }

    #[test]
    fn reports_the_product_name() {
        assert_eq!(backend(&config(), StubNetbox::default()).name(), "NetBox");
    }

    #[test]
    fn the_debug_impl_shows_the_policy_without_the_api() {
        let rendered = format!("{:?}", backend(&config(), StubNetbox::default()));
        assert!(rendered.contains("acme_allowed_names"), "{rendered}");
        assert!(rendered.contains("Device"), "{rendered}");
    }

    #[test]
    fn the_default_sources_are_what_the_filter_always_did() {
        let backend = backend(&config(), StubNetbox::default());
        assert!(backend.sources.contains(&Source::DnsName));
        assert!(backend.sources.contains(&Source::CustomField));
        assert!(backend.sources.contains(&Source::Device));
        assert!(!backend.sources.contains(&Source::Vip));
        assert!(!backend.sources.contains(&Source::Fhrp));
    }
}
