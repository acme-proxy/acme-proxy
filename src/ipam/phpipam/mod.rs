//! The `phpipam` IPAM backend: what phpIPAM associates with an address.
//!
//! The second inventory, and the one that shows the [`Ipam`] seam is not NetBox
//! with extra steps. It answers the same question by a different route, with a
//! different auth scheme, a different response envelope and a different idea of
//! what "no such address" looks like on the wire.
//!
//! ## What phpIPAM is asked
//!
//! One lookup always happens:
//! `GET /api/<app_id>/addresses/search/<client ip>/`. What it returns permits
//! names two ways — the address's `hostname` ([`Source::DnsName`], the direct
//! analogue of NetBox's `dns_name`) and a custom column on it
//! ([`Source::CustomField`]).
//!
//! One more is conditional: [`Source::Device`] follows the address's `deviceId`
//! to `GET /api/<app_id>/devices/<id>/` and reads the same column there. Like
//! NetBox's, it is a **fallback and not a union** — a value on the address is
//! the more specific statement.
//!
//! [`Source::Vip`] and [`Source::Fhrp`] are **refused by name at startup**:
//! phpIPAM records no address roles and no redundancy groups, so there is
//! nothing here to read. Ignoring them silently would leave an operator
//! believing a check runs that never runs.
//!
//! ## A 404 is an answer, not a failure
//!
//! The one place phpIPAM's wire behaviour differs in a way this code has to
//! know about. NetBox answers an unknown address with `200` and an empty result
//! list; phpIPAM answers `404` with `{"code":404,"message":"No addresses
//! found"}`. Reading that as a transport failure would turn every request from
//! an unrecorded machine into a retryable 500 instead of the refusal it is —
//! which is why [`JsonApiError`](crate::ipam::http::JsonApiError) carries the
//! status at all.
//!
//! ## Multi-valued custom fields
//!
//! A phpIPAM custom field is a plain text column, so several names are written
//! as one comma-separated string and split here. Hardcoded rather than
//! configurable: a comma is not legal in a DNS name, so there is no estate the
//! separator could need to differ for.

pub mod client;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::{info, warn};

use super::{AddressNames, Ipam, IpamError, Source, Sources, field_values, parse_sources};
use crate::config::PhpIpamConfig;

/// One phpIPAM address object, reduced to what this backend reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpIpamAddress {
    /// The address's `hostname`, empty when unset.
    pub hostname: String,
    /// Every column phpIPAM returned, custom ones included — they are plain
    /// top-level members rather than a nested object as in NetBox.
    pub fields: Map<String, Value>,
    /// The device this address is assigned to, when there is one.
    pub device_id: Option<u64>,
}

/// The phpIPAM queries this backend makes.
///
/// A trait so the policy above can be tested without a phpIPAM, the same seam
/// [`NetboxApi`](crate::ipam::netbox::NetboxApi) is. `Ok(None)` from
/// [`Self::search`] is the 404 case: an answer, not a failure.
#[async_trait]
pub trait PhpIpamApi: Send + Sync {
    /// The address objects phpIPAM holds for this address, or `None` when it
    /// holds no record of it at all.
    async fn search(&self, ip: IpAddr) -> Result<Option<Vec<PhpIpamAddress>>, String>;

    /// One device's columns.
    async fn device(&self, id: u64) -> Result<Map<String, Value>, String>;
}

/// Reports which names phpIPAM associates with an address.
pub struct PhpIpamBackend {
    api: Arc<dyn PhpIpamApi>,
    custom_field: String,
    sources: Sources,
}

impl std::fmt::Debug for PhpIpamBackend {
    /// `dyn PhpIpamApi` is not `Debug`; the policy is the interesting part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpIpamBackend")
            .field("custom_field", &self.custom_field)
            .field("sources", &self.sources)
            .finish_non_exhaustive()
    }
}

/// phpIPAM records no roles and no redundancy groups, so `vip` and `fhrp` are
/// absent here and refused by name.
const SUPPORTED: &[Source] = &[Source::DnsName, Source::CustomField, Source::Device];

impl PhpIpamBackend {
    /// Builds the real phpIPAM client, then delegates. Contacts nothing.
    pub fn from_config(
        cfg: &PhpIpamConfig,
        outbound: crate::http_client::Outbound,
    ) -> anyhow::Result<Self> {
        let api = Arc::new(client::PhpIpamClient::new(cfg, outbound)?);
        let backend = Self::with_api(cfg, api)?;

        info!(
            event = "ipam_phpipam_loaded",
            outcome = "success",
            backend_url = %cfg.url,
            app_id = %cfg.app_id,
            custom_field = %cfg.custom_field,
            sources = ?backend.sources,
        );

        // Unconditional and deliberately not once-only, the
        // `ipam_netbox_tls_verification_disabled` treatment.
        if cfg.insecure_skip_verify {
            warn!(
                event = "ipam_phpipam_tls_verification_disabled",
                outcome = "advisory",
                backend_url = %cfg.url,
                "ipam.phpipam.insecure_skip_verify is on: phpIPAM's TLS certificate is not \
                 verified, so the answers this server trusts could come from anyone able to \
                 intercept the connection (ipam.phpipam.ca_cert_path is ignored while it is set)"
            );
        }

        Ok(backend)
    }

    /// Same, against a caller-supplied API. Used by tests.
    pub fn with_api(cfg: &PhpIpamConfig, api: Arc<dyn PhpIpamApi>) -> anyhow::Result<Self> {
        let sources = parse_sources("phpIPAM", "ipam.phpipam.sources", &cfg.sources, SUPPORTED)?;

        if sources.contains(&Source::CustomField) || sources.contains(&Source::Device) {
            anyhow::ensure!(
                !cfg.custom_field.trim().is_empty(),
                "ipam.phpipam.custom_field is empty while ipam.phpipam.sources names \
                 `custom_field` or `device`; name the phpIPAM column holding the permitted \
                 names (default `custom_acme_allowed_names`)"
            );
        }

        Ok(Self {
            api,
            custom_field: cfg.custom_field.clone(),
            sources,
        })
    }

    /// The custom column's entries, split on commas.
    ///
    /// Goes through the shared [`field_values`] first, so a phpIPAM that ever
    /// starts returning a JSON array is read the same way NetBox's is; the
    /// split is what a text column needs on top of that.
    fn column_values(&self, fields: &Map<String, Value>, source: &str) -> Vec<String> {
        field_values(fields, &self.custom_field, "phpIPAM", source)
            .iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Adds one address object's own names, and reports whether its custom
    /// column said anything — which is what decides the device fallback.
    fn add_object_names(
        &self,
        names: &mut AddressNames,
        fields: &Map<String, Value>,
        hostname: &str,
        source: &str,
    ) -> bool {
        if self.sources.contains(&Source::DnsName) {
            names.insert(hostname);
        }

        if !self.sources.contains(&Source::CustomField) {
            return false;
        }

        let values = self.column_values(fields, source);
        let answered = !values.is_empty();
        for value in values {
            names.insert(&value);
        }
        answered
    }
}

#[async_trait]
impl Ipam for PhpIpamBackend {
    fn name(&self) -> &'static str {
        "phpIPAM"
    }

    async fn names_for(&self, client_ip: IpAddr) -> Result<AddressNames, IpamError> {
        let found = self.api.search(client_ip).await.map_err(|error| {
            IpamError(format!("phpIPAM lookup for {client_ip} failed: {error}"))
        })?;

        // `None` is phpIPAM's 404 — a fact about the address, not a failure to
        // look it up. An empty list means the same thing and is treated alike.
        let Some(objects) = found.filter(|objects| !objects.is_empty()) else {
            return Ok(AddressNames::Unknown);
        };

        let mut names = AddressNames::known();
        let mut custom_field_answered = false;
        let mut device_id = None;

        for object in &objects {
            custom_field_answered |=
                self.add_object_names(&mut names, &object.fields, &object.hostname, "address");
            if device_id.is_none() {
                device_id = object.device_id;
            }
        }

        // A fallback: skipped entirely when the address spoke for itself. With
        // `custom_field` not among the sources nothing was read from the
        // address, so there is nothing to fall back *from* and the device's
        // list always applies.
        if let Some(id) = device_id
            && self.sources.contains(&Source::Device)
            && !custom_field_answered
        {
            let fields = self.api.device(id).await.map_err(|error| {
                IpamError(format!(
                    "phpIPAM lookup of device {id} for {client_ip} failed: {error}"
                ))
            })?;
            for value in self.column_values(&fields, "device") {
                names.insert(&value);
            }
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

    /// A phpIPAM answering from canned maps, never touching the network.
    #[derive(Default)]
    struct StubPhpIpam {
        addresses: HashMap<IpAddr, Vec<PhpIpamAddress>>,
        devices: HashMap<u64, Map<String, Value>>,
        error: Option<String>,
        device_calls: AtomicUsize,
    }

    impl StubPhpIpam {
        fn with_address(mut self, ip: &str, objects: Vec<PhpIpamAddress>) -> Self {
            self.addresses.insert(ip.parse().unwrap(), objects);
            self
        }

        fn with_device(mut self, id: u64, fields: Value) -> Self {
            self.devices.insert(id, fields.as_object().unwrap().clone());
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
    impl PhpIpamApi for StubPhpIpam {
        async fn search(&self, ip: IpAddr) -> Result<Option<Vec<PhpIpamAddress>>, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.addresses.get(&ip).cloned())
        }

        async fn device(&self, id: u64) -> Result<Map<String, Value>, String> {
            self.device_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.devices.get(&id).cloned().unwrap_or_default())
        }
    }

    // ------------------------------------------------------------- fixtures

    fn with_hostname(hostname: &str) -> PhpIpamAddress {
        PhpIpamAddress {
            hostname: hostname.to_string(),
            ..PhpIpamAddress::default()
        }
    }

    fn with_column(value: Value) -> PhpIpamAddress {
        PhpIpamAddress {
            fields: json!({ "custom_acme_allowed_names": value })
                .as_object()
                .unwrap()
                .clone(),
            ..PhpIpamAddress::default()
        }
    }

    fn on_device(id: u64) -> PhpIpamAddress {
        PhpIpamAddress {
            device_id: Some(id),
            ..PhpIpamAddress::default()
        }
    }

    fn config() -> PhpIpamConfig {
        PhpIpamConfig {
            url: "https://ipam.example.com".to_string(),
            token: "t0ken".to_string(),
            ..PhpIpamConfig::default()
        }
    }

    fn with_sources(sources: &[&str]) -> PhpIpamConfig {
        PhpIpamConfig {
            sources: sources.iter().map(|v| (*v).to_string()).collect(),
            ..config()
        }
    }

    fn backend(cfg: &PhpIpamConfig, api: StubPhpIpam) -> PhpIpamBackend {
        PhpIpamBackend::with_api(cfg, Arc::new(api)).unwrap()
    }

    async fn names(backend: &PhpIpamBackend) -> AddressNames {
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
    async fn the_hostname_permits_that_name() {
        let api = StubPhpIpam::default()
            .with_address("10.0.0.5", vec![with_hostname("host.example.com")]);

        assert_permits(&names(&backend(&config(), api)).await, "host.example.com");
    }

    #[tokio::test]
    async fn the_custom_column_permits_its_names() {
        let api = StubPhpIpam::default()
            .with_address("10.0.0.5", vec![with_column(json!("www.example.com"))]);

        assert_permits(&names(&backend(&config(), api)).await, "www.example.com");
    }

    /// A phpIPAM custom field is a text column, so several names arrive as one
    /// comma-separated string.
    #[tokio::test]
    async fn a_comma_separated_column_yields_several_names() {
        let api = StubPhpIpam::default().with_address(
            "10.0.0.5",
            vec![with_column(json!(
                "www.example.com, api.example.com ,,mail.example.com"
            ))],
        );

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "www.example.com");
        assert_permits(&names, "api.example.com");
        assert_permits(&names, "mail.example.com");
        assert_eq!(names.names().len(), 3);
    }

    /// A phpIPAM that ever starts returning a JSON array is read the same way
    /// NetBox's is, because both go through the shared `field_values`.
    #[tokio::test]
    async fn a_column_holding_a_list_is_accepted_too() {
        let api = StubPhpIpam::default().with_address(
            "10.0.0.5",
            vec![with_column(json!(["a.example.com", "b.example.com"]))],
        );

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "a.example.com");
        assert_permits(&names, "b.example.com");
    }

    #[tokio::test]
    async fn names_are_normalized_on_the_way_in() {
        let api = StubPhpIpam::default()
            .with_address("10.0.0.5", vec![with_hostname("Host.Example.COM.")]);

        assert_permits(&names(&backend(&config(), api)).await, "host.example.com");
    }

    // ------------------------------------------------------------- refusals

    /// The 404 case, which is the one shape phpIPAM does differently from
    /// NetBox: a fact about the address, never a retryable failure.
    #[tokio::test]
    async fn an_address_phpipam_does_not_know_is_unknown() {
        let names = names(&backend(&config(), StubPhpIpam::default())).await;
        assert_eq!(names, AddressNames::Unknown);
    }

    /// An empty list means the same thing as a 404 and is treated alike.
    #[tokio::test]
    async fn an_empty_result_is_also_unknown() {
        let api = StubPhpIpam::default().with_address("10.0.0.5", Vec::new());

        assert_eq!(names(&backend(&config(), api)).await, AddressNames::Unknown);
    }

    #[tokio::test]
    async fn a_recorded_address_with_no_names_is_known_and_empty() {
        let api = StubPhpIpam::default().with_address("10.0.0.5", vec![PhpIpamAddress::default()]);

        let names = names(&backend(&config(), api)).await;
        assert!(names.is_known());
        assert!(names.names().is_empty());
    }

    #[tokio::test]
    async fn a_failed_lookup_is_an_error_not_an_empty_answer() {
        let backend = backend(&config(), StubPhpIpam::failing("HTTP 500"));

        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 500"), "{error}");
    }

    // ------------------------------------------------------ the sources gate

    #[tokio::test]
    async fn dropping_dns_name_ignores_the_hostname() {
        let api = StubPhpIpam::default()
            .with_address("10.0.0.5", vec![with_hostname("host.example.com")]);
        let cfg = with_sources(&["custom_field", "device"]);

        assert_refuses(&names(&backend(&cfg, api)).await, "host.example.com");
    }

    #[tokio::test]
    async fn dropping_custom_field_ignores_the_column() {
        let api = StubPhpIpam::default().with_address(
            "10.0.0.5",
            vec![PhpIpamAddress {
                hostname: "host.example.com".to_string(),
                ..with_column(json!("www.example.com"))
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
        let api = StubPhpIpam::default()
            .with_address("10.0.0.5", vec![on_device(3)])
            .with_device(
                3,
                json!({ "custom_acme_allowed_names": "machine.example.com" }),
            );

        assert_permits(
            &names(&backend(&config(), api)).await,
            "machine.example.com",
        );
    }

    #[tokio::test]
    async fn the_device_is_not_consulted_when_the_address_answered() {
        let api = Arc::new(
            StubPhpIpam::default()
                .with_address(
                    "10.0.0.5",
                    vec![PhpIpamAddress {
                        device_id: Some(3),
                        ..with_column(json!("own.example.com"))
                    }],
                )
                .with_device(
                    3,
                    json!({ "custom_acme_allowed_names": "machine.example.com" }),
                ),
        );
        let backend = PhpIpamBackend::with_api(&config(), api.clone()).unwrap();

        let names = names(&backend).await;
        assert_permits(&names, "own.example.com");
        assert_refuses(&names, "machine.example.com");
        assert_eq!(api.device_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_hostname_alone_does_not_suppress_the_fallback() {
        let api = StubPhpIpam::default()
            .with_address(
                "10.0.0.5",
                vec![PhpIpamAddress {
                    hostname: "host.example.com".to_string(),
                    device_id: Some(3),
                    ..PhpIpamAddress::default()
                }],
            )
            .with_device(
                3,
                json!({ "custom_acme_allowed_names": "machine.example.com" }),
            );

        let names = names(&backend(&config(), api)).await;
        assert_permits(&names, "host.example.com");
        assert_permits(&names, "machine.example.com");
    }

    #[tokio::test]
    async fn dropping_device_never_consults_it() {
        let api = Arc::new(
            StubPhpIpam::default()
                .with_address("10.0.0.5", vec![on_device(3)])
                .with_device(
                    3,
                    json!({ "custom_acme_allowed_names": "machine.example.com" }),
                ),
        );
        let cfg = with_sources(&["dns_name", "custom_field"]);
        let backend = PhpIpamBackend::with_api(&cfg, api.clone()).unwrap();

        assert_refuses(&names(&backend).await, "machine.example.com");
        assert_eq!(api.device_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_address_on_no_device_makes_no_further_query() {
        let api = Arc::new(
            StubPhpIpam::default()
                .with_address("10.0.0.5", vec![with_hostname("host.example.com")]),
        );
        let backend = PhpIpamBackend::with_api(&config(), api.clone()).unwrap();

        assert_permits(&names(&backend).await, "host.example.com");
        assert_eq!(api.device_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failing_device_lookup_is_an_error() {
        struct DeviceFails;
        #[async_trait]
        impl PhpIpamApi for DeviceFails {
            async fn search(&self, _ip: IpAddr) -> Result<Option<Vec<PhpIpamAddress>>, String> {
                Ok(Some(vec![PhpIpamAddress {
                    device_id: Some(3),
                    ..PhpIpamAddress::default()
                }]))
            }
            async fn device(&self, _id: u64) -> Result<Map<String, Value>, String> {
                Err("HTTP 403".to_string())
            }
        }

        let backend = PhpIpamBackend::with_api(&config(), Arc::new(DeviceFails)).unwrap();
        let error = backend
            .names_for("10.0.0.5".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.0.contains("HTTP 403"), "{error}");
        assert!(error.0.contains("device 3"), "{error}");
    }

    // ------------------------------------------------------ startup + wiring

    /// The refusal that proves the trait is not just NetBox with extra steps:
    /// a source this product cannot answer for is named, not ignored.
    #[test]
    fn a_netbox_only_source_is_refused_by_name() {
        for source in ["vip", "fhrp"] {
            let cfg = with_sources(&["dns_name", source]);
            let error = PhpIpamBackend::with_api(&cfg, Arc::new(StubPhpIpam::default()))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("`{source}` is not a source phpIPAM has")),
                "{error}"
            );
        }
    }

    #[test]
    fn an_empty_custom_field_is_a_startup_error_when_something_reads_it() {
        let cfg = PhpIpamConfig {
            custom_field: "   ".to_string(),
            ..config()
        };
        let error = PhpIpamBackend::with_api(&cfg, Arc::new(StubPhpIpam::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.phpipam.custom_field"), "{error}");
    }

    #[test]
    fn an_empty_custom_field_is_fine_when_nothing_reads_it() {
        let cfg = PhpIpamConfig {
            custom_field: String::new(),
            ..with_sources(&["dns_name"])
        };
        PhpIpamBackend::with_api(&cfg, Arc::new(StubPhpIpam::default()))
            .expect("no source reads the custom field");
    }

    #[test]
    fn an_empty_sources_list_is_a_startup_error() {
        let cfg = with_sources(&[]);
        let error = PhpIpamBackend::with_api(&cfg, Arc::new(StubPhpIpam::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.phpipam.sources is empty"), "{error}");
    }

    #[test]
    fn reports_the_product_name() {
        assert_eq!(backend(&config(), StubPhpIpam::default()).name(), "phpIPAM");
    }

    #[test]
    fn the_debug_impl_shows_the_policy_without_the_api() {
        let rendered = format!("{:?}", backend(&config(), StubPhpIpam::default()));
        assert!(rendered.contains("custom_acme_allowed_names"), "{rendered}");
        assert!(rendered.contains("Device"), "{rendered}");
    }
}
