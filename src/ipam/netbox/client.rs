//! The production [`NetboxApi`]: NetBox's REST API over HTTP/1.1.
//!
//! Five queries, of which one always runs and four are gated by
//! [`Source`](crate::ipam::Source):
//!
//! | Query | Source |
//! | --- | --- |
//! | `ipam/ip-addresses/?address=…` | always |
//! | `dcim/devices/{id}/`, `virtualization/virtual-machines/{id}/` | `device` |
//! | `ipam/ip-addresses/?device_id=…&role=…` | `vip` |
//! | `ipam/fhrp-group-assignments/?interface_type=…&interface_id=…` | `fhrp` |
//! | `ipam/ip-addresses/?fhrpgroup_id=…` | `fhrp` |
//!
//! The transport, the body cap, the TLS policy and the error shape all live in
//! [`ipam::http`](crate::ipam::http), which both backends share. What is here
//! is NetBox's own paths, filters and wire shapes.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::debug;
use url::form_urlencoded::Serializer;

use super::{AssignedKind, AssignedRef, NetboxApi, NetboxIp};
use crate::config::NetboxConfig;
use crate::ipam::http::{JsonApi, JsonApiError, tls_config};

/// NetBox's own labels for the two interface types an address can hang off.
pub(super) const DEVICE_INTERFACE: &str = "dcim.interface";
pub(super) const VM_INTERFACE: &str = "virtualization.vminterface";

/// A NetBox REST client.
#[derive(Debug)]
pub struct NetboxClient {
    api: JsonApi,
}

impl NetboxClient {
    /// Validates the URL and builds the TLS configuration. No network yet.
    pub fn new(
        cfg: &NetboxConfig,
        resolver: Arc<dyn crate::dns::Resolver>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.url.trim().is_empty(),
            "ipam.backend is `netbox` but ipam.netbox.url is empty; give the base URL of the \
             NetBox instance"
        );
        anyhow::ensure!(
            !cfg.token.trim().is_empty(),
            "ipam.backend is `netbox` but ipam.netbox.token is empty; supply a NetBox API \
             token, preferably through ACME_PROXY_IPAM__NETBOX__TOKEN"
        );

        Ok(Self {
            api: JsonApi::new(
                &cfg.url,
                "ipam.netbox.url",
                vec![(hyper::header::AUTHORIZATION, format!("Token {}", cfg.token))],
                tls_config(
                    &cfg.ca_cert_path,
                    cfg.insecure_skip_verify,
                    "ipam.netbox.ca_cert_path",
                )?,
                resolver,
            )?,
        })
    }

    /// A `GET` whose every failure is a failure — NetBox has no status this
    /// backend reads as an answer.
    async fn get(&self, path_and_query: &str) -> Result<Value, String> {
        self.api
            .get(path_and_query)
            .await
            .map_err(|error: JsonApiError| error.message)
    }

    /// The address list endpoint, with a pre-built query string.
    async fn addresses(&self, query: &str, what: &str) -> Result<Vec<NetboxIp>, String> {
        let body = self
            .get(&format!("/api/ipam/ip-addresses/?{query}"))
            .await?;
        let parsed: IpListResponse = serde_json::from_value(body)
            .map_err(|error| format!("unexpected {what} response: {error}"))?;
        Ok(parsed.results.into_iter().map(NetboxIp::from).collect())
    }
}

// ------------------------------------------------------- the wire shapes

/// The `ipam/ip-addresses` list response, reduced to what is read.
#[derive(Debug, Deserialize)]
struct IpListResponse {
    #[serde(default)]
    results: Vec<IpResult>,
}

#[derive(Debug, Deserialize)]
struct IpResult {
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    custom_fields: Map<String, Value>,
    #[serde(default)]
    assigned_object_type: Option<String>,
    #[serde(default)]
    assigned_object: Option<Value>,
    /// NetBox renders a choice field as `{"value": "vrrp", "label": "VRRP"}`.
    #[serde(default)]
    role: Option<Choice>,
}

/// One NetBox choice field. Only `value` is read — `label` is display text and
/// is localized, so comparing against it would break on a translated instance.
#[derive(Debug, Deserialize)]
struct Choice {
    #[serde(default)]
    value: String,
}

/// A detail response, of which only the custom fields matter.
#[derive(Debug, Deserialize)]
struct ObjectResponse {
    #[serde(default)]
    custom_fields: Map<String, Value>,
}

/// The `ipam/fhrp-group-assignments` list response.
///
/// One row per (interface, group) pair. Filtering it by `interface_id` is the
/// membership question, and the only way this backend ever learns a group id.
#[derive(Debug, Deserialize)]
struct AssignmentListResponse {
    #[serde(default)]
    results: Vec<AssignmentResult>,
}

#[derive(Debug, Deserialize)]
struct AssignmentResult {
    #[serde(default)]
    group: Option<Nested>,
}

/// Any nested NetBox object, of which only the id is read.
#[derive(Debug, Deserialize)]
struct Nested {
    id: u64,
}

impl From<IpResult> for NetboxIp {
    fn from(result: IpResult) -> Self {
        Self {
            dns_name: result.dns_name,
            custom_fields: result.custom_fields,
            assigned: assigned_ref(
                result.assigned_object_type.as_deref(),
                result.assigned_object.as_ref(),
            ),
            role: result.role.map(|choice| choice.value),
        }
    }
}

/// Digs the device or VM — and the interface — out of an address's assignment.
///
/// NetBox nests it: an address points at an *interface*, and the interface
/// carries the device (or virtual machine) it belongs to. The brief serializer
/// the list endpoint uses includes that nested object, so both ids are known
/// without an extra request — which is what keeps the FHRP membership query
/// down to one round trip.
///
/// An address assigned to an FHRP group itself (`ipam.fhrpgroup`) yields
/// `None`, and rightly so: a client connecting *from* the VIP already got that
/// object's own names out of the first query, and there is no device to scope
/// anything else to.
fn assigned_ref(typ: Option<&str>, object: Option<&Value>) -> Option<AssignedRef> {
    let (kind, field) = match typ? {
        DEVICE_INTERFACE => (AssignedKind::Device, "device"),
        VM_INTERFACE => (AssignedKind::VirtualMachine, "virtual_machine"),
        other => {
            debug!(
                event = "ipam_netbox_assignment_ignored",
                outcome = "advisory",
                assigned_object_type = other,
                "address is assigned to an object with no machine behind it"
            );
            return None;
        }
    };

    let object = object?;
    let interface_id = object.get("id")?.as_u64()?;
    let id = object.get(field)?.get("id")?.as_u64()?;
    Some(AssignedRef {
        kind,
        id,
        interface_id,
    })
}

#[async_trait]
impl NetboxApi for NetboxClient {
    async fn ip_addresses(&self, ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
        let query = Serializer::new(String::new())
            .append_pair("address", &ip.to_string())
            .finish();
        self.addresses(&query, "ip-addresses").await
    }

    async fn object_custom_fields(
        &self,
        reference: &AssignedRef,
    ) -> Result<Map<String, Value>, String> {
        let path = match reference.kind {
            AssignedKind::Device => format!("/api/dcim/devices/{}/", reference.id),
            AssignedKind::VirtualMachine => {
                format!("/api/virtualization/virtual-machines/{}/", reference.id)
            }
        };

        let body = self.get(&path).await?;
        let parsed: ObjectResponse = serde_json::from_value(body)
            .map_err(|error| format!("unexpected response for {path}: {error}"))?;

        Ok(parsed.custom_fields)
    }

    async fn shared_addresses(
        &self,
        reference: &AssignedRef,
        roles: &[String],
    ) -> Result<Vec<NetboxIp>, String> {
        // `role` is a multiple-choice filter, so it is repeated rather than
        // comma-joined; NetBox ORs the values. Built and finished inside its
        // own scope: `Serializer` is not `Send`, so holding one across the
        // await below would make this future unspawnable.
        let query = {
            let mut query = Serializer::new(String::new());
            query.append_pair(reference.kind.owner_filter(), &reference.id.to_string());
            for role in roles {
                query.append_pair("role", role);
            }
            query.finish()
        };
        self.addresses(&query, "service-address").await
    }

    async fn fhrp_groups(&self, reference: &AssignedRef) -> Result<Vec<u64>, String> {
        let query = Serializer::new(String::new())
            .append_pair("interface_type", reference.kind.interface_type())
            .append_pair("interface_id", &reference.interface_id.to_string())
            .finish();

        let body = self
            .get(&format!("/api/ipam/fhrp-group-assignments/?{query}"))
            .await?;
        let parsed: AssignmentListResponse = serde_json::from_value(body)
            .map_err(|error| format!("unexpected fhrp-group-assignments response: {error}"))?;

        Ok(parsed
            .results
            .into_iter()
            .filter_map(|assignment| assignment.group.map(|group| group.id))
            .collect())
    }

    async fn fhrp_group_addresses(&self, group_ids: &[u64]) -> Result<Vec<NetboxIp>, String> {
        // Also a multiple-choice filter, so every group resolves in one query
        // however many the interface belongs to. Scoped for the same `Send`
        // reason as `shared_addresses` above.
        let query = {
            let mut query = Serializer::new(String::new());
            for id in group_ids {
                query.append_pair("fhrpgroup_id", &id.to_string());
            }
            query.finish()
        };
        self.addresses(&query, "fhrp-group-address").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::http::testing::{
        closed_port, ok, serve_many, serve_once, serve_once_tls, status, test_resolver,
    };
    use serde_json::json;

    fn config(url: &str) -> NetboxConfig {
        NetboxConfig {
            url: url.to_string(),
            token: "t0ken".to_string(),
            ..NetboxConfig::default()
        }
    }

    // ------------------------------------------------------ startup checks

    #[test]
    fn an_empty_url_is_a_startup_error() {
        let error = NetboxClient::new(&config("  "), test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.url"), "{error}");
    }

    #[test]
    fn an_empty_token_is_a_startup_error() {
        let cfg = NetboxConfig {
            token: String::new(),
            ..config("https://netbox.example.com")
        };
        let error = NetboxClient::new(&cfg, test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.token"), "{error}");
        assert!(error.contains("ACME_PROXY_IPAM__NETBOX__TOKEN"), "{error}");
    }

    #[test]
    fn an_unparsable_url_is_a_startup_error() {
        let error = NetboxClient::new(&config("not a url"), test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.url"), "{error}");
    }

    #[test]
    fn a_missing_ca_certificate_is_a_startup_error() {
        let cfg = NetboxConfig {
            ca_cert_path: "/nonexistent/netbox-ca.pem".to_string(),
            ..config("https://netbox.example.com")
        };
        let error = NetboxClient::new(&cfg, test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.ca_cert_path"), "{error}");
    }

    #[test]
    fn the_debug_impl_never_renders_the_token() {
        let client =
            NetboxClient::new(&config("https://netbox.example.com"), test_resolver()).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("t0ken"), "{rendered}");
    }

    // ------------------------------------------------- the assignment digger

    #[test]
    fn a_device_interface_yields_its_device_and_its_interface() {
        let object = json!({ "id": 7, "name": "eth0", "device": { "id": 3, "name": "srv1" } });
        assert_eq!(
            assigned_ref(Some(DEVICE_INTERFACE), Some(&object)),
            Some(AssignedRef {
                kind: AssignedKind::Device,
                id: 3,
                interface_id: 7,
            })
        );
    }

    #[test]
    fn a_vm_interface_yields_its_virtual_machine() {
        let object = json!({ "id": 9, "virtual_machine": { "id": 11, "name": "vm1" } });
        assert_eq!(
            assigned_ref(Some(VM_INTERFACE), Some(&object)),
            Some(AssignedRef {
                kind: AssignedKind::VirtualMachine,
                id: 11,
                interface_id: 9,
            })
        );
    }

    #[test]
    fn an_unassigned_or_unreadable_assignment_yields_nothing() {
        let object = json!({ "id": 7, "name": "eth0", "device": { "id": 3 } });
        // No type at all, no object, a type with no machine behind it (which is
        // what an FHRP-group VIP looks like), a device without an id, and an
        // interface without one.
        assert_eq!(assigned_ref(None, Some(&object)), None);
        assert_eq!(assigned_ref(Some(DEVICE_INTERFACE), None), None);
        assert_eq!(assigned_ref(Some("ipam.fhrpgroup"), Some(&object)), None);
        assert_eq!(
            assigned_ref(
                Some(DEVICE_INTERFACE),
                Some(&json!({ "id": 7, "device": {} }))
            ),
            None
        );
        assert_eq!(
            assigned_ref(
                Some(DEVICE_INTERFACE),
                Some(&json!({ "device": { "id": 3 } }))
            ),
            None
        );
    }

    /// The real client against a loopback listener. A stub `NetboxApi` proves
    /// the policy; only this proves the request line, the `Host` header and the
    /// `Authorization` header are what NetBox actually needs.
    mod loopback {
        use super::*;

        fn client(port: u16) -> NetboxClient {
            NetboxClient::new(
                &config(&format!("http://127.0.0.1:{port}")),
                test_resolver(),
            )
            .unwrap()
        }

        fn on_device() -> AssignedRef {
            AssignedRef {
                kind: AssignedKind::Device,
                id: 3,
                interface_id: 7,
            }
        }

        /// A realistic NetBox answer, nested assignment included.
        fn one_address() -> Value {
            json!({
                "count": 1,
                "results": [{
                    "id": 12,
                    "address": "10.0.0.5/24",
                    "dns_name": "host.example.com",
                    "custom_fields": { "acme_allowed_names": ["www.example.com"] },
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 7,
                    "assigned_object": { "id": 7, "name": "eth0", "device": { "id": 3 } }
                }]
            })
        }

        #[tokio::test]
        async fn queries_the_address_and_authenticates() {
            let (port, server) = serve_once(ok(one_address())).await;

            let objects = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap();

            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].dns_name, "host.example.com");
            assert_eq!(
                objects[0].custom_fields["acme_allowed_names"],
                json!(["www.example.com"])
            );
            assert_eq!(objects[0].assigned, Some(on_device()));

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/ipam/ip-addresses/?address=10.0.0.5 HTTP/1.1"),
                "{request}"
            );
            assert!(request.contains("authorization: Token t0ken"), "{request}");
        }

        /// An IPv6 address's colons must survive into the query.
        #[tokio::test]
        async fn an_ipv6_address_is_percent_encoded() {
            let (port, server) = serve_once(ok(json!({ "results": [] }))).await;

            let objects = client(port)
                .ip_addresses("2001:db8::5".parse().unwrap())
                .await
                .unwrap();
            assert!(objects.is_empty());

            let request = server.await.unwrap();
            assert!(request.contains("address=2001%3Adb8%3A%3A5"), "{request}");
        }

        #[tokio::test]
        async fn a_role_is_read_off_the_choice_object() {
            let (port, _server) = serve_once(ok(json!({
                "results": [{ "dns_name": "service.example.com",
                              "role": { "value": "vrrp", "label": "VRRP" } }]
            })))
            .await;

            let objects = client(port)
                .shared_addresses(&on_device(), &[])
                .await
                .unwrap();
            assert_eq!(objects[0].role.as_deref(), Some("vrrp"));
        }

        #[tokio::test]
        async fn fetches_a_devices_custom_fields() {
            let (port, server) = serve_once(ok(json!({
                "id": 3,
                "custom_fields": { "acme_allowed_names": ["machine.example.com"] }
            })))
            .await;

            let fields = client(port)
                .object_custom_fields(&on_device())
                .await
                .unwrap();

            assert_eq!(fields["acme_allowed_names"], json!(["machine.example.com"]));

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/dcim/devices/3/ HTTP/1.1"),
                "{request}"
            );
        }

        #[tokio::test]
        async fn fetches_a_virtual_machines_custom_fields() {
            let (port, server) = serve_once(ok(json!({ "custom_fields": {} }))).await;

            client(port)
                .object_custom_fields(&AssignedRef {
                    kind: AssignedKind::VirtualMachine,
                    id: 11,
                    interface_id: 9,
                })
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/virtualization/virtual-machines/11/ HTTP/1.1"),
                "{request}"
            );
        }

        /// `role` is repeated, not comma-joined: NetBox's multiple-choice
        /// filters OR their values, and a comma-joined one matches nothing.
        #[tokio::test]
        async fn service_addresses_are_scoped_to_the_device_and_the_roles() {
            let (port, server) = serve_once(ok(json!({ "results": [] }))).await;

            client(port)
                .shared_addresses(&on_device(), &["vip".to_string(), "vrrp".to_string()])
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with(
                    "GET /api/ipam/ip-addresses/?device_id=3&role=vip&role=vrrp HTTP/1.1"
                ),
                "{request}"
            );
        }

        #[tokio::test]
        async fn service_addresses_of_a_virtual_machine_use_the_vm_filter() {
            let (port, server) = serve_once(ok(json!({ "results": [] }))).await;

            client(port)
                .shared_addresses(
                    &AssignedRef {
                        kind: AssignedKind::VirtualMachine,
                        id: 11,
                        interface_id: 9,
                    },
                    &["vrrp".to_string()],
                )
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.contains("virtual_machine_id=11&role=vrrp"),
                "{request}"
            );
        }

        /// The membership query, and the whole security property of the `fhrp`
        /// source: it is scoped to the client's **own** interface, never to a
        /// group or a name.
        #[tokio::test]
        async fn membership_is_queried_by_the_clients_own_interface() {
            let (port, server) = serve_once(ok(json!({
                "results": [
                    { "id": 1, "group": { "id": 41, "name": "vrrp-41" } },
                    { "id": 2, "group": { "id": 42 } }
                ]
            })))
            .await;

            let groups = client(port).fhrp_groups(&on_device()).await.unwrap();
            assert_eq!(groups, vec![41, 42]);

            let request = server.await.unwrap();
            assert!(
                request.starts_with(
                    "GET /api/ipam/fhrp-group-assignments/\
                     ?interface_type=dcim.interface&interface_id=7 HTTP/1.1"
                ),
                "{request}"
            );
        }

        #[tokio::test]
        async fn membership_of_a_vm_interface_uses_the_vm_interface_type() {
            let (port, server) = serve_once(ok(json!({ "results": [] }))).await;

            let groups = client(port)
                .fhrp_groups(&AssignedRef {
                    kind: AssignedKind::VirtualMachine,
                    id: 11,
                    interface_id: 9,
                })
                .await
                .unwrap();
            assert!(groups.is_empty());

            let request = server.await.unwrap();
            assert!(
                request.contains("interface_type=virtualization.vminterface&interface_id=9"),
                "{request}"
            );
        }

        /// However many groups an interface belongs to, their addresses come
        /// back in one query — `fhrpgroup_id` is a multiple-choice filter.
        #[tokio::test]
        async fn every_group_resolves_in_one_query() {
            let (port, server) = serve_once(ok(json!({
                "results": [{ "dns_name": "service.example.com" }]
            })))
            .await;

            let objects = client(port).fhrp_group_addresses(&[41, 42]).await.unwrap();
            assert_eq!(objects[0].dns_name, "service.example.com");

            let request = server.await.unwrap();
            assert!(
                request.starts_with(
                    "GET /api/ipam/ip-addresses/?fhrpgroup_id=41&fhrpgroup_id=42 HTTP/1.1"
                ),
                "{request}"
            );
        }

        /// The two FHRP queries in sequence, over two connections, which is
        /// what one lookup with `fhrp` on actually costs.
        #[tokio::test]
        async fn the_two_fhrp_queries_run_in_order() {
            let (port, server) = serve_many(vec![
                ok(json!({ "results": [{ "group": { "id": 41 } }] })),
                ok(json!({ "results": [{ "dns_name": "service.example.com" }] })),
            ])
            .await;

            let client = client(port);
            let groups = client.fhrp_groups(&on_device()).await.unwrap();
            let objects = client.fhrp_group_addresses(&groups).await.unwrap();
            assert_eq!(objects[0].dns_name, "service.example.com");

            let requests = server.await.unwrap();
            assert!(requests.contains("fhrp-group-assignments"), "{requests}");
            assert!(requests.contains("fhrpgroup_id=41"), "{requests}");
        }

        /// A subpath deployment keeps its prefix in the request line.
        #[tokio::test]
        async fn a_subpath_base_url_prefixes_the_api_path() {
            let (port, server) = serve_once(ok(json!({ "results": [] }))).await;
            let cfg = config(&format!("http://127.0.0.1:{port}/netbox"));

            NetboxClient::new(&cfg, test_resolver())
                .unwrap()
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /netbox/api/ipam/ip-addresses/?address="),
                "{request}"
            );
        }

        /// A refused token is the operator's problem, not the client's — it
        /// must surface as an error the caller turns into a 500, never as an
        /// empty answer that would read as "this address owns no names".
        #[tokio::test]
        async fn a_refused_token_is_reported_rather_than_parsed() {
            let (port, _server) = serve_once(status(
                401,
                "Unauthorized",
                r#"{"detail":"Invalid token header."}"#,
            ))
            .await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("401"), "{error}");
            assert!(error.contains("Invalid token header"), "{error}");
        }

        /// Unlike phpIPAM, NetBox has no status this backend reads as an
        /// answer: a 404 is a failure like any other.
        #[tokio::test]
        async fn a_404_is_a_failure_for_netbox() {
            let (port, _server) = serve_once(status(404, "Not Found", "{}")).await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("404"), "{error}");
        }

        /// A body of the right shape but the wrong types is not an outage —
        /// still an error, because a wrong answer must not read as "no names".
        #[tokio::test]
        async fn a_response_of_the_wrong_shape_is_an_error() {
            let (port, _server) = serve_once(ok(json!({ "results": "nope" }))).await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(
                error.contains("unexpected ip-addresses response"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn a_malformed_assignment_list_is_an_error() {
            let (port, _server) = serve_once(ok(json!({ "results": "nope" }))).await;

            let error = client(port).fhrp_groups(&on_device()).await.unwrap_err();
            assert!(
                error.contains("unexpected fhrp-group-assignments response"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn a_malformed_device_response_is_an_error() {
            let (port, _server) = serve_once(ok(json!({ "custom_fields": 7 }))).await;

            let error = client(port)
                .object_custom_fields(&on_device())
                .await
                .unwrap_err();
            assert!(error.contains("unexpected response for"), "{error}");
        }

        #[tokio::test]
        async fn a_closed_port_is_a_connect_error() {
            let port = closed_port().await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("connecting to 127.0.0.1"), "{error}");
        }
    }

    /// The proof that `insecure_skip_verify` does what it says: the same
    /// self-signed server is unreachable with verification on and readable with
    /// it off. Without this the switch would only be declarative.
    mod tls {
        use super::*;

        fn https_config(port: u16, skip: bool) -> NetboxConfig {
            NetboxConfig {
                insecure_skip_verify: skip,
                ..config(&format!("https://localhost:{port}"))
            }
        }

        #[tokio::test]
        async fn a_self_signed_netbox_is_refused_by_default() {
            let port = serve_once_tls(json!({ "results": [] })).await;

            let error = NetboxClient::new(&https_config(port, false), test_resolver())
                .unwrap()
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("TLS handshake"), "{error}");
        }

        #[tokio::test]
        async fn skipping_verification_reaches_the_same_netbox() {
            let port = serve_once_tls(json!({
                "results": [{ "dns_name": "host.example.com", "custom_fields": {} }]
            }))
            .await;

            let objects = NetboxClient::new(&https_config(port, true), test_resolver())
                .unwrap()
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .expect("skip-verify must accept a self-signed certificate");
            assert_eq!(objects[0].dns_name, "host.example.com");
        }
    }
}
