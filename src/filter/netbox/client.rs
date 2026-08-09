//! The production [`NetboxApi`]: NetBox's REST API over HTTP/1.1.
//!
//! ## Why the plumbing is hand-rolled again
//!
//! This is the third small HTTP client in the tree, after
//! [`HyperFetcher`](crate::challenge::http_01::HyperFetcher) and the upstream
//! ACME client in [`signer::acme_proxy`](crate::signer::acme_proxy). Neither
//! could be reused: one deliberately validates no certificate at all, the other
//! is built around nonces, JWS bodies and ACME problem documents. `Cargo.toml`
//! records why the answer is not `reqwest` — `hyper`, `rustls` and
//! `http-body-util` are already in the tree via `axum`, so this is a direct edge
//! to crates that are present, not a new dependency.
//!
//! ## TLS
//!
//! Unlike the challenge validators — where the certificate is deliberately not
//! checked because the *proof* is what matters — NetBox's certificate is the
//! only thing identifying the service whose answers decide who may have a name
//! certified. So the public roots apply, plus any operator-supplied CA, and the
//! one way to switch that off is explicit, logged at startup and documented as
//! temporary.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::debug;
use url::Url;

use super::{AssignedKind, AssignedRef, NetboxApi, NetboxIp};
use crate::config::NetboxConfig;

/// Cap on a NetBox response body. An address query returns a handful of small
/// objects; anything approaching this is not an answer this filter can use.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// NetBox's own labels for the two interface types an address can hang off.
const DEVICE_INTERFACE: &str = "dcim.interface";
const VM_INTERFACE: &str = "virtualization.vminterface";

/// A NetBox REST client, holding one TLS configuration for the process.
pub struct NetboxClient {
    /// Base URL with no trailing slash, so a NetBox under a subpath keeps it.
    base: String,
    token: String,
    tls: Arc<rustls::ClientConfig>,
    /// The resolver every outbound hop in this server shares, so a
    /// split-horizon estate does not have NetBox resolving differently from the
    /// challenge validators.
    resolver: Arc<dyn crate::dns::Resolver>,
}

impl std::fmt::Debug for NetboxClient {
    /// Never renders the token.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetboxClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl NetboxClient {
    /// Validates the URL and builds the TLS configuration. No network yet.
    pub fn new(
        cfg: &NetboxConfig,
        resolver: Arc<dyn crate::dns::Resolver>,
    ) -> anyhow::Result<Self> {
        if cfg.url.trim().is_empty() {
            anyhow::bail!(
                "filter.netbox is enabled but filter.netbox.url is empty; give the base URL of \
                 the NetBox instance, or remove `netbox` from filter.enabled"
            );
        }
        if cfg.token.trim().is_empty() {
            anyhow::bail!(
                "filter.netbox is enabled but filter.netbox.token is empty; supply a NetBox API \
                 token, preferably through ACME_PROXY_FILTER__NETBOX__TOKEN"
            );
        }

        let url = Url::parse(cfg.url.trim()).map_err(|error| {
            anyhow::anyhow!("filter.netbox.url: {} is not a URL: {error}", cfg.url)
        })?;
        // Restricted to the two schemes NetBox is served over — which also
        // guarantees a host, since `url` requires one for both.
        match url.scheme() {
            "http" | "https" => {}
            other => {
                anyhow::bail!(
                    "filter.netbox.url: unsupported scheme {other}, expected http or https"
                )
            }
        }

        Ok(Self {
            base: url.as_str().trim_end_matches('/').to_string(),
            token: cfg.token.clone(),
            tls: tls_config(cfg)?,
            resolver,
        })
    }

    /// One `GET`, returning the parsed JSON body.
    async fn get_json(&self, path_and_query: &str) -> Result<Value, String> {
        let target = format!("{}{path_and_query}", self.base);
        let url = Url::parse(&target).map_err(|error| format!("{target} is not a URL: {error}"))?;

        let endpoint = crate::http_client::Endpoint::from_url(&url)?;

        let mut request_target = url.path().to_string();
        if let Some(query) = url.query() {
            request_target.push('?');
            request_target.push_str(query);
        }

        // hyper 1.x's low-level client sends exactly what it is given, `Host`
        // included — see `HyperFetcher`, whose loopback test is what caught it.
        let request = Request::builder()
            .uri(request_target)
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::ACCEPT, "application/json")
            .header(
                hyper::header::AUTHORIZATION,
                format!("Token {}", self.token),
            )
            .header(hyper::header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|error| format!("building the request: {error}"))?;

        let sender =
            crate::http_client::connect(self.resolver.as_ref(), &endpoint, &self.tls).await?;
        exchange(sender, request, &url).await
    }
}

/// Sends the request over an established stream and parses the answer.
async fn exchange(
    mut sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    request: Request<Empty<Bytes>>,
    url: &Url,
) -> Result<Value, String> {
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("request to {url} failed: {error}"))?;

    let status = response.status();
    // `Limited` errors once the cap is passed; a body that large is not an
    // answer worth parsing, so it is refused rather than read further.
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| format!("response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"))?
        .to_bytes();

    if !status.is_success() {
        // A 401/403 is a misconfigured token and a 5xx is an outage: both are
        // this server failing to reach a decision, never a statement about the
        // client. The caller turns every error here into `Internal`.
        let excerpt: String = String::from_utf8_lossy(&body).chars().take(200).collect();
        return Err(format!("{url} answered {status}: {excerpt}"));
    }

    serde_json::from_slice(&body)
        .map_err(|error| format!("{url} returned unreadable JSON: {error}"))
}

/// The rustls configuration this client dials with.
fn tls_config(cfg: &NetboxConfig) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    if cfg.insecure_skip_verify {
        // The same "accept anything" configuration the challenge validators
        // use, reused rather than re-derived — it already passes the crypto
        // provider explicitly, which `install_default` must never be used for.
        // No ALPN: this is an ordinary https request.
        return crate::challenge::tls_alpn_01::accept_any_client_config(&[]);
    }

    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    if !cfg.ca_cert_path.trim().is_empty() {
        let path = std::path::Path::new(cfg.ca_cert_path.trim());
        let extra = crate::pemfile::read_certificates(path)
            .map_err(|error| anyhow::anyhow!("filter.netbox.ca_cert_path: {error}"))?;
        for certificate in extra {
            roots.add(certificate).map_err(|error| {
                anyhow::anyhow!(
                    "filter.netbox.ca_cert_path: {} is not a usable CA certificate: {error}",
                    path.display()
                )
            })?;
        }
    }

    // Provider passed explicitly rather than installed as the process default:
    // `install_default` panics on a second call, which would make `cargo test`
    // depend on which tests happen to run together.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| anyhow::anyhow!("building the TLS client configuration: {error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();

    Ok(Arc::new(config))
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
}

/// A detail response, of which only the custom fields matter.
#[derive(Debug, Deserialize)]
struct ObjectResponse {
    #[serde(default)]
    custom_fields: Map<String, Value>,
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
        }
    }
}

/// Digs the device or VM out of an address's assigned interface.
///
/// NetBox nests it: an address points at an *interface*, and the interface
/// carries the device (or virtual machine) it belongs to. The brief serializer
/// the list endpoint uses includes that nested object, so no extra request is
/// needed to learn the id.
fn assigned_ref(typ: Option<&str>, object: Option<&Value>) -> Option<AssignedRef> {
    let (kind, field) = match typ? {
        DEVICE_INTERFACE => (AssignedKind::Device, "device"),
        VM_INTERFACE => (AssignedKind::VirtualMachine, "virtual_machine"),
        other => {
            debug!(
                event = "filter_netbox_assignment_ignored",
                assigned_object_type = other,
                "address is assigned to an object with no custom fields to read"
            );
            return None;
        }
    };

    let id = object?.get(field)?.get("id")?.as_u64()?;
    Some(AssignedRef { kind, id })
}

#[async_trait]
impl NetboxApi for NetboxClient {
    async fn ip_addresses(&self, ip: IpAddr) -> Result<Vec<NetboxIp>, String> {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("address", &ip.to_string())
            .finish();
        let body = self
            .get_json(&format!("/api/ipam/ip-addresses/?{query}"))
            .await?;

        let parsed: IpListResponse = serde_json::from_value(body)
            .map_err(|error| format!("unexpected ip-addresses response: {error}"))?;

        Ok(parsed.results.into_iter().map(NetboxIp::from).collect())
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

        let body = self.get_json(&path).await?;
        let parsed: ObjectResponse = serde_json::from_value(body)
            .map_err(|error| format!("unexpected response for {path}: {error}"))?;

        Ok(parsed.custom_fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These reach a loopback listener by IP literal, which `dns::connect`
    /// short-circuits without a lookup, so the system resolver is fine.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }
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
        assert!(error.contains("filter.netbox.url"), "{error}");
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
        assert!(error.contains("filter.netbox.token"), "{error}");
    }

    #[test]
    fn an_unparsable_url_is_a_startup_error() {
        let error = NetboxClient::new(&config("not a url"), test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.netbox.url"), "{error}");
    }

    #[test]
    fn a_non_http_scheme_is_a_startup_error() {
        let error = NetboxClient::new(&config("ftp://netbox.example.com"), test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported scheme ftp"), "{error}");
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
        assert!(error.contains("filter.netbox.ca_cert_path"), "{error}");
    }

    /// With verification off nothing is loaded, so even an unusable
    /// `ca_cert_path` cannot fail startup — the branch never opens it.
    #[test]
    fn skipping_verification_ignores_the_ca_certificate_entirely() {
        let cfg = NetboxConfig {
            insecure_skip_verify: true,
            ca_cert_path: "/nonexistent/netbox-ca.pem".to_string(),
            ..config("https://netbox.example.com")
        };
        NetboxClient::new(&cfg, test_resolver()).expect("skip-verify must not read ca_cert_path");
    }

    /// A base URL under a subpath keeps it: the API path is appended, never
    /// substituted the way `Url::join` on an absolute path would.
    #[test]
    fn a_base_url_under_a_subpath_is_preserved() {
        let client =
            NetboxClient::new(&config("https://example.com/netbox/"), test_resolver()).unwrap();
        assert_eq!(client.base, "https://example.com/netbox");
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
    fn a_device_interface_yields_its_device() {
        let object = json!({ "id": 7, "name": "eth0", "device": { "id": 3, "name": "srv1" } });
        assert_eq!(
            assigned_ref(Some(DEVICE_INTERFACE), Some(&object)),
            Some(AssignedRef {
                kind: AssignedKind::Device,
                id: 3
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
                id: 11
            })
        );
    }

    #[test]
    fn an_unassigned_or_unreadable_assignment_yields_nothing() {
        let object = json!({ "id": 7, "name": "eth0", "device": { "id": 3 } });
        // No type at all, an object NetBox nests differently, a type carrying
        // no custom fields worth reading, and a device without an id.
        assert_eq!(assigned_ref(None, Some(&object)), None);
        assert_eq!(assigned_ref(Some(DEVICE_INTERFACE), None), None);
        assert_eq!(assigned_ref(Some("dcim.frontport"), Some(&object)), None);
        assert_eq!(
            assigned_ref(Some(DEVICE_INTERFACE), Some(&json!({ "device": {} }))),
            None
        );
    }

    /// The real client against a loopback listener. A stub `NetboxApi` proves
    /// the policy; only this proves the request line, the `Host` header and the
    /// `Authorization` header are what NetBox actually needs.
    mod loopback {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// Serves one canned response and returns the request it received.
        async fn serve_once(response: String) -> (u16, tokio::task::JoinHandle<String>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                String::from_utf8_lossy(&buffer[..read]).into_owned()
            });

            (port, handle)
        }

        /// An HTTP/1.1 response with `body` as its JSON payload.
        fn ok(body: Value) -> String {
            status(200, "OK", &body.to_string())
        }

        /// An HTTP/1.1 response with a hand-written status and body. The
        /// `Content-Length` is computed, never guessed — a wrong one leaves
        /// hyper waiting for a body that never arrives.
        fn status(code: u16, reason: &str, body: &str) -> String {
            format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        fn client(port: u16) -> NetboxClient {
            NetboxClient::new(
                &config(&format!("http://127.0.0.1:{port}")),
                test_resolver(),
            )
            .unwrap()
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
            assert_eq!(
                objects[0].assigned,
                Some(AssignedRef {
                    kind: AssignedKind::Device,
                    id: 3
                })
            );

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/ipam/ip-addresses/?address=10.0.0.5 HTTP/1.1"),
                "{request}"
            );
            assert!(request.contains("authorization: Token t0ken"), "{request}");
            assert!(
                request.contains(&format!("host: 127.0.0.1:{port}")),
                "{request}"
            );
            assert!(request.contains("accept: application/json"), "{request}");
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
        async fn fetches_a_devices_custom_fields() {
            let (port, server) = serve_once(ok(json!({
                "id": 3,
                "name": "srv1",
                "custom_fields": { "acme_allowed_names": ["machine.example.com"] }
            })))
            .await;

            let fields = client(port)
                .object_custom_fields(&AssignedRef {
                    kind: AssignedKind::Device,
                    id: 3,
                })
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
                })
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/virtualization/virtual-machines/11/ HTTP/1.1"),
                "{request}"
            );
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

        #[tokio::test]
        async fn a_server_error_is_reported_with_its_status() {
            let (port, _server) = serve_once(status(500, "Internal Server Error", "boom!")).await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("500"), "{error}");
            assert!(error.contains("boom!"), "{error}");
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

        #[tokio::test]
        async fn an_unreadable_body_is_an_error() {
            let (port, _server) = serve_once(status(200, "OK", "not json!")).await;

            let error = client(port)
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("unreadable JSON"), "{error}");
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
        async fn a_closed_port_is_a_connect_error() {
            // Bind then drop, so the port is almost certainly free and unbound.
            let port = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap().port()
            };

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
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::{ServerConfig, sign::CertifiedKey};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        /// Serves one https request with a self-signed certificate for
        /// `localhost`, then stops.
        async fn serve_once(body: Value) -> u16 {
            let key_pair = KeyPair::generate().unwrap();
            let key = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
            let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            params.distinguished_name = rcgen::DistinguishedName::new();
            let der = params
                .self_signed(&key_pair)
                .unwrap()
                .der()
                .as_ref()
                .to_vec();

            let provider = rustls::crypto::ring::default_provider();
            let signing_key = provider.key_provider.load_private_key(key).unwrap();
            let certified = CertifiedKey::new(vec![CertificateDer::from(der)], signing_key);
            let config = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified))));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let acceptor = TlsAcceptor::from(Arc::new(config));

            let response = {
                let body = body.to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };

            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                // A client that refuses the certificate fails here, which is
                // exactly what one of the two tests is asserting.
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = vec![0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            });

            port
        }

        #[derive(Debug)]
        struct FixedCert(Arc<CertifiedKey>);

        impl rustls::server::ResolvesServerCert for FixedCert {
            fn resolve(
                &self,
                _hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<CertifiedKey>> {
                Some(self.0.clone())
            }
        }

        fn https_config(port: u16, skip: bool) -> NetboxConfig {
            NetboxConfig {
                insecure_skip_verify: skip,
                ..config(&format!("https://localhost:{port}"))
            }
        }

        #[tokio::test]
        async fn a_self_signed_netbox_is_refused_by_default() {
            let port = serve_once(json!({ "results": [] })).await;

            let error = NetboxClient::new(&https_config(port, false), test_resolver())
                .unwrap()
                .ip_addresses("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("TLS handshake"), "{error}");
        }

        #[tokio::test]
        async fn skipping_verification_reaches_the_same_netbox() {
            let port = serve_once(json!({
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
