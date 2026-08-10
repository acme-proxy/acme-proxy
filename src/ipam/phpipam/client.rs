//! The production [`PhpIpamApi`]: phpIPAM's REST API over HTTP/1.1.
//!
//! Two queries, of which one always runs:
//!
//! | Query | Source |
//! | --- | --- |
//! | `<app_id>/addresses/search/<ip>/` | always |
//! | `<app_id>/devices/<id>/` | `device` |
//!
//! ## Two things phpIPAM does that NetBox does not
//!
//! **Authentication is a bare `token` header**, not `Authorization`. phpIPAM
//! calls it the application's *app code*, configured per API application under
//! Administration → API with security "SSL with App code". The other scheme —
//! user credentials exchanged for a six-hour session token — is deliberately
//! not implemented: it needs a refresh loop and a place to keep the token, for
//! no gain over a credential that can simply be rotated in the environment.
//!
//! **An unknown address is a `404`**, not an empty list, and the body is a
//! phpIPAM envelope rather than an HTTP error page. That is why [`search`]
//! returns `Ok(None)` for it — a fact about the address, not a failure to look
//! it up — and why the shared transport carries the status at all.
//!
//! ## The envelope
//!
//! Every phpIPAM answer is `{"code": 200, "success": true, "data": …}`, with
//! `data` an array for a search and an object for a detail read. Custom columns
//! are plain top-level members of each row (`custom_acme_allowed_names`),
//! unlike NetBox's nested `custom_fields`.
//!
//! [`search`]: PhpIpamApi::search

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hyper::{StatusCode, header::HeaderName};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{PhpIpamAddress, PhpIpamApi};
use crate::config::PhpIpamConfig;
use crate::ipam::http::{JsonApi, JsonApiError, tls_config};

/// phpIPAM's own header name for the application's app code.
const TOKEN_HEADER: &str = "token";

/// A phpIPAM REST client.
#[derive(Debug)]
pub struct PhpIpamClient {
    api: JsonApi,
    app_id: String,
}

impl PhpIpamClient {
    /// Validates the URL and builds the TLS configuration. No network yet.
    pub fn new(
        cfg: &PhpIpamConfig,
        resolver: Arc<dyn crate::dns::Resolver>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.url.trim().is_empty(),
            "ipam.backend is `phpipam` but ipam.phpipam.url is empty; give the base URL of the \
             phpIPAM instance"
        );
        anyhow::ensure!(
            !cfg.token.trim().is_empty(),
            "ipam.backend is `phpipam` but ipam.phpipam.token is empty; supply the API \
             application's app code, preferably through ACME_PROXY_IPAM__PHPIPAM__TOKEN"
        );
        // The app id is a path segment in every request, so a stray slash would
        // silently retarget the API rather than fail.
        let app_id = cfg.app_id.trim().to_string();
        anyhow::ensure!(
            !app_id.is_empty()
                && app_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "ipam.phpipam.app_id must be a single path segment of letters, digits, `-` or `_` \
             (the API application's identifier in phpIPAM); got `{}`",
            cfg.app_id
        );

        let header = HeaderName::from_static(TOKEN_HEADER);

        Ok(Self {
            api: JsonApi::new(
                &cfg.url,
                "ipam.phpipam.url",
                vec![(header, cfg.token.clone())],
                tls_config(
                    &cfg.ca_cert_path,
                    cfg.insecure_skip_verify,
                    "ipam.phpipam.ca_cert_path",
                )?,
                resolver,
            )?,
            app_id,
        })
    }
}

/// The phpIPAM envelope. `data` is an array for a search and an object for a
/// detail read, so it stays a raw [`Value`] and each caller shapes it.
#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    data: Value,
}

/// One address row, of which `hostname` and `deviceId` are named and every
/// other column — the custom ones included — is kept as it arrived.
#[derive(Debug, Deserialize)]
struct AddressRow {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(rename = "deviceId", default)]
    device_id: Option<Value>,
    #[serde(flatten)]
    fields: Map<String, Value>,
}

impl From<AddressRow> for PhpIpamAddress {
    fn from(row: AddressRow) -> Self {
        Self {
            hostname: row.hostname.unwrap_or_default(),
            device_id: row.device_id.as_ref().and_then(numeric_id),
            fields: row.fields,
        }
    }
}

/// phpIPAM renders integer columns as JSON *strings* in some versions and as
/// numbers in others, and an unassigned device is `null`, `"0"` or `0`
/// depending on the release. All four have to read as "no device".
fn numeric_id(value: &Value) -> Option<u64> {
    let id = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(text) => text.trim().parse().ok()?,
        _ => return None,
    };
    (id != 0).then_some(id)
}

#[async_trait]
impl PhpIpamApi for PhpIpamClient {
    async fn search(&self, ip: IpAddr) -> Result<Option<Vec<PhpIpamAddress>>, String> {
        // The address is a path segment. It is an `IpAddr`, so it is already
        // known to hold nothing needing escaping — no operator string reaches
        // this path.
        let path = format!("/api/{}/addresses/search/{ip}/", self.app_id);

        let body = match self.api.get(&path).await {
            Ok(body) => body,
            // The one status phpIPAM uses as an answer rather than a failure.
            Err(JsonApiError {
                status: Some(StatusCode::NOT_FOUND),
                ..
            }) => return Ok(None),
            Err(error) => return Err(error.message),
        };

        let envelope: Envelope = serde_json::from_value(body)
            .map_err(|error| format!("unexpected addresses/search response: {error}"))?;
        let rows: Vec<AddressRow> = serde_json::from_value(envelope.data)
            .map_err(|error| format!("unexpected addresses/search data: {error}"))?;

        Ok(Some(rows.into_iter().map(PhpIpamAddress::from).collect()))
    }

    async fn device(&self, id: u64) -> Result<Map<String, Value>, String> {
        let path = format!("/api/{}/devices/{id}/", self.app_id);

        let body = self
            .api
            .get(&path)
            .await
            .map_err(|error: JsonApiError| error.message)?;

        let envelope: Envelope = serde_json::from_value(body)
            .map_err(|error| format!("unexpected response for {path}: {error}"))?;

        match envelope.data {
            Value::Object(fields) => Ok(fields),
            // A device phpIPAM has no row for answers 200 with an empty array
            // rather than a 404. Not an error — it simply lends no names.
            Value::Null | Value::Array(_) => Ok(Map::new()),
            other => Err(format!(
                "unexpected response for {path}: data is a {}",
                crate::ipam::value_kind(&other)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::http::testing::{
        closed_port, ok, serve_once, serve_once_tls, status, test_resolver,
    };
    use serde_json::json;

    fn config(url: &str) -> PhpIpamConfig {
        PhpIpamConfig {
            url: url.to_string(),
            token: "t0ken".to_string(),
            ..PhpIpamConfig::default()
        }
    }

    // ------------------------------------------------------ startup checks

    #[test]
    fn an_empty_url_is_a_startup_error() {
        let error = PhpIpamClient::new(&config("  "), test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.phpipam.url"), "{error}");
    }

    #[test]
    fn an_empty_token_is_a_startup_error() {
        let cfg = PhpIpamConfig {
            token: String::new(),
            ..config("https://ipam.example.com")
        };
        let error = PhpIpamClient::new(&cfg, test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.phpipam.token"), "{error}");
        assert!(error.contains("ACME_PROXY_IPAM__PHPIPAM__TOKEN"), "{error}");
    }

    /// The app id is a path segment, so a slash in it would silently retarget
    /// every request rather than fail.
    #[test]
    fn an_app_id_that_is_not_one_path_segment_is_a_startup_error() {
        for bad in ["", "  ", "a/b", "a?b", "a b", "../admin"] {
            let cfg = PhpIpamConfig {
                app_id: bad.to_string(),
                ..config("https://ipam.example.com")
            };
            let error = PhpIpamClient::new(&cfg, test_resolver())
                .unwrap_err()
                .to_string();
            assert!(error.contains("ipam.phpipam.app_id"), "{bad}: {error}");
        }
    }

    #[test]
    fn a_missing_ca_certificate_is_a_startup_error() {
        let cfg = PhpIpamConfig {
            ca_cert_path: "/nonexistent/ipam-ca.pem".to_string(),
            ..config("https://ipam.example.com")
        };
        let error = PhpIpamClient::new(&cfg, test_resolver())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.phpipam.ca_cert_path"), "{error}");
    }

    #[test]
    fn the_debug_impl_never_renders_the_token() {
        let client =
            PhpIpamClient::new(&config("https://ipam.example.com"), test_resolver()).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("t0ken"), "{rendered}");
    }

    // ---------------------------------------------------------- the id shim

    /// phpIPAM renders integer columns as strings in some versions and numbers
    /// in others, and an unassigned device is `null`, `"0"` or `0`.
    #[test]
    fn a_device_id_reads_from_either_json_type() {
        assert_eq!(numeric_id(&json!(3)), Some(3));
        assert_eq!(numeric_id(&json!("3")), Some(3));
        assert_eq!(numeric_id(&json!(" 3 ")), Some(3));
        assert_eq!(numeric_id(&json!(0)), None);
        assert_eq!(numeric_id(&json!("0")), None);
        assert_eq!(numeric_id(&Value::Null), None);
        assert_eq!(numeric_id(&json!("")), None);
        assert_eq!(numeric_id(&json!([3])), None);
    }

    /// The real client against a loopback listener. A stub proves the policy;
    /// only this proves the path and the `token` header are what phpIPAM needs.
    mod loopback {
        use super::*;

        fn client(port: u16) -> PhpIpamClient {
            PhpIpamClient::new(
                &config(&format!("http://127.0.0.1:{port}")),
                test_resolver(),
            )
            .unwrap()
        }

        fn one_address() -> Value {
            json!({
                "code": 200,
                "success": true,
                "data": [{
                    "id": "12",
                    "subnetId": "4",
                    "ip": "10.0.0.5",
                    "hostname": "host.example.com",
                    "deviceId": "3",
                    "custom_acme_allowed_names": "www.example.com"
                }]
            })
        }

        #[tokio::test]
        async fn searches_the_address_and_authenticates() {
            let (port, server) = serve_once(ok(one_address())).await;

            let objects = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap()
                .unwrap();

            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].hostname, "host.example.com");
            assert_eq!(objects[0].device_id, Some(3));
            assert_eq!(
                objects[0].fields["custom_acme_allowed_names"],
                json!("www.example.com")
            );

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/acme/addresses/search/10.0.0.5/ HTTP/1.1"),
                "{request}"
            );
            // A bare `token` header, not `Authorization` — phpIPAM's own scheme.
            assert!(request.contains("token: t0ken"), "{request}");
            assert!(!request.contains("authorization:"), "{request}");
        }

        #[tokio::test]
        async fn the_app_id_is_part_of_the_path() {
            let (port, server) = serve_once(ok(json!({ "data": [] }))).await;
            let cfg = PhpIpamConfig {
                app_id: "certs".to_string(),
                ..config(&format!("http://127.0.0.1:{port}"))
            };

            PhpIpamClient::new(&cfg, test_resolver())
                .unwrap()
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/certs/addresses/search/"),
                "{request}"
            );
        }

        #[tokio::test]
        async fn an_ipv6_address_keeps_its_colons_in_the_path() {
            let (port, server) = serve_once(ok(json!({ "data": [] }))).await;

            client(port)
                .search("2001:db8::5".parse().unwrap())
                .await
                .unwrap();

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/acme/addresses/search/2001:db8::5/"),
                "{request}"
            );
        }

        /// The behaviour this whole backend is shaped around: phpIPAM answers
        /// an unknown address with a 404, and that is an answer.
        #[tokio::test]
        async fn a_404_reads_as_no_such_address_rather_than_a_failure() {
            let (port, _server) = serve_once(status(
                404,
                "Not Found",
                r#"{"code":404,"success":false,"message":"No addresses found"}"#,
            ))
            .await;

            let found = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .expect("a 404 must not be an error");
            assert!(found.is_none());
        }

        /// …and every other status still is a failure, so a broken phpIPAM
        /// stops issuance rather than reading as "this address owns no names".
        #[tokio::test]
        async fn a_refused_token_is_still_a_failure() {
            let (port, _server) = serve_once(status(
                401,
                "Unauthorized",
                r#"{"code":401,"message":"Invalid app code"}"#,
            ))
            .await;

            let error = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("401"), "{error}");
            assert!(error.contains("Invalid app code"), "{error}");
        }

        #[tokio::test]
        async fn a_server_error_is_a_failure() {
            let (port, _server) = serve_once(status(500, "Internal Server Error", "boom!")).await;

            let error = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("500"), "{error}");
        }

        #[tokio::test]
        async fn fetches_a_devices_columns() {
            let (port, server) = serve_once(ok(json!({
                "code": 200,
                "data": { "id": "3", "hostname": "srv1",
                          "custom_acme_allowed_names": "machine.example.com" }
            })))
            .await;

            let fields = client(port).device(3).await.unwrap();
            assert_eq!(
                fields["custom_acme_allowed_names"],
                json!("machine.example.com")
            );

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /api/acme/devices/3/ HTTP/1.1"),
                "{request}"
            );
        }

        /// phpIPAM answers a device it has no row for with `200` and an empty
        /// array rather than a 404. Not an error — it simply lends no names.
        #[tokio::test]
        async fn an_absent_device_lends_no_names_without_erroring() {
            let (port, _server) = serve_once(ok(json!({ "code": 200, "data": [] }))).await;

            assert!(client(port).device(3).await.unwrap().is_empty());
        }

        #[tokio::test]
        async fn a_device_response_of_the_wrong_shape_is_an_error() {
            let (port, _server) = serve_once(ok(json!({ "data": "nope" }))).await;

            let error = client(port).device(3).await.unwrap_err();
            assert!(error.contains("data is a string"), "{error}");
        }

        #[tokio::test]
        async fn a_search_response_of_the_wrong_shape_is_an_error() {
            let (port, _server) = serve_once(ok(json!({ "data": "nope" }))).await;

            let error = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(
                error.contains("unexpected addresses/search data"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn an_unreadable_envelope_is_an_error() {
            let (port, _server) = serve_once(ok(json!([1, 2, 3]))).await;

            let error = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(
                error.contains("unexpected addresses/search response"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn a_closed_port_is_a_connect_error() {
            let port = closed_port().await;

            let error = client(port)
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("connecting to 127.0.0.1"), "{error}");
        }
    }

    /// The same proof the NetBox client carries: `insecure_skip_verify` is not
    /// merely declarative.
    mod tls {
        use super::*;

        fn https_config(port: u16, skip: bool) -> PhpIpamConfig {
            PhpIpamConfig {
                insecure_skip_verify: skip,
                ..config(&format!("https://localhost:{port}"))
            }
        }

        #[tokio::test]
        async fn a_self_signed_phpipam_is_refused_by_default() {
            let port = serve_once_tls(json!({ "data": [] })).await;

            let error = PhpIpamClient::new(&https_config(port, false), test_resolver())
                .unwrap()
                .search("10.0.0.5".parse().unwrap())
                .await
                .unwrap_err();
            assert!(error.contains("TLS handshake"), "{error}");
        }

        #[tokio::test]
        async fn skipping_verification_reaches_the_same_phpipam() {
            let port = serve_once_tls(json!({
                "data": [{ "hostname": "host.example.com" }]
            }))
            .await;

            let objects = PhpIpamClient::new(&https_config(port, true), test_resolver())
                .unwrap()
                .search("10.0.0.5".parse().unwrap())
                .await
                .expect("skip-verify must accept a self-signed certificate")
                .unwrap();
            assert_eq!(objects[0].hostname, "host.example.com");
        }
    }
}
