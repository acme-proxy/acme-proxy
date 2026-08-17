//! The JSON-over-HTTP transport both IPAM backends speak.
//!
//! ## Why this exists where the four other clients did not get one
//!
//! [`http_client`](crate::http_client) already owns the plumbing every outbound
//! client in this tree shares — picking a URL apart, connecting through the
//! shared resolver, the TLS handshake, the hyper handshake — and its module doc
//! is explicit that *policy* stays per-module, because
//! [`challenge::http_01`](crate::challenge::http_01) must validate no
//! certificate at all while the others must, and each caps its body, sets its
//! headers and shapes its errors differently.
//!
//! Two IPAM backends are the case that argument does not cover: they have the
//! *same* policy. Both authenticate with a static token in a header, both read
//! a small JSON document, both trust the public roots plus an operator's own
//! CA, both treat an unreachable inventory as this server's failure rather than
//! the client's. Writing that out twice is the shape
//! [`script_hook`](crate::script_hook) exists to prevent — it owns the hardening
//! the three `custom` hooks used to repeat token-for-token.
//!
//! What stays per-backend is what genuinely differs: the header name, the paths,
//! the wire shapes, and — the reason [`JsonApiError`] carries a status —
//! **what a 404 means**. NetBox answers an unknown address with an empty result
//! list; phpIPAM answers it with a 404. One is a failure and one is an answer,
//! and only the backend knows which.
//!
//! ## TLS
//!
//! Unlike the challenge validators — where the certificate is deliberately not
//! checked because the *proof* is what matters — an inventory's certificate is
//! the only thing identifying the service whose answers decide who may have a
//! name certified. So the public roots apply, plus any operator-supplied CA,
//! and the one way to switch that off is explicit, logged at startup and
//! documented as temporary.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, StatusCode, header::HeaderName};
use serde_json::Value;
use url::Url;

/// Cap on an inventory response body. An address query returns a handful of
/// small objects; anything approaching this is not an answer a filter can use.
use crate::http_client::{MAX_RESPONSE_BYTES, error_excerpt};

/// Why a request to an inventory did not produce a usable document.
///
/// `status` is `Some` only when the server answered at all, which is what lets
/// a backend read one particular code as an answer rather than a failure. The
/// message is already worded for an operator and names the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonApiError {
    pub status: Option<StatusCode>,
    pub message: String,
}

impl JsonApiError {
    fn transport(message: String) -> Self {
        Self {
            status: None,
            message,
        }
    }
}

impl std::fmt::Display for JsonApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// A base URL, a fixed set of headers, and one TLS configuration.
pub(crate) struct JsonApi {
    /// Base URL with no trailing slash, so an instance under a subpath keeps it.
    base: String,
    headers: Vec<(HeaderName, String)>,
    tls: Arc<rustls::ClientConfig>,
    /// The resolver every outbound hop in this server shares, so a split-horizon
    /// estate does not have the inventory resolving differently from the
    /// challenge validators.
    resolver: Arc<dyn crate::dns::Resolver>,
    /// The forward proxy, if any, this inventory is reached through.
    proxies: Arc<crate::proxy::OutboundProxies>,
}

impl std::fmt::Debug for JsonApi {
    /// Never renders the headers: one of them is the credential.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JsonApi")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl JsonApi {
    /// Validates the URL and keeps the headers every request will carry.
    ///
    /// `setting` is the configuration key the URL came from, so an error names
    /// what an operator has to go and edit. Nothing is contacted here.
    pub(crate) fn new(
        url: &str,
        setting: &str,
        headers: Vec<(HeaderName, String)>,
        tls: Arc<rustls::ClientConfig>,
        resolver: Arc<dyn crate::dns::Resolver>,
        proxies: Arc<crate::proxy::OutboundProxies>,
    ) -> anyhow::Result<Self> {
        let parsed = Url::parse(url.trim())
            .map_err(|error| anyhow::anyhow!("{setting}: {url} is not a URL: {error}"))?;
        // Restricted to the two schemes an inventory is served over — which
        // also guarantees a host, since `url` requires one for both.
        match parsed.scheme() {
            "http" | "https" => {}
            other => anyhow::bail!("{setting}: unsupported scheme {other}, expected http or https"),
        }

        Ok(Self {
            base: parsed.as_str().trim_end_matches('/').to_string(),
            headers,
            tls,
            resolver,
            proxies,
        })
    }

    /// The base URL, with no trailing slash.
    #[cfg(test)]
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// One `GET`, returning the parsed JSON body.
    pub(crate) async fn get(&self, path_and_query: &str) -> Result<Value, JsonApiError> {
        let target = format!("{}{path_and_query}", self.base);
        let url = Url::parse(&target)
            .map_err(|error| JsonApiError::transport(format!("{target} is not a URL: {error}")))?;

        let endpoint = crate::http_client::Endpoint::from_url(&url).map_err(|error| {
            JsonApiError::transport(format!("{target} is not a usable endpoint: {error}"))
        })?;

        let connection = crate::http_client::connect(
            self.resolver.as_ref(),
            &self.proxies,
            &endpoint,
            &self.tls,
        )
        .await
        .map_err(JsonApiError::transport)?;

        // Origin-form directly, absolute-form when this connection forwards
        // through a proxy — which is why the connection is opened first.
        let request_target = connection.request_target(&url);

        // hyper 1.x's low-level client sends exactly what it is given, `Host`
        // included — see `HyperFetcher`, whose loopback test is what caught it.
        let mut builder = Request::builder()
            .uri(request_target)
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::ACCEPT, "application/json")
            .header(hyper::header::CONNECTION, "close");
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Empty::<Bytes>::new())
            .map_err(|error| JsonApiError::transport(format!("building the request: {error}")))?;

        exchange(connection, request, &url).await
    }
}

/// Sends the request over an established stream and parses the answer.
async fn exchange(
    mut connection: crate::http_client::Connection<Empty<Bytes>>,
    request: Request<Empty<Bytes>>,
    url: &Url,
) -> Result<Value, JsonApiError> {
    let response = connection
        .send_request(request)
        .await
        .map_err(|error| JsonApiError::transport(format!("request to {url} failed: {error}")))?;

    let status = response.status();
    // `Limited` errors once the cap is passed; a body that large is not an
    // answer worth parsing, so it is refused rather than read further.
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| {
            JsonApiError::transport(format!(
                "response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
            ))
        })?
        .to_bytes();

    if !status.is_success() {
        // A 401/403 is a misconfigured token and a 5xx is an outage: both are
        // this server failing to reach a decision, never a statement about the
        // client. A backend that reads one particular code as an answer says so
        // itself, off `status`.
        let excerpt = error_excerpt(&body);
        return Err(JsonApiError {
            status: Some(status),
            message: format!("{url} answered {status}: {excerpt}"),
        });
    }

    serde_json::from_slice(&body).map_err(|error| JsonApiError {
        status: Some(status),
        message: format!("{url} returned unreadable JSON: {error}"),
    })
}

/// The rustls configuration an inventory client dials with.
///
/// `setting` names the `ca_cert_path` key, so an unusable certificate is
/// reported against the key that has to change.
pub(crate) fn tls_config(
    ca_cert_path: &str,
    insecure_skip_verify: bool,
    setting: &str,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    if insecure_skip_verify {
        // The same "accept anything" configuration the challenge validators
        // use, reused rather than re-derived — it already passes the crypto
        // provider explicitly, which `install_default` must never be used for.
        // No ALPN: this is an ordinary https request.
        return crate::challenge::tls_alpn_01::accept_any_client_config(&[]);
    }

    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    if !ca_cert_path.trim().is_empty() {
        let path = std::path::Path::new(ca_cert_path.trim());
        let extra = crate::pemfile::read_certificates(path)
            .map_err(|error| anyhow::anyhow!("{setting}: {error}"))?;
        for certificate in extra {
            roots.add(certificate).map_err(|error| {
                anyhow::anyhow!(
                    "{setting}: {} is not a usable CA certificate: {error}",
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

/// Loopback servers both backends' client tests drive the real transport
/// against. A stub trait impl proves the policy; only these prove the request
/// line and the headers are what the product actually needs.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// These reach a loopback listener by IP literal, which `dns::connect`
    /// short-circuits without a lookup, so the system resolver is fine.
    pub(crate) fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    /// Serves one canned response and returns the request it received.
    pub(crate) async fn serve_once(response: String) -> (u16, tokio::task::JoinHandle<String>) {
        serve_many(vec![response]).await
    }

    /// Serves `responses` in order over as many connections, and returns every
    /// request text joined by a form feed — a backend that makes several
    /// requests to answer one question needs all of them asserted on.
    pub(crate) async fn serve_many(
        responses: Vec<String>,
    ) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                seen.push(String::from_utf8_lossy(&buffer[..read]).into_owned());
            }
            seen.join("\u{c}")
        });

        (port, handle)
    }

    /// An HTTP/1.1 response with `body` as its JSON payload.
    pub(crate) fn ok(body: Value) -> String {
        status(200, "OK", &body.to_string())
    }

    /// An HTTP/1.1 response with a hand-written status and body. The
    /// `Content-Length` is computed, never guessed — a wrong one leaves hyper
    /// waiting for a body that never arrives.
    pub(crate) fn status(code: u16, reason: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A port nothing is listening on: bound then dropped, so it is almost
    /// certainly free.
    pub(crate) async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Serves one https request with a self-signed certificate for `localhost`,
    /// then stops. Both backends use it to prove `insecure_skip_verify` does
    /// what it says: the same server is unreachable with verification on and
    /// readable with it off.
    pub(crate) async fn serve_once_tls(body: Value) -> u16 {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::{ServerConfig, sign::CertifiedKey};
        use tokio_rustls::TlsAcceptor;

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
        let response = ok(body);

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // A client that refuses the certificate fails here, which is
            // exactly what one of the two tests is asserting.
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let mut buffer = vec![0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        port
    }

    /// A JSON body larger than [`MAX_RESPONSE_BYTES`], for the cap test.
    pub(crate) fn oversized_body() -> String {
        let filler = "x".repeat(MAX_RESPONSE_BYTES + 1024);
        json!({ "results": [], "filler": filler }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    fn api(port: u16, path: &str) -> JsonApi {
        JsonApi::new(
            &format!("http://127.0.0.1:{port}{path}"),
            "ipam.test.url",
            vec![(hyper::header::AUTHORIZATION, "Token t0ken".to_string())],
            tls_config("", false, "ipam.test.ca_cert_path").unwrap(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap()
    }

    // ------------------------------------------------------ startup checks

    #[test]
    fn an_unparsable_url_names_the_setting() {
        let error = JsonApi::new(
            "not a url",
            "ipam.netbox.url",
            Vec::new(),
            tls_config("", false, "x").unwrap(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("ipam.netbox.url"), "{error}");
    }

    #[test]
    fn a_non_http_scheme_is_a_startup_error() {
        let error = JsonApi::new(
            "ftp://netbox.example.com",
            "ipam.netbox.url",
            Vec::new(),
            tls_config("", false, "x").unwrap(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unsupported scheme ftp"), "{error}");
    }

    /// A base URL under a subpath keeps it: the API path is appended, never
    /// substituted the way `Url::join` on an absolute path would.
    #[test]
    fn a_base_url_under_a_subpath_is_preserved() {
        let api = JsonApi::new(
            "https://example.com/netbox/",
            "ipam.netbox.url",
            Vec::new(),
            tls_config("", false, "x").unwrap(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap();
        assert_eq!(api.base(), "https://example.com/netbox");
    }

    #[test]
    fn the_debug_impl_never_renders_a_header() {
        let api = JsonApi::new(
            "https://example.com",
            "ipam.netbox.url",
            vec![(hyper::header::AUTHORIZATION, "Token t0ken".to_string())],
            tls_config("", false, "x").unwrap(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap();
        let rendered = format!("{api:?}");
        assert!(!rendered.contains("t0ken"), "{rendered}");
    }

    #[test]
    fn a_missing_ca_certificate_names_the_setting() {
        let error = tls_config("/nonexistent/ca.pem", false, "ipam.netbox.ca_cert_path")
            .unwrap_err()
            .to_string();
        assert!(error.contains("ipam.netbox.ca_cert_path"), "{error}");
    }

    /// With verification off nothing is loaded, so even an unusable
    /// `ca_cert_path` cannot fail startup — the branch never opens it.
    #[test]
    fn skipping_verification_ignores_the_ca_certificate_entirely() {
        tls_config("/nonexistent/ca.pem", true, "ipam.netbox.ca_cert_path")
            .expect("skip-verify must not read ca_cert_path");
    }

    // ------------------------------------------------------------ requests

    #[tokio::test]
    async fn sends_the_configured_headers_and_parses_the_body() {
        let (port, server) = serve_once(ok(json!({ "results": [] }))).await;

        let body = api(port, "").get("/api/thing/?a=b").await.unwrap();
        assert_eq!(body, json!({ "results": [] }));

        let request = server.await.unwrap();
        assert!(
            request.starts_with("GET /api/thing/?a=b HTTP/1.1"),
            "{request}"
        );
        assert!(request.contains("authorization: Token t0ken"), "{request}");
        assert!(
            request.contains(&format!("host: 127.0.0.1:{port}")),
            "{request}"
        );
        assert!(request.contains("accept: application/json"), "{request}");
        assert!(request.contains("user-agent: acme-proxy"), "{request}");
    }

    #[tokio::test]
    async fn a_subpath_base_url_prefixes_the_api_path() {
        let (port, server) = serve_once(ok(json!({}))).await;

        api(port, "/netbox").get("/api/thing/").await.unwrap();

        let request = server.await.unwrap();
        assert!(
            request.starts_with("GET /netbox/api/thing/ HTTP/1.1"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_server_error_is_reported_with_its_status_and_an_excerpt() {
        let (port, _server) = serve_once(status(500, "Internal Server Error", "boom!")).await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert_eq!(error.status, Some(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(error.message.contains("boom!"), "{error}");
    }

    /// A refused token is the operator's problem, not the client's — it must
    /// surface as an error the caller turns into a 500, never as an empty
    /// answer that would read as "this address owns no names".
    #[tokio::test]
    async fn a_refused_token_is_reported_rather_than_parsed() {
        let (port, _server) = serve_once(status(
            401,
            "Unauthorized",
            r#"{"detail":"Invalid token header."}"#,
        ))
        .await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert_eq!(error.status, Some(StatusCode::UNAUTHORIZED));
        assert!(error.message.contains("Invalid token header"), "{error}");
    }

    /// The status is what lets phpIPAM read a 404 as an answer while NetBox
    /// keeps reading it as a failure.
    #[tokio::test]
    async fn a_404_is_reported_with_its_status_intact() {
        let (port, _server) = serve_once(status(404, "Not Found", r#"{"code":404}"#)).await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert_eq!(error.status, Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn an_unreadable_body_is_an_error() {
        let (port, _server) = serve_once(status(200, "OK", "not json!")).await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert!(error.message.contains("unreadable JSON"), "{error}");
    }

    /// A body past the cap is refused rather than read further — and it is a
    /// transport failure, with no status, since nothing was parsed.
    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let (port, _server) = serve_once(status(200, "OK", &oversized_body())).await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert!(error.message.contains("exceeds"), "{error}");
        assert_eq!(error.status, None);
    }

    #[tokio::test]
    async fn a_closed_port_is_a_connect_error() {
        let port = closed_port().await;

        let error = api(port, "").get("/api/thing/").await.unwrap_err();
        assert_eq!(error.status, None);
        assert!(error.message.contains("connecting to 127.0.0.1"), "{error}");
    }

    #[test]
    fn the_error_displays_as_its_message() {
        let error = JsonApiError::transport("nope".to_string());
        assert_eq!(error.to_string(), "nope");
    }
}
