//! The transport half of this server's four outbound HTTP clients.
//!
//! Deliberately **not** a shared client type. What
//! [`challenge::http_01`](crate::challenge::http_01),
//! [`signer::acme_proxy::client`](crate::signer::acme_proxy::client),
//! [`filter::netbox::client`](crate::filter::netbox::client) and
//! [`notify::mattermost`](crate::notify::mattermost) have in common is
//! *plumbing*: pick a URL apart into host, scheme and port; connect through the
//! shared resolver; wrap in TLS with the right SNI; hand the stream to hyper and
//! spawn the connection task. That part was written out four times, and
//! `client_tls_config` twice byte-for-byte.
//!
//! What differs is *policy*, and each of those modules' comment defending
//! "per-module locality" is right about policy and wrong about plumbing:
//! `http_01` must **not** validate the peer certificate (RFC 8555 §8.3 — what
//! it carries is the proof, not an identity) while the other three must; each
//! caps its response body differently; each has its own headers and its own
//! error type. So this module owns the plumbing and nothing else.

use std::sync::Arc;

use hyper::body::Body;
use hyper_util::rt::TokioIo;
use url::Url;

use crate::dns::Resolver;

/// Where an outbound request is going, once its URL has been picked apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
    pub https: bool,
}

impl Endpoint {
    /// Splits a URL into host, port and scheme, rejecting anything this server
    /// will not speak.
    ///
    /// Only `http` and `https`: an outbound client here talks to a CA, a NetBox
    /// instance or a webhook, and a `file:` or `gopher:` URL in a configuration
    /// field is a mistake worth naming rather than a scheme to support.
    pub(crate) fn from_url(url: &Url) -> Result<Self, String> {
        let host = url
            .host_str()
            .ok_or_else(|| format!("{url} has no host"))?
            .to_string();
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            other => return Err(format!("unsupported scheme: {other}")),
        };
        let port = url
            .port_or_known_default()
            .unwrap_or(if https { 443 } else { 80 });

        Ok(Self { host, port, https })
    }

    /// `host` or `host:port` — what a `Host` header should carry.
    pub(crate) fn authority(&self) -> String {
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// The webpki root store, for the clients that talk to a real remote service
/// whose certificate is the only thing establishing who it is.
///
/// The fourth client, `challenge::http_01`, deliberately validates nothing —
/// see [`crate::challenge::tls_alpn_01::accept_any_client_config`].
///
/// The provider is passed explicitly rather than installed as a process
/// default: `CryptoProvider::install_default` panics on a second call, which
/// would make test ordering matter.
pub(crate) fn webpki_tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Connects to `endpoint` and completes the HTTP/1 handshake, returning the
/// sender half.
///
/// Connects through `resolver` rather than `TcpStream::connect`, so
/// `dns.resolver` governs every outbound hop the way it already governs the
/// `dns-01` TXT lookup — and so a dual-stack answer whose first address is
/// unreachable falls back instead of failing outright. Three of the four
/// clients used to bypass that, which meant an operator running a split-horizon
/// estate would find NetBox and their upstream CA resolving differently from
/// the challenge validators, with nothing in the code saying so.
///
/// The connection task is spawned and detached: hyper drives the connection
/// there while the caller uses the sender, and it ends when the sender drops.
pub(crate) async fn connect<B>(
    resolver: &dyn Resolver,
    endpoint: &Endpoint,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<hyper::client::conn::http1::SendRequest<B>, String>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = crate::dns::connect(resolver, &endpoint.host, endpoint.port)
        .await
        .map_err(|error| format!("connecting to {}:{}: {error}", endpoint.host, endpoint.port))?;

    if endpoint.https {
        let server_name = rustls_pki_types::ServerName::try_from(endpoint.host.clone())
            .map_err(|error| format!("{}: {error}", endpoint.host))?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("TLS handshake with {}: {error}", endpoint.host))?;
        spawn_handshake(TokioIo::new(stream)).await
    } else {
        spawn_handshake(TokioIo::new(stream)).await
    }
}

/// The `http1::handshake` + detached connection task the four clients each
/// wrote out identically.
async fn spawn_handshake<B, I>(io: I) -> Result<hyper::client::conn::http1::SendRequest<B>, String>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| format!("HTTP handshake: {error}"))?;
    tokio::spawn(async move {
        // Nothing to do with the result: the caller learns about a broken
        // connection from its own request future failing.
        let _ = connection.await;
    });
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    #[test]
    fn default_ports_follow_the_scheme() {
        let http = Endpoint::from_url(&url("http://example.com/x")).unwrap();
        assert_eq!(http.port, 80);
        assert!(!http.https);
        assert_eq!(http.host, "example.com");

        let https = Endpoint::from_url(&url("https://example.com/x")).unwrap();
        assert_eq!(https.port, 443);
        assert!(https.https);
    }

    #[test]
    fn an_explicit_port_wins() {
        let endpoint = Endpoint::from_url(&url("https://example.com:8443/x")).unwrap();
        assert_eq!(endpoint.port, 8443);
        assert!(endpoint.https);
    }

    /// The `Host` header omits the port when it is the scheme's default, which
    /// is what a server expects to see.
    #[test]
    fn the_authority_omits_a_default_port() {
        assert_eq!(
            Endpoint::from_url(&url("https://example.com/x"))
                .unwrap()
                .authority(),
            "example.com"
        );
        assert_eq!(
            Endpoint::from_url(&url("http://example.com/x"))
                .unwrap()
                .authority(),
            "example.com"
        );
        assert_eq!(
            Endpoint::from_url(&url("https://example.com:8443/x"))
                .unwrap()
                .authority(),
            "example.com:8443"
        );
    }

    #[test]
    fn a_url_with_no_host_is_refused() {
        let error = Endpoint::from_url(&url("file:///etc/passwd")).unwrap_err();
        assert!(
            error.contains("no host") || error.contains("unsupported scheme"),
            "{error}"
        );
    }

    #[test]
    fn an_unsupported_scheme_is_refused() {
        let error = Endpoint::from_url(&url("ftp://example.com/x")).unwrap_err();
        assert!(error.contains("unsupported scheme"), "{error}");
    }

    #[test]
    fn an_ipv6_literal_survives_the_round_trip() {
        let endpoint = Endpoint::from_url(&url("https://[2001:db8::1]:8443/x")).unwrap();
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.authority(), "[2001:db8::1]:8443");
    }

    #[test]
    fn the_webpki_config_builds() {
        let config = webpki_tls_config();
        assert!(config.alpn_protocols.is_empty());
    }
}
