//! The transport half of this server's four outbound HTTP clients.
//!
//! Deliberately **not** a shared client type. What
//! [`challenge::http_01`](crate::challenge::http_01),
//! [`signer::relay::client`](crate::signer::relay::client),
//! [`ipam::http`](crate::ipam::http) and
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

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Body;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;

use crate::dns::Resolver;
use crate::proxy::{OutboundProxies, ProxyTarget};

/// How much of a proxy's refusal is quoted back. A `407` body is a page, and
/// what an operator needs from it is the first line.
const MAX_PROXY_ERROR_BYTES: usize = 512;

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

    /// An endpoint for a TLS connection that never came from a URL —
    /// [`crate::challenge::tls_alpn_01`]'s probe, which has an identifier and a
    /// port and no scheme at all.
    pub(crate) fn tls(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            https: true,
        }
    }

    /// The host with any IPv6 brackets removed — the form `IpAddr::from_str`
    /// and a resolver want.
    ///
    /// [`Url::host_str`] hands back `[2001:db8::1]` for a literal, which
    /// [`crate::dns::connect`] cannot parse as an address and would therefore
    /// try to *resolve*. [`authority`](Self::authority) keeps the brackets,
    /// because that is the form a `Host` header and a request line need.
    pub(crate) fn host_for_lookup(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(&self.host)
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

    /// Always `host:port`, including a port [`authority`](Self::authority)
    /// would elide.
    ///
    /// A `CONNECT` request-target is authority-form and RFC 9110 §9.3.6 requires
    /// both components: a proxy handed `CONNECT example.com` refuses it. This is
    /// the one place the distinction bites, and it is why the two spellings are
    /// separate methods rather than one with a flag.
    pub(crate) fn connect_authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
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

/// The transport under an outbound connection: a direct socket, or one
/// tunnelled through a forward proxy's `CONNECT`.
///
/// An enum rather than `Box<dyn AsyncRead + AsyncWrite + Unpin + Send>`: the
/// delegation is mechanical, it costs no allocation, and it keeps the concrete
/// `TcpStream` visible to anyone reading the direct path.
pub(crate) enum ClientStream {
    Direct(tokio::net::TcpStream),
    Tunnelled(TokioIo<hyper::upgrade::Upgraded>),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tunnelled(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tunnelled(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_flush(context),
            Self::Tunnelled(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tunnelled(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// How the request line must address the target on a given connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestForm {
    /// `GET /path?query` — a direct connection, or one inside a tunnel.
    /// RFC 9112 §3.2.1 makes this the form for an origin server.
    Origin,
    /// `GET http://host/path?query` — plain HTTP forwarded by a proxy, the one
    /// case §3.2.2 is for.
    Absolute,
}

/// An established HTTP/1 connection, plus how requests on it must be addressed
/// and credentialed.
///
/// Returned instead of a bare `SendRequest` because those two facts are
/// properties of *this connection*, not of the caller: a request built for a
/// direct connection is malformed on a forwarding one, and the other way round.
pub(crate) struct Connection<B> {
    sender: hyper::client::conn::http1::SendRequest<B>,
    form: RequestForm,
    /// Carried only on a forwarding connection — see
    /// [`send_request`](Self::send_request).
    proxy_authorization: Option<String>,
}

impl<B> Connection<B>
where
    B: Body + 'static,
{
    /// The request-line target for `url` on this connection.
    pub(crate) fn request_target(&self, url: &Url) -> String {
        match self.form {
            RequestForm::Absolute => url.as_str().to_string(),
            RequestForm::Origin => {
                let mut target = url.path().to_string();
                if let Some(query) = url.query() {
                    target.push('?');
                    target.push_str(query);
                }
                target
            }
        }
    }

    /// Sends `request`, attaching `Proxy-Authorization` when this connection
    /// reaches the origin *through* a proxy in the clear.
    ///
    /// Attached here rather than left to the caller so a new caller cannot
    /// forget it — and never on a tunnelled connection: the credential was
    /// already spent on the `CONNECT`, and repeating it inside the tunnel would
    /// hand it to the origin server.
    pub(crate) async fn send_request(
        &mut self,
        mut request: hyper::Request<B>,
    ) -> hyper::Result<hyper::Response<hyper::body::Incoming>> {
        if let Some(credential) = &self.proxy_authorization
            && let Ok(value) = hyper::header::HeaderValue::from_str(credential)
        {
            request
                .headers_mut()
                .insert(hyper::header::PROXY_AUTHORIZATION, value);
        }
        self.sender.send_request(request).await
    }
}

/// Opens a byte stream to `endpoint`, tunnelling when a proxy applies.
///
/// For callers that layer their own TLS — [`crate::challenge::tls_alpn_01`]'s
/// probe is the one. When a proxy is selected this always uses `CONNECT`,
/// including for a cleartext endpoint: the caller asked for an end-to-end
/// stream, not a forwarding relationship.
pub(crate) async fn connect_stream(
    resolver: &dyn Resolver,
    proxies: &OutboundProxies,
    endpoint: &Endpoint,
) -> Result<ClientStream, String> {
    match proxies.select(endpoint) {
        Some(proxy) => tunnel(resolver, proxy, endpoint)
            .await
            .map(ClientStream::Tunnelled),
        None => dial(resolver, endpoint).await.map(ClientStream::Direct),
    }
}

/// Connects to `endpoint` and completes the HTTP/1 handshake.
///
/// Connects through `resolver` rather than `TcpStream::connect`, so
/// `dns.resolver` governs every outbound hop the way it already governs the
/// `dns-01` TXT lookup — and so a dual-stack answer whose first address is
/// unreachable falls back instead of failing outright. Three of the four
/// clients used to bypass that, which meant an operator running a split-horizon
/// estate would find NetBox and their upstream CA resolving differently from
/// the challenge validators, with nothing in the code saying so.
///
/// Four shapes, and the table is the whole of what a proxy changes here:
///
/// | proxy | `https` | transport | request form |
/// | --- | --- | --- | --- |
/// | none | no | TCP to the origin | origin |
/// | none | yes | TCP + TLS to the origin | origin |
/// | some | yes | `CONNECT` tunnel, TLS **inside** it | origin |
/// | some | no | TCP to the proxy | absolute + `Proxy-Authorization` |
///
/// There is deliberately no timeout here: every caller already wraps the whole
/// operation in one, so a black-holed proxy surfaces as the same failure as a
/// black-holed origin rather than as a second budget to keep in step.
///
/// The connection task is spawned and detached: hyper drives the connection
/// there while the caller uses the sender, and it ends when the sender drops.
pub(crate) async fn connect<B>(
    resolver: &dyn Resolver,
    proxies: &OutboundProxies,
    endpoint: &Endpoint,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<Connection<B>, String>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let proxy = proxies.select(endpoint);

    // Cleartext through a proxy is the one case that is not a tunnel: the proxy
    // is the peer, and it learns the target from the request line instead.
    if let Some(proxy) = proxy
        && !endpoint.https
    {
        let stream = dial(resolver, proxy.endpoint())
            .await
            .map_err(|error| format!("connecting to proxy {}: {error}", proxy.redacted()))?;
        let sender = spawn_handshake(TokioIo::new(stream)).await?;
        return Ok(Connection {
            sender,
            form: RequestForm::Absolute,
            proxy_authorization: proxy.authorization().map(str::to_string),
        });
    }

    let stream = match proxy {
        Some(proxy) => ClientStream::Tunnelled(tunnel(resolver, proxy, endpoint).await?),
        None => ClientStream::Direct(dial(resolver, endpoint).await?),
    };

    let sender = if endpoint.https {
        // SNI and validation are against the *origin*, never the proxy: the
        // tunnel is a pipe, and the certificate at the far end is the origin's.
        let server_name =
            rustls_pki_types::ServerName::try_from(endpoint.host_for_lookup().to_string())
                .map_err(|error| format!("{}: {error}", endpoint.host))?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("TLS handshake with {}: {error}", endpoint.host))?;
        spawn_handshake(TokioIo::new(stream)).await?
    } else {
        spawn_handshake(TokioIo::new(stream)).await?
    };

    Ok(Connection {
        sender,
        form: RequestForm::Origin,
        proxy_authorization: None,
    })
}

/// The TCP half, named so the error says which hop failed.
async fn dial(
    resolver: &dyn Resolver,
    endpoint: &Endpoint,
) -> Result<tokio::net::TcpStream, String> {
    crate::dns::connect(resolver, endpoint.host_for_lookup(), endpoint.port)
        .await
        .map_err(|error| format!("connecting to {}:{}: {error}", endpoint.host, endpoint.port))
}

/// Opens a `CONNECT` tunnel to `endpoint` through `proxy`.
///
/// The proxy is reached through the shared resolver too: `dns.resolver` is
/// documented as governing every lookup this server makes, and a proxy named by
/// hostname is a lookup.
async fn tunnel(
    resolver: &dyn Resolver,
    proxy: &ProxyTarget,
    endpoint: &Endpoint,
) -> Result<TokioIo<hyper::upgrade::Upgraded>, String> {
    let socket = dial(resolver, proxy.endpoint())
        .await
        .map_err(|error| format!("connecting to proxy {}: {error}", proxy.redacted()))?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
        .await
        .map_err(|error| format!("HTTP handshake with proxy {}: {error}", proxy.redacted()))?;

    // `with_upgrades` is load-bearing: without it the connection task never
    // surrenders the socket, `hyper::upgrade::on` never resolves, and the tunnel
    // hangs rather than failing — a far worse shape than an error.
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });

    let authority = endpoint.connect_authority();
    // No `Connection: close` (a proxy honouring it would close the tunnel we
    // just asked for) and no `Proxy-Connection`, which no RFC defines.
    let mut builder = hyper::Request::connect(&authority)
        .header(hyper::header::HOST, &authority)
        .header(hyper::header::USER_AGENT, "acme-proxy");
    if let Some(credential) = proxy.authorization() {
        builder = builder.header(hyper::header::PROXY_AUTHORIZATION, credential);
    }
    let request = builder
        .body(Empty::<Bytes>::new())
        .map_err(|error| format!("building the CONNECT request: {error}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("CONNECT {authority} via {}: {error}", proxy.redacted()))?;

    // The status is checked *before* asking for the upgrade: a non-2xx has no
    // pending upgrade to hand over, and its body is the whole diagnosis —
    // "407 Proxy Authentication Required" is something an operator can act on,
    // and they will never see the proxy's own log.
    if !response.status().is_success() {
        let status = response.status();
        let excerpt = Limited::new(response.into_body(), MAX_PROXY_ERROR_BYTES)
            .collect()
            .await
            .map(|body| {
                String::from_utf8_lossy(&body.to_bytes())
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(200)
                    .collect::<String>()
            })
            .unwrap_or_default();
        return Err(format!(
            "proxy {} refused CONNECT {authority}: {status} {excerpt}",
            proxy.redacted()
        ));
    }

    hyper::upgrade::on(response)
        .await
        .map(TokioIo::new)
        .map_err(|error| {
            format!(
                "proxy {} did not hand over the tunnel to {authority}: {error}",
                proxy.redacted()
            )
        })
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

    /// The brackets a `Host` header needs are exactly what
    /// `IpAddr::from_str` chokes on, so the connect path strips them — without
    /// this, an IPv6-literal URL is handed to the resolver as a name.
    #[test]
    fn an_ipv6_literal_loses_its_brackets_for_a_lookup() {
        let endpoint = Endpoint::from_url(&url("https://[2001:db8::1]:8443/x")).unwrap();
        assert_eq!(endpoint.host_for_lookup(), "2001:db8::1");
        assert!(
            endpoint
                .host_for_lookup()
                .parse::<std::net::IpAddr>()
                .is_ok()
        );

        let named = Endpoint::from_url(&url("https://example.com/x")).unwrap();
        assert_eq!(named.host_for_lookup(), "example.com");
    }

    #[test]
    fn the_webpki_config_builds() {
        let config = webpki_tls_config();
        assert!(config.alpn_protocols.is_empty());
    }

    /// A `CONNECT` target must keep the port even when it is the scheme's
    /// default — `authority()` elides it, and `CONNECT example.com` is refused
    /// by every real proxy.
    #[test]
    fn a_connect_authority_always_carries_the_port() {
        let https = Endpoint::from_url(&url("https://example.com/x")).unwrap();
        assert_eq!(https.authority(), "example.com");
        assert_eq!(https.connect_authority(), "example.com:443");

        let http = Endpoint::from_url(&url("http://example.com/x")).unwrap();
        assert_eq!(http.connect_authority(), "example.com:80");

        let literal = Endpoint::from_url(&url("https://[2001:db8::1]/x")).unwrap();
        assert_eq!(literal.connect_authority(), "[2001:db8::1]:443");
    }

    #[test]
    fn an_endpoint_can_be_built_without_a_url() {
        let endpoint = Endpoint::tls("example.com", 8443);
        assert!(endpoint.https);
        assert_eq!(endpoint.connect_authority(), "example.com:8443");
    }

    /// The request line is a property of the connection, not the caller: the
    /// same URL is spelled two ways depending on who the peer is.
    #[test]
    fn the_request_target_follows_the_form() {
        let target = url("http://example.com/a/b?c=d&e=f");
        for (form, expected) in [
            (RequestForm::Origin, "/a/b?c=d&e=f"),
            (RequestForm::Absolute, "http://example.com/a/b?c=d&e=f"),
        ] {
            let connection = Connection::<Empty<Bytes>> {
                sender: unreachable_sender(),
                form,
                proxy_authorization: None,
            };
            assert_eq!(connection.request_target(&target), expected);
        }

        let no_query = url("http://example.com/a");
        let connection = Connection::<Empty<Bytes>> {
            sender: unreachable_sender(),
            form: RequestForm::Origin,
            proxy_authorization: None,
        };
        assert_eq!(connection.request_target(&no_query), "/a");
    }

    /// A `SendRequest` for a connection whose peer never answers. The pure
    /// `request_target` tests need the field, not a live socket.
    fn unreachable_sender() -> hyper::client::conn::http1::SendRequest<Empty<Bytes>> {
        let (sender, connection) = futures_lite_block_on(async {
            let (client, _server) = tokio::io::duplex(64);
            hyper::client::conn::http1::handshake(TokioIo::new(client))
                .await
                .unwrap()
        });
        drop(connection);
        sender
    }

    /// A one-shot current-thread runtime, so the helper above stays usable from
    /// a plain `#[test]`.
    fn futures_lite_block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// The transport against a loopback proxy that really speaks `CONNECT`.
    ///
    /// Every case builds its proxies with `OutboundProxies::always`, because
    /// `select` bypasses loopback unconditionally — through the ordinary
    /// constructor a proxy on `127.0.0.1` would never be selected, and every
    /// one of these would pass for the wrong reason.
    ///
    /// Two of them (the tunnel cases) would **hang** rather than fail if
    /// `with_upgrades()` were ever dropped from `tunnel`, which is the shape
    /// that mistake actually has.
    mod loopback {
        use super::*;
        use crate::proxy::{OutboundProxies, ProxyTarget};
        use crate::testutil::{FakeProxy, ProxyBehaviour};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Everything here targets `127.0.0.1` literally, which
        /// [`crate::dns::connect`] short-circuits before asking a resolver —
        /// except `resolving`, below, which is the one case that needs a name.
        struct UnreachableResolver;

        #[async_trait::async_trait]
        impl Resolver for UnreachableResolver {
            async fn reverse(&self, _ip: std::net::IpAddr) -> Result<Vec<String>, String> {
                unreachable!()
            }
            async fn forward(&self, _name: &str) -> Result<Vec<std::net::IpAddr>, String> {
                unreachable!("a literal 127.0.0.1 must short-circuit before this is called")
            }
            async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
                unreachable!()
            }
        }

        /// Answers every name with loopback, for the cases that need a real
        /// hostname on the wire.
        struct LoopbackResolver;

        #[async_trait::async_trait]
        impl Resolver for LoopbackResolver {
            async fn reverse(&self, _ip: std::net::IpAddr) -> Result<Vec<String>, String> {
                unreachable!()
            }
            async fn forward(&self, _name: &str) -> Result<Vec<std::net::IpAddr>, String> {
                Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])])
            }
            async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
                unreachable!()
            }
        }

        fn through(proxy: &FakeProxy) -> OutboundProxies {
            OutboundProxies::always(ProxyTarget::for_test(&proxy.url()))
        }

        fn tunnelling(port: u16) -> ProxyBehaviour {
            ProxyBehaviour::Tunnel {
                status: "HTTP/1.1 200 Connection established\r\n",
                force_port: Some(port),
            }
        }

        /// A plain TCP server that answers one canned response.
        async fn origin(response: &'static str) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
            port
        }

        /// The `tls_alpn_01` shape: a raw byte stream carried end to end.
        #[tokio::test]
        async fn connect_stream_tunnels_to_the_origin() {
            let port = origin("pong").await;
            let proxy = FakeProxy::start(tunnelling(port)).await;

            // A name, not `127.0.0.1`: `select` bypasses loopback
            // unconditionally, so a literal would take the direct path and this
            // would pass without the proxy being involved at all.
            let mut stream = connect_stream(
                &LoopbackResolver,
                &through(&proxy),
                &Endpoint::tls("origin.example", 443),
            )
            .await
            .expect("the tunnel must open");

            stream.write_all(b"ping").await.unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.unwrap();
            assert_eq!(answer, "pong");

            assert_eq!(proxy.connections(), 1);
            let request = proxy.requests().remove(0);
            assert!(
                request.starts_with("CONNECT origin.example:443 HTTP/1.1"),
                "{request}"
            );
            // Never on a CONNECT: a proxy honouring it would close the tunnel
            // that was just asked for.
            assert!(
                !request.to_lowercase().contains("connection: close"),
                "{request}"
            );
            assert!(
                !request.to_lowercase().contains("proxy-connection"),
                "{request}"
            );
        }

        /// What squid actually answers: an older version and an extra header.
        /// The framing has to survive both.
        #[tokio::test]
        async fn a_squid_shaped_reply_still_opens_the_tunnel() {
            let port = origin("pong").await;
            let proxy = FakeProxy::start(ProxyBehaviour::Tunnel {
                status: "HTTP/1.0 200 Connection established\r\nProxy-Agent: squid/6.10\r\n",
                force_port: Some(port),
            })
            .await;

            let mut stream = connect_stream(
                &LoopbackResolver,
                &through(&proxy),
                &Endpoint::tls("origin.example", 443),
            )
            .await
            .expect("a 1.0 reply is still a tunnel");
            stream.write_all(b"ping").await.unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.unwrap();
            assert_eq!(answer, "pong");
        }

        /// A cleartext target is forwarded rather than tunnelled: the request
        /// line carries the whole URL and the credential rides on the request.
        #[tokio::test]
        async fn a_cleartext_target_is_forwarded_with_its_credentials() {
            let proxy = FakeProxy::start(ProxyBehaviour::Forward(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            ))
            .await;
            let proxies = OutboundProxies::always(ProxyTarget::for_test(&format!(
                "http://user:pass@127.0.0.1:{}",
                proxy.port
            )));

            let target = Url::parse("http://origin.example/a?b=c").unwrap();
            let endpoint = Endpoint::from_url(&target).unwrap();
            let mut connection = connect::<Empty<Bytes>>(
                &UnreachableResolver,
                &proxies,
                &endpoint,
                &Arc::new(webpki_tls_config()),
            )
            .await
            .expect("the proxy is the peer, so the origin need not exist");

            let request = hyper::Request::builder()
                .uri(connection.request_target(&target))
                .header(hyper::header::HOST, endpoint.authority())
                .body(Empty::<Bytes>::new())
                .unwrap();
            assert_eq!(
                connection.send_request(request).await.unwrap().status(),
                200
            );

            let seen = proxy.requests().remove(0);
            assert!(
                seen.starts_with("GET http://origin.example/a?b=c HTTP/1.1"),
                "{seen}"
            );
            assert!(
                seen.to_lowercase()
                    .contains("proxy-authorization: basic dxnlcjpwyxnz"),
                "{seen}"
            );
        }

        /// The https path end to end: the tunnel carries a TLS session whose
        /// SNI is the *origin's* name, and the credential spent on the CONNECT
        /// is not repeated inside — where the origin would read it.
        #[tokio::test]
        async fn https_is_tunnelled_with_the_origin_s_own_sni() {
            use rustls::server::{ClientHello, ResolvesServerCert};
            use rustls::sign::CertifiedKey;
            use std::sync::Mutex;

            #[derive(Debug)]
            struct RecordingCert {
                key: Arc<CertifiedKey>,
                names: Arc<Mutex<Vec<String>>>,
            }

            impl ResolvesServerCert for RecordingCert {
                fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                    self.names
                        .lock()
                        .unwrap()
                        .push(hello.server_name().unwrap_or_default().to_string());
                    Some(self.key.clone())
                }
            }

            // A self-signed certificate for the name the client will ask for;
            // the client validates nothing (this is the transport under test,
            // not a trust decision), so its contents do not matter.
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let certificate = rcgen::CertificateParams::new(vec!["origin.example".to_string()])
                .unwrap()
                .self_signed(&key_pair)
                .unwrap();
            let provider = rustls::crypto::ring::default_provider();
            let signing_key = provider
                .key_provider
                .load_private_key(
                    rustls_pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
                )
                .unwrap();
            let names = Arc::new(Mutex::new(Vec::new()));
            let resolver = RecordingCert {
                key: Arc::new(CertifiedKey::new(
                    vec![certificate.der().clone()],
                    signing_key,
                )),
                names: names.clone(),
            };
            let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = listener.local_addr().unwrap().port();
            let seen_inside = Arc::new(Mutex::new(String::new()));
            let recorder = seen_inside.clone();
            tokio::spawn(async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut buffer = vec![0u8; 2048];
                let read = stream.read(&mut buffer).await.unwrap();
                *recorder.lock().unwrap() = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });

            // `force_port` so the CONNECT target can be a real name — which is
            // what makes the SNI assertion mean anything — without that name
            // having to resolve for the *proxy*.
            let proxy = FakeProxy::start(ProxyBehaviour::Tunnel {
                status: "HTTP/1.1 200 Connection established\r\n",
                force_port: Some(origin_port),
            })
            .await;
            let proxies = OutboundProxies::always(ProxyTarget::for_test(&format!(
                "http://user:pass@127.0.0.1:{}",
                proxy.port
            )));

            let target = Url::parse("https://origin.example/x").unwrap();
            let endpoint = Endpoint::from_url(&target).unwrap();
            let mut connection = connect::<Empty<Bytes>>(
                &LoopbackResolver,
                &proxies,
                &endpoint,
                &crate::challenge::tls_alpn_01::accept_any_client_config(&[]).unwrap(),
            )
            .await
            .expect("the tunnel must carry the TLS session");

            let request = hyper::Request::builder()
                .uri(connection.request_target(&target))
                .header(hyper::header::HOST, endpoint.authority())
                .body(Empty::<Bytes>::new())
                .unwrap();
            assert_eq!(
                connection.send_request(request).await.unwrap().status(),
                204
            );

            let connect_request = proxy.requests().remove(0);
            assert!(
                connect_request.starts_with("CONNECT origin.example:443 HTTP/1.1"),
                "{connect_request}"
            );
            assert!(
                connect_request
                    .to_lowercase()
                    .contains("proxy-authorization"),
                "{connect_request}"
            );

            assert_eq!(names.lock().unwrap().as_slice(), ["origin.example"]);

            let inside = seen_inside.lock().unwrap().clone();
            // Origin-form inside the tunnel: the peer is the origin server.
            assert!(inside.starts_with("GET /x HTTP/1.1"), "{inside}");
            // …and the proxy credential stops at the proxy.
            assert!(
                !inside.to_lowercase().contains("proxy-authorization"),
                "{inside}"
            );
        }

        /// "407 Proxy Authentication Required" is the whole diagnosis, and an
        /// operator never sees the proxy's own log.
        #[tokio::test]
        async fn a_refused_connect_reports_the_status_and_the_body() {
            let proxy = FakeProxy::start(ProxyBehaviour::Refuse(
                "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 20\r\n\r\n\
                 credentials required",
            ))
            .await;
            let proxies = OutboundProxies::always(ProxyTarget::for_test(&format!(
                "http://user:hunter2@127.0.0.1:{}",
                proxy.port
            )));

            let Err(error) = connect_stream(
                &LoopbackResolver,
                &proxies,
                &Endpoint::tls("origin.example", 443),
            )
            .await
            else {
                panic!("a 407 is not a tunnel");
            };

            assert!(error.contains("407"), "{error}");
            assert!(error.contains("credentials required"), "{error}");
            // …and the password stays out of the message an operator pastes
            // into a ticket.
            assert!(!error.contains("hunter2"), "{error}");
        }

        /// A dead proxy must name the proxy: "connection refused" against the
        /// origin's address would send an operator to the wrong host.
        #[tokio::test]
        async fn an_unreachable_proxy_names_the_proxy() {
            // Bound then dropped, so the port is free but was recently valid.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);

            let proxies =
                OutboundProxies::always(ProxyTarget::for_test(&format!("http://127.0.0.1:{port}")));
            let Err(error) = connect_stream(
                &LoopbackResolver,
                &proxies,
                &Endpoint::tls("origin.example", 443),
            )
            .await
            else {
                panic!("a dead proxy is not a tunnel");
            };

            assert!(error.contains("proxy"), "{error}");
            assert!(error.contains(&port.to_string()), "{error}");
            assert!(!error.contains("origin.example"), "{error}");
        }

        /// A `no_proxy` hit really leaves the proxy untouched — which only a
        /// connection counter can prove, since a successful response looks
        /// exactly the same either way.
        #[tokio::test]
        async fn a_bypassed_target_never_reaches_the_proxy() {
            let port = origin("pong").await;
            let proxy = FakeProxy::start(tunnelling(port)).await;
            let proxies = through(&proxy).with_bypass(&["bypassed.example"]).unwrap();

            let mut stream = connect_stream(
                &LoopbackResolver,
                &proxies,
                &Endpoint::tls("bypassed.example", port),
            )
            .await
            .expect("a bypassed target still connects, just directly");
            stream.write_all(b"ping").await.unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.unwrap();
            assert_eq!(answer, "pong");

            assert_eq!(proxy.connections(), 0, "the proxy must not be dialled");
        }
    }
}
