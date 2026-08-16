//! The `mattermost` notify backend: POSTs to an incoming webhook.
//!
//! Written on `hyper` + `tokio-rustls`, already in the tree via
//! [`crate::challenge::http_01`] and [`crate::signer::relay`] — the same
//! reasoning `Cargo.toml`'s own comment gives for skipping `reqwest`
//! everywhere else in this codebase: a direct edge, not a new dependency.
//! Written as its own small helper rather than reusing
//! `signer::relay::client`'s (private) request plumbing, matching this
//! codebase's preference for per-module locality over a shared HTTP-client
//! abstraction.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde_json::json;
use tracing::info;
use url::Url;

use super::{NotifyBackend, NotifyError, NotifyEvent, render};
use crate::config::MattermostNotifyConfig;

pub struct MattermostNotifier {
    webhook_url: Url,
    channel: String,
    username: String,
    timeout: Duration,
    tls: Arc<rustls::ClientConfig>,
    /// The same resolver every other outbound hop uses, so `dns.resolver`
    /// governs this webhook too.
    resolver: Arc<dyn crate::dns::Resolver>,
    /// The forward proxy, if any, the webhook host is reached through.
    proxies: Arc<crate::proxy::OutboundProxies>,
    env: Arc<minijinja::Environment<'static>>,
}

impl std::fmt::Debug for MattermostNotifier {
    /// `dyn Resolver` is not `Debug`; the webhook host is the part worth
    /// reading, and the URL's path carries the shared secret so it must not be
    /// rendered. Mirrors `FilterPolicy`'s own impl.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MattermostNotifier")
            .field("webhook_host", &self.webhook_url.host_str())
            .field("channel", &self.channel)
            .field("username", &self.username)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl MattermostNotifier {
    pub fn from_config(
        cfg: &MattermostNotifyConfig,
        env: Arc<minijinja::Environment<'static>>,
        resolver: Arc<dyn crate::dns::Resolver>,
        proxies: Arc<crate::proxy::OutboundProxies>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.webhook_url.trim().is_empty(),
            "notify.mattermost is enabled but notify.mattermost.webhook_url is empty"
        );
        let webhook_url: Url = cfg.webhook_url.parse().map_err(|error| {
            anyhow::anyhow!("notify.mattermost.webhook_url is not a valid URL: {error}")
        })?;
        anyhow::ensure!(
            matches!(webhook_url.scheme(), "http" | "https"),
            "notify.mattermost.webhook_url must be http:// or https://"
        );

        info!(event = "notify_mattermost_loaded", outcome = "success", webhook_host = ?webhook_url.host_str());

        Ok(Self {
            webhook_url,
            channel: cfg.channel.clone(),
            username: cfg.username.clone(),
            timeout: Duration::from_millis(cfg.timeout_ms),
            tls: Arc::new(crate::http_client::webpki_tls_config()),
            resolver,
            proxies,
            env,
        })
    }
}

#[async_trait]
impl NotifyBackend for MattermostNotifier {
    fn name(&self) -> &'static str {
        "mattermost"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        let text = render(&self.env, &format!("mattermost/{}.j2", event.kind()), event)?;

        let mut payload = json!({ "text": text });
        if !self.channel.is_empty() {
            payload["channel"] = json!(self.channel);
        }
        if !self.username.is_empty() {
            payload["username"] = json!(self.username);
        }
        // Permanent: this payload is two strings and a rendered template, so a
        // serializer that refuses it will refuse it again.
        let body = Bytes::from(serde_json::to_vec(&payload).map_err(|error| {
            NotifyError::permanent(format!("failed to serialize webhook payload: {error}"))
        })?);

        let status = tokio::time::timeout(
            self.timeout,
            post(
                &self.tls,
                self.resolver.as_ref(),
                &self.proxies,
                &self.webhook_url,
                body,
            ),
        )
        .await
        .map_err(|_| NotifyError::new(format!("timed out after {:?}", self.timeout)))??;

        if status.is_success() {
            Ok(())
        } else if retryable_status(status) {
            Err(NotifyError::new(format!("webhook returned {status}")))
        } else {
            Err(NotifyError::permanent(format!("webhook returned {status}")))
        }
    }
}

/// Whether a non-2xx from the webhook is worth asking again about.
///
/// A 5xx is the server having a bad minute and a 429 is it asking for one, so
/// both are retried. Every other 4xx is Mattermost stating a reason — a webhook
/// that has been deleted, a payload it will not accept — and repeating the same
/// request four more times only delays the log line that says so. 408 is a 4xx
/// by number and a transport failure by meaning, so it goes with the 5xx.
fn retryable_status(status: hyper::StatusCode) -> bool {
    status.is_server_error()
        || status == hyper::StatusCode::TOO_MANY_REQUESTS
        || status == hyper::StatusCode::REQUEST_TIMEOUT
}

async fn post(
    tls: &Arc<rustls::ClientConfig>,
    resolver: &dyn crate::dns::Resolver,
    proxies: &crate::proxy::OutboundProxies,
    url: &Url,
    body: Bytes,
) -> Result<hyper::StatusCode, NotifyError> {
    // Permanent: `webhook_url` is configuration, and a URL that does not parse
    // now will not parse in thirty seconds either.
    let endpoint = crate::http_client::Endpoint::from_url(url).map_err(NotifyError::permanent)?;

    // Retryable: DNS, the proxy, the handshake and the socket.
    let mut connection = crate::http_client::connect(resolver, proxies, &endpoint, tls)
        .await
        .map_err(NotifyError::new)?;

    // Origin-form directly, absolute-form through a proxy — the connection
    // decides, which is why it is opened before the request is built.
    let request = Request::builder()
        .method(Method::POST)
        .uri(connection.request_target(url))
        .header(hyper::header::HOST, endpoint.authority())
        .header(hyper::header::USER_AGENT, "acme-proxy")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .map_err(|error| NotifyError::permanent(format!("failed to build request: {error}")))?;

    let response = connection
        .send_request(request)
        .await
        .map_err(|error| NotifyError::new(error.to_string()))?;
    let status = response.status();
    // Drain the body so the connection task can complete cleanly; the
    // response content itself carries nothing this backend needs.
    let _ = response.into_body().collect().await;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{ProfileMountedData, build_environment};
    use hyper_util::rt::TokioIo;

    /// These all talk to a loopback listener by IP literal, which
    /// `dns::connect` short-circuits without a lookup — so the resolver is
    /// never actually consulted and the system one is fine.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    fn cfg() -> MattermostNotifyConfig {
        MattermostNotifyConfig {
            webhook_url: "https://mattermost.example.com/hooks/xyz".to_string(),
            ..MattermostNotifyConfig::default()
        }
    }

    #[test]
    fn missing_webhook_url_is_a_startup_error() {
        let cfg = MattermostNotifyConfig {
            webhook_url: String::new(),
            ..cfg()
        };
        let error = MattermostNotifier::from_config(
            &cfg,
            Arc::new(build_environment("")),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("webhook_url is empty"));
    }

    #[test]
    fn non_http_scheme_is_a_startup_error() {
        let cfg = MattermostNotifyConfig {
            webhook_url: "ftp://mattermost.example.com/hooks/xyz".to_string(),
            ..cfg()
        };
        let error = MattermostNotifier::from_config(
            &cfg,
            Arc::new(build_environment("")),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("http"));
    }

    #[tokio::test]
    async fn renders_the_profile_mounted_template() {
        let notifier = MattermostNotifier::from_config(
            &cfg(),
            Arc::new(build_environment("")),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap();
        let event = NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: "le".to_string(),
        });
        let text = render(&notifier.env, "mattermost/profile_mounted.j2", &event).unwrap();
        assert!(text.contains("le"));
    }

    /// A real POST against a loopback listener, proving the transport itself
    /// (connect/handshake/send/read-status) works end to end — the same
    /// technique `challenge::http_01`'s `HyperFetcher` test and
    /// `signer::relay::client`'s tests use.
    #[tokio::test]
    async fn posts_to_a_loopback_listener_and_reads_the_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service =
                hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::new())))
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let tls = Arc::new(crate::http_client::webpki_tls_config());
        let url: Url = format!("http://{addr}/hooks/xyz").parse().unwrap();
        let status = post(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &url,
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap();
        assert!(status.is_success());
    }

    /// The whole `send` path — render the template, serialize, POST — against
    /// the same loopback listener, so the trait impl is exercised and not just
    /// the transport under it.
    #[tokio::test]
    async fn send_renders_and_posts_the_event() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let tx = std::sync::Mutex::new(Some(tx));
            let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let tx = tx.lock().unwrap().take();
                async move {
                    let body = http_body_util::BodyExt::collect(req.into_body())
                        .await
                        .unwrap()
                        .to_bytes();
                    if let Some(tx) = tx {
                        let _ = tx.send(body);
                    }
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::new())))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let notifier = MattermostNotifier::from_config(
            &MattermostNotifyConfig {
                webhook_url: format!("http://{addr}/hooks/xyz"),
                channel: "ops".to_string(),
                username: "acme-proxy".to_string(),
                ..MattermostNotifyConfig::default()
            },
            Arc::new(crate::notify::build_environment("")),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap();

        assert_eq!(notifier.name(), "mattermost");
        notifier
            .send(&crate::notify::NotifyEvent::ProfileMounted(
                crate::notify::ProfileMountedData {
                    profile: "default".to_string(),
                },
            ))
            .await
            .expect("the webhook accepted the post");

        let body: serde_json::Value = serde_json::from_slice(&rx.await.unwrap()).unwrap();
        assert_eq!(body["channel"], "ops");
        assert_eq!(body["username"], "acme-proxy");
        assert!(
            body["text"].as_str().unwrap().contains("default"),
            "the rendered text must name the profile: {body}"
        );
    }

    /// A webhook that answers 4xx/5xx is a delivery failure, not a success —
    /// the dispatcher logs it rather than pretending the message landed.
    #[tokio::test]
    async fn a_rejecting_webhook_is_a_delivery_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service =
                hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(hyper::StatusCode::FORBIDDEN)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let notifier = MattermostNotifier::from_config(
            &MattermostNotifyConfig {
                webhook_url: format!("http://{addr}/hooks/xyz"),
                ..MattermostNotifyConfig::default()
            },
            Arc::new(crate::notify::build_environment("")),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap();

        let error = notifier
            .send(&crate::notify::NotifyEvent::ProfileMounted(
                crate::notify::ProfileMountedData {
                    profile: "default".to_string(),
                },
            ))
            .await
            .expect_err("403 is not a delivery");
        assert!(error.to_string().contains("403"), "{error}");
        assert!(
            !error.retryable(),
            "a 403 is Mattermost stating a reason, not a bad minute"
        );
    }

    /// Which non-2xx answers are worth asking again about. The split decides
    /// whether a queued delivery spends its whole budget on a webhook that has
    /// been deleted, or gives up immediately on one that is merely overloaded.
    #[test]
    fn only_a_transient_status_is_retried() {
        use hyper::StatusCode;
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::REQUEST_TIMEOUT,
        ] {
            assert!(retryable_status(status), "{status} must be retried");
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::GONE,
        ] {
            assert!(!retryable_status(status), "{status} must not be retried");
        }
    }

    /// A URL the transport cannot even parse is configuration, so it must not
    /// consume a retry budget.
    #[tokio::test]
    async fn an_unusable_url_is_permanent_and_an_unreachable_host_is_not() {
        let tls = Arc::new(crate::http_client::webpki_tls_config());

        let url: Url = "ftp://chat.example.com/hooks/xyz".parse().unwrap();
        let error = post(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &url,
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap_err();
        assert!(!error.retryable(), "{error}");

        let url: Url = "http://127.0.0.1:1/hooks/xyz".parse().unwrap();
        let error = post(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &url,
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap_err();
        assert!(
            error.retryable(),
            "a host that is down may come back: {error}"
        );
    }

    /// A URL whose scheme is neither `http` nor `https` never reaches the
    /// socket. `from_config` refuses these, so this pins the transport's own
    /// guard for a URL arriving by any other route.
    #[tokio::test]
    async fn a_non_http_scheme_never_reaches_the_socket() {
        let tls = Arc::new(crate::http_client::webpki_tls_config());
        let url: Url = "ftp://chat.example.com/hooks/xyz".parse().unwrap();
        let error = post(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &url,
            Bytes::from_static(b"{}"),
        )
        .await
        .expect_err("ftp is not a webhook transport");
        assert!(error.to_string().contains("unsupported scheme"), "{error}");
    }

    /// Nothing is listening, so the connect fails — the common real-world case
    /// (a webhook host that is down) must be an error, never a silent drop.
    #[tokio::test]
    async fn an_unreachable_webhook_is_an_error() {
        let tls = Arc::new(crate::http_client::webpki_tls_config());
        let url: Url = "http://127.0.0.1:1/hooks/xyz".parse().unwrap();
        let error = post(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &url,
            Bytes::from_static(b"{}"),
        )
        .await
        .expect_err("nothing is listening on port 1");
        assert!(error.to_string().contains("connecting to"), "{error}");
    }
}
