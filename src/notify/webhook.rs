//! The `webhook` notify backend: one HTTP request per event, with the URL, the
//! method, the headers and the body all stated by the operator.
//!
//! This is the backend that exists so a chat provider is *configuration*.
//! Slack, Mattermost, Microsoft Teams, Telegram and Matrix differ in a URL, a
//! verb, an `Authorization` header and a JSON shape, and nothing else — so
//! there is one backend and a recipe table in the book, rather than one
//! backend per provider each carrying its own copy of the transport, the
//! timeout and the retryable/permanent split.
//!
//! ## Two-stage rendering
//!
//! 1. `webhook/<event>.j2` — embedded, and overridable file by file through
//!    `notify.template_dir` like every other template — renders the
//!    human-readable `message`.
//! 2. The entry's own `body` key is a template compiled at **startup**, with
//!    `message`, `hook` and every field of the event's payload in scope.
//!
//! The split is what lets an operator restyle every message by overriding six
//! files, or restructure one provider's payload by editing one config line,
//! without either choice implying the other.
//!
//! **`| tojson` in a body template is not decoration.** A `.j2` template has
//! auto-escaping off — deliberately, unlike the web admin's `.html` — so a
//! `challenge_failed` whose error text holds a quote or a newline would
//! otherwise render a payload the receiving provider answers `400` to, once,
//! permanently, for exactly the events an operator most wanted to hear about.
//!
//! Written on `hyper` + `tokio-rustls` like every other outbound hop here (see
//! [`crate::http_client`]), rather than pulling in `reqwest` for one POST.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request};
use tracing::info;
use url::Url;

use super::{NotifyBackend, NotifyError, NotifyEvent, render};
use crate::config::WebhookNotifyConfig;

/// How much of a rejecting webhook's body is quoted back. Slack answers a bad
/// payload with `invalid_payload` and nothing else, which is the whole
/// diagnosis; a provider that answers with a page is not owed a log line the
/// size of one.
const MAX_ERROR_BODY_CHARS: usize = 200;

/// The methods a webhook may be called with.
///
/// A webhook is a write, and a body on `GET`/`DELETE` is nonsense, so the list
/// is closed rather than "whatever parses": a typo'd verb should stop the
/// server, not produce a request no provider answers. `PUT` is Matrix's
/// send-message API, which is the reason this is configurable at all.
const ALLOWED_METHODS: [&str; 3] = ["POST", "PUT", "PATCH"];

pub struct WebhookNotifier {
    /// The `notify.webhook.<name>` entry this was built from — the only part of
    /// the configuration safe to log, and what tells two entries apart.
    entry: String,
    url: Url,
    method: Method,
    headers: HeaderMap,
    /// The name [`Self::env`] holds this entry's compiled `body` under.
    body_template: String,
    timeout: Duration,
    tls: Arc<rustls::ClientConfig>,
    /// The same resolver every other outbound hop uses, so `dns.resolver`
    /// governs this webhook too.
    resolver: Arc<dyn crate::dns::Resolver>,
    /// The forward proxy, if any, the webhook host is reached through.
    proxies: Arc<crate::proxy::OutboundProxies>,
    /// The shared template environment plus this entry's own compiled `body`.
    env: Arc<minijinja::Environment<'static>>,
}

impl std::fmt::Debug for WebhookNotifier {
    /// `dyn Resolver` is not `Debug`, and two of these fields are secrets: the
    /// URL's path carries the credential for a Slack hook or a Telegram bot,
    /// and a header value carries it for Matrix. So the host, the method and
    /// the header *names* are rendered, and nothing else. Mirrors
    /// `FilterPolicy`'s own impl.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookNotifier")
            .field("entry", &self.entry)
            .field("webhook_host", &self.url.host_str())
            .field("method", &self.method.as_str())
            .field(
                "headers",
                &self
                    .headers
                    .keys()
                    .map(HeaderName::as_str)
                    .collect::<Vec<_>>(),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl WebhookNotifier {
    /// Builds one entry's notifier, refusing everything unusable **here** — an
    /// unparseable URL, an unknown verb, a header a wire format will not carry
    /// and a body template that does not compile are all configuration, so they
    /// stop the server rather than becoming a permanent delivery failure hours
    /// later, on the one event an operator was waiting for.
    pub fn from_config(
        entry: &str,
        cfg: &WebhookNotifyConfig,
        env: &minijinja::Environment<'static>,
        resolver: Arc<dyn crate::dns::Resolver>,
        proxies: Arc<crate::proxy::OutboundProxies>,
    ) -> anyhow::Result<Self> {
        let key = format!("notify.webhook.{entry}");

        anyhow::ensure!(
            !cfg.url.trim().is_empty(),
            "{key} is enabled but {key}.url is empty"
        );
        let url: Url = cfg
            .url
            .parse()
            .map_err(|error| anyhow::anyhow!("{key}.url is not a valid URL: {error}"))?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "{key}.url must be http:// or https://"
        );

        let spelled = cfg.method.trim().to_ascii_uppercase();
        anyhow::ensure!(
            ALLOWED_METHODS.contains(&spelled.as_str()),
            "{key}.method: unknown method `{}` (expected one of {ALLOWED_METHODS:?})",
            cfg.method
        );
        let method = Method::from_bytes(spelled.as_bytes())
            .map_err(|error| anyhow::anyhow!("{key}.method is not a valid HTTP method: {error}"))?;

        let headers = build_headers(&key, &cfg.headers)?;

        anyhow::ensure!(
            !cfg.body.trim().is_empty(),
            "{key}.body is empty; a webhook with no payload delivers nothing"
        );
        // Compiled into a clone of the shared environment, which is what turns a
        // syntax error into a startup error. The clone still resolves
        // `webhook/<event>.j2` through the shared loader: minijinja consults a
        // loader only for names not already stored, so adding one template
        // shadows nothing.
        let body_template = format!("webhook:{entry}.body");
        let mut env = env.clone();
        env.add_template_owned(body_template.clone(), cfg.body.clone())
            .map_err(|error| anyhow::anyhow!("{key}.body is not a valid template: {error}"))?;

        info!(
            event = "notify_webhook_loaded",
            outcome = "success",
            entry = %entry,
            method = %method,
            webhook_host = ?url.host_str(),
        );

        Ok(Self {
            entry: entry.to_string(),
            url,
            method,
            headers,
            body_template,
            timeout: Duration::from_millis(cfg.timeout_ms),
            tls: Arc::new(crate::http_client::webpki_tls_config()),
            resolver,
            proxies,
            env: Arc::new(env),
        })
    }

    /// Renders this entry's body for `event`: the shared per-event message
    /// first, then the entry's own template with that message in scope.
    fn body_for(&self, event: &NotifyEvent) -> Result<String, NotifyError> {
        let message = render(&self.env, &format!("webhook/{}.j2", event.kind()), event)?;

        let template = self
            .env
            .get_template(&self.body_template)
            .map_err(|error| {
                NotifyError::permanent(format!("notify.webhook.{}.body: {error}", self.entry))
            })?;
        template
            .render(minijinja::context! {
                message,
                hook => event.kind(),
                ..event.context()
            })
            .map_err(|error| {
                NotifyError::permanent(format!("notify.webhook.{}.body: {error}", self.entry))
            })
    }
}

/// The request headers, defaults first so an entry may override them.
///
/// `content-type` is a default rather than a key of its own: a provider wanting
/// `application/x-www-form-urlencoded` states it here, in the same table as the
/// `Authorization` it also needs, instead of in a key that would be dead
/// configuration for every other provider.
fn build_headers(key: &str, configured: &BTreeMap<String, String>) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        hyper::header::USER_AGENT,
        HeaderValue::from_static("acme-proxy"),
    );

    for (name, value) in configured {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            anyhow::anyhow!("{key}.headers: `{name}` is not a header name: {error}")
        })?;
        // The value is never quoted back: these carry bearer tokens.
        let value = HeaderValue::from_str(value).map_err(|_| {
            anyhow::anyhow!("{key}.headers.{name}: the value is not a valid header value")
        })?;
        headers.insert(name, value);
    }

    Ok(headers)
}

#[async_trait]
impl NotifyBackend for WebhookNotifier {
    fn name(&self) -> &'static str {
        // Every entry answers this, which is why a slot is addressed by
        // `webhook:<entry>` and not by this — see `BackendSlot`.
        "webhook"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        let body = Bytes::from(self.body_for(event)?.into_bytes());

        let (status, excerpt) = tokio::time::timeout(
            self.timeout,
            send_request(
                &self.tls,
                self.resolver.as_ref(),
                &self.proxies,
                &self.method,
                &self.url,
                &self.headers,
                body,
            ),
        )
        .await
        .map_err(|_| NotifyError::new(format!("timed out after {:?}", self.timeout)))??;

        if status.is_success() {
            Ok(())
        } else {
            let detail = if excerpt.is_empty() {
                format!("webhook returned {status}")
            } else {
                format!("webhook returned {status}: {excerpt}")
            };
            if retryable_status(status) {
                Err(NotifyError::new(detail))
            } else {
                Err(NotifyError::permanent(detail))
            }
        }
    }
}

/// Whether a non-2xx from the webhook is worth asking again about.
///
/// A 5xx is the server having a bad minute and a 429 is it asking for one, so
/// both are retried. Every other 4xx is the provider stating a reason — a
/// webhook that has been deleted, a payload it will not accept — and repeating
/// the same request four more times only delays the log line that says so. 408
/// is a 4xx by number and a transport failure by meaning, so it goes with the
/// 5xx.
fn retryable_status(status: hyper::StatusCode) -> bool {
    status.is_server_error()
        || status == hyper::StatusCode::TOO_MANY_REQUESTS
        || status == hyper::StatusCode::REQUEST_TIMEOUT
}

/// Performs the request, answering with the status and a short excerpt of the
/// body — which for a refusal is usually the entire diagnosis.
#[allow(clippy::too_many_arguments)]
async fn send_request(
    tls: &Arc<rustls::ClientConfig>,
    resolver: &dyn crate::dns::Resolver,
    proxies: &crate::proxy::OutboundProxies,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<(hyper::StatusCode, String), NotifyError> {
    // Permanent: `url` is configuration, and a URL that does not parse now will
    // not parse in thirty seconds either.
    let endpoint = crate::http_client::Endpoint::from_url(url).map_err(NotifyError::permanent)?;

    // Retryable: DNS, the proxy, the handshake and the socket.
    let mut connection = crate::http_client::connect(resolver, proxies, &endpoint, tls)
        .await
        .map_err(NotifyError::new)?;

    // Origin-form directly, absolute-form through a proxy — the connection
    // decides, which is why it is opened before the request is built.
    let mut builder = Request::builder()
        .method(method.clone())
        .uri(connection.request_target(url))
        .header(hyper::header::HOST, endpoint.authority());
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Full::new(body))
        .map_err(|error| NotifyError::permanent(format!("failed to build request: {error}")))?;

    let response = connection
        .send_request(request)
        .await
        .map_err(|error| NotifyError::new(error.to_string()))?;
    let status = response.status();
    // Drained either way, so the connection task completes cleanly; on a
    // refusal the first few words of it are the diagnosis.
    let body = response
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let excerpt = String::from_utf8_lossy(&body)
        .chars()
        .take(MAX_ERROR_BODY_CHARS)
        .collect::<String>()
        .trim()
        .to_string();
    Ok((status, excerpt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{ChallengeFailedData, ProfileMountedData, build_environment};
    use hyper_util::rt::TokioIo;

    /// These all talk to a loopback listener by IP literal, which
    /// `dns::connect` short-circuits without a lookup — so the resolver is
    /// never actually consulted and the system one is fine.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    fn cfg() -> WebhookNotifyConfig {
        WebhookNotifyConfig {
            url: "https://chat.example.com/hooks/xyz".to_string(),
            ..WebhookNotifyConfig::default()
        }
    }

    fn build(cfg: &WebhookNotifyConfig) -> anyhow::Result<WebhookNotifier> {
        WebhookNotifier::from_config(
            "chat",
            cfg,
            &build_environment(""),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
    }

    fn mounted() -> NotifyEvent {
        NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: "default".to_string(),
        })
    }

    /// A listener that answers `status` with `body` and hands back the one
    /// request it received.
    async fn serve_once(
        status: hyper::StatusCode,
        body: &'static str,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Receiver<(String, HeaderMap, Bytes)>,
    ) {
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
                    let method = req.method().to_string();
                    let headers = req.headers().clone();
                    let received = BodyExt::collect(req.into_body()).await.unwrap().to_bytes();
                    if let Some(tx) = tx {
                        let _ = tx.send((method, headers, received));
                    }
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        (addr, rx)
    }

    /// Every way an entry can be unusable, refused where an operator can still
    /// do something about it: at startup, naming the key.
    #[test]
    fn an_unusable_entry_is_a_startup_error() {
        let cases: Vec<(WebhookNotifyConfig, &str)> = vec![
            (
                WebhookNotifyConfig {
                    url: String::new(),
                    ..cfg()
                },
                "url is empty",
            ),
            (
                WebhookNotifyConfig {
                    url: "not a url".to_string(),
                    ..cfg()
                },
                "not a valid URL",
            ),
            (
                WebhookNotifyConfig {
                    url: "ftp://chat.example.com/hooks/xyz".to_string(),
                    ..cfg()
                },
                "must be http",
            ),
            (
                WebhookNotifyConfig {
                    method: "GET".to_string(),
                    ..cfg()
                },
                "unknown method `GET`",
            ),
            (
                WebhookNotifyConfig {
                    headers: BTreeMap::from([("not a header".to_string(), "x".to_string())]),
                    ..cfg()
                },
                "is not a header name",
            ),
            (
                WebhookNotifyConfig {
                    headers: BTreeMap::from([("x-token".to_string(), "bad\nvalue".to_string())]),
                    ..cfg()
                },
                "not a valid header value",
            ),
            (
                WebhookNotifyConfig {
                    body: "   ".to_string(),
                    ..cfg()
                },
                "body is empty",
            ),
            (
                WebhookNotifyConfig {
                    body: "{{ message".to_string(),
                    ..cfg()
                },
                "not a valid template",
            ),
        ];

        for (config, expected) in cases {
            let error = build(&config).unwrap_err().to_string();
            assert!(
                error.contains(expected) && error.contains("notify.webhook.chat"),
                "expected `{expected}` naming the entry, got: {error}"
            );
        }
    }

    /// A method is taken however it was spelled — `post` and `POST` are the
    /// same verb, and refusing the lowercase one would be a puzzle rather than
    /// a diagnostic.
    #[test]
    fn a_method_is_case_insensitive() {
        let notifier = build(&WebhookNotifyConfig {
            method: "put".to_string(),
            ..cfg()
        })
        .unwrap();
        assert_eq!(notifier.method, Method::PUT);
    }

    /// The regression the `tojson` filter exists for. A challenge error is
    /// remote text — it quotes what a validator saw — so it routinely holds
    /// quotes and newlines, and `.j2` auto-escaping is off. Without the filter
    /// the payload stops being JSON exactly when something has gone wrong.
    #[test]
    fn a_message_holding_quotes_and_newlines_still_renders_valid_json() {
        let notifier = build(&cfg()).unwrap();
        let event = NotifyEvent::ChallengeFailed(ChallengeFailedData {
            profile: "default".to_string(),
            order_id: "o1".to_string(),
            account_id: "a1".to_string(),
            authz_id: "z1".to_string(),
            challenge_id: "c1".to_string(),
            challenge_type: "http-01".to_string(),
            identifier: "www.example.com".to_string(),
            error: "fetched \"nonsense\"\nand a backslash \\".to_string(),
            client_ip: None,
        });

        let body = notifier.body_for(&event).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|error| panic!("{error}: {body}"));
        let text = parsed["text"].as_str().unwrap();
        assert!(text.contains("nonsense"), "{text}");
        assert!(text.contains("www.example.com"), "{text}");
    }

    /// A body template reaches past `message` into the event's own fields, and
    /// the `hook` the enum is tagged with. This is what lets a provider needing
    /// a structured payload (a Teams card, a Telegram `chat_id`) be
    /// configuration rather than code.
    #[test]
    fn a_body_template_sees_the_events_own_fields() {
        let notifier = build(&WebhookNotifyConfig {
            body: r#"{"chat_id": "-100", "hook": {{ hook | tojson }}, "profile": {{ profile | tojson }}, "text": {{ message | tojson }}}"#
                .to_string(),
            ..cfg()
        })
        .unwrap();

        let body = notifier.body_for(&mounted()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["hook"], "profile_mounted");
        assert_eq!(parsed["profile"], "default");
        assert_eq!(parsed["chat_id"], "-100");
    }

    /// The whole `send` path against a loopback listener: the configured verb
    /// reaches the wire, the operator's headers arrive, one of them overrides a
    /// default, and the body is the rendered template.
    #[tokio::test]
    async fn send_uses_the_configured_method_headers_and_body() {
        let (addr, rx) = serve_once(hyper::StatusCode::OK, "").await;

        let notifier = build(&WebhookNotifyConfig {
            url: format!("http://{addr}/hooks/xyz"),
            method: "PUT".to_string(),
            headers: BTreeMap::from([
                ("Authorization".to_string(), "Bearer s3cret".to_string()),
                (
                    "content-type".to_string(),
                    "application/vnd.chat".to_string(),
                ),
            ]),
            ..cfg()
        })
        .unwrap();

        assert_eq!(notifier.name(), "webhook");
        notifier
            .send(&mounted())
            .await
            .expect("the webhook accepted the request");

        let (method, headers, body) = rx.await.unwrap();
        assert_eq!(method, "PUT");
        assert_eq!(headers["authorization"], "Bearer s3cret");
        assert_eq!(headers["content-type"], "application/vnd.chat");
        assert_eq!(headers["user-agent"], "acme-proxy");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed["text"].as_str().unwrap().contains("default"),
            "the rendered text must name the profile: {parsed}"
        );
    }

    /// A webhook that answers 4xx is a delivery failure — and its body is the
    /// diagnosis, so it reaches the error rather than being drained silently.
    #[tokio::test]
    async fn a_rejecting_webhook_reports_its_status_and_body() {
        let (addr, _rx) = serve_once(hyper::StatusCode::BAD_REQUEST, "invalid_payload").await;

        let notifier = build(&WebhookNotifyConfig {
            url: format!("http://{addr}/hooks/xyz"),
            ..cfg()
        })
        .unwrap();

        let error = notifier
            .send(&mounted())
            .await
            .expect_err("400 is not a delivery");
        assert!(error.to_string().contains("400"), "{error}");
        assert!(error.to_string().contains("invalid_payload"), "{error}");
        assert!(
            !error.retryable(),
            "a 400 is the provider stating a reason, not a bad minute"
        );
    }

    /// The same transport failure twice over: a URL the transport cannot use is
    /// configuration and must not consume a retry budget, while a host that is
    /// down may come back.
    #[tokio::test]
    async fn an_unusable_url_is_permanent_and_an_unreachable_host_is_not() {
        let tls = Arc::new(crate::http_client::webpki_tls_config());

        let url: Url = "ftp://chat.example.com/hooks/xyz".parse().unwrap();
        let error = send_request(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &Method::POST,
            &url,
            &HeaderMap::new(),
            Bytes::from_static(b"{}"),
        )
        .await
        .expect_err("ftp is not a webhook transport");
        assert!(error.to_string().contains("unsupported scheme"), "{error}");
        assert!(!error.retryable(), "{error}");

        let url: Url = "http://127.0.0.1:1/hooks/xyz".parse().unwrap();
        let error = send_request(
            &tls,
            test_resolver().as_ref(),
            &crate::proxy::OutboundProxies::direct(),
            &Method::POST,
            &url,
            &HeaderMap::new(),
            Bytes::from_static(b"{}"),
        )
        .await
        .expect_err("nothing is listening on port 1");
        assert!(error.to_string().contains("connecting to"), "{error}");
        assert!(
            error.retryable(),
            "a host that is down may come back: {error}"
        );
    }

    /// A template that compiles and then fails while rendering is still the
    /// operator's text and will fail identically every time, so it is
    /// **permanent** — a delivery that spends five attempts on it only delays
    /// the log line naming the entry.
    #[test]
    fn a_body_that_fails_at_render_time_is_permanent() {
        let notifier = build(&WebhookNotifyConfig {
            body: "{{ message.no_such_method() }}".to_string(),
            ..cfg()
        })
        .unwrap();

        let error = notifier.body_for(&mounted()).unwrap_err();
        assert!(
            error.to_string().contains("notify.webhook.chat.body"),
            "{error}"
        );
        assert!(!error.retryable(), "{error}");
    }

    /// A provider that accepts the connection and then says nothing must not
    /// hold the delivery open for ever: `timeout_ms` bounds the whole attempt,
    /// and running out is retryable — the next attempt may find it awake.
    #[tokio::test]
    async fn a_silent_webhook_times_out_and_is_retryable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Held, never answered, until the test is over.
            std::future::pending::<()>().await;
            drop(stream);
        });

        let notifier = build(&WebhookNotifyConfig {
            url: format!("http://{addr}/hooks/xyz"),
            timeout_ms: 100,
            ..cfg()
        })
        .unwrap();

        let error = notifier
            .send(&mounted())
            .await
            .expect_err("a silent server is not a delivery");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(error.retryable(), "{error}");
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

    /// Both secrets an entry can hold — the credential in the URL path and the
    /// one in a header — must stay out of anything that reaches a log or a
    /// ticket.
    #[test]
    fn debug_renders_neither_the_url_path_nor_a_header_value() {
        let notifier = build(&WebhookNotifyConfig {
            url: "https://chat.example.com/hooks/T00/B00/s3cret-hook-id".to_string(),
            headers: BTreeMap::from([("Authorization".to_string(), "Bearer s3cret".to_string())]),
            ..cfg()
        })
        .unwrap();

        let rendered = format!("{notifier:?}");
        assert!(rendered.contains("chat.example.com"), "{rendered}");
        assert!(rendered.contains("authorization"), "{rendered}");
        assert!(!rendered.contains("s3cret"), "{rendered}");
    }
}
