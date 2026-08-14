//! The `http-01` challenge (RFC 8555 §8.3): a file served at
//! `http://<identifier>/.well-known/acme-challenge/<token>` whose body is the
//! key authorization.
//!
//! ## Redirects, and the SSRF surface they open
//!
//! Redirecting port 80 to https is the single most common web-server
//! configuration, and RFC 8555 §8.3 explicitly permits following it — saying, in
//! the same breath, that the responder's certificate is *not* validated. Boulder,
//! Pebble and step-ca all follow. So does this validator, by default.
//!
//! The cost is real: an account holder can make this server issue GET requests
//! to wherever it points a `Location` header, and Boulder's mitigation — refusing
//! RFC1918 destinations — is unavailable here, because serving private networks
//! is the entire purpose of this server. What keeps it a nuisance rather than an
//! exfiltration channel is a set of rules that must not be relaxed casually:
//!
//! - only `http` and `https`, only the two configured ports;
//! - at most `max_redirects` hops, and `follow_redirects` turns it off entirely;
//! - the whole chain shares the registry's one timeout;
//! - **the fetched body is never echoed into the client-visible error**. The
//!   client is told the status and the length, nothing more. A truncated preview
//!   is logged at `debug`, server-side.
//!
//! Operators who want the request itself not to happen have
//! [`filter.allowed_ip`](crate::filter::ip_allow) and
//! [`filter.identifiers`](crate::filter::identifiers).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use tracing::{debug, info, warn};
use url::Url;

use super::{ChallengeError, ChallengeValidator, HTTP_01, ValidationContext};
use crate::config::Http01Config;
use crate::dns::Resolver;

/// The well-known path RFC 8555 §8.3 reserves for this challenge.
///
/// Shared with the *other* direction: the `relay` signer's
/// [`http01`](crate::signer::relay::http01) strategy answers an upstream
/// CA's own challenge, and the route it is served from is built from this
/// constant. Same rule the `dns-01` pair follows, where
/// [`super::dns_01::record_name`] and [`super::dns_01::expected_value`] are
/// called by the publisher rather than restated — a validator and a responder
/// that disagree about the convention would fail in the least legible way.
pub(crate) const WELL_KNOWN_PREFIX: &str = "/.well-known/acme-challenge/";

/// What one HTTP request returned.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    /// The `Location` header, if any. The redirect *policy* is the validator's,
    /// not the fetcher's.
    pub location: Option<String>,
    pub body: Vec<u8>,
    /// The body hit the caller's cap and was cut short. A truncated body is
    /// refused without being compared — the key authorization is under a hundred
    /// bytes and nothing else belongs at that URL.
    pub truncated: bool,
}

/// Why a single fetch produced no response.
#[derive(Debug)]
pub enum FetchError {
    /// Nothing answered: DNS, TCP connect, TLS, the socket dying.
    Connect(String),
    /// Something answered, but not with usable HTTP.
    Protocol(String),
}

/// A single HTTP GET.
///
/// Deliberately **does not follow redirects**: that policy lives in
/// [`Http01Validator`], where a stub can drive every branch of it without a
/// listener.
#[async_trait]
pub trait HttpFetcher: Send + Sync {
    async fn get(&self, url: &Url, max_bytes: usize) -> Result<HttpResponse, FetchError>;
}

/// Fetches the challenge file and compares it to the key authorization.
pub struct Http01Validator {
    fetcher: Arc<dyn HttpFetcher>,
    port: u16,
    https_port: u16,
    follow_redirects: bool,
    max_redirects: u8,
    max_response_bytes: usize,
}

impl std::fmt::Debug for Http01Validator {
    /// `dyn HttpFetcher` is not `Debug`; the policy is what matters.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http01Validator")
            .field("port", &self.port)
            .field("https_port", &self.https_port)
            .field("follow_redirects", &self.follow_redirects)
            .field("max_redirects", &self.max_redirects)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl Http01Validator {
    /// Builds the validator with a real HTTP client, resolving its connect
    /// target through `resolver` — the same one `challenge::from_config`
    /// selected for `dns-01` (`dns.resolver` if set, else the system
    /// configuration), so a deployment overriding it gets one consistent
    /// answer for every challenge type rather than `dns-01` alone.
    pub fn from_config(cfg: &Http01Config, resolver: Arc<dyn Resolver>) -> anyhow::Result<Self> {
        let fetcher = Arc::new(
            HyperFetcher::new(resolver)
                .map_err(|error| anyhow::anyhow!("challenge.http_01: {error}"))?,
        );
        info!(
            event = "challenge_http_01_loaded",
            outcome = "success",
            port = cfg.port,
            follow_redirects = cfg.follow_redirects,
        );
        Ok(Self::with_fetcher(cfg, fetcher))
    }

    /// Same, against a caller-supplied fetcher. Used by tests.
    pub fn with_fetcher(cfg: &Http01Config, fetcher: Arc<dyn HttpFetcher>) -> Self {
        Self {
            fetcher,
            port: cfg.port,
            https_port: cfg.https_port,
            follow_redirects: cfg.follow_redirects,
            max_redirects: cfg.max_redirects,
            max_response_bytes: cfg.max_response_bytes,
        }
    }

    /// The URL the challenge file must be served at.
    fn challenge_url(&self, identifier: &str, token: &str) -> Result<Url, ChallengeError> {
        let authority = if self.port == 80 {
            identifier.to_string()
        } else {
            format!("{identifier}:{}", self.port)
        };
        Url::parse(&format!("http://{authority}{WELL_KNOWN_PREFIX}{token}")).map_err(|error| {
            ChallengeError::Internal(format!(
                "building the challenge URL for {identifier}: {error}"
            ))
        })
    }

    /// Whether a redirect target is somewhere this validator will follow.
    ///
    /// Without this a `Location: file:///etc/passwd` or
    /// `http://10.0.0.5:9200/` would turn the validator into a file reader and a
    /// port scanner respectively.
    fn redirect_allowed(&self, target: &Url) -> Result<(), ChallengeError> {
        let (scheme, expected_port) = match target.scheme() {
            "http" => ("http", self.port),
            "https" => ("https", self.https_port),
            other => {
                return Err(ChallengeError::Unauthorized(format!(
                    "redirect to unsupported scheme {other}"
                )));
            }
        };

        let default_port = if scheme == "http" { 80 } else { 443 };
        let port = target.port().unwrap_or(default_port);
        if port != expected_port {
            return Err(ChallengeError::Unauthorized(format!(
                "redirect to {scheme} port {port}, which is not the configured {expected_port}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl ChallengeValidator for Http01Validator {
    fn typ(&self) -> &'static str {
        HTTP_01
    }

    async fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        let mut url = self.challenge_url(ctx.identifier, ctx.token)?;

        for hop in 0..=self.max_redirects {
            let response = self
                .fetcher
                .get(&url, self.max_response_bytes)
                .await
                .map_err(|error| match error {
                    FetchError::Connect(detail) => ChallengeError::Connection(detail),
                    // A reply that is not HTTP still means something answered,
                    // but the client's setup is what is wrong.
                    FetchError::Protocol(detail) => ChallengeError::Connection(detail),
                })?;

            if let (true, Some(location)) = (is_redirect(response.status), &response.location) {
                if !self.follow_redirects {
                    return Err(ChallengeError::Unauthorized(format!(
                        "{url} redirected but following redirects is disabled"
                    )));
                }
                let target = url.join(location).map_err(|error| {
                    ChallengeError::Unauthorized(format!("redirect Location is not a URL: {error}"))
                })?;
                self.redirect_allowed(&target)?;
                debug!(
                    event = "challenge_http_01_redirect",
                    outcome = "progress",
                    from = %url,
                    to = %target,
                    hop,
                    challenge_id = ctx.challenge_id,
                );
                url = target;
                continue;
            }

            if response.status != 200 {
                return Err(ChallengeError::Unauthorized(format!(
                    "{url} responded with HTTP {}",
                    response.status
                )));
            }

            if response.truncated {
                return Err(ChallengeError::Unauthorized(format!(
                    "{url} responded with more than {} bytes",
                    self.max_response_bytes
                )));
            }

            // RFC 8555 §8.3: leading and trailing whitespace is ignored, so a
            // webroot file written with a trailing newline still matches.
            let body = String::from_utf8_lossy(&response.body);
            if body.trim() == ctx.key_authorization {
                debug!(
                    event = "challenge_http_01_matched",
                    outcome = "success",
                    probe_url = %url,
                    challenge_id = ctx.challenge_id,
                );
                return Ok(());
            }

            // The responder answered but with the wrong content — the single
            // most useful signal that a client is misconfigured, so it belongs
            // at `warn` where the default filter shows it.
            warn!(
                event = "challenge_http_01_mismatch",
                outcome = "failure",
                probe_url = %url,
                challenge_id = ctx.challenge_id,
                body_bytes = response.body.len(),
            );
            // The preview stays at `debug`, separately: the body is
            // attacker-controlled and may be the response to a redirect the
            // client chose, so it must not be promoted into the level an
            // operator alerts on. The client itself learns the length, never
            // the content.
            debug!(
                event = "challenge_http_01_mismatch_body",
                outcome = "failure",
                probe_url = %url,
                challenge_id = ctx.challenge_id,
                preview = %body.chars().take(64).collect::<String>(),
            );
            return Err(ChallengeError::Unauthorized(format!(
                "{url} served {} bytes that are not the key authorization",
                response.body.len()
            )));
        }

        Err(ChallengeError::Connection(format!(
            "more than {} redirects while validating {}",
            self.max_redirects, ctx.identifier
        )))
    }
}

/// The 3xx statuses that carry a `Location` worth following.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// The production fetcher: one HTTP/1.1 request per call, over TCP or TLS.
pub struct HyperFetcher {
    tls: Arc<rustls::ClientConfig>,
    resolver: Arc<dyn Resolver>,
}

impl HyperFetcher {
    pub fn new(resolver: Arc<dyn Resolver>) -> anyhow::Result<Self> {
        // No ALPN: this is an ordinary https request, not a challenge handshake.
        // The certificate is not validated — RFC 8555 §8.3 says so explicitly,
        // and the proof is the body, not the transport.
        Ok(Self {
            tls: super::tls_alpn_01::accept_any_client_config(&[])?,
            resolver,
        })
    }

    /// Sends the request over an established connection and reads a capped body.
    async fn exchange(
        mut sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        url: &Url,
        max_bytes: usize,
    ) -> Result<HttpResponse, FetchError> {
        let authority = url
            .host_str()
            .map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
            .ok_or_else(|| FetchError::Protocol(format!("{url} has no host")))?;

        let mut target = url.path().to_string();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }

        // The low-level client sends what it is given: hyper 1.x does not add a
        // `Host` header, and a request without one is rejected by most servers.
        let request = Request::builder()
            .uri(target)
            .header(hyper::header::HOST, &authority)
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|error| FetchError::Protocol(format!("building the request: {error}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|error| FetchError::Protocol(format!("request to {url} failed: {error}")))?;

        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(hyper::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        // `Limited` errors once the cap is passed; that is the signal, not a
        // failure — a body too large is refused without being read further.
        let (body, truncated) = match Limited::new(response.into_body(), max_bytes)
            .collect()
            .await
        {
            Ok(collected) => (collected.to_bytes().to_vec(), false),
            Err(_) => (Vec::new(), true),
        };

        Ok(HttpResponse {
            status,
            location,
            body,
            truncated,
        })
    }
}

#[async_trait]
impl HttpFetcher for HyperFetcher {
    async fn get(&self, url: &Url, max_bytes: usize) -> Result<HttpResponse, FetchError> {
        // Resolved and connected through the shared resolver rather than left
        // to `TcpStream::connect`'s own OS-level lookup, so `dns.resolver`
        // governs this connect target the same way it governs the `dns-01` TXT
        // query — and so a dual-stack answer whose first address is
        // unreachable falls back rather than failing outright. That is
        // `http_client::connect`'s job now; this validator is the one client
        // that always did it right, and the other three were brought to it.
        //
        // The TLS configuration handed over is `accept_any_client_config`:
        // RFC 8555 §8.3 says the responder's certificate is *not* validated —
        // what it carries is the proof. That is the policy this module keeps
        // for itself, and the only reason it cannot share more than transport.
        let endpoint = crate::http_client::Endpoint::from_url(url).map_err(FetchError::Protocol)?;

        let sender = crate::http_client::connect(self.resolver.as_ref(), &endpoint, &self.tls)
            .await
            .map_err(FetchError::Connect)?;

        Self::exchange(sender, url, max_bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const KEY_AUTH: &str = "token-value.thumbprint-value";
    const TOKEN: &str = "token-value";

    /// A fetcher answering from canned responses, recording what it was asked
    /// for.
    #[derive(Default)]
    struct StubFetcher {
        responses: HashMap<String, (u16, Option<String>, Vec<u8>, bool)>,
        error: Option<&'static str>,
        requested: Mutex<Vec<String>>,
    }

    impl StubFetcher {
        fn serving(url: &str, body: &str) -> Self {
            Self::default().with(url, 200, None, body.as_bytes().to_vec(), false)
        }

        fn with(
            mut self,
            url: &str,
            status: u16,
            location: Option<&str>,
            body: Vec<u8>,
            truncated: bool,
        ) -> Self {
            self.responses.insert(
                url.to_string(),
                (status, location.map(str::to_string), body, truncated),
            );
            self
        }

        fn redirecting(url: &str, to: &str) -> Self {
            Self::default().with(url, 301, Some(to), Vec::new(), false)
        }

        fn failing(error: &'static str) -> Self {
            Self {
                error: Some(error),
                ..Self::default()
            }
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpFetcher for StubFetcher {
        async fn get(&self, url: &Url, _max_bytes: usize) -> Result<HttpResponse, FetchError> {
            self.requested.lock().unwrap().push(url.to_string());
            if let Some(error) = self.error {
                return Err(FetchError::Connect(error.to_string()));
            }
            match self.responses.get(url.as_str()) {
                Some((status, location, body, truncated)) => Ok(HttpResponse {
                    status: *status,
                    location: location.clone(),
                    body: body.clone(),
                    truncated: *truncated,
                }),
                // An unmapped URL stands in for "nothing there".
                None => Ok(HttpResponse {
                    status: 404,
                    location: None,
                    body: Vec::new(),
                    truncated: false,
                }),
            }
        }
    }

    fn validate_with(cfg: Http01Config, fetcher: Arc<StubFetcher>) -> Http01Validator {
        Http01Validator::with_fetcher(&cfg, fetcher)
    }

    fn context(identifier: &str) -> ValidationContext<'_> {
        ValidationContext {
            identifier,
            wildcard: false,
            token: TOKEN,
            key_authorization: KEY_AUTH,
            challenge_id: "chall-1",
        }
    }

    const CHALLENGE_URL: &str = "http://example.com/.well-known/acme-challenge/token-value";

    #[tokio::test]
    async fn the_key_authorization_is_fetched_from_the_well_known_url() {
        let fetcher = Arc::new(StubFetcher::serving(CHALLENGE_URL, KEY_AUTH));
        let validator = validate_with(Http01Config::default(), fetcher.clone());

        assert!(validator.validate(&context("example.com")).await.is_ok());
        assert_eq!(fetcher.requested(), vec![CHALLENGE_URL.to_string()]);
    }

    /// RFC 8555 §8.3 ignores surrounding whitespace — a webroot file written by
    /// `echo` has a trailing newline.
    #[tokio::test]
    async fn surrounding_whitespace_is_ignored() {
        let fetcher = Arc::new(StubFetcher::serving(
            CHALLENGE_URL,
            &format!("  {KEY_AUTH}\n"),
        ));
        assert!(
            validate_with(Http01Config::default(), fetcher)
                .validate(&context("example.com"))
                .await
                .is_ok()
        );
    }

    /// The body may be the response to a redirect the client chose, so it must
    /// never reach the client-visible problem document.
    #[tokio::test]
    async fn a_wrong_body_is_refused_without_echoing_it() {
        let secret = "internal-api-token-abc123";
        let fetcher = Arc::new(StubFetcher::serving(CHALLENGE_URL, secret));
        let error = validate_with(Http01Config::default(), fetcher)
            .validate(&context("example.com"))
            .await
            .unwrap_err();

        match &error {
            ChallengeError::Unauthorized(detail) => {
                assert!(!detail.contains(secret), "the body leaked: {detail}");
                assert!(detail.contains("25 bytes"), "{detail}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_non_200_response_is_refused() {
        // Nothing is mapped, so the stub answers 404.
        let error = validate_with(Http01Config::default(), Arc::new(StubFetcher::default()))
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Unauthorized(detail) if detail.contains("HTTP 404")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_target_is_a_connection_error() {
        let error = validate_with(
            Http01Config::default(),
            Arc::new(StubFetcher::failing("connection refused")),
        )
        .validate(&context("example.com"))
        .await
        .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Connection(detail) if detail.contains("refused")),
            "{error:?}"
        );
    }

    /// The common deployment: port 80 redirects everything to https.
    #[tokio::test]
    async fn a_redirect_to_https_is_followed() {
        const HTTPS_URL: &str = "https://example.com/.well-known/acme-challenge/token-value";
        let fetcher = Arc::new(StubFetcher::redirecting(CHALLENGE_URL, HTTPS_URL).with(
            HTTPS_URL,
            200,
            None,
            KEY_AUTH.as_bytes().to_vec(),
            false,
        ));
        let validator = validate_with(Http01Config::default(), fetcher.clone());

        assert!(validator.validate(&context("example.com")).await.is_ok());
        assert_eq!(
            fetcher.requested(),
            vec![CHALLENGE_URL.to_string(), HTTPS_URL.to_string()]
        );
    }

    #[tokio::test]
    async fn a_relative_location_is_resolved_against_the_current_url() {
        const MOVED: &str = "http://example.com/elsewhere";
        let fetcher = Arc::new(StubFetcher::redirecting(CHALLENGE_URL, "/elsewhere").with(
            MOVED,
            200,
            None,
            KEY_AUTH.as_bytes().to_vec(),
            false,
        ));
        let validator = validate_with(Http01Config::default(), fetcher.clone());

        assert!(validator.validate(&context("example.com")).await.is_ok());
        assert_eq!(fetcher.requested()[1], MOVED);
    }

    /// A redirect loop must terminate at the cap rather than spinning until the
    /// registry's timeout fires.
    #[tokio::test]
    async fn a_redirect_loop_stops_at_the_cap() {
        let fetcher = Arc::new(StubFetcher::redirecting(CHALLENGE_URL, CHALLENGE_URL));
        let cfg = Http01Config {
            max_redirects: 3,
            ..Http01Config::default()
        };
        let validator = validate_with(cfg, fetcher.clone());

        let error = validator
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Connection(detail) if detail.contains("more than 3 redirects")),
            "{error:?}"
        );
        // The cap counts hops, so the first request plus three redirects.
        assert_eq!(fetcher.requested().len(), 4);
    }

    /// Without a scheme check the validator reads local files on request.
    #[tokio::test]
    async fn a_redirect_to_another_scheme_is_refused() {
        let fetcher = Arc::new(StubFetcher::redirecting(
            CHALLENGE_URL,
            "file:///etc/passwd",
        ));
        let error = validate_with(Http01Config::default(), fetcher)
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Unauthorized(detail) if detail.contains("unsupported scheme")),
            "{error:?}"
        );
    }

    /// Without a port check the validator is a port scanner for the client's
    /// own network.
    #[tokio::test]
    async fn a_redirect_to_another_port_is_refused() {
        let fetcher = Arc::new(StubFetcher::redirecting(
            CHALLENGE_URL,
            "http://10.0.0.5:9200/_cluster/health",
        ));
        let error = validate_with(Http01Config::default(), fetcher)
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Unauthorized(detail) if detail.contains("port 9200")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn redirects_can_be_turned_off_entirely() {
        let fetcher = Arc::new(StubFetcher::redirecting(
            CHALLENGE_URL,
            "https://example.com/.well-known/acme-challenge/token-value",
        ));
        let cfg = Http01Config {
            follow_redirects: false,
            ..Http01Config::default()
        };
        let error = validate_with(cfg, fetcher.clone())
            .validate(&context("example.com"))
            .await
            .unwrap_err();

        assert!(
            matches!(&error, ChallengeError::Unauthorized(detail) if detail.contains("disabled")),
            "{error:?}"
        );
        assert_eq!(fetcher.requested().len(), 1);
    }

    /// An oversized body is refused *without* being compared — the key
    /// authorization is under a hundred bytes.
    #[tokio::test]
    async fn an_oversized_body_is_refused_without_comparison() {
        let fetcher = Arc::new(StubFetcher::default().with(
            CHALLENGE_URL,
            200,
            None,
            KEY_AUTH.as_bytes().to_vec(),
            true,
        ));
        let error = validate_with(Http01Config::default(), fetcher)
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Unauthorized(detail) if detail.contains("more than 4096 bytes")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_non_default_port_appears_in_the_url() {
        const URL: &str = "http://example.com:8080/.well-known/acme-challenge/token-value";
        let fetcher = Arc::new(StubFetcher::serving(URL, KEY_AUTH));
        let cfg = Http01Config {
            port: 8080,
            ..Http01Config::default()
        };
        let validator = validate_with(cfg, fetcher.clone());

        assert!(validator.validate(&context("example.com")).await.is_ok());
        assert_eq!(fetcher.requested(), vec![URL.to_string()]);
    }

    #[test]
    fn reports_its_challenge_type() {
        assert_eq!(
            validate_with(Http01Config::default(), Arc::new(StubFetcher::default())).typ(),
            "http-01"
        );
    }

    #[test]
    fn only_3xx_statuses_carrying_a_location_are_redirects() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect(status), "{status}");
        }
        for status in [200, 204, 304, 400, 404, 500] {
            assert!(!is_redirect(status), "{status}");
        }
    }

    /// The real fetcher, against a loopback listener. This is the only thing
    /// that catches a missing `Host` header or a mis-formatted request line — a
    /// stub never would.
    mod loopback {
        use super::*;
        use std::net::IpAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// Every test here targets `127.0.0.1` literally, so `resolve_first`
        /// short-circuits before ever asking a resolver anything.
        struct UnreachableResolver;

        #[async_trait]
        impl Resolver for UnreachableResolver {
            async fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
                unreachable!()
            }
            async fn forward(&self, _name: &str) -> Result<Vec<IpAddr>, String> {
                unreachable!("a literal 127.0.0.1 must short-circuit before this is called")
            }
            async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
                unreachable!()
            }
        }

        fn fetcher() -> HyperFetcher {
            HyperFetcher::new(Arc::new(UnreachableResolver)).unwrap()
        }

        /// Serves one canned response and returns the request it received.
        async fn serve_once(response: &'static str) -> (u16, tokio::task::JoinHandle<String>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 2048];
                let read = stream.read(&mut buffer).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                String::from_utf8_lossy(&buffer[..read]).into_owned()
            });

            (port, handle)
        }

        #[tokio::test]
        async fn fetches_a_body_and_sends_a_host_header() {
            let (port, server) = serve_once(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .await;
            let url = Url::parse(&format!("http://127.0.0.1:{port}/.well-known/x")).unwrap();

            let response = fetcher().get(&url, 4096).await.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"hello");
            assert!(!response.truncated);

            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /.well-known/x HTTP/1.1"),
                "{request}"
            );
            assert!(
                request
                    .to_lowercase()
                    .contains(&format!("host: 127.0.0.1:{port}")),
                "{request}"
            );
        }

        #[tokio::test]
        async fn reads_a_redirect_location() {
            let (port, _server) = serve_once(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/x\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            let url = Url::parse(&format!("http://127.0.0.1:{port}/x")).unwrap();

            let response = fetcher().get(&url, 4096).await.unwrap();
            assert_eq!(response.status, 301);
            assert_eq!(response.location.as_deref(), Some("https://example.com/x"));
        }

        #[tokio::test]
        async fn a_body_over_the_cap_is_reported_as_truncated() {
            let (port, _server) = serve_once(
                "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n\
                 aaaaaaaaaaaaaaaaaaaa",
            )
            .await;
            let url = Url::parse(&format!("http://127.0.0.1:{port}/x")).unwrap();

            let response = fetcher().get(&url, 8).await.unwrap();
            assert!(response.truncated);
        }

        #[tokio::test]
        async fn a_closed_port_is_a_connect_error() {
            // Bind then drop, so the port is almost certainly free and unbound.
            let port = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap().port()
            };
            let url = Url::parse(&format!("http://127.0.0.1:{port}/x")).unwrap();

            let error = fetcher().get(&url, 4096).await.unwrap_err();
            assert!(matches!(&error, FetchError::Connect(_)), "{error:?}");
        }

        /// The request line carries the query string. A challenge URL has none,
        /// but a redirect can land on one, and dropping it would fetch a
        /// different resource than the one that was redirected to.
        #[tokio::test]
        async fn the_request_target_keeps_the_query_string() {
            let (port, server) =
                serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            let url =
                Url::parse(&format!("http://127.0.0.1:{port}/.well-known/x?a=1&b=2")).unwrap();

            fetcher().get(&url, 4096).await.unwrap();
            let request = server.await.unwrap();
            assert!(
                request.starts_with("GET /.well-known/x?a=1&b=2 "),
                "{request}"
            );
        }

        /// A cleartext server on an `https` URL fails the handshake. The point
        /// is that the failure is a `Connect` error naming the host, not a
        /// panic or a silent fall back to plaintext.
        #[tokio::test]
        async fn an_https_url_against_a_cleartext_server_is_a_connect_error() {
            let (port, _server) =
                serve_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            let url = Url::parse(&format!("https://127.0.0.1:{port}/x")).unwrap();

            let error = fetcher().get(&url, 4096).await.unwrap_err();
            assert!(matches!(&error, FetchError::Connect(_)), "{error:?}");
        }
    }

    /// `dyn HttpFetcher` is not `Debug`, so the validator renders its policy —
    /// the ports and redirect limits an operator would check a startup log for.
    #[test]
    fn the_validator_debug_shows_its_policy() {
        let validator = validate_with(
            Http01Config {
                port: 8080,
                https_port: 8443,
                follow_redirects: false,
                max_redirects: 2,
                max_response_bytes: 1024,
            },
            Arc::new(StubFetcher::default()),
        );
        let rendered = format!("{validator:?}");
        for expected in ["Http01Validator", "8080", "8443", "false", "1024"] {
            assert!(
                rendered.contains(expected),
                "{expected} missing: {rendered}"
            );
        }
    }

    /// A `Location` that is neither absolute nor a valid relative reference
    /// cannot be resolved against the current URL. Refusing is the only safe
    /// answer — guessing would mean fetching something nobody named.
    #[tokio::test]
    async fn a_location_that_is_not_a_url_is_refused() {
        let fetcher = Arc::new(StubFetcher::redirecting(CHALLENGE_URL, "http://"));
        let error = validate_with(Http01Config::default(), fetcher)
            .validate(&context("example.com"))
            .await
            .unwrap_err();
        match error {
            ChallengeError::Unauthorized(detail) => {
                assert!(detail.contains("Location is not a URL"), "{detail}")
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }
}
