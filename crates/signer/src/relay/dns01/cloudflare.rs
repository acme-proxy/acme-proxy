//! Cloudflare's DNS API: the [`DnsUpdater`] for a zone on Cloudflare's own
//! nameservers.
//!
//! ## Why a provider rather than a bridge
//!
//! Cloudflare serves a zone from its own nameservers and accepts changes to it
//! through its API alone: it takes no RFC 2136 update and knows no TSIG key.
//! So a zone there is written over HTTP, and the alternative — a nameserver
//! speaking `nsupdate` here and the Cloudflare API there — is a piece of
//! infrastructure the operator has to run, secure and keep in step with the
//! zone. This provider removes it.
//!
//! ## What the API costs that a DNS update does not
//!
//! Two things follow from the API being an API rather than the authoritative
//! server itself, and both are visible to an operator:
//!
//! - **A retraction is two requests.** `nsupdate` deletes one value in one
//!   packet ([`rfc2136`](super::rfc2136)); Cloudflare identifies a record by an
//!   internal id, so retracting means listing the TXT records at the name,
//!   finding the one whose content matches, and deleting *that* id. Matching by
//!   content is what keeps the trait's retract-by-value promise intact: several
//!   live challenges share one record name, and this server never clears a name
//!   it does not own the value at.
//! - **An accepted write is not a served record.** The API answers before every
//!   Cloudflare edge has the value, which is what
//!   `signer.relay.dns01.propagation`'s `delay` mode exists for, and why this
//!   provider recommends it rather than working fine with the default `none`.
//!
//! Unlike the RFC 2136 provider this one is an ordinary outbound HTTPS client,
//! so it dials through the configuration generation's `dns.resolver` and
//! `[proxy]` like the upstream CA, the IPAM inventory and the notification
//! webhooks do — see [`acme_proxy_net::egress`].
//!
//! ## The credential
//!
//! A scoped API token in `Authorization: Bearer`, needing only
//! `Zone / DNS / Edit` on the zone. The legacy global API key (`X-Auth-Token`)
//! is deliberately unsupported: it authenticates the *account*, so it can do
//! everything in it, and Cloudflare is phasing it out.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::rr::Name;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;
use url::Url;

use acme_proxy_core::config::CloudflareConfig;
use acme_proxy_net::http_client::{Endpoint, MAX_RESPONSE_BYTES, Outbound, error_excerpt};

use super::{DnsUpdater, check_in_zone};

/// The API's root. Private rather than a configuration key: this provider
/// speaks Cloudflare, and an operator who needs a proxy in front of it has
/// `[proxy]`. A test points elsewhere through [`CloudflareUpdater::at_base`].
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// TTL on a published record: 60 seconds, the shortest Cloudflare allows on a
/// non-Enterprise zone (an Enterprise zone may go to 30). Deliberately short for
/// the reason `rfc2136` gives its own: a challenge record is wanted for seconds,
/// and a long TTL keeps a stale value cached past the point the CA reads it.
const RECORD_TTL: u32 = 60;

/// Budget for one API request. The relay's own `poll_timeout_secs` bounds the
/// whole attempt; this bounds a single hop, so a black-holed API surfaces as a
/// retryable failure rather than as a stalled job.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Records asked for per page. Cloudflare's maximum, so the common case — a
/// challenge name with one or two values at it — is one request.
const PAGE_SIZE: u32 = 100;

/// Pages [`CloudflareUpdater::list_txt`] will walk before refusing. A name with
/// more than this many TXT records is not a challenge name this server wrote,
/// and walking an unbounded listing with a credential in hand is not what a
/// best-effort cleanup is for.
const MAX_PAGES: u32 = 10;

/// The one field of a listed record this provider needs: Cloudflare's own id,
/// which is how a record is deleted, and the content, which is how the right
/// one is found.
#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    content: String,
}

/// Cloudflare's DNS API as a [`DnsUpdater`].
pub struct CloudflareUpdater {
    /// API root with no trailing slash, so a deployment behind a gateway that
    /// mounts it under a prefix still works.
    base: String,
    /// The zone's Cloudflare id, the path segment every call is addressed to.
    zone_id: String,
    /// The configured apex, absolute, for [`check_in_zone`] — and the zone an
    /// operator is told about, since every name this type refuses names it.
    zone_name: Name,
    /// The whole `Authorization` header value, built once so the token is
    /// assembled at startup and never concatenated per request — which is also
    /// what keeps it out of every error message this type produces.
    authorization: String,
    tls: Arc<rustls::ClientConfig>,
    /// This generation's resolver and proxy policy: this provider is an HTTP
    /// client, so `[dns]` and `[proxy]` apply to it.
    outbound: Outbound,
    timeout: Duration,
}

impl std::fmt::Debug for CloudflareUpdater {
    /// Never renders `authorization`: it is the credential.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudflareUpdater")
            .field("base", &self.base)
            .field("zone_id", &self.zone_id)
            .field("zone", &self.zone_name)
            .finish_non_exhaustive()
    }
}

impl CloudflareUpdater {
    /// Validates the configuration and builds the client.
    ///
    /// Nothing is contacted: unlike the RFC 2136 provider's `server`, the API
    /// endpoint is not a configured key, and an unreachable API must not stop a
    /// server that issues from this zone (see
    /// [`CloudflareConfig::zone_id`]'s note on why the id is configured rather
    /// than looked up).
    pub fn from_config(cfg: &CloudflareConfig, outbound: Outbound) -> anyhow::Result<Self> {
        Self::build(cfg, outbound, API_BASE)
    }

    /// The same construction pointed at `base`, which is how a test drives the
    /// real transport against a loopback stub.
    #[cfg(test)]
    fn at_base(cfg: &CloudflareConfig, outbound: Outbound, base: &str) -> anyhow::Result<Self> {
        Self::build(cfg, outbound, base)
    }

    fn build(cfg: &CloudflareConfig, outbound: Outbound, base: &str) -> anyhow::Result<Self> {
        let token = cfg.api_token.trim();
        if token.is_empty() {
            anyhow::bail!("signer.relay.dns01.cloudflare.api_token is not set");
        }
        refuse_unsendable(token, "signer.relay.dns01.cloudflare.api_token")?;

        let zone_id = cfg.zone_id.trim();
        if zone_id.is_empty() {
            anyhow::bail!("signer.relay.dns01.cloudflare.zone_id is not set");
        }
        refuse_unsendable(zone_id, "signer.relay.dns01.cloudflare.zone_id")?;

        // A trailing dot is accepted, because `[signer.relay.dns01.rfc2136]`'s
        // `zone` is spelled with one and Cloudflare's own UI spells it without.
        let zone = cfg.zone.trim().trim_end_matches('.');
        if zone.is_empty() {
            anyhow::bail!("signer.relay.dns01.cloudflare.zone is not set");
        }
        // Absolute, so [`check_in_zone`] compares two absolute names whatever
        // the spelling in the file was.
        let zone_name = Name::from_utf8(format!("{zone}.")).map_err(|error| {
            anyhow::anyhow!(
                "signer.relay.dns01.cloudflare.zone ({}) is not a DNS name: {error}",
                cfg.zone
            )
        })?;

        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            zone_id: zone_id.to_string(),
            zone_name,
            authorization: format!("Bearer {token}"),
            // The public roots, as the relay's own upstream client uses: this
            // is a credential leaving, so the certificate is the only thing
            // saying which API it arrives at. There is deliberately no
            // `insecure_skip_verify` here, unlike the IPAM clients.
            tls: Arc::new(acme_proxy_net::http_client::webpki_tls_config()),
            outbound,
            timeout: REQUEST_TIMEOUT,
        })
    }

    /// `name` as the API wants it: refused before any request unless it lies in
    /// the configured zone, and without the trailing dot Cloudflare's `name`
    /// field does not take.
    ///
    /// The zone test is the one [`rfc2136`](super::rfc2136) uses, so a
    /// `challenge_alias` cannot be inside one provider's zone and outside the
    /// other's.
    fn record_name(&self, name: &str) -> Result<String, String> {
        let absolute = absolute(name);
        check_in_zone(&self.zone_name, &absolute)?;
        Ok(absolute.trim_end_matches('.').to_string())
    }

    /// The zone test on its own, which is what the startup check on
    /// `challenge_alias` uses so that both providers are asked the same question
    /// the same way.
    pub fn check_in_zone(&self, name: &str) -> Result<Name, String> {
        check_in_zone(&self.zone_name, &absolute(name))
    }

    /// The collection every call is addressed to.
    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.base, self.zone_id)
    }

    /// The TXT records at `name`, across every page Cloudflare reports.
    async fn list_txt(&self, name: &str) -> Result<Vec<DnsRecord>, String> {
        let mut records = Vec::new();
        let mut page = 1u32;
        loop {
            let per_page = PAGE_SIZE.to_string();
            let page_number = page.to_string();
            let url = Url::parse_with_params(
                &self.records_url(),
                &[
                    ("name", name),
                    ("type", "TXT"),
                    ("per_page", per_page.as_str()),
                    ("page", page_number.as_str()),
                ],
            )
            .map_err(|error| format!("{}: {error}", self.records_url()))?;

            let answer = self.request(Method::GET, url.as_str(), None).await?;
            let listed = answer["result"]
                .as_array()
                .ok_or_else(|| format!("{url} named no `result` array"))?;
            for entry in listed {
                records
                    .push(serde_json::from_value(entry.clone()).map_err(|error| {
                        format!("{url} returned an unreadable record: {error}")
                    })?);
            }

            let total_pages = answer["result_info"]["total_pages"].as_u64().unwrap_or(1);
            if listed.is_empty() || u64::from(page) >= total_pages {
                return Ok(records);
            }
            if page >= MAX_PAGES {
                return Err(format!(
                    "{} lists more than {MAX_PAGES} pages of TXT records at {name}; refusing to \
                     walk them",
                    self.records_url()
                ));
            }
            page += 1;
        }
    }

    /// Whether this server's own value is sitting at `name`.
    async fn record_present(&self, name: &str, value: &str) -> Result<bool, String> {
        Ok(self
            .list_txt(name)
            .await?
            .iter()
            .any(|record| record.content == value))
    }

    /// One request, answered with the whole `success`/`errors`/`result`
    /// envelope once both the status and Cloudflare's own verdict agree that it
    /// worked.
    async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        tokio::time::timeout(self.timeout, self.request_inner(method.clone(), url, body))
            .await
            .map_err(|_| format!("{method} {url} timed out after {:?}", self.timeout))?
    }

    async fn request_inner(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        // The verb is needed in the messages as well as in the request line, and
        // `Method` is not `Copy`, so the wording is rendered once up front.
        let verb = method.to_string();
        let parsed = Url::parse(url).map_err(|error| format!("{url} is not a URL: {error}"))?;
        let endpoint = Endpoint::from_url(&parsed)
            .map_err(|error| format!("{url} is not a usable endpoint: {error}"))?;

        let mut connection = self
            .outbound
            .connect(&endpoint, &self.tls)
            .await
            .map_err(|error| format!("{verb} {url} failed: {error}"))?;

        // Origin-form directly, absolute-form when a proxy forwards this hop.
        let payload = body.map(|document| Bytes::from(document.to_string()));
        let mut builder = Request::builder()
            .method(method)
            .uri(connection.request_target(&parsed))
            .header(HOST, endpoint.authority())
            .header(USER_AGENT, "acme-proxy")
            .header(ACCEPT, "application/json")
            .header(CONNECTION, "close")
            .header(AUTHORIZATION, self.authorization.as_str());
        if payload.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(Full::new(payload.unwrap_or_default()))
            .map_err(|error| format!("building the request: {error}"))?;

        let response = connection
            .send_request(request)
            .await
            .map_err(|error| format!("{verb} {url} failed: {error}"))?;

        let status = response.status();
        // Capped like every other outbound client here: a remote API's choice
        // of how much to send is not this process's memory to spend.
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| format!("the response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"))?
            .to_bytes();

        if !status.is_success() {
            return Err(format!(
                "{url} answered {status}: {}",
                refusal_detail(&body)
            ));
        }

        // Cloudflare answers a refusal with its envelope too, and the envelope
        // is the one thing that says which of the two this is: `success` is the
        // verdict, `errors` the diagnosis. Reading the status alone would call a
        // `200` whose `success` is `false` a publish that happened.
        let document: Value = serde_json::from_slice(&body)
            .map_err(|error| format!("{url} returned unreadable JSON: {error}"))?;
        if document.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "{url} refused the request: {}",
                refusal_detail(&body)
            ));
        }
        Ok(document)
    }
}

#[async_trait]
impl DnsUpdater for CloudflareUpdater {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let name = self.record_name(name)?;
        let url = self.records_url();
        let body = json!({
            "type": "TXT",
            "name": name,
            "content": value,
            "ttl": RECORD_TTL,
        });

        match self.request(Method::POST, &url, Some(body)).await {
            Ok(_) => Ok(()),
            // A retry of a publish whose answer was lost in transit, and a
            // concurrent order for the same name and value, can both arrive here
            // with Cloudflare declining to hold a second copy of a record it
            // already has. What the relay cares about is whether the value is at
            // the name NOW, so ask: if it is, the record the CA will look for
            // exists, and reporting a failure would fail an order that is about
            // to validate. One extra request, on a path already going wrong.
            Err(refusal) => match self.record_present(&name, value).await {
                Ok(true) => {
                    debug!(
                        event = "signer_relay_dns_01_record_already_present",
                        outcome = "success",
                        name = %name,
                        refusal = %refusal,
                    );
                    Ok(())
                }
                Ok(false) => Err(format!(
                    "{refusal}; and {name} carries no such value now, so the record was \
                     genuinely not published"
                )),
                // Two failures, and only the operator can tell what to do about
                // them: the POST's own words, and why the check that would have
                // excused it could not run. Claiming the record is absent here
                // would be a guess, and one that reads like a finding.
                Err(check) => Err(format!(
                    "{refusal}; and the check for whether it exists anyway failed: {check}"
                )),
            },
        }
    }

    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let name = self.record_name(name)?;
        let found = self.list_txt(&name).await?;
        let mine = found.iter().filter(|record| record.content == value);
        for record in mine {
            let url = format!("{}/{}", self.records_url(), record.id);
            self.request(Method::DELETE, &url, None).await?;
        }
        // Nothing matched, including nothing at all: a value that is not there
        // needs no retracting, which is what the trait promises.
        Ok(())
    }
}

/// `name` as an absolute name, which is the form [`check_in_zone`] compares.
///
/// The relay hands over absolute names already; this is here so a caller
/// anywhere in this module cannot get a zone test that quietly compares a
/// relative name against an absolute one.
fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Refuses a credential or an id that could not be sent as it stands.
///
/// Both end up in a header or a path segment built by concatenation, so the
/// failure a stray newline in a secrets-manager template causes would otherwise
/// be a request error at the first issuance.
fn refuse_unsendable(value: &str, setting: &str) -> anyhow::Result<()> {
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        anyhow::bail!(
            "{setting} contains whitespace or a control character, which cannot be sent to the \
             API as it stands"
        );
    }
    Ok(())
}

/// Cloudflare's own words about a refusal: its `errors` array, or the body's
/// first line when the answer was not the envelope at all.
///
/// The code is kept because operators search Cloudflare's docs by it — `1003`
/// and `1061` mean different things and look the same in a log otherwise.
fn refusal_detail(body: &[u8]) -> String {
    let joined = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|document| {
            Some(
                document["errors"]
                    .as_array()?
                    .iter()
                    .filter_map(|error| {
                        let message = error["message"].as_str()?;
                        Some(match error["code"].as_u64() {
                            Some(code) => format!("{code}: {message}"),
                            None => message.to_string(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })
        .unwrap_or_default();
    if joined.is_empty() {
        error_excerpt(body)
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_net::dns::HickoryResolver;
    use hyper::StatusCode;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// These reach a loopback listener by IP literal, which
    /// `dns::connect` short-circuits without a lookup.
    fn test_outbound() -> Outbound {
        Outbound::new(
            Arc::new(HickoryResolver::from_system_uncached().unwrap()),
            acme_proxy_net::testutil::no_proxies(),
        )
    }

    fn config() -> CloudflareConfig {
        CloudflareConfig {
            api_token: "test-token".to_string(),
            zone: "example.com".to_string(),
            zone_id: "0123456789abcdef".to_string(),
        }
    }

    /// One canned answer: status and body.
    type Canned = (u16, Value);

    /// A scripted Cloudflare API on a loopback port.
    ///
    /// Answers are served in order, one per connection, which is the shape this
    /// client has: every request opens its own connection and closes it. Once
    /// the script is spent it keeps answering with a refusal, so a request the
    /// test did not predict fails with what was asked for rather than by
    /// hanging the client.
    struct Stub {
        base: String,
        seen: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Stub {
        /// The request lines and headers the API has received so far.
        fn requests(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }

        /// The bodies of the requests it has received, parsed as JSON.
        fn bodies(&self) -> Vec<Value> {
            self.requests()
                .iter()
                .map(|request| {
                    request
                        .split("\r\n\r\n")
                        .nth(1)
                        .and_then(|body| serde_json::from_str(body).ok())
                        .unwrap_or(Value::Null)
                })
                .collect()
        }
    }

    async fn stub(script: Vec<Canned>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let shared = seen.clone();

        let task = tokio::spawn(async move {
            let mut script = script.into_iter();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let request = read_request(&mut stream).await;
                shared.lock().unwrap().push(request);
                let (status, body) = script
                    .next()
                    .unwrap_or_else(|| (StatusCode::BAD_REQUEST.as_u16(), unexpected()));
                let _ = stream
                    .write_all(response(status, &body.to_string()).as_bytes())
                    .await;
                let _ = stream.shutdown().await;
            }
        });

        Stub {
            base: format!("http://127.0.0.1:{port}/client/v4"),
            seen,
            task,
        }
    }

    /// Reads one request in full: the head, then exactly `Content-Length` more
    /// bytes. Asserting on a body means waiting for it — a head-only read would
    /// race the client's write and record a request with no body.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut head: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let length = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);

        let mut body = vec![0u8; length];
        let mut filled = 0;
        while filled < length {
            let read = stream.read(&mut body[filled..]).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            filled += read;
        }
        format!("{}{}", text, String::from_utf8_lossy(&body[..filled]))
    }

    /// A canned Cloudflare answer. `Content-Length` is computed, never guessed:
    /// a wrong one leaves hyper waiting for bytes that never arrive.
    fn response(status: u16, body: &str) -> String {
        let reason = StatusCode::from_u16(status)
            .ok()
            .and_then(|code| code.canonical_reason())
            .unwrap_or("Status");
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// The answer to a request the test did not script, carrying the shape of a
    /// real Cloudflare refusal so it reads as a failure and not a transport
    /// error.
    fn unexpected() -> Value {
        json!({"success": false, "errors": [{"code": 99_999, "message": "unscripted request"}]})
    }

    /// Cloudflare's envelope around `result`.
    fn ok(result: Value) -> Canned {
        (
            200,
            json!({"success": true, "errors": [], "messages": [], "result": result}),
        )
    }

    /// The same, with the pagination metadata a listing carries.
    fn ok_page(result: Value, page: u64, total_pages: u64) -> Canned {
        (
            200,
            json!({
                "success": true, "errors": [], "messages": [],
                "result": result,
                "result_info": {"page": page, "per_page": 100, "count": result.as_array().map_or(0, Vec::len), "total_count": 0, "total_pages": total_pages}
            }),
        )
    }

    fn updater(stub: &Stub) -> CloudflareUpdater {
        CloudflareUpdater::at_base(&config(), test_outbound(), &stub.base).unwrap()
    }

    // ---- the configuration ------------------------------------------------

    #[test]
    fn a_well_formed_config_builds() {
        let updater = CloudflareUpdater::from_config(&config(), test_outbound()).unwrap();
        assert_eq!(updater.zone_id, "0123456789abcdef");
        assert_eq!(updater.authorization, "Bearer test-token");
        assert_eq!(
            updater.records_url(),
            format!("{API_BASE}/zones/0123456789abcdef/dns_records")
        );
    }

    /// A credential that cannot be parsed will never start working on its own,
    /// so each half of it stops the startup rather than the first issuance.
    #[test]
    fn every_missing_or_unsendable_field_is_a_startup_error() {
        /// One case: how to break the configuration.
        type Breaker = fn(&mut CloudflareConfig);

        let cases: Vec<(&str, Breaker)> = vec![
            ("api_token", |c| c.api_token = String::new()),
            (
                "api_token",
                |c| c.api_token = "  \n".to_string(), // trimmed to nothing
            ),
            ("whitespace", |c| c.api_token = "line1\nline2".to_string()),
            ("zone_id", |c| c.zone_id = String::new()),
            ("zone_id", |c| c.zone_id = "with space".to_string()),
            ("zone", |c| c.zone = String::new()),
            ("zone", |c| c.zone = "not a dns name".to_string()),
        ];

        for (expected, break_it) in cases {
            let mut cfg = config();
            break_it(&mut cfg);
            let error = CloudflareUpdater::from_config(&cfg, test_outbound())
                .err()
                .unwrap_or_else(|| panic!("{expected}: this configuration must not build"))
                .to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?} in: {error}"
            );
        }
    }

    /// Cloudflare's UI spells a zone without the trailing dot that
    /// `[signer.relay.dns01.rfc2136]`'s `zone` is spelled with; both mean the
    /// same zone.
    #[tokio::test]
    async fn a_zone_spelled_either_way_writes_in_it() {
        for zone in ["example.com", "example.com.", "  example.com.  "] {
            let mut cfg = config();
            cfg.zone = zone.to_string();
            let stub = stub(vec![ok(
                json!({"id": "1", "name": "_acme-challenge.example.com"}),
            )])
            .await;
            let updater = CloudflareUpdater::at_base(&cfg, test_outbound(), &stub.base).unwrap();
            updater
                .upsert_txt("_acme-challenge.example.com.", "digest")
                .await
                .unwrap_or_else(|error| panic!("{zone:?}: {error}"));
        }
    }

    /// The `Debug` rendering is what the signer's identity key builds on; the
    /// token must never be in it.
    #[test]
    fn the_debug_rendering_hides_the_token() {
        let updater = CloudflareUpdater::from_config(&config(), test_outbound()).unwrap();
        let rendered = format!("{updater:?}");
        assert!(!rendered.contains("test-token"), "{rendered}");
    }

    // ---- publishing ------------------------------------------------------

    /// The request on the wire, not just "no error": the path Cloudflare routes
    /// on, the header it authenticates with, and the body fields it requires.
    #[tokio::test]
    async fn a_publish_posts_a_txt_record_to_the_zone() {
        let stub = stub(vec![ok(
            json!({"id": "rec-1", "name": "_acme-challenge.example.com"}),
        )])
        .await;
        updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap();

        let requests = stub.requests();
        assert_eq!(requests.len(), 1, "one record is one request");
        let head = requests[0].split("\r\n\r\n").next().unwrap().to_lowercase();
        assert!(
            head.starts_with("post /client/v4/zones/0123456789abcdef/dns_records "),
            "{}",
            &requests[0]
        );
        assert!(head.contains("authorization: bearer test-token"), "{head}");
        assert!(head.contains("content-type: application/json"), "{head}");
        assert!(head.contains("accept: application/json"), "{head}");
        // hyper's low-level client sends exactly what it is given, `Host` in it.
        assert!(head.contains("host: 127.0.0.1"), "{head}");

        assert_eq!(
            stub.bodies()[0],
            json!({
                "type": "TXT",
                "name": "_acme-challenge.example.com",
                "content": "digest-value",
                "ttl": RECORD_TTL,
            })
        );
    }

    /// The name is sent without the trailing dot the DNS world carries, since
    /// Cloudflare answers a dotted `name` as an invalid record name.
    #[tokio::test]
    async fn a_published_name_loses_its_trailing_dot() {
        let stub = stub(vec![ok(json!({"id": "rec-1"}))]).await;
        updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap();
        assert_eq!(
            stub.bodies()[0]["name"],
            "_acme-challenge.example.com",
            "Cloudflare wants the name unqualified"
        );
    }

    /// A name outside the zone is refused locally: the update key for one zone
    /// must not be able to write in another, and a name in someone else's zone
    /// would answer with their error message instead of this explanation.
    #[tokio::test]
    async fn a_name_outside_the_zone_never_reaches_the_api() {
        let stub = stub(vec![]).await;
        for name in ["_acme-challenge.example.net.", "example.org."] {
            let error = updater(&stub)
                .upsert_txt(name, "digest-value")
                .await
                .unwrap_err();
            assert!(error.contains("outside the zone"), "{error}");
            assert!(error.contains("example.com"), "{error}");
        }
        assert!(
            stub.requests().is_empty(),
            "a refused name must cost no request"
        );
    }

    #[tokio::test]
    async fn a_malformed_record_name_fails_before_the_api() {
        let stub = stub(vec![]).await;
        assert!(
            updater(&stub)
                .upsert_txt("not a dns name", "v")
                .await
                .is_err()
        );
        assert!(
            updater(&stub)
                .delete_txt("not a dns name", "v")
                .await
                .is_err()
        );
        assert!(stub.requests().is_empty());
    }

    /// Cloudflare refuses a bad request with its own envelope, and the code in
    /// it is what an operator searches its docs by.
    #[tokio::test]
    async fn a_refusal_names_cloudflares_error() {
        let stub = stub(vec![
            (
                400,
                json!({"success": false, "errors": [{"code": 1003, "message": "Invalid request"}]}),
            ),
            // The check that follows finds nothing at the name, so the refusal
            // stands: the record really was not published.
            ok(json!([])),
        ])
        .await;
        let error = updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        // The publish's own refusal is what an operator has to act on, and the
        // presence check adds its own sentence to it.
        assert!(error.contains("1003: Invalid request"), "{error}");
        assert!(error.contains("genuinely not published"), "{error}");
        assert_eq!(
            stub.requests().len(),
            2,
            "the refusal is followed by one check for the record"
        );
    }

    /// A `200` whose `success` is `false` is a refusal. Reading the status alone
    /// would report a record that does not exist as published.
    #[tokio::test]
    async fn an_envelope_saying_failure_is_a_failure() {
        let stub = stub(vec![
            (
                200,
                json!({"success": false, "errors": [{"code": 1061, "message": "Already exists"}]}),
            ),
            ok(json!([])),
        ])
        .await;
        let error = updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("1061: Already exists"), "{error}");
    }

    /// The retry case this provider has to survive: the value is already at the
    /// name, so the record the relay needs exists, whatever the POST said.
    #[tokio::test]
    async fn a_record_that_is_already_there_counts_as_published() {
        let stub = stub(vec![
            (
                400,
                json!({"success": false, "errors": [{"code": 1061, "message": "Already exists"}]}),
            ),
            ok(json!([{"id": "rec-1", "content": "digest-value"}])),
        ])
        .await;
        updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .expect("the value is present, which is the whole of what was asked");

        let listing = stub.requests()[1]
            .split("\r\n\r\n")
            .next()
            .unwrap()
            .to_string();
        assert!(listing.starts_with("GET "), "{listing}");
        assert!(listing.contains("type=TXT"), "{listing}");
        assert!(
            listing.contains("name=_acme-challenge.example.com"),
            "{listing}"
        );
    }

    /// A refusal the check cannot explain is still a failure: swallowing it
    /// would send the relay to trigger a challenge no record answers.
    #[tokio::test]
    async fn a_refusal_with_a_different_value_at_the_name_still_fails() {
        let stub = stub(vec![
            (
                400,
                json!({"success": false, "errors": [{"code": 1003, "message": "Invalid"}]}),
            ),
            ok(json!([{"id": "rec-1", "content": "somebody-elses-value"}])),
        ])
        .await;
        let error = updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("genuinely not published"), "{error}");
    }

    /// The check itself failing must not be mistaken for an answer. Both
    /// failures are named, since the operator has to diagnose the pair.
    #[tokio::test]
    async fn a_refusal_the_check_cannot_explain_is_reported_whole() {
        let stub = stub(vec![
            (
                400,
                json!({"success": false, "errors": [{"code": 1003, "message": "Invalid"}]}),
            ),
            (
                503,
                json!({"success": false, "errors": [{"code": 1001, "message": "Service unavailable"}]}),
            ),
        ]).await;
        let error = updater(&stub)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("1003: Invalid"), "{error}");
        assert!(error.contains("1001: Service unavailable"), "{error}");
        // Neither failure is hidden, and the absence of the record is not
        // asserted: the check that would have settled it is the thing that
        // failed.
        assert!(
            error.contains("the check for whether it exists anyway failed"),
            "{error}"
        );
        assert!(
            !error.contains("genuinely not published"),
            "a check that failed proves nothing: {error}"
        );
    }

    // ---- retracting ------------------------------------------------------

    /// Cloudflare deletes by id, so the retraction has to find the id whose
    /// content is *this* value — and leave every other value at the name, which
    /// is where a concurrent order's record lives.
    #[tokio::test]
    async fn a_retraction_deletes_only_its_own_value() {
        let stub = stub(vec![
            ok(json!([
                {"id": "rec-1", "content": "digest-value"},
                {"id": "rec-2", "content": "another-orders-value"},
            ])),
            ok(json!({"id": "rec-1", "content": "digest-value"})),
        ])
        .await;
        updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap();

        let requests = stub.requests();
        assert_eq!(requests.len(), 2, "the listing and the one deletion");
        let deletion = requests[1].split("\r\n\r\n").next().unwrap().to_string();
        assert!(
            deletion.starts_with("DELETE /client/v4/zones/0123456789abcdef/dns_records/rec-1 "),
            "{deletion}"
        );
        assert!(
            !requests.iter().any(|r| r.contains("rec-2")),
            "the other value must survive"
        );
    }

    /// The trait's promise: a value that is not there is not an error, so a
    /// best-effort cleanup after a failed publish cannot fail the order.
    #[tokio::test]
    async fn retracting_what_is_absent_is_not_an_error() {
        let stub = stub(vec![ok(json!([]))]).await;
        updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .expect("nothing to retract is a clean answer");
        assert_eq!(stub.requests().len(), 1, "no DELETE without a match");
    }

    /// Two values this server wrote at one name (a wildcard and its base share
    /// the name) means two deletions.
    #[tokio::test]
    async fn every_value_matching_is_deleted() {
        let stub = stub(vec![
            ok(json!([
                {"id": "rec-1", "content": "digest-value"},
                {"id": "rec-2", "content": "digest-value"},
            ])),
            ok(json!({"id": "rec-1"})),
            ok(json!({"id": "rec-2"})),
        ])
        .await;
        updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap();
        assert_eq!(stub.requests().len(), 3);
    }

    /// A name with more records than one page holds. Cloudflare reports the
    /// page count beside the result, and walking it is the only way to find
    /// this server's own value on a later page.
    #[tokio::test]
    async fn a_listing_is_walked_to_its_last_page() {
        let stub = stub(vec![
            ok_page(json!([{"id": "rec-1", "content": "other"}]), 1, 2),
            ok_page(json!([{"id": "rec-2", "content": "digest-value"}]), 2, 2),
            ok(json!({"id": "rec-2"})),
        ])
        .await;
        updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap();

        let requests = stub.requests();
        assert_eq!(requests.len(), 3, "two pages, then the deletion");
        let second = requests[1].split("\r\n\r\n").next().unwrap();
        assert!(second.contains("page=2"), "{second}");
        assert!(
            requests[2].contains("/dns_records/rec-2"),
            "the value was on the second page: {}",
            requests[2]
        );
    }

    /// A listing that never says it ends is refused rather than walked, with a
    /// credential that can edit the zone in hand.
    #[tokio::test]
    async fn a_listing_that_never_ends_is_refused() {
        let endless = (1..=u64::from(MAX_PAGES))
            .map(|page| {
                ok_page(
                    json!([{"id": format!("rec-{page}"), "content": "other"}]),
                    page,
                    99,
                )
            })
            .collect();
        let stub = stub(endless).await;
        let error = updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains(&MAX_PAGES.to_string()), "{error}");
    }

    // ---- the transport and the envelope ----------------------------------

    /// Serves one hand-written response on a fresh port, for the answers the
    /// scripted stub cannot express: a body that is not JSON at all, a page
    /// where an envelope belongs, and a body larger than the cap.
    async fn serve_raw(response: String) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch).await;
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (port, task)
    }

    /// An updater aimed at `port`, where no Cloudflare is.
    fn updater_at(port: u16) -> CloudflareUpdater {
        CloudflareUpdater::at_base(
            &config(),
            test_outbound(),
            &format!("http://127.0.0.1:{port}/client/v4"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_unreadable_answer_is_reported() {
        let body = "definitely not JSON";
        let (port, task) = serve_raw(response(200, body)).await;
        let error = updater_at(port)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("unreadable JSON"), "{error}");
        task.abort();
    }

    /// A page instead of an envelope: the excerpt of what did arrive is the
    /// whole diagnosis, so it is quoted.
    #[tokio::test]
    async fn a_non_json_refusal_quotes_what_arrived() {
        let (port, task) = serve_raw(response(502, "<html><body>Bad gateway</body></html>")).await;
        let error = updater_at(port)
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("502"), "{error}");
        assert!(error.contains("Bad gateway"), "{error}");
        task.abort();
    }

    /// A body the size of the ceiling is refused rather than buffered: the
    /// ceiling exists exactly for the answer that is not an answer.
    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        let filler = "x".repeat(MAX_RESPONSE_BYTES + 1024);
        let body = format!(r#"{{"success":true,"result":[],"filler":"{filler}"}}"#);
        let (port, task) = serve_raw(response(200, &body)).await;
        let error = updater_at(port)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
        task.abort();
    }

    /// Nothing listening: reported as a failure of this request, retryable by
    /// the relay's job, never as a publish that happened.
    #[tokio::test]
    async fn an_unreachable_api_is_a_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(
            updater_at(port)
                .upsert_txt("_acme-challenge.example.com.", "digest-value")
                .await
                .is_err()
        );
    }

    /// An API that accepts the connection and then says nothing has to be given
    /// up on: the relay's budget is finite and its job holds an order.
    #[tokio::test]
    async fn a_silent_api_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let held = listener.accept().await.unwrap().0;
            // Held open, unanswered, until the test's own budget runs out.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });
        let mut updater = updater_at(port);
        updater.timeout = Duration::from_millis(200);
        let error = updater
            .upsert_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        task.abort();
    }

    /// A record entry without the two fields this provider reads is not
    /// something it can act on, and must not look like an empty listing.
    #[tokio::test]
    async fn a_record_without_an_id_is_reported() {
        let stub = stub(vec![ok(json!([{"name": "_acme-challenge.example.com"}]))]).await;
        let error = updater(&stub)
            .delete_txt("_acme-challenge.example.com.", "digest-value")
            .await
            .unwrap_err();
        assert!(error.contains("unreadable record"), "{error}");
    }

    /// The refusal detail falls back to the excerpt when the envelope carries no
    /// usable `errors` array.
    #[test]
    fn a_refusal_without_errors_falls_back_to_the_body() {
        let no_errors = br#"{"success":false,"errors":[]}"#;
        assert_eq!(
            refusal_detail(no_errors),
            String::from_utf8_lossy(no_errors)
        );
        let no_message = br#"{"success":false,"errors":[{"code":1003}]}"#;
        assert_eq!(
            refusal_detail(no_message),
            String::from_utf8_lossy(no_message)
        );
        let joined =
            br#"{"success":false,"errors":[{"code":1,"message":"first"},{"message":"second"}]}"#;
        assert_eq!(refusal_detail(joined), "1: first; second");
    }
}
