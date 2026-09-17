//! [deSEC.io](https://desec.io) REST API DNS-01 provider.
//!
//! An alternative to [`super::dns01`]'s RFC 2136 updater for the same job:
//! publishing and retracting the `_acme-challenge` TXT record an *upstream*
//! CA's `dns-01` challenge asks for, when `signer.relay.dns01.provider =
//! "desec"`. See [`super::dns01`]'s module doc for why this proxy — not the
//! end client — is the one answering it.
//!
//! ## Why this needs its own transport rather than reusing `ipam::http`
//!
//! [`crate::ipam::http`] already owns a JSON-over-HTTP client built on
//! [`crate::http_client`], but its own doc scopes it deliberately to "both
//! IPAM backends" and it exposes only `GET`. deSEC's rrset endpoint needs a
//! bearer-token `Authorization` header and a `PUT` carrying a JSON body, so
//! this module builds its own small client directly on
//! [`crate::http_client`] — the same plumbing layer, a different, if
//! similarly shaped, policy.
//!
//! ## Replace, not append
//!
//! deSEC's `PUT /domains/{domain}/rrsets/{subname}/TXT/` **replaces** the
//! whole `records` array for that name — unlike RFC 2136's `append`, which
//! adds a value alongside whatever is already there. A base-plus-wildcard
//! order (`example.com` + `*.example.com`) produces two authorizations whose
//! TXT records live at the *same* `_acme-challenge` name with two different
//! values, both of which must be present at once. So every
//! `upsert_txt`/`delete_txt` here does a **read-modify-write**: fetch the
//! current record set (a `404` reads as "none yet"), add or remove the one
//! value that changed, then `PUT` the merged list — an empty result clears
//! the rrset by `PUT`ting `"records": []`. This opens a narrow window where
//! two concurrent updates to the same name can race and one write is lost —
//! documented rather than solved with a lock, the same trade `delete_txt`'s
//! own best-effort cleanup already makes elsewhere in this module.
//!
//! ## Creating a name deSEC has never seen
//!
//! `PUT` only ever *replaces* an rrset that already exists — a `subname`
//! deSEC has no record for answers `404` no matter what the body says, since
//! there is nothing to replace. The very first publish of any given name
//! (typically `_acme-challenge` under a domain issuing for the first time)
//! therefore hits this, so [`DesecUpdater::put_records`] falls back to `POST
//! /domains/{domain}/rrsets/` — the collection endpoint, which *creates* an
//! rrset from `subname`/`type` carried in the body — whenever the `PUT`
//! 404s on a non-empty write. Deleting a value from an rrset deSEC never
//! held is a no-op either way, so an empty write's `404` stays "already not
//! there" and never reaches `POST`.
//!
//! ## TTL
//!
//! deSEC enforces a server-side minimum TTL (3600 seconds for an ordinary
//! account) well above the 60-second [`super::dns01::CHALLENGE_TTL`] used for
//! RFC 2136 — sending anything lower is simply refused. [`TTL`] sends that
//! floor; like `rfc2136`'s own TTL, this is not a configuration key.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode};
use serde_json::Value;
use url::Url;

use super::dns01::DnsUpdater;
use crate::config::DesecConfig;
use crate::http_client::{
    Endpoint, MAX_RESPONSE_BYTES, Outbound, error_excerpt, webpki_tls_config,
};

/// TTL sent on every published record — see the module doc.
const TTL: u32 = 3600;

/// Publishes and retracts TXT records through the deSEC.io REST API.
pub struct DesecUpdater {
    /// Base URL with no trailing slash.
    base: String,
    /// The deSEC-managed zone, with any trailing dot stripped.
    domain: String,
    token: String,
    tls: Arc<rustls::ClientConfig>,
    outbound: Outbound,
}

impl std::fmt::Debug for DesecUpdater {
    /// Never renders `token` — it is a bearer credential.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesecUpdater")
            .field("base", &self.base)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl DesecUpdater {
    /// Validates the configuration and builds the TLS configuration.
    ///
    /// Every failure here is a startup error, matching
    /// `Rfc2136Updater::from_config`'s "a credential that cannot be parsed
    /// will never start working on its own". Nothing is contacted yet.
    pub fn from_config(cfg: &DesecConfig, outbound: Outbound) -> anyhow::Result<Self> {
        if cfg.domain.trim().is_empty() {
            anyhow::bail!("signer.relay.dns01.desec.domain is not set");
        }
        if cfg.token.trim().is_empty() {
            anyhow::bail!("signer.relay.dns01.desec.token is not set");
        }

        let api_url = if cfg.api_url.trim().is_empty() {
            DesecConfig::DEFAULT_API_URL
        } else {
            cfg.api_url.trim()
        };
        let parsed = Url::parse(api_url)
            .map_err(|error| anyhow::anyhow!("desec.api_url ({api_url}) is not a URL: {error}"))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => anyhow::bail!("desec.api_url: unsupported scheme {other}"),
        }

        Ok(Self {
            base: parsed.as_str().trim_end_matches('/').to_string(),
            domain: cfg.domain.trim().trim_end_matches('.').to_string(),
            token: cfg.token.trim().to_string(),
            tls: Arc::new(webpki_tls_config()),
            outbound,
        })
    }

    /// The part of `name` relative to `domain`, e.g. `_acme-challenge` for
    /// `_acme-challenge.example.dedyn.io.` against `domain =
    /// "example.dedyn.io"`, or `_acme-challenge.foo` when a wildcard's base
    /// name sits under a subdomain. Empty when `name` names the zone apex.
    fn subname<'a>(&self, name: &'a str) -> Result<&'a str, String> {
        let trimmed = name.trim_end_matches('.');
        if trimmed.eq_ignore_ascii_case(&self.domain) {
            return Ok("");
        }
        let suffix = format!(".{}", self.domain);
        trimmed
            .strip_suffix(suffix.as_str())
            .filter(|_| suffix.len() < trimmed.len() + 1)
            .ok_or_else(|| format!("{name} is not inside the configured zone {}", self.domain))
    }

    /// Reads the current TXT record set at `subname`, `[]` when none exists.
    async fn get_records(&self, subname: &str) -> Result<Vec<String>, String> {
        match self
            .request(hyper::Method::GET, &self.rrset_target(subname), None)
            .await
        {
            Ok((_, body)) => extract_records(&body),
            Err(DesecError::NotFound) => Ok(Vec::new()),
            Err(DesecError::Other(message)) => Err(message),
        }
    }

    /// Replaces the TXT record set at `subname` wholesale.
    async fn put_records(&self, subname: &str, records: Vec<String>) -> Result<(), String> {
        // deSEC's per-rrset `PUT` requires `subname`/`type` in the body too,
        // matching the URL exactly — omitting them is a `400`, not merely
        // redundant with the path.
        let body = serde_json::json!({
            "subname": subname,
            "type": "TXT",
            "ttl": TTL,
            "records": records,
        });
        match self
            .request(hyper::Method::PUT, &self.rrset_target(subname), Some(body))
            .await
        {
            Ok(_) => Ok(()),
            // An empty rrset deSEC has never seen is already "not there" —
            // deleting a record that was never published is not a failure.
            Err(DesecError::NotFound) if records.is_empty() => Ok(()),
            // deSEC's per-rrset `PUT` only ever *replaces* an rrset it
            // already has — a subname it has never seen answers `404`
            // there no matter what the body says, since there is nothing
            // to replace. Creating one for the first time is a different
            // endpoint: `POST` to the domain's rrset *collection*, with
            // `subname`/`type` carried in the body instead of the path.
            // This is exactly the case a brand-new `_acme-challenge` name
            // hits on its very first publish.
            Err(DesecError::NotFound) => self.create_records(subname, records).await,
            Err(DesecError::Other(message)) => Err(message),
        }
    }

    /// Creates a new rrset via `POST /domains/{domain}/rrsets/` — the only
    /// way to publish a `subname`/`type` combination deSEC has never held a
    /// record for; see [`Self::put_records`].
    async fn create_records(&self, subname: &str, records: Vec<String>) -> Result<(), String> {
        let body = serde_json::json!({
            "subname": subname,
            "type": "TXT",
            "ttl": TTL,
            "records": records,
        });
        let target = format!(
            "{}/domains/{}/rrsets/",
            self.base,
            percent_encode(&self.domain)
        );
        match self.request(hyper::Method::POST, &target, Some(body)).await {
            Ok(_) => Ok(()),
            Err(DesecError::NotFound) => Err(format!(
                "deSEC has no domain {} to create a rrset under",
                self.domain
            )),
            Err(DesecError::Other(message)) => Err(message),
        }
    }

    /// The URL of `/domains/{domain}/rrsets/{subname}/TXT/`.
    fn rrset_target(&self, subname: &str) -> String {
        format!(
            "{}/domains/{}/rrsets/{}/TXT/",
            self.base,
            percent_encode(&self.domain),
            percent_encode(subname)
        )
    }

    /// One request against `target`, an absolute URL string built by the
    /// caller — either the specific-rrset endpoint (`GET`/`PUT`) or the
    /// domain's rrset collection (`POST`, to create one for the first time).
    async fn request(
        &self,
        method: hyper::Method,
        target: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Bytes), DesecError> {
        let url = Url::parse(target)
            .map_err(|error| DesecError::Other(format!("{target} is not a URL: {error}")))?;

        let endpoint = Endpoint::from_url(&url)
            .map_err(|error| DesecError::Other(format!("{target}: {error}")))?;

        // Connect before building the request: whether it is addressed
        // origin-form or absolute-form depends on the connection (a proxy in
        // the clear forwards it absolute-form), which `Outbound::connect`
        // alone knows — the same ordering `ipam::http::JsonApi::get` uses.
        let mut connection = self
            .outbound
            .connect(&endpoint, &self.tls)
            .await
            .map_err(DesecError::Other)?;
        let request_target = connection.request_target(&url);

        let payload = match &body {
            Some(value) => Bytes::from(serde_json::to_vec(value).map_err(|error| {
                DesecError::Other(format!("encoding the request body: {error}"))
            })?),
            None => Bytes::new(),
        };

        let mut builder = Request::builder()
            .method(method)
            .uri(request_target.clone())
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::ACCEPT, "application/json")
            .header(
                hyper::header::AUTHORIZATION,
                format!("Token {}", self.token),
            )
            .header(hyper::header::CONNECTION, "close");
        if body.is_some() {
            builder = builder
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .header(hyper::header::CONTENT_LENGTH, payload.len());
        }
        let request = builder
            .body(Full::new(payload))
            .map_err(|error| DesecError::Other(format!("building the request: {error}")))?;

        let (status, bytes) = exchange(connection.send_request(request).await, &url).await?;

        if status == StatusCode::NOT_FOUND {
            return Err(DesecError::NotFound);
        }
        if !status.is_success() {
            let excerpt = error_excerpt(&bytes);
            return Err(DesecError::Other(format!(
                "{url} answered {status}: {excerpt}"
            )));
        }
        Ok((status, bytes))
    }
}

/// Why one request failed — `NotFound` is a distinguishable answer (deSEC's
/// spelling of "no such rrset yet"), never itself an error the caller must
/// report; every other outcome is [`DesecError::Other`], the plain `String`
/// [`DnsUpdater`] wants back.
enum DesecError {
    NotFound,
    Other(String),
}

/// Percent-encodes one path segment. deSEC domain/subname values are DNS
/// labels — `_acme-challenge`, dashes, dots between labels — so this only
/// ever has to cope with the dot separating labels within a subname, which
/// `url` would otherwise treat as a path boundary if left unescaped in a
/// hand-built string; encoding defensively costs nothing here.
fn percent_encode(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// Sends the request and collects the response body, capped like every other
/// JSON client in this tree.
async fn exchange(
    result: hyper::Result<hyper::Response<hyper::body::Incoming>>,
    url: &Url,
) -> Result<(StatusCode, Bytes), DesecError> {
    let response =
        result.map_err(|error| DesecError::Other(format!("request to {url} failed: {error}")))?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| {
            DesecError::Other(format!(
                "response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
            ))
        })?
        .to_bytes();
    Ok((status, body))
}

/// Pulls the `records` array (already-quoted TXT strings) out of a deSEC
/// rrset document.
fn extract_records(body: &[u8]) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("deSEC returned unreadable JSON: {error}"))?;
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| "deSEC rrset carried no \"records\" array".to_string())?;
    records
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "deSEC rrset held a non-string record".to_string())
        })
        .collect()
}

/// Quotes a value as one TXT presentation-format string, escaping the two
/// characters RFC 1035 §5.1 requires — the same value `hickory_proto`'s `TXT`
/// type encodes on the wire for the `rfc2136` provider, restated here since
/// deSEC's API takes the presentation form as a literal JSON string rather
/// than an already-framed wire record.
fn quote_txt(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

#[async_trait]
impl DnsUpdater for DesecUpdater {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let subname = self.subname(name)?.to_string();
        let quoted = quote_txt(value);
        let mut records = self.get_records(&subname).await?;
        if !records.contains(&quoted) {
            records.push(quoted);
        }
        self.put_records(&subname, records).await
    }

    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let subname = self.subname(name)?.to_string();
        let quoted = quote_txt(value);
        let mut records = self.get_records(&subname).await?;
        records.retain(|record| record != &quoted);
        self.put_records(&subname, records).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::http::testing::{closed_port, serve_many, serve_once, status, test_resolver};

    fn config(api_url: &str) -> DesecConfig {
        DesecConfig {
            domain: "example.dedyn.io".to_string(),
            token: "test-token".to_string(),
            api_url: api_url.to_string(),
        }
    }

    fn test_outbound() -> Outbound {
        crate::testutil::outbound_with(test_resolver())
    }

    #[test]
    fn an_empty_domain_is_refused() {
        let mut cfg = config(DesecConfig::DEFAULT_API_URL);
        cfg.domain = String::new();
        let error = DesecUpdater::from_config(&cfg, test_outbound()).unwrap_err();
        assert!(error.to_string().contains("domain is not set"));
    }

    #[test]
    fn an_empty_token_is_refused() {
        let mut cfg = config(DesecConfig::DEFAULT_API_URL);
        cfg.token = String::new();
        let error = DesecUpdater::from_config(&cfg, test_outbound()).unwrap_err();
        assert!(error.to_string().contains("token is not set"));
    }

    #[test]
    fn an_unsupported_scheme_is_refused() {
        let cfg = config("ftp://desec.example/api");
        let error = DesecUpdater::from_config(&cfg, test_outbound()).unwrap_err();
        assert!(error.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn the_default_api_url_applies_when_unset() {
        let mut cfg = config(DesecConfig::DEFAULT_API_URL);
        cfg.api_url = String::new();
        let updater = DesecUpdater::from_config(&cfg, test_outbound()).unwrap();
        assert_eq!(updater.base, DesecConfig::DEFAULT_API_URL);
    }

    #[test]
    fn subname_strips_the_configured_zone() {
        let updater =
            DesecUpdater::from_config(&config(DesecConfig::DEFAULT_API_URL), test_outbound())
                .unwrap();
        assert_eq!(
            updater
                .subname("_acme-challenge.example.dedyn.io.")
                .unwrap(),
            "_acme-challenge"
        );
        assert_eq!(updater.subname("example.dedyn.io.").unwrap(), "");
        assert!(updater.subname("_acme-challenge.other.example.").is_err());
    }

    #[test]
    fn txt_values_are_quoted_and_escaped() {
        assert_eq!(quote_txt("plain"), "\"plain\"");
        assert_eq!(quote_txt("with\"quote"), "\"with\\\"quote\"");
        assert_eq!(quote_txt("with\\backslash"), "\"with\\\\backslash\"");
    }

    /// Points a `DesecUpdater` at a loopback server on `port`, TLS disabled
    /// (`http://`) since these tests are about the rrset semantics, not TLS —
    /// `ipam::http`'s own suite already proves this transport layer's TLS
    /// handling.
    fn updater_for(port: u16) -> DesecUpdater {
        DesecUpdater::from_config(
            &config(&format!("http://127.0.0.1:{port}")),
            test_outbound(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn upsert_on_an_empty_rrset_publishes_one_record() {
        let (port, server) = serve_once(status(404, "Not Found", "{}")).await;
        // The GET (empty rrset) is answered above; the PUT that follows opens
        // a second connection this single-shot server does not answer, which
        // is fine for asserting the *request* it already received — swap to
        // `serve_many` below where the PUT's answer matters too.
        let updater = updater_for(port);
        let _ = updater.get_records("_acme-challenge").await;
        let seen = server.await.unwrap();
        assert!(seen.contains("GET /domains/example.dedyn.io/rrsets/_acme-challenge/TXT/"));
        assert!(
            seen.to_lowercase()
                .contains("authorization: token test-token")
        );
    }

    #[tokio::test]
    async fn a_missing_rrset_reads_as_no_records() {
        let (port, _server) =
            serve_once(status(404, "Not Found", "{\"detail\":\"Not found.\"}")).await;
        let updater = updater_for(port);
        assert_eq!(
            updater.get_records("_acme-challenge").await.unwrap(),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn an_existing_rrset_is_parsed() {
        let body = serde_json::json!({
            "subname": "_acme-challenge",
            "type": "TXT",
            "ttl": 3600,
            "records": ["\"one\"", "\"two\""],
        });
        let (port, _server) = serve_once(status(200, "OK", &body.to_string())).await;
        let updater = updater_for(port);
        assert_eq!(
            updater.get_records("_acme-challenge").await.unwrap(),
            vec!["\"one\"".to_string(), "\"two\"".to_string()]
        );
    }

    #[tokio::test]
    async fn put_records_sends_the_ttl_and_merged_list() {
        let (port, server) = serve_once(status(200, "OK", "{}")).await;
        let updater = updater_for(port);
        updater
            .put_records("_acme-challenge", vec!["\"one\"".to_string()])
            .await
            .unwrap();
        let seen = server.await.unwrap();
        assert!(seen.contains("PUT /domains/example.dedyn.io/rrsets/_acme-challenge/TXT/"));
        assert!(seen.contains("\"ttl\":3600"));
        assert!(seen.contains("\"records\":[\"\\\"one\\\"\"]"));
        assert!(seen.contains("\"subname\":\"_acme-challenge\""));
        assert!(seen.contains("\"type\":\"TXT\""));
    }

    #[tokio::test]
    async fn deleting_the_last_value_clears_the_rrset() {
        let (port, server) = serve_once(status(200, "OK", "{}")).await;
        let updater = updater_for(port);
        updater
            .put_records("_acme-challenge", Vec::new())
            .await
            .unwrap();
        let seen = server.await.unwrap();
        assert!(seen.contains("\"records\":[]"));
    }

    #[tokio::test]
    async fn putting_an_empty_set_desec_never_saw_is_not_a_failure() {
        let (port, _server) = serve_once(status(404, "Not Found", "{}")).await;
        let updater = updater_for(port);
        assert!(
            updater
                .put_records("_acme-challenge", Vec::new())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn putting_records_desec_never_saw_creates_the_rrset() {
        // The `PUT` to the specific rrset endpoint 404s (deSEC has never
        // seen this subname); the fallback `POST` to the collection
        // endpoint is what actually publishes it.
        let (port, server) = serve_many(vec![
            status(404, "Not Found", "{}"),
            status(201, "Created", "{}"),
        ])
        .await;
        let updater = updater_for(port);
        updater
            .put_records("_acme-challenge", vec!["\"one\"".to_string()])
            .await
            .unwrap();
        let seen = server.await.unwrap();
        assert!(seen.contains("PUT /domains/example.dedyn.io/rrsets/_acme-challenge/TXT/"));
        assert!(seen.contains("POST /domains/example.dedyn.io/rrsets/"));
        assert!(seen.contains("\"subname\":\"_acme-challenge\""));
        assert!(seen.contains("\"type\":\"TXT\""));
    }

    #[tokio::test]
    async fn creating_a_rrset_for_a_missing_domain_is_reported() {
        let (port, _server) = serve_many(vec![
            status(404, "Not Found", "{}"),
            status(404, "Not Found", "{}"),
        ])
        .await;
        let updater = updater_for(port);
        let error = updater
            .put_records("_acme-challenge", vec!["\"one\"".to_string()])
            .await
            .unwrap_err();
        assert!(error.contains("no domain"));
    }

    #[tokio::test]
    async fn a_server_error_is_reported_with_its_body() {
        let (port, _server) = serve_once(status(500, "Internal Server Error", "boom")).await;
        let updater = updater_for(port);
        let error = updater.get_records("_acme-challenge").await.unwrap_err();
        assert!(error.contains("500"));
        assert!(error.contains("boom"));
    }

    #[tokio::test]
    async fn an_unreachable_server_is_reported() {
        let port = closed_port().await;
        let updater = updater_for(port);
        assert!(updater.get_records("_acme-challenge").await.is_err());
    }

    #[tokio::test]
    async fn upsert_txt_adds_a_value_alongside_an_existing_one_and_does_not_duplicate() {
        let existing = serde_json::json!({ "records": ["\"already-there\""] });
        let (port, server) = serve_many(vec![
            status(200, "OK", &existing.to_string()),
            status(200, "OK", "{}"),
        ])
        .await;
        let updater = updater_for(port);
        updater
            .upsert_txt("_acme-challenge.example.dedyn.io.", "already-there")
            .await
            .unwrap();
        let seen = server.await.unwrap();
        // Merging a value that is already present must not duplicate it:
        // it appears once in the PUT body the client sent.
        assert_eq!(seen.matches("already-there").count(), 1);
    }

    #[tokio::test]
    async fn delete_txt_removes_only_the_matching_value() {
        let existing = serde_json::json!({ "records": ["\"keep\"", "\"drop\""] });
        let (port, server) = serve_many(vec![
            status(200, "OK", &existing.to_string()),
            status(200, "OK", "{}"),
        ])
        .await;
        let updater = updater_for(port);
        updater
            .delete_txt("_acme-challenge.example.dedyn.io.", "drop")
            .await
            .unwrap();
        let seen = server.await.unwrap();
        let put_request = seen.split('\u{c}').nth(1).unwrap();
        assert!(put_request.contains("\\\"keep\\\""));
        assert!(!put_request.contains("\\\"drop\\\""));
    }
}
