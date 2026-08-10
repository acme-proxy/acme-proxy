//! A minimal outbound ACME client: the half of RFC 8555 this server does not
//! otherwise implement, since everywhere else it is the *server*.
//!
//! Written by hand on `hyper` rather than pulling in `instant-acme` or
//! `acme-lib`, for the same reason [`crate::challenge::http_01`] uses `hyper`
//! rather than `reqwest`: the whole stack (`hyper`, `hyper-util`, `rustls`,
//! `ring`, `base64`) is already in the tree, and what is needed here is a few
//! hundred lines of JWS assembly, not a framework.
//!
//! ## What this does not do
//!
//! No account key rollover, no `newAuthz` (pre-authorization), no order
//! listing — this client only drives the flow
//! [`super::RelaySigner`] needs: discover, register, order, answer, poll,
//! finalize, download, revoke, and ARI.
//!
//! ## TLS
//!
//! Unlike [`crate::challenge::tls_alpn_01`], which deliberately accepts any
//! server certificate because the certificate is the *proof* rather than an
//! identity, this client validates the upstream normally against the webpki
//! root store. Here the certificate is the only thing establishing that the CA
//! being handed CSRs is the intended one.

use std::sync::Arc;
use std::time::Duration;

use base64::prelude::*;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, LOCATION, RETRY_AFTER};
use hyper::{Method, Request, StatusCode};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;
use url::Url;

/// The most an upstream response body may be. Generous next to what any ACME
/// resource actually is — the largest is a certificate chain, a few kilobytes —
/// and there purely so a remote CA cannot decide how much memory this process
/// spends on one reply.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Everything that can go wrong talking to the upstream. Mapped to
/// [`SignerError`](crate::signer::SignerError) at the trait boundary in
/// [`super`]; kept separate here so this module never mentions `error.rs`,
/// the same split `challenge` and `filter` draw.
#[derive(Debug)]
pub enum UpstreamError {
    /// The URL was unusable, or named a scheme/host this client cannot reach.
    Url(String),
    /// TCP/TLS/HTTP transport failure.
    Transport(String),
    /// A response body was not the JSON this client expected.
    Protocol(String),
    /// The upstream answered with an ACME problem document.
    Problem {
        status: u16,
        typ: String,
        detail: String,
    },
    /// Signing the outgoing JWS failed (a local key problem).
    Jws(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Url(detail) => write!(f, "upstream URL invalid: {detail}"),
            UpstreamError::Transport(detail) => write!(f, "upstream transport failed: {detail}"),
            UpstreamError::Protocol(detail) => write!(f, "upstream protocol error: {detail}"),
            UpstreamError::Problem {
                status,
                typ,
                detail,
            } => {
                write!(f, "upstream returned {status} {typ}: {detail}")
            }
            UpstreamError::Jws(detail) => write!(f, "outbound JWS signing failed: {detail}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl UpstreamError {
    /// Whether this is the upstream rejecting the relayed CSR itself, as
    /// opposed to any other failure. That one case is the client's fault, not
    /// this server's, so it must surface as `badCSR` and leave the local order
    /// retryable rather than terminally invalid.
    pub fn is_bad_csr(&self) -> bool {
        matches!(self, UpstreamError::Problem { typ, .. } if typ.ends_with(":badCSR"))
    }

    /// Whether the upstream is telling us the certificate is already revoked.
    /// [`SignerBackend::revoke`](crate::signer::SignerBackend::revoke) is
    /// contractually idempotent, so this reads as success.
    pub fn is_already_revoked(&self) -> bool {
        matches!(self, UpstreamError::Problem { typ, .. } if typ.ends_with(":alreadyRevoked"))
    }

    /// Whether the upstream is refusing to create an account without an
    /// External Account Binding. Distinguished from any other refusal because
    /// it is fixable by a specific operator action, and the message can say so.
    pub fn is_external_account_required(&self) -> bool {
        matches!(self, UpstreamError::Problem { typ, .. } if typ.ends_with(":externalAccountRequired"))
    }

    /// Whether the nonce was stale — the one error worth retrying blindly,
    /// since RFC 8555 §6.5 makes it a normal part of the protocol rather than
    /// a real failure.
    fn is_bad_nonce(&self) -> bool {
        matches!(self, UpstreamError::Problem { typ, .. } if typ.ends_with(":badNonce"))
    }
}

/// The subset of the upstream's directory this client uses. Every member is
/// optional in RFC 8555 except in practice; `renewalInfo` genuinely is (it is
/// RFC 9773, which an upstream may predate).
#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: Option<String>,
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,
}

/// One HTTP response, reduced to what the ACME flow reads off it.
#[derive(Debug)]
pub struct AcmeResponse {
    pub status: StatusCode,
    pub body: Bytes,
    pub location: Option<String>,
    pub retry_after: Option<u64>,
    pub nonce: Option<String>,
}

impl AcmeResponse {
    /// Deserializes the body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, UpstreamError> {
        serde_json::from_slice(&self.body).map_err(|error| {
            UpstreamError::Protocol(format!("response was not the expected JSON: {error}"))
        })
    }

    /// The body as UTF-8 text (the PEM chain, for the certificate endpoint).
    pub fn text(&self) -> Result<String, UpstreamError> {
        String::from_utf8(self.body.to_vec())
            .map_err(|_| UpstreamError::Protocol("response body was not UTF-8".to_string()))
    }
}

/// The account key this proxy holds at the upstream. `ring`'s `EcdsaKeyPair`
/// cannot be cloned or serialized back out, so the PKCS#8 document is kept
/// alongside it — that is what gets written to disk on first provisioning.
pub struct AccountKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    /// DER SubjectPublicKeyInfo, so [`crate::extractors::jwk_thumbprint`] can
    /// be reused rather than reimplementing RFC 7638 here.
    spki_der: Vec<u8>,
}

impl AccountKey {
    /// Wraps a PKCS#8 P-256 document.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, UpstreamError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|error| UpstreamError::Jws(format!("account key unusable: {error}")))?;
        let spki_der = spki_from_p256_public(pair.public_key().as_ref())?;
        Ok(Self {
            pair,
            rng,
            spki_der,
        })
    }

    /// The public key as a JWK, the form `newAccount` embeds and the EAB inner
    /// payload repeats.
    pub fn jwk(&self) -> Value {
        // ring hands back the uncompressed SEC1 point: 0x04 || X(32) || Y(32).
        let point = self.pair.public_key().as_ref();
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": BASE64_URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": BASE64_URL_SAFE_NO_PAD.encode(&point[33..65]),
        })
    }

    /// DER SPKI, for [`crate::extractors::jwk_thumbprint`].
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        self.pair
            .sign(&self.rng, input)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|error| UpstreamError::Jws(format!("signing failed: {error}")))
    }
}

/// Wraps a raw SEC1 P-256 point in a DER SubjectPublicKeyInfo.
///
/// Hand-rolled rather than via `simple_asn1` because every field is fixed for
/// this one curve: the whole prefix is a constant, and only the 65-byte point
/// varies. `src/extractors/signature.rs` builds the same structure the general
/// way, for keys whose parameters are not known in advance.
fn spki_from_p256_public(point: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(UpstreamError::Jws(
            "P-256 public key was not an uncompressed 65-byte point".to_string(),
        ));
    }
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING(point) }
    const PREFIX: &[u8] = &[
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes (AlgorithmIdentifier)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID id-ecPublicKey (7 bytes)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, // OID prime256v1 (8 bytes)
        0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + point.len());
    der.extend_from_slice(PREFIX);
    der.extend_from_slice(point);
    Ok(der)
}

/// How the outgoing JWS names the key: an embedded `jwk` (only `newAccount`
/// may use this, RFC 8555 §6.2) or the account `kid` (everything else).
pub enum Signer<'a> {
    Jwk,
    Kid(&'a str),
}

/// The outbound ACME client. Holds the discovered directory and the TLS
/// config; the account key is passed per-request so the same client can serve
/// registration (before a `kid` exists) and normal operation.
impl std::fmt::Debug for AcmeClient {
    /// `dyn Resolver` is not `Debug`; the directory is what identifies this
    /// client anyway.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcmeClient")
            .field("directory", &self.directory)
            .field("timeout", &self.timeout)
            .finish()
    }
}

pub struct AcmeClient {
    directory: Directory,
    tls: Arc<rustls::ClientConfig>,
    /// The resolver every outbound hop in this server shares — so the upstream
    /// CA is reached through `dns.resolver` like everything else.
    resolver: Arc<dyn crate::dns::Resolver>,
    timeout: Duration,
}

impl AcmeClient {
    /// Fetches the upstream directory. This is the one network call made
    /// before anything is signed, so it doubles as the reachability check that
    /// makes a misconfigured `directory_url` a startup failure.
    pub async fn discover(
        directory_url: &str,
        resolver: Arc<dyn crate::dns::Resolver>,
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        let tls = Arc::new(crate::http_client::webpki_tls_config());
        let url = Url::parse(directory_url)
            .map_err(|error| UpstreamError::Url(format!("{directory_url}: {error}")))?;
        let response = request(&tls, resolver.as_ref(), Method::GET, &url, None, timeout).await?;
        if !response.status.is_success() {
            return Err(problem_from(&response));
        }
        let directory: Directory = response.json()?;
        debug!(event = "upstream_directory_discovered", url = %directory_url);
        Ok(Self {
            directory,
            resolver,
            tls,
            timeout,
        })
    }

    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// A fresh nonce (RFC 8555 §7.2). Fetched before every signed request
    /// rather than cached: a nonce is single-use, and a stale one costs a
    /// round-trip to discover anyway.
    async fn nonce(&self) -> Result<String, UpstreamError> {
        let url = self.parse(&self.directory.new_nonce)?;
        let response = request(
            &self.tls,
            self.resolver.as_ref(),
            Method::HEAD,
            &url,
            None,
            self.timeout,
        )
        .await?;
        response.nonce.ok_or_else(|| {
            UpstreamError::Protocol("newNonce response carried no Replay-Nonce".to_string())
        })
    }

    fn parse(&self, url: &str) -> Result<Url, UpstreamError> {
        Url::parse(url).map_err(|error| UpstreamError::Url(format!("{url}: {error}")))
    }

    /// A signed POST (RFC 8555 §6.2). `payload` of `None` is the POST-as-GET
    /// form (§6.3), whose payload segment is the empty string rather than
    /// `null` or `{}`.
    ///
    /// Retries once on `badNonce`: §6.5 makes a rejected nonce an ordinary
    /// event, and the retry is what keeps it from surfacing as a real failure.
    pub async fn post(
        &self,
        key: &AccountKey,
        signer: &Signer<'_>,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<AcmeResponse, UpstreamError> {
        match self.post_once(key, signer, url, payload).await {
            Err(error) if error.is_bad_nonce() => {
                debug!(event = "upstream_bad_nonce_retry", url = %url);
                self.post_once(key, signer, url, payload).await
            }
            other => other,
        }
    }

    async fn post_once(
        &self,
        key: &AccountKey,
        signer: &Signer<'_>,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<AcmeResponse, UpstreamError> {
        let nonce = self.nonce().await?;
        let parsed = self.parse(url)?;

        let protected = match signer {
            Signer::Jwk => json!({
                "alg": "ES256", "jwk": key.jwk(), "nonce": nonce, "url": url,
            }),
            Signer::Kid(kid) => json!({
                "alg": "ES256", "kid": kid, "nonce": nonce, "url": url,
            }),
        };
        let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&protected)
                .map_err(|error| UpstreamError::Jws(error.to_string()))?,
        );
        // POST-as-GET signs over an *empty* payload segment, not "{}".
        let payload_b64 = match payload {
            Some(value) => BASE64_URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(value).map_err(|error| UpstreamError::Jws(error.to_string()))?,
            ),
            None => String::new(),
        };
        let signature = key.sign(format!("{protected_b64}.{payload_b64}").as_bytes())?;

        let body = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": BASE64_URL_SAFE_NO_PAD.encode(signature),
        });
        let body =
            serde_json::to_vec(&body).map_err(|error| UpstreamError::Jws(error.to_string()))?;

        let response = request(
            &self.tls,
            self.resolver.as_ref(),
            Method::POST,
            &parsed,
            Some(Bytes::from(body)),
            self.timeout,
        )
        .await?;

        if response.status.is_success() {
            Ok(response)
        } else {
            Err(problem_from(&response))
        }
    }

    /// A POST-as-GET read of `url` (RFC 8555 §6.3).
    pub async fn get(
        &self,
        key: &AccountKey,
        kid: &str,
        url: &str,
    ) -> Result<AcmeResponse, UpstreamError> {
        self.post(key, &Signer::Kid(kid), url, None).await
    }

    /// An unauthenticated GET, for the one endpoint that takes no JWS:
    /// `renewalInfo` (RFC 9773 §4.1).
    pub async fn get_unsigned(&self, url: &str) -> Result<AcmeResponse, UpstreamError> {
        let parsed = self.parse(url)?;
        let response = request(
            &self.tls,
            self.resolver.as_ref(),
            Method::GET,
            &parsed,
            None,
            self.timeout,
        )
        .await?;
        if response.status.is_success() {
            Ok(response)
        } else {
            Err(problem_from(&response))
        }
    }
}

/// Builds an [`UpstreamError::Problem`] from a non-2xx response, falling back
/// to the raw body when it is not a problem document.
fn problem_from(response: &AcmeResponse) -> UpstreamError {
    #[derive(Deserialize)]
    struct ProblemDoc {
        #[serde(rename = "type")]
        typ: Option<String>,
        detail: Option<String>,
    }
    let status = response.status.as_u16();
    match serde_json::from_slice::<ProblemDoc>(&response.body) {
        Ok(doc) => UpstreamError::Problem {
            status,
            typ: doc.typ.unwrap_or_else(|| "about:blank".to_string()),
            detail: doc.detail.unwrap_or_default(),
        },
        Err(_) => UpstreamError::Problem {
            status,
            typ: "about:blank".to_string(),
            detail: String::from_utf8_lossy(&response.body)
                .chars()
                .take(200)
                .collect(),
        },
    }
}

/// One HTTP request over TCP or TLS, under `timeout`.
async fn request(
    tls: &Arc<rustls::ClientConfig>,
    resolver: &dyn crate::dns::Resolver,
    method: Method,
    url: &Url,
    body: Option<Bytes>,
    timeout: Duration,
) -> Result<AcmeResponse, UpstreamError> {
    tokio::time::timeout(timeout, request_inner(tls, resolver, method, url, body))
        .await
        .map_err(|_| UpstreamError::Transport(format!("timed out after {timeout:?}")))?
}

async fn request_inner(
    tls: &Arc<rustls::ClientConfig>,
    resolver: &dyn crate::dns::Resolver,
    method: Method,
    url: &Url,
    body: Option<Bytes>,
) -> Result<AcmeResponse, UpstreamError> {
    let endpoint = crate::http_client::Endpoint::from_url(url).map_err(UpstreamError::Url)?;

    let has_body = body.is_some();
    let request = Request::builder()
        .method(method)
        .uri(url.as_str())
        .header(hyper::header::HOST, endpoint.authority())
        .header(hyper::header::USER_AGENT, "acme-proxy")
        .header(
            hyper::header::CONTENT_TYPE,
            if has_body {
                "application/jose+json"
            } else {
                "application/json"
            },
        )
        .body(Full::new(body.unwrap_or_default()))
        .map_err(|error| UpstreamError::Transport(error.to_string()))?;

    let sender = crate::http_client::connect(resolver, &endpoint, tls)
        .await
        .map_err(UpstreamError::Transport)?;
    send(sender, request).await
}

async fn send(
    mut sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> Result<AcmeResponse, UpstreamError> {
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| UpstreamError::Transport(error.to_string()))?;

    let status = response.status();
    let location = header_string(response.headers().get(LOCATION));
    let nonce = header_string(response.headers().get("replay-nonce"));
    let retry_after = header_string(response.headers().get(RETRY_AFTER))
        .and_then(|value| value.trim().parse::<u64>().ok());

    // Capped, like every other outbound client here (`challenge::http_01`,
    // `filter::netbox::client`). The upstream is a remote CA reached over the
    // network; how much it chooses to send back is not this process's memory
    // to spend. A certificate chain is kilobytes, so the ceiling only ever
    // trips on something that has already gone wrong.
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|error| UpstreamError::Transport(format!("response body: {error}")))?
        .to_bytes();

    Ok(AcmeResponse {
        status,
        body,
        location,
        retry_after,
        nonce,
    })
}

fn header_string(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared resolver `Profile::build_all` supplies at startup. These
    /// tests reach loopback by IP literal, which `dns::connect` short-circuits.
    fn test_resolver() -> std::sync::Arc<dyn crate::dns::Resolver> {
        std::sync::Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }
    use crate::signer::relay::testsrv::{self, Script};

    /// A P-256 PKCS#8 document, via rcgen (already a normal dependency).
    fn pkcs8() -> Vec<u8> {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_der()
    }

    fn key() -> AccountKey {
        AccountKey::from_pkcs8(&pkcs8()).unwrap()
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn an_account_key_exposes_a_jwk_and_a_matching_spki() {
        let key = key();
        let jwk = key.jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");

        // The SPKI must describe the *same* key as the JWK — the cheapest
        // proof being that the crate's own thumbprint helper accepts it and
        // agrees with a thumbprint computed from the JWK members directly.
        let thumbprint = crate::extractors::acme::jwk_thumbprint(key.spki_der()).unwrap();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        let expected = BASE64_URL_SAFE_NO_PAD
            .encode(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref());
        assert_eq!(thumbprint, expected);
    }

    #[test]
    fn a_non_p256_key_is_refused() {
        let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .unwrap()
            .serialize_der();
        assert!(matches!(
            AccountKey::from_pkcs8(&ed25519),
            Err(UpstreamError::Jws(_))
        ));
    }

    #[test]
    fn spki_encoding_rejects_a_malformed_point() {
        assert!(spki_from_p256_public(&[0x04, 0x01]).is_err());
        // A compressed point is well-formed EC but not what ring hands back.
        assert!(spki_from_p256_public(&[0x02; 65]).is_err());
    }

    #[test]
    fn upstream_errors_classify_the_three_cases_the_caller_branches_on() {
        let bad_csr = UpstreamError::Problem {
            status: 403,
            typ: "urn:ietf:params:acme:error:badCSR".to_string(),
            detail: String::new(),
        };
        assert!(bad_csr.is_bad_csr());
        assert!(!bad_csr.is_already_revoked());
        assert!(!bad_csr.is_bad_nonce());

        let revoked = UpstreamError::Problem {
            status: 400,
            typ: "urn:ietf:params:acme:error:alreadyRevoked".to_string(),
            detail: String::new(),
        };
        assert!(revoked.is_already_revoked());
        assert!(!revoked.is_bad_csr());

        let nonce = UpstreamError::Problem {
            status: 400,
            typ: "urn:ietf:params:acme:error:badNonce".to_string(),
            detail: String::new(),
        };
        assert!(nonce.is_bad_nonce());

        // A transport failure is none of them.
        let transport = UpstreamError::Transport("boom".to_string());
        assert!(!transport.is_bad_csr() && !transport.is_already_revoked());
    }

    /// Every variant must render something an operator can act on; the
    /// `Problem` one in particular has to keep the upstream's own wording.
    #[test]
    fn errors_display_their_detail() {
        assert!(UpstreamError::Url("bad".into()).to_string().contains("bad"));
        assert!(
            UpstreamError::Transport("refused".into())
                .to_string()
                .contains("refused")
        );
        assert!(
            UpstreamError::Protocol("garbage".into())
                .to_string()
                .contains("garbage")
        );
        assert!(
            UpstreamError::Jws("nope".into())
                .to_string()
                .contains("nope")
        );
        let rendered = UpstreamError::Problem {
            status: 429,
            typ: "urn:ietf:params:acme:error:rateLimited".to_string(),
            detail: "slow down".to_string(),
        }
        .to_string();
        assert!(
            rendered.contains("429") && rendered.contains("slow down"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn discover_reads_the_directory() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        assert_eq!(
            client.directory().new_order,
            format!("{}/newOrder", upstream.base)
        );
        assert!(client.directory().revoke_cert.is_some());
        assert!(client.directory().renewal_info.is_some());
    }

    #[tokio::test]
    async fn discover_fails_on_an_unusable_url() {
        assert!(matches!(
            AcmeClient::discover("not a url", test_resolver(), TIMEOUT).await,
            Err(UpstreamError::Url(_))
        ));
        assert!(matches!(
            AcmeClient::discover("ftp://example.invalid/dir", test_resolver(), TIMEOUT).await,
            Err(UpstreamError::Url(_))
        ));
    }

    /// A closed port must surface as a transport error rather than hanging.
    #[tokio::test]
    async fn discover_fails_when_nothing_is_listening() {
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = AcmeClient::discover(
            &format!("http://127.0.0.1:{port}/directory"),
            test_resolver(),
            TIMEOUT,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, UpstreamError::Transport(_)), "{error:?}");
    }

    /// Each signed POST must fetch its own nonce: they are single-use, so
    /// reusing one would fail every request after the first.
    #[tokio::test]
    async fn every_signed_post_fetches_a_fresh_nonce() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        let key = key();

        for _ in 0..3 {
            client
                .post(
                    &key,
                    &Signer::Jwk,
                    &client.directory().new_account.clone(),
                    Some(&json!({})),
                )
                .await
                .unwrap();
        }
        assert_eq!(upstream.nonce_fetches(), 3);
    }

    /// RFC 8555 §6.5 treats a rejected nonce as routine, so one retry must
    /// absorb it rather than surfacing a failure.
    #[tokio::test]
    async fn a_bad_nonce_is_retried_once() {
        let upstream = testsrv::start(Script {
            bad_nonce_once: true,
            ..Script::default()
        })
        .await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();

        let response = client
            .post(
                &key(),
                &Signer::Jwk,
                &client.directory().new_account.clone(),
                Some(&json!({})),
            )
            .await
            .expect("the retry must absorb a single badNonce");
        assert_eq!(response.status, 201);
        // Two nonces: the rejected one and the retry's.
        assert_eq!(upstream.nonce_fetches(), 2);
    }

    #[tokio::test]
    async fn a_created_response_carries_its_location() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        let response = client
            .post(
                &key(),
                &Signer::Jwk,
                &client.directory().new_account.clone(),
                Some(&json!({})),
            )
            .await
            .unwrap();
        assert_eq!(
            response.location.as_deref(),
            Some(format!("{}/acct/1", upstream.base).as_str())
        );
    }

    /// A POST-as-GET signs over an *empty* payload segment, not `{}` — the
    /// distinction RFC 8555 §6.3 draws, and one a server checks.
    #[tokio::test]
    async fn post_as_get_sends_an_empty_payload() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        let response = client
            .get(&key(), "kid-1", &format!("{}/order/1", upstream.base))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(upstream.order_polls(), 1);
    }

    /// An upstream problem document must keep its `type` and `detail`, since
    /// those are what the caller branches on and what an operator reads.
    #[tokio::test]
    async fn an_error_response_becomes_a_problem() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        let error = client
            .get(&key(), "kid-1", &format!("{}/nope", upstream.base))
            .await
            .unwrap_err();
        match error {
            UpstreamError::Problem { status, typ, .. } => {
                assert_eq!(status, 404);
                assert!(typ.ends_with(":malformed"), "{typ}");
            }
            other => panic!("expected a problem document, got {other:?}"),
        }
    }

    /// A non-JSON error body must still produce a usable error rather than a
    /// parse failure that loses the status entirely.
    #[test]
    fn a_non_problem_error_body_still_carries_the_status() {
        let response = AcmeResponse {
            status: StatusCode::BAD_GATEWAY,
            body: Bytes::from_static(b"<html>proxy error</html>"),
            location: None,
            retry_after: None,
            nonce: None,
        };
        match problem_from(&response) {
            UpstreamError::Problem {
                status,
                typ,
                detail,
            } => {
                assert_eq!(status, 502);
                assert_eq!(typ, "about:blank");
                assert!(detail.contains("proxy error"), "{detail}");
            }
            other => panic!("expected a problem, got {other:?}"),
        }
    }

    #[test]
    fn response_helpers_decode_json_and_text() {
        let response = AcmeResponse {
            status: StatusCode::OK,
            body: Bytes::from_static(br#"{"status":"valid"}"#),
            location: None,
            retry_after: None,
            nonce: None,
        };
        let value: Value = response.json().unwrap();
        assert_eq!(value["status"], "valid");
        assert_eq!(response.text().unwrap(), r#"{"status":"valid"}"#);

        let invalid = AcmeResponse {
            status: StatusCode::OK,
            body: Bytes::from_static(b"not json"),
            location: None,
            retry_after: None,
            nonce: None,
        };
        assert!(invalid.json::<Value>().is_err());
        // Invalid UTF-8 must be reported, not silently replaced.
        let binary = AcmeResponse {
            status: StatusCode::OK,
            body: Bytes::from_static(&[0xff, 0xfe]),
            location: None,
            retry_after: None,
            nonce: None,
        };
        assert!(binary.text().is_err());
    }

    /// The whole point of the timeout: a server that accepts but never answers
    /// must not wedge the caller.
    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Hold the connection open, answering nothing.
            std::mem::forget(stream);
        });

        let error = AcmeClient::discover(
            &format!("http://127.0.0.1:{port}/directory"),
            test_resolver(),
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, UpstreamError::Transport(detail) if detail.contains("timed out")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn get_unsigned_reaches_an_endpoint_that_takes_no_jws() {
        let upstream = testsrv::start(Script::default()).await;
        let client = AcmeClient::discover(&upstream.directory_url(), test_resolver(), TIMEOUT)
            .await
            .unwrap();
        // The directory itself is the one unsigned GET target the fake serves.
        let response = client
            .get_unsigned(&upstream.directory_url())
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(
            client
                .get_unsigned(&format!("{}/nope", upstream.base))
                .await
                .is_err()
        );
    }
}
