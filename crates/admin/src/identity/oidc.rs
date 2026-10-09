//! One OpenID Connect provider, signed in to with the authorization code flow
//! and PKCE (OpenID Connect Core 1.0 §3.1, RFC 7636 `S256`).
//!
//! Hand-rolled on the tree's own outbound client and `core::jws::jwt` rather
//! than a library -- ADR 0015 has the trade. What this module owns:
//!
//! - **Discovery and the key set are fetched lazily and cached.** Startup never
//!   contacts the provider, so a provider that is down cannot stop the panel
//!   (or its local break-glass realm) from starting. Discovery is kept for
//!   [`DISCOVERY_TTL`]; the key set until a token names a `kid` it does not
//!   hold, and then refetched at most once per [`JWKS_REFETCH_INTERVAL`], so a
//!   stream of forged `kid`s cannot turn this server into a load generator
//!   against the provider.
//! - **The issuer is checked twice:** the discovery document must name exactly
//!   the configured issuer (§4.3 of OpenID Connect Discovery), and every token
//!   must too.
//! - **`state`, `nonce` and the PKCE verifier are the caller's**
//!   (`webadmin::pages::oidc`), which stores them in `admin_oidc_logins` and
//!   hands them back at the callback. This module is stateless about sign-ins.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use url::Url;

use acme_proxy_core::config::OidcProviderConfig;
use acme_proxy_core::jws::jwt::{IdTokenExpectations, JwkSet, JwtError, verify_id_token};
use acme_proxy_net::http_client::Outbound;

use super::http::Client;
use super::{ExternalIdentity, RoleMap, SignInError, read_secret};

/// How long a discovery document is trusted before it is fetched again.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

/// The least time between two key-set fetches forced by an unknown `kid`.
pub const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Clock skew tolerated on a token's times.
const LEEWAY_SECONDS: i64 = 60;

/// The parts of a discovery document this relying party uses, as published.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// [`DiscoveryDocument`], its endpoints parsed and checked.
#[derive(Debug, Clone)]
struct Discovery {
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
    userinfo_endpoint: Option<Url>,
}

impl Discovery {
    /// Parses every endpoint, refusing one that is not `https` -- the client
    /// secret and the authorization code cross the token endpoint, and the key
    /// set decides whose tokens are believed. `http` is allowed only when the
    /// issuer itself is loopback (a provider on the same host, or a test).
    fn from_document(document: DiscoveryDocument, issuer: &Url) -> Result<Self, String> {
        let plain_ok = super::is_loopback(issuer);
        let endpoint = |name: &str, raw: &str| -> Result<Url, String> {
            let url = Url::parse(raw).map_err(|error| format!("{name} `{raw}`: {error}"))?;
            match url.scheme() {
                "https" => Ok(url),
                "http" if plain_ok => Ok(url),
                other => Err(format!(
                    "{name} `{raw}`: scheme `{other}` (https is required)"
                )),
            }
        };
        Ok(Self {
            authorization_endpoint: endpoint(
                "authorization_endpoint",
                &document.authorization_endpoint,
            )?,
            token_endpoint: endpoint("token_endpoint", &document.token_endpoint)?,
            jwks_uri: endpoint("jwks_uri", &document.jwks_uri)?,
            userinfo_endpoint: document
                .userinfo_endpoint
                .as_deref()
                .map(|raw| endpoint("userinfo_endpoint", raw))
                .transpose()?,
        })
    }
}

#[derive(Default)]
struct Cache {
    discovery: Option<(Arc<Discovery>, Instant)>,
    keys: Option<Arc<JwkSet>>,
    /// When an unknown `kid` last forced a fetch. Only those are rate-limited:
    /// a rotation just after the first fetch must still be picked up at once.
    keys_forced_at: Option<Instant>,
}

/// One `[admin.auth.oidc.<name>]`.
pub struct OidcProvider {
    pub name: String,
    pub display_name: String,
    config: OidcProviderConfig,
    client_secret: String,
    pub roles: RoleMap,
    client: Client,
    timeout: Duration,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for OidcProvider {
    /// Never renders the client secret.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcProvider")
            .field("name", &self.name)
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

/// What the callback hands back to finish a sign-in.
#[derive(Debug, Clone, Copy)]
pub struct Callback<'a> {
    pub code: &'a str,
    pub pkce_verifier: &'a str,
    pub nonce: &'a str,
    /// Exactly the `redirect_uri` the authorization request carried.
    pub redirect_uri: &'a str,
    pub now: i64,
}

impl OidcProvider {
    /// Builds the provider from its section, reading the client secret and the
    /// CA file now. Contacts nothing.
    pub fn from_config(
        name: &str,
        config: &OidcProviderConfig,
        outbound: &Outbound,
    ) -> anyhow::Result<Self> {
        let key = format!("admin.auth.oidc.{name}");
        let client_secret = read_secret(
            &config.client_secret,
            &config.client_secret_file,
            &format!("{key}.client_secret_file"),
        )?;
        let tls = acme_proxy_net::http_client::webpki_tls_config_with_ca(
            &config.ca_cert_path,
            &format!("{key}.ca_cert_path"),
        )?;
        Ok(Self {
            name: name.to_string(),
            display_name: if config.display_name.trim().is_empty() {
                name.to_string()
            } else {
                config.display_name.clone()
            },
            config: config.clone(),
            client_secret,
            roles: RoleMap::from_config(&config.roles),
            client: Client {
                outbound: outbound.clone(),
                tls: Arc::new(tls),
            },
            timeout: Duration::from_millis(config.timeout_ms),
            cache: Mutex::new(Cache::default()),
        })
    }

    /// `oidc:<name>`, the `admin_users.auth_provider` value.
    #[must_use]
    pub fn key(&self) -> String {
        format!("oidc:{}", self.name)
    }

    /// The URL to send the browser to: the provider's authorization endpoint
    /// with this sign-in's `state`, `nonce` and PKCE challenge.
    pub async fn authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<Url, SignInError> {
        let discovery = self.discovery().await?;
        let mut scopes: Vec<&str> = self.config.scopes.iter().map(String::as_str).collect();
        if !scopes.contains(&"openid") {
            scopes.insert(0, "openid");
        }
        let mut url = discovery.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &pkce_challenge(pkce_verifier))
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    /// Exchanges the authorization code and verifies what comes back,
    /// answering who signed in.
    pub async fn complete(&self, callback: &Callback<'_>) -> Result<ExternalIdentity, SignInError> {
        let discovery = self.discovery().await?;
        let response = self
            .timed(self.client.post_form(
                &discovery.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", callback.code),
                    ("redirect_uri", callback.redirect_uri),
                    ("code_verifier", callback.pkce_verifier),
                ],
                (&self.config.client_id, &self.client_secret),
            ))
            .await?;
        let id_token = response
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SignInError::rejected("id_token_invalid", "the token response has no id_token")
            })?;

        let expected = IdTokenExpectations {
            issuer: &self.config.issuer,
            client_id: &self.config.client_id,
            nonce: callback.nonce,
            now: callback.now,
            leeway_seconds: LEEWAY_SECONDS,
        };
        let claims = self.verify(id_token, &discovery, &expected).await?;
        self.check_assurance(&claims)?;

        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let groups = if self.config.userinfo_groups {
            let access_token = response
                .get("access_token")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SignInError::rejected(
                        "id_token_invalid",
                        "the token response has no access_token",
                    )
                })?;
            self.userinfo_groups(&discovery, access_token, &subject)
                .await?
        } else {
            groups_of(&claims, &self.config.groups_claim)
        };

        let username = claims
            .get(&self.config.username_claim)
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                SignInError::rejected(
                    "id_token_invalid",
                    format!(
                        "the token carries no `{}` claim",
                        self.config.username_claim
                    ),
                )
            })?;

        Ok(ExternalIdentity {
            provider: self.key(),
            // An issuer is a URL and holds no space, so the split is unambiguous.
            external_id: format!("{} {subject}", self.config.issuer),
            username: username.to_string(),
            groups,
        })
    }

    /// The ID token's claims, refetching the key set once if the token names a
    /// key the cached set does not hold.
    async fn verify(
        &self,
        id_token: &str,
        discovery: &Discovery,
        expected: &IdTokenExpectations<'_>,
    ) -> Result<Map<String, Value>, SignInError> {
        let keys = self.keys(discovery, false).await?;
        match verify_id_token(id_token, &keys, expected) {
            Err(JwtError::UnknownKey) => {
                let refreshed = self.keys(discovery, true).await?;
                verify_id_token(id_token, &refreshed, expected)
            }
            other => other,
        }
        .map_err(|error| SignInError::rejected("id_token_invalid", error.to_string()))
    }

    /// `required_acr` and `required_amr`: the assurance the operator demands
    /// of the provider's own authentication (§2, `acr` and `amr`).
    fn check_assurance(&self, claims: &Map<String, Value>) -> Result<(), SignInError> {
        if !self.config.required_acr.is_empty() {
            let acr = claims
                .get("acr")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !self.config.required_acr.iter().any(|wanted| wanted == acr) {
                return Err(SignInError::rejected(
                    "assurance_not_met",
                    format!("acr `{acr}` is none of the required values"),
                ));
            }
        }
        if !self.config.required_amr.is_empty() {
            let amr = groups_of(claims, "amr");
            if let Some(missing) = self
                .config
                .required_amr
                .iter()
                .find(|wanted| !amr.contains(wanted))
            {
                return Err(SignInError::rejected(
                    "assurance_not_met",
                    format!("amr lacks `{missing}`"),
                ));
            }
        }
        Ok(())
    }

    async fn userinfo_groups(
        &self,
        discovery: &Discovery,
        access_token: &str,
        subject: &str,
    ) -> Result<Vec<String>, SignInError> {
        let endpoint = discovery.userinfo_endpoint.as_ref().ok_or_else(|| {
            SignInError::Unreachable(
                "userinfo_groups is set but the provider advertises no userinfo_endpoint"
                    .to_string(),
            )
        })?;
        let userinfo = self
            .timed(self.client.get_json(endpoint, Some(access_token)))
            .await?;
        // OpenID Connect Core §5.3.2: a userinfo `sub` that is not the ID
        // token's must not be used.
        if userinfo.get("sub").and_then(Value::as_str) != Some(subject) {
            return Err(SignInError::rejected(
                "id_token_invalid",
                "the userinfo `sub` is not the ID token's",
            ));
        }
        Ok(userinfo
            .as_object()
            .map(|claims| groups_of(claims, &self.config.groups_claim))
            .unwrap_or_default())
    }

    /// The discovery document, from the cache while it is fresh.
    async fn discovery(&self) -> Result<Arc<Discovery>, SignInError> {
        let mut cache = self.cache.lock().await;
        if let Some((discovery, fetched)) = &cache.discovery
            && fetched.elapsed() < DISCOVERY_TTL
        {
            return Ok(discovery.clone());
        }

        let issuer = Url::parse(&self.config.issuer)
            .map_err(|error| SignInError::Unreachable(format!("issuer: {error}")))?;
        let url = discovery_url(&self.config.issuer)
            .map_err(|error| SignInError::Unreachable(error.to_string()))?;
        let document = self.timed(self.client.get_json(&url, None)).await?;
        let document: DiscoveryDocument = serde_json::from_value(document).map_err(|error| {
            SignInError::Unreachable(format!("{url} is not a discovery document: {error}"))
        })?;
        if document.issuer != self.config.issuer {
            return Err(SignInError::Unreachable(format!(
                "{url} names issuer `{}`, not the configured `{}`",
                document.issuer, self.config.issuer
            )));
        }
        let discovery = Arc::new(
            Discovery::from_document(document, &issuer)
                .map_err(|error| SignInError::Unreachable(format!("{url}: {error}")))?,
        );
        cache.discovery = Some((discovery.clone(), Instant::now()));
        Ok(discovery)
    }

    /// The key set: the cached one, or a fresh fetch when there is none, or
    /// when `refresh` asks and no forced fetch happened in the last
    /// [`JWKS_REFETCH_INTERVAL`].
    async fn keys(&self, discovery: &Discovery, refresh: bool) -> Result<Arc<JwkSet>, SignInError> {
        let mut cache = self.cache.lock().await;
        let forced_recently = cache
            .keys_forced_at
            .is_some_and(|at| at.elapsed() < JWKS_REFETCH_INTERVAL);
        if let Some(keys) = &cache.keys
            && (!refresh || forced_recently)
        {
            return Ok(keys.clone());
        }
        if refresh {
            cache.keys_forced_at = Some(Instant::now());
        }

        let document = self
            .timed(self.client.get_json(&discovery.jwks_uri, None))
            .await?;
        let keys = JwkSet::parse(document.to_string().as_bytes()).map_err(|error| {
            SignInError::Unreachable(format!("{}: {error}", discovery.jwks_uri))
        })?;
        let keys = Arc::new(keys);
        cache.keys = Some(keys.clone());
        Ok(keys)
    }

    /// One call to the provider, bounded by `timeout_ms`.
    async fn timed(
        &self,
        call: impl Future<Output = Result<Value, String>>,
    ) -> Result<Value, SignInError> {
        match tokio::time::timeout(self.timeout, call).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(SignInError::Unreachable(error)),
            Err(_) => Err(SignInError::Unreachable(format!(
                "no answer within {} ms",
                self.timeout.as_millis()
            ))),
        }
    }
}

/// `{issuer}/.well-known/openid-configuration` -- appended to the issuer's
/// path, not substituted for it (Discovery §4.1), so an issuer under a path
/// (Keycloak's `/realms/<realm>`) keeps it.
fn discovery_url(issuer: &str) -> Result<Url, url::ParseError> {
    Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
}

/// RFC 7636 §4.2: `BASE64URL(SHA256(code_verifier))`.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ))
}

/// The strings in a claim that is an array of strings, or a single string.
/// Anything else -- absent, a number, an object -- is no groups at all.
fn groups_of(claims: &Map<String, Value>, claim: &str) -> Vec<String> {
    match claims.get(claim) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(one)) => vec![one.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 appendix B.
    #[test]
    fn the_pkce_challenge_matches_the_rfc_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn discovery_keeps_the_issuer_path() {
        assert_eq!(
            discovery_url("https://sso.example/realms/acme/")
                .unwrap()
                .as_str(),
            "https://sso.example/realms/acme/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://login.example").unwrap().as_str(),
            "https://login.example/.well-known/openid-configuration"
        );
    }

    /// Every endpoint must be `https`, unless the issuer itself is loopback.
    #[test]
    fn discovery_endpoints_must_be_https_off_loopback() {
        let document = |token: &str| DiscoveryDocument {
            issuer: String::new(),
            authorization_endpoint: "https://idp.example/authorize".to_string(),
            token_endpoint: token.to_string(),
            jwks_uri: "https://idp.example/jwks".to_string(),
            userinfo_endpoint: Some("https://idp.example/userinfo".to_string()),
        };
        let remote = Url::parse("https://idp.example").unwrap();
        let local = Url::parse("http://127.0.0.1:8080").unwrap();

        let refused =
            Discovery::from_document(document("http://idp.example/token"), &remote).unwrap_err();
        assert!(refused.contains("token_endpoint"), "{refused}");
        assert!(Discovery::from_document(document("not a url"), &remote).is_err());
        assert!(Discovery::from_document(document("http://127.0.0.1:8080/token"), &local).is_ok());
        let parsed =
            Discovery::from_document(document("https://idp.example/token"), &remote).unwrap();
        assert!(parsed.userinfo_endpoint.is_some());
    }

    #[test]
    fn debug_never_renders_the_client_secret() {
        let provider = OidcProvider::from_config(
            "corp",
            &OidcProviderConfig {
                client_secret: "hunter2".to_string(),
                ..OidcProviderConfig::default()
            },
            &acme_proxy_net::testutil::outbound_with(std::sync::Arc::new(
                acme_proxy_net::dns::HickoryResolver::from_system_uncached().unwrap(),
            )),
        )
        .unwrap();
        assert!(!format!("{provider:?}").contains("hunter2"));
        assert_eq!(provider.key(), "oidc:corp");
        assert_eq!(provider.display_name, "corp");
    }

    #[test]
    fn groups_are_an_array_or_a_single_string() {
        let claims: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "many": ["a", 7, "b"], "one": "c", "number": 3
        }))
        .unwrap();
        assert_eq!(groups_of(&claims, "many"), vec!["a", "b"]);
        assert_eq!(groups_of(&claims, "one"), vec!["c"]);
        assert!(groups_of(&claims, "number").is_empty());
        assert!(groups_of(&claims, "absent").is_empty());
    }
}
