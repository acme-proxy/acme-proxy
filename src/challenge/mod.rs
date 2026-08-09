//! Challenge-validation abstraction.
//!
//! Triggering a challenge is the moment a client proves it controls the name it
//! asked a certificate for (RFC 8555 §8). *How* that proof is checked is
//! pluggable: the [`ChallengeValidator`] trait hides each type behind a single
//! [`validate`](ChallengeValidator::validate) call, and [`from_config`] builds
//! the configured set at startup.
//!
//! The shape mirrors the [`signer`](crate::signer) and [`filter`](crate::filter)
//! subsystems — a trait, an error enum the *caller* maps to a
//! [`Problem`](crate::error::Problem), and a `from_config` selector that fails
//! fast. Like them, this module never mentions `error.rs`: what a failed
//! validation means in HTTP terms is the handler's business.
//!
//! ## Two independent knobs
//!
//! [`ChallengeConfig::enabled`](crate::config::ChallengeConfig::enabled) shapes
//! the **authorization object** — which challenges a client is offered, and
//! therefore which it may choose. [`bypass`](crate::config::ChallengeConfig::bypass)
//! decides whether triggering one does any work.
//!
//! They are separate because they answer different questions, and because
//! `bypass` has to short-circuit *construction*: building the real validators
//! reads `/etc/resolv.conf` and installs a TLS client configuration, which a
//! bypassing server (the default, and every test) must not do.
//!
//! ## Bypass is opt-in
//!
//! With `bypass = true` a triggered challenge is accepted with no network check
//! at all. That means an open CA: anyone who can reach the server can obtain a
//! certificate for any name, and the [`filter`](crate::filter) subsystem is
//! then the only access control. [`from_config`] says so, loudly, at startup.
//!
//! It used to be the default — the behaviour predating real validation, kept so
//! an existing deployment survived that upgrade. It no longer is, because
//! combined with an empty `filter.enabled` and a default bind on every
//! interface it made a zero-config server an open CA. `ChallengeRegistry::default()`
//! still bypasses: that is a test convenience the server never reaches.
//!
//! ## One budget for the whole attempt
//!
//! Validation runs **inside** the `POST /chall/{id}` request — there is no
//! `processing` state and no detached task — so [`ChallengeRegistry::validate`]
//! wraps every attempt in `challenge.timeout_ms`. Without it a wedged target
//! would pin a request, and a `SQLite` connection, open indefinitely.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{ChallengeConfig, DnsConfig};
use crate::dns::{HickoryResolver, Resolver, resolver_addr};

pub mod dns_01;
pub mod http_01;
pub mod tls_alpn_01;

/// The RFC 8555 §8.3 challenge type: fetch a file over HTTP.
pub const HTTP_01: &str = "http-01";
/// The RFC 8555 §8.4 challenge type: look up a TXT record. The only type that
/// can prove a wildcard.
pub const DNS_01: &str = "dns-01";
/// The RFC 8737 challenge type: a TLS handshake carrying the proof in the
/// responder's certificate.
pub const TLS_ALPN_01: &str = "tls-alpn-01";

/// Every challenge type this server knows how to offer.
pub const KNOWN_TYPES: &[&str] = &[HTTP_01, DNS_01, TLS_ALPN_01];

/// A pluggable challenge-validation policy: one type of proof.
#[async_trait]
pub trait ChallengeValidator: Send + Sync {
    /// The RFC challenge `type` this validator answers for.
    ///
    /// Doubles as the registry's dispatch key, deliberately: a validator cannot
    /// end up registered under a name it does not actually handle.
    fn typ(&self) -> &'static str;

    /// Proves the client controls `ctx.identifier`. `Ok(())` is a pass.
    async fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), ChallengeError>;
}

/// What a [`ChallengeValidator`] needs to know to check one challenge.
#[derive(Debug)]
pub struct ValidationContext<'a> {
    /// The DNS name to probe. For a wildcard authorization this is the **base**
    /// name (`example.com`), never `*.example.com`: a wildcard is proved by
    /// controlling the zone, so the record and the handshake both live at the
    /// base name.
    pub identifier: &'a str,

    /// Whether the authorization this challenge belongs to covers the wildcard.
    /// Only `dns-01` ever sees `true` — [`ChallengeRegistry::types_for`] never
    /// creates the other types for a wildcard authorization.
    pub wildcard: bool,

    /// The challenge's own token.
    pub token: &'a str,

    /// `token || "." || base64url(SHA256(JWK thumbprint))`, RFC 8555 §8.1.
    ///
    /// Computed once by the handler from the account key: every validator needs
    /// it and none of them should re-derive it.
    pub key_authorization: &'a str,

    /// For log correlation only.
    pub challenge_id: &'a str,
}

/// Why a validation failed, mapped by the caller to the right ACME error.
///
/// The split mirrors [`FilterError`](crate::filter::FilterError): a statement
/// about the client's setup is not the same as the server being unable to reach
/// a verdict at all.
#[derive(Debug)]
pub enum ChallengeError {
    /// The validation target could not be reached: TCP refused, no route, a
    /// redirect chain that never ended, the attempt timing out.
    Connection(String),
    /// A DNS query the challenge needed failed or returned nothing.
    Dns(String),
    /// The target answered, but not with what the challenge requires — a TXT
    /// record that does not match, a certificate missing the expected extension.
    IncorrectResponse(String),
    /// A TLS-level failure during a `tls-alpn-01` handshake.
    Tls(String),
    /// The target served something that is not the key authorization. RFC 8555
    /// §8.3 uses this type for exactly that case.
    Unauthorized(String),
    /// The validator itself failed — a bug, or a type with no validator behind
    /// it. The client may retry.
    Internal(String),
}

impl ChallengeError {
    /// Short label for logs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::Dns(_) => "dns",
            Self::IncorrectResponse(_) => "incorrectResponse",
            Self::Tls(_) => "tls",
            Self::Unauthorized(_) => "unauthorized",
            Self::Internal(_) => "internal",
        }
    }

    /// The human-readable detail, shown to the client.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Connection(detail)
            | Self::Dns(detail)
            | Self::IncorrectResponse(detail)
            | Self::Tls(detail)
            | Self::Unauthorized(detail)
            | Self::Internal(detail) => detail,
        }
    }
}

/// The configured validators plus the settings the handlers need to apply them.
///
/// Cheap to clone behind the `Arc` it is always held in.
pub struct ChallengeRegistry {
    /// Empty when [`Self::bypass`] is set — the real validators are never built.
    validators: Vec<Arc<dyn ChallengeValidator>>,
    /// Always populated: this is what shapes each new authorization, bypass or
    /// not.
    enabled: Vec<String>,
    bypass: bool,
    timeout: Duration,
}

impl std::fmt::Debug for ChallengeRegistry {
    /// `dyn ChallengeValidator` is not `Debug`, and `enabled` says everything
    /// the validator list would.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChallengeRegistry")
            .field("enabled", &self.enabled)
            .field("bypass", &self.bypass)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for ChallengeRegistry {
    /// Bypassing, offering `http-01` alone.
    ///
    /// This is a **test** default and deliberately no longer matches
    /// `from_config(&ChallengeConfig::default())`, which validates for real.
    /// The server never reaches this impl — `Profile::build_all` always goes
    /// through `from_config` — and a test suite that has no `http-01` responder
    /// on port 80 needs a registry that answers without one. The divergence is
    /// pinned by `the_test_default_bypasses_where_the_configured_default_does_not`
    /// so it stays a decision rather than a drift.
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            enabled: vec![HTTP_01.to_string()],
            bypass: true,
            timeout: Duration::from_secs(5),
        }
    }
}

impl ChallengeRegistry {
    /// Builds a registry directly from parts. Mostly useful to tests; production
    /// goes through [`from_config`].
    #[must_use]
    pub fn new(
        validators: Vec<Arc<dyn ChallengeValidator>>,
        enabled: Vec<String>,
        bypass: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            validators,
            enabled,
            bypass,
            timeout,
        }
    }

    /// The challenge types offered, in the order they were configured.
    #[must_use]
    pub fn enabled_types(&self) -> &[String] {
        &self.enabled
    }

    /// Whether triggering a challenge skips validation entirely.
    #[must_use]
    pub fn is_bypassed(&self) -> bool {
        self.bypass
    }

    /// The challenge types to create on a new authorization.
    ///
    /// A wildcard can only be proved by `dns-01` (RFC 8555 §8.4): control of one
    /// host says nothing about the rest of the zone. The other types are
    /// therefore filtered out for a wildcard authorization — possibly leaving
    /// **nothing**, which the caller turns into a `rejectedIdentifier` rather
    /// than creating an authorization no client could ever satisfy.
    pub fn types_for(&self, wildcard: bool) -> Vec<&str> {
        self.enabled
            .iter()
            .map(String::as_str)
            .filter(|typ| !wildcard || *typ == DNS_01)
            .collect()
    }

    /// Runs the validator for `typ` within the configured budget.
    pub async fn validate(
        &self,
        typ: &str,
        ctx: &ValidationContext<'_>,
    ) -> Result<(), ChallengeError> {
        if self.bypass {
            debug!(
                event = "challenge_bypassed",
                typ,
                identifier = ctx.identifier,
                challenge_id = ctx.challenge_id,
            );
            return Ok(());
        }

        let validator = self
            .validators
            .iter()
            .find(|validator| validator.typ() == typ)
            .ok_or_else(|| {
                ChallengeError::Internal(format!("no validator registered for {typ}"))
            })?;

        match timeout(self.timeout, validator.validate(ctx)).await {
            Ok(result) => result.inspect_err(|error| {
                warn!(
                    event = "challenge_validation_failed",
                    typ,
                    identifier = ctx.identifier,
                    challenge_id = ctx.challenge_id,
                    kind = error.kind(),
                    detail = %error.detail(),
                );
            }),
            // A timeout never reaches the `inspect_err` above, so without this
            // the one failure mode most worth seeing — the responder never
            // answered at all — was the only one not to emit an event.
            Err(_) => {
                warn!(
                    event = "challenge_validation_timeout",
                    typ,
                    identifier = ctx.identifier,
                    challenge_id = ctx.challenge_id,
                    timeout_ms = crate::millis(self.timeout),
                );
                Err(ChallengeError::Connection(format!(
                    "{typ} validation of {} timed out after {}ms",
                    ctx.identifier,
                    self.timeout.as_millis()
                )))
            }
        }
    }
}
/// Refuses a `challenge.enabled` this server cannot act on.
///
/// Run before anything else and **regardless of `bypass`**: a typo would
/// otherwise sit unnoticed until someone turned validation on, and in the
/// meantime it would silently shape every authorization this server hands out.
fn validate_enabled(enabled: &[String]) -> anyhow::Result<()> {
    if enabled.is_empty() {
        anyhow::bail!(
            "challenge.enabled is empty: authorizations would carry no challenges, \
             so no client could ever prove control of a name"
        );
    }
    for name in enabled {
        if !KNOWN_TYPES.contains(&name.as_str()) {
            anyhow::bail!("unknown challenge type: {name}");
        }
    }
    Ok(())
}

/// The one resolver every validator shares: `dns-01`'s TXT lookup, and the
/// connect target `http-01`/`tls-alpn-01` resolve before reaching out.
///
/// Built once rather than per-validator, since it is the same answer for all of
/// them — and **uncached**, because a client that publishes a `dns-01` record
/// moments before triggering would otherwise be defeated by a cached negative.
pub fn build_resolver(addr: Option<std::net::SocketAddr>) -> anyhow::Result<Arc<dyn Resolver>> {
    Ok(Arc::new(match addr {
        Some(addr) => HickoryResolver::from_address_uncached(addr)
            .map_err(|error| anyhow::anyhow!("dns.resolver: {error}"))?,
        None => HickoryResolver::from_system_uncached()
            .map_err(|error| anyhow::anyhow!("challenge: {error}"))?,
    }))
}

/// Builds the configured challenge registry. Called once at startup, so it may
/// fail fast (the caller exits on error).
///
/// `dns` is [`crate::config::Config::dns`], not a field of `cfg`: the resolver
/// it selects is shared with [`filter::from_config`](crate::filter::from_config)
/// (`reverse_dns`), since both answer the same question — which nameserver this
/// process trusts — and a deployment overriding it wants that answered
/// consistently everywhere, not per-subsystem.
pub fn from_config(
    cfg: &ChallengeConfig,
    dns: &DnsConfig,
) -> anyhow::Result<Arc<ChallengeRegistry>> {
    validate_enabled(&cfg.enabled)?;

    // Parsed bypass or not, for the same reason: a typo in `dns.resolver` must
    // not sit silent until someone turns validation on. Building the resolver
    // it names is what actually reaches the network (or /etc/resolv.conf), so
    // that part still waits for the `!cfg.bypass` branch below.
    let addr = resolver_addr(dns)?;

    let timeout = Duration::from_millis(cfg.timeout_ms);

    if cfg.bypass {
        // Worth being noisy about, for the same reason `filters_disabled` is:
        // this is the setting that makes the server an open CA.
        warn!(
            event = "challenge_validation_bypassed",
            enabled = ?cfg.enabled,
            "challenge.bypass is on: triggering a challenge marks it valid with no network \
             check, so any client that can reach this server can obtain a certificate for \
             any name (set challenge.bypass = false)"
        );
        return Ok(Arc::new(ChallengeRegistry::new(
            Vec::new(),
            cfg.enabled.clone(),
            true,
            timeout,
        )));
    }

    let resolver = build_resolver(addr)?;

    let mut validators: Vec<Arc<dyn ChallengeValidator>> = Vec::with_capacity(cfg.enabled.len());
    for name in &cfg.enabled {
        let validator: Arc<dyn ChallengeValidator> = match name.as_str() {
            HTTP_01 => Arc::new(http_01::Http01Validator::from_config(
                &cfg.http_01,
                resolver.clone(),
            )?),
            DNS_01 => Arc::new(dns_01::Dns01Validator::from_config(resolver.clone())),
            TLS_ALPN_01 => Arc::new(tls_alpn_01::TlsAlpn01Validator::from_config(
                &cfg.tls_alpn_01,
                resolver.clone(),
            )?),
            // Unreachable: the loop above rejected every unknown name.
            other => anyhow::bail!("unknown challenge type: {other}"),
        };
        validators.push(validator);
    }

    info!(
        event = "challenge_validation_enabled",
        enabled = ?cfg.enabled,
        timeout_ms = cfg.timeout_ms,
    );

    Ok(Arc::new(ChallengeRegistry::new(
        validators,
        cfg.enabled.clone(),
        false,
        timeout,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A validator answering from a canned outcome, never touching the network.
    struct StubValidator {
        typ: &'static str,
        outcome: Option<&'static str>,
        hang: bool,
        calls: Arc<AtomicUsize>,
    }

    impl StubValidator {
        fn passing(typ: &'static str) -> Self {
            Self {
                typ,
                outcome: None,
                hang: false,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl ChallengeValidator for StubValidator {
        fn typ(&self) -> &'static str {
            self.typ
        }

        async fn validate(&self, _ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hang {
                // Outlives any timeout the tests set.
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            match self.outcome {
                Some(detail) => Err(ChallengeError::IncorrectResponse(detail.to_string())),
                None => Ok(()),
            }
        }
    }

    fn context<'a>(identifier: &'a str, key_authorization: &'a str) -> ValidationContext<'a> {
        ValidationContext {
            identifier,
            wildcard: false,
            token: "tok",
            key_authorization,
            challenge_id: "chall-1",
        }
    }

    fn cfg(enabled: &[&str], bypass: bool) -> ChallengeConfig {
        ChallengeConfig {
            enabled: enabled
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            bypass,
            ..ChallengeConfig::default()
        }
    }

    /// The out-of-the-box posture: `http-01`, really validated.
    ///
    /// It used to bypass. A server started with no configuration binds every
    /// interface and has an empty `filter.enabled`, so bypassing by default made
    /// the zero-config case an open certificate authority.
    #[test]
    fn the_default_config_validates_and_offers_http_01_alone() {
        let registry = from_config(&ChallengeConfig::default(), &DnsConfig::default()).unwrap();
        assert!(!registry.is_bypassed());
        assert_eq!(registry.enabled_types(), [HTTP_01.to_string()]);
        // The real validator is built, since nothing is being bypassed.
        assert_eq!(registry.validators.len(), 1);
    }

    /// Bypassing still builds nothing: constructing the real validators reads
    /// the system resolver and builds a TLS client configuration, which is why
    /// bypass is a flag on the registry rather than a `NoopValidator`.
    #[test]
    fn bypassing_constructs_no_validators() {
        let registry = from_config(&cfg(&["http-01"], true), &DnsConfig::default()).unwrap();
        assert!(registry.is_bypassed());
        assert!(registry.validators.is_empty());
    }

    /// `ChallengeRegistry::default()` is a test convenience and deliberately
    /// differs from the configured default now that the latter validates. The
    /// server never reaches it — `Profile::build_all` always goes through
    /// `from_config` — but a suite with no `http-01` responder on port 80 needs
    /// a registry that answers without one. Asserted so the difference stays a
    /// decision rather than a drift somebody discovers later.
    #[test]
    fn the_test_default_bypasses_where_the_configured_default_does_not() {
        let configured = from_config(&ChallengeConfig::default(), &DnsConfig::default()).unwrap();
        let direct = ChallengeRegistry::default();

        assert!(!configured.is_bypassed());
        assert!(direct.is_bypassed());
        // Everything else must still agree.
        assert_eq!(configured.enabled_types(), direct.enabled_types());
        assert_eq!(configured.timeout, direct.timeout);
    }

    /// A typo must stop the server, not hide behind the bypass until someone
    /// turns validation on months later.
    #[test]
    fn an_unknown_type_is_a_startup_error_even_when_bypassing() {
        for bypass in [true, false] {
            let error = from_config(
                &cfg(&["http-01", "htttp-01"], bypass),
                &DnsConfig::default(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("unknown challenge type") && error.contains("htttp-01"),
                "{error}"
            );
        }
    }

    /// An enabled subsystem configured into a no-op is an operator mistake — the
    /// same reasoning that makes `allowed_ip` refuse two empty lists.
    #[test]
    fn an_empty_enabled_list_is_a_startup_error() {
        let error = from_config(&cfg(&[], true), &DnsConfig::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("challenge.enabled is empty"), "{error}");
    }

    /// `dns.resolver` is validated bypass or not, the same as `enabled`'s
    /// names — a typo must not sit silent until someone turns validation on.
    #[test]
    fn an_invalid_dns_resolver_is_a_startup_error_even_when_bypassing() {
        let dns = DnsConfig {
            resolver: Some("not-a-socket-address".to_string()),
        };
        for bypass in [true, false] {
            let error = from_config(&cfg(&["http-01"], bypass), &dns)
                .unwrap_err()
                .to_string();
            assert!(error.contains("dns.resolver"), "{error}");
        }
    }

    /// A valid override builds without touching the system resolver.
    #[test]
    fn a_valid_dns_resolver_is_used_to_build_the_real_validators() {
        let dns = DnsConfig {
            resolver: Some("127.0.0.1:5300".to_string()),
        };
        let registry = from_config(&cfg(&["dns-01"], false), &dns).unwrap();
        assert!(!registry.is_bypassed());
    }

    #[tokio::test]
    async fn bypass_accepts_every_type_without_a_validator() {
        let registry = ChallengeRegistry::default();
        for typ in KNOWN_TYPES {
            assert!(
                registry
                    .validate(typ, &context("example.com", "tok.thumb"))
                    .await
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn validate_dispatches_on_the_challenge_type() {
        let http = StubValidator::passing(HTTP_01);
        let dns = StubValidator {
            outcome: Some("no matching TXT record"),
            ..StubValidator::passing(DNS_01)
        };
        let (http_calls, dns_calls) = (http.calls.clone(), dns.calls.clone());

        let registry = ChallengeRegistry::new(
            vec![Arc::new(http), Arc::new(dns)],
            vec![HTTP_01.to_string(), DNS_01.to_string()],
            false,
            Duration::from_secs(5),
        );
        let ctx = context("example.com", "tok.thumb");

        assert!(registry.validate(HTTP_01, &ctx).await.is_ok());
        assert!(matches!(
            registry.validate(DNS_01, &ctx).await,
            Err(ChallengeError::IncorrectResponse(_))
        ));

        assert_eq!(http_calls.load(Ordering::SeqCst), 1);
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);
    }

    /// A challenge whose type has no validator is a server bug, not a client
    /// error — it means an authorization outlived a configuration change.
    #[tokio::test]
    async fn a_type_without_a_validator_is_internal() {
        let registry = ChallengeRegistry::new(
            vec![Arc::new(StubValidator::passing(HTTP_01))],
            vec![HTTP_01.to_string()],
            false,
            Duration::from_secs(5),
        );
        assert!(matches!(
            registry
                .validate(DNS_01, &context("example.com", "tok.thumb"))
                .await,
            Err(ChallengeError::Internal(detail)) if detail.contains("dns-01")
        ));
    }

    /// Validation runs inside the request, so a wedged target must not be able
    /// to pin one open.
    #[tokio::test]
    async fn a_wedged_validator_times_out_rather_than_hanging() {
        let registry = ChallengeRegistry::new(
            vec![Arc::new(StubValidator {
                hang: true,
                ..StubValidator::passing(HTTP_01)
            })],
            vec![HTTP_01.to_string()],
            false,
            Duration::from_millis(10),
        );

        assert!(matches!(
            registry
                .validate(HTTP_01, &context("example.com", "tok.thumb"))
                .await,
            Err(ChallengeError::Connection(detail)) if detail.contains("timed out")
        ));
    }

    /// A wildcard authorization offers `dns-01` and nothing else, whatever is
    /// enabled — and offers nothing at all when `dns-01` is not.
    #[test]
    fn types_for_restricts_a_wildcard_to_dns_01() {
        let all = ChallengeRegistry::new(
            Vec::new(),
            KNOWN_TYPES
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            true,
            Duration::from_secs(5),
        );
        assert_eq!(all.types_for(false), KNOWN_TYPES);
        assert_eq!(all.types_for(true), [DNS_01]);

        let without_dns = ChallengeRegistry::default();
        assert_eq!(without_dns.types_for(false), [HTTP_01]);
        assert!(without_dns.types_for(true).is_empty());
    }

    #[test]
    fn challenge_error_labels_and_details() {
        let errors = [
            ChallengeError::Connection("a".into()),
            ChallengeError::Dns("b".into()),
            ChallengeError::IncorrectResponse("c".into()),
            ChallengeError::Tls("d".into()),
            ChallengeError::Unauthorized("e".into()),
            ChallengeError::Internal("f".into()),
        ];
        let kinds: Vec<_> = errors.iter().map(ChallengeError::kind).collect();
        assert_eq!(
            kinds,
            [
                "connection",
                "dns",
                "incorrectResponse",
                "tls",
                "unauthorized",
                "internal"
            ]
        );
        let details: Vec<_> = errors.iter().map(ChallengeError::detail).collect();
        assert_eq!(details, ["a", "b", "c", "d", "e", "f"]);
    }

    #[test]
    fn debug_shows_the_policy_not_the_validators() {
        let rendered = format!("{:?}", ChallengeRegistry::default());
        assert!(rendered.contains("http-01"), "{rendered}");
        assert!(rendered.contains("bypass: true"), "{rendered}");
    }
}
