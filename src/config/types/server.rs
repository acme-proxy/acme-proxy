//! `[database]`, `[server]`, `[admin]`, `[nonce]`, `[logging]`, `[dns]`,
//! `[order]` and `[meta]` — the process-wide sections.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::empty_string_is_no_values;

/// The resolver every DNS lookup this server makes goes through.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub resolver: Option<String>,
}
/// Database connection and configuration settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://sqlite.db".to_string(),
        }
    }
}
/// Server network and binding configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind_address: String,
    pub base_url: String,
    pub tls: TlsConfig,
    /// How many ACME requests may be in flight at once before the server starts
    /// refusing. The value is what it has always been; what changed is that
    /// exceeding it now *sheds* rather than queueing indefinitely.
    pub max_concurrent_requests: usize,
    /// How long a request may wait for a slot before it is refused. Long enough
    /// to absorb a burst, short enough that the queue behind the limit can never
    /// grow deeper than this in time.
    pub admission_wait_ms: u64,
    /// A whole-request deadline. Must exceed every hook the server runs *inside*
    /// a request — `challenge.timeout_ms` and `signer.custom.timeout_ms` — or a
    /// validation still in progress is cut off and reported as a server failure;
    /// `Profile::build_all` refuses to start if it does not.
    pub request_timeout_ms: u64,
    /// Largest request body accepted. An ACME body is a JWS carrying at most a
    /// CSR, i.e. kilobytes; axum's implicit default is 2 MiB.
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "[::]:3000".to_string(),
            base_url: "http://localhost:3000".to_string(),
            tls: TlsConfig::default(),
            max_concurrent_requests: 100,
            admission_wait_ms: 50,
            request_timeout_ms: 60_000,
            max_body_bytes: 128 * 1024,
        }
    }
}
/// HTTPS termination for the server's own listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub handshake_timeout_ms: u64,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: "server.pem".to_string(),
            key_path: "server.key".to_string(),
            handshake_timeout_ms: 10_000,
        }
    }
}
/// The web admin interface: a **second listener**, on its own socket, serving
/// no ACME.
///
/// Process-wide, not per-profile -- an operator manages every endpoint this
/// process serves, so there is no `[profiles.<name>].admin` and this is not in
/// `PROFILE_SECTIONS`.
///
/// Off by default. A certificate authority should not grow a management
/// surface because somebody upgraded it.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    pub enabled: bool,
    /// Loopback on purpose. This listener has no admission control and no
    /// filter chain, and until [`AdminTlsConfig::enabled`] is set, no
    /// transport security either. `webadmin::check_config` refuses to start on
    /// a non-loopback bind while TLS is off.
    pub bind_address: String,
    /// The origin the panel is reached at. Load-bearing three times over: the
    /// CSRF origin check compares against it, a generated self-signed
    /// certificate takes its host, and the pages will build absolute URLs from
    /// it -- exactly as `server.base_url` does for the ACME listener.
    pub base_url: String,
    /// Absolute session lifetime. Never extended by activity: past it, the
    /// operator signs in again.
    pub session_ttl_seconds: u64,
    /// Idle session lifetime, advanced on use (at most once a minute, so a
    /// polling page is not a stream of database writes).
    pub session_idle_timeout_seconds: u64,
    /// Failed logins allowed from one address per window, then `429` with a
    /// `Retry-After`. The password hash is deliberately expensive, so this is
    /// an availability control as much as a credential one.
    pub login_max_attempts: u32,
    pub login_window_seconds: u64,
    /// Require a second factor of every operator.
    ///
    /// What this changes is the operator who has **none**: with it on, their
    /// next sign-in lands on the enrolment page and their session stays
    /// `pending_mfa` until they finish. An operator who already has a factor is
    /// challenged whether this is set or not -- the flag governs enrolment, not
    /// enforcement.
    ///
    /// Deliberately *not* "refuse a password-only login": enrolling needs a
    /// session and a session would then need a factor, so setting this on a
    /// panel with no enrolled operator would brick it, with no way in to fix it.
    ///
    /// Does not retroactively end sessions that predate it. The lever that does
    /// is `acme-proxy admin session revoke --all`.
    pub require_mfa: bool,
    /// Largest admin request body -- a small JSON object or a form.
    pub max_body_bytes: usize,
    /// Ceiling on `?limit=` for the list endpoints.
    pub page_size_max: i64,
    /// Override individual page templates on disk, mirroring
    /// `notify.template_dir`. Empty means the compiled-in defaults.
    pub template_dir: String,
    pub tls: AdminTlsConfig,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1:3001".to_string(),
            base_url: "http://localhost:3001".to_string(),
            session_ttl_seconds: 43_200,
            session_idle_timeout_seconds: 3_600,
            login_max_attempts: 5,
            login_window_seconds: 300,
            require_mfa: false,
            max_body_bytes: 64 * 1024,
            page_size_max: 200,
            template_dir: String::new(),
            tls: AdminTlsConfig::default(),
        }
    }
}
/// HTTPS termination for the admin listener.
///
/// Same shape and same one-listener-not-two semantics as [`TlsConfig`], with
/// its own certificate paths so the two listeners cannot be made to share one
/// by accident. A separate type rather than a reuse of `TlsConfig` because the
/// defaults differ and `config.toml.example` documents each key against its
/// own default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdminTlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub handshake_timeout_ms: u64,
}

impl Default for AdminTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: "admin.pem".to_string(),
            key_path: "admin.key".to_string(),
            handshake_timeout_ms: 10_000,
        }
    }
}
/// Nonce expiration and validation configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NonceConfig {
    pub ttl_seconds: u64,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self { ttl_seconds: 300 }
    }
}
/// Logging and tracing configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub filter: String,
    pub json_format: bool,
    /// Where records are written: `stdout` or `stderr`. Anything else is a
    /// startup error.
    ///
    /// `stdout` is the default and is load-bearing beyond taste: the end-to-end
    /// suite gates container readiness on `server_startup` appearing there.
    pub target: String,
    /// ANSI colour in the human-readable format. Ignored under `json_format`.
    pub ansi: bool,
    /// Span lifecycle records: `none`, `close` or `full`. `close` is the useful
    /// one — it emits a record per span as it closes, carrying the time spent
    /// busy and idle inside it.
    pub span_events: String,
    /// JSON only: lift a record's own fields to the top level instead of
    /// nesting them under `fields`. What most log pipelines want, but it can
    /// collide with the format's reserved keys, so it is not the default.
    pub flatten_event: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter: "acme_proxy=info".to_string(),
            json_format: false,
            target: "stdout".to_string(),
            ansi: true,
            span_events: "none".to_string(),
            flatten_event: false,
        }
    }
}
/// Order object configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OrderConfig {
    pub validity_seconds: u64,
}

impl Default for OrderConfig {
    fn default() -> Self {
        Self {
            validity_seconds: 604800,
        }
    }
}
/// The optional `meta` members of the directory object (RFC 8555 §7.1.1).
///
/// All empty by default, and an empty field is omitted rather than sent blank:
/// §7.1.1 makes every one optional, and advertising `"website": ""` says less
/// than saying nothing.
///
/// `terms_of_service` is the one with teeth. Setting it turns on §7.3.3's
/// agreement requirement — `newAccount` then refuses a request that does not
/// carry `termsOfServiceAgreed: true` — so it is not merely cosmetic, and
/// leaving it unset (the default) keeps today's behaviour exactly.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct MetaConfig {
    /// A URL identifying the current terms of service.
    pub terms_of_service: String,
    /// An HTTP or HTTPS URL locating a website providing more information
    /// about the ACME server.
    pub website: String,
    /// The hostnames this CA recognizes in CAA records (RFC 8555 §7.1.1).
    /// Advertised only; this server does not itself check CAA.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub caa_identities: Vec<String>,
}
