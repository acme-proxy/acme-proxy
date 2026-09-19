//! `[challenge]` — which challenge types an authorization offers, and how each
//! one is validated.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::string_list;

/// Challenge configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ChallengeConfig {
    #[serde(deserialize_with = "string_list")]
    pub enabled: Vec<String>,
    /// Skip domain-control validation entirely: a triggered challenge is marked
    /// `valid` with no network check.
    ///
    /// Defaults to `false`. It defaulted to `true` — convenient for development,
    /// but it meant a server started with no configuration at all, bound to
    /// `[::]:3000` on every interface, would issue a certificate for **any**
    /// name to **anyone** who could reach the port, since `filter.enabled` is
    /// empty by default too. A certificate authority's safe direction is to
    /// prove control; the convenience of not proving it is worth having, but
    /// worth having to ask for.
    pub bypass: bool,
    pub timeout_ms: u64,
    /// How many of one account's challenges may be validating at once.
    ///
    /// A validation is queued work that reaches out to an address the client
    /// named, and one account can queue as many as it can create orders. The
    /// cap keeps one busy — or hostile — account from filling the runner with
    /// outbound probes while signings, revocations and CRLs wait behind them.
    /// A trigger over the cap is answered `429 rateLimited` with a
    /// `Retry-After`, and the challenge stays `pending`, so the client retries
    /// rather than losing the order.
    ///
    /// `0` is no limit.
    pub max_in_flight_per_account: u32,
    pub http_01: Http01Config,
    pub tls_alpn_01: TlsAlpnConfig,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: vec!["http-01".to_string()],
            bypass: false,
            timeout_ms: 5000,
            max_in_flight_per_account: 32,
            http_01: Http01Config::default(),
            tls_alpn_01: TlsAlpnConfig::default(),
        }
    }
}
/// Configuration for the `http-01` challenge.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Http01Config {
    pub port: u16,
    pub https_port: u16,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub max_response_bytes: usize,
}

impl Default for Http01Config {
    fn default() -> Self {
        Self {
            port: 80,
            https_port: 443,
            follow_redirects: true,
            max_redirects: 5,
            max_response_bytes: 4096,
        }
    }
}
/// Configuration for the `tls-alpn-01` challenge.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsAlpnConfig {
    pub port: u16,
}

impl Default for TlsAlpnConfig {
    fn default() -> Self {
        Self { port: 443 }
    }
}
