//! `[signer]` and everything under it: the three backends, the local CA's key
//! sources, and the relaying backend's upstream.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use serde::Deserialize;

use super::empty_string_is_no_values;

/// Certificate-issuance signer configuration.
///
/// All three backends' tables are always present, whichever `backend` names —
/// the unselected ones are simply never read, exactly as `local_ca`'s keys
/// have always been parsed even when unused.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SignerConfig {
    pub backend: String,
    pub local_ca: LocalCaConfig,
    pub acme_proxy: AcmeProxyConfig,
    pub custom: CustomSignerConfig,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            backend: "local_ca".to_string(),
            local_ca: LocalCaConfig::default(),
            acme_proxy: AcmeProxyConfig::default(),
            custom: CustomSignerConfig::default(),
        }
    }
}
/// Configuration for the `custom` signer backend: issuance/revocation
/// delegated to an external script (see [`crate::signer::custom`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CustomSignerConfig {
    pub script_path: String,
    pub timeout_ms: u64,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub args: Vec<String>,
    /// Whether the script answers the `crl` hook (`GET /crl`). Off by
    /// default: an unset script has nothing useful to say here, and the
    /// trait's own default (`None`, "no CRL of my own to publish") already
    /// covers that — same reasoning as `supports_renewal_info` below.
    pub supports_crl: bool,
    /// Whether the script answers the `renewal_info` hook (RFC 9773). Off by
    /// default: the trait's own default (`Ok(None)`, "no opinion") already
    /// falls back to this server's local ARI estimate, which is normal and
    /// expected for a backend with nothing better to say.
    pub supports_renewal_info: bool,
}

impl Default for CustomSignerConfig {
    fn default() -> Self {
        Self {
            script_path: String::new(),
            timeout_ms: 5000,
            args: Vec::new(),
            supports_crl: false,
            supports_renewal_info: false,
        }
    }
}
/// Configuration for the `acme_proxy` signer backend: this server relaying
/// issuance to a real upstream ACME server, of which it becomes a client.
///
/// The upstream account itself is provisioned once — either via `eab` below,
/// or out of band via `acme-proxy upstream register` — and only the account
/// key and the `kid` registration yields persist afterwards; see
/// [`AcmeProxyEabConfig`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeProxyConfig {
    /// The upstream ACME server's directory URL.
    pub directory_url: String,
    /// This proxy's own account key at the upstream, generated (P-256) if the
    /// file is absent. The `kid` the upstream assigns is stored beside it, in
    /// the same path with its extension replaced by `.kid`.
    pub account_key_path: String,
    /// Optional contacts sent with `newAccount`.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub contact: Vec<String>,
    /// How this proxy satisfies the upstream's own domain-control checks:
    /// `bypass` (the upstream validates nothing — a private CA, or another
    /// acme-proxy with `challenge.bypass`) or `dns01` (publish the TXT record
    /// the upstream asks for, which is what a public CA requires).
    pub challenge_strategy: String,
    /// How often to poll an upstream order/authorization while it resolves.
    pub poll_interval_ms: u64,
    /// Total budget for one upstream issuance, after which the local order is
    /// marked `invalid` rather than left processing forever.
    pub poll_timeout_secs: u64,
    pub dns01: Dns01Config,
    pub eab: AcmeProxyEabConfig,
}

impl Default for AcmeProxyConfig {
    fn default() -> Self {
        Self {
            directory_url: String::new(),
            account_key_path: "upstream_account.key".to_string(),
            contact: Vec::new(),
            challenge_strategy: "bypass".to_string(),
            poll_interval_ms: 2000,
            poll_timeout_secs: 300,
            dns01: Dns01Config::default(),
            eab: AcmeProxyEabConfig::default(),
        }
    }
}
/// This proxy's own upstream External Account Binding credential (RFC 8555
/// §7.3.4), as an alternative to `acme-proxy upstream register --eab-kid
/// <kid>`.
///
/// Both are the *same* one-shot credential: it authorizes exactly one
/// `newAccount` call and is useless afterwards — registration itself only
/// ever runs once, guarded by the `.kid` sidecar next to `account_key_path`
/// (see [`AcmeProxyConfig`]). Putting it here trades away the property that
/// made `acme-proxy upstream register` the only path (a bootstrap secret
/// living in configuration for the life of the server) for the convenience
/// of not needing a separate imperative step — useful when `config.toml` is
/// already populated by a secrets manager or a templated deployment. Once
/// registration succeeds, `serve` logs a
/// `signer_acme_proxy_eab_secret_in_config` warning on **every** startup for
/// as long as `hmac_key` stays non-empty, the same "stays visible for as long
/// as it lasts" treatment `challenge.bypass` and
/// `filter.netbox.insecure_skip_verify` get — the fix is to blank it out
/// (`acme-proxy upstream show` confirms the `kid` is already stored).
///
/// Leaving both fields empty (the default) is unchanged from before this
/// existed: `serve` then requires `acme-proxy upstream register` if the
/// upstream demands EAB.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AcmeProxyEabConfig {
    /// The EAB key id the upstream's operator issued. Empty means "no
    /// config-file credential".
    pub kid: String,
    /// SENSITIVE — prefer the environment variable to a file on disk, like
    /// every other secret in this file. Base64: url-safe, unpadded url-safe,
    /// or standard (the same three forms `acme-proxy upstream register`
    /// accepts) — a value that decodes as none of them is a startup error.
    pub hmac_key: String,
}
/// Which DNS provider the `dns01` challenge strategy writes through.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Dns01Config {
    pub provider: String,
    pub rfc2136: Rfc2136Config,
}

impl Default for Dns01Config {
    fn default() -> Self {
        Self {
            provider: "rfc2136".to_string(),
            rfc2136: Rfc2136Config::default(),
        }
    }
}
/// RFC 2136 dynamic DNS update, authenticated with TSIG.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Rfc2136Config {
    /// `host:port` of the authoritative server accepting the update.
    pub server: String,
    /// The zone to update, e.g. `example.org.`.
    pub zone: String,
    pub tsig_key_name: String,
    /// Base64 TSIG secret. Unlike the EAB secret this *is* long-lived — every
    /// update needs it — so it legitimately lives in configuration; prefer the
    /// environment variable over a file on disk.
    pub tsig_key_secret: String,
    pub tsig_algorithm: String,
}
/// Configuration for the persistent local-CA signer backend.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LocalCaConfig {
    pub cert_path: String,
    pub key_path: String,
    pub key_type: String,
    pub leaf_validity_days: u64,
    pub crl_path: String,
    /// Overrides for the autogenerated CA's own X.509 Subject. Read only
    /// when the CA is generated (no existing `cert_path`/`key_path`) — an
    /// already-on-disk CA's Subject is whatever it already has, re-signing
    /// nothing.
    pub subject: LocalCaSubjectConfig,
    /// Where the issuing private key lives: `"file"` (the default, and the
    /// only behaviour that existed before this key) or `"pkcs11"`.
    ///
    /// A selector string rather than a `pkcs11.enabled` flag, matching
    /// `signer.backend` and `signer.acme_proxy.challenge_strategy`: it makes
    /// "both configured" unrepresentable instead of a precedence rule.
    pub key_source: String,
    /// The token to sign with when `key_source = "pkcs11"`. Ignored
    /// otherwise — `Config` cannot tell an unset table from a defaulted one,
    /// so validation lives in `LocalCa::load_or_generate`, where the selector
    /// that makes these fields required is also in scope.
    pub pkcs11: Pkcs11Config,
}

impl Default for LocalCaConfig {
    fn default() -> Self {
        Self {
            cert_path: "ca.pem".to_string(),
            key_path: "ca.key".to_string(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: "ca.crl".to_string(),
            subject: LocalCaSubjectConfig::default(),
            key_source: "file".to_string(),
            pkcs11: Pkcs11Config::default(),
        }
    }
}
/// A PKCS#11 token holding the local CA's issuing key
/// (`signer.local_ca.key_source = "pkcs11"`, requires `--features hsm`).
///
/// The private key never leaves the token: this server sends it the bytes to
/// be signed and gets a signature back. Consequently the CA is **never
/// generated** in this mode — `cert_path` must already hold a certificate for
/// the token's key, and `key_path` is not read or written at all.
/// Every field defaults to "unset" — unlike its neighbours, none of these has
/// a useful compiled-in value, so the `Default` is derived rather than written
/// out. Which of them are *required* depends on `key_source`, and is checked in
/// `LocalCa::load_or_generate` where that selector is in scope.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Pkcs11Config {
    /// The PKCS#11 module to `dlopen`, e.g. `/usr/lib/softhsm/libsofthsm2.so`
    /// or `/usr/lib/libykcs11.so`. Required once `key_source = "pkcs11"`.
    pub module_path: String,
    /// The token to use, by its label. Preferred over `slot_id`, which is not
    /// stable across reboots or re-plugs on most drivers.
    pub token_label: String,
    /// The slot to use, when the token carries no usable label. Consulted
    /// only if `token_label` is empty.
    pub slot_id: Option<u64>,
    /// `CKA_LABEL` of the private key. Required once `key_source = "pkcs11"`.
    /// Note that on a YubiKey the labels are fixed by `libykcs11` (slot 9c is
    /// `"Private key for Digital Signature"`), so this is looked up, not
    /// chosen.
    pub key_label: String,
    /// `CKA_ID` as hex, to disambiguate a token carrying several keys under
    /// one label. Optional; empty means "match on the label alone".
    pub key_id: String,
    /// The user PIN. **Secret** — prefer `pin_file`, or the
    /// `ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__PIN` environment variable, over
    /// writing it here.
    pub pin: String,
    /// A file holding the user PIN, trailing whitespace trimmed. Wins over
    /// `pin` when both are set.
    pub pin_file: String,
}
/// Overrides for the autogenerated Local CA's X.509 Subject (Distinguished
/// Name). Every field is optional and, when unset (or set to an empty
/// string — the `config` crate cannot tell an env var explicitly set empty
/// from one that's absent), is simply omitted from the Subject — except
/// `common_name`, which falls back to `"acme-proxy local CA"` so the CA
/// always carries one.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LocalCaSubjectConfig {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}
