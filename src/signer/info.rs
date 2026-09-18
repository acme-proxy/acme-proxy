//! The read side of a signer: what a backend publishes, built from public
//! material only.
//!
//! [`SignerBackend`](super::SignerBackend) is the half that signs, revokes and
//! keeps a CRL signed — the half that needs `ca.key`, a PKCS#11 login or a
//! relay's upstream account. [`SignerInfo`] is everything else a request asks
//! of the backend: its CRL as last stored, its trust anchor, its opinion on
//! when to renew, the `http-01` tokens it publishes, and where a revocation
//! goes. None of those needs a key, so every role builds one, and only the
//! `worker` role builds the backend. That split is what lets the process
//! parsing untrusted JWS and CSRs run without read access to the CA key.
//!
//! Two constructors, one type each. [`info_from_config`] is the production
//! path in every topology — all-in-one included, so the read side a split
//! deployment serves is the one every deployment serves.
//! [`SignerBackend::info`](super::SignerBackend::info) derives the same type
//! from a built backend, for the suites whose backend exists only in memory;
//! `info_from_config_agrees_with_the_backends_own_info` pins the two together.

use std::sync::Arc;

use async_trait::async_trait;

use super::{
    Http01TokenStore, RenewalWindow, RevocationRoute, SignerError, SignerParts, custom, local_ca,
    relay,
};
use crate::config::SignerConfig;

/// What a request may ask of a signer backend without holding its key.
#[async_trait]
pub trait SignerInfo: Send + Sync {
    /// The backend's current certificate revocation list (RFC 5280), DER
    /// encoded, if it maintains one servable here. `Ok(None)` means the backend
    /// has no CRL of its own (e.g. a delegating backend whose CRL is only
    /// ever published by the upstream CA it defers to, at a URL of the
    /// upstream's choosing).
    ///
    /// An `Err` is a CRL that exists but could not be read — `local_ca`'s
    /// database being unreachable, or no worker having stored the first one
    /// yet — which `GET /crl` answers with a 500 rather than the 404 that would
    /// tell a relying party there is no CRL at all.
    async fn crl_der(&self) -> Result<Option<Vec<u8>>, SignerError> {
        Ok(None)
    }

    /// The certificates a client needs to trust what this backend issues, PEM
    /// encoded, anchor last — served unauthenticated at `GET /ca.pem`.
    ///
    /// `None` means the backend has no trust anchor of its own to hand out, and
    /// the route answers `404`. That is the honest answer for both delegating
    /// backends: [`relay`]'s anchor belongs to the upstream CA and is published
    /// wherever that CA chooses, and a `custom` script's is wherever its
    /// operator put it. Only a local CA answers, which is also the only backend
    /// that generates an anchor nothing else knows about — the case where
    /// "fetch it over HTTP" is the difference between one `curl` and finding a
    /// file on the server's disk.
    async fn ca_chain_pem(&self) -> Option<String> {
        None
    }

    /// The backend's opinion on when `cert_der` should be renewed (ACME
    /// Renewal Information, RFC 9773) — the same [`RenewalWindow`]
    /// `calculate_suggested_window` produces, so the handler can use either
    /// interchangeably.
    ///
    /// `Ok(None)` — the default, which a local CA keeps — means "no opinion,
    /// compute it locally". Only a backend delegating to an upstream CA that
    /// publishes its own ARI has anything better to say.
    async fn renewal_info(&self, _cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        Ok(None)
    }

    /// The `http-01` token store this backend answers the *upstream's* own
    /// challenge from, if it has one.
    ///
    /// [`crate::router::build_app`] mounts `GET
    /// /.well-known/acme-challenge/{token}` on the root router when any
    /// profile's backend returns `Some`, and not at all otherwise — the same "a
    /// backend that has something to publish over HTTP says so" shape as
    /// [`crl_der`](SignerInfo::crl_der). Only [`relay`] with
    /// `challenge_strategy = "http01"` answers.
    fn http01_tokens(&self) -> Option<Arc<dyn Http01TokenStore>> {
        None
    }

    /// Where a revocation of a certificate this backend issued goes, decided
    /// without the backend: a row in the local CA's ledger, or a job for the
    /// process that holds the backend.
    fn revocation_route(&self) -> RevocationRoute;
}

/// A backend with nothing to publish — what
/// [`SignerBackend::info`](super::SignerBackend::info) answers for a backend
/// that does not say otherwise.
///
/// Its revocations are [`RevocationRoute::Delegated`], since without a ledger
/// of its own the only thing that can revoke is the backend itself.
pub struct Opaque;

impl SignerInfo for Opaque {
    fn revocation_route(&self) -> RevocationRoute {
        RevocationRoute::Delegated
    }
}

/// Builds the read side of the configured backend, from public material only.
///
/// A local CA reads `cert_path` and nothing else — never `key_path`, never a
/// token. A missing certificate is refused by name: a process that does not
/// run the `worker` role never generates one, so the fix is `acme-proxy init`
/// or starting the worker first.
pub fn info_from_config(
    cfg: &SignerConfig,
    parts: &SignerParts,
) -> anyhow::Result<Arc<dyn SignerInfo>> {
    match cfg.backend.as_str() {
        "local_ca" => Ok(Arc::new(local_ca::LocalCaInfo::load(
            &cfg.local_ca,
            parts.database.clone(),
        )?)),
        "relay" => Ok(Arc::new(relay::RelayInfo::from_config(&cfg.relay, parts)?)),
        "custom" => Ok(Arc::new(custom::CustomScriptInfo::from_config(
            &cfg.custom,
        )?)),
        // Refused the way `from_config` refuses them, so a process that builds
        // no backend still says what is wrong with the configuration.
        other => Err(super::unknown_backend(other)),
    }
}
