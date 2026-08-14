//! Provisioning this proxy's own account at the upstream ACME server.
//!
//! Split from the backend itself because it is the one part with a lifecycle of
//! its own: it runs once — at first startup, or from
//! `acme-proxy upstream register` — and everything afterwards only ever *uses*
//! the `kid` it produced. The `kid` lives in a sidecar file beside the account
//! key, which is what makes only the first startup contact the upstream at all.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use tracing::{info, warn};

use crate::config::RelayConfig;

use super::client::{AccountKey, AcmeClient, Signer, UpstreamError};
use super::eab;

pub(super) fn kid_path(account_key_path: &str) -> PathBuf {
    Path::new(account_key_path).with_extension("kid")
}

pub(super) async fn provision(
    cfg: &RelayConfig,
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
    timeout: Duration,
) -> anyhow::Result<(AcmeClient, AccountKey, String)> {
    let account = load_or_generate_key(&cfg.account_key_path)?;
    let client = AcmeClient::discover(&cfg.directory_url, resolver, timeout).await?;

    if let Some(kid) = stored_kid(cfg) {
        info!(event = "upstream_account_loaded", outcome = "success", kid = %kid);
        warn_if_eab_secret_still_configured(cfg, &kid);
        return Ok((client, account, kid));
    }

    // No `kid` on disk: self-register, with whatever credential
    // `signer.relay.eab` supplies (possibly none).
    let config_eab = configured_eab(cfg)?;
    let kid = match register(
        &client,
        &account,
        cfg,
        config_eab
            .as_ref()
            .map(|(kid, secret)| (kid.as_str(), secret.as_slice())),
    )
    .await
    {
        Ok(kid) => kid,
        Err(error) if error.is_external_account_required() => {
            if config_eab.is_some() {
                anyhow::bail!(
                    "the upstream rejected signer.relay.eab as External Account Binding \
                     (a wrong kid/hmac_key, or a credential that has already been consumed). Fix \
                     the configured credential, or clear it and run \
                     `acme-proxy upstream register --eab-kid <kid>` once instead."
                );
            }
            anyhow::bail!(
                "the upstream requires External Account Binding. Set signer.relay.eab.kid \
                 and signer.relay.eab.hmac_key in configuration, or run \
                 `acme-proxy upstream register --eab-kid <kid>` once, then start the server again."
            );
        }
        Err(error) => return Err(error.into()),
    };

    write_kid(cfg, &kid)?;
    info!(event = "upstream_account_registered", outcome = "success", kid = %kid);
    warn_if_eab_secret_still_configured(cfg, &kid);
    Ok((client, account, kid))
}

/// Validates and decodes `cfg.eab`, the config-file alternative to
/// `acme-proxy upstream register`'s `--eab-kid`/stdin secret.
///
/// `Ok(None)` means no credential is configured (both fields empty) — the
/// only state this crate supported before `signer.relay.eab` existed.
/// Either field set without the other, or a `hmac_key` that isn't valid
/// base64, is a startup error: a half-supplied credential is a configuration
/// mistake, not something worth silently ignoring or silently treating as
/// "none".
fn configured_eab(cfg: &RelayConfig) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    let kid = cfg.eab.kid.as_str();
    let hmac_key = cfg.eab.hmac_key.as_str();
    match (kid.is_empty(), hmac_key.is_empty()) {
        (true, true) => Ok(None),
        (false, true) => {
            anyhow::bail!("signer.relay.eab.kid is set but signer.relay.eab.hmac_key is not")
        }
        (true, false) => {
            anyhow::bail!("signer.relay.eab.hmac_key is set but signer.relay.eab.kid is not")
        }
        (false, false) => {
            let secret = eab::decode_secret(hmac_key)
                .ok_or_else(|| anyhow::anyhow!("signer.relay.eab.hmac_key is not valid base64"))?;
            Ok(Some((kid.to_string(), secret)))
        }
    }
}

/// The credential in `signer.relay.eab.hmac_key` is only ever needed for
/// the *first* registration; once the `kid` sidecar exists it does nothing
/// but sit on disk as a live secret. Logged unconditionally, every startup,
/// for as long as it stays set — the same "stays visible for as long as it
/// lasts" treatment as `challenge_validation_bypassed` and
/// `filter_netbox_tls_verification_disabled`, since this is equally a
/// temporary operational state the operator is expected to clean up.
fn warn_if_eab_secret_still_configured(cfg: &RelayConfig, kid: &str) {
    if !cfg.eab.hmac_key.is_empty() {
        warn!(
            event = "signer_relay_eab_secret_in_config",
            outcome = "advisory",
            kid = %kid,
            "signer.relay.eab.hmac_key is set but this proxy is already registered \
             upstream; the credential is no longer needed and does nothing now except sit on \
             disk as a live secret — clear signer.relay.eab.hmac_key from configuration"
        );
    }
}

/// The `kid` this server previously registered, if any.
pub fn stored_kid(cfg: &RelayConfig) -> Option<String> {
    std::fs::read_to_string(kid_path(&cfg.account_key_path))
        .ok()
        .map(|kid| kid.trim().to_string())
        .filter(|kid| !kid.is_empty())
}

fn write_kid(cfg: &RelayConfig, kid: &str) -> anyhow::Result<()> {
    // `0600`, matching the account key it sits beside. The `kid` is an account
    // URL rather than a secret, but it identifies this server's account at a
    // public CA and there is no reason for it to be the one world-readable file
    // in that directory. Atomic for the same reason the CA's ledger is: a
    // truncated sidecar reads as "never registered" and sends the next startup
    // to `newAccount` again.
    crate::pemfile::write_atomic(&kid_path(&cfg.account_key_path), kid.as_bytes(), 0o600)?;
    Ok(())
}

/// Sends `newAccount`, optionally carrying an External Account Binding, and
/// returns the account URL (`kid`) the upstream assigns.
///
/// `newAccount` is find-or-create (RFC 8555 §7.3), so running this again for a
/// key the upstream already knows returns the same account rather than making
/// a second one — which is what makes re-registering after losing the sidecar
/// safe.
pub(super) async fn register(
    client: &AcmeClient,
    account: &AccountKey,
    cfg: &RelayConfig,
    eab: Option<(&str, &[u8])>,
) -> Result<String, UpstreamError> {
    let new_account_url = client.directory().new_account.clone();

    let mut payload = json!({ "termsOfServiceAgreed": true });
    if !cfg.contact.is_empty() {
        payload["contact"] = json!(cfg.contact);
    }
    if let Some((kid, secret)) = eab {
        // The binding is over this account's own key and this exact URL, so it
        // cannot be replayed for another key or another endpoint.
        payload["externalAccountBinding"] =
            serde_json::to_value(eab::build(kid, secret, &account.jwk(), &new_account_url))
                .map_err(|error| UpstreamError::Jws(error.to_string()))?;
    }

    let response = client
        .post(account, &Signer::Jwk, &new_account_url, Some(&payload))
        .await?;

    response.location.clone().ok_or_else(|| {
        UpstreamError::Protocol("newAccount succeeded but returned no Location header".to_string())
    })
}

/// Registers this server's upstream account once, from the admin CLI, and
/// persists the resulting `kid`.
///
/// This is the only path that ever sees an EAB secret, and it borrows it —
/// nothing here writes it anywhere. See [`crate::cli::upstream`] for why that
/// matters.
/// `resolver` is the process-wide one when called from `serve`; the CLI builds
/// a throwaway from the same configuration, since it is a one-shot command with
/// no server around it to share.
pub async fn register_upstream_account(
    cfg: &RelayConfig,
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
    eab: Option<(&str, &[u8])>,
) -> anyhow::Result<String> {
    let account = load_or_generate_key(&cfg.account_key_path)?;
    let client = AcmeClient::discover(
        &cfg.directory_url,
        resolver,
        Duration::from_secs(cfg.poll_timeout_secs),
    )
    .await?;

    let kid = register(&client, &account, cfg, eab).await?;
    write_kid(cfg, &kid)?;
    // Distinct from the `serve`-path event of the same shape above: this one
    // says an operator ran `upstream register` deliberately, which is the only
    // way a bootstrap EAB secret never touches configuration.
    info!(event = "upstream_account_registered_by_cli", outcome = "success", kid = %kid);
    Ok(kid)
}

/// Reads the PKCS#8 account key, generating and writing a P-256 one if absent
/// — the same load-or-generate shape as `LocalCa::load_or_generate`, and the
/// same `0600`-from-creation guarantee via [`crate::pemfile::write_private_key`].
pub(super) fn load_or_generate_key(path: &str) -> anyhow::Result<AccountKey> {
    let path = Path::new(path);
    if path.exists() {
        crate::pemfile::warn_if_key_is_readable("upstream_account_key_permissive", path);
        let key = crate::pemfile::read_private_key(path)?;
        return Ok(AccountKey::from_pkcs8(key.secret_der())?);
    }

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    crate::pemfile::write_private_key(path, &key_pair.serialize_pem())?;
    info!(event = "upstream_account_key_generated", outcome = "success", file_path = ?path);
    Ok(AccountKey::from_pkcs8(&key_pair.serialize_der())?)
}
