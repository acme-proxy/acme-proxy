//! A local CA's read side: its certificate and the CRL a worker last stored.
//!
//! Everything here is public material. [`LocalCaInfo::load`] reads `cert_path`
//! and nothing else — never `key_path`, never a token — so a process that does
//! not run the `worker` role serves `GET /ca.pem` and `GET /crl`, and records
//! revocations in the ledger, without read access to the key.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::error;

use super::issuer_id_of;
use crate::signer::{RevocationRoute, SignerError, SignerInfo};
use crate::sqlite::crl::StoredCrl;
use crate::sqlite::db::Database;
use acme_proxy_core::config::LocalCaConfig;

/// What a request may ask of a local CA without its key.
pub struct LocalCaInfo {
    /// The CA certificate PEM — the anchor `GET /ca.pem` serves, byte-identical
    /// to what `LocalCa::issue` appends to every chain.
    ca_pem: String,
    /// [`acme_proxy_core::cert::issuer_id`] of that certificate: the key its revocations
    /// and its CRL are stored under.
    issuer: String,
    database: Arc<Database>,
}

impl LocalCaInfo {
    /// Reads the CA certificate at `cfg.cert_path`.
    ///
    /// A missing file is refused by name. Only the `worker` role — or
    /// `acme-proxy init` — ever generates a CA, so a process that finds none
    /// was started before the one that makes it.
    pub fn load(cfg: &LocalCaConfig, database: Arc<Database>) -> anyhow::Result<Self> {
        Self::new(read_ca_certificate(&cfg.cert_path)?, database)
    }

    /// Over a CA certificate already in hand — what `LocalCa::info` builds
    /// from the certificate it loaded or generated.
    pub fn new(ca_pem: String, database: Arc<Database>) -> anyhow::Result<Self> {
        let issuer = issuer_id_of(&ca_pem)?;
        Ok(Self {
            ca_pem,
            issuer,
            database,
        })
    }

    /// The issuer id its revocation state is stored under.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// Reads the CA certificate at `path`, naming the two ways to create one when
/// it is not there.
pub(crate) fn read_ca_certificate(path: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!(
            "cannot read the CA certificate `{path}`: {error} — run `acme-proxy init` with this \
             configuration, or start the `worker` role first, so the CA exists"
        )
    })
}

#[async_trait]
impl SignerInfo for LocalCaInfo {
    /// The stored CRL, read and never signed.
    ///
    /// No stored row is an `Err`, not `Ok(None)`: this CA does keep a CRL, and
    /// a `404` would tell a relying party it has none. The worker stores the
    /// first one on its first pass after startup, so the window is the moment
    /// between a worker starting and its runner's first tick.
    async fn crl_der(&self) -> Result<Option<Vec<u8>>, SignerError> {
        match StoredCrl::find_current(&self.issuer, &self.database).await {
            Ok(Some(crl)) => Ok(Some(crl.der)),
            Ok(None) => {
                error!(
                    event = "local_ca_crl_not_stored",
                    outcome = "failure",
                    issuer = %self.issuer,
                    "no worker has stored this CA's first CRL yet"
                );
                Err(SignerError::Internal(
                    "this CA has no stored CRL yet".to_string(),
                ))
            }
            Err(error) => {
                error!(event = "local_ca_database_query_failed", outcome = "failure", error = %error);
                Err(SignerError::Internal(format!("revocation state: {error}")))
            }
        }
    }

    /// This CA's own certificate — the anchor, and the whole chain, since a
    /// local CA is a single self-signed root with `pathLenConstraint: 0`.
    async fn ca_chain_pem(&self) -> Option<String> {
        Some(self.ca_pem.clone())
    }

    fn revocation_route(&self) -> RevocationRoute {
        RevocationRoute::Ledger {
            issuer: self.issuer.clone(),
        }
    }
}
