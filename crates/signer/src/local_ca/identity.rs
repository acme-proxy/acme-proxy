//! Which CA a `local_ca` profile issues from, checked against the database.
//!
//! A worker's CA is files on its own host — or a token attached to it — and
//! [`LocalCa::load_or_generate`](super::LocalCa::load_or_generate) makes a new
//! one when `ca.key` is missing. With one worker that is the first-run
//! convenience it was written as. With a second worker over the same database
//! it is a silent fork: a host started without the copied key files mints a
//! CA of its own, and the profile then issues from two CAs, each trusted by
//! only the clients that installed it and each revoking into its own CRL.
//!
//! So the database records each profile's issuer (`profile_issuers`, keyed by
//! the CA certificate's SPKI hash — the `issuer` that `revocations` and `crls`
//! use), and a worker runs [`check_issuers`] **before** it builds its backends
//! and again after:
//!
//! - **Before**, a profile with an issuer recorded and no certificate on disk
//!   is refused rather than generated, and one whose certificate hashes to
//!   another issuer is refused rather than loaded.
//! - **After**, the CA a first run just generated is recorded. The first
//!   recording is insert-if-absent, so two workers starting at once with
//!   different CAs cannot both win: the loser reads the winner back and
//!   refuses.
//!
//! A deployment upgraded from before the table existed records whatever CA
//! its first worker loads, silently. A deliberate change of CA is
//! `acme-proxy profile issuer accept <profile>`; nothing changes the record
//! implicitly. `relay` and `custom` profiles hold no CA here and are skipped.

use std::path::Path;

use tracing::{error, info};

use acme_proxy_core::config::ProfileConfig;
use acme_proxy_store::db::Database;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::profile_issuer::ProfileIssuer;

/// Checks every `local_ca` profile's CA against the issuer recorded for it,
/// recording the issuer of any profile that has none yet.
///
/// # Errors
///
/// A profile whose CA is not the recorded one, or that has an issuer recorded
/// and no CA certificate to load, or a database failure.
pub async fn check_issuers(resolved: &[ProfileConfig], database: &Database) -> anyhow::Result<()> {
    for profile in resolved {
        let signer = &profile.sections.signer;
        if signer.backend != "local_ca" {
            continue;
        }
        check_one(&profile.name, &signer.local_ca.cert_path, database).await?;
    }
    Ok(())
}

async fn check_one(profile: &str, cert_path: &str, database: &Database) -> anyhow::Result<()> {
    if !Path::new(cert_path).exists() {
        // Nothing to compare yet. Fine on a first run — the backend about to
        // be built generates the CA, and the second pass records it — and a
        // second CA in the making when the deployment already has one.
        let Some(recorded) = ProfileIssuer::find(profile, database).await? else {
            return Ok(());
        };
        error!(event = "local_ca_issuer_missing",
               outcome = "failure",
               profile = %profile,
               cert_path = %cert_path,
               issuer = %recorded.issuer);
        anyhow::bail!(
            "profile `{profile}`: there is no CA certificate at `{cert_path}`, but this \
             deployment already issues from CA {issuer}. Copy that CA's certificate and key \
             here from an existing worker (or attach its token) rather than letting this \
             worker generate a second CA.",
            issuer = recorded.issuer,
        );
    }

    let actual = super::issuer_id_of(&super::read_ca_certificate(cert_path)?)?;
    let recorded = match ProfileIssuer::find(profile, database).await? {
        Some(recorded) => recorded,
        None => {
            let recorded =
                ProfileIssuer::record_if_absent(profile, &actual, now_secs(), database).await?;
            // Unless a twin starting at the same moment won the insert.
            if recorded.issuer == actual {
                info!(event = "local_ca_issuer_recorded",
                      outcome = "success",
                      profile = %profile,
                      issuer = %actual);
            }
            recorded
        }
    };
    if recorded.issuer == actual {
        return Ok(());
    }

    error!(event = "local_ca_issuer_mismatch",
           outcome = "failure",
           profile = %profile,
           cert_path = %cert_path,
           issuer = %actual,
           recorded_issuer = %recorded.issuer);
    anyhow::bail!(
        "profile `{profile}`: the CA at `{cert_path}` (issuer {actual}) is not the one this \
         deployment issues from ({recorded}). Copy the right CA here from an existing worker; \
         if the change of CA is deliberate, run `acme-proxy profile issuer accept {profile}` \
         first.",
        recorded = recorded.issuer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::testutil::TempDir;

    fn profile(name: &str, cert_path: &str) -> ProfileConfig {
        let mut config = ProfileConfig {
            name: name.to_string(),
            sections: Default::default(),
        };
        config.sections.signer.backend = "local_ca".to_string();
        config.sections.signer.local_ca.cert_path = cert_path.to_string();
        config
    }

    fn write_ca(dir: &TempDir, name: &str) -> (String, String) {
        let (_, pem) = super::super::generate_ca("ecdsa-p256", &Default::default()).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, &pem).unwrap();
        let path = path.to_str().unwrap().to_string();
        let issuer = super::super::issuer_id_of(&pem).unwrap();
        (path, issuer)
    }

    #[tokio::test]
    async fn the_first_ca_is_recorded_and_then_required() {
        let database = Database::connect_for_test().await.unwrap();
        let dir = TempDir::new("identity-record");
        let (first, issuer) = write_ca(&dir, "first.pem");
        let (second, _) = write_ca(&dir, "second.pem");

        check_issuers(&[profile("default", &first)], &database)
            .await
            .unwrap();
        assert_eq!(
            ProfileIssuer::find("default", &database)
                .await
                .unwrap()
                .unwrap()
                .issuer,
            issuer
        );
        // Idempotent for the same CA.
        check_issuers(&[profile("default", &first)], &database)
            .await
            .unwrap();

        // Another CA for the same profile is refused, naming the way out.
        let message = check_issuers(&[profile("default", &second)], &database)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("profile issuer accept default"),
            "{message}"
        );
        assert!(message.contains(&issuer), "{message}");

        // Another profile is a record of its own.
        check_issuers(&[profile("other", &second)], &database)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_missing_certificate_is_refused_only_once_an_issuer_is_recorded() {
        let database = Database::connect_for_test().await.unwrap();
        let dir = TempDir::new("identity-missing");
        let absent = dir.join("absent.pem");
        let absent = absent.to_str().unwrap();

        // A first run: nothing recorded, so the CA may be generated.
        check_issuers(&[profile("default", absent)], &database)
            .await
            .unwrap();

        // Once the deployment has a CA, a worker without one refuses.
        let (existing, _) = write_ca(&dir, "existing.pem");
        check_issuers(&[profile("default", &existing)], &database)
            .await
            .unwrap();
        let message = check_issuers(&[profile("default", absent)], &database)
            .await
            .unwrap_err()
            .to_string();
        assert!(message.contains("rather than letting this"), "{message}");
    }

    #[tokio::test]
    async fn other_backends_are_skipped() {
        let database = Database::connect_for_test().await.unwrap();
        let mut relay = profile("relay", "/nonexistent/ca.pem");
        relay.sections.signer.backend = "relay".to_string();
        ProfileIssuer::record_if_absent("relay", &"a".repeat(64), 1, &database)
            .await
            .unwrap();
        check_issuers(&[relay], &database).await.unwrap();
    }
}
