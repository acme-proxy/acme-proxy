//! `profile list` — the ACME endpoints this configuration mounts — and
//! `profile issuer accept`, the deliberate change of a profile's CA.
//!
//! The terminal's half of `GET /api/profiles`. Both render
//! [`acme_proxy_admin::admin::render_profile_json`], and they reach it from opposite
//! directions: the API describes a **mounted** [`acme_proxy_protocol::profile::Profile`],
//! where this describes what the configuration on disk *would* mount.
//!
//! That difference is deliberate rather than a shortcut. Building the real
//! thing means `server::profile::build_all`, which constructs every signer backend —
//! generating a CA key that does not exist yet, and contacting a relay's
//! upstream — which is not a price a read-only listing should make an operator
//! pay. `filter show` already draws the same line, and it cuts both ways: the
//! panel is right about what is running, and this is the only one of the two
//! that can be pointed at a configuration the server would refuse to start on.
//!
//! `issuer accept` is the one way to change the issuer the database records
//! for a `local_ca` profile (`profile_issuers`), which every worker compares
//! its CA against before signing — see `acme_proxy_signer::local_ca::identity`.
//! It reads the configured CA *certificate* and nothing else: no key, no
//! backend, so it runs as any uid that can read `ca.pem`.

use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::cli::CliError;
use crate::cli::render;
use acme_proxy_admin::admin;
use acme_proxy_admin::admin::ProfileSummary;
use acme_proxy_core::config::Config;
use acme_proxy_core::palette::Palette;
use acme_proxy_jobs::auditor::admin as audit_admin;
use acme_proxy_store::db::Database;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::profile_issuer::ProfileIssuer;

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List the ACME endpoints this configuration mounts, name-sorted.
    List {
        /// Print it as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The CA a `local_ca` profile issues from, as the database records it.
    Issuer {
        #[command(subcommand)]
        command: IssuerCommand,
    },
}

#[derive(Subcommand)]
pub enum IssuerCommand {
    /// Record the CA the configuration names for a profile as the one it issues
    /// from, replacing the recorded one. Every worker then refuses the old CA.
    Accept {
        /// The profile whose CA changed.
        name: String,
    },
}

pub async fn run_profile_command(
    command: ProfileCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Arc<Config>,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::Issuer {
            command: IssuerCommand::Accept { name },
        } => accept_issuer(&name, yes, palette, reader, config, &database).await?,
        ProfileCommand::List { json } => {
            // The same call `serve` makes, so every startup refusal reaches an
            // operator here too -- `filter show`'s reason for building rather
            // than reading back. `resolve_profiles` has already dropped anything
            // `enabled = false`, so there is no filter here: the list is the
            // mounted set.
            let resolved = config
                .resolve_profiles()
                .map_err(|error| CliError::failed(format!("configuration error: {error}")))?;

            let profiles: Vec<ProfileSummary> = resolved
                .iter()
                .map(|profile| ProfileSummary::configured(&config.server.base_url, profile))
                .collect();

            // Not `print_page`, and the one listing that is not paged: profiles
            // are configuration an operator writes by hand in one file, not rows
            // a table grows, so there is no page and no total to report.
            // `/api/profiles` answers the same bare array.
            if json {
                let rendered: Vec<_> = profiles.iter().map(admin::render_profile_json).collect();
                println!("{}", serde_json::Value::Array(rendered));
            } else {
                for profile in &profiles {
                    println!("{}", render::render_profile_line(profile, palette));
                }
            }
        }
    }
    Ok(())
}

/// `profile issuer accept <name>`.
async fn accept_issuer(
    name: &str,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Config,
    database: &Arc<Database>,
) -> Result<(), CliError> {
    let resolved = config
        .resolve_profiles()
        .map_err(|error| CliError::failed(format!("configuration error: {error}")))?;
    let Some(profile) = resolved.iter().find(|profile| profile.name == name) else {
        return Err(CliError::failed(format!("no profile named `{name}`")));
    };
    let signer = &profile.sections.signer;
    if signer.backend != "local_ca" {
        return Err(CliError::failed(format!(
            "profile `{name}` uses the `{}` signer, which holds no CA here",
            signer.backend
        )));
    }
    let acme_proxy_signer::RevocationRoute::Ledger { issuer } =
        acme_proxy_signer::revocation_route(signer)
            .map_err(|error| CliError::failed(error.to_string()))?
    else {
        // `revocation_route` answers `Ledger` for every `local_ca`; an error
        // rather than a panic if that ever stops being true.
        return Err(CliError::failed(format!(
            "profile `{name}` has a local CA but no revocation ledger"
        )));
    };

    let previous = ProfileIssuer::find(name, database).await?;
    if previous
        .as_ref()
        .is_some_and(|previous| previous.issuer == issuer)
    {
        println!("Profile `{name}` already issues from CA {issuer}.");
        return Ok(());
    }
    let prompt = match &previous {
        Some(previous) => format!(
            "Profile `{name}`: record CA {issuer} (from `{}`) in place of {}? \
             Every worker will then refuse the old CA.",
            signer.local_ca.cert_path, previous.issuer
        ),
        None => format!(
            "Profile `{name}`: record CA {issuer} (from `{}`)?",
            signer.local_ca.cert_path
        ),
    };
    if !admin::confirm(&prompt, yes, reader) {
        println!("Cancelled.");
        return Ok(());
    }

    ProfileIssuer::replace(name, &issuer, now_secs(), database).await?;
    let previous = previous.map(|previous| previous.issuer);
    audit_admin::record_cli_action(database, |actor, client| {
        audit_admin::profile_issuer_accepted(actor, client, name, previous.as_deref(), &issuer)
    })
    .await;
    println!(
        "{}",
        palette.ok(&format!("Profile `{name}` now issues from CA {issuer}."))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::config::ENV_LOCK;

    /// Loads a `Config` the way the server does, so `resolve_profiles` has the
    /// raw sources per-key inheritance needs — `cli::upstream`'s helper, and
    /// for its reason.
    fn config_from(body: &str) -> Arc<Config> {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = acme_proxy_core::testutil::TempDir::new("profile");
        std::fs::write(dir.join("config.toml"), body).unwrap();
        // SAFETY: single-threaded test holding ENV_LOCK; removed before return.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        Arc::new(config)
    }

    /// Name-sorted, `enabled = false` absent, and each summary carrying the
    /// profile's *own* merged sections rather than the global ones.
    #[test]
    fn the_listing_is_the_profiles_this_configuration_would_mount() {
        let config = config_from(
            r#"
            [server]
            base_url = "https://ca.example.com"

            [challenge]
            bypass = false

            [profiles.staging]
            challenge.bypass = true

            [profiles.le]
            eab.enabled = true

            [profiles.parked]
            enabled = false
            "#,
        );

        let resolved = config.resolve_profiles().unwrap();
        let summaries: Vec<ProfileSummary> = resolved
            .iter()
            .map(|profile| ProfileSummary::configured(&config.server.base_url, profile))
            .collect();

        let names: Vec<&str> = summaries.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["le", "staging"], "parked is not mounted");

        let le = &summaries[0];
        assert_eq!(le.base_url, "https://ca.example.com/profile/le");
        assert_eq!(
            le.directory_url(),
            "https://ca.example.com/profile/le/directory"
        );
        assert!(le.eab_enabled);
        // Inherited from the global section, not reverted to the compiled
        // default -- the per-key merge `Config::merged_sections` performs.
        assert!(!le.challenge_bypass);
        assert!(summaries[1].challenge_bypass, "staging overrode it");
    }

    /// Both output shapes run, and a configuration that resolves no profiles is
    /// reported in words rather than printing an empty list -- `resolve_profiles`
    /// refuses it, and this command is meant to surface exactly the startup
    /// refusals `serve` would hit.
    #[tokio::test]
    async fn both_shapes_render_and_a_profileless_configuration_is_refused() {
        let config = config_from("[profiles.default]\n");
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        for json in [false, true] {
            run_profile_command(
                ProfileCommand::List { json },
                true,
                Palette::plain(),
                &mut &b""[..],
                &config,
                database.clone(),
            )
            .await
            .unwrap();
        }

        let empty = Arc::new(Config::default());
        let error = run_profile_command(
            ProfileCommand::List { json: false },
            true,
            Palette::plain(),
            &mut &b""[..],
            &empty,
            database,
        )
        .await
        .expect_err("a configuration mounting nothing is not a listing of nothing");
        assert!(
            error.to_string().starts_with("configuration error: "),
            "{error}"
        );
    }

    fn accept(name: &str) -> ProfileCommand {
        ProfileCommand::Issuer {
            command: IssuerCommand::Accept {
                name: name.to_string(),
            },
        }
    }

    /// A fresh CA at `dir`'s `ca.pem`/`ca.key`, replacing any there, and its
    /// issuer id.
    async fn new_ca(dir: &acme_proxy_core::testutil::TempDir, database: &Arc<Database>) -> String {
        let _ = std::fs::remove_file(dir.join("ca.pem"));
        let _ = std::fs::remove_file(dir.join("ca.key"));
        let local_ca = acme_proxy_core::config::LocalCaConfig {
            cert_path: dir.join("ca.pem").to_str().unwrap().to_string(),
            key_path: dir.join("ca.key").to_str().unwrap().to_string(),
            crl_path: dir.join("ca.crl").to_str().unwrap().to_string(),
            ..Default::default()
        };
        acme_proxy_signer::local_ca::LocalCa::load_or_generate(&local_ca, database.clone())
            .unwrap();
        acme_proxy_signer::local_ca::issuer_id_of(
            &std::fs::read_to_string(dir.join("ca.pem")).unwrap(),
        )
        .unwrap()
    }

    /// The deliberate change of CA: recorded on `--yes` (or a `y`), left alone
    /// on anything else, audited when it lands, and a no-op for the CA already
    /// recorded.
    #[tokio::test]
    async fn issuer_accept_records_the_configured_ca_and_audits_it() {
        let dir = acme_proxy_core::testutil::TempDir::new("profile-issuer");
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = config_from(&format!(
            "[profiles.default]\nsigner.local_ca.cert_path = \"{dir}/ca.pem\"\n\
             [profiles.up]\nsigner.backend = \"relay\"\n",
            dir = dir.path().display()
        ));
        let run = async |command, yes, input: &[u8]| {
            run_profile_command(
                command,
                yes,
                Palette::plain(),
                &mut &input[..],
                &config,
                database.clone(),
            )
            .await
        };

        let first = new_ca(&dir, &database).await;
        run(accept("default"), true, b"").await.unwrap();
        let recorded = ProfileIssuer::find("default", &database).await.unwrap();
        assert_eq!(recorded.unwrap().issuer, first);
        // Again: nothing to change, and nothing asked.
        run(accept("default"), false, b"").await.unwrap();

        // A new CA: declined, then accepted.
        let second = new_ca(&dir, &database).await;
        run(accept("default"), false, b"n\n").await.unwrap();
        let recorded = ProfileIssuer::find("default", &database).await.unwrap();
        assert_eq!(
            recorded.unwrap().issuer,
            first,
            "a declined prompt changes nothing"
        );
        run(accept("default"), false, b"y\n").await.unwrap();
        let recorded = ProfileIssuer::find("default", &database).await.unwrap();
        assert_eq!(recorded.unwrap().issuer, second);

        let (trail, _) = acme_proxy_store::audit::AuditEntry::search(
            &acme_proxy_store::audit::AuditQuery {
                limit: 100,
                ..Default::default()
            },
            &database,
        )
        .await
        .unwrap();
        let accepted: Vec<_> = trail
            .iter()
            .filter(|row| row.event == "profile_issuer_accepted")
            .collect();
        assert_eq!(accepted.len(), 2, "one row per change that landed");
        assert!(
            accepted.iter().any(|row| row
                .detail
                .as_deref()
                .is_some_and(|d| d.contains(&first) && d.contains(&second))),
            "the replacement names both issuers"
        );

        // Refusals by name.
        let error = run(accept("nope"), true, b"").await.unwrap_err();
        assert!(
            error.to_string().contains("no profile named `nope`"),
            "{error}"
        );
        let error = run(accept("up"), true, b"").await.unwrap_err();
        assert!(error.to_string().contains("holds no CA"), "{error}");
    }
}
