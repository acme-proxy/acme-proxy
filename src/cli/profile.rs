//! `profile list` — the ACME endpoints this configuration mounts.
//!
//! The terminal's half of `GET /api/profiles`. Both render
//! [`crate::admin::render_profile_json`], and they reach it from opposite
//! directions: the API describes a **mounted** [`crate::Profile`], where this
//! describes what the configuration on disk *would* mount.
//!
//! That difference is deliberate rather than a shortcut. Building the real
//! thing means `Profile::build_all`, which constructs every signer backend —
//! generating a CA key that does not exist yet, and contacting a relay's
//! upstream — which is not a price a read-only listing should make an operator
//! pay. `filter show` already draws the same line, and it cuts both ways: the
//! panel is right about what is running, and this is the only one of the two
//! that can be pointed at a configuration the server would refuse to start on.

use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, ProfileSummary};
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::config::Config;

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List the ACME endpoints this configuration mounts, name-sorted.
    List {
        #[arg(long)]
        json: bool,
    },
}

pub async fn run_profile_command(
    command: ProfileCommand,
    palette: Palette,
    config: &Arc<Config>,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::List { json } => {
            // The same call `serve` makes, so every startup refusal reaches an
            // operator here too -- `filter show`'s reason for building rather
            // than reading back. `resolve_profiles` has already dropped anything
            // `enabled = false`, so there is no filter here: the list is the
            // mounted set.
            let resolved = config
                .resolve_profiles()
                .map_err(|error| CliError(format!("configuration error: {error}")))?;

            let profiles: Vec<ProfileSummary> = resolved
                .iter()
                .map(|profile| ProfileSummary::configured(&config.server.base_url, profile))
                .collect();

            // Not `print_page`: this is a list an operator writes by hand in one
            // file, so it has no page and nothing to report a total against --
            // the argument the three paged listings had outgrown and this one
            // has not.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ENV_LOCK;

    /// Loads a `Config` the way the server does, so `resolve_profiles` has the
    /// raw sources per-key inheritance needs — `cli::upstream`'s helper, and
    /// for its reason.
    fn config_from(body: &str) -> Arc<Config> {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = crate::testutil::TempDir::new("profile");
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
        for json in [false, true] {
            run_profile_command(ProfileCommand::List { json }, Palette::plain(), &config)
                .await
                .unwrap();
        }

        let empty = Arc::new(Config::default());
        let error = run_profile_command(
            ProfileCommand::List { json: false },
            Palette::plain(),
            &empty,
        )
        .await
        .expect_err("a configuration mounting nothing is not a listing of nothing");
        assert!(
            error.to_string().starts_with("configuration error: "),
            "{error}"
        );
    }
}
