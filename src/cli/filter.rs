//! `acme-proxy filter show|explain` — reading the configured access policy.
//!
//! Argument marshalling and profile resolution only; everything printed comes
//! from [`crate::filter::explain`], so the panel could serve the same output
//! later without moving any logic. Why it does not today is recorded there.

use std::net::IpAddr;

use clap::Subcommand;

use super::{CliError, resolve_profile};
use crate::config::Config;
use crate::filter::explain::{
    Subject, explain, explanation_json, render_explanation, render_policy,
};
use crate::sqlite::order::Identifier;

#[derive(Subcommand)]
pub enum FilterCommand {
    /// Print the resolved access policy for a profile.
    Show {
        /// Which endpoint's policy. Optional when exactly one is configured.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Evaluate the policy against a hypothetical request.
    ///
    /// This really runs your `custom` scripts and really queries the
    /// inventory, exactly as a request would. It touches no database and
    /// creates nothing.
    Explain {
        #[arg(long)]
        profile: Option<String>,
        /// The address the request would come from.
        #[arg(long)]
        client_ip: Option<IpAddr>,
        /// A name the request would ask for. Repeatable.
        #[arg(long = "identifier")]
        identifiers: Vec<String>,
        /// The request path, for `path` checks.
        #[arg(long, default_value = "/newOrder")]
        path: String,
        /// The account id the request would come from.
        #[arg(long, default_value = "explain")]
        account_id: String,
        #[arg(long)]
        json: bool,
    },
}

pub async fn run_filter_command(command: FilterCommand, config: &Config) -> Result<(), CliError> {
    match command {
        FilterCommand::Show { profile } => {
            let (name, policy) = build(config, profile.as_deref())?;
            print!("{}", render_policy(&name, &policy));
            Ok(())
        }
        FilterCommand::Explain {
            profile,
            client_ip,
            identifiers,
            path,
            account_id,
            json,
        } => {
            let (name, policy) = build(config, profile.as_deref())?;
            let subject = Subject {
                client_ip,
                account_id,
                identifiers: identifiers.iter().map(Identifier::dns).collect(),
                path,
                eab: None,
            };

            let explanation = explain(&policy, &subject).await;
            if json {
                let value = explanation_json(&name, &subject, &explanation);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value)
                        .map_err(|error| CliError(format!("cannot render JSON: {error}")))?
                );
            } else {
                print!("{}", render_explanation(&name, &subject, &explanation));
            }
            Ok(())
        }
    }
}

/// Resolves the profile and builds its policy, exactly as startup would.
///
/// Building here rather than reading the configuration back means every
/// startup refusal — an unknown check type, a condition that will not parse, a
/// rule whose checks share no stage — is reported by this command too, which
/// makes it the cheapest way to check a policy before restarting the server.
///
/// The inventory is deliberately **not** built: an `ipam` check would then need
/// a reachable NetBox just to *print* the policy. The check is constructed with
/// the same registry a running server would give it only when one is
/// configured, and `explain` says so in its output when it reached outside.
fn build(
    config: &Config,
    wanted: Option<&str>,
) -> Result<(String, crate::filter::FilterPolicy), CliError> {
    let profile = resolve_profile(config, wanted)?;
    let sections = &profile.sections;

    let resolver = crate::dns::HickoryResolver::from_system_uncached()
        .map_err(|error| CliError(format!("cannot build a resolver: {error}")))?;
    let proxies = crate::proxy::OutboundProxies::from_config(&config.proxy)
        .map_err(|error| CliError(format!("configuration error: {error}")))?;

    let inventory = crate::ipam::from_config(
        &sections.ipam,
        crate::http_client::Outbound::new(
            std::sync::Arc::new(resolver),
            std::sync::Arc::new(proxies),
        ),
    )
    .map_err(|error| CliError(format!("profile `{}`: {error}", profile.name)))?;

    let policy = crate::filter::build::build(
        &sections.filter,
        &config.dns,
        inventory,
        sections.eab.enabled,
    )
    .map_err(|error| CliError(format!("profile `{}`: {error}", profile.name)))?;

    Ok((profile.name, policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ENV_LOCK;

    /// Loads a `Config` from TOML the way the server does, so
    /// `resolve_profiles` has the raw sources per-key inheritance needs — the
    /// same helper shape `cli::upstream`'s tests use, and for the same reason:
    /// a `Config` deserialized directly carries no raw layer and resolves no
    /// profiles at all.
    fn load(body: &str) -> Config {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = crate::testutil::TempDir::new("cli-filter");
        std::fs::write(dir.join("config.toml"), body).unwrap();
        // SAFETY: single-threaded test holding ENV_LOCK; removed before return.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    const ONE_PROFILE: &str = r#"
        [profiles.default]
        [profiles.default.filter]
        rules = ["mgmt"]
        rule.mgmt.when = "net"
        rule.mgmt.then = "allow"
        check.net.type = "allowed_ip"
        check.net.allow = ["10.0.0.0/8"]
    "#;

    async fn run(config: &Config, command: FilterCommand) -> Result<(), CliError> {
        run_filter_command(command, config).await
    }

    #[tokio::test]
    async fn show_prints_the_policy_of_the_only_profile() {
        let config = load(ONE_PROFILE);
        assert!(
            run(&config, FilterCommand::Show { profile: None })
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn show_accepts_the_profile_by_name() {
        let config = load(ONE_PROFILE);
        assert!(
            run(
                &config,
                FilterCommand::Show {
                    profile: Some("default".to_string())
                }
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn an_unknown_profile_is_refused_by_name() {
        let config = load(ONE_PROFILE);
        let error = run(
            &config,
            FilterCommand::Show {
                profile: Some("nope".to_string()),
            },
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("no profile named `nope`"), "{}", error.0);
    }

    /// `--profile` is optional only when there is nothing to disambiguate,
    /// matching `upstream show`.
    #[tokio::test]
    async fn several_profiles_require_naming_one() {
        let config = load(
            r#"
            [profiles.a]
            [profiles.b]
            "#,
        );
        let error = run(&config, FilterCommand::Show { profile: None })
            .await
            .unwrap_err();
        assert!(error.0.contains("--profile"), "{}", error.0);
    }

    /// The command builds the policy rather than reading it back, so every
    /// startup refusal reaches an operator here too — which is the point of
    /// having it.
    #[tokio::test]
    async fn a_broken_policy_is_reported_rather_than_printed() {
        let config = load(
            r#"
            [profiles.default]
            [profiles.default.filter]
            rules = ["broken"]
            rule.broken.when = "net and )"
            rule.broken.then = "allow"
            check.net.type = "allowed_ip"
            check.net.allow = ["10.0.0.0/8"]
            "#,
        );
        let error = run(&config, FilterCommand::Show { profile: None })
            .await
            .unwrap_err();
        assert!(error.0.contains("at column"), "{}", error.0);
    }

    fn explain_of(profile: Option<String>, ip: &str, names: &[&str], json: bool) -> FilterCommand {
        FilterCommand::Explain {
            profile,
            client_ip: Some(ip.parse().unwrap()),
            identifiers: names.iter().map(std::string::ToString::to_string).collect(),
            path: "/newOrder".to_string(),
            account_id: "explain".to_string(),
            json,
        }
    }

    #[tokio::test]
    async fn explain_runs_in_both_output_shapes() {
        let config = load(ONE_PROFILE);
        for json in [false, true] {
            assert!(
                run(
                    &config,
                    explain_of(None, "10.0.0.5", &["a.example.com"], json)
                )
                .await
                .is_ok(),
                "json = {json}"
            );
        }
    }

    #[tokio::test]
    async fn explain_works_on_a_refused_address_too() {
        let config = load(ONE_PROFILE);
        assert!(
            run(&config, explain_of(None, "203.0.113.9", &[], false))
                .await
                .is_ok()
        );
    }

    /// An unconfigured policy explains rather than erroring: "no rules apply"
    /// is the answer, and an operator checking a fresh install should see it.
    #[tokio::test]
    async fn explain_handles_a_policy_with_no_rules() {
        let config = load("[profiles.default]\n");
        assert!(
            run(
                &config,
                explain_of(None, "10.0.0.5", &["a.example.com"], false)
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn explain_accepts_no_client_address_at_all() {
        let config = load(ONE_PROFILE);
        let command = FilterCommand::Explain {
            profile: None,
            client_ip: None,
            identifiers: Vec::new(),
            path: "/directory".to_string(),
            account_id: "explain".to_string(),
            json: false,
        };
        assert!(run(&config, command).await.is_ok());
    }
}
