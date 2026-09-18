//! How a configuration generation builds every [`Profile`] it mounts.

use std::sync::Arc;

use crate::challenge;
use crate::config::{self, Config};
use crate::filter;
use crate::ipam;
use crate::profile::{Profile, ProfileParts};
use crate::sqlite::db::Database;

use super::{Assembly, GenerationParts};

/// Builds every endpoint this configuration mounts, ready to serve.
///
/// Lives here rather than in `server::serve_on` because it is the assembly
/// step, not dispatch: it resolves the profiles, builds the signer backends
/// (deduplicated by configuration — see
/// [`signer::build_backends`](crate::signer::build_backends)), and gives
/// each profile its own filter chain and challenge registry. Every failure
/// is fatal at startup, so they come back as one error for the caller to
/// report and exit on.
///
/// Each profile's subsystems are built inside a span naming it, so the
/// warnings they emit at build time (`filter_disabled`,
/// `challenge_validation_bypassed`) say *which* endpoint is wide open —
/// with several mounted, an unattributed warning is worse than none.
/// `jobs` is the enqueue side of the durable queue, handed in rather than
/// built here for the reason the `Auditor` is built in `serve_on_with`:
/// `[jobs]` is process-wide, one queue drained by one runner, and a profile
/// is not the thing that owns it.
pub fn build_all(
    config: &Config,
    database: Arc<Database>,
    jobs: &crate::jobs::JobQueue,
) -> anyhow::Result<Vec<Arc<Profile>>> {
    let resolved = config.resolve_profiles()?;
    // All roles: this builder is the CLI's and the tests' path, where the
    // process is doing everything it is going to do.
    let (_assembly, first) = Assembly::new(
        super::RoleSet::default(),
        &resolved,
        database,
        jobs.clone(),
        config,
    )?;
    build_all_with(config, &resolved, &first)
}

/// One generation of profiles, over an [`Assembly`] that outlives it.
///
/// The half of [`build_all`] a configuration reload runs
/// again. Everything it touches is cheap and side-effect-free to rebuild —
/// a filter policy, an IPAM client, a challenge registry — which is exactly
/// why the *stateful* half lives in the `Assembly` instead. A profile takes
/// its signer's read side from `generation.infos` — built, like the
/// backends, only where the configuration moved (see
/// [`signer::build_infos`](crate::signer::build_infos)) — and never the
/// backend itself, which stays with the job handlers.
pub fn build_all_with(
    config: &Config,
    resolved: &[config::ProfileConfig],
    generation: &GenerationParts,
) -> anyhow::Result<Vec<Arc<Profile>>> {
    let egress = &generation.egress;
    let dispatchers = &generation.dispatchers;

    let mut profiles = Vec::with_capacity(resolved.len());
    for profile in resolved {
        let sections = &profile.sections;
        let span = tracing::info_span!("profile", profile = %profile.name);
        let (filter, challenges) = span.in_scope(|| {
            // Built per profile with no dedup pass, unlike
            // `signer::build_backends`. Sharing a signer backend is a
            // correctness requirement — two `LocalCa` over one CRL file
            // would clobber each other's ledger — whereas an IPAM client
            // owns no files and holds no mutable state, so two profiles
            // naming the same inventory each building one costs nothing
            // but a `rustls::ClientConfig`.
            let ipam = ipam::from_config(&sections.ipam, egress.outbound())
                .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
            let filter =
                filter::from_config(&sections.filter, &config.dns, ipam, sections.eab.enabled)
                    .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
            let challenges =
                challenge::from_config(&sections.challenge, &config.dns, egress.proxies.clone())
                    .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
            check_request_timeout(config, profile.name.as_str(), sections)?;
            Ok::<_, anyhow::Error>((filter, challenges))
        })?;

        profiles.push(Arc::new(Profile::new(
            &profile.name,
            &config.server.base_url,
            ProfileParts {
                signer_info: generation
                    .infos
                    .get(&profile.name)
                    .ok_or_else(|| {
                        anyhow::anyhow!("profile `{}`: no signer read side", profile.name)
                    })?
                    .clone(),
                filter,
                challenges,
                order: sections.order.clone(),
                eab: sections.eab.clone(),
                meta: sections.meta.clone(),
                notify: dispatchers[&profile.name].clone(),
            },
        )));
    }
    Ok(profiles)
}

/// Refuses a `server.request_timeout_ms` shorter than the work the server does
/// *inside* a request.
///
/// One hook still runs inline in a handler: a `custom` signer's read-only
/// script hooks, `crl` (`GET /crl`) and `renewal_info` (`GET /renewalInfo`),
/// each only when its `supports_*` flag is on. If the request deadline is the
/// shorter of the two budgets, an answer that was coming is cut off and the
/// client is told the server failed — a misconfiguration that would look like
/// an intermittent outage and be miserable to diagnose. Cheaper to refuse to
/// start and say which two numbers disagree.
///
/// **Two budgets used to be checked here and deliberately are not any more.**
/// `challenge.timeout_ms` went when validation moved into the job queue
/// (`acme::validate`), and the script's `issue` hook when finalize did
/// (`acme::issue`): both now bound a job attempt rather than a request. A
/// revocation a `custom` profile delegates waits on its job for at most the
/// request's own deadline, so it needs no check either.
fn check_request_timeout(
    config: &Config,
    name: &str,
    sections: &config::ProfileSections,
) -> anyhow::Result<()> {
    let deadline = config.server.request_timeout_ms;
    let custom = &sections.signer.custom;
    // Only when that backend is the one installed, and only for the hooks a
    // request runs; an unused `[signer.custom]` section, or one whose read
    // hooks are off, says nothing about how long this profile's requests take.
    let budget = if sections.signer.backend == "custom"
        && (custom.supports_crl || custom.supports_renewal_info)
    {
        custom.timeout_ms
    } else {
        0
    };

    anyhow::ensure!(
        deadline > budget,
        "profile `{name}`: server.request_timeout_ms ({deadline}) must exceed \
         signer.custom.timeout_ms ({budget}) — the script's `crl`/`renewal_info` hooks run inside \
         the request, so a shorter deadline would cut off an answer that was coming and report it \
         to the client as a server failure",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loads a whole configuration file, the only way profile resolution can be
    /// exercised (it reads the raw sources — see `Config::resolve_profiles`).
    ///
    /// Holds the crate-wide `ENV_LOCK` while it does: this points
    /// `ACME_PROXY_CONFIG` at its own file, and the environment is process-wide.
    fn config_from(body: &str) -> Config {
        let _lock = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = crate::testutil::TempDir::new("lib");
        std::fs::write(dir.join("config.toml"), body).unwrap();
        // SAFETY: single-threaded test; the variable is removed before return.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    /// A CA-material-free configuration: `local_ca` writes files at startup, so
    /// each profile gets its own throwaway directory.
    fn two_profiles_config(dir: impl AsRef<std::path::Path>) -> Config {
        let dir = dir.as_ref();
        let a = dir.join("a");
        let b = dir.join("b");
        config_from(&format!(
            r#"
            [challenge]
            enabled = ["http-01"]
            bypass = true

            [profiles.a]
            signer.local_ca.cert_path = "{a}.pem"
            signer.local_ca.key_path = "{a}.key"
            signer.local_ca.crl_path = "{a}.crl"

            [profiles.b]
            challenge.bypass = false
            signer.local_ca.cert_path = "{b}.pem"
            signer.local_ca.key_path = "{b}.key"
            signer.local_ca.crl_path = "{b}.crl"
            "#,
            a = a.display(),
            b = b.display(),
        ))
    }

    async fn database() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    #[tokio::test]
    async fn build_all_assembles_every_endpoint_from_its_own_configuration() {
        let dir = crate::testutil::TempDir::new("build");
        let config = two_profiles_config(&dir);

        let profiles = crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        )
        .unwrap();
        assert_eq!(profiles.len(), 2);

        assert_eq!(profiles[0].name, "a");
        assert_eq!(profiles[0].path, "/profile/a");
        assert_eq!(profiles[0].base_url, "http://localhost:3000/profile/a");
        // `a` inherits the global challenge section wholesale…
        assert!(profiles[0].challenges.is_bypassed());
        // …while `b` overrides one key of it and keeps the rest.
        assert!(!profiles[1].challenges.is_bypassed());
        assert_eq!(profiles[1].challenges.enabled_types(), ["http-01"]);
    }

    #[tokio::test]
    async fn build_all_refuses_a_configuration_that_mounts_nothing() {
        let config = config_from("[server]\nbase_url = \"http://acme.test\"\n");
        let error = match crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a server with no endpoint must not start"),
        };
        assert!(error.contains("[profiles.default]"), "{error}");
    }

    /// A subsystem that cannot be built names the endpoint it belongs to —
    /// with several mounted, "unknown challenge type" alone would not say where.
    #[tokio::test]
    async fn build_all_names_the_profile_a_failure_came_from() {
        let config = config_from(
            r#"
            [profiles.le]
            challenge.enabled = ["not-a-challenge"]
            "#,
        );
        let error = match crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an unknown challenge type is a startup error"),
        };
        assert!(error.contains("profile `le`"), "{error}");
        assert!(error.contains("not-a-challenge"), "{error}");
    }

    /// A request deadline shorter than a hook that runs inside the request is a
    /// misconfiguration that would look like an intermittent outage: an answer
    /// that was coming gets cut off and reported to the client as a server
    /// failure. Refuse to start and name both numbers.
    #[tokio::test]
    async fn build_all_refuses_a_deadline_shorter_than_an_inline_hook() {
        let config = config_from(
            r#"
            [server]
            request_timeout_ms = 1000

            [profiles.le]
            signer.backend = "custom"
            signer.custom.script_path = "/bin/true"
            signer.custom.timeout_ms = 5000
            signer.custom.supports_crl = true
            "#,
        );
        let error = match crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a deadline below signer.custom.timeout_ms is a startup error"),
        };
        assert!(error.contains("profile `le`"), "{error}");
        assert!(error.contains("request_timeout_ms"), "{error}");
        assert!(error.contains("signer.custom.timeout_ms"), "{error}");
    }

    /// The script's `issue` hook runs in the `signer_issue` job now, so a
    /// `custom` profile whose read hooks are off has nothing inline for the
    /// deadline to cut off. A configuration the old check refused must start.
    #[tokio::test]
    async fn a_custom_issue_hook_above_the_deadline_is_no_longer_refused() {
        let config = config_from(
            r#"
            [server]
            request_timeout_ms = 1000

            [profiles.le]
            signer.backend = "custom"
            signer.custom.script_path = "/bin/true"
            signer.custom.timeout_ms = 5000
            "#,
        );
        crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        )
        .expect("issuance no longer runs inside the request");
    }

    /// `challenge.timeout_ms` is deliberately **not** checked against the
    /// request deadline any more: validation runs in the job queue, so that
    /// budget bounds an attempt rather than a request and the two numbers are
    /// independent. A configuration the old check refused must now start.
    #[tokio::test]
    async fn a_challenge_timeout_above_the_deadline_is_no_longer_refused() {
        let config = config_from(
            r#"
            [server]
            request_timeout_ms = 1000

            [profiles.le]
            challenge.timeout_ms = 5000
            "#,
        );
        crate::server::profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        )
        .expect("challenge validation no longer runs inside the request");
    }

    /// The same check must not fire on `signer.custom.timeout_ms` when that
    /// backend is not the one installed — an unused `[signer.custom]` section
    /// says nothing about how long this profile's requests take.
    #[tokio::test]
    async fn an_unused_custom_signer_timeout_does_not_constrain_the_deadline() {
        let config = config_from(
            r#"
            [server]
            request_timeout_ms = 2000

            [signer.custom]
            script_path = "/bin/true"
            timeout_ms = 30000

            [profiles.le]
            challenge.timeout_ms = 1000
            "#,
        );
        assert!(
            crate::server::profile::build_all(
                &config,
                database().await,
                &crate::testutil::idle_job_queue(database().await)
            )
            .is_ok()
        );
    }
}
