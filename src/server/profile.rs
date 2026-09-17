//! [`Profile`]: one ACME endpoint, and how a configuration generation builds
//! every one it mounts.

use std::sync::Arc;

use crate::challenge::{self, ChallengeRegistry};
use crate::config::{self, Config};
use crate::filter::{self, FilterPolicy};
use crate::ipam;
use crate::notify::NotifyDispatcher;
use crate::routes::{self, PROFILE_PREFIX};
use crate::signer::SignerBackend;
use crate::sqlite::db::Database;

use super::{Assembly, GenerationParts};

/// One ACME endpoint: its identity, its URLs, and the three subsystems that
/// answer for it.
///
/// Everything per-endpoint lives here rather than beside the global config in
/// [`AppState`](super::AppState), so a handler cannot pair one profile's signer
/// with another's base URL — the two always travel together.
pub struct Profile {
    /// The configured name (`[profiles.<name>]`), also the URL segment and the
    /// value stored in `accounts.profile` / `orders.profile`.
    pub name: String,
    /// Where the router mounts it: `/profile/<name>`.
    pub path: String,
    /// The public base for every URL this endpoint hands out and for the
    /// RFC 8555 §6.4 `url` check: `server.base_url` + [`Profile::path`].
    pub base_url: String,
    pub signer: Arc<dyn SignerBackend>,
    pub filter: Arc<FilterPolicy>,
    pub challenges: Arc<ChallengeRegistry>,
    pub order: config::OrderConfig,
    pub eab: config::EabConfig,
    /// The optional `meta` members this endpoint's directory advertises
    /// (RFC 8555 §7.1.1). Per-profile, like everything else here: two endpoints
    /// on one process can have different terms of service.
    pub meta: config::MetaConfig,
    pub notify: Arc<NotifyDispatcher>,
}

/// The subsystems and per-endpoint sections a [`Profile`] is assembled from.
///
/// A struct because [`Profile::new`] took nine positional parameters, four of
/// them `Arc<dyn …>` or config sections that a reader has to count commas to
/// tell apart. It also retires the crate's last
/// `#[allow(clippy::too_many_arguments)]`.
///
/// `name` and `base_url` stay positional: they are what the constructor
/// *derives* from rather than stores, and keeping them out of here is what
/// makes "the path is never configured" visible in the signature.
pub struct ProfileParts {
    pub signer: Arc<dyn SignerBackend>,
    pub filter: Arc<FilterPolicy>,
    pub challenges: Arc<ChallengeRegistry>,
    pub order: config::OrderConfig,
    pub eab: config::EabConfig,
    pub meta: config::MetaConfig,
    pub notify: Arc<NotifyDispatcher>,
}

impl Profile {
    /// Assembles a profile, deriving its path and base URL from its name —
    /// the two are never configured, so they cannot drift from each other or
    /// from what the database records.
    pub fn new(name: &str, base_url: &str, parts: ProfileParts) -> Self {
        let path = format!("{PROFILE_PREFIX}/{name}");
        Self {
            name: name.to_string(),
            base_url: format!("{}{path}", base_url.trim_end_matches('/')),
            path,
            signer: parts.signer,
            filter: parts.filter,
            challenges: parts.challenges,
            order: parts.order,
            eab: parts.eab,
            meta: parts.meta,
            notify: parts.notify,
        }
    }

    /// This endpoint's directory URL — where a client starts.
    ///
    /// Derived here rather than `format!`-ed at each of the three call sites
    /// (the startup log line, the admin API's profile listing, and anything
    /// added later), all of which have to agree with what `build_router`
    /// actually mounts.
    #[must_use]
    pub fn directory_url(&self) -> String {
        format!("{}{}", self.base_url, routes::DIRECTORY)
    }

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
        let (_assembly, first) = Assembly::new(&resolved, database, jobs.clone(), config)?;
        Self::build_all_with(config, &resolved, &first)
    }

    /// One generation of profiles, over an [`Assembly`] that outlives it.
    ///
    /// The half of [`build_all`](Self::build_all) a configuration reload runs
    /// again. Everything it touches is cheap and side-effect-free to rebuild —
    /// a filter policy, an IPAM client, a challenge registry — which is exactly
    /// why the *stateful* half lives in the `Assembly` instead. The signer
    /// backends are the interesting middle case: they are rebuilt here too, but
    /// only the ones whose configuration actually moved, and those adopt what
    /// the outgoing instance held (see
    /// [`signer::build_backends`](crate::signer::build_backends)).
    pub fn build_all_with(
        config: &Config,
        resolved: &[config::ProfileConfig],
        generation: &GenerationParts,
    ) -> anyhow::Result<Vec<Arc<Profile>>> {
        let egress = &generation.egress;
        let dispatchers = &generation.dispatchers;
        let backends = &generation.signers;

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
                let challenges = challenge::from_config(
                    &sections.challenge,
                    &config.dns,
                    egress.proxies.clone(),
                )
                .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                check_request_timeout(config, profile.name.as_str(), sections)?;
                Ok::<_, anyhow::Error>((filter, challenges))
            })?;

            profiles.push(Arc::new(Profile::new(
                &profile.name,
                &config.server.base_url,
                ProfileParts {
                    signer: backends
                        .get(&profile.name)
                        .ok_or_else(|| {
                            anyhow::anyhow!("profile `{}`: no signer backend", profile.name)
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
}

/// Refuses a `server.request_timeout_ms` shorter than the work the server does
/// *inside* a request.
///
/// Two hooks run inline in a handler rather than in the background: challenge
/// validation (`post_challenge` awaits `challenges.validate`) and the `custom`
/// signer's script (`post_finalize` awaits it). If the request deadline is the
/// shorter of the two budgets, a validation that was going to succeed is cut
/// off and the client is told the server failed — a misconfiguration that would
/// look like an intermittent CA outage and be miserable to diagnose. Cheaper to
/// refuse to start and say which two numbers disagree.
fn check_request_timeout(
    config: &Config,
    name: &str,
    sections: &config::ProfileSections,
) -> anyhow::Result<()> {
    let deadline = config.server.request_timeout_ms;
    let inline = [
        ("challenge.timeout_ms", sections.challenge.timeout_ms),
        (
            "signer.custom.timeout_ms",
            // Only when that backend is the one actually installed; an unused
            // `[signer.custom]` section says nothing about this profile.
            if sections.signer.backend == "custom" {
                sections.signer.custom.timeout_ms
            } else {
                0
            },
        ),
    ];

    for (key, budget) in inline {
        anyhow::ensure!(
            deadline > budget,
            "profile `{name}`: server.request_timeout_ms ({deadline}) must exceed {key} \
             ({budget}) — that hook runs inside the request, so a shorter deadline would cut \
             off work that was going to succeed and report it to the client as a server failure",
        );
    }
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

        let profiles = Profile::build_all(
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
        let error = match Profile::build_all(
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
        let error = match Profile::build_all(
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
    /// misconfiguration that would look like an intermittent CA outage: a
    /// validation that was going to succeed gets cut off and reported to the
    /// client as a server failure. Refuse to start and name both numbers.
    #[tokio::test]
    async fn build_all_refuses_a_deadline_shorter_than_an_inline_hook() {
        let config = config_from(
            r#"
            [server]
            request_timeout_ms = 1000

            [profiles.le]
            challenge.timeout_ms = 5000
            "#,
        );
        let error = match Profile::build_all(
            &config,
            database().await,
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a deadline below challenge.timeout_ms is a startup error"),
        };
        assert!(error.contains("profile `le`"), "{error}");
        assert!(error.contains("request_timeout_ms"), "{error}");
        assert!(error.contains("challenge.timeout_ms"), "{error}");
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
            Profile::build_all(
                &config,
                database().await,
                &crate::testutil::idle_job_queue(database().await)
            )
            .is_ok()
        );
    }
}
