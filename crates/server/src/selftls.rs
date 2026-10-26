//! Keeping this server's own listener certificate issued.
//!
//! Without `cert_path`, `[server.tls]` serves a self-signed certificate, which
//! every client has to be told to trust — the exact chore the rest of this server
//! exists to remove. With `server.tls.acme_enabled`, one row in the durable queue
//! obtains a real certificate for the host of `server.base_url` from the upstream
//! CA of the profile the configuration names, proving control of it through that
//! profile's `[signer.relay.dns01]` updater. The upstream half is
//! [`acme_proxy_signer::relay`]'s; what lives here is the *when*, the files, and
//! making the listener serve the result.
//!
//! ## Why a job rather than a startup step
//!
//! Booting must not wait for a CA. An issuance is a DNS API write, a wait for
//! propagation, and a CA that may take minutes to answer — all of it in front of
//! the listener binding its socket if it happens at startup, which turns a DNS
//! provider's outage into a server that will not start. So the first issuance is
//! queued, and the listener serves whatever is already on disk until it resolves.
//! That is the same posture as [`acme_proxy_signer::relay`]'s "nothing is
//! contacted at startup", and it is why the toggle's failure mode is a warning
//! naming itself rather than an exit status.
//!
//! ## Why the file on disk is the whole state
//!
//! There is no "last issued" row, and nothing to reconcile from a previous process:
//! [`needs_issuance`] asks the certificate that is actually there. That survives a
//! restore that took the database back a week, an operator replacing the files by
//! hand, and a restart in the middle of a renewal — the row is re-queued by
//! [`JobHandler::recover`] and the first thing the attempt does is re-read the file
//! it was going to replace.
//!
//! ## Where the new certificate takes effect
//!
//! Written to `cert_path` first, then a reload is asked for through the same handle
//! `SIGHUP` uses. Deliberately the same path rather than a second one: the acceptor
//! a reload builds is the acceptor the listener would have built at startup from
//! those files, so there is exactly one way a listener certificate is installed, and
//! a renewal cannot drift from what a restart would have produced. The cost is one
//! reload per renewal, which for a certificate that renews twice a year is nothing.
//!
//! ## What a role split means for it
//!
//! Only a process running the `worker` role builds signer backends, so only one
//! resolves the toggle, issues, and writes. A separate `acme` process picks the new
//! files up at its own next reload or restart — it has no CA to order from and no
//! DNS credential, and it should not need either.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info, warn};

use acme_proxy_core::cert;
use acme_proxy_core::config::{Config, ProfileConfig};
use acme_proxy_core::pemfile;
use acme_proxy_jobs::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use acme_proxy_signer::relay::{RelayState, SelfTlsError};
use acme_proxy_store::job::Job;
use acme_proxy_store::nonce::now_secs;

use crate::reload::ReloadHandle;

/// The `jobs.kind` the listener certificate is renewed under.
pub(crate) const SELF_TLS_JOB_KIND: &str = "server_self_tls";

/// The identity of the one live row. There is one listener certificate per process
/// — one `server.base_url`, one `cert_path` — so one key, which is also what makes
/// two workers sharing a database issue once rather than twice.
const LISTENER: &str = "listener";

/// How long before expiry the certificate is replaced.
///
/// Thirty days, which is a third of a Let's Encrypt lifetime and the same margin
/// every ACME client uses: enough that a CA outage, a rate limit, and a week of
/// DNS provider trouble all fit inside it while the certificate being served is
/// still valid.
const RENEW_BEFORE_SECONDS: i64 = 30 * 24 * 60 * 60;

/// How long to wait before looking again when nothing needed doing.
///
/// Half a day, because the answer comes from reading one file and the only cost of
/// looking too often is a row waking up. A renewal that misses its window by hours
/// costs nothing; one that misses it by a month costs a client an expired listener.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// What `server.tls.acme_enabled` resolved to for one configuration generation.
pub(crate) struct Plan {
    /// The name the certificate is for, from `server.base_url`.
    domain: String,
    /// Kept because the key is read (and may be created) from it, and because the
    /// name is derived from it rather than configured beside it.
    base_url: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    /// The profile whose upstream is asked, and whose dns-01 updater answers.
    relay: RelayState,
    /// One attempt's lease: what an issuance can take at worst.
    lease: Duration,
    reload: ReloadHandle,
}

/// Resolves `server.tls.acme_enabled` against the profiles and the backends this
/// process actually built.
///
/// `Ok(None)` means the toggle is off, which is every configuration that does not
/// set it. Everything it *can* refuse is refused here rather than at issuance time:
/// the upstream CA, the DNS API and the propagation wait are all outside this
/// process, but the shape of its own configuration is not, and an operator who
/// enabled the toggle wants told now which key is wrong.
///
/// `relays` is the `(profile, backend)` list of the generation — empty in a process
/// that does not run the `worker` role, which is why that role must call this and no
/// other may.
pub(crate) fn resolve(
    config: &Config,
    resolved: &[ProfileConfig],
    relays: &[(String, RelayState)],
    reload: &ReloadHandle,
) -> anyhow::Result<Option<Plan>> {
    let tls = &config.server.tls;
    if !tls.acme_enabled {
        return Ok(None);
    }
    if !tls.enabled {
        anyhow::bail!(
            "server.tls.acme_enabled needs server.tls.enabled: while this server serves \
             cleartext HTTP there is no listener certificate to obtain"
        );
    }
    let domain = acme_proxy_net::tls::listener_domain(&config.server.base_url)?;
    let profile = match tls.acme_profile.as_str() {
        "" => only_dns01_relay(resolved)?,
        named => named.to_string(),
    };
    let relay = relays
        .iter()
        .find(|(name, _)| *name == profile)
        .map(|(_, state)| state.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "server.tls.acme_profile names `{profile}`, which has no relay backend in this \
                 process — only a process running the `worker` role builds one, so run this \
                 toggle from one"
            )
        })?;
    if !relay.can_prove_control() {
        anyhow::bail!(
            "profile `{profile}` cannot obtain the listener certificate: its \
             signer.relay.challenge_strategy is not \"dns01\", and there is no other way for \
             this server to prove control of its own hostname upstream"
        );
    }

    // The worst case is the upstream's own polling budget plus the record's wait for
    // propagation, and both are the profile's, not this section's — an attempt cut
    // off at the default lease would abandon an order the CA is still working on.
    let relay_config = resolved
        .iter()
        .find(|profile_config| profile_config.name == profile)
        .map(|profile_config| &profile_config.sections.signer.relay);
    let lease = match relay_config {
        Some(relay_config) => Duration::from_secs(
            relay_config.poll_timeout_secs + relay_config.dns01.propagation.delay_secs + 60,
        ),
        None => Duration::from_secs(600),
    };

    info!(
        event = "server_self_tls_configured",
        outcome = "advisory",
        domain = %domain,
        profile = %profile,
        cert_path = ?tls.cert_path,
        "this server will obtain and renew its own listener certificate"
    );
    Ok(Some(Plan {
        domain,
        base_url: config.server.base_url.clone(),
        cert_path: PathBuf::from(&tls.cert_path),
        key_path: PathBuf::from(&tls.key_path),
        relay,
        lease,
        reload: reload.clone(),
    }))
}

/// The single profile that could serve as the listener certificate's upstream, when
/// `server.tls.acme_profile` did not name one.
///
/// Refusing on more than one is the point: the choice decides whose CA is asked,
/// whose DNS credential writes a record, and whose rate-limit allowance is spent,
/// and none of those are things to infer from whichever profile came first in a
/// `BTreeMap`.
fn only_dns01_relay(resolved: &[ProfileConfig]) -> anyhow::Result<String> {
    let candidates: Vec<&str> = resolved
        .iter()
        .filter(|profile| {
            profile.sections.signer.backend == "relay"
                && profile.sections.signer.relay.challenge_strategy == "dns01"
        })
        .map(|profile| profile.name.as_str())
        .collect();
    match candidates.as_slice() {
        [] => anyhow::bail!(
            "server.tls.acme_enabled has no profile to order from: no profile relays with \
             signer.relay.challenge_strategy = \"dns01\", so set server.tls.acme_profile or \
             turn the toggle off"
        ),
        [one] => Ok((*one).to_string()),
        several => anyhow::bail!(
            "server.tls.acme_enabled could order from any of {several:?}; name one with \
             server.tls.acme_profile"
        ),
    }
}

/// Whether the certificate on disk still needs obtaining or replacing.
///
/// The questions are asked in the order an operator would check them: is there a
/// certificate at all, is it one a CA issued, and is it going to outlive the renewal
/// window. A certificate that will not parse counts as needing replacement, because
/// the alternative is leaving a listener serving bytes no client will accept.
fn needs_issuance(cert_path: &Path) -> bool {
    let Ok(chain) = std::fs::read_to_string(cert_path) else {
        return true;
    };
    let Ok(leaf) = cert::leaf_der_from_chain(&chain) else {
        return true;
    };
    // The server's own generated certificate, which is what is on disk until the
    // first issuance lands.
    if cert::is_self_signed(&leaf) {
        return true;
    }
    match cert::not_after(&leaf) {
        Some(not_after) => not_after - now_secs() < RENEW_BEFORE_SECONDS,
        None => true,
    }
}

/// The queue row that keeps `[server.tls] acme_enabled` satisfied.
pub(crate) struct SelfTlsJob(Box<Plan>);

impl SelfTlsJob {
    pub(crate) fn new(plan: Plan) -> Self {
        Self(Box::new(plan))
    }
}

#[async_trait]
impl JobHandler for SelfTlsJob {
    fn kind(&self) -> &'static str {
        SELF_TLS_JOB_KIND
    }

    async fn run(&self, _job: &Job) -> JobOutcome {
        let plan = &self.0;
        if !needs_issuance(&plan.cert_path) {
            return JobOutcome::Reschedule(CHECK_INTERVAL);
        }

        let (domain, csr) = match acme_proxy_net::tls::listener_csr(&plan.base_url, &plan.key_path)
        {
            Ok(request) => request,
            Err(error) => {
                // Permanent on purpose: a key file that is not a key, or a
                // `base_url` that names an address, is not going to mend by the
                // next pass, and an operator wants the row retired with a reason
                // rather than retried for a week.
                error!(
                    event = "server_self_tls_abandoned",
                    outcome = "failure",
                    domain = %plan.domain,
                    error = %error
                );
                return JobOutcome::Failed(error.to_string());
            }
        };

        match plan.relay.issue_listener_certificate(&domain, &csr).await {
            Ok(chain) => self.install(&chain),
            Err(SelfTlsError::Retryable(reason)) => {
                warn!(
                    event = "server_self_tls_failed",
                    outcome = "failure",
                    domain = %domain,
                    error = %reason,
                    "trying again on the queue's backoff"
                );
                JobOutcome::Retry(reason)
            }
            Err(SelfTlsError::Permanent(reason)) => {
                error!(
                    event = "server_self_tls_abandoned",
                    outcome = "failure",
                    domain = %domain,
                    error = %reason
                );
                JobOutcome::Failed(reason)
            }
        }
    }

    fn lease(&self, _job: &Job) -> Option<Duration> {
        Some(self.0.lease)
    }

    async fn recover(&self, queue: &JobQueue) {
        // Idempotent by key, so this can run at every startup and after every
        // reload: the row that keeps the listener certificate current must exist
        // for as long as the toggle does, and `recover` is the only hook that is
        // certain to have run before anything else can notice the row is gone.
        queue
            .enqueue_or_log(JobSpec::now(SELF_TLS_JOB_KIND, LISTENER))
            .await;
    }
}

impl SelfTlsJob {
    /// Publishes a freshly issued chain: the file first, then the reload that makes
    /// the listener read it.
    fn install(&self, chain: &str) -> JobOutcome {
        let plan = &self.0;
        if let Err(error) = pemfile::write_atomic(&plan.cert_path, chain.as_bytes(), 0o644) {
            warn!(
                event = "server_self_tls_failed",
                outcome = "failure",
                domain = %plan.domain,
                cert_path = ?plan.cert_path,
                error = %error,
                "the certificate was issued but could not be written; the issued chain is lost \
                 and the order will be opened again"
            );
            return JobOutcome::Retry(format!("writing {}: {error}", plan.cert_path.display()));
        }

        info!(
            event = "server_self_tls_installed",
            outcome = "success",
            domain = %plan.domain,
            cert_path = ?plan.cert_path,
            "the listener certificate was obtained from the upstream CA"
        );

        // After the file, and asking rather than doing: the reload rebuilds the
        // acceptor from what is now on disk. A refusal means a reload is already
        // pending — which will read these files anyway — or that the supervisor has
        // gone, which is the case an operator has to be told about because the new
        // chain will not be served until something reloads.
        if !plan.reload.trigger() {
            warn!(
                event = "server_self_tls_reload_refused",
                outcome = "failure",
                domain = %plan.domain,
                "the reload supervisor is not accepting requests, so the new listener \
                 certificate is on disk but not being served; reload the process"
            );
        }
        JobOutcome::Reschedule(CHECK_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::config::{CloudflareConfig, RelayConfig, Rfc2136Config};
    use acme_proxy_core::testutil::TempDir;
    use acme_proxy_signer::relay::RelaySigner;
    use acme_proxy_signer::relay::testsrv;
    use acme_proxy_signer::{SignerBackend, SignerParts};
    use acme_proxy_store::db::Database;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// The host every fixture here puts in `server.base_url`, and so the name the
    /// certificate is asked for.
    const HOST: &str = "acme.int.example.com";

    /// A TSIG key as the configuration takes it: the secret is never used by these
    /// tests, but it is validated at startup and so has to be real base64.
    const TSIG_SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /// An RFC 2136 server that answers nothing: port 1 on loopback refuses a UDP
    /// exchange the way a dead DNS API does, which is what the dns01 fixtures here
    /// need once a test wants to watch an update fail.
    const CLOSED_DNS: &str = "127.0.0.1:1";

    /// Loads `body` as a configuration, holding the environment lock across the
    /// `ACME_PROXY_CONFIG` that points at it, as every caller of `Config::load` in
    /// this workspace has to.
    fn load(dir: &TempDir, body: &str) -> Config {
        let _lock = acme_proxy_core::config::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        dir.write("config.toml", body);
        // SAFETY: the lock above makes this the only thread touching the
        // environment, and the variable is removed before returning.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    /// `[server.tls] acme_enabled` turned on over `tls_extra` and `profiles`, with
    /// the two files it manages inside `dir`.
    ///
    /// `tls_enabled` is a parameter of its own because refusing the combination of
    /// the two toggles is one of the cases, and every other case wants it on.
    fn toggle(
        dir: &TempDir,
        tls_enabled: bool,
        tls_extra: &str,
        base_url: &str,
        profiles: &str,
    ) -> Config {
        load(
            dir,
            &format!(
                r#"
                [server]
                bind_address = "127.0.0.1:0"
                base_url = "{base_url}"

                [server.tls]
                enabled = {tls_enabled}
                acme_enabled = true
                cert_path = "{dir}/server.pem"
                key_path = "{dir}/server.key"
                {tls_extra}

                {profiles}
                "#,
                dir = dir.path().display(),
            ),
        )
    }

    /// One profile relaying with `dns01` over an RFC 2136 key: the shape the
    /// toggle needs, and one that builds without a nameserver.
    const ONE_DNS01: &str = r#"
        [profiles.default]
        signer.backend = "relay"
        signer.relay.directory_url = "https://ca.invalid/directory"
        signer.relay.account_key_path = "/tmp/acme-proxy-self-tls-key.key"
        signer.relay.challenge_strategy = "dns01"
        signer.relay.dns01.rfc2136.server = "127.0.0.1:53"
        signer.relay.dns01.rfc2136.zone = "example.com"
        signer.relay.dns01.rfc2136.tsig_key_name = "acme-key."
        signer.relay.dns01.rfc2136.tsig_key_secret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        signer.relay.dns01.rfc2136.tsig_algorithm = "hmac-sha256"
    "#;

    /// The same profile publishing through Cloudflare's DNS API instead of a
    /// TSIG-signed update: the shape a deployment whose zone lives there writes.
    const ONE_CLOUDFLARE: &str = r#"
        [profiles.default]
        signer.backend = "relay"
        signer.relay.directory_url = "https://ca.invalid/directory"
        signer.relay.account_key_path = "/tmp/acme-proxy-self-tls-cf-key.key"
        signer.relay.challenge_strategy = "dns01"
        signer.relay.dns01.provider = "cloudflare"
        signer.relay.dns01.cloudflare.api_token = "test-token"
        signer.relay.dns01.cloudflare.zone = "example.com"
        signer.relay.dns01.cloudflare.zone_id = "0123456789abcdef0123456789abcdef"
    "#;

    /// The same profile twice, distinguishable only by name — which is exactly why
    /// the server has to refuse to choose: the decision picks whose DNS credential
    /// writes the record and whose rate-limit allowance pays for it.
    const TWO_DNS01: &str = r#"
        [profiles.le]
        signer.backend = "relay"
        signer.relay.directory_url = "https://ca-one.invalid/directory"
        signer.relay.account_key_path = "/tmp/acme-proxy-self-tls-one.key"
        signer.relay.challenge_strategy = "dns01"
        signer.relay.dns01.rfc2136.server = "127.0.0.1:53"
        signer.relay.dns01.rfc2136.zone = "example.com"
        signer.relay.dns01.rfc2136.tsig_key_name = "acme-key."
        signer.relay.dns01.rfc2136.tsig_key_secret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        signer.relay.dns01.rfc2136.tsig_algorithm = "hmac-sha256"

        [profiles.internal]
        signer.backend = "relay"
        signer.relay.directory_url = "https://ca-two.invalid/directory"
        signer.relay.account_key_path = "/tmp/acme-proxy-self-tls-two.key"
        signer.relay.challenge_strategy = "dns01"
        signer.relay.dns01.rfc2136.server = "127.0.0.1:53"
        signer.relay.dns01.rfc2136.zone = "internal.example"
        signer.relay.dns01.rfc2136.tsig_key_name = "acme-key."
        signer.relay.dns01.rfc2136.tsig_key_secret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        signer.relay.dns01.rfc2136.tsig_algorithm = "hmac-sha256"
    "#;

    /// What `resolve` answered, in the shape the assertions below want.
    enum Answer {
        Off,
        Planned(Plan),
        Refused(String),
    }

    /// Runs `resolve` the way a worker's generation build does, over the profiles
    /// this configuration resolves to and the backends `relays` stands in for.
    fn resolve_against(config: &Config, relays: &[(String, RelayState)]) -> Answer {
        let profiles = config.resolve_profiles().unwrap();
        match resolve(config, &profiles, relays, &ReloadHandle::none()) {
            Ok(None) => Answer::Off,
            Ok(Some(plan)) => Answer::Planned(plan),
            Err(error) => Answer::Refused(error.to_string()),
        }
    }

    /// The toggle off must cost nothing at all: no name derived, no profile
    /// inspected, no row queued. That is every configuration that never heard of
    /// this feature.
    #[test]
    fn a_disabled_toggle_resolves_to_nothing() {
        let dir = TempDir::new("self-tls-off");
        let config = load(
            &dir,
            r#"
            [server]
            base_url = "https://acme.int.example.com"

            [profiles.default]
            signer.backend = "local_ca"
            "#,
        );
        assert!(matches!(resolve_against(&config, &[]), Answer::Off));
    }

    /// Every way the toggle can be asked for something impossible, each refused by
    /// naming the key that fixes it. One test because they share one guarantee: not
    /// one of them is allowed to reach a CA or a DNS API in order to be discovered.
    #[test]
    fn an_impossible_toggle_refuses_startup_naming_the_key() {
        let dir = TempDir::new("self-tls-refusals");

        // TLS off: there is no listener certificate to obtain.
        let Answer::Refused(reason) = resolve_against(
            &toggle(&dir, false, "", &format!("https://{HOST}"), ONE_DNS01),
            &[],
        ) else {
            panic!("a cleartext listener has no certificate to obtain");
        };
        assert!(reason.contains("server.tls.enabled"), "{reason}");

        // An address, which dns-01 cannot prove.
        let Answer::Refused(reason) = resolve_against(
            &toggle(&dir, true, "", "https://192.0.2.1:3000", ONE_DNS01),
            &[],
        ) else {
            panic!("a certificate cannot be obtained for an address");
        };
        assert!(reason.contains("192.0.2.1"), "{reason}");

        // Nothing to order from: the only profile signs locally.
        let Answer::Refused(reason) = resolve_against(
            &toggle(
                &dir,
                true,
                "",
                &format!("https://{HOST}"),
                r#"
                [profiles.default]
                signer.backend = "local_ca"
                "#,
            ),
            &[],
        ) else {
            panic!("a local_ca profile has no upstream to order from");
        };
        assert!(reason.contains("no profile relays"), "{reason}");

        // Two candidates and no name given.
        let Answer::Refused(reason) = resolve_against(
            &toggle(&dir, true, "", &format!("https://{HOST}"), TWO_DNS01),
            &[],
        ) else {
            panic!("the choice between two profiles belongs to the operator");
        };
        assert!(
            reason.contains("le") && reason.contains("internal"),
            "the refusal has to name what it could not choose between: {reason}"
        );

        // Named, but this process built no backend for it — which is what a
        // process without the `worker` role looks like.
        let Answer::Refused(reason) = resolve_against(
            &toggle(
                &dir,
                true,
                "acme_profile = \"internal\"",
                &format!("https://{HOST}"),
                TWO_DNS01,
            ),
            &[],
        ) else {
            panic!("there is no backend here to order through");
        };
        assert!(reason.contains("internal"), "{reason}");
        assert!(reason.contains("worker"), "{reason}");
    }

    /// A configuration that can work resolves to a name without the port, the two
    /// files `[server.tls]` reads, and a lease long enough that an issuance is not
    /// cut off while the CA is still working.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_workable_toggle_resolves_to_a_plan() {
        let dir = TempDir::new("self-tls-plan");
        let config = toggle(&dir, true, "", &format!("https://{HOST}:3000"), ONE_DNS01);
        let upstream = testsrv::start(testsrv::Script::default()).await;
        let relay = dns01_backend(&dir, &upstream).await;

        let Answer::Planned(plan) = resolve_against(&config, &[("default".to_string(), relay)])
        else {
            panic!("one profile relaying with dns01 is unambiguous");
        };
        assert_eq!(plan.domain, HOST, "a port is not part of a hostname");
        assert_eq!(plan.base_url, format!("https://{HOST}:3000"));
        assert_eq!(plan.cert_path, dir.join("server.pem"));
        assert_eq!(plan.key_path, dir.join("server.key"));
        // `poll_timeout_secs` (300) plus the propagation wait (30) plus a minute of
        // slack, all of them this profile's own defaults. The wait is counted
        // whether or not `propagation.mode` turns it on: a lease is only ever a
        // ceiling, and a too-generous one costs a stalled row's reclaim, nothing more.
        assert_eq!(plan.lease, Duration::from_secs(390));
    }

    /// Which provider a `dns01` profile publishes through is that profile's own
    /// business: the toggle resolves over a Cloudflare profile exactly as it does
    /// over a TSIG key, because what it holds is an updater, not a provider.
    /// Pinned because the day this resolution reaches for `dns01.rfc2136` is the
    /// day a Cloudflare-hosted zone cannot obtain a certificate for its own
    /// hostname.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cloudflare_profile_resolves_like_any_other() {
        let dir = TempDir::new("self-tls-cloudflare");
        let upstream = testsrv::start(testsrv::Script::default()).await;
        let relay = backend(&dir, &upstream, |config| {
            config.challenge_strategy = "dns01".to_string();
            config.dns01.provider = "cloudflare".to_string();
            config.dns01.cloudflare = CloudflareConfig {
                api_token: "test-token".to_string(),
                zone: "example.com".to_string(),
                zone_id: "0123456789abcdef0123456789abcdef".to_string(),
            };
        })
        .await;
        assert!(
            relay.can_prove_control(),
            "the provider is not the question"
        );

        let Answer::Planned(plan) = resolve_against(
            &toggle(
                &dir,
                true,
                "",
                &format!("https://{HOST}:3000"),
                ONE_CLOUDFLARE,
            ),
            &[("default".to_string(), relay)],
        ) else {
            panic!("a dns01 profile proves control whatever provider it names");
        };
        assert_eq!(plan.domain, HOST);
    }

    /// A profile that is a relay but answers `bypass` (or `http01`) upstream is
    /// refused even when it is the one named: it publishes nothing, so there is
    /// nothing that could have proved this server owns its own hostname.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_profile_that_cannot_prove_control_is_refused() {
        let dir = TempDir::new("self-tls-bypass");
        let upstream = testsrv::start(testsrv::Script::default()).await;
        let relay = backend(&dir, &upstream, |config| {
            config.challenge_strategy = "bypass".to_string();
        })
        .await;

        let Answer::Refused(reason) = resolve_against(
            &toggle(&dir, true, "", &format!("https://{HOST}"), ONE_DNS01),
            &[("default".to_string(), relay)],
        ) else {
            panic!("a bypass profile proves nothing upstream");
        };
        assert!(reason.contains("dns01"), "{reason}");
    }

    /// What each state of `cert_path` means for whether to go and get a
    /// certificate — the whole of the renewal decision, and the part that has to
    /// be right for a 90-day certificate to never be served expired.
    #[test]
    fn issuance_is_decided_from_the_certificate_on_disk() {
        let dir = TempDir::new("self-tls-need");

        // Absent: a first boot, or an operator who deleted it.
        assert!(needs_issuance(&dir.join("absent.pem")));

        // Unparseable: better to replace it than to keep serving it.
        assert!(needs_issuance(
            &dir.write("garbage.pem", "not a certificate")
        ));

        // This server's own placeholder. Its validity is irrelevant — that is the
        // point of checking the issuer as well as the expiry: a ten-year
        // self-signed certificate would otherwise never look due.
        assert!(needs_issuance(
            &dir.write("placeholder.pem", &self_signed_pem())
        ));

        // Issued, and months clear of the window: the common case, and the one
        // that must not spend an order.
        assert!(!needs_issuance(&dir.write("fresh.pem", &issued_pem(60))));

        // Inside it.
        assert!(needs_issuance(&dir.write("due.pem", &issued_pem(25))));
    }

    /// With a certificate that is still good, an attempt does nothing: no CSR, no
    /// order, no reload. That is what makes checking twice a day free.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pass_over_a_fresh_certificate_only_reschedules() {
        let dir = TempDir::new("self-tls-fresh");
        dir.write("server.pem", &issued_pem(60));
        let job = SelfTlsJob::new(plan(&dir).await);

        assert!(matches!(
            job.run(&job_row()).await,
            JobOutcome::Reschedule(CHECK_INTERVAL)
        ));
    }

    /// A key file that is not a key retires the row with the reason instead of
    /// retrying it forever: it will not mend by the next pass, and an operator
    /// reading `jobs list` wants the sentence, not a row stuck in `retry`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unusable_listener_key_abandons_the_row() {
        let dir = TempDir::new("self-tls-key");
        dir.write("server.key", "-----BEGIN PRIVATE KEY-----\nnonsense\n");
        dir.write("server.pem", &self_signed_pem());
        let job = SelfTlsJob::new(plan(&dir).await);

        let JobOutcome::Failed(reason) = job.run(&job_row()).await else {
            panic!("a key that will not parse is not a moment's bad luck");
        };
        assert!(reason.contains("server.key"), "{reason}");
    }

    /// The two things the queue reads from a handler before it runs anything: the
    /// kind a row is claimed by, which is also what `recover` dedups on, and the
    /// lease that bounds one attempt. Both come from the plan rather than from the
    /// queue's default — a lease taken from the default would abandon an order the
    /// CA is still working on.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_handler_names_its_kind_and_its_lease() {
        let dir = TempDir::new("self-tls-identity");
        let job = SelfTlsJob::new(plan(&dir).await);

        assert_eq!(job.kind(), SELF_TLS_JOB_KIND);
        assert_eq!(
            job.lease(&job_row()),
            Some(Duration::from_secs(60)),
            "the plan's lease, never the queue's default"
        );
    }

    /// The signer's own distinction, arriving as the queue's vocabulary: a CA that
    /// stated a reason retires the row, and the reason is what the operator reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_upstream_that_cannot_be_answered_abandons_the_row() {
        let dir = TempDir::new("self-tls-permanent");
        dir.write("server.pem", &self_signed_pem());
        let job = SelfTlsJob::new(plan(&dir).await);

        let JobOutcome::Failed(reason) = job.run(&job_row()).await else {
            panic!("a bypass backend can never prove control of anything");
        };
        assert!(reason.contains("dns01"), "{reason}");
    }

    /// A DNS API that refused the record is a moment's bad luck, and the row goes
    /// back to the queue rather than into the bin — the signer's own distinction
    /// arriving as the queue's vocabulary, which is the whole reason
    /// [`SelfTlsError`] exists instead of one error type here.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unwritable_record_retries_the_row() {
        let dir = TempDir::new("self-tls-retry");
        let upstream = testsrv::start(testsrv::Script {
            pose_challenge: true,
            ..testsrv::Script::default()
        })
        .await;
        let placeholder = self_signed_pem();
        dir.write("server.pem", &placeholder);
        let job = SelfTlsJob::new(dns01_plan(&dir, &upstream).await);

        let JobOutcome::Retry(reason) = job.run(&job_row()).await else {
            panic!("a DNS API that refused this record may take the next one");
        };
        assert!(reason.contains("_acme-challenge."), "{reason}");
        assert_eq!(
            upstream.finalized(),
            0,
            "nothing is finalized on a record that never published"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("server.pem")).unwrap(),
            placeholder,
            "a failed attempt leaves the certificate being served alone"
        );
    }

    /// The file is the durable half of an install. A reload nobody is there to act
    /// on is a warning the operator can act on, not a reason to throw the chain
    /// away: the next reload or restart serves it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_chain_still_lands_when_no_supervisor_can_hear_the_ask() {
        let dir = TempDir::new("self-tls-no-supervisor");
        // `plan` hands out a `ReloadHandle::none()`, which is what a process
        // running no reload supervisor has.
        let job = SelfTlsJob::new(plan(&dir).await);
        let chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";

        assert!(matches!(
            job.install(chain),
            JobOutcome::Reschedule(CHECK_INTERVAL)
        ));
        assert_eq!(
            std::fs::read_to_string(dir.join("server.pem")).unwrap(),
            chain
        );
    }

    /// Installing is the file first and the reload second, in that order: the
    /// acceptor a reload builds is read from disk, so a reload asked for before the
    /// write would publish the certificate it replaced.
    #[tokio::test(flavor = "multi_thread")]
    async fn installing_writes_the_chain_then_asks_for_a_reload() {
        let dir = TempDir::new("self-tls-install");
        let (reload, mut reloads) = crate::reload::channel();
        let mut plan = plan(&dir).await;
        plan.reload = reload;
        let job = SelfTlsJob::new(plan);
        let chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";

        assert!(matches!(
            job.install(chain),
            JobOutcome::Reschedule(CHECK_INTERVAL)
        ));
        assert_eq!(
            std::fs::read_to_string(dir.join("server.pem")).unwrap(),
            chain
        );
        assert!(
            reloads.recv().await.is_some(),
            "a chain on disk is not a chain being served"
        );
    }

    /// A chain that cannot be written is retried, not reported: the certificate on
    /// disk is still the one being served and still valid, and the next attempt
    /// opens the order again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_chain_that_cannot_be_written_is_retried() {
        let dir = TempDir::new("self-tls-unwritable");
        let plan = plan(&dir).await;
        // The directory `cert_path` names is gone, so the write has nowhere to go.
        std::fs::remove_dir_all(dir.path()).unwrap();
        let job = SelfTlsJob::new(plan);

        let JobOutcome::Retry(reason) = job.install("chain") else {
            panic!("a failed write must not be reported as an install");
        };
        assert!(reason.contains("server.pem"), "{reason}");
    }

    /// `recover` is what makes the row exist at all, and idempotence is what lets
    /// it run at every startup *and* after every reload without leaving a pile.
    #[tokio::test(flavor = "multi_thread")]
    async fn recovering_queues_the_one_row_it_needs() {
        let dir = TempDir::new("self-tls-recover");
        let job = SelfTlsJob::new(plan(&dir).await);
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let queue = acme_proxy_jobs::jobs::JobQueue::new(
            database.clone(),
            &acme_proxy_core::config::JobsConfig::default(),
        );

        job.recover(&queue).await;
        job.recover(&queue).await;

        assert_eq!(
            Job::count_live(SELF_TLS_JOB_KIND, &database).await.unwrap(),
            1,
            "one listener, one row"
        );
    }

    /// A plan over the scripted upstream's `bypass` backend — enough for every case
    /// that never reaches a CA, and honest about why it cannot.
    async fn plan(dir: &TempDir) -> Plan {
        let upstream = testsrv::start(testsrv::Script::default()).await;
        let relay = backend(dir, &upstream, |_| {}).await;
        Plan {
            domain: HOST.to_string(),
            base_url: format!("https://{HOST}:3000"),
            cert_path: dir.join("server.pem"),
            key_path: dir.join("server.key"),
            relay,
            lease: Duration::from_secs(60),
            reload: ReloadHandle::none(),
        }
    }

    /// A plan over [`dns01_backend`]: the toggle's shape end to end, with a DNS API
    /// that will refuse the update.
    async fn dns01_plan(dir: &TempDir, upstream: &testsrv::Upstream) -> Plan {
        Plan {
            domain: HOST.to_string(),
            base_url: format!("https://{HOST}:3000"),
            cert_path: dir.join("server.pem"),
            key_path: dir.join("server.key"),
            relay: dns01_backend(dir, upstream).await,
            lease: Duration::from_secs(60),
            reload: ReloadHandle::none(),
        }
    }

    /// The dns01 half of [`plan`], for the cases that need
    /// [`RelayState::can_prove_control`] to answer true. The updater it carries
    /// points at [`CLOSED_DNS`], so an issuance that reaches it fails the way a
    /// dead DNS API fails rather than writing to someone's zone.
    async fn dns01_backend(dir: &TempDir, upstream: &testsrv::Upstream) -> RelayState {
        let relay = backend(dir, upstream, |config| {
            config.challenge_strategy = "dns01".to_string();
            config.dns01.rfc2136 = Rfc2136Config {
                server: CLOSED_DNS.to_string(),
                zone: "example.com".to_string(),
                tsig_key_name: "acme-key.".to_string(),
                tsig_key_secret: TSIG_SECRET.to_string(),
                tsig_algorithm: "hmac-sha256".to_string(),
            };
        })
        .await;
        assert!(relay.can_prove_control());
        relay
    }

    /// A relay backend, built the way a generation builds one — including the
    /// upstream account it provisions on first use, which is why it needs an
    /// upstream rather than a URL that will not answer.
    async fn backend(
        dir: &TempDir,
        upstream: &testsrv::Upstream,
        adjust: impl FnOnce(&mut RelayConfig),
    ) -> RelayState {
        let mut config = RelayConfig {
            directory_url: upstream.directory_url(),
            account_key_path: dir.join("upstream.key").to_string_lossy().into_owned(),
            ..RelayConfig::default()
        };
        adjust(&mut config);
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        RelaySigner::from_config(
            &config,
            &SignerParts {
                database: database.clone(),
                notifiers: HashMap::new().into(),
                metrics: acme_proxy_jobs::testutil::test_metrics(database.clone()),
                egress: acme_proxy_net::testutil::egress_with(Arc::new(
                    acme_proxy_net::dns::HickoryResolver::from_system_uncached().unwrap(),
                )),
                jobs: acme_proxy_jobs::jobs::JobQueue::new(
                    database,
                    &acme_proxy_core::config::JobsConfig::default(),
                ),
            },
        )
        .unwrap()
        .relay_state()
        .expect("a relay backend always has state to hand over")
    }

    /// A claimed row to hand an attempt, for a handler that reads nothing out of
    /// it: the key is fixed, so the payload and the attempt count are noise here.
    fn job_row() -> Job {
        acme_proxy_store::testutil::job_fixture()
    }

    /// The placeholder `[server.tls]` writes when it has nothing to read:
    /// self-signed, and named for the listener's own host.
    fn self_signed_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![HOST.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, HOST);
        params.self_signed(&key).unwrap().pem()
    }

    /// A chain as an upstream hands one over: a leaf a CA signed, `days_left`
    /// days from expiring. The names differ, as they must in anything a CA issued.
    fn issued_pem(days_left: i64) -> String {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(vec![]).unwrap();
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "Upstream Test CA");
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::new(vec![HOST.to_string()]).unwrap();
        leaf.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        leaf.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days_left);
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, HOST);
        let pem = leaf.signed_by(&leaf_key, &issuer).unwrap().pem();
        format!("{pem}{ca_pem}")
    }
}
