//! Certificate-issuance abstraction.
//!
//! Finalizing an ACME order turns the client's CSR into an issued certificate.
//! *How* that happens is pluggable: the [`SignerBackend`] trait hides the backend
//! behind a single [`issue`](SignerBackend::issue) call, and [`from_config`]
//! builds the configured one at startup. The only backend implemented today is
//! [`local_ca::LocalCa`] — a persistent local CA.
//!
//! Revocation (RFC 8555 §7.6) is part of the same abstraction:
//! [`revoke`](SignerBackend::revoke) must actually revoke the certificate at
//! the backend, not just at the ACME/database layer — for [`local_ca::LocalCa`]
//! that means a real, CA-signed CRL. [`crl_der`](SignerBackend::crl_der) is how
//! a backend that maintains one serves it (`GET /crl`); it defaults to `None`
//! for a backend with no CRL of its own to publish here (e.g. one delegating to
//! an upstream CA that publishes its own).
//!
//! ## Asynchronous by design
//!
//! [`issue`](SignerBackend::issue) is **async**, so a backend that *delegates*
//! signing over the network (an upstream ACME CA, a remote signer) can await its
//! IO instead of blocking a runtime thread. [`local_ca::LocalCa`] never awaits —
//! its file IO happens once at startup and signing is CPU-bound — but the trait
//! is shaped for the backends that do. Like [`crate::filter::Check`], it needs
//! `#[async_trait]`: `Arc<dyn SignerBackend>` with an `async fn` is not dyn-safe.
//!
//! Construction stays synchronous: [`from_config`] runs once at startup, where a
//! failure is fatal anyway.
//!
//! ## Certificate validity is a backend policy
//!
//! Leaf validity is decided by the backend, not by the caller or the order — see
//! [`local_ca::LocalCa`], which uses its own `leaf_validity_days`. A delegating
//! backend would have no validity knob at all (the upstream CA decides).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::SignerConfig;
use crate::notify::NotifyDispatcher;
use crate::sqlite::db::Database;
use crate::sqlite::order::Identifier;

pub mod custom;
pub mod local_ca;
pub mod relay;

/// Re-exported so [`SignerBackend::http01_tokens`]'s signature — and the route
/// in [`crate::build_app`] it feeds — do not reach into one backend's module
/// for a type the generic trait mentions.
pub use relay::http01::TokenStore as Http01TokenStore;

/// What [`SignerBackend::issue`] produced: a certificate, or a promise of one.
///
/// A backend that signs locally answers synchronously with [`Issued`]. A
/// backend that delegates over the network answers [`Processing`] and finishes
/// the work in the background, because holding the finalize request open for
/// an upstream CA's own validation cycle could take minutes — RFC 8555 §7.4
/// has the `processing` order status for exactly this, and the client polls.
///
/// [`Issued`]: IssueOutcome::Issued
/// [`Processing`]: IssueOutcome::Processing
#[derive(Debug)]
pub enum IssueOutcome {
    /// A finished PEM chain (leaf followed by the issuer).
    Issued(String),
    /// The backend accepted the request and will update the `Order` itself
    /// (via `Order::finalize`/`Order::mark_invalid`) once it resolves. The
    /// handler moves the order to `processing` and returns it as-is.
    Processing,
}

/// A suggested renewal window (RFC 9773 §4.2): when the CA would like this
/// certificate replaced, and optionally why.
///
/// A struct rather than the `(start, end)` tuple this used to be, because
/// `explanationURL` has nowhere to live in a tuple — and it is precisely the
/// field a *delegating* backend most wants to pass through, since an upstream
/// CA setting an unusual window (a mass-revocation event, say) is exactly when
/// it publishes a page explaining it. §4.2: "Clients SHOULD provide this URL to
/// their operator, if present."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalWindow {
    /// Start of the window, epoch seconds.
    pub start: i64,
    /// End of the window, epoch seconds. §4.2 makes a window whose `end` equals
    /// or precedes its `start` invalid, and servers "MUST NOT serve such a
    /// response" — see `get_renewal_info`, which enforces that on the way out
    /// no matter which backend produced the window.
    pub end: i64,
    /// A page explaining why the window has this value, if the backend has one.
    pub explanation_url: Option<String>,
}

impl RenewalWindow {
    /// A window with no explanation — what a backend computing its own answer
    /// from certificate validity returns.
    #[must_use]
    pub fn new(start: i64, end: i64) -> Self {
        Self {
            start,
            end,
            explanation_url: None,
        }
    }
}

/// The validity window an order asked for (RFC 8555 §7.4's `notBefore` /
/// `notAfter`), in epoch seconds. Either half may be absent, and usually both
/// are — most clients let the CA decide.
///
/// A request, not an instruction: §7.4 lets the server override, and
/// [`local_ca::LocalCa`] clamps it to its own `leaf_validity_days` rather than
/// letting a client mint a ten-year certificate. But before this existed the
/// fields were stored and echoed in the order object while being dropped on the
/// way to the signer — so a client that asked for a window, and read one back,
/// got a certificate with a different one and no way to tell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedValidity {
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

impl RequestedValidity {
    /// Whether the order asked for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.not_before.is_none() && self.not_after.is_none()
    }
}

/// A pluggable certificate-issuance backend.
#[async_trait]
pub trait SignerBackend: Send + Sync {
    /// Issues a leaf certificate for the PKCS#10 CSR in `csr_der`.
    /// `identifiers` are the order's identifiers, so the backend can check the
    /// CSR requests exactly them.
    ///
    /// `order_id` names the local order this issuance belongs to. A
    /// synchronous backend ignores it; an asynchronous one needs it to find
    /// the `Order` again from its background task, since by then the handler
    /// that called this has long returned.
    ///
    /// `validity` is what the order asked for (RFC 8555 §7.4). A backend is
    /// free to ignore it — one that delegates has no say over the upstream's
    /// policy — but must not silently *contradict* its own advertised limits;
    /// see [`RequestedValidity`].
    async fn issue(
        &self,
        order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError>;

    /// Revokes the certificate `cert_der` (RFC 8555 §7.6), with an optional
    /// RFC 5280 §5.3.1 `CRLReason` code. Must be idempotent: revoking an
    /// already-revoked certificate is not an error.
    ///
    /// Deliberately takes no `order_id`: revocation needs no per-order state.
    /// The backend identifies the certificate from its DER, and a delegating
    /// backend's upstream account already owns the corresponding upstream
    /// order — the same `kid`-authenticated path `post_revoke_cert` implements
    /// on this server's own side.
    async fn revoke(&self, cert_der: &[u8], reason: Option<u32>) -> Result<(), SignerError>;

    /// The backend's current certificate revocation list (RFC 5280), DER
    /// encoded, if it maintains one servable here. `None` means the backend
    /// has no CRL of its own (e.g. a delegating backend whose CRL is only
    /// ever published by the upstream CA it defers to, at a URL of the
    /// upstream's choosing).
    async fn crl_der(&self) -> Option<Vec<u8>> {
        None
    }

    /// The backend's opinion on when `cert_der` should be renewed (ACME
    /// Renewal Information, RFC 9773) — the same
    /// [`RenewalWindow`] [`crate::handlers::calculate_suggested_window`]
    /// produces, so the handler can use either interchangeably.
    ///
    /// `Ok(None)` — the default, which [`local_ca::LocalCa`] keeps — means
    /// "no opinion, compute it locally". Only a backend delegating to an
    /// upstream CA that publishes its own ARI has anything better to say.
    async fn renewal_info(&self, _cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        Ok(None)
    }

    /// The background work this backend needs a durable queue for.
    ///
    /// Only a backend that resolves issuance asynchronously has anything to
    /// register: its work outlives the request that started it and must survive
    /// the process. A synchronous backend like [`local_ca::LocalCa`] never has a
    /// half-finished issuance at all, so the default is an empty list.
    ///
    /// A getter on the trait for the same reason
    /// [`crl_der`](SignerBackend::crl_der) and
    /// [`http01_tokens`](SignerBackend::http01_tokens) are: whether a backend has
    /// something to publish, or to run later, is the backend's own business, and
    /// the alternative is threading a registry through `build_backends` for the
    /// two implementations that have nothing to put in it.
    ///
    /// This replaced a `resume` hook that took no arguments and returned
    /// nothing, which each asynchronous backend implemented by re-spawning its
    /// own tasks at startup. Recovery is now one case of a queue rather than a
    /// mechanism of its own — see [`crate::jobs::JobHandler::recover`], which is
    /// where that logic went.
    fn jobs(&self) -> Vec<Arc<dyn crate::jobs::JobHandler>> {
        Vec::new()
    }

    /// The `http-01` token store this backend answers the *upstream's* own
    /// challenge from, if it has one.
    ///
    /// [`crate::build_app`] mounts `GET /.well-known/acme-challenge/{token}`
    /// on the root router when any profile's backend returns `Some`, and not
    /// at all otherwise — the same "a backend that has something to publish
    /// over HTTP says so" shape as [`crl_der`](SignerBackend::crl_der), and the
    /// reason this is a getter on the trait rather than a parameter threaded
    /// through `build_app`.
    ///
    /// Only [`relay`] with `challenge_strategy = "http01"` overrides it.
    fn http01_tokens(&self) -> Option<Arc<dyn Http01TokenStore>> {
        None
    }
}

/// Why issuance failed, mapped by the handler to the right ACME error:
/// a client-side CSR problem versus an internal signing failure.
#[derive(Debug)]
pub enum SignerError {
    /// The CSR was unparsable or did not match the order's identifiers.
    /// Maps to `Problem::bad_csr` (400).
    BadCsr,
    /// The backend failed to sign (should not happen in normal operation).
    /// Maps to `Problem::server_internal` (500).
    Internal(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::BadCsr => write!(f, "Bad CSR"),
            SignerError::Internal(detail) => write!(f, "Internal signer error: {detail}"),
        }
    }
}

impl std::error::Error for SignerError {}

/// Builds the configured signer backend. Called once at startup, so it may fail
/// fast (the caller exits on error).
///
/// `database` is handed to backends that resolve issuance asynchronously: they
/// own the `Order` update once the answer arrives, long after the handler that
/// asked for it returned. `local_ca` ignores it. `notifiers` is the same kind
/// of dependency, for the same reason: a backend whose completion happens in a
/// background task has no `Profile`/`AppState` to reach a notifier through, so
/// it is handed the whole `profile name -> dispatcher` map and looks up the
/// right one by `Order.profile` once it has something to report. Only
/// `relay` uses it today.
pub fn from_config(
    cfg: &SignerConfig,
    profiles: Vec<String>,
    database: Arc<Database>,
    notifiers: Arc<HashMap<String, Arc<NotifyDispatcher>>>,
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
    jobs: crate::jobs::JobQueue,
) -> anyhow::Result<Arc<dyn SignerBackend>> {
    match cfg.backend.as_str() {
        "local_ca" => Ok(Arc::new(local_ca::LocalCa::load_or_generate(
            &cfg.local_ca,
        )?)),
        "relay" => Ok(Arc::new(relay::RelaySigner::from_config(
            &cfg.relay, profiles, database, notifiers, resolver, proxies, jobs,
        )?)),
        "custom" => Ok(Arc::new(custom::CustomScriptSigner::from_config(
            &cfg.custom,
        )?)),
        // The one name worth explaining rather than merely refusing: it was
        // this backend's own until it was renamed away from the host program's
        // name, so an operator hitting it has a written-down configuration and
        // a one-line fix, not a typo. A diagnostic, not a compatibility path —
        // nothing reads the old spelling, and this arm goes at 1.0.0.
        "acme_proxy" => anyhow::bail!(
            "unknown signer backend: acme_proxy — renamed to `relay`. Set \
             signer.backend = \"relay\" and rename the [signer.acme_proxy] table to \
             [signer.relay] (environment: ACME_PROXY_SIGNER__ACME_PROXY__* becomes \
             ACME_PROXY_SIGNER__RELAY__*)"
        ),
        other => anyhow::bail!("unknown signer backend: {other}"),
    }
}

/// Builds one backend per profile, **sharing** the instance between profiles
/// whose signer configuration is identical, and returns them keyed by profile
/// name.
///
/// Sharing is not an optimization, it is a correctness requirement. Two
/// `LocalCa` instances over the same files each keep their own in-memory
/// revocation ledger and rewrite the CRL from it, so the second one to revoke
/// silently drops the first one's entries. Two `RelaySigner`s over the same
/// account key would likewise each register a job handler for one kind, which
/// the registry refuses outright. Hence also
/// the check below: identical configuration shares one instance, but *different*
/// configuration touching the same file is refused outright rather than
/// half-working.
pub fn build_backends(
    profiles: &[crate::config::ProfileConfig],
    database: Arc<Database>,
    notifiers: Arc<HashMap<String, Arc<NotifyDispatcher>>>,
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
    jobs: &crate::jobs::JobQueue,
) -> anyhow::Result<HashMap<String, Arc<dyn SignerBackend>>> {
    // The identity of a configuration is its `Debug` rendering: every config
    // type derives `Debug`, the output is deterministic for equal values, and
    // it is only ever compared to another one — never parsed, never shown.
    let key_of = |cfg: &SignerConfig| format!("{cfg:?}");

    let mut owners: HashMap<String, String> = HashMap::new();
    for profile in profiles {
        let key = key_of(&profile.sections.signer);
        for path in signer_paths(&profile.sections.signer) {
            match owners.get(&path) {
                Some(existing) if *existing != key => anyhow::bail!(
                    "profile `{}` reuses `{path}` with a different signer configuration: \
                     two backends over one file would overwrite each other's state \
                     (give each profile its own paths, or make their [signer] sections identical)",
                    profile.name
                ),
                _ => {
                    owners.insert(path, key.clone());
                }
            }
        }
    }

    // Which profiles each distinct configuration serves — what a relaying
    // backend needs to know to recover the right orders and only those.
    let mut served: HashMap<String, Vec<String>> = HashMap::new();
    for profile in profiles {
        served
            .entry(key_of(&profile.sections.signer))
            .or_default()
            .push(profile.name.clone());
    }

    let mut built: HashMap<String, Arc<dyn SignerBackend>> = HashMap::new();
    let mut backends: HashMap<String, Arc<dyn SignerBackend>> = HashMap::new();
    for profile in profiles {
        let key = key_of(&profile.sections.signer);
        let backend = match built.get(&key) {
            Some(backend) => backend.clone(),
            None => {
                let backend = from_config(
                    &profile.sections.signer,
                    served.get(&key).cloned().unwrap_or_default(),
                    database.clone(),
                    notifiers.clone(),
                    resolver.clone(),
                    proxies.clone(),
                    jobs.clone(),
                )
                .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                built.insert(key, backend.clone());
                backend
            }
        };
        backends.insert(profile.name.clone(), backend);
    }
    Ok(backends)
}

/// The files a signer configuration owns — what two profiles must not share
/// unless they share the whole configuration.
fn signer_paths(cfg: &SignerConfig) -> Vec<String> {
    match cfg.backend.as_str() {
        "local_ca" => {
            let mut paths = vec![
                cfg.local_ca.cert_path.clone(),
                cfg.local_ca.key_path.clone(),
                cfg.local_ca.crl_path.clone(),
            ];
            // A PKCS#11 key is shared state in exactly the way this check
            // exists for: two `LocalCa`s over one token key would each keep
            // their own revocation ledger and rewrite the CRL from it. Not a
            // file, but the same hazard, so it goes in the same list under a
            // pseudo-path that cannot collide with a real one.
            if cfg.local_ca.key_source == "pkcs11" {
                paths.push(format!(
                    "pkcs11:{}#{}#{}#{}",
                    cfg.local_ca.pkcs11.module_path,
                    cfg.local_ca.pkcs11.token_label,
                    cfg.local_ca.pkcs11.key_label,
                    cfg.local_ca.pkcs11.key_id,
                ));
            }
            paths
        }
        "relay" => vec![cfg.relay.account_key_path.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared resolver `Profile::build_all` supplies at startup. These
    /// tests reach loopback by IP literal, which `dns::connect` short-circuits.
    fn test_resolver() -> std::sync::Arc<dyn crate::dns::Resolver> {
        std::sync::Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }
    use crate::config::LocalCaConfig;

    /// A `SignerConfig` writing its CA material into a throwaway directory, so
    /// the `local_ca` arm can run without touching the repository's `ca.pem`.
    fn config(backend: &str) -> (SignerConfig, crate::testutil::TempDir) {
        let dir = crate::testutil::TempDir::new("signer");
        let cfg = SignerConfig {
            backend: backend.to_string(),
            local_ca: LocalCaConfig {
                cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
                key_path: dir.join("ca.key").to_string_lossy().into_owned(),
                crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
                ..LocalCaConfig::default()
            },
            ..SignerConfig::default()
        };
        (cfg, dir)
    }

    async fn database() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    fn no_notifiers() -> Arc<HashMap<String, Arc<NotifyDispatcher>>> {
        Arc::new(HashMap::new())
    }

    fn profile(name: &str, signer: SignerConfig) -> crate::config::ProfileConfig {
        crate::config::ProfileConfig {
            name: name.to_string(),
            sections: crate::config::ProfileSections {
                signer,
                ..crate::config::ProfileSections::default()
            },
        }
    }

    /// Two endpoints configured identically share **one** backend instance.
    ///
    /// Not an optimization: a second `LocalCa` over the same files would keep
    /// its own revocation ledger and rewrite the CRL from it, silently dropping
    /// the first one's entries.
    #[tokio::test]
    async fn identical_signer_configuration_yields_one_shared_backend() {
        let (cfg, _dir) = config("local_ca");
        let profiles = vec![profile("a", cfg.clone()), profile("b", cfg)];

        let backends = build_backends(
            &profiles,
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            &crate::testutil::idle_job_queue(database().await),
        )
        .unwrap();
        assert_eq!(backends.len(), 2);
        assert!(
            Arc::ptr_eq(&backends["a"], &backends["b"]),
            "one configuration must mean one instance"
        );
    }

    #[tokio::test]
    async fn differing_signer_configuration_yields_separate_backends() {
        let (first, dir_a) = config("local_ca");
        let (second, dir_b) = config("local_ca");
        let profiles = vec![profile("a", first), profile("b", second)];

        let backends = build_backends(
            &profiles,
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            &crate::testutil::idle_job_queue(database().await),
        )
        .unwrap();
        assert!(
            !Arc::ptr_eq(&backends["a"], &backends["b"]),
            "different CA material must mean different CAs"
        );

        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }

    /// Sharing files while disagreeing about anything else is refused outright:
    /// the two instances would overwrite each other's state, and the failure
    /// would only show up as a mysteriously short CRL much later.
    #[tokio::test]
    async fn sharing_ca_files_with_a_different_configuration_is_a_startup_error() {
        let (first, _dir) = config("local_ca");
        let mut second = first.clone();
        second.local_ca.leaf_validity_days = 7;

        let profiles = vec![profile("a", first), profile("b", second)];
        let error = match build_backends(
            &profiles,
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("two backends over one key file must not both be built"),
        };
        assert!(error.contains("different signer configuration"), "{error}");
        assert!(
            error.contains("ca.key") || error.contains("ca.pem"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_backend_failure_names_the_profile_it_came_from() {
        let profiles = vec![profile(
            "le",
            SignerConfig {
                backend: "nope".to_string(),
                ..SignerConfig::default()
            },
        )];

        let error = match build_backends(
            &profiles,
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            &crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an unknown backend is a startup error"),
        };
        assert!(error.contains("profile `le`"), "{error}");
    }

    #[tokio::test]
    async fn builds_the_local_ca_backend_and_it_can_issue() {
        let (cfg, _dir) = config("local_ca");
        let signer = from_config(
            &cfg,
            vec!["default".to_string()],
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            crate::testutil::idle_job_queue(database().await),
        )
        .expect("local_ca is a known backend");

        // Reached through the trait object, which is how handlers see it.
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let outcome = signer
            .issue(
                "ord-1",
                csr.der(),
                &[Identifier::dns("example.com")],
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        // A local CA answers synchronously; only a delegating backend defers.
        let chain = match outcome {
            IssueOutcome::Issued(chain) => chain,
            IssueOutcome::Processing => panic!("local_ca must issue synchronously"),
        };
        assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }

    #[tokio::test]
    async fn builds_the_custom_backend_and_it_can_issue() {
        let dir = crate::testutil::TempDir::new("signer");
        let script_path = dir.join("issue.sh");
        std::fs::write(
            &script_path,
            "#!/bin/sh\ncat > /dev/null\necho '-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----'\nexit 0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let cfg = SignerConfig {
            backend: "custom".to_string(),
            custom: crate::config::CustomSignerConfig {
                script_path: script_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..SignerConfig::default()
        };
        let signer = from_config(
            &cfg,
            vec!["default".to_string()],
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            crate::testutil::idle_job_queue(database().await),
        )
        .expect("custom is a known backend");

        let outcome = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &[Identifier::dns("example.com")],
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, IssueOutcome::Issued(chain) if chain.contains("leaf")));
    }

    /// `local_ca` has no upstream to ask, so it must keep the trait's default
    /// "no opinion" answer — that is what makes `get_renewal_info` fall back to
    /// its own local computation.
    #[tokio::test]
    async fn the_local_ca_backend_has_no_renewal_info_opinion() {
        let (cfg, _dir) = config("local_ca");
        let signer = from_config(
            &cfg,
            vec!["default".to_string()],
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            crate::testutil::idle_job_queue(database().await),
        )
        .unwrap();
        assert!(matches!(signer.renewal_info(&[0x30, 0x00]).await, Ok(None)));
    }

    /// A typo in `signer.backend` stops the server rather than silently leaving
    /// it unable to issue.
    #[tokio::test]
    async fn an_unknown_backend_is_a_startup_error() {
        let (cfg, _dir) = config("hashicorp-vault");
        // `Arc<dyn SignerBackend>` is not `Debug`, so `unwrap_err` is unavailable.
        let error = match from_config(
            &cfg,
            vec!["default".to_string()],
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an unknown backend must not build"),
        };
        assert!(
            error.contains("unknown signer backend") && error.contains("hashicorp-vault"),
            "{error}"
        );
    }

    /// The one unknown backend that is a renamed key rather than a typo:
    /// `acme_proxy` was this backend's own name until it was renamed away from
    /// the host program's. The refusal has to carry the new name and the new
    /// environment prefix, since neither is guessable from "unknown signer
    /// backend" alone.
    #[tokio::test]
    async fn the_old_acme_proxy_backend_name_is_refused_by_its_new_one() {
        let (cfg, _dir) = config("acme_proxy");
        let error = match from_config(
            &cfg,
            vec!["default".to_string()],
            database().await,
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
            crate::testutil::idle_job_queue(database().await),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("the old backend name must not build"),
        };
        for expected in [
            "acme_proxy",
            "`relay`",
            "[signer.relay]",
            "ACME_PROXY_SIGNER__RELAY__",
        ] {
            assert!(error.contains(expected), "{expected} missing from: {error}");
        }
    }

    /// Both variants render. `SignerError` is what a handler logs when
    /// issuance fails, so a variant with no message would leave nothing behind.
    #[test]
    fn signer_errors_render_their_kind() {
        assert_eq!(SignerError::BadCsr.to_string(), "Bad CSR");
        assert_eq!(
            SignerError::Internal("ca offline".to_string()).to_string(),
            "Internal signer error: ca offline"
        );
    }
}
