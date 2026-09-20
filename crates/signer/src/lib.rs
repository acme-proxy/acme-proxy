// Feature badges on docs.rs. Turned on by `--cfg docsrs` from
// `[package.metadata.docs.rs]`, so a stable `cargo doc`, `cargo build` and
// clippy never see this nightly-only attribute. `doc_cfg` annotates every
// `#[cfg(…)]` item on its own, so the `hsm`-gated items need no per-item
// attribute and a future one is covered for free — the behaviour that used to
// be a separate `doc_auto_cfg` feature, removed in 1.92 and merged into this
// one. Do not reintroduce that name; it no longer compiles.
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Certificate-issuance abstraction.
//!
//! Finalizing an ACME order turns the client's CSR into an issued certificate.
//! *How* that happens is pluggable: the [`SignerBackend`] trait hides the backend
//! behind a single [`issue`](SignerBackend::issue) call, and [`from_config`]
//! builds the configured one. Three backends exist: [`local_ca::LocalCa`], a
//! persistent local CA (its key in a file or behind PKCS#11); [`relay`], which
//! obtains the certificate from an upstream ACME server; and [`custom`], which
//! delegates to an operator script.
//!
//! Revocation (RFC 8555 §7.6) is part of the same abstraction:
//! [`revoke`](SignerBackend::revoke) must actually revoke the certificate at
//! the backend, not just at the ACME/database layer — for [`local_ca::LocalCa`]
//! that means a real, CA-signed CRL.
//!
//! ## Two halves: the backend and its read side
//!
//! [`SignerBackend`] is the half that holds the key — `ca.key`, a PKCS#11
//! login, a relay's upstream account — and only the `worker` role builds it.
//! [`SignerInfo`] is what a request may ask without the key: the CRL as last
//! stored (`GET /crl`), the trust anchor (`GET /ca.pem`), a renewal opinion,
//! the `http-01` tokens a relay publishes, and where a revocation goes. Every
//! role builds one through [`info_from_config`], which is what lets the process
//! parsing untrusted JWS and CSRs run with no read access to the key at all.
//! See [`info`].
//!
//! ## Asynchronous by design
//!
//! [`issue`](SignerBackend::issue) is **async**, so a backend that *delegates*
//! signing over the network (an upstream ACME CA, a remote signer) can await its
//! IO instead of blocking a runtime thread. [`local_ca::LocalCa`] never awaits —
//! its file IO happens once at startup and signing is CPU-bound — but the trait
//! is shaped for the backends that do. Like `filter::Check`, it needs
//! `#[async_trait]`: `Arc<dyn SignerBackend>` with an `async fn` is not dyn-safe.
//!
//! Construction stays synchronous: [`from_config`] runs once at startup, where a
//! failure is fatal anyway.
//!
//! ## Certificate validity is a backend policy
//!
//! The order's requested window reaches the backend as a [`RequestedValidity`],
//! and the backend has the last word: [`local_ca::LocalCa`] clamps it to its own
//! `leaf_validity_days`, and a delegating backend leaves it to whoever signs.
//!
//! ## A backend outlives the configuration it was built from
//!
//! A configuration reload rebuilds nearly everything (see `reload`),
//! but a backend that is still configured exactly as it was is **reused
//! verbatim** — see [`build_backends`], which keys on the configuration's own
//! `Debug` rendering. Only a backend whose configuration actually moved is
//! constructed again. Without the reuse every `SIGHUP` would re-read a CA key
//! and re-open a PKCS#11 session for nothing.
//!
//! A rebuilt backend has nothing to adopt from the one it replaces: every piece
//! of state a backend keeps between requests — a local CA's revocations and
//! CRL, a relay's `http-01` tokens and upstream orders — lives in the database,
//! which the outgoing and the incoming instance share. That is also what lets
//! two processes over one database run the same backend.
//!
//! The one crate that can hold a CA key, which is why only the `worker` role
//! builds a backend from it. An internal crate of the `acme-proxy` binary,
//! published in lockstep with it and with no semver promise of its own.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use acme_proxy_core::config::SignerConfig;
use acme_proxy_core::identifier::Identifier;
use acme_proxy_store::db::Database;

pub mod custom;
pub mod info;
pub mod issuance;
pub mod local_ca;
pub mod relay;

pub use info::{Opaque, SignerInfo, info_from_config};

/// Re-exported so [`SignerInfo::http01_tokens`]'s signature — and the route
/// in `router::build_app` it feeds — do not reach into one backend's
/// module for a type the generic trait mentions.
pub use relay::http01::TokenStore as Http01TokenStore;

/// What [`SignerBackend::issue`] produced: a certificate, or a promise of one.
///
/// A backend that signs locally answers with [`Issued`]. A backend that
/// delegates over the network answers [`Processing`] and finishes the work in
/// the background, because holding the `signer_issue` job — and the worker slot
/// it occupies — for an upstream CA's own validation cycle could take minutes.
/// Either way the client already holds a `processing` order (RFC 8555 §7.4)
/// from `finalize`, which queues the issuance rather than waiting for it, and
/// polls.
///
/// [`Issued`]: IssueOutcome::Issued
/// [`Processing`]: IssueOutcome::Processing
#[derive(Debug)]
pub enum IssueOutcome {
    /// A finished PEM chain (leaf followed by the issuer).
    Issued(String),
    /// The backend accepted the request and will update the `Order` itself
    /// (via `Order::finalize`/`Order::mark_invalid`) once it resolves. The
    /// `signer_issue` job leaves the order `processing` for it.
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

    /// What this backend publishes — its CRL, its anchor, its renewal opinion,
    /// its `http-01` tokens, where its revocations go — as the read side every
    /// role serves from. See [`info`].
    ///
    /// The default is [`Opaque`]: nothing to publish, revocations delegated to
    /// the backend itself. The three real backends override it, each returning
    /// the same type [`info_from_config`] builds for it from configuration.
    fn info(&self) -> Arc<dyn SignerInfo> {
        Arc::new(Opaque)
    }

    /// This backend's in-flight issuances, as the process-wide relay handler
    /// sees them, if it resolves issuance asynchronously at all.
    ///
    /// Only a backend whose work outlives the request that started it has
    /// anything to hand over; a synchronous backend like [`local_ca::LocalCa`]
    /// never has a half-finished issuance, so the default is `None`.
    ///
    /// **State, not a [`JobHandler`](acme_proxy_jobs::jobs::JobHandler)** — the same
    /// distinction, and for the same reason, as
    /// [`crl_refresher`](SignerBackend::crl_refresher) below. This method replaced a
    /// `jobs()` returning one handler per backend, which made two profiles
    /// relaying to *different* upstreams — two backends, since
    /// [`build_backends`] deliberately does not collapse them — a startup
    /// error, `JobRegistry::register` refusing the second handler for
    /// `signer_relay_issue`. `server::generation::build_generation` now builds
    /// one [`relay::flow::RelayJob`] over every relay profile in the process,
    /// which picks the backend per row from the profile the row names.
    ///
    /// There is deliberately no general "here are my job handlers" hook left on
    /// this trait: every one it could return has this problem, and a subsystem
    /// that wants a queue registers one handler covering every backend of its
    /// kind. Recovery is a case of that queue rather than a mechanism of its own
    /// — see [`acme_proxy_jobs::jobs::JobHandler::recover`].
    fn relay_state(&self) -> Option<relay::RelayState> {
        None
    }

    /// This backend's CRL, if it keeps one that must be pruned (RFC 5280 §3.3)
    /// and re-signed before it lapses.
    ///
    /// A getter handing over *state* rather than a
    /// [`JobHandler`](acme_proxy_jobs::jobs::JobHandler), and the distinction is not
    /// cosmetic: [`acme_proxy_jobs::jobs::JobRegistry::register`] refuses two handlers
    /// for one `kind`, and two profiles with *different* `[signer.local_ca]`
    /// sections are two distinct backends — so a handler returned from here
    /// would make a supported configuration a startup error. Handing over the
    /// state instead lets `server::generation::build_generation` build one
    /// handler over every CA in the process, the shape
    /// [`SignerInfo::http01_tokens`] already has for the same reason.
    /// [`relay_state`](SignerBackend::relay_state) above is the second method of
    /// this shape, and the trait deliberately has no third form: a backend never
    /// returns a handler of its own.
    ///
    /// Only [`local_ca::LocalCa`] overrides it. The delegating backends have no
    /// CRL of their own to keep — the upstream or the script keeps it.
    fn crl_refresher(&self) -> Option<Arc<dyn CrlRefresher>> {
        None
    }
}

/// One backend's CRL, as the periodic sweep sees it.
///
/// Deliberately narrow: the sweep has no business knowing what a `LocalCa` is,
/// and this is the whole of what it needs — something to name in a log line and
/// something to call. See [`SignerBackend::crl_refresher`] for why the state
/// travels rather than a [`JobHandler`](acme_proxy_jobs::jobs::JobHandler).
#[async_trait]
pub trait CrlRefresher: Send + Sync {
    /// Which CA this is, for logging: its issuer id
    /// ([`acme_proxy_core::cert::issuer_id`]), the key its revocation state is stored
    /// under. Two profiles sharing one CA name one issuer.
    fn issuer(&self) -> &str;

    /// Drops revocations whose certificates have expired, re-signs the CRL if
    /// any went or if it is due, and returns how many went. Must be cheap and
    /// sign nothing when there is nothing to do — it runs daily on every CA in
    /// the process.
    async fn refresh(&self) -> Result<u64, SignerError>;

    /// Re-signs the CRL when it does not list every recorded revocation, and
    /// says whether it did.
    ///
    /// What a revocation recorded *without* this CA's key asks for: the row is
    /// in `revocations`, and the process that holds the key signs it into the
    /// CRL (`local_ca_crl_regenerate`). A no-op when another writer's CRL has
    /// already caught up, so a burst of such revocations signs once.
    async fn republish(&self) -> Result<bool, SignerError>;
}

/// Why issuance failed, mapped by the handler to the right ACME error:
/// a client-side CSR problem versus an internal signing failure.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The CSR was unparsable or did not match the order's identifiers.
    /// Maps to `Problem::bad_csr` (400).
    #[error("Bad CSR")]
    BadCsr,
    /// The backend failed to sign (should not happen in normal operation).
    /// Maps to `Problem::server_internal` (500).
    #[error("Internal signer error: {0}")]
    Internal(String),
}

/// The dependencies every backend is built from, minus its own `[signer]`
/// section.
///
/// A struct for `ProfileParts`' reason:
/// [`from_config`] had reached seven positional parameters, which is where a
/// reader starts counting commas and clippy starts complaining. Taken by reference and cloned field by field, since
/// [`build_backends`] calls [`from_config`] in a loop.
///
/// `database` is for the backends that resolve issuance asynchronously: they own
/// the `Order` update once the answer arrives, long after the handler that asked
/// for it returned. `local_ca` ignores it. `notifiers` is the same kind of
/// dependency for the same reason — a backend whose completion happens in a
/// background task has no `Profile`/`AppState` to reach a notifier through, so it
/// is handed the whole `profile name -> dispatcher` map and looks up the right
/// one by `Order.profile` once it has something to report. It arrives as
/// [`acme_proxy_jobs::notify::Notifiers`] rather than a bare `Arc` because a backend
/// outlives the generation that built it while the map does not: a captured
/// `Arc` would pin the backend to the dispatchers that existed when it was
/// constructed.
#[derive(Clone)]
pub struct SignerParts {
    pub database: Arc<Database>,
    pub notifiers: acme_proxy_jobs::notify::Notifiers,
    pub metrics: Arc<acme_proxy_jobs::metrics::Metrics>,
    /// This generation's outbound plumbing **and** the configuration identity of
    /// it, held whole rather than as a bare
    /// [`Outbound`](acme_proxy_net::http_client::Outbound). The two cannot then disagree,
    /// and a value that disagreed would make a `dns.resolver` edit a silent
    /// no-op for every signer — see [`build_backends`].
    pub egress: Arc<acme_proxy_net::egress::Egress>,
    pub jobs: acme_proxy_jobs::jobs::JobQueue,
}

/// How a revocation reaches a configured backend **without building it**.
///
/// The host CLI never constructs a signer: building one loads the CA key,
/// logs in to a PKCS#11 token or registers with an upstream, none of which a
/// one-shot command should do beside a running server. This is what it
/// decides from the configuration alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationRoute {
    /// A local CA: the revocation is a row in `revocations` under this issuer
    /// id, and whichever process holds the key signs it into the CRL.
    Ledger { issuer: String },
    /// A backend that must itself be asked — an upstream CA or an operator
    /// script — so the work goes to the server's job queue.
    Delegated,
}

/// The [`RevocationRoute`] for `cfg`.
///
/// For a local CA this reads `cert_path` (public, and present once
/// `acme-proxy init` or a `worker` has run with this configuration) and nothing
/// else — the same answer [`SignerInfo::revocation_route`] gives, for a caller
/// with no read side built.
pub fn revocation_route(cfg: &SignerConfig) -> anyhow::Result<RevocationRoute> {
    match cfg.backend.as_str() {
        "local_ca" => Ok(RevocationRoute::Ledger {
            issuer: local_ca::issuer_id_of(&local_ca::read_ca_certificate(
                &cfg.local_ca.cert_path,
            )?)?,
        }),
        "relay" | "custom" => Ok(RevocationRoute::Delegated),
        other => Err(unknown_backend(other)),
    }
}

/// Builds the configured signer backend.
///
/// Called at startup and again for any backend a reload rebuilds; a failure is
/// fatal to whichever of the two it is (the process exits, or the reload is
/// refused with the running generation untouched).
pub fn from_config(
    cfg: &SignerConfig,
    parts: &SignerParts,
) -> anyhow::Result<Arc<dyn SignerBackend>> {
    match cfg.backend.as_str() {
        "local_ca" => Ok(Arc::new(local_ca::LocalCa::load_or_generate(
            &cfg.local_ca,
            parts.database.clone(),
        )?)),
        // The one backend that reads the metrics registry, because it is the
        // one that finishes an issuance from a task of its own: the
        // `signer_issue` job answered `Processing` and moved on, so no
        // `Auditor` of its is in scope when the certificate actually arrives,
        // and the backend builds an offline one counting into this registry.
        "relay" => Ok(Arc::new(relay::RelaySigner::from_config(
            &cfg.relay, parts,
        )?)),
        "custom" => Ok(Arc::new(custom::CustomScriptSigner::from_config(
            &cfg.custom,
        )?)),
        other => Err(unknown_backend(other)),
    }
}

/// The refusal for a `signer.backend` that names no backend — shared by
/// [`from_config`] and [`info_from_config`], so a process that builds only the
/// read side still says what is wrong with the configuration.
fn unknown_backend(name: &str) -> anyhow::Error {
    match name {
        // The one name worth explaining rather than merely refusing: it was
        // this backend's own until it was renamed away from the host program's
        // name, so an operator hitting it has a written-down configuration and
        // a one-line fix, not a typo. A diagnostic, not a compatibility path —
        // nothing reads the old spelling, and this arm goes at 1.0.0.
        "acme_proxy" => anyhow::anyhow!(
            "unknown signer backend: acme_proxy — renamed to `relay`. Set \
             signer.backend = \"relay\" and rename the [signer.acme_proxy] table to \
             [signer.relay] (environment: ACME_PROXY_SIGNER__ACME_PROXY__* becomes \
             ACME_PROXY_SIGNER__RELAY__*)"
        ),
        other => anyhow::anyhow!("unknown signer backend: {other}"),
    }
}

/// The backends one configuration generation runs — or their read sides —
/// in the two views that are needed of them.
///
/// `by_profile` is what a `Profile` or a job handler
/// is handed and the only thing that serves. `by_identity` exists purely so the
/// **next** reload can ask "is this one already built?" — see
/// [`build_backends`], where answering yes is what keeps a `SIGHUP` from
/// re-reading a CA key and re-opening a PKCS#11 session for a configuration
/// that did not move.
///
/// Generic because a generation holds two: the backends (`T = dyn
/// SignerBackend`, the default), built only by the `worker` role, and their
/// read sides (`T = dyn SignerInfo`), built by every role through
/// [`build_infos`]. Both follow one identity and one reuse rule.
pub struct SignerSet<T: ?Sized = dyn SignerBackend> {
    by_profile: HashMap<String, Arc<T>>,
    by_identity: HashMap<String, Arc<T>>,
}

impl<T: ?Sized> Default for SignerSet<T> {
    fn default() -> Self {
        Self {
            by_profile: HashMap::new(),
            by_identity: HashMap::new(),
        }
    }
}

impl<T: ?Sized> Clone for SignerSet<T> {
    fn clone(&self) -> Self {
        Self {
            by_profile: self.by_profile.clone(),
            by_identity: self.by_identity.clone(),
        }
    }
}

impl<T: ?Sized> SignerSet<T> {
    /// The instance serving `profile`, if that endpoint is mounted.
    #[must_use]
    pub fn get(&self, profile: &str) -> Option<&Arc<T>> {
        self.by_profile.get(profile)
    }

    /// Every mounted profile with its instance, for a job handler that picks
    /// one per row by the profile the row names.
    #[must_use]
    pub fn by_profile(&self) -> Vec<(String, Arc<T>)> {
        self.by_profile
            .iter()
            .map(|(profile, instance)| (profile.clone(), instance.clone()))
            .collect()
    }

    /// How many distinct instances this set holds — one per distinct
    /// `[signer]` configuration, not one per profile.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }
}

/// The identity a `[signer]` configuration is shared and reused under; see
/// [`build_backends`].
fn identity_key(cfg: &SignerConfig, parts: &SignerParts) -> String {
    format!("{cfg:?}|{}", parts.egress.identity)
}

/// One instance per profile, shared between identical configurations and
/// reused from `previous` where the configuration did not move — the half of
/// [`build_backends`] that [`build_infos`] shares.
fn assemble_set<T: ?Sized>(
    profiles: &[acme_proxy_core::config::ProfileConfig],
    parts: &SignerParts,
    previous: &SignerSet<T>,
    build: impl Fn(&SignerConfig, &SignerParts) -> anyhow::Result<Arc<T>>,
    reused: impl Fn(&str),
) -> anyhow::Result<SignerSet<T>> {
    let mut set = SignerSet::<T>::default();
    for profile in profiles {
        let key = identity_key(&profile.sections.signer, parts);
        let instance = match (set.by_identity.get(&key), previous.by_identity.get(&key)) {
            (Some(instance), _) => instance.clone(),
            (None, Some(instance)) => {
                reused(&profile.name);
                let instance = instance.clone();
                set.by_identity.insert(key, instance.clone());
                instance
            }
            (None, None) => {
                let instance = build(&profile.sections.signer, parts)
                    .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                set.by_identity.insert(key, instance.clone());
                instance
            }
        };
        set.by_profile.insert(profile.name.clone(), instance);
    }
    Ok(set)
}

/// The read side of every profile's signer, from configuration alone — what
/// every role serves `/crl`, `/ca.pem`, `renewalInfo` and `http-01` tokens
/// from, and where it routes a revocation.
///
/// Shared and reused exactly as [`build_backends`] shares and reuses backends,
/// under the same identity. Never touches a key: see [`info_from_config`].
pub fn build_infos(
    profiles: &[acme_proxy_core::config::ProfileConfig],
    parts: &SignerParts,
    previous: &SignerSet<dyn SignerInfo>,
) -> anyhow::Result<SignerSet<dyn SignerInfo>> {
    assemble_set(profiles, parts, previous, info_from_config, |_| {})
}

/// Builds one backend per profile, **sharing** the instance between profiles
/// whose signer configuration is identical, and **reusing** the instance the
/// previous generation built for a configuration that has not moved.
///
/// Sharing is cheaper than two instances, and the check below keeps it honest:
/// identical configuration shares one instance, but *different* configuration
/// touching the same file — one CA key under two leaf policies, one upstream
/// account under two poll budgets — is refused outright rather than
/// half-working.
///
/// Reuse is the same requirement in the time dimension, and `previous` is what
/// makes a reload able to touch this at all. Three outcomes per distinct
/// configuration:
///
/// 1. **Already built** — the very same `Arc` comes back, and nothing is
///    constructed; this is the ordinary case, since most reloads touch
///    `[filter]` or `[notify]` and leave every signer alone.
/// 2. **New** — built. This covers both a profile mounted for the first time
///    and a live profile whose `[signer]` an operator edited; the rebuilt
///    backend finds its state where the outgoing one left it, in the database.
/// 3. **Gone** — no longer named by any profile, so it is simply absent from the
///    result and dropped once the caller publishes it.
///
/// The identity a configuration is keyed by is its `Debug` rendering — every
/// config type derives `Debug`, the output is deterministic for equal values,
/// and it is only ever compared to another one, never parsed and never shown —
/// **plus [`SignerParts::egress`]**. That second half is what lets `[dns]` and
/// `[proxy]` reload: they are not `[signer]` keys, but every backend that
/// reaches the network caches them at construction, so a backend reused across a
/// reload that changed either would keep dialling through the old policy with
/// nothing saying so.
pub fn build_backends(
    profiles: &[acme_proxy_core::config::ProfileConfig],
    parts: &SignerParts,
    previous: &SignerSet,
) -> anyhow::Result<SignerSet> {
    let mut owners: HashMap<String, String> = HashMap::new();
    for profile in profiles {
        let key = identity_key(&profile.sections.signer, parts);
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

    assemble_set(profiles, parts, previous, from_config, |profile| {
        debug!(
            event = "signer_backend_reused",
            outcome = "success",
            profile = %profile,
            "the configuration did not move, so the running backend is carried \
             whole rather than rebuilt"
        );
    })
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
            // exists for: two `LocalCa`s over one token key are two writers of
            // one CA's CRL, racing each other's `crlNumber` for as long as both
            // run. Not a file, but the same hazard, so it goes in the same list
            // under a pseudo-path that cannot collide with a real one.
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

    /// The shared resolver `server::profile::build_all` supplies at startup. These
    /// tests reach loopback by IP literal, which `dns::connect` short-circuits.
    fn test_resolver() -> std::sync::Arc<dyn acme_proxy_net::dns::Resolver> {
        std::sync::Arc::new(acme_proxy_net::dns::HickoryResolver::from_system_uncached().unwrap())
    }
    use acme_proxy_core::config::LocalCaConfig;

    /// A `SignerConfig` writing its CA material into a throwaway directory, so
    /// the `local_ca` arm can run without touching the repository's `ca.pem`.
    fn config(backend: &str) -> (SignerConfig, acme_proxy_core::testutil::TempDir) {
        let dir = acme_proxy_core::testutil::TempDir::new("signer");
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

    /// The dependencies a backend is built from, none of which these tests are
    /// about. `egress` carries a fixed identity, so a case that wants to prove
    /// `[dns]`/`[proxy]` reach the identity key overrides it deliberately.
    async fn parts() -> SignerParts {
        crate::testutil::signer_parts(database().await, test_resolver())
    }

    /// `parts()` with a different egress identity — what a reload that changed
    /// `dns.resolver` or `[proxy]` hands `build_backends`.
    async fn parts_with_egress(identity: &str) -> SignerParts {
        let mut parts = parts().await;
        parts.egress = Arc::new(acme_proxy_net::egress::Egress {
            resolver: test_resolver(),
            proxies: acme_proxy_net::testutil::no_proxies(),
            identity: identity.to_string(),
        });
        parts
    }

    fn profile(name: &str, signer: SignerConfig) -> acme_proxy_core::config::ProfileConfig {
        acme_proxy_core::config::ProfileConfig {
            name: name.to_string(),
            sections: acme_proxy_core::config::ProfileSections {
                signer,
                ..acme_proxy_core::config::ProfileSections::default()
            },
        }
    }

    /// A configuration that did not move is **not rebuilt**: the reload gets the
    /// very same instance back.
    ///
    /// The ordinary case, and the one that matters most for cost — most reloads
    /// touch `[filter]` or `[notify]` and leave every signer alone, and
    /// rebuilding one there would re-read a CA key and, under
    /// `key_source = "pkcs11"`, log in to a token again per `SIGHUP`.
    ///
    /// `Arc::ptr_eq` against the *previous* set is the only assertion that can
    /// tell reuse from a rebuild that happened to adopt everything: both produce
    /// a backend that behaves identically.
    #[tokio::test]
    async fn a_configuration_that_did_not_move_is_reused_rather_than_rebuilt() {
        let (cfg, _dir) = config("local_ca");
        let profiles = vec![profile("le", cfg)];

        let parts = parts().await;
        let first = build_backends(&profiles, &parts, &SignerSet::default()).unwrap();
        let second = build_backends(&profiles, &parts, &first).unwrap();

        assert!(
            Arc::ptr_eq(first.get("le").unwrap(), second.get("le").unwrap()),
            "an unchanged `[signer]` must hand back the running instance"
        );
    }

    /// A configuration that *did* move is rebuilt — and the new instance shares
    /// the old one's revocation ledger.
    ///
    /// A backend rebuilt by a reload serves what the outgoing one revoked.
    /// Proven through the CRL rather than by inspecting the table: a
    /// revocation recorded on the outgoing backend is visible in the incoming
    /// one's CRL, which is what an operator would notice if it were not.
    #[tokio::test]
    async fn an_edited_configuration_is_rebuilt_over_the_same_revocations() {
        let (cfg, _dir) = config("local_ca");
        let parts = parts().await;
        let running =
            build_backends(&[profile("le", cfg.clone())], &parts, &SignerSet::default()).unwrap();

        // Something to lose: a certificate issued and revoked by the instance
        // that is about to be replaced.
        let outgoing = running.get("le").unwrap().clone();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let chain = match outgoing
            .issue(
                "ord-1",
                csr.der(),
                &[Identifier::dns("example.com")],
                RequestedValidity::default(),
            )
            .await
            .unwrap()
        {
            IssueOutcome::Issued(chain) => chain,
            IssueOutcome::Processing => panic!("local_ca issues synchronously"),
        };
        let leaf = acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap();
        outgoing.revoke(&leaf, Some(1)).await.unwrap();
        let before = crate::testutil::served_crl(outgoing.as_ref()).await;

        // The operator edits one key of `[signer]` and signals.
        let mut edited = cfg;
        edited.local_ca.leaf_validity_days = 30;
        let reloaded = build_backends(&[profile("le", edited)], &parts, &running).unwrap();

        let incoming = reloaded.get("le").unwrap();
        assert!(
            !Arc::ptr_eq(&outgoing, incoming),
            "an edited `[signer]` must really be rebuilt, or the edit did nothing"
        );
        assert_eq!(
            crate::testutil::served_crl(incoming.as_ref()).await,
            before,
            "the rebuilt CA must serve the same CRL, revocations and all",
        );

        // And a revocation landing on the outgoing instance after the
        // replacement was built — the window between building and publishing
        // it — still reaches the replacement.
        let second = params.serialize_request(&key_pair).unwrap();
        let chain = match outgoing
            .issue(
                "ord-2",
                second.der(),
                &[Identifier::dns("example.com")],
                RequestedValidity::default(),
            )
            .await
            .unwrap()
        {
            IssueOutcome::Issued(chain) => chain,
            IssueOutcome::Processing => unreachable!(),
        };
        let leaf = acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap();
        outgoing.revoke(&leaf, None).await.unwrap();
        assert_ne!(
            crate::testutil::served_crl(incoming.as_ref()).await,
            before,
            "a revocation landing on the outgoing instance mid-reload must reach \
             the incoming one",
        );
    }

    /// `[dns]` and `[proxy]` are not `[signer]` keys, but a change to either
    /// still rebuilds every backend.
    ///
    /// This is the whole reason those two keys could come off `reload::FROZEN`.
    /// A backend caches the resolver and proxy policy it was built with, so
    /// reuse keyed on `[signer]` alone would leave a `dns.resolver` edit
    /// applying to every subsystem *except* the signers, silently.
    #[tokio::test]
    async fn a_changed_egress_rebuilds_a_backend_whose_signer_section_did_not_move() {
        let (cfg, _dir) = config("local_ca");
        let profiles = vec![profile("le", cfg)];

        let first = build_backends(
            &profiles,
            &parts_with_egress("before").await,
            &SignerSet::default(),
        )
        .unwrap();
        let second = build_backends(&profiles, &parts_with_egress("after").await, &first).unwrap();

        assert!(
            !Arc::ptr_eq(first.get("le").unwrap(), second.get("le").unwrap()),
            "a moved `[dns]`/`[proxy]` must reach the signers, which cache it",
        );
    }

    /// A profile mounted by a reload gets a backend; one unmounted leaves its
    /// backend behind, and it is not carried into the next generation.
    ///
    /// Between them these are "mount an endpoint without a restart", which was
    /// the visible half of the whole freeze.
    #[tokio::test]
    async fn mounting_and_unmounting_a_profile_adds_and_drops_its_backend() {
        let (first_cfg, _first_dir) = config("local_ca");
        let (second_cfg, _second_dir) = config("local_ca");

        let parts = parts().await;
        let one = build_backends(
            &[profile("le", first_cfg.clone())],
            &parts,
            &SignerSet::default(),
        )
        .unwrap();
        assert_eq!(one.len(), 1);

        let two = build_backends(
            &[
                profile("le", first_cfg),
                profile("staging", second_cfg.clone()),
            ],
            &parts,
            &one,
        )
        .unwrap();
        assert_eq!(two.len(), 2, "the new endpoint got a backend of its own");
        assert!(
            Arc::ptr_eq(one.get("le").unwrap(), two.get("le").unwrap()),
            "and the endpoint that was already running kept its instance"
        );

        let back_to_one = build_backends(&[profile("staging", second_cfg)], &parts, &two).unwrap();
        assert_eq!(back_to_one.len(), 1);
        assert!(back_to_one.get("le").is_none(), "the endpoint is unmounted");
        assert!(
            Arc::ptr_eq(
                two.get("staging").unwrap(),
                back_to_one.get("staging").unwrap()
            ),
            "the survivor is untouched by its neighbour going away"
        );
    }

    /// A rebuild over *different* files is a different CA, and serves none of
    /// the old one's revocations.
    ///
    /// The safety half of keying revocation state on the CA's key: an operator
    /// repointing a profile at a second CA must get that CA's revocation
    /// history, not the first one's.
    #[tokio::test]
    async fn a_backend_rebuilt_over_different_files_adopts_nothing() {
        let (cfg, _dir) = config("local_ca");
        let parts = parts().await;
        let running = build_backends(&[profile("le", cfg)], &parts, &SignerSet::default()).unwrap();

        let outgoing = running.get("le").unwrap().clone();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let IssueOutcome::Issued(chain) = outgoing
            .issue(
                "ord-1",
                csr.der(),
                &[Identifier::dns("example.com")],
                RequestedValidity::default(),
            )
            .await
            .unwrap()
        else {
            panic!("local_ca issues synchronously")
        };
        outgoing
            .revoke(
                &acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap(),
                None,
            )
            .await
            .unwrap();

        let (elsewhere, _other_dir) = config("local_ca");
        let reloaded = build_backends(&[profile("le", elsewhere)], &parts, &running).unwrap();

        assert_ne!(
            crate::testutil::served_crl(reloaded.get("le").unwrap().as_ref()).await,
            crate::testutil::served_crl(outgoing.as_ref()).await,
            "a different CA key is a different issuer with its own revocations",
        );
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

        let backends = build_backends(&profiles, &parts().await, &SignerSet::default()).unwrap();
        assert_eq!(backends.len(), 1);
        assert!(
            Arc::ptr_eq(backends.get("a").unwrap(), backends.get("b").unwrap()),
            "one configuration must mean one instance"
        );
    }

    #[tokio::test]
    async fn differing_signer_configuration_yields_separate_backends() {
        let (first, dir_a) = config("local_ca");
        let (second, dir_b) = config("local_ca");
        let profiles = vec![profile("a", first), profile("b", second)];

        let backends = build_backends(&profiles, &parts().await, &SignerSet::default()).unwrap();
        assert!(
            !Arc::ptr_eq(backends.get("a").unwrap(), backends.get("b").unwrap()),
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
        let error = match build_backends(&profiles, &parts().await, &SignerSet::default()) {
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

        let error = match build_backends(&profiles, &parts().await, &SignerSet::default()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an unknown backend is a startup error"),
        };
        assert!(error.contains("profile `le`"), "{error}");
    }

    #[tokio::test]
    async fn builds_the_local_ca_backend_and_it_can_issue() {
        let (cfg, _dir) = config("local_ca");
        let signer = from_config(&cfg, &parts().await).expect("local_ca is a known backend");

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
        let dir = acme_proxy_core::testutil::TempDir::new("signer");
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
            custom: acme_proxy_core::config::CustomSignerConfig {
                script_path: script_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..SignerConfig::default()
        };
        let signer = from_config(&cfg, &parts().await).expect("custom is a known backend");

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
        let signer = from_config(&cfg, &parts().await).unwrap();
        assert!(matches!(
            signer.info().renewal_info(&[0x30, 0x00]).await,
            Ok(None)
        ));
    }

    /// A typo in `signer.backend` stops the server rather than silently leaving
    /// it unable to issue.
    #[tokio::test]
    async fn an_unknown_backend_is_a_startup_error() {
        let (cfg, _dir) = config("hashicorp-vault");
        // `Arc<dyn SignerBackend>` is not `Debug`, so `unwrap_err` is unavailable.
        let error = match from_config(&cfg, &parts().await) {
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
        let error = match from_config(&cfg, &parts().await) {
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

    /// The two ways to build a read side describe one CA: what every role
    /// builds from configuration serves the same anchor and routes revocations
    /// to the same issuer as what the worker's own backend hands out.
    ///
    /// Without this the suites — which derive the read side from an in-memory
    /// backend — could pass while production, which reads `cert_path`, served
    /// something else.
    #[tokio::test]
    async fn info_from_config_agrees_with_the_backends_own_info() {
        let (cfg, _dir) = config("local_ca");
        let parts = parts().await;
        let backend = from_config(&cfg, &parts).unwrap();
        let from_config = info_from_config(&cfg, &parts).unwrap();

        assert_eq!(
            from_config.ca_chain_pem().await,
            backend.info().ca_chain_pem().await
        );
        assert_eq!(
            from_config.revocation_route(),
            backend.info().revocation_route()
        );
        assert!(matches!(
            from_config.revocation_route(),
            RevocationRoute::Ledger { .. }
        ));
        assert_eq!(
            from_config.revocation_route(),
            revocation_route(&cfg).unwrap(),
            "the CLI's route and the served one agree"
        );

        // Both serve the CRL the backend stored, once it has stored one.
        let served = crate::testutil::served_crl(backend.as_ref()).await;
        assert_eq!(from_config.crl_der().await.unwrap().unwrap(), served);
    }

    /// The read side never signs: before any worker has stored this CA's first
    /// CRL it answers an error — not the `404` of a CA with none — and leaves
    /// the table as it found it.
    #[tokio::test]
    async fn a_read_side_with_no_stored_crl_answers_an_error_and_signs_nothing() {
        let (cfg, _dir) = config("local_ca");
        let parts = parts().await;
        // Generates the CA files, and touches no table.
        from_config(&cfg, &parts).unwrap();
        let info = info_from_config(&cfg, &parts).unwrap();

        let error = info.crl_der().await.unwrap_err().to_string();
        assert!(error.contains("no stored CRL"), "{error}");
        let RevocationRoute::Ledger { issuer } = info.revocation_route() else {
            panic!("a local CA routes to its ledger")
        };
        let mut tx = parts.database.transaction().await.unwrap();
        assert!(
            acme_proxy_store::crl::StoredCrl::find(&issuer, &mut *tx)
                .await
                .unwrap()
                .is_none(),
            "reading must not store a CRL"
        );
    }

    /// A process that builds only the read side and finds no CA says how to
    /// make one, and never makes one itself.
    #[tokio::test]
    async fn a_read_side_without_a_ca_certificate_names_init() {
        let (cfg, _dir) = config("local_ca");
        let error = match info_from_config(&cfg, &parts().await) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("no CA certificate exists yet"),
        };
        assert!(error.contains("acme-proxy init"), "{error}");
        assert!(error.contains("worker"), "{error}");
        assert!(
            !std::path::Path::new(&cfg.local_ca.key_path).exists(),
            "the read side must never generate a key"
        );
        assert!(!std::path::Path::new(&cfg.local_ca.cert_path).exists());
    }

    /// The two delegating backends route every revocation to the process that
    /// holds them, and publish no anchor of their own.
    #[tokio::test]
    async fn a_delegating_read_side_routes_revocations_to_the_backend() {
        let (mut cfg, _dir) = config("custom");
        cfg.custom.script_path = "/bin/true".to_string();
        let info = info_from_config(&cfg, &parts().await).unwrap();
        assert_eq!(info.revocation_route(), RevocationRoute::Delegated);
        assert!(info.ca_chain_pem().await.is_none());
        assert!(info.http01_tokens().is_none());

        let (mut cfg, _dir) = config("relay");
        cfg.relay.directory_url = "https://127.0.0.1:1/directory".to_string();
        cfg.relay.challenge_strategy = "http01".to_string();
        // Contacts nothing: the directory is discovered on first use.
        let info = info_from_config(&cfg, &parts().await).unwrap();
        assert_eq!(info.revocation_route(), RevocationRoute::Delegated);
        assert!(info.http01_tokens().is_some());
        assert!(
            info.renewal_info(&[0x30, 0x00]).await.is_err(),
            "an unreachable upstream is an error the handler falls back from"
        );

        cfg.relay.directory_url = String::new();
        assert!(info_from_config(&cfg, &parts().await).is_err());
        let (cfg, _dir) = config("hashicorp-vault");
        let error = match info_from_config(&cfg, &parts().await) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an unknown backend has no read side"),
        };
        assert!(error.contains("unknown signer backend"), "{error}");
    }

    /// Read sides follow the backends' reuse rule: an unmoved configuration
    /// keeps its instance, an edited one gets a new one.
    #[tokio::test]
    async fn read_sides_are_reused_like_backends() {
        let (cfg, _dir) = config("local_ca");
        let parts = parts().await;
        from_config(&cfg, &parts).unwrap();

        let first =
            build_infos(&[profile("le", cfg.clone())], &parts, &SignerSet::default()).unwrap();
        let second = build_infos(&[profile("le", cfg.clone())], &parts, &first).unwrap();
        assert!(Arc::ptr_eq(
            first.get("le").unwrap(),
            second.get("le").unwrap()
        ));

        let mut edited = cfg;
        edited.local_ca.leaf_validity_days = 30;
        let third = build_infos(&[profile("le", edited)], &parts, &second).unwrap();
        assert!(!Arc::ptr_eq(
            second.get("le").unwrap(),
            third.get("le").unwrap()
        ));
        assert_eq!(third.by_profile().len(), 1);
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

#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
