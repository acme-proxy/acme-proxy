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
//!
//! ## A backend outlives the configuration it was built from
//!
//! A configuration reload rebuilds nearly everything (see [`crate::reload`]),
//! but a backend that is still configured exactly as it was is **reused
//! verbatim** — see [`build_backends`], which keys on the configuration's own
//! `Debug` rendering. Only a backend whose configuration actually moved is
//! constructed again, and that one adopts the previous instance's in-memory
//! state through [`CarriedState`]. Both halves matter: without the reuse every
//! `SIGHUP` would re-read a CA key and re-open a PKCS#11 session for nothing,
//! and without the adoption a rebuilt backend would start with an empty
//! revocation ledger and an empty `http-01` token store.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::config::SignerConfig;
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

/// In-memory state a signer backend owns that has no durable home, carried from
/// one configuration generation to the next.
///
/// Keyed by the **resource** the state describes — a `crl_path`, a relay account
/// key path — never by profile name and never by configuration identity. That
/// choice is the whole safety argument: a backend rebuilt over the same files is
/// the same CA and must not start with an empty ledger, while one rebuilt over
/// *different* files must never adopt state describing somebody else's. A key
/// cannot collide, because [`signer_paths`] already refuses two live backends
/// over one path.
///
/// A map of `Arc<dyn Any>` rather than an enum naming each backend's internals,
/// so `signer/mod.rs` keeps knowing nothing about what a backend holds — the
/// same line [`SignerBackend::crl_der`] and [`SignerBackend::http01_tokens`]
/// draw. And a map of *state* rather than a `fn adopt(&self, previous: &dyn
/// SignerBackend)`, which would need every backend downcast to itself and would
/// still have to answer "is that previous backend the same thing I am?" — a
/// question the key already answers, in the open, one resource at a time.
#[derive(Default)]
pub struct CarriedState(HashMap<String, Arc<dyn Any + Send + Sync>>);

impl CarriedState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Offers `value` to whichever backend is built over `resource` next.
    pub fn insert<T: Any + Send + Sync>(&mut self, resource: String, value: Arc<T>) {
        self.0.insert(resource, value);
    }

    /// Takes the state recorded for `resource`, if the previous generation left
    /// any *and* it is of the expected type.
    ///
    /// A type mismatch answers `None` rather than panicking: it can only mean a
    /// backend changed kind over one path (a `local_ca` where a `relay` used to
    /// be), which is a legitimate reload and should start from disk, not abort.
    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self, resource: &str) -> Option<Arc<T>> {
        self.0.get(resource)?.clone().downcast::<T>().ok()
    }

    /// Folds another backend's contribution in.
    pub fn absorb(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// The resources this state covers, for a caller that wants to log what it
    /// is carrying.
    #[must_use]
    pub fn resources(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.0.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
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

    /// The certificates a client needs to trust what this backend issues, PEM
    /// encoded, anchor last — served unauthenticated at `GET /ca.pem`.
    ///
    /// `None` means the backend has no trust anchor of its own to hand out, and
    /// the route answers `404`. That is the honest answer for both delegating
    /// backends: [`relay`]'s anchor belongs to the upstream CA and is published
    /// wherever that CA chooses, and a `custom` script's is wherever its
    /// operator put it. Only [`local_ca::LocalCa`] overrides this, which is
    /// also the only backend that generates an anchor nothing else knows about
    /// — the case where "fetch it over HTTP" is the difference between one
    /// `curl` and finding a file on the server's disk.
    ///
    /// A getter on the trait for the same reason
    /// [`crl_der`](SignerBackend::crl_der) is one.
    async fn ca_chain_pem(&self) -> Option<String> {
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

    /// This backend's in-flight issuances, as the process-wide relay handler
    /// sees them, if it resolves issuance asynchronously at all.
    ///
    /// Only a backend whose work outlives the request that started it has
    /// anything to hand over; a synchronous backend like [`local_ca::LocalCa`]
    /// never has a half-finished issuance, so the default is `None`.
    ///
    /// **State, not a [`JobHandler`](crate::jobs::JobHandler)** — the same
    /// distinction, and for the same reason, as
    /// [`crl_pruner`](SignerBackend::crl_pruner) above. This method replaced a
    /// `jobs()` returning one handler per backend, which made two profiles
    /// relaying to *different* upstreams — two backends, since
    /// [`build_backends`] deliberately does not collapse them — a startup
    /// error, `JobRegistry::register` refusing the second handler for
    /// `signer_relay_issue`. `cli::build_generation` now builds one
    /// [`relay::flow::RelayJob`] over every relay profile in the process, which
    /// picks the backend per row from the profile the row names.
    ///
    /// There is deliberately no general "here are my job handlers" hook left on
    /// this trait: every one it could return has this problem, and a subsystem
    /// that wants a queue registers one handler covering every backend of its
    /// kind. Recovery is a case of that queue rather than a mechanism of its own
    /// — see [`crate::jobs::JobHandler::recover`].
    fn relay_state(&self) -> Option<relay::RelayState> {
        None
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

    /// This backend's revocation ledger, if it keeps one that grows and can be
    /// swept (RFC 5280 §3.3).
    ///
    /// A getter handing over *state* rather than a
    /// [`JobHandler`](crate::jobs::JobHandler), and the distinction is not
    /// cosmetic: [`crate::jobs::JobRegistry::register`] refuses two handlers for
    /// one `kind`, and two profiles with *different* `[signer.local_ca]`
    /// sections are two distinct backends — so a handler returned from here
    /// would make a supported configuration a startup error. Handing over the
    /// state instead lets `cli::build_generation` build one handler over every
    /// CA in the process, the shape
    /// [`http01_tokens`](SignerBackend::http01_tokens) already has for the same
    /// reason. [`relay_state`](SignerBackend::relay_state) below is the second
    /// method of this shape, and the trait deliberately has no third form: a
    /// backend never returns a handler of its own.
    ///
    /// Only [`local_ca::LocalCa`] overrides it, and only when it has files to
    /// persist to. The delegating backends have no ledger of their own — the
    /// upstream or the script keeps it.
    fn crl_pruner(&self) -> Option<Arc<dyn CrlPruner>> {
        None
    }

    /// What this backend hands to whichever backend replaces it on a
    /// configuration reload, keyed by the resource each piece describes.
    ///
    /// A getter on the trait for the fourth time and for the same reason as
    /// [`crl_der`](SignerBackend::crl_der) and
    /// [`relay_state`](SignerBackend::relay_state): what a backend owns is the
    /// backend's own business. The default is empty,
    /// which is the honest answer for [`custom::CustomScriptSigner`] — it holds
    /// nothing between calls — and for any state that already has a durable
    /// home.
    ///
    /// **Durability is not the test, though; a race is.** `local_ca`'s ledger
    /// *is* persisted, and it is still carried, because a revocation landing on
    /// the outgoing instance between the incoming one's read of the sidecar and
    /// the swap would otherwise be lost. Sharing the `Arc` means both instances
    /// see one ledger for the whole window, so there is nothing to diverge.
    fn carried_state(&self) -> CarriedState {
        CarriedState::default()
    }
}

/// One backend's revocation ledger, as the periodic sweep sees it.
///
/// Deliberately narrow: the sweep has no business knowing what a `LocalCa` is,
/// and this is the whole of what it needs — something to name in a log line and
/// something to call. See [`SignerBackend::crl_pruner`] for why the state
/// travels rather than a [`JobHandler`](crate::jobs::JobHandler).
#[async_trait]
pub trait CrlPruner: Send + Sync {
    /// Which ledger this is, for logging. The same
    /// [`CarriedState`] key the reload path files it under, so one CA reads as
    /// one resource wherever it is named.
    fn state_key(&self) -> String;

    /// Drops entries whose certificates have expired and re-signs the CRL if
    /// any went, returning how many. Must be cheap and write nothing when
    /// there was nothing to drop — it runs daily on every CA in the process.
    async fn prune_expired(&self) -> Result<usize, SignerError>;
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
/// A struct for [`ProfileParts`](crate::ProfileParts)' reason: [`from_config`]
/// took seven positional parameters and needed an eighth for [`CarriedState`],
/// which is where a reader starts counting commas and clippy starts complaining.
/// Taken by reference and cloned field by field, since [`build_backends`] calls
/// [`from_config`] in a loop.
///
/// `database` is for the backends that resolve issuance asynchronously: they own
/// the `Order` update once the answer arrives, long after the handler that asked
/// for it returned. `local_ca` ignores it. `notifiers` is the same kind of
/// dependency for the same reason — a backend whose completion happens in a
/// background task has no `Profile`/`AppState` to reach a notifier through, so it
/// is handed the whole `profile name -> dispatcher` map and looks up the right
/// one by `Order.profile` once it has something to report. It arrives as
/// [`crate::notify::Notifiers`] rather than a bare `Arc` because a backend
/// outlives the generation that built it while the map does not: a captured
/// `Arc` would pin the backend to the dispatchers that existed when it was
/// constructed.
#[derive(Clone)]
pub struct SignerParts {
    pub database: Arc<Database>,
    pub notifiers: crate::notify::Notifiers,
    pub metrics: Arc<crate::metrics::Metrics>,
    /// This generation's outbound plumbing **and** the configuration identity of
    /// it, held whole rather than as a bare
    /// [`Outbound`](crate::http_client::Outbound). The two cannot then disagree,
    /// and a value that disagreed would make a `dns.resolver` edit a silent
    /// no-op for every signer — see [`build_backends`].
    pub egress: Arc<crate::Egress>,
    pub jobs: crate::jobs::JobQueue,
}

/// Builds the configured signer backend, adopting whatever the generation before
/// it left for this backend's own resources.
///
/// Called at startup and again for any backend a reload rebuilds; a failure is
/// fatal to whichever of the two it is (the process exits, or the reload is
/// refused with the running generation untouched).
pub fn from_config(
    cfg: &SignerConfig,
    parts: &SignerParts,
    carried: &CarriedState,
) -> anyhow::Result<Arc<dyn SignerBackend>> {
    match cfg.backend.as_str() {
        "local_ca" => Ok(Arc::new(local_ca::LocalCa::load_or_generate(
            &cfg.local_ca,
            carried,
        )?)),
        // The one backend handed the metrics registry, because it is the one
        // that finishes an issuance from a background task: `post_finalize`
        // answered `processing` and returned, so no `Auditor` — and no request
        // — is in scope when the certificate actually arrives.
        "relay" => Ok(Arc::new(relay::RelaySigner::from_config(
            &cfg.relay, parts, carried,
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

/// The backends one configuration generation runs, in the two views that are
/// needed of them.
///
/// `by_profile` is what a [`Profile`](crate::Profile) is handed and the only
/// thing that serves a request. `by_identity` exists purely so the **next**
/// reload can ask "is this one already built?" — see [`build_backends`], where
/// answering yes is what keeps a `SIGHUP` from re-reading a CA key and
/// re-opening a PKCS#11 session for a configuration that did not move.
#[derive(Default, Clone)]
pub struct SignerSet {
    by_profile: HashMap<String, Arc<dyn SignerBackend>>,
    by_identity: HashMap<String, Arc<dyn SignerBackend>>,
}

impl SignerSet {
    /// The backend serving `profile`, if that endpoint is mounted.
    #[must_use]
    pub fn get(&self, profile: &str) -> Option<&Arc<dyn SignerBackend>> {
        self.by_profile.get(profile)
    }

    /// How many distinct backend instances this set holds — one per distinct
    /// `[signer]` configuration, not one per profile.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }

    /// Everything these backends would hand to their replacements, folded into
    /// one map.
    ///
    /// Folded across *all* of them rather than matched backend to backend,
    /// because the keys are resources and [`signer_paths`] already refuses two
    /// live backends over one path — so a rebuilt backend finds its own state by
    /// naming its own files, and no ownership analysis is needed here.
    #[must_use]
    pub fn carried(&self) -> CarriedState {
        let mut carried = CarriedState::new();
        for backend in self.by_identity.values() {
            carried.absorb(backend.carried_state());
        }
        carried
    }
}

/// Builds one backend per profile, **sharing** the instance between profiles
/// whose signer configuration is identical, and **reusing** the instance the
/// previous generation built for a configuration that has not moved.
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
///
/// Reuse is the same requirement in the time dimension, and `previous` is what
/// makes a reload able to touch this at all. Three outcomes per distinct
/// configuration:
///
/// 1. **Already built** — the very same `Arc` comes back. Nothing is adopted
///    because nothing is constructed; this is the ordinary case, since most
///    reloads touch `[filter]` or `[notify]` and leave every signer alone.
/// 2. **New** — built, and handed everything the outgoing generation offered
///    ([`SignerSet::carried`]). This covers both a profile mounted for the first
///    time and a live profile whose `[signer]` an operator edited.
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
    profiles: &[crate::config::ProfileConfig],
    parts: &SignerParts,
    previous: &SignerSet,
) -> anyhow::Result<SignerSet> {
    let key_of = |cfg: &SignerConfig| format!("{cfg:?}|{}", parts.egress.identity);

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

    // Gathered once, before anything is built: a backend rebuilt over the same
    // files must find the live ledger, and the outgoing instances are still
    // holding it at this point — which is the whole reason the handover is a
    // shared `Arc` and not a copy.
    let carried = previous.carried();

    let mut set = SignerSet::default();
    for profile in profiles {
        let key = key_of(&profile.sections.signer);
        let backend = match (set.by_identity.get(&key), previous.by_identity.get(&key)) {
            (Some(backend), _) => backend.clone(),
            (None, Some(backend)) => {
                debug!(
                    event = "signer_backend_reused",
                    outcome = "success",
                    profile = %profile.name,
                    "the configuration did not move, so the running backend is carried \
                     whole rather than rebuilt"
                );
                let backend = backend.clone();
                set.by_identity.insert(key, backend.clone());
                backend
            }
            (None, None) => {
                let backend = from_config(&profile.sections.signer, parts, &carried)
                    .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                set.by_identity.insert(key, backend.clone());
                backend
            }
        };
        set.by_profile.insert(profile.name.clone(), backend);
    }
    Ok(set)
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
        parts.egress = Arc::new(crate::Egress {
            resolver: test_resolver(),
            proxies: crate::testutil::no_proxies(),
            identity: identity.to_string(),
        });
        parts
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
    /// The whole point of [`CarriedState`]. Proven through the CRL rather than
    /// by inspecting the ledger: a revocation recorded on the outgoing backend
    /// is visible in the incoming one's CRL, which is what an operator would
    /// notice if it were not.
    #[tokio::test]
    async fn an_edited_configuration_is_rebuilt_over_the_running_ledger() {
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
        let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
        outgoing.revoke(&leaf, Some(1)).await.unwrap();
        let before = outgoing.crl_der().await.expect("a local CA has a CRL");

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
            incoming.crl_der().await.expect("a local CA has a CRL"),
            before,
            "the rebuilt CA must serve the same CRL, ledger and all",
        );

        // And the sharing is live in both directions, which is what closes the
        // window between building the replacement and publishing it.
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
        let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
        outgoing.revoke(&leaf, None).await.unwrap();
        assert_ne!(
            incoming.crl_der().await.unwrap(),
            before,
            "a revocation landing on the outgoing instance mid-reload must reach \
             the incoming one — that is the case reading the sidecar back cannot cover",
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

    /// A rebuild over *different* files starts from those files, never from the
    /// state describing the old ones.
    ///
    /// The safety half of keying [`CarriedState`] on a resource: an operator
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
            .revoke(&crate::cert::leaf_der_from_chain(&chain).unwrap(), None)
            .await
            .unwrap();

        let (elsewhere, _other_dir) = config("local_ca");
        let reloaded = build_backends(&[profile("le", elsewhere)], &parts, &running).unwrap();

        assert_ne!(
            reloaded.get("le").unwrap().crl_der().await.unwrap(),
            outgoing.crl_der().await.unwrap(),
            "a different `crl_path` is a different CA and starts from its own sidecar",
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
        let signer = from_config(&cfg, &parts().await, &CarriedState::new())
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
        let signer = from_config(&cfg, &parts().await, &CarriedState::new())
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
        let signer = from_config(&cfg, &parts().await, &CarriedState::new()).unwrap();
        assert!(matches!(signer.renewal_info(&[0x30, 0x00]).await, Ok(None)));
    }

    /// A typo in `signer.backend` stops the server rather than silently leaving
    /// it unable to issue.
    #[tokio::test]
    async fn an_unknown_backend_is_a_startup_error() {
        let (cfg, _dir) = config("hashicorp-vault");
        // `Arc<dyn SignerBackend>` is not `Debug`, so `unwrap_err` is unavailable.
        let error = match from_config(&cfg, &parts().await, &CarriedState::new()) {
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
        let error = match from_config(&cfg, &parts().await, &CarriedState::new()) {
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
