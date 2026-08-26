// Feature badges on docs.rs. Turned on by `--cfg docsrs` from
// `[package.metadata.docs.rs]`, so a stable `cargo doc`, `cargo build` and
// clippy never see this nightly-only attribute. `doc_cfg` annotates every
// `#[cfg(…)]` item on its own, so the `hsm`-gated items need no per-item
// attribute and a future one is covered for free — the behaviour that used to
// be a separate `doc_auto_cfg` feature, removed in 1.92 and merged into this
// one. Do not reintroduce that name; it no longer compiles.
#![cfg_attr(docsrs, feature(doc_cfg))]

//! ACME (RFC 8555) Server Implementation
//!
//! This is a server-side implementation of the ACME protocol (RFC 8555) for
//! issuing and managing SSL/TLS certificates. It serves as a backend for
//! certificate clients like certbot and acme.sh.
//!
//! ## Features
//!
//! - The full RFC 8555 flow: directory, newNonce, newAccount, account
//!   lookup/update and deactivation, newOrder, authorizations and challenges,
//!   finalize, certificate retrieval via signed POST-as-GET, and revocation
//! - JWS signature verification for EC (ES256) and RSA (RS256) keys
//! - Automatic nonce management with replay protection
//! - Challenge validation behind pluggable validators (`http-01`, `dns-01`,
//!   `tls-alpn-01`), with a configurable bypass
//! - Certificate issuance behind a pluggable signer backend: a local CA (whose
//!   key may live in a PKCS#11 token), a relay to an upstream ACME CA, or an
//!   operator-supplied script
//! - **Profiles** — several independent ACME endpoints in one process, each with
//!   its own signer, filters, challenge validators and EAB policy
//! - External Account Binding (§7.3.4), account key rollover (§7.3.5) and
//!   Renewal Information (RFC 9773)
//! - Access control behind a policy engine of named checks combined by boolean
//!   rules, including an IPAM lookup (NetBox, phpIPAM or a script) asking the
//!   inventory whether the client's own address owns the names it is requesting
//! - An append-only audit trail of every issuance *and every refusal*
//! - An optional web admin listener, and admin subcommands in the same binary
//! - Optional Prometheus metrics on a third listener of their own
//! - A durable job queue, so work the server owes itself survives a restart and
//!   an upstream blip is retried rather than invalidating a client's order
//! - Configuration reload on `SIGHUP` — a rebuild and a swap, with
//!   `database.url` the only key that still needs a restart
//! - `SQLite` persistence for accounts, nonces, orders and the audit trail
//! - Configurable via TOML, environment variables, or defaults
//!
//! ## Architecture
//!
//! The ACME request path, in the order a request meets it:
//! - [`middlewares`] - Server-wide layers: request correlation and the access
//!   line, admission control, the `Replay-Nonce` and `Link: rel="index"` headers
//! - [`filter`] - Pluggable request filtering (who may ask at all)
//! - [`extractors`] - Parse and validate ACME JWS requests, verifying the media
//!   type, the `crit` header, the signature, the JWS `url` and the nonce before
//!   any handler runs
//! - [`handlers`] - One module per ACME resource
//! - [`challenge`] - Pluggable challenge validators (http-01, dns-01, tls-alpn-01)
//! - [`signer`] - Pluggable certificate-issuance backends (local CA, ACME relay,
//!   custom script)
//!
//! Supporting subsystems:
//! - [`audit`] - The durable record of who asked this CA to sign or revoke
//! - [`notify`] - Pluggable operator notifications on lifecycle events (email,
//!   webhook, custom)
//! - [`ipam`] - The inventory [`filter`] asks which names an address owns
//!   (NetBox, phpIPAM, a custom script), behind one trait
//! - [`eab`] - Verification of the External Account Binding inner JWS (§7.3.4)
//! - [`key_change`] - Verification of account key rollover JWS (§7.3.5)
//! - [`dns`] - The resolver shared by every subsystem that looks anything up
//! - [`http_client`] - The transport every outbound HTTP client is built on,
//!   including the `CONNECT` tunnel
//! - [`proxy`] - Which forward proxy, if any, that transport dials through
//! - [`script_hook`] - The hardened contract every `custom` hook runs under
//! - [`tls`] - Optional HTTPS termination for either listener
//! - [`cert`] - X.509 parsing helpers (serial, SPKI, leaf-from-chain)
//! - [`pemfile`] - PEM reading, atomic writing and key-permission warnings
//! - [`sqlite`] - Database access, one module per table
//! - [`config`] - Configuration loading from multiple sources
//! - [`error`] - ACME error types and problem document rendering
//!
//! Process lifecycle — what keeps the server running and lets it be retuned
//! without a restart:
//! - [`listener`] - The sockets, and replacing one while it serves
//! - [`reload`] - Rebuild-and-swap on `SIGHUP`; nothing is mutated in place
//! - [`jobs`] - The durable queue and its runner, so work outlives the process
//!   that queued it
//! - [`metrics`] - The Prometheus registry and its text exposition
//!
//! Administration, which serves no ACME and is a second listener plus a CLI:
//! - [`admin`] - The operation layer both front ends dispatch to
//! - [`webadmin`] - The optional HTML + JSON admin listener
//! - [`cli`] - The `clap` command tree, and the startup path itself
//!
//! ## Usage
//!
//! The main entry point is `build_app()`, which mounts one ACME router per
//! configured profile under `/profile/<name>` and serves the server-level
//! routes (`/health`) at the root.
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use acme_proxy::{
//!     Profile, ProfileParts, build_app, challenge, config::Config, filter, ipam, jobs, notify,
//!     signer, sqlite::db::Database,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Arc::new(Config::load()?);
//!     let database = Arc::new(Database::connect(&config.database.url).await?);
//!
//!     let resolved = config.resolve_profiles()?;
//!     // The resolver and the proxy policy, resolved before anything can dial:
//!     // a proxy URL that cannot be understood must stop the process rather
//!     // than leave egress elsewhere, and `dns.resolver` governs every outbound
//!     // connection this server makes, not just challenge lookups. Bundled,
//!     // because every outbound client takes them together — and because the
//!     // rendering beside them is what tells a reload whether a signer backend
//!     // has to be rebuilt.
//!     let egress = Arc::new(acme_proxy::Egress::from_config(&config)?);
//!     let outbound = egress.outbound();
//!     // The enqueue side of the durable queue, built first because everything
//!     // below queues into it. A backend that defers issuance (`relay`) is
//!     // handed one at construction, and so is every notify dispatcher — a
//!     // notification is a job row too. The runner that drains it is started
//!     // separately, below.
//!     let job_queue = jobs::JobQueue::new(database.clone(), &config.jobs);
//!     // Built once, up front: an asynchronous signer backend (`relay`)
//!     // has no `Profile` to reach a notifier through from its background
//!     // completion task, so it is handed this whole map instead — and so is
//!     // the `NotifyJob` that performs the deliveries.
//!     let mut notifiers = std::collections::HashMap::new();
//!     for profile in &resolved {
//!         notifiers.insert(
//!             profile.name.clone(),
//!             notify::from_config(
//!                 &profile.name,
//!                 &profile.sections.notify,
//!                 outbound.clone(),
//!                 &job_queue,
//!             )?,
//!         );
//!     }
//!     let notifiers = Arc::new(notifiers);
//!     // The Prometheus counters. Built here rather than per generation, so a
//!     // `SIGHUP` does not reset every counter to zero — see `Assembly`.
//!     let metrics = Arc::new(acme_proxy::metrics::Metrics::new(database.clone()));
//!
//!     let mut profiles = Vec::new();
//!     for profile in &resolved {
//!         let sections = &profile.sections;
//!         profiles.push(Arc::new(Profile::new(
//!             &profile.name,
//!             &config.server.base_url,
//!             ProfileParts {
//!                 signer: signer::from_config(
//!                     &sections.signer,
//!                     vec![profile.name.clone()],
//!                     &signer::SignerParts {
//!                         database: database.clone(),
//!                         notifiers: notifiers.clone().into(),
//!                         metrics: metrics.clone(),
//!                         egress: egress.clone(),
//!                         jobs: job_queue.clone(),
//!                     },
//!                     // Nothing to adopt at startup; a reload passes what the
//!                     // previous generation's backends handed over.
//!                     &signer::CarriedState::new(),
//!                 )?,
//!                 filter: filter::from_config(
//!                     &sections.filter,
//!                     &config.dns,
//!                     ipam::from_config(&sections.ipam, outbound.clone())?,
//!                     sections.eab.enabled,
//!                 )?,
//!                 challenges: challenge::from_config(
//!                     &sections.challenge,
//!                     &config.dns,
//!                     egress.proxies.clone(),
//!                 )?,
//!                 order: sections.order.clone(),
//!                 eab: sections.eab.clone(),
//!                 meta: sections.meta.clone(),
//!                 notify: notifiers[&profile.name].clone(),
//!             },
//!         )));
//!     }
//!     // Process-wide, like `[audit]` itself: one trail for the whole CA,
//!     // shared by every profile's router and by the web admin listener.
//!     // The registry is a parameter rather than a builder step, so a serving
//!     // process cannot build an auditor that counts into nothing. The counters
//!     // come off the same `AuditRecord` the trail is written from, so the two
//!     // can never disagree.
//!     let audit = Arc::new(acme_proxy::audit::Auditor::from_config(
//!         &config.audit,
//!         &config.dns,
//!         database.clone(),
//!         metrics.clone(),
//!     )?);
//!     let app = build_app(
//!         database.clone(),
//!         config.clone(),
//!         profiles,
//!         audit,
//!         metrics.clone(),
//!     );
//!
//!     // One runner drains the queue for the process. Every handler comes from
//!     // a subsystem that has background work — `SignerBackend::jobs`,
//!     // notification delivery, and the periodic table sweeps — and the runner
//!     // calls `recover` on each before it claims anything, which is how work a
//!     // previous run left in flight is picked back up, and how each sweep's
//!     // single row gets queued.
//!     let mut registry = jobs::JobRegistry::new();
//!     registry.register(Arc::new(notify::NotifyJob::new(notifiers)))?;
//!     registry.register(Arc::new(jobs::SweepJob::nonces(
//!         database.clone(),
//!         std::time::Duration::from_secs(config.nonce.ttl_seconds),
//!     )))?;
//!     let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
//!     jobs::spawn_runner(job_queue, Arc::new(registry), &config.jobs, shutdown_rx);
//!
//!     let listener = tokio::net::TcpListener::bind(&config.server.bind_address).await?;
//!     axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
//!
//!     Ok(())
//! }
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, header};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    middleware::Next,
    response::Redirect,
    routing::{get, post},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{Span, info};

pub mod admin;
pub mod audit;
pub mod cert;
pub mod challenge;
pub mod cli;
pub mod config;
pub mod dns;
pub mod eab;
pub mod error;
pub mod extractors;
pub mod filter;
pub mod handlers;
pub mod http_client;
pub mod ipam;
pub mod jobs;
pub mod key_change;
pub mod listener;
pub mod metrics;
pub mod middlewares;
pub mod notify;
pub mod pemfile;
pub mod proxy;
mod random;
pub mod reload;
pub mod script_hook;
pub mod signer;
pub mod sqlite;
mod templating;
#[cfg(test)]
pub(crate) mod testutil;
pub mod tls;
pub mod webadmin;

use crate::challenge::ChallengeRegistry;
use crate::config::Config;
use crate::error::Problem;
use crate::filter::FilterPolicy;
use crate::notify::NotifyDispatcher;
use crate::signer::SignerBackend;
use crate::sqlite::db::Database;

// Re-export name shape helpers for backwards compatibility
pub use handlers::helpers::{is_wildcard, normalize_dns_name, well_formed_name};

/// The ACME resource paths, profile-relative.
///
/// One definition each, because they are written in three places that must
/// agree and previously agreed only by inspection: the router that *mounts*
/// them (`build_router`), the directory that *advertises* them
/// (`handlers::get_directory`), and `middlewares::nonce`, which singles out
/// `newNonce`. A directory advertising a path nothing serves is a client that
/// fails on its very first request, and nothing structural caught it.
///
/// Only the resources with a fixed path are here; the id-bearing ones
/// (`/acct/{id}`, `/order/{id}/finalize`, …) are never advertised, so they have
/// exactly one call site and gain nothing from a constant.
pub mod routes {
    pub const DIRECTORY: &str = "/directory";
    pub const NEW_NONCE: &str = "/newNonce";
    pub const NEW_ACCOUNT: &str = "/newAccount";
    pub const NEW_ORDER: &str = "/newOrder";
    pub const REVOKE_CERT: &str = "/revokeCert";
    pub const KEY_CHANGE: &str = "/keyChange";
    /// RFC 9773 §4.1 has the client append the certID, so the directory
    /// advertises this bare while the router mounts `{id}` under it.
    pub const RENEWAL_INFO: &str = "/renewalInfo";
    pub const CRL: &str = "/crl";
    /// The trust anchor a client installs to accept this profile's leaves.
    /// Routed beside [`CRL`] and, like it, deliberately not advertised in the
    /// directory — both are CA infrastructure rather than ACME resources.
    pub const CA_CHAIN: &str = "/ca.pem";
}

/// The URL namespace every ACME endpoint is mounted under: a profile named
/// `le` serves `/profile/le/directory`.
///
/// Reserved and fixed, which is the point — server-level routes live at the
/// root and a profile can never collide with one, now or when the next one is
/// added.
pub const PROFILE_PREFIX: &str = "/profile";

/// A duration in milliseconds, as a log field.
///
/// `Duration::as_millis` returns `u128`, which `tracing` has no primitive
/// visitor for and so records through `Display` — landing in the JSON output as
/// a quoted `"42"` rather than the number `42`. That output exists to be
/// aggregated by machines, and a latency field a collector has to re-parse (or
/// silently indexes as a string) is a defect in it. Every duration logged
/// anywhere in this crate goes through here.
///
/// The saturation is unreachable — `u64::MAX` milliseconds is some 584 million
/// years — and is written out only to avoid a silent truncating cast.
#[must_use]
pub fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// One ACME endpoint: its identity, its URLs, and the three subsystems that
/// answer for it.
///
/// Everything per-endpoint lives here rather than beside the global config in
/// [`AppState`], so a handler cannot pair one profile's signer with another's
/// base URL — the two always travel together.
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
    /// Lives here rather than in `cli::serve_on` because it is the assembly step,
    /// not dispatch: it resolves the profiles, builds the signer backends
    /// (deduplicated by configuration — see [`signer::build_backends`]), and
    /// gives each profile its own filter chain and challenge registry. Every
    /// failure is fatal at startup, so they come back as one error for the
    /// caller to report and exit on.
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
    /// the outgoing instance held (see [`signer::build_backends`]).
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

/// The outbound plumbing one configuration generation dials through, and the
/// identity of the configuration it came from.
///
/// `[dns]` and `[proxy]` are process-wide but no longer frozen, so they belong
/// to a *generation* rather than to the [`Assembly`]: a reload builds a fresh
/// resolver and proxy policy from the file, and every subsystem that reaches the
/// network is handed this generation's pair. The signer backends look like the
/// exception and are not — they cache what they were built with, so
/// [`signer::build_backends`] folds `identity` into a backend's identity key and
/// rebuilds any backend whose egress moved. Keeping the identity here rather
/// than beside the call site is what stops the two disagreeing, which would make
/// a `dns.resolver` edit a silent no-op for every signer.
pub struct Egress {
    /// Uncached, for the reason `challenge::build_resolver` explains: a client
    /// publishing a `dns-01` record moments before triggering must not be
    /// defeated by a cached negative answer.
    pub resolver: Arc<dyn dns::Resolver>,
    pub proxies: Arc<proxy::OutboundProxies>,
    /// `[dns]` and `[proxy]` rendered. Only ever compared to another one — never
    /// parsed, never shown — which is the same contract `signer::build_backends`
    /// keys a `[signer]` section on.
    pub identity: String,
}

impl Egress {
    /// Builds both clients from `config`.
    ///
    /// Fallible for two separate reasons worth keeping apart: a proxy URL that
    /// cannot be understood, and a `dns.resolver` that is not a socket address.
    /// Both must stop a startup and refuse a reload rather than degrade — a
    /// server that silently fell back to direct egress would dial around exactly
    /// the control its operator configured.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let proxies = crate::proxy::from_config(&config.proxy)?;
        // One resolver per generation, handed to every subsystem that makes an
        // outbound connection. `dns.resolver` is documented as "the nameserver
        // every DNS lookup this server makes goes through", and three of the
        // four HTTP clients used to bypass it — so an operator on a
        // split-horizon estate had NetBox and their upstream CA resolving
        // differently from the challenge validators, with nothing saying so.
        let resolver = challenge::build_resolver(crate::dns::resolver_addr(&config.dns)?)?;
        Ok(Self {
            resolver,
            proxies,
            identity: format!("{:?}|{:?}", config.dns, config.proxy),
        })
    }

    /// The resolver and proxy policy as one value, for the subsystems that make
    /// outbound HTTP requests.
    ///
    /// An accessor rather than a stored field: `challenge::from_config` builds
    /// its *own* resolver past the bypass branch (constructing one is what
    /// reads `/etc/resolv.conf`, so it must not happen when validation is off),
    /// and so needs the proxy half on its own.
    #[must_use]
    pub fn outbound(&self) -> http_client::Outbound {
        http_client::Outbound::new(self.resolver.clone(), self.proxies.clone())
    }
}

/// The three things one configuration generation contributes to its profiles,
/// built before any of them is published.
///
/// A struct because [`Profile::build_all_with`] would otherwise take three
/// same-shaped values positionally, and because the three are built together and
/// must be published together — `cli::apply_reload` swaps the notifier map and
/// the signer set in the same uninterruptible run as the routers built from
/// them.
pub struct GenerationParts {
    pub egress: Arc<Egress>,
    pub dispatchers: notify::DispatcherMap,
    pub signers: signer::SignerSet,
}

/// What survives a configuration reload.
///
/// Every generation rebuilds its profiles, its routers, its job registry, its
/// egress clients and any signer backend whose configuration moved. The things
/// here are built once for the life of the process and handed to each generation
/// instead — and after three rounds of moving things *off* this list, everything
/// left is here because rebuilding it would lose something, never because
/// rebuilding it would merely cost something:
///
/// - `database` and `jobs` are the pool and its enqueue side. `database.url` is
///   the one key [`crate::reload`] still refuses, and this is why.
/// - `metrics` is a **correctness** requirement. A registry rebuilt per
///   generation would reset every counter on `SIGHUP`, and a counter going
///   backwards is precisely how Prometheus recognises a process restart — so
///   `rate()` would report the whole pre-reload total as a spike on every
///   configuration change.
/// - `signers` is the *previous* generation's backend set, kept so the next
///   reload can reuse a backend whose configuration did not move and hand the
///   live in-memory state of one that did to its replacement (see
///   [`signer::CarriedState`]). Behind a `Mutex` because it is written once per
///   generation; nothing reads it to serve a request, since a `Profile` holds
///   its own `Arc<dyn SignerBackend>`.
/// - `notifiers` is a handle rather than a map, so `[notify]` can reload
///   underneath the backends that captured it.
///
/// `resolver` and `proxies` used to be here, justified by the signers caching
/// them at construction. They moved to [`Egress`] when that stopped being a
/// reason to freeze `[dns]`/`[proxy]` and became a reason to rebuild a signer.
pub struct Assembly {
    pub database: Arc<Database>,
    pub jobs: crate::jobs::JobQueue,
    pub metrics: Arc<metrics::Metrics>,
    pub notifiers: notify::Notifiers,
    notifiers_tx: notify::NotifiersSender,
    signers: std::sync::Mutex<signer::SignerSet>,
}

impl Assembly {
    /// Builds everything that outlives a generation, plus the first generation's
    /// own parts.
    ///
    /// Those come back rather than being kept here because they are *not*
    /// long-lived: the caller hands them to [`Profile::build_all_with`] and then
    /// forgets them, and every later generation builds its own through
    /// [`build_parts`](Self::build_parts).
    pub fn new(
        resolved: &[config::ProfileConfig],
        database: Arc<Database>,
        jobs: crate::jobs::JobQueue,
        config: &Config,
    ) -> anyhow::Result<(Self, GenerationParts)> {
        // Built before the signers, because the `relay` backend settles an
        // issuance from a background task that has no request and no `Auditor`,
        // so it counts that issuance through a handle it was given at
        // construction.
        let metrics = Arc::new(metrics::Metrics::new(database.clone()));
        // Opened over an empty map and republished immediately below, so the
        // handle the signers capture is the one every later generation writes
        // into.
        let (notifiers_tx, notifiers) = notify::notifiers_channel(notify::DispatcherMap::new());

        let assembly = Self {
            database,
            jobs,
            metrics,
            notifiers,
            notifiers_tx,
            signers: std::sync::Mutex::new(signer::SignerSet::default()),
        };
        let parts = assembly.build_parts(resolved, config)?;
        // The first generation's map has to reach the handle before anything
        // dispatches through it; every later one goes through `publish` in the
        // reload's own synchronous run.
        assembly.publish_notifiers(parts.dispatchers.clone());
        assembly.publish_signers(parts.signers.clone());
        Ok((assembly, parts))
    }

    /// Builds one generation's egress, dispatchers and signer backends, without
    /// publishing any of them.
    ///
    /// Separate from [`publish_notifiers`](Self::publish_notifiers) and
    /// [`publish_signers`](Self::publish_signers) because a reload must be able
    /// to fail *after* building all three and still leave the running generation
    /// untouched. Everything fallible is here; everything published is there.
    ///
    /// May block: `RelaySigner::from_config` contacts the upstream the first
    /// time it is built for an account with no `kid` sidecar yet, which is why
    /// `cli::supervise_reloads` runs this on a blocking thread.
    pub fn build_parts(
        &self,
        resolved: &[config::ProfileConfig],
        config: &Config,
    ) -> anyhow::Result<GenerationParts> {
        // Resolved before anything can dial: a proxy URL that cannot be
        // understood must stop the process, and the `relay` backend below makes
        // a real network call on its very first startup.
        let egress = Arc::new(Egress::from_config(config)?);
        // Built before the signer backends: the `relay` backend's background
        // completion task has no `Profile`/`AppState` to reach a notifier
        // through (it outlives any single request, the same reason it is handed
        // `database`), so it is instead handed the whole `profile name ->
        // dispatcher` map and looks up the right one by `Order.profile` once an
        // issuance settles.
        let dispatchers = notify::build_registry(resolved, egress.outbound(), &self.jobs)?;
        let previous = self
            .signers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let signers = signer::build_backends(
            resolved,
            &signer::SignerParts {
                database: self.database.clone(),
                notifiers: self.notifiers.clone(),
                metrics: self.metrics.clone(),
                egress: egress.clone(),
                jobs: self.jobs.clone(),
            },
            &previous,
        )?;

        Ok(GenerationParts {
            egress,
            dispatchers,
            signers,
        })
    }

    /// Makes `dispatchers` the generation every long-lived reader sees.
    ///
    /// Synchronous, and deliberately: it is one of the sends a reload makes
    /// back-to-back so no task can observe a half-swapped generation.
    pub fn publish_notifiers(&self, dispatchers: notify::DispatcherMap) {
        self.notifiers_tx.send_replace(Arc::new(dispatchers));
    }

    /// Records `signers` as what the *next* reload compares against, and drops
    /// whatever the generation before it held.
    ///
    /// That drop is the point at which a backend nobody references any more —
    /// an unmounted profile's, or the instance a `[signer]` edit replaced — is
    /// finally released. Deliberately after its replacement was built and has
    /// adopted its state, never before.
    pub fn publish_signers(&self, signers: signer::SignerSet) {
        *self
            .signers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = signers;
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

/// Shared application state handed to every route via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub database: Arc<Database>,
    /// Process-wide configuration only — `server`, `nonce`, `dns`, `logging`.
    /// Anything an endpoint can differ on is on [`AppState::profile`].
    pub config: Arc<Config>,
    pub profile: Arc<Profile>,
    /// The CA's audit trail. Beside `config` rather than on the profile,
    /// because `[audit]` is process-wide: the trail describes the CA, and the
    /// web admin writes to the same one across every endpoint it can revoke on.
    pub audit: Arc<audit::Auditor>,
}

/// Every distinct `http-01` token store across the mounted profiles.
///
/// Deduplicated by pointer: [`signer::build_backends`] already shares one
/// backend instance between profiles with identical `[signer]` sections, so
/// several profiles usually contribute the *same* store. Two profiles relaying
/// to two different upstreams contribute two, and the route consults both —
/// there is nothing to isolate, because the token is the upstream's own random
/// value and is itself the secret (RFC 8555 §8.3), so one merged view cannot
/// answer the wrong challenge.
fn http01_stores(profiles: &[Arc<Profile>]) -> Vec<Arc<dyn signer::Http01TokenStore>> {
    let mut stores: Vec<Arc<dyn signer::Http01TokenStore>> = Vec::new();
    for profile in profiles {
        if let Some(store) = profile.signer.http01_tokens()
            && !stores.iter().any(|existing| Arc::ptr_eq(existing, &store))
        {
            stores.push(store);
        }
    }
    stores
}

/// Builds the whole HTTP service: the server-level routes at the root, and one
/// ACME router per profile under `/profile/<name>`.
/// The three response-hardening headers **both** listeners apply.
///
/// A shared constructor rather than two copies: the admin router is not nested
/// inside [`build_app`] and so inherits none of its layers, but these three are
/// a security control, and two hand-written copies of one are a control that
/// drifts. Everything genuinely per-listener — the admin's `Cache-Control`,
/// `Referrer-Policy` and CSP, this one's admission and nonce layers — stays at
/// its own call site.
///
/// A tuple because `tower` implements [`Layer`](tower::Layer) for one, so the
/// three still apply as three separate layers rather than being collapsed into
/// a wrapper type. They set distinct headers, so their order among themselves
/// carries no meaning.
pub(crate) fn security_headers() -> (
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
) {
    (
        SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ),
    )
}

pub fn build_app(
    database: Arc<Database>,
    config: Arc<Config>,
    profiles: Vec<Arc<Profile>>,
    audit: Arc<audit::Auditor>,
    metrics: Arc<metrics::Metrics>,
) -> Router {
    // Server-level routes. Deliberately *outside* the admission limit below: a
    // health probe is asked for precisely when the server is saturated, and
    // inside the limit it was starved exactly when it mattered — a load
    // balancer would go on reporting the server healthy right up to the point
    // where the probe itself could no longer get a slot.
    let mut root = Router::new()
        .route("/", get(|| async { Redirect::temporary("/health") }))
        .route("/health", get(handlers::get_health_check));

    // The `http-01` responder for the *upstream's* challenge, mounted only when
    // a signer backend has tokens to serve — which today means `relay`
    // with `challenge_strategy = "http01"`. Here beside `/health` rather than
    // inside a profile: RFC 8555 §8.3 fixes this path at the root of the name
    // being certified, and the CA fetching it holds no account at this server,
    // so it must not meet a filter chain, a nonce or an ACME 404.
    let stores = http01_stores(&profiles);
    if !stores.is_empty() {
        info!(
            event = "http_01_responder_mounted",
            outcome = "advisory",
            path = challenge::http_01::WELL_KNOWN_PREFIX,
            stores = stores.len(),
            "a reverse proxy must forward or redirect \
             http://<identifier>:80/.well-known/acme-challenge/ here for the upstream to reach it"
        );
        root = root.merge(
            Router::new()
                .route(
                    &format!("{}{{token}}", challenge::http_01::WELL_KNOWN_PREFIX),
                    get(handlers::get_challenge_file),
                )
                .with_state(handlers::Http01Stores(Arc::new(stores))),
        );
    }

    let mut acme = Router::new();
    for profile in &profiles {
        let path = profile.path.clone();
        acme = acme.nest(
            &path,
            build_router(
                database.clone(),
                config.clone(),
                profile.clone(),
                audit.clone(),
            ),
        );
    }

    let server = &config.server;
    let acme = acme
        .layer(middleware::from_fn_with_state(
            middlewares::admission::Admission::new(
                server.max_concurrent_requests,
                server.admission_wait_ms,
                server.request_timeout_ms,
            ),
            middlewares::admission::admission_middleware,
        ))
        // Innermost of the two, so it is in force by the time
        // `String::from_request` reads the JWS body in `verify_jws`. Without it
        // the ceiling is axum's implicit 2 MiB, which every concurrent request
        // may buffer and then hand to `serde_json` — for a body that is a JWS
        // carrying at most a CSR.
        .layer(DefaultBodyLimit::max(server.max_body_bytes));

    // Server-wide layers, applied once rather than once per profile. The
    // filter and nonce layers are deliberately *not* here: both are ACME
    // concerns and live inside each profile's own router.
    let app = root.merge(acme);

    // Counting sits here even though the exposition is served on a *different*
    // socket (see `metrics_app`): this is the only router that sees an ACME
    // request, and the registry both share is an `Arc`. On the merged router
    // rather than inside a profile, because `Router::layer` applies per route
    // *and* to the fallback — so a request that matched nothing is counted too,
    // under `ROUTE_UNMATCHED`. It also runs after routing, which is what makes
    // `MatchedPath` present: the label has to be the route *pattern*
    // (`/order/{id}`), never the URI, or every order ever finalized would be
    // its own series for as long as the scraper retained it.
    //
    // Added only when the listener exists, so an operator who has not asked for
    // metrics pays neither the lock nor the allocation per request.
    let app = if config.metrics.enabled {
        app.layer(middleware::from_fn_with_state(
            metrics,
            middlewares::metrics::record_request,
        ))
    } else {
        app
    };

    app.layer(security_headers())
        // Outermost of everything, so the `request` span it opens — and the
        // `x-request-id` it echoes — covers every route, the admission layer
        // and the two hardening layers alike. Nothing below it is allowed to
        // log without an id.
        .layer(middleware::from_fn(
            middlewares::access::add_access_middleware,
        ))
}

/// Builds the metrics listener's router: `GET /metrics` and nothing else.
///
/// A **third socket**, not a route on either of the other two. The port is the
/// access control — see [`crate::config::MetricsConfig`] — which is why there
/// is no session extractor here and no filter chain, and why the exposition can
/// name every profile without that being a decision about the public listener.
///
/// Deliberately none of `build_app`'s layers. There is no admission control (a
/// scrape is wanted *most* when the server is saturated, the reason `/health`
/// sits outside it too), no `Replay-Nonce`, no `Link: rel="index"`, no
/// `DefaultBodyLimit` (a `GET` with no body), and no security headers — those
/// exist for a browser, and nothing renders this. It keeps only the access
/// middleware, so a scrape is a `request_completed` line like everything else
/// and its `x-request-id` correlates with whatever it was measuring.
///
/// This router is **not** behind a [`reload`] swap cell, unlike the other two.
/// It has one route, and its only state is the registry — which by design is
/// carried across generations rather than rebuilt (see [`Assembly`]), so there
/// is nothing a reload could put in a new one. `metrics.enabled` and
/// `metrics.bind_address` are frozen for the reason every bind address is: the
/// socket cannot move under a running listener.
pub fn metrics_app(metrics: Arc<metrics::Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(handlers::get_metrics))
        .with_state(handlers::MetricsState(metrics))
        .layer(middleware::from_fn(
            middlewares::access::add_access_middleware,
        ))
}

/// Builds one profile's ACME router: every RFC 8555 resource, plus the two
/// layers that are per-endpoint (its filter chain) or ACME-specific (the
/// `Replay-Nonce` minting).
///
/// Paths here are relative to the mount point — `axum::Router::nest` strips
/// the prefix before this router sees a request, which is also what makes
/// `verify_jws`'s `base_url + path` reconstruction correct.
pub fn build_router(
    database: Arc<Database>,
    config: Arc<Config>,
    profile: Arc<Profile>,
    audit: Arc<audit::Auditor>,
) -> Router {
    let filter = profile.filter.clone();
    let state = AppState {
        database: database.clone(),
        config,
        profile: profile.clone(),
        audit,
    };

    let profile_name = profile.name.clone();

    // RFC 8555 §7.1 — the `index` link every resource but the directory carries.
    // Built once here rather than per response; an invalid header value is
    // impossible for a URL that already passed config validation, but falling
    // back to skipping the layer beats panicking a whole endpoint over it.
    let index_link =
        HeaderValue::from_str(&format!("<{}/directory>;rel=\"index\"", profile.base_url));

    let router = Router::<AppState>::new()
        // §6.3: the directory and newNonce MUST answer a plain GET *and* a
        // POST-as-GET. The extra methods chain onto one `MethodRouter` —
        // registering the same path twice would replace the first route.
        .route(
            routes::DIRECTORY,
            get(handlers::get_directory).post(handlers::post_directory),
        )
        .route(
            routes::NEW_NONCE,
            get(handlers::get_new_nonce)
                .head(handlers::head_new_nonce)
                .post(handlers::post_new_nonce),
        )
        .route(routes::NEW_ACCOUNT, post(handlers::post_new_account))
        .route("/acct/{id}", post(handlers::post_account))
        .route("/acct/{id}/orders", post(handlers::post_account_orders))
        .route(routes::KEY_CHANGE, post(handlers::post_key_change))
        .route(routes::NEW_ORDER, post(handlers::post_new_order))
        .route("/order/{id}", post(handlers::post_order))
        .route("/order/{id}/finalize", post(handlers::post_finalize))
        .route("/authz/{id}", post(handlers::post_authz))
        .route("/chall/{id}", post(handlers::post_challenge))
        .route("/certificate/{id}", post(handlers::post_certificate))
        .route(routes::REVOKE_CERT, post(handlers::post_revoke_cert))
        .route(
            &format!("{}/{{id}}", routes::RENEWAL_INFO),
            get(handlers::get_renewal_info),
        )
        .route(routes::CRL, get(handlers::get_crl))
        .route(routes::CA_CHAIN, get(handlers::get_ca_chain))
        // §6.3: "if the server receives a GET request, it MUST return an error
        // with status code 405 (Method Not Allowed) and type `malformed`".
        // axum's own default gets the status right but sends an empty body, so
        // these two fallbacks supply the problem document — for a wrong method
        // and, in the same spirit, for a path that routes nowhere.
        .method_not_allowed_fallback(|| async {
            Problem::method_not_allowed("This resource must be read with POST-as-GET")
        })
        .fallback(|| async { Problem::not_found("No such resource") })
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            filter,
            middlewares::filter::add_filter_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            database.clone(),
            middlewares::nonce::add_nonce_middleware,
        ));

    // Outermost of the profile's layers that touch a response, so the link
    // reaches every one of them — including the two fallbacks above and
    // anything a filter refuses. (The `profile` recorder below wraps this, but
    // only writes to the tracing span.)
    let router = match index_link {
        Ok(value) => router.layer(middleware::from_fn_with_state(
            value,
            middlewares::index_link::add_index_link_middleware,
        )),
        Err(error) => {
            tracing::error!(
                event = "request_index_link_header_invalid",
                outcome = "failure",
                base_url = %profile.base_url,
                error = %error,
            );
            router
        }
    };

    // `profile` is declared `field::Empty` on the server-wide `request` span
    // (`middlewares::access`) and filled in here — the first layer that knows
    // which endpoint the request landed on, since the name comes from the
    // `/profile/<name>` mount point `Router::nest` has already stripped.
    // Ahead of every other layer of this router so a request a filter refuses
    // still says *which* endpoint refused it.
    router.layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let name = profile_name.clone();
            async move {
                Span::current().record("profile", &*name);
                next.run(request).await
            }
        },
    ))
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
