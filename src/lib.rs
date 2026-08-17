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
//! - An append-only audit trail of every issuance *and every refusal*
//! - An optional web admin listener, and admin subcommands in the same binary
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
//! - [`eab`] - Verification of the External Account Binding inner JWS (§7.3.4)
//! - [`key_change`] - Verification of account key rollover JWS (§7.3.5)
//! - [`dns`] - The resolver shared by every subsystem that looks anything up
//! - [`tls`] - Optional HTTPS termination for either listener
//! - [`cert`] - X.509 parsing helpers (serial, SPKI, leaf-from-chain)
//! - [`sqlite`] - Database access, one module per table
//! - [`config`] - Configuration loading from multiple sources
//! - [`error`] - ACME error types and problem document rendering
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
//!     // Resolved before anything can dial: a proxy URL that cannot be
//!     // understood must stop the process rather than leave egress elsewhere.
//!     let proxies = acme_proxy::proxy::from_config(&config.proxy)?;
//!     // One resolver for the whole process: `dns.resolver` governs every
//!     // outbound connection this server makes, not just challenge lookups.
//!     let resolver = challenge::build_resolver(acme_proxy::dns::resolver_addr(&config.dns)?)?;
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
//!                 resolver.clone(),
//!                 proxies.clone(),
//!                 &job_queue,
//!             )?,
//!         );
//!     }
//!     let notifiers = Arc::new(notifiers);
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
//!                     database.clone(),
//!                     notifiers.clone(),
//!                     resolver.clone(),
//!                     proxies.clone(),
//!                     job_queue.clone(),
//!                 )?,
//!                 filter: filter::from_config(
//!                     &sections.filter,
//!                     &config.dns,
//!                     ipam::from_config(&sections.ipam, resolver.clone(), proxies.clone())?,
//!                     sections.eab.enabled,
//!                 )?,
//!                 challenges: challenge::from_config(
//!                     &sections.challenge,
//!                     &config.dns,
//!                     proxies.clone(),
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
//!     let audit = Arc::new(acme_proxy::audit::Auditor::from_config(
//!         &config.audit,
//!         &config.dns,
//!         database.clone(),
//!     )?);
//!     let app = build_app(database.clone(), config.clone(), profiles, audit);
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
pub mod middlewares;
pub mod notify;
pub mod pemfile;
pub mod proxy;
pub mod reload;
pub mod script_hook;
pub mod signer;
pub mod sqlite;
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
        let (assembly, dispatchers) = Assembly::new(&resolved, database, jobs.clone(), config)?;
        Self::build_all_with(config, &resolved, &assembly, &dispatchers)
    }

    /// One generation of profiles, over an [`Assembly`] that outlives it.
    ///
    /// The half of [`build_all`](Self::build_all) a configuration reload runs
    /// again. Everything it touches is cheap and side-effect-free to rebuild —
    /// a filter policy, an IPAM client, a challenge registry — which is exactly
    /// why the expensive and stateful half lives in the `Assembly` instead.
    pub fn build_all_with(
        config: &Config,
        resolved: &[config::ProfileConfig],
        assembly: &Assembly,
        dispatchers: &notify::DispatcherMap,
    ) -> anyhow::Result<Vec<Arc<Profile>>> {
        let proxies = &assembly.proxies;
        let resolver = &assembly.resolver;
        let backends = &assembly.signers;

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
                let ipam = ipam::from_config(&sections.ipam, resolver.clone(), proxies.clone())
                    .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                let filter =
                    filter::from_config(&sections.filter, &config.dns, ipam, sections.eab.enabled)
                        .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                let challenges =
                    challenge::from_config(&sections.challenge, &config.dns, proxies.clone())
                        .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
                check_request_timeout(config, profile.name.as_str(), sections)?;
                Ok::<_, anyhow::Error>((filter, challenges))
            })?;

            profiles.push(Arc::new(Profile::new(
                &profile.name,
                &config.server.base_url,
                ProfileParts {
                    signer: backends[&profile.name].clone(),
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

/// What survives a configuration reload.
///
/// Every generation rebuilds its profiles, its routers and its job registry; the
/// four things here are built once for the life of the process and handed to
/// each generation instead. Two different reasons put them on this side of the
/// line, and both are worth keeping straight:
///
/// - `resolver` and `proxies` are frozen configuration (`dns.*`, `proxy.*`).
///   Rebuilding them would be harmless but pointless, since every outbound
///   client caches whichever one it was handed at construction — including the
///   signer backends below, which are never rebuilt.
/// - `signers` is a **correctness** requirement, not an optimisation. A signer
///   backend owns in-memory state with no durable home: `LocalCa` rebuilds the
///   whole CRL from its own ledger, so a second instance over one `crl_path`
///   would drop the first's entries, and a relay's `http-01` token store would
///   come back empty under an upstream fetch already in flight. That is the
///   same hazard [`signer::build_backends`] refuses *within* one build; carrying
///   the map forward is what refuses it *across* builds. It also means
///   `JobRegistry::register` never sees a duplicate kind, since a new generation
///   re-registers handlers over the very same `Arc`.
///
/// `notifiers` is the one cell that lives here and still changes: `[notify]` is
/// reloadable, so the map behind the handle is republished per generation while
/// the handle the signers captured stays valid.
pub struct Assembly {
    pub database: Arc<Database>,
    pub jobs: crate::jobs::JobQueue,
    pub resolver: Arc<dyn dns::Resolver>,
    pub proxies: Arc<proxy::OutboundProxies>,
    pub signers: std::collections::HashMap<String, Arc<dyn signer::SignerBackend>>,
    pub notifiers: notify::Notifiers,
    notifiers_tx: notify::NotifiersSender,
}

impl Assembly {
    /// Builds everything that outlives a generation, plus the first generation's
    /// dispatcher map.
    ///
    /// The map comes back rather than being kept here because it is *not*
    /// long-lived: the caller hands it to [`Profile::build_all_with`] and then
    /// forgets it, and every later generation gets its own from
    /// [`build_dispatchers`](Self::build_dispatchers).
    pub fn new(
        resolved: &[config::ProfileConfig],
        database: Arc<Database>,
        jobs: crate::jobs::JobQueue,
        config: &Config,
    ) -> anyhow::Result<(Self, notify::DispatcherMap)> {
        // Resolved before anything can dial: a proxy URL that cannot be
        // understood must stop the process, and the `relay` backend below makes
        // a real network call on its very first startup.
        let proxies = crate::proxy::from_config(&config.proxy)?;
        // One resolver for the whole process, handed to every subsystem that
        // makes an outbound connection. `dns.resolver` is documented as "the
        // nameserver every DNS lookup this server makes goes through", and
        // three of the four HTTP clients used to bypass it — so an operator on
        // a split-horizon estate had NetBox and their upstream CA resolving
        // differently from the challenge validators, with nothing saying so.
        //
        // Uncached, for the reason `challenge::build_resolver` explains: a
        // client publishing a `dns-01` record moments before triggering must
        // not be defeated by a cached negative answer.
        let resolver = challenge::build_resolver(crate::dns::resolver_addr(&config.dns)?)?;
        // Built before the signer backends: the `relay` backend's
        // background completion task has no `Profile`/`AppState` to reach a
        // notifier through (it outlives any single request, the same reason
        // it is handed `database`), so it is instead handed this whole
        // `profile name -> dispatcher` map and looks up the right one by
        // `Order.profile` once an issuance settles.
        let dispatchers =
            notify::build_registry(resolved, resolver.clone(), proxies.clone(), &jobs)?;
        // Opened before `build_backends`, so the handle the signers capture is
        // the one later generations republish into.
        let (notifiers_tx, notifiers) = notify::notifiers_channel(dispatchers.clone());
        let signers = signer::build_backends(
            resolved,
            database.clone(),
            notifiers.clone(),
            resolver.clone(),
            proxies.clone(),
            &jobs,
        )?;

        Ok((
            Self {
                database,
                jobs,
                resolver,
                proxies,
                signers,
                notifiers,
                notifiers_tx,
            },
            dispatchers,
        ))
    }

    /// A fresh dispatcher map for `resolved`, without publishing it.
    ///
    /// Separate from [`publish_notifiers`](Self::publish_notifiers) because a
    /// reload must be able to fail *after* building this and still leave the
    /// running generation untouched.
    pub fn build_dispatchers(
        &self,
        resolved: &[config::ProfileConfig],
    ) -> anyhow::Result<notify::DispatcherMap> {
        notify::build_registry(
            resolved,
            self.resolver.clone(),
            self.proxies.clone(),
            &self.jobs,
        )
    }

    /// Makes `dispatchers` the generation every long-lived reader sees.
    ///
    /// Synchronous, and deliberately: it is one of the sends a reload makes
    /// back-to-back so no task can observe a half-swapped generation.
    pub fn publish_notifiers(&self, dispatchers: notify::DispatcherMap) {
        self.notifiers_tx.send_replace(Arc::new(dispatchers));
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
    root.merge(acme)
        .layer(security_headers())
        // Outermost of everything, so the `request` span it opens — and the
        // `x-request-id` it echoes — covers every route, the admission layer
        // and the two hardening layers alike. Nothing below it is allowed to
        // log without an id.
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
