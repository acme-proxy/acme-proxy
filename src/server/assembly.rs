//! What one configuration generation dials through ([`Egress`]), what it hands
//! its profiles ([`GenerationParts`]), and what outlives it ([`Assembly`]).

use std::sync::Arc;

use crate::config::{self, Config};
use crate::sqlite::db::Database;
use crate::{challenge, dns, http_client, metrics, notify, proxy, signer};

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
/// A struct because [`Profile::build_all_with`](super::Profile::build_all_with)
/// would otherwise take three same-shaped values positionally, and because the
/// three are built together and must be published together —
/// `server::generation::publish_reload` swaps the notifier map and the signer
/// set in the same uninterruptible run as the routers built from them.
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
///   reload can reuse a backend whose configuration did not move (see
///   [`signer::build_backends`]). Behind a `Mutex` because it is written once per
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
    /// long-lived: the caller hands them to
    /// [`Profile::build_all_with`](super::Profile::build_all_with) and then
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
    /// `server::supervisor::supervise_reloads` runs this on a blocking thread.
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
        let mut dispatchers = notify::build_registry(resolved, egress.outbound(), &self.jobs)?;
        // The process-wide web-admin security dispatcher, registered under a
        // reserved key that no profile name can collide with. Built only when
        // the panel is on; `NotifyJob` routes a `notify_deliver` row naming it
        // here with no special case, and a reload republishes it in this same
        // map.
        if config.admin.enabled {
            dispatchers.insert(
                notify::ADMIN_DISPATCHER_KEY.to_string(),
                notify::from_config(
                    notify::ADMIN_DISPATCHER_KEY,
                    &config.admin.notify,
                    egress.outbound(),
                    &self.jobs,
                )?,
            );
        }
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
