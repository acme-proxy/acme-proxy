//! What one configuration generation hands its profiles ([`GenerationParts`]),
//! and what outlives it ([`Assembly`]). What it dials through is
//! [`crate::egress::Egress`].

use std::sync::Arc;

use crate::config::{self, Config};
use crate::egress::Egress;
use crate::sqlite::db::Database;
use crate::{metrics, notify, signer};

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
    /// The backends, which the job handlers sign and revoke through.
    pub signers: signer::SignerSet,
    /// Their read sides, which the profiles serve from.
    pub infos: signer::SignerSet<dyn signer::SignerInfo>,
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
///   [`signer::build_backends`]); `infos` the same for their read sides. Behind
///   a `Mutex` because each is written once per generation; nothing reads
///   either to serve a request, since a `Profile` holds its own read side.
/// - `roles` decides whether there are backends at all: only a process running
///   the `worker` role builds one, so the others never read a CA key, log in to
///   a token or contact a relay's upstream — not at startup, not on reload.
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
    /// The previous generation's read sides, kept for `signers`' reason.
    infos: std::sync::Mutex<signer::SignerSet<dyn signer::SignerInfo>>,
    roles: super::RoleSet,
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
        roles: super::RoleSet,
        resolved: &[config::ProfileConfig],
        database: Arc<Database>,
        jobs: crate::jobs::JobQueue,
        config: &Config,
    ) -> anyhow::Result<(Self, GenerationParts)> {
        // Built before the signers, because the `relay` backend settles an
        // issuance from a background task that has no request and no `Auditor`,
        // so it counts that issuance through a handle it was given at
        // construction.
        let metrics = Arc::new(metrics::Metrics::new(database.clone()).with_roles(&roles.labels()));
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
            infos: std::sync::Mutex::new(signer::SignerSet::default()),
            roles,
        };
        let parts = assembly.build_parts(resolved, config)?;
        // The first generation's map has to reach the handle before anything
        // dispatches through it; every later one goes through `publish` in the
        // reload's own synchronous run.
        assembly.publish_notifiers(parts.dispatchers.clone());
        assembly.publish_signers(parts.signers.clone(), parts.infos.clone());
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
        let signer_parts = signer::SignerParts {
            database: self.database.clone(),
            notifiers: self.notifiers.clone(),
            metrics: self.metrics.clone(),
            egress: egress.clone(),
            jobs: self.jobs.clone(),
        };
        let previous = self
            .signers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // The worker's alone. Every other role serves from the read sides below
        // and queues what needs a key, so it never reads `ca.key`, never logs
        // in to a PKCS#11 token and never registers with a relay's upstream —
        // which is also what makes the worker the one process that generates
        // first-run material.
        let signers = if self.roles.has(super::ProcessRole::Worker) {
            signer::build_backends(resolved, &signer_parts, &previous)?
        } else {
            signer::SignerSet::default()
        };
        // After the backends, so that on a fresh directory the one that
        // generates a CA has written its certificate before its read side
        // looks for it. A process without the worker role finding none is
        // refused by name: it was started before the process that makes it.
        let previous = self
            .infos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let infos = signer::build_infos(resolved, &signer_parts, &previous)?;

        Ok(GenerationParts {
            egress,
            dispatchers,
            signers,
            infos,
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
    pub fn publish_signers(
        &self,
        signers: signer::SignerSet,
        infos: signer::SignerSet<dyn signer::SignerInfo>,
    ) {
        *self
            .signers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = signers;
        *self
            .infos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = infos;
    }
}
