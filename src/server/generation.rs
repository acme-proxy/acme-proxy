//! One configuration generation: built and validated in full, then published
//! in one uninterruptible run. Startup builds the first; a reload builds and
//! publishes every later one.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use super::logging;
use acme_proxy_core::config::Config;
use acme_proxy_net::tls;

use super::sockets::{Role, SocketPlans, check_metrics_config, plan_sockets};
use super::supervisor::Cells;
use super::{Assembly, GenerationParts};
use crate::profile::Profile;
use crate::router::build_app;

/// Everything one configuration generation contributes, built and validated
/// before any of it is published.
///
/// The unit exists so startup and reload cannot drift: both go through
/// [`build_generation`], so a subsystem added to one is added to the other by
/// construction rather than by remembering.
pub(crate) struct Generation {
    /// Kept so startup can announce them; a reload drops them on the floor,
    /// since `profile_mounted` is a lifecycle event and not a heartbeat.
    pub(super) profiles: Vec<Arc<Profile>>,
    pub(super) acme_app: axum::Router,
    pub(super) admin_app: Option<axum::Router>,
    pub(super) job_registry: crate::jobs::JobRegistry,
    pub(super) tls: Option<tls::TlsSettings>,
    pub(super) admin_tls: Option<tls::TlsSettings>,
    /// The limiter this generation ended up with, for the next one to carry.
    pub(super) logins: Option<Arc<crate::webadmin::LoginLimiter>>,
}

/// Builds one generation: profiles, both routers, the job registry, the audit
/// trail and both TLS acceptors.
///
/// Fallible throughout and side-effect-free on the *serving* state: nothing here
/// touches a cell, so a failure leaves whatever is already running exactly as it
/// was. That is what makes an atomic reload possible — everything is built
/// first, and only a complete success publishes anything.
///
/// `dispatchers` is passed in rather than built here because a reload needs to
/// hold it back: it is published to the long-lived [`crate::notify::Notifiers`]
/// handle at swap time, *before* the routers, so a request served by the new
/// generation cannot queue a delivery the job runner's map does not know.
///
/// Whether the panel is part of this generation is read from `admin.enabled`
/// rather than from whether a socket exists. It used to be the latter, which
/// was the same answer while the key was frozen and is the wrong one now that a
/// reload can turn the panel on: the app, its TLS, its session sweep and its
/// login limiter all have to appear in the generation *before* there is a
/// listener to serve them.
pub(crate) fn build_generation(
    config: &Arc<Config>,
    resolved: &[acme_proxy_core::config::ProfileConfig],
    assembly: &Assembly,
    parts: &GenerationParts,
    previous_logins: Option<&crate::webadmin::LoginLimiter>,
) -> anyhow::Result<Generation> {
    let admin_enabled = config.admin.enabled;
    let database = assembly.database.clone();
    let profiles = crate::server::profile::build_all_with(config, resolved, parts)?;

    let tls = tls::from_config(&config.server)
        .inspect_err(|error| {
            error!(event = "tls_init_failed", outcome = "failure", error = %error);
        })?
        .map(|acceptor| {
            tls::TlsSettings::new(
                acceptor,
                Duration::from_millis(config.server.tls.handshake_timeout_ms),
            )
        });

    let admin_tls = match admin_enabled {
        false => None,
        true => tls::admin_from_config(&config.admin)
            .inspect_err(|error| {
                error!(event = "admin_tls_init_failed", outcome = "failure", error = %error);
            })?
            .map(|acceptor| {
                tls::TlsSettings::new(
                    acceptor,
                    Duration::from_millis(config.admin.tls.handshake_timeout_ms),
                )
            }),
    };

    // Every subsystem with background work, in one registry. **Nothing here
    // registers a handler per backend**: the registry refuses a second handler
    // for one kind outright, since two would each claim about half the rows, and
    // two profiles over different `[signer]` sections are two backends that
    // `build_backends` deliberately does not collapse. So each backend hands
    // over *state* and one handler is built over all of it.
    let mut job_registry = crate::jobs::JobRegistry::new();
    // The CRLs are collected once per distinct backend, since two profiles
    // sharing one CA share one CRL and refreshing it twice a day would be
    // pointless work. The identity is kept as a `usize` rather than the
    // pointer itself, so this function's caller stays `Send`; it is spawned.
    let mut registered: Vec<usize> = Vec::new();
    let mut refreshers: Vec<Arc<dyn crate::signer::CrlRefresher>> = Vec::new();
    // The relay backends are collected per *profile*, because that is the key a
    // job row is dispatched on — and because taking the profile list from the
    // backend would take a stale one: a backend whose configuration did not
    // move is reused verbatim across a reload, so a profile newly mounted onto
    // it is not in any list it remembers.
    //
    // Both come from this generation's **backends**, which only a process
    // running the `worker` role builds: everywhere else the set is empty, so
    // none of these handlers has a backend to reach, and none of them runs
    // there anyway.
    let mut relays: Vec<(String, crate::signer::relay::RelayState)> = Vec::new();
    let mut backends = parts.signers.by_profile();
    backends.sort_by(|a, b| a.0.cmp(&b.0));
    for (profile, backend) in &backends {
        relays.extend(backend.relay_state().map(|state| (profile.clone(), state)));
        let identity = Arc::as_ptr(backend).cast::<()>() as usize;
        if registered.contains(&identity) {
            continue;
        }
        registered.push(identity);
        refreshers.extend(backend.crl_refresher());
    }
    // The daily CRL refresh, over whichever CAs keep a CRL of their own.
    // Registered only when there is one, the way the audit sweep is registered
    // only for a non-zero retention.
    // Beside it, the handler that signs revocations the CLI recorded without
    // the key.
    if !refreshers.is_empty() {
        job_registry
            .register(Arc::new(
                crate::signer::local_ca::sweep::CrlRegenerateJob::new(refreshers.clone()),
            ))
            .inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
        job_registry
            .register(Arc::new(crate::signer::local_ca::sweep::CrlSweepJob::new(
                refreshers,
            )))
            .inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
    }
    // Relayed issuance, over every relay profile at once. Registered only when
    // some profile relays, for `CrlSweepJob`'s reason: a deployment with none
    // has no row of this kind to claim.
    if !relays.is_empty() {
        job_registry
            .register(Arc::new(crate::signer::relay::flow::RelayJob::new(
                database.clone(),
                relays,
            )))
            .inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
    }
    // Revocations the host CLI queued for a backend it does not build (`relay`,
    // `custom`). Registered unconditionally, `NotifyJob`'s reason below: a row
    // queued before a configuration change must still find a handler, and one
    // naming a profile this generation does not mount is retried rather than
    // lost.
    job_registry
        .register(Arc::new(crate::acme::revoke::SignerRevokeJob::new(
            database.clone(),
            Arc::new(
                crate::auditor::Auditor::offline(database.clone())
                    .with_metrics(assembly.metrics.clone()),
            ),
            backends.clone(),
            assembly.notifiers.clone(),
        )))
        .inspect_err(|error| {
            error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
        })?;
    // Issuance. `finalize` claims the order and queues the signing, so the
    // process answering ACME holds no backend. Registered unconditionally for
    // `SignerRevokeJob`'s reason above, over this generation's backends — none
    // at all in a process without the worker role, which never claims a row.
    job_registry
        .register(Arc::new(crate::acme::issue::SignerIssueJob::new(
            database.clone(),
            Arc::new(
                crate::auditor::Auditor::offline(database.clone())
                    .with_metrics(assembly.metrics.clone()),
            ),
            backends.clone(),
            assembly.notifiers.clone(),
        )))
        .inspect_err(|error| {
            error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
        })?;
    // Challenge validation. `POST /chall/{id}` claims the challenge and queues
    // the outbound check, so the probe of a client-chosen host no longer holds
    // an admission permit for the length of `challenge.timeout_ms`. Registered
    // unconditionally for `SignerRevokeJob`'s reason above — a row queued
    // before a configuration change must still find a handler — and holding the
    // profiles rather than one profile, since the registry refuses a second
    // handler for one kind.
    job_registry
        .register(Arc::new(crate::acme::validate::ChallengeValidateJob::new(
            database.clone(),
            Arc::new(
                crate::auditor::Auditor::offline(database.clone())
                    .with_metrics(assembly.metrics.clone()),
            ),
            profiles
                .iter()
                .map(|profile| (profile.name.clone(), profile.clone()))
                .collect(),
        )))
        .inspect_err(|error| {
            error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
        })?;

    // Notification delivery. The same shape as the two above and the reason it
    // is: one handler for every profile, holding the whole
    // `profile name -> dispatcher` map, with a job row naming its own profile.
    // Registered unconditionally — a profile with no `[notify]`
    // backends queues nothing, so the handler simply never claims a row, and
    // making the registration conditional would mean a row queued before a
    // configuration change had nobody to run it.
    //
    // It takes the *handle*, not this generation's map: the handler is
    // registered per generation but must read whichever map is current, and a
    // row queued by a reloaded router names a slot id only the new one has.
    job_registry
        .register(Arc::new(crate::notify::NotifyJob::new(
            assembly.notifiers.clone(),
        )))
        .inspect_err(|error| {
            error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
        })?;

    // The expiry digest, registered only when some profile asked for one
    // (`notify.expiry.lead_days`), the way `CrlSweepJob` is registered only
    // when there is a ledger to prune. It takes the `Notifiers` handle rather
    // than the profiles' own dispatchers for `NotifyJob`'s reason above, and
    // the queue because its per-profile rows are something it maintains on
    // every pass rather than only at `recover`.
    if let Some(digest) = crate::notify::expiry::ExpiryDigestJob::from_profiles(
        resolved,
        assembly.notifiers.clone(),
        database.clone(),
        assembly.jobs.clone(),
    ) {
        job_registry
            .register(Arc::new(digest))
            .inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
    }

    // The periodic table sweeps. Each is one self-rescheduling row rather than
    // its own interval loop, so a sweep that dies is reclaimed by lease expiry
    // and its schedule survives a restart. Their `recover` is also the startup
    // sweep — it queues at `run_at = now`, so the runner performs the first pass
    // on its way into the loop and there is nothing to run separately here.
    let ttl = Duration::from_secs(config.nonce.ttl_seconds);
    let mut sweeps = vec![crate::jobs::SweepJob::nonces(database.clone(), ttl)];
    // `0` keeps everything for ever on both of these, and is a handler not
    // registered rather than a sweep with a cutoff at the epoch.
    if config.audit.retention_days > 0 {
        sweeps.push(crate::jobs::SweepJob::audit(
            database.clone(),
            config.audit.retention_days,
        ));
    }
    if config.jobs.retention_days > 0 {
        sweeps.push(crate::jobs::SweepJob::jobs(
            database.clone(),
            config.jobs.retention_days,
        ));
    }
    // One handler covering every mounted profile, since the registry refuses a
    // second handler for one kind. A profile keeping everything (`0`) is left
    // out of the list rather than swept with a cutoff at the epoch.
    let order_retention: Vec<(String, u64)> = resolved
        .iter()
        .filter(|profile| profile.sections.order.retention_days > 0)
        .map(|profile| (profile.name.clone(), profile.sections.order.retention_days))
        .collect();
    if !order_retention.is_empty() {
        sweeps.push(crate::jobs::SweepJob::orders(
            database.clone(),
            order_retention,
        ));
    }
    // Only where some backend publishes http-01 tokens: the table stays empty
    // otherwise, and the CRL refresh's rule applies.
    if profiles
        .iter()
        .any(|profile| profile.signer_info.http01_tokens().is_some())
    {
        sweeps.push(crate::jobs::SweepJob::http01_tokens(database.clone()));
    }
    if admin_enabled {
        sweeps.push(crate::jobs::SweepJob::admin_sessions(
            database.clone(),
            Duration::from_secs(config.admin.session_idle_timeout_seconds),
            config.admin.session_ttl_seconds,
        ));
    }
    for sweep in sweeps {
        job_registry
            .register(Arc::new(sweep))
            .inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
    }

    // The CA's audit trail: one per process, shared by every profile's router
    // and by the web admin listener, because `[audit]` is process-wide. Built
    // here rather than in `server::profile::build_all` for exactly that reason — it is
    // not a per-endpoint subsystem.
    let auditor = Arc::new(
        crate::auditor::Auditor::from_config(
            &config.audit,
            &config.dns,
            database.clone(),
            // The registry the certificate counters land in. Carried by
            // `Assembly`, so it is the same one across every generation and the
            // same one `metrics_app` serves from.
            assembly.metrics.clone(),
        )
        .inspect_err(|error| {
            error!(event = "audit_init_failed", outcome = "failure", error = %error);
        })?,
    );

    // Built **before** `build_app`, which consumes `profiles`. The admin state
    // needs the same profiles (revoking an order resolves that order's own
    // signer), and `build_admin_app` takes a slice precisely so the ordering
    // is a signature constraint rather than a borrow error to rediscover.
    let (admin_app, logins) = match admin_enabled {
        false => (None, None),
        true => {
            let (router, logins) = crate::webadmin::build_admin_app_with_logins(
                database.clone(),
                config.clone(),
                &profiles,
                auditor.clone(),
                assembly.notifiers.clone(),
                assembly.jobs.clone(),
                previous_logins,
            );
            (Some(router), Some(logins))
        }
    };
    let acme_app = build_app(
        database,
        config.clone(),
        profiles.clone(),
        auditor,
        assembly.metrics.clone(),
        assembly.jobs.clone(),
    );

    Ok(Generation {
        profiles,
        acme_app,
        admin_app,
        job_registry,
        tls,
        admin_tls,
        logins,
    })
}

/// What one successful reload hands back to the supervisor: the report to log,
/// and the pieces of state the *next* reload compares against.
///
/// A struct rather than the tuple this used to return — which needed
/// `#[allow(clippy::type_complexity)]` and left the caller destructuring four
/// same-shaped values positionally, where swapping two would still compile.
/// The same move `ProfileParts` made, for the same reason.
pub(super) struct Reloaded {
    pub(super) report: crate::reload::ReloadReport,
    pub(super) config: Arc<Config>,
    pub(super) resolved: Vec<acme_proxy_core::config::ProfileConfig>,
    pub(super) logins: Option<Arc<crate::webadmin::LoginLimiter>>,
    /// Each socket this reload bound, with the address it landed on. Announced
    /// by the supervisor rather than here, because saying a listener is up
    /// reaches the database (the panel's "nobody can sign in yet" warning) and
    /// [`publish_reload`] has no await point to spend on it — deliberately, that
    /// being what keeps its publishing run uninterruptible.
    pub(super) opened: Vec<(Role, String)>,
    /// The endpoints this reload **added**, for the same reason and announced in
    /// the same place: `profile_mounted` is dispatched to the `[notify]`
    /// backends, which queues a job row.
    pub(super) mounted: Vec<Arc<Profile>>,
}

/// Everything a reload built and validated, waiting to be published.
///
/// The build/publish split is the whole shape of a reload, and making it two
/// values rather than two halves of one function buys the thing the split was
/// always claiming: [`prepare_reload`] can run wherever it likes — it runs on a
/// blocking thread, since building a `relay` backend can contact its upstream —
/// while [`publish_reload`] stays on the supervisor task, where having no await
/// point is what makes a generation unobservable half-applied.
pub(super) struct Prepared {
    config: Arc<Config>,
    resolved: Vec<acme_proxy_core::config::ProfileConfig>,
    parts: GenerationParts,
    generation: Generation,
    sockets: SocketPlans,
    logging: logging::PreparedLogging,
    /// Whether `RUST_LOG` is what the filter came from, so the publish phase can
    /// say when an edited `logging.filter` changed nothing, and which of the
    /// two outranking layers is why.
    logging_filter_source: logging::FilterSource,
    /// The endpoints in this generation that the previous one did not mount.
    mounted: Vec<Arc<Profile>>,
    /// The endpoints the previous generation mounted and this one does not.
    unmounted: Vec<String>,
}

impl Prepared {
    /// The backends this reload built or carried, for the one step the
    /// supervisor takes between building and publishing.
    pub(super) fn signers(&self) -> &crate::signer::SignerSet {
        &self.parts.signers
    }
}

/// The build half of one reload: everything that can fail, and everything that
/// can block.
///
/// Nothing here touches a cell, so a failure anywhere leaves the running
/// generation exactly as it was — which is the property the whole "atomic,
/// refuse by name" decision exists for. Every socket this reload needs is bound
/// here too, where a port already in use is still a refusal rather than a
/// listener already dropped.
///
/// Run on a blocking thread by
/// [`supervise_reloads`](super::supervisor::supervise_reloads), because
/// building a `relay` backend for the first time contacts its upstream
/// synchronously.
pub(super) fn prepare_reload(
    roles: crate::server::RoleSet,
    config: &Arc<Config>,
    resolved: &[acme_proxy_core::config::ProfileConfig],
    assembly: &Assembly,
    logins: Option<&crate::webadmin::LoginLimiter>,
) -> Result<Prepared, crate::reload::ReloadError> {
    use crate::reload::{Applied, ReloadError, check_frozen};

    // Re-read from scratch: `Config::load` consults the file *and* the
    // `ACME_PROXY_*` environment, so a reload sees whatever the process would
    // see if it restarted right now.
    let next = Arc::new(Config::load().map_err(|error| ReloadError::Load(error.to_string()))?);
    let next_resolved = next
        .resolve_profiles()
        .map_err(|error| ReloadError::Load(error.to_string()))?;

    check_frozen(
        &Applied {
            config,
            profiles: resolved,
        },
        &Applied {
            config: &next,
            profiles: &next_resolved,
        },
    )?;

    // Built here rather than published here: a bad `logging.target` must refuse
    // the whole reload with the message startup would have printed, not leave a
    // half-swapped generation behind. The same build-then-publish split
    // `Assembly::build_parts` makes.
    // `flag_override()` is how a `--log-level` typed at startup survives a
    // `SIGHUP`: the stack is rebuilt from the file, so without re-reading it
    // the reload would silently demote the server to `logging.filter`.
    let logging = logging::prepare_logging(&next.logging, logging::flag_override())
        .map_err(ReloadError::Build)?;
    let logging_filter_source = logging.filter_source;

    // The same validation startup runs before either socket binds, so a panel
    // that would refuse to start refuses to be reloaded into. It also compiles
    // every `admin.template_dir` override, which is what keeps a broken one a
    // failed reload rather than a 500 in a browser.
    crate::webadmin::check_config(&next).map_err(|error| ReloadError::Build(error.to_string()))?;
    // Its twin for the third listener: `webadmin::check_config` sees the
    // admin-versus-server pair, this one sees the two it cannot.
    check_metrics_config(&next).map_err(|error| ReloadError::Build(error.to_string()))?;

    // Every socket this reload needs is bound **here**, where a failure is still
    // a refusal: a port already taken, an address that does not resolve, a
    // privileged port after a `setcap` was lost. Past the publish phase nothing
    // can fail, so the running listeners are never dropped for a configuration
    // that then turns out not to work.
    let sockets = plan_sockets(roles, config, &next)?;

    // The egress clients, the notification dispatchers and the signer backends.
    // The last is where a newly mounted endpoint gets a backend, a removed one's
    // is left out, and an edited `[signer]` is rebuilt over the live instance's
    // in-memory state — see `signer::build_backends`. It is also the one step
    // that can make a network call, hence this whole function's blocking thread.
    let parts = assembly
        .build_parts(&next_resolved, &next)
        .map_err(|error| ReloadError::Build(error.to_string()))?;
    let generation = build_generation(&next, &next_resolved, assembly, &parts, logins)
        .map_err(|error| ReloadError::Build(error.to_string()))?;

    // Compared by name against what is running, not against what is written
    // down: `resolve_profiles` has already dropped every `enabled = false`
    // entry, so this is the set of endpoints actually served.
    let running: std::collections::HashSet<&str> = resolved
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    let mounted = generation
        .profiles
        .iter()
        .filter(|profile| !running.contains(profile.name.as_str()))
        .cloned()
        .collect();
    let next_names: std::collections::HashSet<&str> = next_resolved
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    let unmounted = resolved
        .iter()
        .map(|profile| profile.name.clone())
        .filter(|name| !next_names.contains(name.as_str()))
        .collect();

    Ok(Prepared {
        config: next,
        resolved: next_resolved,
        parts,
        generation,
        sockets,
        logging,
        logging_filter_source,
        mounted,
        unmounted,
    })
}

/// The publish half: infallible, synchronous, and uninterruptible.
///
/// There is no `.await` in here, and that is load-bearing rather than
/// incidental. `watch::Sender::send_replace` and
/// `mpsc::UnboundedSender::send` are both synchronous, so a run of them with no
/// await point between cannot be interleaved — no task can observe a generation
/// half-applied, and no lock is needed to say so.
///
/// The order matters in three places. `[logging]` goes **first**, because an
/// operator who raised the level did it to see what happens next, starting with
/// this reload's own completion line. The notifier map, the signer set and the
/// job registry go **before** the routers: a request served by the new
/// generation queues a `notify_deliver` row naming a slot id from the new
/// configuration, and a `NotifyJob` still holding the old map would retire it —
/// permanently, since an unknown backend id is a `Failed`, not a `Retry`. And
/// the TLS mode goes before the socket, so a freshly bound listener's very first
/// connection is already accepted under this generation's settings.
pub(super) fn publish_reload(
    prepared: Prepared,
    applied: &Arc<Config>,
    assembly: &Assembly,
    cells: &Cells,
    generation: u64,
    started: std::time::Instant,
) -> Reloaded {
    use crate::reload::ReloadReport;

    let Prepared {
        config: next,
        resolved: next_resolved,
        parts,
        generation: built,
        sockets,
        logging,
        logging_filter_source,
        mounted,
        unmounted,
    } = prepared;

    let logging_reloaded = logging::publish_logging(logging);

    let report = ReloadReport {
        generation,
        profiles: built
            .profiles
            .iter()
            .map(|profile| profile.name.clone())
            .collect(),
        job_kinds: built.job_registry.kinds(),
        tls_reloaded: built.tls.is_some(),
        admin_tls_reloaded: built.admin_tls.is_some(),
        listeners_rebound: sockets.rebound(),
        logging_reloaded,
        duration: started.elapsed(),
    };
    let next_logins = built.logins.clone();

    assembly.publish_notifiers(parts.dispatchers);
    // The set the *next* reload compares against, and the point at which the
    // backends this one dropped are finally released — after their replacements
    // were built and adopted their state, never before.
    assembly.publish_signers(parts.signers, parts.infos);
    cells
        .job_registry
        .send_replace(Arc::new(built.job_registry));

    // `[jobs]` in its two halves, both synchronous and neither able to fail —
    // which is what lets them sit in this run rather than needing a build phase
    // of their own. The runner re-derives its pacing from the cell on its next
    // pass; `max_attempts` goes to the queue instead, because it is the enqueue
    // side that reads it, and it sets the budget for work queued from here on
    // rather than for the rows already waiting.
    cells.jobs.send_replace(Arc::new(next.jobs.clone()));
    assembly.jobs.set_max_attempts(next.jobs.max_attempts);

    cells.acme.set_tls(built.tls);
    cells.admin.set_tls(built.admin_tls);
    let opened = sockets.bound.clone();
    sockets.publish(cells);

    cells
        .acme_router
        .send_replace(built.acme_app.into_service::<axum::body::Body>());
    // An empty router when the panel is off, which is what a request arriving
    // on a connection established a moment before it was switched off now gets:
    // closing the socket stops the next client, and this stops that one.
    cells.admin_router.send_replace(
        built
            .admin_app
            .unwrap_or_default()
            .into_service::<axum::body::Body>(),
    );

    // Said here rather than by the supervisor because it needs nothing but a
    // name, unlike the mounting half, which dispatches a notification.
    for profile in unmounted {
        warn!(
            event = "profile_unmounted",
            outcome = "advisory",
            profile = %profile,
            "the endpoint is no longer served: its accounts and orders stay in the \
             database and come back if it is mounted again, but any issuance still in \
             flight for it has no handler left to finish it"
        );
    }

    // `--log-level` and `RUST_LOG` both outrank `logging.filter` on a reload
    // exactly as they do at startup — the two disagreeing would be worse — but
    // that makes an edited `logging.filter` a silent no-op, which is the one
    // outcome an operator would read as "my reload did not land". Said only
    // when both halves hold: something outranked the file, *and* the file's
    // filter actually moved. `source` names which, since the two are unset in
    // different places.
    if logging_filter_source.outranks_config() && applied.logging.filter != next.logging.filter {
        warn!(
            event = "server_logging_filter_overridden",
            outcome = "advisory",
            source = logging_filter_source.as_str(),
            configured = %next.logging.filter,
        );
    }

    Reloaded {
        report,
        config: next,
        resolved: next_resolved,
        logins: next_logins,
        opened,
        mounted,
    }
}

/// The one announcement an endpoint that has just come up makes: a log line and
/// a `[notify]` lifecycle event.
///
/// Shared by startup and by a reload that mounted a new endpoint, so the two
/// cannot drift — before the profile set could reload there was only one caller
/// and the sharing was not needed.
pub(super) async fn announce_profile(profile: &Arc<Profile>) {
    info!(
        event = "profile_mounted",
        outcome = "success",
        profile = %profile.name,
        directory = %profile.directory_url(),
        challenge_bypass = profile.challenges.is_bypassed(),
        eab_enabled = profile.eab.enabled
    );
    profile
        .notify
        .dispatch(crate::notify::NotifyEvent::ProfileMounted(
            crate::notify::ProfileMountedData {
                profile: profile.name.clone(),
            },
        ))
        .await;
}
