//! The one task that serves reload requests for the life of the process.

use std::sync::Arc;

use tracing::{error, info, warn};

use crate::config::Config;

use super::Assembly;
use super::generation::{announce_profile, prepare_reload, publish_reload};
use super::sockets::{Role, announce_admin_listener, announce_metrics_listener};

/// The cells one generation is published into.
///
/// Held by the supervisor and by nothing else. Every field is a `watch::Sender`,
/// and `send_replace` is synchronous — so publishing a generation is a run of
/// sends with no `.await` between them, which no other task can interleave with.
/// That is what makes a reload atomic without a lock.
pub(super) struct Cells {
    pub(super) acme_router:
        tokio::sync::watch::Sender<axum::routing::RouterIntoService<axum::body::Body>>,
    pub(super) admin_router:
        tokio::sync::watch::Sender<axum::routing::RouterIntoService<axum::body::Body>>,
    pub(super) job_registry: tokio::sync::watch::Sender<Arc<crate::jobs::JobRegistry>>,
    /// The runner's own pacing. Separate from the registry above because the two
    /// reach it by different routes: the registry carries what a *handler*
    /// captured, this carries what the *loop* re-reads each pass.
    pub(super) jobs: tokio::sync::watch::Sender<Arc<crate::config::JobsConfig>>,
    /// The three sockets. Each carries its role's TLS mode as well, since both
    /// are read by the same accept loop and both are published the same
    /// synchronous way — see [`crate::listener::ListenerHandle`].
    pub(super) acme: crate::listener::ListenerHandle,
    pub(super) admin: crate::listener::ListenerHandle,
    pub(super) metrics: crate::listener::ListenerHandle,
}

/// Serves reload requests for the life of the process.
///
/// One task, so reloads are serialised: two overlapping rebuilds could publish
/// their cells interleaved, and the second-newest generation would win some of
/// them. Ends when the last [`crate::reload::ReloadHandle`] is dropped, which is
/// what makes [`crate::reload::Reloads::none`] cost nothing.
pub(super) async fn supervise_reloads(
    roles: crate::server::RoleSet,
    mut reloads: crate::reload::Reloads,
    mut config: Arc<Config>,
    mut resolved: Vec<crate::config::ProfileConfig>,
    assembly: Arc<Assembly>,
    cells: Cells,
    mut logins: Option<Arc<crate::webadmin::LoginLimiter>>,
) {
    let mut generation: u64 = 1;

    while let Some(request) = reloads.recv().await {
        let started = std::time::Instant::now();
        info!(
            event = "server_config_reload_requested",
            outcome = "progress",
            generation = generation,
        );

        // The build phase runs on a blocking thread, and that is not a
        // precaution: `RelaySigner::from_config` contacts the upstream the first
        // time it is built for an account with no `kid` sidecar yet, on a scoped
        // OS thread it then *joins*. Mounting a relay profile by `SIGHUP` would
        // otherwise park a runtime worker for as long as
        // `signer.relay.poll_timeout_secs` allows — five minutes by default —
        // with every connection that worker was polling parked behind it. The
        // publish phase stays on this task, where its lack of an await point is
        // what makes a generation unobservable half-applied.
        let outcome = {
            let config = config.clone();
            let resolved = resolved.clone();
            let assembly = assembly.clone();
            let logins = logins.clone();
            tokio::task::spawn_blocking(move || {
                prepare_reload(roles, &config, &resolved, &assembly, logins.as_deref())
            })
            .await
            .unwrap_or_else(|error| {
                Err(crate::reload::ReloadError::Build(format!(
                    "the reload build task did not finish: {error}"
                )))
            })
        };
        // A CA this reload mounted has no stored CRL yet, and the read side
        // never signs one. Stored here, before the routers that serve it are
        // published, for startup's reason — see `store_first_crls`.
        if let Ok(prepared) = &outcome
            && roles.has(super::ProcessRole::Worker)
        {
            super::store_first_crls(prepared.signers()).await;
        }
        let outcome = outcome.map(|prepared| {
            publish_reload(
                prepared,
                &config,
                &assembly,
                &cells,
                generation + 1,
                started,
            )
        });

        match outcome {
            Ok(reloaded) => {
                let report = reloaded.report;
                config = reloaded.config;
                resolved = reloaded.resolved;
                logins = reloaded.logins;
                generation = report.generation;
                info!(
                    event = "server_config_reloaded",
                    outcome = "success",
                    generation = report.generation,
                    profiles = ?report.profiles,
                    job_kinds = ?report.job_kinds,
                    tls_reloaded = report.tls_reloaded,
                    admin_tls_reloaded = report.admin_tls_reloaded,
                    listeners_rebound = ?report.listeners_rebound,
                    logging_reloaded = report.logging_reloaded,
                    duration_ms = crate::logfields::millis(report.duration),
                );
                // After the reload's own line, and under the new configuration,
                // since that is what these describe. Each is the same
                // announcement startup makes for a listener that has just come
                // up — including the panel's two warnings, which is why this is
                // here rather than inside the synchronous publishing run.
                for (role, address) in reloaded.opened {
                    match role {
                        Role::Acme => info!(
                            event = "server_listening",
                            outcome = "success",
                            bind_address = %address,
                            protocol = if config.server.tls.enabled { "https" } else { "http" }
                        ),
                        Role::Admin => {
                            announce_admin_listener(&config, &assembly.database, &address).await;
                        }
                        Role::Metrics => announce_metrics_listener(&address),
                    }
                }
                // An endpoint this reload mounted really did come up, so it gets
                // the same announcement and the same notification startup makes
                // for one. An endpoint that was *already* mounted stays silent:
                // `profile_mounted` is a lifecycle event and not a heartbeat,
                // and re-firing it per `SIGHUP` would make the notify surface
                // noisiest in exactly the config-managed deployments that would
                // least want it. Here rather than in the publishing run because
                // dispatching reaches the database.
                for profile in reloaded.mounted {
                    announce_profile(&profile).await;
                }
                if let Some(respond) = request.respond {
                    let _ = respond.send(Ok(report));
                }
            }
            Err(error) => {
                // Two names, because they are two different things for whoever
                // is reading: a refusal is a configuration an operator must
                // change, a failure is one the server could not build.
                match &error {
                    crate::reload::ReloadError::Frozen { .. } => warn!(
                        event = "server_config_reload_refused",
                        outcome = "failure",
                        generation = generation,
                        reason = error.kind(),
                        error = %error,
                    ),
                    _ => error!(
                        event = "server_config_reload_failed",
                        outcome = "failure",
                        generation = generation,
                        reason = error.kind(),
                        error = %error,
                    ),
                }
                if let Some(respond) = request.respond {
                    let _ = respond.send(Err(error));
                }
            }
        }
    }
}
