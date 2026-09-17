//! The server runtime: how a configuration becomes routers, and how those are
//! served and rebuilt.
//!
//! Startup is split on the socket boundary, which is what lets a test drive the
//! whole path on an ephemeral port with its own shutdown future instead of a
//! process signal:
//!
//! - [`run`] binds `server.bind_address`, installs the `SIGHUP` handler, and
//!   hands the socket on. It is the whole of `acme-proxy serve`.
//! - [`serve_on`] validates the admin configuration and binds that socket too,
//!   when `[admin]` is enabled.
//! - [`serve_on_with`] does everything else — profile resolution, deduplicated
//!   signer backends, per-profile filters and validators, TLS, the job registry
//!   (every signer's handlers, notification delivery and the four table sweeps),
//!   the runner draining it, and `axum::serve` with connect info attached.
//!
//! That assembly is [`generation::build_generation`], and it is called again on
//! every reload rather than only at startup — so the two cannot drift, and a
//! subsystem added to one is added to the other by construction. What a reload
//! may change, and what it refuses by name, is [`crate::reload`]'s to say;
//! [`serve_on_with_reloads`] is where the two meet.
//!
//! - [`profile`] — one ACME endpoint, and how a generation builds each one.
//! - [`assembly`] — what a generation dials through, and what outlives it.
//! - [`router`] — the routers each listener serves, and their shared layers.
//! - [`generation`] — one generation built, then published: the reload policy.
//! - [`supervisor`] — the task that serialises reloads.
//! - [`sockets`] — the three listeners' binds, plans and announcements.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::Config;
use crate::sqlite::db::Database;

pub mod assembly;
pub mod generation;
pub mod profile;
pub mod router;
pub mod sockets;
pub mod supervisor;
#[cfg(test)]
mod tests;

pub use assembly::{Assembly, Egress, GenerationParts};
pub use profile::{Profile, ProfileParts};
pub use router::{AppState, build_app, build_router, catch_panic_acme, metrics_app};
pub(crate) use router::{panic_message, security_headers};
pub use sockets::check_metrics_config;

use generation::{Generation, announce_profile, build_generation};
use sockets::{
    announce_admin_listener, announce_metrics_listener, bind_admin, bind_metrics, bound_address,
};
use supervisor::{Cells, supervise_reloads};

/// Binds the configured sockets and runs the server until a shutdown signal
/// arrives: the whole of `acme-proxy serve`.
///
/// Every failure is logged here — `server_socket_bind_failed` for the ACME
/// socket, `server_fatal_error` for anything after it — and returned for the
/// caller to turn into an exit status.
pub async fn run(config: Arc<Config>, database: Arc<Database>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.server.bind_address)
        .await
        .map_err(|error| {
            error!(event = "server_socket_bind_failed",
                   outcome = "failure",
                   bind_address = %config.server.bind_address,
                   error = %error);
            anyhow::anyhow!("cannot bind {}: {error}", config.server.bind_address)
        })?;

    // Installed here, before anything slow: `SIGHUP`'s default disposition is
    // *terminate*, so until the handler exists a reload signal kills the
    // process. `serve_on_with_reloads` does profile assembly and the relay's
    // first upstream contact before it binds anything, which is exactly the
    // window an operator's `systemctl reload` could land in.
    let (reload_handle, reloads) = crate::reload::channel();
    let _hangups = AbortOnDrop(tokio::spawn(watch_for_hangup(reload_handle)));

    let fatal = |error: &anyhow::Error| {
        error!(event = "server_fatal_error", outcome = "failure", error = %error);
    };
    let admin_listener = bind_admin(&config).await.inspect_err(fatal)?;
    let metrics_listener = bind_metrics(&config).await.inspect_err(fatal)?;

    serve_on_with_reloads(
        config,
        database,
        listener,
        admin_listener,
        metrics_listener,
        shutdown_signal(),
        reloads,
    )
    .await
    .inspect_err(fatal)
}

/// Turns every `SIGHUP` into a reload request, for the life of the process.
///
/// Unlike the shutdown signal, this one does not consume its stream: an operator
/// reloads repeatedly, and a handler that fired once would leave the second
/// `SIGHUP` back at its default disposition — killing the server.
#[cfg(unix)]
async fn watch_for_hangup(handle: crate::reload::ReloadHandle) {
    let mut hangups = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(error) => {
            error!(event = "server_signal_handler_failed", outcome = "failure", signal = "SIGHUP", error = %error);
            return;
        }
    };
    while hangups.recv().await.is_some() {
        handle.trigger();
    }
}

/// No `SIGHUP` off Unix, so there is nothing to watch for.
#[cfg(not(unix))]
async fn watch_for_hangup(_handle: crate::reload::ReloadHandle) {
    std::future::pending::<()>().await;
}

/// Assembles and serves the application over an already-bound socket.
///
/// Split from [`run`] on the socket boundary: a caller supplying its own
/// listener and its own `shutdown` future can drive the whole startup path —
/// profile assembly, TLS, backend resume, the nonce reaper, both `axum::serve`
/// arms — without owning a fixed port or a process signal.
///
/// Binds the web admin socket itself when `[admin]` is enabled. The signature
/// is unchanged, and `admin.enabled` is false by default, so every existing
/// caller is untouched; a test that wants to drive *both* listeners supplies
/// its own pair through [`serve_on_with`].
pub async fn serve_on(
    config: Arc<Config>,
    database: Arc<Database>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let admin_listener = bind_admin(&config).await?;
    let metrics_listener = bind_metrics(&config).await?;
    serve_on_with(
        config,
        database,
        listener,
        admin_listener,
        metrics_listener,
        shutdown,
    )
    .await
}

/// [`serve_on`] with all three sockets supplied.
///
/// The full version, split on the same boundary and for the same reason: a
/// caller handing in three ephemeral ports can drive the whole startup path —
/// including that one shutdown signal stops all of them — without owning a
/// fixed port or a process signal.
pub async fn serve_on_with(
    config: Arc<Config>,
    database: Arc<Database>,
    listener: TcpListener,
    admin_listener: Option<TcpListener>,
    metrics_listener: Option<TcpListener>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_on_with_reloads(
        config,
        database,
        listener,
        admin_listener,
        metrics_listener,
        shutdown,
        crate::reload::Reloads::none(),
    )
    .await
}

/// [`serve_on_with`], serving configuration reloads as well as requests.
///
/// The variant [`run`] uses, so a `SIGHUP` rebuilds both routers, the job
/// registry, the notifier map and both TLS acceptors behind the sockets that are
/// already bound. Every other caller goes through [`serve_on_with`] and gets a
/// source that never fires, which costs one task that ends immediately.
///
/// See [`crate::reload`] for what a reload may change and what it refuses.
pub async fn serve_on_with_reloads(
    config: Arc<Config>,
    database: Arc<Database>,
    listener: TcpListener,
    admin_listener: Option<TcpListener>,
    metrics_listener: Option<TcpListener>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    reloads: crate::reload::Reloads,
) -> anyhow::Result<()> {
    info!(
        event = "server_startup",
        outcome = "success",
        bind_address = %config.server.bind_address,
        base_url = %config.server.base_url,
        tls = config.server.tls.enabled,
        database_database_url = %config.database.url
    );

    // One `shutdown` future, several consumers: both listeners and the job
    // runner. Created here rather than beside `axum::serve` below so a signal
    // arriving *during* startup is not ignored — profile assembly and the
    // relay's first upstream contact both happen before anything binds. The
    // relay task is held under `AbortOnDrop` so an error path below does not
    // leak a task parked on a signal that will never arrive.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _shutdown_relay = AbortOnDrop(tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    }));

    // The enqueue side of the durable queue. Built before the profiles because
    // a signer backend that defers issuance is handed one at construction, and
    // process-wide for the reason `[audit]` is: one table, one runner, and a
    // per-endpoint retry budget would make a job's pacing depend on which
    // profile happened to queue it.
    let job_queue = crate::jobs::JobQueue::new(database.clone(), &config.jobs);

    let resolved = config.resolve_profiles().inspect_err(|error| {
        error!(event = "profile_init_failed", outcome = "failure", error = %error);
    })?;
    // Everything that outlives a configuration generation — the signer backends
    // above all, which are carried rather than rebuilt. See
    // `crate::server::Assembly`.
    let (assembly, parts) = Assembly::new(&resolved, database.clone(), job_queue.clone(), &config)
        .inspect_err(|error| {
            error!(event = "profile_init_failed", outcome = "failure", error = %error);
        })?;
    let assembly = Arc::new(assembly);

    let generation =
        build_generation(&config, &resolved, &assembly, &parts, None).inspect_err(|error| {
            error!(event = "profile_init_failed", outcome = "failure", error = %error);
        })?;

    // Every endpoint in the first generation came up, so every one is announced.
    // A reload announces only the endpoints it *added* — see
    // `supervise_reloads`, which shares this function for exactly that reason.
    for profile in &generation.profiles {
        announce_profile(profile).await;
    }

    let Generation {
        profiles: _,
        acme_app,
        admin_app,
        job_registry,
        tls,
        admin_tls,
        logins,
    } = generation;

    // The one task that drains the queue. Held under `AbortOnDrop` for the same
    // reason the reapers are — an un-cancelled loop holding an `Arc<Database>`
    // per `serve_on` call — and, unlike the relay tasks this replaced, it does
    // *not* need to outlive this function: the work is durable now, so a job cut
    // short is re-claimed from its own row rather than lost. It takes the same
    // shutdown signal as both listeners, so a stop is graceful rather than an
    // abort: it releases its leases on the way out, and a restart therefore
    // re-claims its own work immediately instead of waiting one out.
    //
    // Neither the registry it drains nor the `[jobs]` section it paces itself
    // from is a value: both are cells a reload republishes, so a changed
    // retention, a rebuilt notify map and a retuned lease or concurrency all
    // reach the runner without restarting it. `jobs.max_attempts` is the third
    // piece and does not come through here — it belongs to the enqueue side, so
    // it is published onto `job_queue` itself.
    let (registry_tx, registry_rx) = tokio::sync::watch::channel(Arc::new(job_registry));
    let (jobs_tx, jobs_rx) = tokio::sync::watch::channel(Arc::new(config.jobs.clone()));
    let _job_runner = AbortOnDrop(crate::jobs::spawn_runner_watching(
        job_queue,
        registry_rx,
        jobs_rx,
        shutdown_rx.clone(),
    ));

    info!(
        event = "server_listening",
        outcome = "success",
        bind_address = %config.server.bind_address,
        protocol = if tls.is_some() { "https" } else { "http" }
    );

    // One accept loop per role, each owning a socket a reload can replace and a
    // TLS mode it can switch — see `crate::listener`. `axum::serve` below is
    // handed one of these instead of a `TcpListener` and therefore outlives
    // every rebind, which is what removes the listener from the list of things
    // only a restart can change.
    let admin_bound = bound_address(admin_listener.as_ref(), &config.admin.bind_address);
    let metrics_bound = bound_address(metrics_listener.as_ref(), &config.metrics.bind_address);
    let (acme_socket, acme_handle) = crate::listener::spawn("acme", Some(listener), tls);
    let (admin_socket, admin_handle) = crate::listener::spawn("admin", admin_listener, admin_tls);
    let (metrics_socket, metrics_handle) =
        crate::listener::spawn("metrics", metrics_listener, None);

    // Behind a swap cell rather than served directly, so a configuration reload
    // can replace the whole router without the socket moving. The cell is what
    // `axum::serve` holds; `acme_app` itself is only ever generation one.
    let (acme_router_tx, acme_router_rx) = crate::reload::router_channel(acme_app);
    let acme = serve_role(
        crate::reload::swappable(acme_router_rx),
        acme_socket,
        shutdown_rx.clone(),
    );

    // Opened whether or not the panel is on, unlike the app inside it: with
    // `admin.enabled` reloadable, a cell created only when the panel starts
    // would be the one thing a reload turning it on could not reach. An empty
    // `Router` answers `404` to everything, which is also what the panel being
    // switched off later publishes here.
    let (admin_router_tx, admin_router_rx) =
        crate::reload::router_channel(admin_app.unwrap_or_default());
    let admin = serve_role(
        crate::reload::swappable(admin_router_rx),
        admin_socket,
        shutdown_rx.clone(),
    );
    if config.admin.enabled {
        announce_admin_listener(&config, &database, &admin_bound).await;
    }

    // The third listener. Served directly rather than through a
    // `reload::router_channel` like the other two, and the asymmetry is
    // deliberate: this router has one route whose only state is the registry,
    // and the registry is carried across generations rather than rebuilt (see
    // `Assembly`), so a new generation could put nothing new in it.
    if config.metrics.enabled {
        announce_metrics_listener(&metrics_bound);
    }
    let metrics = serve_role(
        metrics_app(assembly.metrics.clone()),
        metrics_socket,
        shutdown_rx,
    );

    // The supervisor owns every cell sender from here on, which is what makes it
    // the only writer: a generation is published by one task or by nobody.
    // Aborted on drop, so an error return below does not leave it parked on a
    // channel nothing will ever send to.
    let _reload_supervisor = AbortOnDrop(tokio::spawn(supervise_reloads(
        reloads,
        config.clone(),
        resolved,
        assembly,
        Cells {
            acme_router: acme_router_tx,
            admin_router: admin_router_tx,
            job_registry: registry_tx,
            jobs: jobs_tx,
            acme: acme_handle,
            admin: admin_handle,
            metrics: metrics_handle,
        },
        logins,
    )));

    // Nothing is drained here any more. A notification in flight at shutdown is
    // a `notify_deliver` row, not a spawned task: the runner released its lease
    // on the way out and whoever starts next claims it. That is what replaced a
    // best-effort five-second drain which still lost anything slower than it.
    tokio::try_join!(acme, admin, metrics)?;
    Ok(())
}

/// Serves `app` on one role's socket until the process shuts down.
///
/// One shape for all three roles, where there used to be a boxed future per
/// listener per TLS arm: [`crate::listener::RoleSocket`] is the same type
/// whether the role is speaking TLS, speaking cleartext or — a socket having
/// been closed by a reload — not serving at all, so the four cases collapse into
/// this one call. Its future lives for the process: a rebind replaces what is
/// underneath it, never the `axum::serve` above.
fn serve_role(
    app: axum::Router,
    socket: crate::listener::RoleSocket,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> impl Future<Output = std::io::Result<()>> + Send {
    axum::serve(
        socket,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(on_shutdown(shutdown))
    .into_future()
}

/// A future that completes when the shutdown relay fires.
async fn on_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    // An error means the sender was dropped, which only happens when the relay
    // task itself is gone — treat it as "shut down" rather than parking
    // forever.
    let _ = receiver.wait_for(|ready| *ready).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Aborts a background task when it goes out of scope.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
