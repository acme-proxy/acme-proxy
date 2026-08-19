//! The command tree, and the startup path itself.
//!
//! **Nothing here prints or exits.** Every command body returns
//! `Result<(), CliError>` and [`dispatch`] routes to it, so each arm is a plain
//! function a test can call and assert on rather than an unreachable dead end.
//! `src/main.rs` is where that `Result` becomes an exit status, and it is the
//! only place in the project that calls `std::process::exit` — a library whose
//! failure mode is ending the process is one nothing else can use.
//!
//! Startup is split on the socket boundary, which is what lets a test drive the
//! whole path on an ephemeral port with its own shutdown future instead of a
//! process signal:
//!
//! - `serve` binds `server.bind_address`, installs the `SIGHUP` handler, and
//!   hands the socket on.
//! - [`serve_on`] validates the admin configuration and binds that socket too,
//!   when `[admin]` is enabled.
//! - [`serve_on_with`] does everything else — profile resolution, deduplicated
//!   signer backends, per-profile filters and validators, TLS, the job registry
//!   (every signer's handlers, notification delivery and the four table sweeps),
//!   the runner draining it, and `axum::serve` with connect info attached.
//!
//! That assembly is [`build_generation`], and it is called again on every
//! reload rather than only at startup — so the two cannot drift, and a
//! subsystem added to one is added to the other by construction. What a reload
//! may change, and what it refuses by name, is [`crate::reload`]'s to say;
//! [`serve_on_with_reloads`] is where the two meet.
//!
//! The logic behind each admin subcommand lives in [`crate::admin`], not here;
//! this module is the `clap` surface over it. [`logging`] turns `[logging]` into
//! an installed subscriber, validating every value before installing anything.

use std::future::Future;
use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub mod account;
pub mod audit;
pub mod eab;
pub mod filter;
mod logging;

/// Installs the `[logging]` configuration. Re-exported because `main.rs` is
/// what calls it — see [`dispatch`].
pub use logging::init_logging;
pub mod nonce;
pub mod order;
pub mod upstream;
pub mod webadmin;

pub use account::AccountCommand;
pub use audit::AuditCommand;
pub use eab::EabCommand;
pub use nonce::NonceCommand;
pub use order::OrderCommand;
pub use upstream::UpstreamCommand;
pub use webadmin::AdminCommand;

use crate::cli::filter::FilterCommand;
use crate::config::Config;
use crate::sqlite::db::Database;
use crate::{Profile, build_app, tls};

#[derive(Parser)]
#[command(
    name = "acme-proxy",
    about = "ACME server, plus admin commands for its database"
)]
pub struct Cli {
    /// Skip interactive "Are you sure?" confirmation on destructive commands.
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the ACME HTTP(S) server. Default when no subcommand is given.
    Serve,
    /// Inspect and manage ACME accounts.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Inspect and manage ACME orders.
    Order {
        #[command(subcommand)]
        command: OrderCommand,
    },
    /// Read and prune the CA's audit trail.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Nonce table maintenance.
    Nonce {
        #[command(subcommand)]
        command: NonceCommand,
    },
    /// Manage External Account Binding (EAB) credentials.
    Eab {
        #[command(subcommand)]
        command: EabCommand,
    },
    /// Read and test the access policy of an endpoint.
    Filter {
        #[command(subcommand)]
        command: FilterCommand,
    },
    /// Manage this server's own account at the upstream ACME server
    /// (`signer.backend = "relay"`).
    Upstream {
        #[command(subcommand)]
        command: UpstreamCommand,
    },
    /// Manage the web admin's operators and their sessions. This is how the
    /// panel is bootstrapped: it has no sign-up page.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

/// Picks the profile a command acts on.
///
/// `--profile` is optional only when the configuration defines exactly one:
/// most per-profile sections would otherwise be acted on ambiguously, and
/// guessing is worse than asking. Shared by `upstream` and `filter`, which had
/// grown one copy each.
pub(crate) fn resolve_profile(
    config: &Config,
    wanted: Option<&str>,
) -> Result<crate::config::ProfileConfig, CliError> {
    let profiles = config
        .resolve_profiles()
        .map_err(|error| CliError(format!("configuration error: {error}")))?;

    match wanted {
        Some(name) => profiles
            .into_iter()
            .find(|profile| profile.name == name)
            .ok_or_else(|| CliError(format!("no profile named `{name}` in this configuration"))),
        None if profiles.len() == 1 => Ok(profiles.into_iter().next().expect("length checked")),
        None => {
            let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
            Err(CliError(format!(
                "this configuration defines several profiles ({}); say which one with --profile",
                names.join(", ")
            )))
        }
    }
}

/// A command that could not complete, carrying the message to print.
///
/// Every failing branch below returns one of these instead of calling
/// `std::process::exit` where it stands: `main.rs` is the single place that
/// prints and exits, so each command body stays a plain function a test can
/// call and assert on.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CliError(pub String);

impl From<sqlx::Error> for CliError {
    fn from(error: sqlx::Error) -> Self {
        Self(format!("database error: {error}"))
    }
}

/// Routes a parsed command to its handler.
///
/// The library's entry point. Everything above it — parsing argv, loading the
/// configuration, installing the subscriber, opening the database, printing a
/// failure and exiting — lives in `src/main.rs`, because those are the
/// binary's job and not a library's: nothing that links this crate can use a
/// function whose failure mode is `std::process::exit`.
pub async fn dispatch(
    command: Option<Command>,
    yes: bool,
    reader: &mut impl BufRead,
    config: &Arc<Config>,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config.clone(), database).await,
        Command::Account { command } => {
            account::run_account_command(command, yes, reader, config, database).await
        }
        Command::Order { command } => {
            order::run_order_command(command, yes, reader, config, database).await
        }
        Command::Audit { command } => {
            audit::run_audit_command(command, yes, reader, database).await
        }
        Command::Nonce { command } => {
            nonce::run_nonce_command(command, yes, reader, config, database).await
        }
        Command::Eab { command } => eab::run_eab_command(command, database).await,
        Command::Filter { command } => filter::run_filter_command(command, config).await,
        Command::Upstream { command } => {
            upstream::run_upstream_command(command, reader, config).await
        }
        Command::Admin { command } => {
            webadmin::run_admin_command(command, yes, reader, database).await
        }
    }
}

/// Binds the configured socket and runs the ACME HTTP(S) server until a
/// shutdown signal arrives.
pub async fn serve(config: Arc<Config>, database: Arc<Database>) -> Result<(), CliError> {
    let listener = TcpListener::bind(&config.server.bind_address)
        .await
        .map_err(|error| {
            error!(event = "server_socket_bind_failed", outcome = "failure", bind_address = %config.server.bind_address, error = %error);
            CliError(format!(
                "cannot bind {}: {error}",
                config.server.bind_address
            ))
        })?;

    // Installed here, before anything slow: `SIGHUP`'s default disposition is
    // *terminate*, so until the handler exists a reload signal kills the
    // process. `serve_on_with_reloads` does profile assembly and the relay's
    // first upstream contact before it binds anything, which is exactly the
    // window an operator's `systemctl reload` could land in.
    let (reload_handle, reloads) = crate::reload::channel();
    let _hangups = AbortOnDrop(tokio::spawn(watch_for_hangup(reload_handle)));

    let admin_listener = bind_admin(&config).await.map_err(|error| {
        error!(event = "server_fatal_error", outcome = "failure", error = %error);
        CliError(error.to_string())
    })?;
    let metrics_listener = bind_metrics(&config).await.map_err(|error| {
        error!(event = "server_fatal_error", outcome = "failure", error = %error);
        CliError(error.to_string())
    })?;

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
    .map_err(|error| {
        error!(event = "server_fatal_error", outcome = "failure", error = %error);
        CliError(error.to_string())
    })
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

/// Validates the admin configuration and binds its socket when it is enabled.
///
/// Shared by [`serve`] and [`serve_on`] rather than living in one of them: both
/// need it, and the validation must happen **before anything binds**, so a
/// misconfigured panel cannot take the ACME listener down with it halfway
/// through startup.
async fn bind_admin(config: &Arc<Config>) -> anyhow::Result<Option<TcpListener>> {
    crate::webadmin::check_config(config).inspect_err(|error| {
        error!(event = "admin_config_invalid", outcome = "failure", error = %error);
    })?;

    match config.admin.enabled {
        false => Ok(None),
        true => Ok(Some(
            TcpListener::bind(&config.admin.bind_address)
                .await
                .inspect_err(|error| {
                    error!(event = "admin_socket_bind_failed",
                           outcome = "failure",
                           bind_address = %config.admin.bind_address,
                           error = %error);
                })?,
        )),
    }
}

/// Binds the metrics socket when `[metrics]` is on, refusing a collision first.
///
/// The twin of [`bind_admin`], and the same shape for the same reason: a socket
/// that cannot be bound must stop startup rather than leave the process running
/// with one of its three listeners silently missing.
///
/// Deliberately **no loopback check**. `webadmin::check_config` refuses a
/// non-loopback admin bind without TLS because that listener's cookie is always
/// `Secure`, which a browser will not store over plain HTTP, so the failure
/// would be invisible. Nothing here has a cookie: a metrics port reachable from
/// a Prometheus host on another machine is the intended deployment, and the
/// firewall is what bounds it.
async fn bind_metrics(config: &Arc<Config>) -> anyhow::Result<Option<TcpListener>> {
    if !config.metrics.enabled {
        return Ok(None);
    }

    // Three listeners, so the collision check is pairwise. `webadmin` already
    // refuses admin-versus-server; these are the two pairs it cannot see.
    // Checked even when `[admin]` is off, since enabling the panel later must
    // not be what surfaces a latent conflict.
    let bind = &config.metrics.bind_address;
    for (name, other) in [
        ("server.bind_address", &config.server.bind_address),
        ("admin.bind_address", &config.admin.bind_address),
    ] {
        if bind == other && (name != "admin.bind_address" || config.admin.enabled) {
            error!(event = "metrics_config_invalid",
                   outcome = "failure",
                   bind_address = %bind);
            anyhow::bail!(
                "metrics.bind_address and {name} are both `{bind}`: the metrics endpoint is a \
                 separate listener and cannot share a socket (give it its own port)"
            );
        }
    }

    let listener = TcpListener::bind(bind).await.inspect_err(|error| {
        error!(event = "metrics_socket_bind_failed",
               outcome = "failure",
               bind_address = %bind,
               error = %error);
    })?;
    Ok(Some(listener))
}

/// Assembles and serves the application over an already-bound socket.
///
/// Split from [`serve`] on the socket boundary: a caller supplying its own
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
/// The variant `serve` uses, so a `SIGHUP` rebuilds both routers, the job
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
    // above all, which are carried rather than rebuilt. See `crate::Assembly`.
    let (assembly, dispatchers) =
        crate::Assembly::new(&resolved, database.clone(), job_queue.clone(), &config).inspect_err(
            |error| {
                error!(event = "profile_init_failed", outcome = "failure", error = %error);
            },
        )?;

    let generation = build_generation(
        &config,
        &resolved,
        &assembly,
        dispatchers,
        admin_listener.is_some(),
        None,
    )
    .inspect_err(|error| {
        error!(event = "profile_init_failed", outcome = "failure", error = %error);
    })?;

    // Startup only, deliberately not re-run on a reload: `profile_mounted` means
    // "this endpoint came up", and re-firing it on every SIGHUP would make the
    // notify surface noisiest in exactly the config-managed deployments that
    // would least want it.
    for profile in &generation.profiles {
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
    // The registry it drains is a cell, not a value: a reload republishes it so
    // a changed retention or a rebuilt notify map reaches the runner without
    // restarting it.
    let (registry_tx, registry_rx) = tokio::sync::watch::channel(Arc::new(job_registry));
    let _job_runner = AbortOnDrop(crate::jobs::spawn_runner_watching(
        job_queue,
        registry_rx,
        &config.jobs,
        shutdown_rx.clone(),
    ));

    info!(
        event = "server_listening",
        outcome = "success",
        bind_address = %config.server.bind_address,
        protocol = if tls.is_some() { "https" } else { "http" }
    );

    // Behind a swap cell rather than served directly, so a configuration reload
    // can replace the whole router without the socket moving. The cell is what
    // `axum::serve` holds; `acme_app` itself is only ever generation one.
    let (acme_router_tx, acme_router_rx) = crate::reload::router_channel(acme_app);
    let app = crate::reload::swappable(acme_router_rx);

    // Boxed rather than four `match` arms: the TLS and cleartext paths produce
    // different listener types, and each listener has its own.
    let mut tls_tx = None;
    let acme: Serving = match tls {
        Some(settings) => {
            let (sender, tls_rx) = tokio::sync::watch::channel(settings);
            tls_tx = Some(sender);
            let listener = tls::TlsListener::spawn(listener, tls_rx).inspect_err(|error| {
                error!(event = "tls_listener_start_failed", outcome = "failure", error = %error);
            })?;
            Box::pin(
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(on_shutdown(shutdown_rx.clone()))
                .into_future(),
            )
        }
        None => Box::pin(
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(on_shutdown(shutdown_rx.clone()))
            .into_future(),
        ),
    };

    // Taken before the admin arm consumes `shutdown_rx`, so all three listeners
    // stop on the one signal — the property `serve_on_with`'s three-port test
    // exists to pin.
    let metrics_shutdown_rx = shutdown_rx.clone();

    let mut admin_router_tx = None;
    let mut admin_tls_tx = None;
    let admin: Serving = match (admin_app, admin_listener) {
        (Some(app), Some(listener)) => {
            let (serving, cells) = serve_admin(
                &config,
                database.clone(),
                app,
                admin_tls,
                listener,
                shutdown_rx,
            )
            .await?;
            admin_router_tx = Some(cells.router);
            admin_tls_tx = cells.tls;
            serving
        }
        // The panel is off: a future that is already done, so `try_join!`
        // below needs no second shape.
        _ => Box::pin(std::future::ready(Ok(()))),
    };

    // The third listener. Served directly rather than through a
    // `reload::router_channel` like the other two, and the asymmetry is
    // deliberate: this router has one route whose only state is the registry,
    // and the registry is carried across generations rather than rebuilt (see
    // `Assembly`), so a new generation could put nothing new in it. Both
    // `[metrics]` keys are frozen for the reason every bind address is — the
    // socket cannot move under a listener that is already serving.
    let metrics: Serving = match metrics_listener {
        Some(listener) => {
            info!(
                event = "metrics_listening",
                outcome = "success",
                bind_address = %config.metrics.bind_address,
                "unauthenticated by design: the port is the boundary, so firewall it"
            );
            let app = crate::metrics_app(assembly.metrics.clone());
            Box::pin(
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(on_shutdown(metrics_shutdown_rx))
                .into_future(),
            )
        }
        None => Box::pin(std::future::ready(Ok(()))),
    };

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
            tls: tls_tx,
            admin_tls: admin_tls_tx,
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

/// The admin listener's swap cells, handed back so the supervisor owns them.
struct AdminCells {
    router: tokio::sync::watch::Sender<axum::routing::RouterIntoService<axum::body::Body>>,
    tls: Option<tokio::sync::watch::Sender<tls::TlsSettings>>,
}

/// Everything one configuration generation contributes, built and validated
/// before any of it is published.
///
/// The unit exists so startup and reload cannot drift: both go through
/// [`build_generation`], so a subsystem added to one is added to the other by
/// construction rather than by remembering.
pub(crate) struct Generation {
    /// Kept so startup can announce them; a reload drops them on the floor,
    /// since `profile_mounted` is a lifecycle event and not a heartbeat.
    profiles: Vec<Arc<Profile>>,
    acme_app: axum::Router,
    admin_app: Option<axum::Router>,
    job_registry: crate::jobs::JobRegistry,
    tls: Option<tls::TlsSettings>,
    admin_tls: Option<tls::TlsSettings>,
    /// The limiter this generation ended up with, for the next one to carry.
    logins: Option<Arc<crate::webadmin::LoginLimiter>>,
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
pub(crate) fn build_generation(
    config: &Arc<Config>,
    resolved: &[crate::config::ProfileConfig],
    assembly: &crate::Assembly,
    dispatchers: crate::notify::DispatcherMap,
    admin_enabled: bool,
    previous_logins: Option<&crate::webadmin::LoginLimiter>,
) -> anyhow::Result<Generation> {
    let database = assembly.database.clone();
    let profiles = Profile::build_all_with(config, resolved, assembly, &dispatchers)?;

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

    // Every subsystem with background work, in one registry. Deduplicated by
    // `Arc` identity: two profiles can share one signer backend, and its handler
    // must be registered once — the registry refuses a second handler for one
    // kind outright, since two would each claim about half the rows. The
    // identity is kept as a `usize` rather than the pointer itself, so this
    // function's caller stays `Send`; it is spawned.
    let mut job_registry = crate::jobs::JobRegistry::new();
    let mut registered: Vec<usize> = Vec::new();
    for profile in &profiles {
        let identity = Arc::as_ptr(&profile.signer).cast::<()>() as usize;
        if registered.contains(&identity) {
            continue;
        }
        registered.push(identity);
        for handler in profile.signer.jobs() {
            job_registry.register(handler).inspect_err(|error| {
                error!(event = "job_registry_init_failed", outcome = "failure", error = %error);
            })?;
        }
    }
    // Notification delivery. **Not** deduplicated by `Arc` identity like the
    // signer handlers above: there is one handler for every profile, holding the
    // whole `profile name -> dispatcher` map, and a job row names its own
    // profile. Registered unconditionally — a profile with no `[notify]`
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
    // here rather than in `Profile::build_all` for exactly that reason — it is
    // not a per-endpoint subsystem.
    let auditor = Arc::new(
        crate::audit::Auditor::from_config(
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

/// The cells one generation is published into.
///
/// Held by the supervisor and by nothing else. Every field is a `watch::Sender`,
/// and `send_replace` is synchronous — so publishing a generation is a run of
/// sends with no `.await` between them, which no other task can interleave with.
/// That is what makes a reload atomic without a lock.
struct Cells {
    acme_router: tokio::sync::watch::Sender<axum::routing::RouterIntoService<axum::body::Body>>,
    admin_router:
        Option<tokio::sync::watch::Sender<axum::routing::RouterIntoService<axum::body::Body>>>,
    job_registry: tokio::sync::watch::Sender<Arc<crate::jobs::JobRegistry>>,
    tls: Option<tokio::sync::watch::Sender<tls::TlsSettings>>,
    admin_tls: Option<tokio::sync::watch::Sender<tls::TlsSettings>>,
}

/// Serves reload requests for the life of the process.
///
/// One task, so reloads are serialised: two overlapping rebuilds could publish
/// their cells interleaved, and the second-newest generation would win some of
/// them. Ends when the last [`crate::reload::ReloadHandle`] is dropped, which is
/// what makes [`crate::reload::Reloads::none`] cost nothing.
async fn supervise_reloads(
    mut reloads: crate::reload::Reloads,
    mut config: Arc<Config>,
    mut resolved: Vec<crate::config::ProfileConfig>,
    assembly: crate::Assembly,
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

        let outcome = apply_reload(
            &config,
            &resolved,
            &assembly,
            &cells,
            logins.as_deref(),
            generation + 1,
            started,
        );

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
                    logging_reloaded = report.logging_reloaded,
                    duration_ms = crate::millis(report.duration),
                );
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

/// What one successful reload hands back to the supervisor: the report to log,
/// and the three pieces of state the *next* reload compares against.
///
/// A struct rather than the 4-tuple this used to return — which needed
/// `#[allow(clippy::type_complexity)]` and left the caller destructuring four
/// same-shaped values positionally, where swapping two would still compile.
/// The same move `ProfileParts` made, for the same reason.
struct Reloaded {
    report: crate::reload::ReloadReport,
    config: Arc<Config>,
    resolved: Vec<crate::config::ProfileConfig>,
    logins: Option<Arc<crate::webadmin::LoginLimiter>>,
}

/// One reload attempt: build everything, then publish it.
///
/// Every fallible step happens before the first `send_replace`, so a failure
/// anywhere leaves the running generation untouched — which is the property the
/// whole "atomic, refuse by name" decision exists for.
///
/// Not `async`, and that is load-bearing rather than incidental: the publishing
/// run at the end cannot be interleaved by another task if there is no await
/// point in it.
fn apply_reload(
    config: &Arc<Config>,
    resolved: &[crate::config::ProfileConfig],
    assembly: &crate::Assembly,
    cells: &Cells,
    logins: Option<&crate::webadmin::LoginLimiter>,
    generation: u64,
    started: std::time::Instant,
) -> Result<Reloaded, crate::reload::ReloadError> {
    use crate::reload::{Applied, ReloadError, ReloadReport, check_frozen};

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
    // `Assembly::build_dispatchers` makes.
    let logging = logging::prepare_logging(&next.logging).map_err(ReloadError::Build)?;
    let logging_filter_from_env = logging.filter_from_env;

    // The same validation startup runs before either socket binds, so a panel
    // that would refuse to start refuses to be reloaded into. It also compiles
    // every `admin.template_dir` override, which is what keeps a broken one a
    // failed reload rather than a 500 in a browser.
    crate::webadmin::check_config(&next).map_err(|error| ReloadError::Build(error.to_string()))?;

    let dispatchers = assembly
        .build_dispatchers(&next_resolved)
        .map_err(|error| ReloadError::Build(error.to_string()))?;
    let generation_built = build_generation(
        &next,
        &next_resolved,
        assembly,
        dispatchers.clone(),
        cells.admin_router.is_some(),
        logins,
    )
    .map_err(|error| ReloadError::Build(error.to_string()))?;

    let next_logins = generation_built.logins.clone();

    // Everything below is infallible and synchronous. The order matters in two
    // places. `[logging]` goes **first**, because an operator who raised the
    // level did it to see what happens next, starting with this reload's own
    // completion line. And the notifier map and the job registry go **before**
    // the routers: a request served by the new generation queues a
    // `notify_deliver` row naming a slot id from the new configuration, and a
    // `NotifyJob` still holding the old map would retire it — permanently,
    // since an unknown backend id is a `Failed`, not a `Retry`.
    let logging_reloaded = logging::publish_logging(logging);

    let report = ReloadReport {
        generation,
        profiles: generation_built
            .profiles
            .iter()
            .map(|profile| profile.name.clone())
            .collect(),
        job_kinds: generation_built.job_registry.kinds(),
        tls_reloaded: generation_built.tls.is_some() && cells.tls.is_some(),
        admin_tls_reloaded: generation_built.admin_tls.is_some() && cells.admin_tls.is_some(),
        logging_reloaded,
        duration: started.elapsed(),
    };

    assembly.publish_notifiers(dispatchers);
    cells
        .job_registry
        .send_replace(Arc::new(generation_built.job_registry));
    if let (Some(cell), Some(settings)) = (&cells.tls, generation_built.tls) {
        cell.send_replace(settings);
    }
    if let (Some(cell), Some(settings)) = (&cells.admin_tls, generation_built.admin_tls) {
        cell.send_replace(settings);
    }
    cells
        .acme_router
        .send_replace(generation_built.acme_app.into_service::<axum::body::Body>());
    if let (Some(cell), Some(router)) = (&cells.admin_router, generation_built.admin_app) {
        cell.send_replace(router.into_service::<axum::body::Body>());
    }

    // `RUST_LOG` outranks `logging.filter` on a reload exactly as it does at
    // startup — the two disagreeing would be worse — but that makes an edited
    // `logging.filter` a silent no-op, which is the one outcome an operator
    // would read as "my reload did not land". Said only when both halves hold:
    // the environment won, *and* the file's filter actually moved.
    if logging_filter_from_env && config.logging.filter != next.logging.filter {
        warn!(
            event = "server_logging_filter_overridden",
            outcome = "advisory",
            configured = %next.logging.filter,
        );
    }

    Ok(Reloaded {
        report,
        config: next,
        resolved: next_resolved,
        logins: next_logins,
    })
}

/// One listener's `axum::serve` future, boxed so the TLS and cleartext arms —
/// which have different listener types — can be joined as one shape.
type Serving = std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

/// A future that completes when the shutdown relay fires.
async fn on_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    // An error means the sender was dropped, which only happens when the relay
    // task itself is gone — treat it as "shut down" rather than parking
    // forever.
    let _ = receiver.wait_for(|ready| *ready).await;
}

/// Starts the admin listener, logging the **resolved** address so a `:0` bind
/// is discoverable, and warning when nobody can sign in yet.
async fn serve_admin(
    config: &Arc<Config>,
    database: Arc<Database>,
    app: axum::Router,
    tls: Option<tls::TlsSettings>,
    listener: TcpListener,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<(Serving, AdminCells)> {
    let bind_address = listener.local_addr().map_or_else(
        |_| config.admin.bind_address.clone(),
        |addr| addr.to_string(),
    );

    // A listener nobody holds an account for is a running service with no way
    // in; say so once, naming the command that fixes it.
    if crate::sqlite::admin_user::AdminUser::list_all(&database)
        .await
        .is_ok_and(|users| users.is_empty())
    {
        warn!(
            event = "admin_no_users",
            outcome = "advisory",
            "the web admin is enabled but has no operators: create one with \
               `acme-proxy admin user create <username>`"
        );
    }

    // Repeated on every start while it holds, the `challenge_validation_bypassed`
    // treatment: these operators can still sign in, they are simply made to
    // enrol before their session becomes usable, and that stays worth seeing
    // for exactly as long as it is true.
    if config.admin.require_mfa
        && let Ok(count) = crate::admin::mfa::operators_without_a_factor(database.clone()).await
        && count > 0
    {
        warn!(
            event = "admin_mfa_enrolment_pending",
            outcome = "advisory",
            count = count,
            "admin.require_mfa is on and some operators have no second factor: \
               their next sign-in will require enrolment before the session is usable"
        );
    }

    // Swept once now, then on an interval: sessions outlive a restart, so a
    // startup-only sweep would leak every one an operator never signed out of.
    let idle = Duration::from_secs(config.admin.session_idle_timeout_seconds);
    if let Err(error) = crate::sqlite::admin_session::AdminSession::cleanup(idle, &database).await {
        error!(event = "admin_session_cleanup_failed", outcome = "failure", error = %error);
    }

    info!(
        event = "admin_listening",
        outcome = "success",
        bind_address = %bind_address,
        protocol = if tls.is_some() { "https" } else { "http" },
        base_url = %config.admin.base_url
    );

    // The admin router's own swap cell, for the same reason as the ACME one.
    let (admin_router_tx, admin_router_rx) = crate::reload::router_channel(app);
    let app = crate::reload::swappable(admin_router_rx);

    let mut tls_tx = None;
    let serving: Serving = match tls {
        Some(settings) => {
            let (sender, tls_rx) = tokio::sync::watch::channel(settings);
            tls_tx = Some(sender);
            let listener =
                tls::TlsListener::spawn(listener, tls_rx).inspect_err(|error| {
                    error!(event = "admin_tls_listener_start_failed", outcome = "failure", error = %error);
                })?;
            Box::pin(
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(on_shutdown(shutdown))
                .into_future(),
            )
        }
        None => Box::pin(
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(on_shutdown(shutdown))
            .into_future(),
        ),
    };

    Ok((
        serving,
        AdminCells {
            router: admin_router_tx,
            tls: tls_tx,
        },
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_subcommands() {
        let cli = Cli::try_parse_from(["acme-proxy"]).unwrap();
        assert!(cli.command.is_none());

        let cli = Cli::try_parse_from(["acme-proxy", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Serve)));

        let cli = Cli::try_parse_from(["acme-proxy", "account", "list", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account {
                command: AccountCommand::List {
                    json: true,
                    profile: None
                }
            })
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "account", "show", "acct-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account {
                command: AccountCommand::Show { id, json: false }
            }) if id == "acct-1"
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "account",
            "update-contact",
            "acct-1",
            "--contact",
            "mailto:test@example.com",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account {
                command: AccountCommand::UpdateContact { id, contact }
            }) if id == "acct-1" && contact == vec!["mailto:test@example.com"]
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "account", "deactivate", "acct-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account {
                command: AccountCommand::Deactivate { id }
            }) if id == "acct-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "-y", "account", "delete", "acct-1"]).unwrap();
        assert!(cli.yes);
        assert!(matches!(
            cli.command,
            Some(Command::Account {
                command: AccountCommand::Delete { id }
            }) if id == "acct-1"
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "order",
            "list",
            "--account-id",
            "acct-1",
            "--status",
            "pending",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::List {
                    profile: None,
                    account_id: Some(a),
                    status: Some(s),
                    json: true
                }
            }) if a == "acct-1" && s == "pending"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "order", "show", "ord-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::Show { id, json: false }
            }) if id == "ord-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "order", "delete", "ord-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::Delete { id }
            }) if id == "ord-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "order", "revoke", "ord-1", "--reason", "1"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::Revoke { id, reason: Some(1) }
            }) if id == "ord-1"
        ));

        let cli =
            Cli::try_parse_from(["acme-proxy", "nonce", "cleanup", "--ttl-seconds", "60"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Nonce {
                command: NonceCommand::Cleanup {
                    ttl_seconds: Some(60)
                }
            })
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "eab",
            "create",
            "--label",
            "test-key",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Eab {
                command: EabCommand::Create { label: Some(l), profile: None, json: true }
            }) if l == "test-key"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "eab", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Eab {
                command: EabCommand::List { json: false }
            })
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "eab", "show", "kid-1", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Eab {
                command: EabCommand::Show { kid, json: true }
            }) if kid == "kid-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "upstream", "register", "--eab-kid", "kid-1"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Upstream {
                command: UpstreamCommand::Register { eab_kid: Some(kid), eab_hmac_key_file: None, profile: None }
            }) if kid == "kid-1"
        ));

        // Registering against an upstream that needs no credential.
        let cli = Cli::try_parse_from(["acme-proxy", "upstream", "register"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Upstream {
                command: UpstreamCommand::Register {
                    eab_kid: None,
                    eab_hmac_key_file: None,
                    profile: None,
                }
            })
        ));

        // The secret itself has no flag: it is stdin- or file-only, never argv.
        assert!(
            Cli::try_parse_from(["acme-proxy", "upstream", "register", "--eab-hmac-key", "s"])
                .is_err(),
            "an EAB secret must not be accepted on the command line"
        );

        let cli = Cli::try_parse_from(["acme-proxy", "upstream", "show", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Upstream {
                command: UpstreamCommand::Show {
                    json: true,
                    profile: None
                }
            })
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "eab", "revoke", "kid-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Eab {
                command: EabCommand::Revoke { kid }
            }) if kid == "kid-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "admin", "user", "create", "alice"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Create {
                        username,
                        password_file: None
                    }
                }
            }) if username == "alice"
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "admin",
            "user",
            "passwd",
            "alice",
            "--password-file",
            "/run/secrets/pw",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Passwd {
                        username,
                        password_file: Some(path)
                    }
                }
            }) if username == "alice" && path == std::path::Path::new("/run/secrets/pw")
        ));

        // The password itself has no flag, for the same reason the EAB secret
        // has none: argv is visible in `ps` and lands in shell history.
        for command in ["create", "passwd"] {
            assert!(
                Cli::try_parse_from([
                    "acme-proxy",
                    "admin",
                    "user",
                    command,
                    "alice",
                    "--password",
                    "hunter2",
                ])
                .is_err(),
                "`admin user {command}` must not accept a password on the command line"
            );
        }

        let cli = Cli::try_parse_from(["acme-proxy", "admin", "user", "totp", "status", "alice"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Totp {
                        command: crate::cli::webadmin::AdminUserTotpCommand::Status {
                            username,
                            json: false
                        }
                    }
                }
            }) if username == "alice"
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "admin",
            "user",
            "totp",
            "recovery-codes",
            "alice",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Totp {
                        command: crate::cli::webadmin::AdminUserTotpCommand::RecoveryCodes {
                            username
                        }
                    }
                }
            }) if username == "alice"
        ));

        // There is no `enrol` from a terminal, deliberately: it would put the
        // base32 secret in scrollback and shell history. See the doc comment on
        // `AdminUserTotpCommand`.
        assert!(
            Cli::try_parse_from(["acme-proxy", "admin", "user", "totp", "enrol", "alice"]).is_err()
        );

        let cli =
            Cli::try_parse_from(["acme-proxy", "-y", "admin", "user", "delete", "alice"]).unwrap();
        assert!(cli.yes);
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Delete { username }
                }
            }) if username == "alice"
        ));

        let cli =
            Cli::try_parse_from(["acme-proxy", "admin", "session", "list", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::Session {
                    command: crate::cli::webadmin::AdminSessionCommand::List {
                        username: None,
                        json: true
                    }
                }
            })
        ));

        // `--user` and `--all` answer the same question two ways; clap refuses
        // both rather than letting one silently win.
        assert!(
            Cli::try_parse_from([
                "acme-proxy",
                "admin",
                "session",
                "revoke",
                "--user",
                "alice",
                "--all",
            ])
            .is_err(),
            "--user and --all are mutually exclusive"
        );
    }

    #[test]
    fn a_database_error_renders_as_a_cli_error() {
        let error = CliError::from(sqlx::Error::PoolClosed);
        assert!(error.to_string().starts_with("database error: "), "{error}");
    }

    /// Every arm reaches its command handler. `Serve` is deliberately absent —
    /// it owns a socket, and [`serve_on`] is what the tests below drive.
    #[tokio::test]
    async fn dispatch_routes_each_command() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Arc::new(Config::default());
        let mut reader: &[u8] = &[];

        let commands = vec![
            Command::Account {
                command: AccountCommand::List {
                    profile: None,
                    json: false,
                },
            },
            Command::Order {
                command: OrderCommand::List {
                    profile: None,
                    account_id: None,
                    status: None,
                    json: false,
                },
            },
            Command::Nonce {
                command: NonceCommand::Cleanup {
                    ttl_seconds: Some(1),
                },
            },
            Command::Eab {
                command: EabCommand::List { json: false },
            },
            // `Upstream` is deliberately absent: it acts on a *profile's*
            // `[signer.relay]`, and this config has none, so it now
            // reports that rather than silently reading the global base
            // section nothing serves from. Covered in `cli::upstream`'s own
            // tests, which supply a configuration with profiles.
        ];
        for command in commands {
            dispatch(Some(command), true, &mut reader, &config, database.clone())
                .await
                .expect("every command must succeed against an empty database");
        }
    }

    /// A failing command's message reaches [`dispatch`]'s caller rather than
    /// exiting the process where it was raised.
    #[tokio::test]
    async fn dispatch_propagates_a_command_failure() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Arc::new(Config::default());
        let mut reader: &[u8] = &[];

        let error = dispatch(
            Some(Command::Account {
                command: AccountCommand::Show {
                    id: "acct-nope".to_string(),
                    json: false,
                },
            }),
            true,
            &mut reader,
            &config,
            database,
        )
        .await
        .expect_err("an unknown account must fail");
        assert_eq!(error, CliError("no such account: acct-nope".to_string()));
    }

    mod serving {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        /// A single-profile configuration whose CA and TLS material all live
        /// under `dir`, so a test never touches the repository.
        fn config_in(dir: impl AsRef<std::path::Path>, tls: bool) -> Config {
            let dir = dir.as_ref();
            let _lock = crate::config::ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ca = dir.join("ca");
            let body = format!(
                r#"
                [server]
                bind_address = "127.0.0.1:0"
                base_url = "http://localhost:3000"

                [server.tls]
                enabled = {tls}
                cert_path = "{dir}/server.pem"
                key_path = "{dir}/server.key"

                [profiles.default]
                signer.local_ca.cert_path = "{ca}.pem"
                signer.local_ca.key_path = "{ca}.key"
                signer.local_ca.crl_path = "{ca}.crl"
                "#,
                dir = dir.display(),
                ca = ca.display(),
            );
            std::fs::write(dir.join("config.toml"), body).unwrap();
            // SAFETY: the lock above makes this the only thread touching the
            // environment, and the variable is removed before returning.
            unsafe {
                std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
            }
            let config = Config::load().expect("the configuration must load");
            unsafe {
                std::env::remove_var("ACME_PROXY_CONFIG");
            }
            config
        }

        fn temp_dir() -> crate::testutil::TempDir {
            crate::testutil::TempDir::new("serve")
        }

        /// Boots `serve_on` on an ephemeral loopback port and returns it with
        /// the handle and the trigger that shuts it back down.
        async fn boot(
            config: Config,
        ) -> (
            SocketAddr,
            tokio::sync::oneshot::Sender<()>,
            tokio::task::JoinHandle<anyhow::Result<()>>,
        ) {
            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(serve_on(Arc::new(config), database, listener, async {
                let _ = rx.await;
            }));
            (addr, tx, handle)
        }

        /// The cleartext path: real socket, real router, real graceful
        /// shutdown. `/health` is a root route, so this also proves the app
        /// `serve_on` assembles is the one `build_app` produces.
        #[tokio::test]
        async fn a_cleartext_server_answers_then_shuts_down() {
            let dir = temp_dir();
            let (addr, shutdown, handle) = boot(config_in(&dir, false)).await;

            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

            shutdown.send(()).unwrap();
            handle
                .await
                .unwrap()
                .expect("a clean shutdown is not an error");
        }

        /// The same path with `server.tls.enabled`, which swaps the listener
        /// for a `TlsListener` — a different `axum::serve` arm, and the only
        /// place `TlsListener::spawn` is wired up in production.
        #[tokio::test]
        async fn a_tls_server_answers_over_a_real_handshake() {
            use tokio_rustls::TlsConnector;
            use tokio_rustls::rustls::pki_types::ServerName;

            let dir = temp_dir();
            let (addr, shutdown, handle) = boot(config_in(&dir, true)).await;

            // The generated certificate is self-signed, so the client must not
            // try to verify it — the point here is the listener, not the trust
            // chain.
            let client =
                crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut tls = TlsConnector::from(client)
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

            shutdown.send(()).unwrap();
            handle
                .await
                .unwrap()
                .expect("a clean shutdown is not an error");
        }

        /// The three-listener path: one shutdown signal, three sockets, and
        /// each one serving only what belongs to it.
        ///
        /// This is the regression test for the `watch` split — before it, the
        /// `shutdown` future was consumed once and only one listener stopped —
        /// and now also for the metrics listener being genuinely *separate*:
        /// `/metrics` answering on the ACME port would put issuance volume and
        /// every profile name on the public socket, which is exactly what
        /// giving it its own port is for.
        #[tokio::test]
        async fn all_three_listeners_serve_and_one_signal_stops_them() {
            let dir = temp_dir();
            let mut config = config_in(&dir, false);
            config.admin.enabled = true;
            config.metrics.enabled = true;

            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let metrics_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let acme_addr = acme_listener.local_addr().unwrap();
            let admin_addr = admin_listener.local_addr().unwrap();
            let metrics_addr = metrics_listener.local_addr().unwrap();
            assert_ne!(acme_addr, admin_addr);
            assert_ne!(acme_addr, metrics_addr);
            assert_ne!(admin_addr, metrics_addr);

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(serve_on_with(
                Arc::new(config),
                database,
                acme_listener,
                Some(admin_listener),
                Some(metrics_listener),
                async {
                    let _ = rx.await;
                },
            ));

            // `/health` is on both of the two that have it.
            for addr in [acme_addr, admin_addr] {
                let response = get(addr, "/health").await;
                assert!(
                    response.starts_with("HTTP/1.1 200 OK"),
                    "{addr}: {response}"
                );
            }

            // The admin API answers on the admin socket (401, since this
            // request carries no session) and is absent from the ACME one.
            let admin = get(admin_addr, "/api/accounts").await;
            assert!(admin.starts_with("HTTP/1.1 401"), "{admin}");
            let acme = get(acme_addr, "/api/accounts").await;
            assert!(acme.starts_with("HTTP/1.1 404"), "{acme}");

            // And the converse: ACME is on the ACME socket only.
            let directory = get(acme_addr, "/profile/default/directory").await;
            assert!(directory.starts_with("HTTP/1.1 200 OK"), "{directory}");
            let no_directory = get(admin_addr, "/profile/default/directory").await;
            assert!(no_directory.starts_with("HTTP/1.1 404"), "{no_directory}");

            // The exposition is on its own socket...
            let metrics = get(metrics_addr, "/metrics").await;
            assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{metrics}");
            assert!(metrics.contains("acme_proxy_requests_total"), "{metrics}");
            // ...and on **neither** of the other two. The whole point of the
            // third listener is that firewalling this port is what controls who
            // can read it.
            for addr in [acme_addr, admin_addr] {
                let leaked = get(addr, "/metrics").await;
                assert!(leaked.starts_with("HTTP/1.1 404"), "{addr}: {leaked}");
            }

            // One signal, all three stop.
            tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .expect("every listener must stop on one signal")
                .unwrap()
                .expect("a clean shutdown is not an error");
        }

        /// Three listeners means the collision check is pairwise, and
        /// `webadmin::check_config` only covers admin-versus-server.
        #[tokio::test]
        async fn a_metrics_bind_colliding_with_another_listener_is_refused() {
            let dir = temp_dir();

            for (other, set) in [
                (
                    "server.bind_address",
                    Box::new(|c: &mut Config| {
                        c.metrics.bind_address = c.server.bind_address.clone()
                    }) as Box<dyn Fn(&mut Config)>,
                ),
                (
                    "admin.bind_address",
                    Box::new(|c: &mut Config| {
                        c.admin.enabled = true;
                        c.metrics.bind_address = c.admin.bind_address.clone();
                    }),
                ),
            ] {
                let mut config = config_in(&dir, false);
                config.metrics.enabled = true;
                set(&mut config);

                let error = bind_metrics(&Arc::new(config))
                    .await
                    .expect_err("a shared socket must not start");
                let message = error.to_string();
                assert!(message.contains(other), "{message}");
            }
        }

        /// The admin bind is only a conflict when the panel is actually going
        /// to bind it. Both default to loopback ports, so refusing on the
        /// *value* alone would reject a configuration that works.
        #[tokio::test]
        async fn a_metrics_bind_matching_a_disabled_admin_is_allowed() {
            let dir = temp_dir();
            let mut config = config_in(&dir, false);
            config.metrics.enabled = true;
            config.admin.enabled = false;
            config.metrics.bind_address = config.admin.bind_address.clone();

            let listener = bind_metrics(&Arc::new(config))
                .await
                .expect("a disabled panel holds no socket");
            assert!(listener.is_some());
        }

        /// Off by default, and off means no socket at all rather than one
        /// answering 404.
        #[tokio::test]
        async fn metrics_disabled_binds_nothing() {
            let dir = temp_dir();
            let config = config_in(&dir, false);
            assert!(!config.metrics.enabled);

            assert!(bind_metrics(&Arc::new(config)).await.unwrap().is_none());
        }

        /// The admin listener's **own** TLS arm.
        ///
        /// `[server.tls]` and `[admin.tls]` are separate settings with separate
        /// certificate paths, on purpose — the two listeners answer to
        /// different names — and they go through separate `axum::serve` arms in
        /// `serve_admin`. `a_tls_server_answers_over_a_real_handshake` covers
        /// the ACME one; this one was the only `TlsListener::spawn` call site
        /// in the crate with no test at all, which for the listener that
        /// carries an operator's session cookie is the wrong one to miss.
        #[tokio::test]
        async fn the_admin_listener_answers_over_its_own_tls() {
            use tokio_rustls::TlsConnector;
            use tokio_rustls::rustls::pki_types::ServerName;

            let dir = temp_dir();
            let mut config = config_in(&dir, false);
            config.admin.enabled = true;
            // A distinct certificate from the ACME listener's, which is the
            // whole reason these are two settings.
            config.admin.tls.enabled = true;
            config.admin.tls.cert_path = dir.as_ref().join("admin.pem").display().to_string();
            config.admin.tls.key_path = dir.as_ref().join("admin.key").display().to_string();
            // `check_config` refuses a non-loopback bind without TLS; with TLS
            // on it is allowed, and this exercises that branch too.
            config.admin.base_url = "https://localhost:3001".to_string();

            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let acme_addr = acme_listener.local_addr().unwrap();
            let admin_addr = admin_listener.local_addr().unwrap();

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(serve_on_with(
                Arc::new(config),
                database,
                acme_listener,
                Some(admin_listener),
                // This test is about the admin listener's own TLS arm; the
                // metrics listener has none.
                None,
                async {
                    let _ = rx.await;
                },
            ));

            // The ACME socket is still cleartext — the two settings really are
            // independent, which a shared switch would hide.
            let acme = get(acme_addr, "/health").await;
            assert!(acme.starts_with("HTTP/1.1 200 OK"), "{acme}");

            // The admin socket needs a handshake. Self-signed, so the client
            // verifies nothing: the listener is the subject, not the chain.
            let client =
                crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
            let stream = TcpStream::connect(admin_addr).await.unwrap();
            let mut tls = TlsConnector::from(client)
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .expect("the admin listener must complete a handshake");
            tls.write_all(
                b"GET /api/accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("HTTP/1.1 401"),
                "the admin API answers over TLS, unauthenticated: {response}"
            );

            // The certificate really was written to the admin paths, not the
            // server's — a shared path would make one listener overwrite the
            // other's key on every start.
            assert!(dir.as_ref().join("admin.pem").exists());
            assert!(dir.as_ref().join("admin.key").exists());
            assert!(!dir.as_ref().join("server.pem").exists());

            tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .expect("both listeners must stop")
                .unwrap()
                .expect("a clean shutdown is not an error");
        }

        /// With `[admin]` off — the default — nothing is bound but the ACME
        /// socket, and the panel's routes do not exist anywhere.
        #[tokio::test]
        async fn the_admin_listener_is_absent_by_default() {
            let dir = temp_dir();
            let config = config_in(&dir, false);
            assert!(!config.admin.enabled, "the default must stay off");
            let (addr, shutdown, handle) = boot(config).await;

            let response = get(addr, "/api/accounts").await;
            assert!(response.starts_with("HTTP/1.1 404"), "{response}");

            shutdown.send(()).unwrap();
            handle.await.unwrap().unwrap();
        }

        /// A `[admin]` section that cannot work stops the whole process before
        /// either socket is bound — it must not leave the ACME listener up and
        /// the panel silently missing.
        #[tokio::test]
        async fn an_invalid_admin_section_refuses_to_serve() {
            let dir = temp_dir();
            let mut config = config_in(&dir, false);
            config.admin.enabled = true;
            // Non-loopback with TLS off: the `Secure` cookie would never be
            // stored, so this is a hard startup error.
            config.admin.bind_address = "0.0.0.0:0".to_string();

            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let error = serve_on(Arc::new(config), database, listener, std::future::ready(()))
                .await
                .expect_err("a panel that cannot work must not start");
            assert!(error.to_string().contains("is not loopback"), "{error}");
        }

        /// Sends one request and returns the raw response.
        async fn get(addr: SocketAddr, path: &str) -> String {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        }

        /// A configuration mounting nothing fails before the socket is ever
        /// served, rather than starting a server that answers 404 everywhere.
        #[tokio::test]
        async fn a_configuration_with_no_profile_refuses_to_serve() {
            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let error = serve_on(
                Arc::new(Config::default()),
                database,
                listener,
                std::future::ready(()),
            )
            .await
            .expect_err("a server with no endpoint must not start");
            assert!(error.to_string().contains("profile"), "{error}");
        }

        /// `Serve` is a `dispatch` arm like any other: its failure travels back
        /// as a value instead of taking the process down where it happened.
        #[tokio::test]
        async fn dispatch_serve_reports_a_startup_failure() {
            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            // Binds fine, but mounts no endpoint — so it fails inside
            // `serve_on` rather than at the socket.
            let mut config = Config::default();
            config.server.bind_address = "127.0.0.1:0".to_string();
            let mut reader: &[u8] = &[];

            let error = dispatch(
                Some(Command::Serve),
                true,
                &mut reader,
                &Arc::new(config),
                database,
            )
            .await
            .expect_err("a server with no endpoint must not start");
            assert!(error.to_string().contains("profile"), "{error}");
        }

        /// Unreadable TLS material stops startup instead of silently falling
        /// back to cleartext on a port operators believe is HTTPS.
        #[tokio::test]
        async fn unusable_tls_material_stops_startup() {
            let dir = temp_dir();
            let mut config = config_in(&dir, true);
            std::fs::write(dir.join("server.pem"), "not a certificate").unwrap();
            std::fs::write(dir.join("server.key"), "not a key").unwrap();
            config.server.tls.cert_path = dir.join("server.pem").display().to_string();
            config.server.tls.key_path = dir.join("server.key").display().to_string();

            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let error = serve_on(Arc::new(config), database, listener, std::future::ready(()))
                .await
                .expect_err("unreadable TLS material must not start a server");
            assert!(!error.to_string().is_empty());
        }

        /// `serve` binds `server.bind_address` itself, so an unusable one is
        /// reported rather than panicking.
        #[tokio::test]
        async fn an_unbindable_address_is_reported() {
            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let mut config = Config::default();
            // A port on an address this process does not hold.
            config.server.bind_address = "192.0.2.1:1".to_string();
            let error = serve(Arc::new(config), database)
                .await
                .expect_err("binding an unroutable address must fail");
            assert!(error.to_string().contains("192.0.2.1:1"), "{error}");
        }
    }
}
