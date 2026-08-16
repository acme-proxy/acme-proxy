//! The command tree, and the startup path itself.
//!
//! [`run`] is the **only** place in the crate that prints an error and calls
//! `std::process::exit`. Every command body returns `Result<(), CliError>` and
//! `dispatch` routes to it, so each arm is a plain function a test can call and
//! assert on rather than an unreachable dead end.
//!
//! Startup is split on the socket boundary, which is what lets a test drive the
//! whole path on an ephemeral port with its own shutdown future instead of a
//! process signal:
//!
//! - `serve` binds `server.bind_address` and hands the socket on.
//! - [`serve_on`] validates the admin configuration and binds that socket too,
//!   when `[admin]` is enabled.
//! - [`serve_on_with`] does everything else — profile resolution, deduplicated
//!   signer backends, per-profile filters and validators, TLS, the job registry
//!   (every signer's handlers, notification delivery and the four table sweeps),
//!   the runner draining it, and `axum::serve` with connect info attached.
//!
//! The logic behind each admin subcommand lives in [`crate::admin`], not here;
//! this module is the `clap` surface over it. [`logging`] turns `[logging]` into
//! an installed subscriber, validating every value before installing anything.

use std::collections::HashMap;
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
/// `std::process::exit` where it stands: [`run`] is the single place that
/// prints and exits, so each command body stays a plain function a test can
/// call and assert on.
#[derive(Debug, PartialEq, Eq)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

impl From<sqlx::Error> for CliError {
    fn from(error: sqlx::Error) -> Self {
        Self(format!("database error: {error}"))
    }
}

/// Runs the CLI entrypoint.
pub async fn run() {
    let cli = Cli::parse();

    let config = Arc::new(Config::load().unwrap_or_else(|error| {
        eprintln!("configuration error: {error}");
        std::process::exit(1);
    }));

    logging::init_logging(&config.logging).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    let database = Arc::new(
        Database::connect(&config.database.url)
            .await
            .unwrap_or_else(|error| {
                error!(event = "db_connect_failed", outcome = "failure", database_url = %config.database.url, error = %error);
                std::process::exit(1);
            }),
    );

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();

    if let Err(error) = dispatch(cli.command, cli.yes, &mut reader, &config, database).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

/// Routes a parsed command to its handler. Split out of [`run`] so every arm
/// but `Serve` is reachable from a test.
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

    serve_on(config, database, listener, shutdown_signal())
        .await
        .map_err(|error| {
            error!(event = "server_fatal_error", outcome = "failure", error = %error);
            CliError(error.to_string())
        })
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
    // Before anything binds: a misconfigured panel must not take the ACME
    // listener down with it halfway through startup.
    crate::webadmin::check_config(&config).inspect_err(|error| {
        error!(event = "admin_config_invalid", outcome = "failure", error = %error);
    })?;

    let admin_listener = match config.admin.enabled {
        false => None,
        true => Some(
            TcpListener::bind(&config.admin.bind_address)
                .await
                .inspect_err(|error| {
                    error!(event = "admin_socket_bind_failed",
                           outcome = "failure",
                           bind_address = %config.admin.bind_address,
                           error = %error);
                })?,
        ),
    };

    serve_on_with(config, database, listener, admin_listener, shutdown).await
}

/// [`serve_on`] with both sockets supplied.
///
/// The full version, split on the same boundary and for the same reason: a
/// caller handing in two ephemeral ports can drive the whole two-listener
/// startup path — including that one shutdown signal stops both — without
/// owning a fixed port or a process signal.
pub async fn serve_on_with(
    config: Arc<Config>,
    database: Arc<Database>,
    listener: TcpListener,
    admin_listener: Option<TcpListener>,
    shutdown: impl Future<Output = ()> + Send + 'static,
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

    // Assembly lives in `Profile::build_all`: this function only reports.
    let profiles =
        Profile::build_all(&config, database.clone(), &job_queue).inspect_err(|error| {
            error!(event = "profile_init_failed", outcome = "failure", error = %error);
        })?;
    for profile in &profiles {
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

    let tls = tls::from_config(&config.server).inspect_err(|error| {
        error!(event = "tls_init_failed", outcome = "failure", error = %error);
    })?;

    // Every subsystem with background work, in one registry. Deduplicated by
    // `Arc` identity: two profiles can share one signer backend, and its handler
    // must be registered once — the registry refuses a second handler for one
    // kind outright, since two would each claim about half the rows. The
    // identity is kept as a `usize` rather than the pointer itself, so this
    // future stays `Send`; it is spawned.
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
    let notifiers: HashMap<String, Arc<crate::notify::NotifyDispatcher>> = profiles
        .iter()
        .map(|profile| (profile.name.clone(), profile.notify.clone()))
        .collect();
    job_registry
        .register(Arc::new(crate::notify::NotifyJob::new(Arc::new(notifiers))))
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
    if admin_listener.is_some() {
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
        crate::audit::Auditor::from_config(&config.audit, &config.dns, database.clone())
            .inspect_err(|error| {
                error!(event = "audit_init_failed", outcome = "failure", error = %error);
            })?,
    );

    // Built **before** `build_app`, which consumes `profiles`. The admin state
    // needs the same profiles (revoking an order resolves that order's own
    // signer), and `build_admin_app` takes a slice precisely so the ordering
    // is a signature constraint rather than a borrow error to rediscover.
    let admin_app = admin_listener.is_some().then(|| {
        crate::webadmin::build_admin_app(
            database.clone(),
            config.clone(),
            &profiles,
            auditor.clone(),
        )
    });
    let app = build_app(database.clone(), config.clone(), profiles, auditor);

    // The one task that drains the queue. Held under `AbortOnDrop` for the same
    // reason the reapers are — an un-cancelled loop holding an `Arc<Database>`
    // per `serve_on` call — and, unlike the relay tasks this replaced, it does
    // *not* need to outlive this function: the work is durable now, so a job cut
    // short is re-claimed from its own row rather than lost. It takes the same
    // shutdown signal as both listeners, so a stop is graceful rather than an
    // abort: it releases its leases on the way out, and a restart therefore
    // re-claims its own work immediately instead of waiting one out.
    let _job_runner = AbortOnDrop(crate::jobs::spawn_runner(
        job_queue,
        Arc::new(job_registry),
        &config.jobs,
        shutdown_rx.clone(),
    ));

    info!(
        event = "server_listening",
        outcome = "success",
        bind_address = %config.server.bind_address,
        protocol = if tls.is_some() { "https" } else { "http" }
    );

    // Boxed rather than four `match` arms: the TLS and cleartext paths produce
    // different listener types, and each listener has its own.
    let acme: Serving = match tls {
        Some(acceptor) => {
            let handshake_timeout = Duration::from_millis(config.server.tls.handshake_timeout_ms);
            let listener = tls::TlsListener::spawn(listener, acceptor, handshake_timeout)
                .inspect_err(|error| {
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

    let admin: Serving = match (admin_app, admin_listener) {
        (Some(app), Some(listener)) => {
            serve_admin(&config, database.clone(), app, listener, shutdown_rx).await?
        }
        // The panel is off: a future that is already done, so `try_join!`
        // below needs no second shape.
        _ => Box::pin(std::future::ready(Ok(()))),
    };

    // Nothing is drained here any more. A notification in flight at shutdown is
    // a `notify_deliver` row, not a spawned task: the runner released its lease
    // on the way out and whoever starts next claims it. That is what replaced a
    // best-effort five-second drain which still lost anything slower than it.
    tokio::try_join!(acme, admin)?;
    Ok(())
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
    listener: TcpListener,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<Serving> {
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

    let tls = tls::admin_from_config(&config.admin).inspect_err(|error| {
        error!(event = "admin_tls_init_failed", outcome = "failure", error = %error);
    })?;

    info!(
        event = "admin_listening",
        outcome = "success",
        bind_address = %bind_address,
        protocol = if tls.is_some() { "https" } else { "http" },
        base_url = %config.admin.base_url
    );

    Ok(match tls {
        Some(acceptor) => {
            let handshake_timeout = Duration::from_millis(config.admin.tls.handshake_timeout_ms);
            let listener = tls::TlsListener::spawn(listener, acceptor, handshake_timeout)
                .inspect_err(|error| {
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
    })
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

        /// The two-listener path: one shutdown signal, two sockets, and the
        /// admin API answering on its own port while the ACME one does not.
        ///
        /// This is the regression test for the `watch` split — before it, the
        /// `shutdown` future was consumed once and only one listener stopped.
        #[tokio::test]
        async fn both_listeners_serve_and_one_signal_stops_both() {
            let dir = temp_dir();
            let mut config = config_in(&dir, false);
            config.admin.enabled = true;

            let database = Arc::new(Database::connect_in_memory().await.unwrap());
            let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let acme_addr = acme_listener.local_addr().unwrap();
            let admin_addr = admin_listener.local_addr().unwrap();
            assert_ne!(acme_addr, admin_addr);

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(serve_on_with(
                Arc::new(config),
                database,
                acme_listener,
                Some(admin_listener),
                async {
                    let _ = rx.await;
                },
            ));

            // `/health` is on both.
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

            // One signal, both stop.
            tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .expect("both listeners must stop on one signal")
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
