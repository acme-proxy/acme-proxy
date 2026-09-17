//! The command tree.
//!
//! **Nothing here prints or exits.** Every command body returns
//! `Result<(), CliError>` and [`dispatch`] routes to it, so each arm is a plain
//! function a test can call and assert on rather than an unreachable dead end.
//! `src/main.rs` is where that `Result` becomes an exit status, and it is the
//! only place in the project that calls `std::process::exit` — a library whose
//! failure mode is ending the process is one nothing else can use.
//!
//! `serve` is one arm like the others: the server runtime itself lives in
//! [`crate::server`], and [`serve`] only turns its failure into a [`CliError`].
//!
//! The logic behind each admin subcommand lives in [`crate::admin`], not here;
//! this module is the `clap` surface over it. [`logging`] turns `[logging]` into
//! an installed subscriber, validating every value before installing anything.
//!
//! What a command *prints* is [`render`]'s, and how it is coloured is
//! [`style`]'s. Those renderings sit here rather than in [`crate::admin`]
//! because they have exactly one consumer — the terminal — where the JSON ones
//! beside them are a wire format the web admin parses too. [`dispatch`]
//! resolves one [`Palette`] and threads it down; `nonce` and `upstream` take
//! none, printing only fixed text.

use std::io::{BufRead, IsTerminal};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use clap_complete::aot::Shell;

pub mod account;
pub mod audit;
pub mod eab;
pub mod filter;
pub mod generate;
pub mod jobs;
pub(crate) mod logging;

/// Installs the `[logging]` configuration. Re-exported because `main.rs` is
/// what calls it — see [`dispatch`].
pub use logging::init_logging;
/// The `--log-level` flag and the per-invocation decision it feeds. Re-exported
/// for `main.rs`, which is where the subscriber is installed.
pub use logging::{LogLevel, LoggingPlan, init_command_logging, plan_logging};
pub mod nonce;
pub mod order;
pub mod profile;
pub mod render;
pub mod style;
pub mod upstream;
pub mod webadmin;
pub mod window;

pub use account::AccountCommand;
pub use audit::AuditCommand;
pub use eab::EabCommand;
pub use jobs::JobsCommand;
pub use nonce::NonceCommand;
pub use order::OrderCommand;
pub use profile::ProfileCommand;
pub use upstream::UpstreamCommand;
pub use webadmin::AdminCommand;

use crate::cli::filter::FilterCommand;
pub use crate::cli::style::{ColorChoice, Palette};
use crate::config::Config;
use crate::sqlite::db::Database;

#[derive(Parser)]
#[command(
    name = "acme-proxy",
    version = env!("CARGO_PKG_VERSION"),
    about = "ACME server, plus admin commands for its database"
)]
pub struct Cli {
    /// Skip interactive "Are you sure?" confirmation on destructive commands.
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    /// When to colour human-readable output. `--json` output never carries it.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    pub color: ColorChoice,

    /// Emit log records for this run, at this level, on stderr. Without it an
    /// admin command prints only its own output; `serve` uses `[logging]`.
    #[arg(long, value_enum, global = true)]
    pub log_level: Option<LogLevel>,

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
    /// Inspect and manage the background job queue.
    Jobs {
        #[command(subcommand)]
        command: JobsCommand,
    },
    /// Nonce table maintenance.
    Nonce {
        #[command(subcommand)]
        command: NonceCommand,
    },
    /// Inspect the ACME endpoints this configuration mounts.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
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
    /// Print a shell completion script on stdout.
    Completions {
        /// The shell to generate for.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Print this binary's man page, in roff, on stdout.
    Man,
}

/// The notification dispatchers `serve` would build from this configuration —
/// every profile's, plus the web admin's when `admin.enabled` — over a queue
/// this process never drains.
///
/// A dispatcher only *writes* `notify_deliver` rows; delivering them is the
/// running server's job runner, over the same database. So a host command
/// whose action deserves a notification (a revocation, a deactivated account,
/// a changed credential) queues it here and exits, and the worker sends it —
/// the CLI never talks SMTP or a webhook itself. A row queued while no server
/// runs waits for the next one to start.
pub(crate) fn offline_notifiers(
    config: &Config,
    database: Arc<Database>,
) -> Result<crate::notify::DispatcherMap, CliError> {
    let failed = |error: anyhow::Error| CliError::failed(format!("configuration error: {error}"));
    let profiles = config
        .resolve_profiles()
        .map_err(|error| failed(anyhow::anyhow!(error)))?;
    let egress = crate::server::Egress::from_config(config).map_err(failed)?;
    let jobs = crate::jobs::JobQueue::new(database, &config.jobs);
    let mut dispatchers =
        crate::notify::build_registry(&profiles, egress.outbound(), &jobs).map_err(failed)?;
    if config.admin.enabled {
        dispatchers.insert(
            crate::notify::ADMIN_DISPATCHER_KEY.to_string(),
            crate::notify::from_config(
                crate::notify::ADMIN_DISPATCHER_KEY,
                &config.admin.notify,
                egress.outbound(),
                &jobs,
            )
            .map_err(failed)?,
        );
    }
    Ok(dispatchers)
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
        .map_err(|error| CliError::failed(format!("configuration error: {error}")))?;

    match wanted {
        Some(name) => profiles
            .into_iter()
            .find(|profile| profile.name == name)
            .ok_or_else(|| {
                CliError::bad_request(format!("no profile named `{name}` in this configuration"))
            }),
        None if profiles.len() == 1 => Ok(profiles.into_iter().next().expect("length checked")),
        None => {
            let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
            Err(CliError::bad_request(format!(
                "this configuration defines several profiles ({}); say which one with --profile",
                names.join(", ")
            )))
        }
    }
}

/// A command that could not complete, carrying the message to print and the
/// [kind](CliErrorKind) that decides the process exit status.
///
/// Every failing branch below returns one of these instead of calling
/// `std::process::exit` where it stands: `main.rs` is the single place that
/// prints and exits, so each command body stays a plain function a test can
/// call and assert on.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    /// The line printed to stderr.
    pub message: String,
    /// What the process exits with.
    pub kind: CliErrorKind,
}

/// Why a command failed, in the one distinction a script cares about: was it
/// the host that could not carry out the request, or the request itself that
/// could not be satisfied as written? Only the first is worth retrying.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CliErrorKind {
    /// The host could not carry out the request — a database error, a signer
    /// or CA failure, an unreadable file, a socket that would not bind, an
    /// outbound network failure, invalid configuration. Exit `1`.
    #[default]
    Failed,
    /// The request cannot be satisfied as written — no object with that id, an
    /// object in the wrong state, an unknown `--status`/`--event`/`--role`
    /// value, contradictory flags. Re-running the identical command will not
    /// help. Exit `3`.
    BadRequest,
}

impl CliError {
    /// A `Failed` error — the host could not carry out the request.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CliErrorKind::Failed,
        }
    }

    /// A `BadRequest` error — the request cannot be satisfied as written.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CliErrorKind::BadRequest,
        }
    }

    /// The kind this error carries.
    pub fn kind(&self) -> CliErrorKind {
        self.kind
    }

    /// The process exit status for this error: `1` for [`CliErrorKind::Failed`],
    /// `3` for [`CliErrorKind::BadRequest`]. `main.rs` is the only caller.
    pub fn exit_code(&self) -> u8 {
        match self.kind {
            CliErrorKind::Failed => 1,
            CliErrorKind::BadRequest => 3,
        }
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::failed(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::failed(message)
    }
}

impl From<sqlx::Error> for CliError {
    fn from(error: sqlx::Error) -> Self {
        Self::failed(format!("database error: {error}"))
    }
}

/// Routes a parsed command to its handler.
///
/// The library's entry point. Everything above it — parsing argv, loading the
/// configuration, installing the subscriber, opening the database, printing a
/// failure and exiting — lives in `src/main.rs`, because those are the
/// binary's job and not a library's: nothing that links this crate can use a
/// function whose failure mode is `std::process::exit`.
///
/// Takes the `--color` *choice* rather than a resolved [`Palette`], and
/// resolves it here: the answer depends on whether this process's stdout is a
/// terminal and on `NO_COLOR`, and neither belongs in `main.rs`, which is
/// excluded from the coverage floor precisely because nothing in it is
/// reachable from a test.
pub async fn dispatch(
    command: Option<Command>,
    yes: bool,
    color: ColorChoice,
    reader: &mut impl BufRead,
    config: &Arc<Config>,
    database: Arc<Database>,
) -> Result<(), CliError> {
    let palette = Palette::resolve(
        color,
        std::io::stdout().is_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    );
    match command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config.clone(), database).await,
        Command::Account { command } => {
            account::run_account_command(command, yes, palette, reader, config, database).await
        }
        Command::Order { command } => {
            order::run_order_command(command, yes, palette, reader, config, database).await
        }
        Command::Audit { command } => {
            audit::run_audit_command(command, yes, palette, reader, database).await
        }
        Command::Jobs { command } => {
            jobs::run_jobs_command(command, yes, palette, reader, database).await
        }
        Command::Nonce { command } => {
            nonce::run_nonce_command(command, yes, reader, config, database).await
        }
        Command::Profile { command } => {
            profile::run_profile_command(command, palette, config).await
        }
        Command::Eab { command } => {
            eab::run_eab_command(command, yes, palette, reader, database).await
        }
        Command::Filter { command } => filter::run_filter_command(command, palette, config).await,
        Command::Upstream { command } => {
            upstream::run_upstream_command(command, reader, palette, config, database).await
        }
        Command::Admin { command } => {
            webadmin::run_admin_command(command, yes, palette, reader, config, database).await
        }
        // Reachable here, though `main.rs` answers both before it opens
        // anything: an `unreachable!()` would be dead code under the coverage
        // floor, and routing them keeps this a total function over `Command`.
        command @ (Command::Completions { .. } | Command::Man) => {
            generate::write(&command, &mut std::io::stdout().lock())
        }
    }
}

/// Runs the ACME HTTP(S) server until a shutdown signal arrives.
///
/// [`crate::server::run`] logs every failure it returns; this only carries the
/// message to `main.rs` as a [`CliError`].
pub async fn serve(config: Arc<Config>, database: Arc<Database>) -> Result<(), CliError> {
    crate::server::run(config, database)
        .await
        .map_err(|error| CliError::failed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--version` exists and reports the crate version. The bug report
    /// template tells people to run it, and clap generates the flag only
    /// because `#[command(version = …)]` says so — drop that and the first
    /// instruction on the form starts erroring out.
    #[test]
    fn version_flag_reports_the_crate_version() {
        let Err(error) = Cli::try_parse_from(["acme-proxy", "--version"]) else {
            panic!("--version parsed as a command rather than printing a version");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    /// `eab delete`'s two account modes are exclusive: asked for both, clap
    /// refuses rather than one silently winning.
    #[test]
    fn eab_delete_refuses_both_account_modes_at_once() {
        let Err(error) = Cli::try_parse_from([
            "acme-proxy",
            "eab",
            "delete",
            "kid",
            "--deactivate-accounts",
            "--delete-accounts",
        ]) else {
            panic!("both modes at once must be refused");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);

        for flag in ["--deactivate-accounts", "--delete-accounts"] {
            Cli::try_parse_from(["acme-proxy", "eab", "delete", "kid", flag]).unwrap();
        }
    }

    /// `--log-level` is global like `--yes` and `--color`, so it may be given
    /// on either side of the subcommand — which is the whole reason an
    /// operator reaches for it, having already typed the command once.
    #[test]
    fn log_level_is_a_global_flag_with_a_closed_set_of_values() {
        let cli = Cli::try_parse_from(["acme-proxy", "account", "list"]).unwrap();
        assert_eq!(
            cli.log_level, None,
            "absent by default: an admin command says nothing unless asked",
        );

        for argv in [
            ["acme-proxy", "--log-level", "debug", "account", "list"],
            ["acme-proxy", "account", "list", "--log-level", "debug"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.log_level, Some(LogLevel::Debug), "{argv:?}");
        }

        let cli = Cli::try_parse_from(["acme-proxy", "serve", "--log-level", "off"]).unwrap();
        assert_eq!(cli.log_level, Some(LogLevel::Off));

        // A `value_enum`, so an unrecognised level is refused with the six
        // spellings listed rather than treated as a filter directive.
        let Err(error) =
            Cli::try_parse_from(["acme-proxy", "account", "list", "--log-level", "loud"])
        else {
            panic!("`--log-level loud` must be refused");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }

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
                    profile: None,
                    eab_kid: None,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0
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
                    identifier: None,
                    identifier_contains: None,
                    cert_serial: None,
                    expiring_in: None,
                    hide_superseded: false,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0,
                    json: true
                }
            }) if a == "acct-1" && s == "pending"
        ));

        let cli = Cli::try_parse_from([
            "acme-proxy",
            "order",
            "list",
            "--expiring-in",
            "30",
            "--hide-superseded",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::List {
                    expiring_in: Some(30),
                    hide_superseded: true,
                    status: None,
                    account_id: None,
                    profile: None,
                    identifier: None,
                    identifier_contains: None,
                    cert_serial: None,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0,
                    json: false
                }
            })
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
                command: OrderCommand::Revoke { id, reason: Some(1), wait: 30 }
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
                command: EabCommand::List {
                    limit: 50,
                    offset: 0,
                    json: false
                }
            })
        ));

        // The four commands added with `TODO.md`'s "last few asymmetries": a
        // detail for the one listable object that had none, and the three reads
        // the panel could already answer and the host could not.
        let cli = Cli::try_parse_from(["acme-proxy", "order", "chain", "ord-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Order {
                command: OrderCommand::Chain { id }
            }) if id == "ord-1"
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "nonce", "count", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Nonce {
                command: NonceCommand::Count { json: true }
            })
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "profile", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Profile {
                command: ProfileCommand::List { json: false }
            })
        ));

        let cli = Cli::try_parse_from(["acme-proxy", "admin", "user", "show", "alice"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::Show { username, json: false }
                }
            }) if username == "alice"
        ));

        // The window the three formerly unwindowed listings grew, defaulted the
        // same way as the four that already had one.
        let cli =
            Cli::try_parse_from(["acme-proxy", "admin", "user", "list", "--limit", "2"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::User {
                    command: crate::cli::webadmin::AdminUserCommand::List {
                        limit: 2,
                        offset: 0,
                        json: false
                    }
                }
            })
        ));

        let cli =
            Cli::try_parse_from(["acme-proxy", "admin", "session", "list", "--offset=5"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::Session {
                    command: crate::cli::webadmin::AdminSessionCommand::List {
                        username: None,
                        limit: window::DEFAULT_LIMIT,
                        offset: 5,
                        json: false
                    }
                }
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
                        password_file: None,
                        role: _,
                        contact: None,
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

        // `--color` is global like `--yes`, so it may sit anywhere on the line,
        // and an unknown value is refused by clap rather than falling back to
        // `auto` — the same rule `--status`/`--event` follow, for the same
        // reason: a silently ignored value looks exactly like a working one.
        let cli = Cli::try_parse_from(["acme-proxy", "account", "list", "--color", "never"])
            .expect("--color is global and accepts `never`");
        assert_eq!(cli.color, ColorChoice::Never);

        let cli = Cli::try_parse_from(["acme-proxy", "--color", "always", "account", "list"])
            .expect("--color is global, so it may precede the subcommand");
        assert_eq!(cli.color, ColorChoice::Always);

        assert_eq!(
            Cli::try_parse_from(["acme-proxy", "account", "list"])
                .unwrap()
                .color,
            ColorChoice::Auto,
            "unset means auto"
        );

        assert!(
            Cli::try_parse_from(["acme-proxy", "account", "list", "--color", "sometimes"]).is_err(),
            "an unknown --color value must be refused, not ignored"
        );

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
                        limit: 50,
                        offset: 0,
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

        // `--session` names one row within one operator's sessions, so it only
        // means anything alongside `--user`, and never with `--all`.
        assert!(
            Cli::try_parse_from([
                "acme-proxy",
                "admin",
                "session",
                "revoke",
                "--session",
                "abc"
            ])
            .is_err(),
            "--session requires --user"
        );
        assert!(
            Cli::try_parse_from([
                "acme-proxy",
                "admin",
                "session",
                "revoke",
                "--all",
                "--session",
                "abc",
            ])
            .is_err(),
            "--session and --all are mutually exclusive"
        );
        assert!(matches!(
            Cli::try_parse_from([
                "acme-proxy",
                "admin",
                "session",
                "revoke",
                "--user",
                "alice",
                "--session",
                "abc",
            ])
            .unwrap()
            .command,
            Some(Command::Admin {
                command: AdminCommand::Session {
                    command: crate::cli::webadmin::AdminSessionCommand::Revoke {
                        user: Some(user),
                        all: false,
                        session: Some(session),
                    }
                }
            }) if user == "alice" && session == "abc"
        ));
    }

    #[test]
    fn a_database_error_renders_as_a_cli_error() {
        let error = CliError::from(sqlx::Error::PoolClosed);
        assert!(error.to_string().starts_with("database error: "), "{error}");
        // A database error is the host's problem, not the request's.
        assert_eq!(error.kind(), CliErrorKind::Failed);
        assert_eq!(error.exit_code(), 1);
    }

    /// The one distinction `main.rs` turns into a process status: `Failed` is
    /// exit `1` (the host could not carry out the request), `BadRequest` is
    /// exit `3` (the request cannot be satisfied as written).
    #[test]
    fn the_kind_decides_the_exit_code() {
        assert_eq!(CliError::failed("x").kind(), CliErrorKind::Failed);
        assert_eq!(CliError::bad_request("x").kind(), CliErrorKind::BadRequest);
        assert_eq!(CliError::failed("x").exit_code(), 1);
        assert_eq!(CliError::bad_request("x").exit_code(), 3);
        // The bare conversions default to `Failed` — a plain `?` on a DB call
        // must keep exiting `1`.
        assert_eq!(CliError::from("x").kind(), CliErrorKind::Failed);
        assert_eq!(CliError::from("x".to_string()).kind(), CliErrorKind::Failed);
    }

    /// A configuration with no resolvable profiles is the host's to fix, so
    /// `resolve_profile` reports it as `Failed` (exit 1). The `BadRequest`
    /// branches — an unknown `--profile`, and none given where several exist —
    /// are covered in `src/cli/filter.rs`, its other caller, where a
    /// multi-profile configuration is already loadable.
    #[test]
    fn resolve_profile_reports_a_missing_profile_set_as_failed() {
        let config = Config::default();
        assert_eq!(
            resolve_profile(&config, None).unwrap_err().kind(),
            CliErrorKind::Failed
        );
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
                    eab_kid: None,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0,
                    json: false,
                },
            },
            Command::Order {
                command: OrderCommand::List {
                    profile: None,
                    account_id: None,
                    status: None,
                    identifier: None,
                    identifier_contains: None,
                    cert_serial: None,
                    expiring_in: None,
                    hide_superseded: false,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0,
                    json: false,
                },
            },
            Command::Nonce {
                command: NonceCommand::Cleanup {
                    ttl_seconds: Some(1),
                },
            },
            Command::Nonce {
                command: NonceCommand::Count { json: false },
            },
            Command::Eab {
                command: EabCommand::List {
                    limit: 50,
                    offset: 0,
                    json: false,
                },
            },
            Command::Jobs {
                command: JobsCommand::List {
                    kind: None,
                    status: None,
                    limit: window::DEFAULT_LIMIT,
                    offset: 0,
                    json: false,
                },
            },
            Command::Man,
            Command::Completions {
                shell: clap_complete::aot::Shell::Bash,
            },
            // `Profile` is deliberately absent for `Upstream`'s reason below,
            // arrived at from the other end: it resolves the profiles, and
            // `Config::default()` mounts none, so it reports that rather than
            // listing nothing. Its arm is driven from `cli::profile`'s own
            // tests, against a configuration that has some.
            // `Upstream` is deliberately absent: it acts on a *profile's*
            // `[signer.relay]`, and this config has none, so it now
            // reports that rather than silently reading the global base
            // section nothing serves from. Covered in `cli::upstream`'s own
            // tests, which supply a configuration with profiles.
        ];
        for command in commands {
            dispatch(
                Some(command),
                true,
                ColorChoice::Never,
                &mut reader,
                &config,
                database.clone(),
            )
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
            ColorChoice::Never,
            &mut reader,
            &config,
            database,
        )
        .await
        .expect_err("an unknown account must fail");
        assert_eq!(
            error,
            CliError::bad_request("no such account: acct-nope".to_string())
        );
        assert_eq!(error.exit_code(), 3);
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
            ColorChoice::Never,
            &mut reader,
            &Arc::new(config),
            database,
        )
        .await
        .expect_err("a server with no endpoint must not start");
        assert!(error.to_string().contains("profile"), "{error}");
    }
}
