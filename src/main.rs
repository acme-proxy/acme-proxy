//! ACME Proxy binary entry point.
//!
//! Everything here is process wiring: parse argv, load the configuration,
//! install the subscriber, open the database, and turn whatever
//! [`acme_proxy::cli::dispatch`] returns into an exit status. It is the **only**
//! place in the project that prints to stderr and ends the process, which is
//! why every command body in `src/cli/` returns a `CliError` instead — each of
//! them stays a plain function a test can call and assert on.
//!
//! A dispatched command that fails exits with `CliError::exit_code`: `1` when
//! the host could not carry out the request, `3` when the request itself could
//! not be satisfied as written. The pre-dispatch failures below (a bad
//! configuration, a database that will not open) are all the former, so they
//! stay on a plain `std::process::exit(1)`.
//!
//! That is also why this file is excluded from the coverage floor: none of it
//! is reachable from a test, because every failure branch here ends the
//! process. What *is* decidable — which subscriber this invocation gets — lives
//! in `cli::plan_logging` for that reason, and is called from here.

use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use acme_proxy::cli::schema::{SchemaPlan, plan_schema};
use acme_proxy::cli::{Cli, Command, LogLevel, LoggingPlan, dispatch, generate, plan_logging};
use acme_proxy::server::logging::{init_command_logging, init_logging};
use acme_proxy::sqlite::db::Database;
use acme_proxy_core::config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Resolved against **stderr**, where these three messages go; `dispatch`
    // resolves its own against stdout. The two streams are redirected
    // independently, so one answer for both would colour into a log file
    // whenever the other half happened to be a terminal.
    let palette = acme_proxy::cli::style::resolve(
        cli.color,
        std::io::stderr().is_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    );

    // Answered here, *before* the configuration and the database: neither
    // command reads either, and `Database::connect` creates its file, so
    // `acme-proxy completions bash` would otherwise drop a `sqlite.db` into
    // whatever directory a shell startup file or a packaging script happened to
    // run it from — as root, in the usual case. The generation itself lives in
    // `cli::generate`, where a test can reach it; this is the fifth branch of
    // wiring in a file the coverage floor excludes.
    if let Some(command @ (Command::Completions { .. } | Command::Man)) = &cli.command {
        if let Err(error) = generate::write(command, &mut std::io::stdout().lock()) {
            eprintln!("{}", palette.bad(&error.to_string()));
            return ExitCode::from(error.exit_code());
        }
        return ExitCode::SUCCESS;
    }

    let config = Arc::new(Config::load().unwrap_or_else(|error| {
        eprintln!("{}", palette.bad(&format!("configuration error: {error}")));
        std::process::exit(1);
    }));

    // Which subscriber this invocation gets — `serve` the server's own, an
    // admin command one only if it asked, and otherwise none at all. The rule
    // lives in `cli::plan_logging` rather than here, because this file is
    // excluded from the coverage floor and that decision is worth a table test.
    let installed = plan_logging(
        cli.command.as_ref(),
        cli.log_level,
        std::env::var("RUST_LOG").ok().as_deref(),
    );
    let logging = match installed {
        LoggingPlan::Silent => Ok(()),
        LoggingPlan::Server => {
            init_logging(&config.logging, cli.log_level.map(LogLevel::directive))
        }
        LoggingPlan::Command => init_command_logging(cli.log_level.map(LogLevel::directive)),
    };
    logging.unwrap_or_else(|error| {
        eprintln!("{}", palette.bad(&error));
        std::process::exit(1);
    });

    let database = Arc::new(
        Database::open(&config.database.url)
            .await
            .unwrap_or_else(|error| {
                // stderr rather than the `error!` this used to be: under
                // `LoggingPlan::Silent` there is no subscriber, so the record
                // went nowhere and the process exited 1 having said nothing at
                // all. A failure to open the database is fatal before anything
                // serves, which is exactly what the configuration error above
                // already reports this way.
                eprintln!(
                    "{}",
                    palette.bad(&format!(
                        "database error: cannot open {}: {error}",
                        config.database.url
                    ))
                );
                std::process::exit(1);
            }),
    );

    // Opening the database no longer migrates it, so an invocation that needs
    // the schema and does not own it stops here, by name. `migrate`, `init` and
    // a `serve` running the `worker` role own it and apply the migrations
    // themselves — the first two in their command body, the third in
    // `server::run`, where it happens before anything reads a row. The rule is
    // `cli::schema::plan_schema`, which is a table test because this file sits
    // outside the coverage floor.
    if plan_schema(cli.command.as_ref()) == SchemaPlan::Require {
        match database.pending_migrations().await {
            Ok(pending) if pending.is_empty() => {}
            Ok(pending) => {
                eprintln!(
                    "{}",
                    palette.bad(&format!(
                        "database error: the schema is {} migration(s) behind; \
                         run `acme-proxy migrate` first",
                        pending.len()
                    ))
                );
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    palette.bad(&format!(
                        "database error: cannot read the schema version: {error}"
                    ))
                );
                std::process::exit(1);
            }
        }
    }

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();

    if let Err(error) = dispatch(
        cli.command,
        cli.yes,
        cli.color,
        &mut reader,
        &config,
        database,
    )
    .await
    {
        eprintln!("{}", palette.bad(&error.to_string()));
        return ExitCode::from(error.exit_code());
    }

    ExitCode::SUCCESS
}
