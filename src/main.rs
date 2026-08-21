//! ACME Proxy binary entry point.
//!
//! Everything here is process wiring: parse argv, load the configuration,
//! install the subscriber, open the database, and turn whatever
//! [`acme_proxy::cli::dispatch`] returns into an exit status. It is the **only**
//! place in the project that prints to stderr and calls `std::process::exit`,
//! which is why every command body in `src/cli/` returns a `CliError` instead —
//! each of them stays a plain function a test can call and assert on.
//!
//! That is also why this file is excluded from the coverage floor: none of it
//! is reachable from a test, because all four failure branches end the process.

use std::io::IsTerminal;
use std::sync::Arc;

use clap::Parser;
use tracing::error;

use acme_proxy::cli::{Cli, Palette, dispatch, init_logging};
use acme_proxy::config::Config;
use acme_proxy::sqlite::db::Database;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Resolved against **stderr**, where these three messages go; `dispatch`
    // resolves its own against stdout. The two streams are redirected
    // independently, so one answer for both would colour into a log file
    // whenever the other half happened to be a terminal.
    let palette = Palette::resolve(
        cli.color,
        std::io::stderr().is_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    );

    let config = Arc::new(Config::load().unwrap_or_else(|error| {
        eprintln!("{}", palette.bad(&format!("configuration error: {error}")));
        std::process::exit(1);
    }));

    init_logging(&config.logging).unwrap_or_else(|error| {
        eprintln!("{}", palette.bad(&error));
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
        std::process::exit(1);
    }
}
