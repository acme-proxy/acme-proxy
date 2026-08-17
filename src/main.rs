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

use std::sync::Arc;

use clap::Parser;
use tracing::error;

use acme_proxy::cli::{Cli, dispatch, init_logging};
use acme_proxy::config::Config;
use acme_proxy::sqlite::db::Database;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = Arc::new(Config::load().unwrap_or_else(|error| {
        eprintln!("configuration error: {error}");
        std::process::exit(1);
    }));

    init_logging(&config.logging).unwrap_or_else(|error| {
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
