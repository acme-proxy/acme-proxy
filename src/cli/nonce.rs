use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;

use clap::Subcommand;

use crate::admin;
use crate::cli::CliError;
use crate::config::Config;
use crate::sqlite::db::Database;

#[derive(Subcommand)]
pub enum NonceCommand {
    /// Delete nonces older than the TTL.
    Cleanup {
        #[arg(long = "ttl-seconds")]
        ttl_seconds: Option<u64>,
    },
}

pub async fn run_nonce_command(
    command: NonceCommand,
    yes: bool,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        NonceCommand::Cleanup { ttl_seconds } => {
            let ttl = Duration::from_secs(ttl_seconds.unwrap_or(config.nonce.ttl_seconds));
            match admin::confirm_cleanup_nonces(ttl, yes, reader, database).await? {
                None => println!("Cancelled."),
                Some(removed) => println!("Removed {removed} nonce(s)."),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Omitting `--ttl-seconds` falls back to `nonce.ttl_seconds`, and a
    /// declined confirmation sweeps nothing without being a failure.
    #[tokio::test]
    async fn cleanup_honours_the_configured_ttl_and_the_prompt() {
        let database = Arc::new(
            crate::sqlite::db::Database::connect_in_memory()
                .await
                .unwrap(),
        );
        let mut config = Config::default();
        config.nonce.ttl_seconds = 1;

        let mut declined: &[u8] = b"n\n";
        run_nonce_command(
            NonceCommand::Cleanup { ttl_seconds: None },
            false,
            &mut declined,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        let mut reader: &[u8] = &[];
        run_nonce_command(
            NonceCommand::Cleanup {
                ttl_seconds: Some(60),
            },
            true,
            &mut reader,
            &config,
            database,
        )
        .await
        .unwrap();
    }
}
