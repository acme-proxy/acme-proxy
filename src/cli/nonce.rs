use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;

use clap::Subcommand;

use crate::admin;
use crate::cli::CliError;
use crate::config::Config;
use crate::sqlite::db::Database;
use crate::sqlite::nonce::Nonce;

#[derive(Subcommand)]
pub enum NonceCommand {
    /// Delete nonces older than the TTL.
    Cleanup {
        #[arg(long = "ttl-seconds")]
        ttl_seconds: Option<u64>,
    },
    /// How many nonces the table holds, and the window they are fresh for.
    Count {
        #[arg(long)]
        json: bool,
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
        NonceCommand::Count { json } => {
            // No `Palette`: a count is data, and the only thing here that could
            // be painted -- "the reaper is not running" -- is a judgement this
            // command deliberately leaves to the operator reading the two
            // numbers together.
            let count = Nonce::count(&database).await?;
            let ttl = config.nonce.ttl_seconds;
            if json {
                println!("{}", admin::render_nonce_stats_json(count, ttl));
            } else {
                println!("{count} nonce(s), ttl {ttl}s.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both shapes, and the pair the count is only meaningful as: the number on
    /// its own says nothing without the window it is a count over.
    #[tokio::test]
    async fn count_reports_the_table_and_the_configured_ttl() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut config = Config::default();
        config.nonce.ttl_seconds = 42;

        for _ in 0..3 {
            Nonce::new().save(&database).await.unwrap();
        }
        assert_eq!(Nonce::count(&database).await.unwrap(), 3);

        assert_eq!(
            admin::render_nonce_stats_json(3, config.nonce.ttl_seconds),
            serde_json::json!({ "count": 3, "ttlSeconds": 42 }),
        );

        for json in [false, true] {
            let mut reader: &[u8] = &[];
            run_nonce_command(
                NonceCommand::Count { json },
                true,
                &mut reader,
                &config,
                database.clone(),
            )
            .await
            .unwrap();
        }
    }

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
