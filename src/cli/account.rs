use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, DeleteOutcome};
use crate::cli::CliError;
use crate::config::Config;
use crate::sqlite::account::Account;
use crate::sqlite::db::Database;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// List accounts, of every profile unless one is named.
    List {
        /// Restrict the listing to one ACME endpoint.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show one account.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Replace an account's contact list.
    UpdateContact {
        id: String,
        #[arg(long = "contact")]
        contact: Vec<String>,
    },
    /// Set status = deactivated (RFC 8555 §7.3.6, terminal).
    Deactivate { id: String },
    /// Hard-delete the account and everything under it.
    Delete { id: String },
}

pub async fn run_account_command(
    command: AccountCommand,
    yes: bool,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AccountCommand::List { profile, json } => {
            let accounts = Account::list_all(profile.as_deref(), &database).await?;
            if json {
                let rendered: Vec<_> = accounts
                    .iter()
                    .map(|a| admin::render_account_json(a, &config.server.base_url))
                    .collect();
                println!("{}", serde_json::Value::Array(rendered));
            } else {
                for account in &accounts {
                    println!("{}", admin::render_account_line(account));
                }
            }
        }
        AccountCommand::Show { id, json } => match Account::find_any_by_id(&id, &database).await? {
            None => return Err(not_found(&id)),
            Some(account) if json => {
                println!(
                    "{}",
                    admin::render_account_json(&account, &config.server.base_url)
                );
            }
            Some(account) => print!("{}", admin::render_account_detail_text(&account)),
        },
        AccountCommand::UpdateContact { id, contact } => {
            match admin::update_account_contact(&id, contact, database).await? {
                None => return Err(not_found(&id)),
                Some(account) => println!("{}", admin::render_account_line(&account)),
            }
        }
        AccountCommand::Deactivate { id } => {
            match admin::deactivate_account(&id, database).await? {
                None => return Err(not_found(&id)),
                Some(account) => println!("{}", admin::render_account_line(&account)),
            }
        }
        AccountCommand::Delete { id } => {
            match admin::confirm_delete_account(&id, yes, reader, database).await? {
                DeleteOutcome::NotFound => return Err(not_found(&id)),
                DeleteOutcome::Cancelled => println!("Cancelled."),
                DeleteOutcome::Deleted => println!("Deleted account {id}."),
            }
        }
    }
    Ok(())
}

fn not_found(id: &str) -> CliError {
    CliError(format!("no such account: {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ClientContext;

    /// Every arm taking an id reports the same thing for one that does not
    /// exist — and reports it as a value, so the caller decides the exit code.
    #[tokio::test]
    async fn every_arm_refuses_an_unknown_account() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let expected = CliError("no such account: acct-nope".to_string());

        let commands = vec![
            AccountCommand::Show {
                id: "acct-nope".to_string(),
                json: false,
            },
            AccountCommand::UpdateContact {
                id: "acct-nope".to_string(),
                contact: vec!["mailto:someone@example.com".to_string()],
            },
            AccountCommand::Deactivate {
                id: "acct-nope".to_string(),
            },
            AccountCommand::Delete {
                id: "acct-nope".to_string(),
            },
        ];
        for command in commands {
            let mut reader: &[u8] = &[];
            let error = run_account_command(command, true, &mut reader, &config, database.clone())
                .await
                .expect_err("an unknown account must fail");
            assert_eq!(error, expected);
        }
    }

    /// `delete` without `--yes` asks first, and a refusal is a success: the
    /// operator answered, nothing was destroyed.
    #[tokio::test]
    async fn a_declined_delete_is_not_a_failure() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let (account, _) = Account::find_or_create(
            "default",
            &[7, 7, 7],
            vec![],
            &ClientContext::default(),
            &database,
        )
        .await
        .unwrap();

        let mut reader: &[u8] = b"n\n";
        run_account_command(
            AccountCommand::Delete {
                id: account.id.clone(),
            },
            false,
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        assert!(
            Account::find_any_by_id(&account.id, &database)
                .await
                .unwrap()
                .is_some(),
            "a declined delete must leave the account in place"
        );
    }

    /// The JSON arms render through `admin::render_account_json`, which needs
    /// the configured `base_url` — a separate branch from the line renderer.
    #[tokio::test]
    async fn the_json_arms_render() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let (account, _) = Account::find_or_create(
            "default",
            &[9, 9, 9],
            vec![],
            &ClientContext::default(),
            &database,
        )
        .await
        .unwrap();

        let mut reader: &[u8] = &[];
        run_account_command(
            AccountCommand::List {
                profile: Some("default".to_string()),
                json: true,
            },
            true,
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        run_account_command(
            AccountCommand::Show {
                id: account.id,
                json: true,
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
