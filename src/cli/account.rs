use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, DeleteOutcome};
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::config::Config;
use crate::sqlite::account::Account;
use crate::sqlite::db::Database;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// List accounts, newest first, of every profile unless one is named.
    List {
        /// Restrict the listing to one ACME endpoint.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
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
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AccountCommand::List {
            profile,
            limit,
            offset,
            json,
        } => {
            let window = Window::resolve(limit, offset);
            let (accounts, total) =
                Account::search(profile.as_deref(), window.limit, window.offset, &database).await?;
            render::print_page(
                &accounts,
                total,
                window,
                json,
                |a| admin::render_account_json(a, &config.server.base_url),
                |a| render::render_account_line(a, palette),
            );
        }
        AccountCommand::Show { id, json } => match Account::find_any_by_id(&id, &database).await? {
            None => return Err(not_found(&id)),
            Some(account) if json => {
                println!(
                    "{}",
                    admin::render_account_json(&account, &config.server.base_url)
                );
            }
            Some(account) => print!("{}", render::render_account_detail_text(&account, palette)),
        },
        AccountCommand::UpdateContact { id, contact } => {
            match admin::update_account_contact(&id, contact, database).await? {
                None => return Err(not_found(&id)),
                Some(account) => println!("{}", render::render_account_line(&account, palette)),
            }
        }
        AccountCommand::Deactivate { id } => {
            match admin::deactivate_account(&id, database).await? {
                None => return Err(not_found(&id)),
                Some(account) => println!("{}", render::render_account_line(&account, palette)),
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
            let error = run_account_command(
                command,
                true,
                Palette::plain(),
                &mut reader,
                &config,
                database.clone(),
            )
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
                id: account.id.to_string(),
            },
            false,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        assert!(
            Account::find_any_by_id(account.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .is_some(),
            "a declined delete must leave the account in place"
        );
    }

    /// The listing takes a window, and a nonsense one is corrected rather than
    /// handed to SQL — where `LIMIT -1` means *no limit* in SQLite, the one
    /// answer a page must never accidentally give. `audit list`'s rule, now
    /// this one's.
    #[tokio::test]
    async fn list_runs_in_both_shapes_and_clamps_a_nonsense_window() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        for key in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            Account::find_or_create("default", key, vec![], &ClientContext::default(), &database)
                .await
                .unwrap();
        }

        let mut reader: &[u8] = &[];
        for (limit, offset, json) in [(2, 0, false), (2, 2, false), (2, 0, true), (0, -5, false)] {
            run_account_command(
                AccountCommand::List {
                    profile: None,
                    limit,
                    offset,
                    json,
                },
                true,
                Palette::plain(),
                &mut reader,
                &config,
                database.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("--limit {limit} --offset {offset}: {error}"));
        }
    }

    /// The window reaches the query rather than being clamped and dropped: two
    /// pages of two over three rows do not overlap, and the total stays the
    /// unpaged count on both. Asserted against the model the command calls,
    /// since a command body prints rather than returns.
    #[tokio::test]
    async fn consecutive_pages_do_not_overlap_and_the_total_stays_unpaged() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        for key in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            Account::find_or_create("default", key, vec![], &ClientContext::default(), &database)
                .await
                .unwrap();
        }

        let (first, total) = Account::search(None, 2, 0, &database).await.unwrap();
        let (second, also_total) = Account::search(None, 2, 2, &database).await.unwrap();

        assert_eq!(total, 3);
        assert_eq!(also_total, 3, "the total is the table, not the page");
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 1);
        for account in &second {
            assert!(
                !first.iter().any(|earlier| earlier.id == account.id),
                "a row appeared on two pages"
            );
        }
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
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: true,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        run_account_command(
            AccountCommand::Show {
                id: account.id.to_string(),
                json: true,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database,
        )
        .await
        .unwrap();
    }
}
