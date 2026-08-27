use std::sync::Arc;

use clap::Subcommand;

use crate::admin;
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::sqlite::db::Database;
use crate::sqlite::eab::Eab;

#[derive(Subcommand)]
pub enum EabCommand {
    /// Generate a new EAB key and print its kid + secret ONCE.
    Create {
        #[arg(long)]
        label: Option<String>,
        /// Bind the credential to one ACME endpoint. Omitted, it is accepted
        /// at every profile — which is what an unscoped credential means.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List EAB keys, newest first. Never shows the secret.
    List {
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one EAB key. Never shows the secret.
    Show {
        kid: String,
        #[arg(long)]
        json: bool,
    },
    /// Revoke a key.
    Revoke { kid: String },
}

pub async fn run_eab_command(
    command: EabCommand,
    palette: Palette,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        EabCommand::Create {
            label,
            profile,
            json,
        } => {
            let eab = Eab::create(label, profile, &database).await?;
            if json {
                println!("{}", admin::render_eab_created_json(&eab));
            } else {
                print!("{}", render::render_eab_created_text(&eab, palette));
            }
        }
        EabCommand::List {
            limit,
            offset,
            json,
        } => {
            let window = Window::resolve(limit, offset);
            let (keys, total) = Eab::search(window.limit, window.offset, &database).await?;
            render::print_page(&keys, total, window, json, admin::render_eab_json, |eab| {
                render::render_eab_line(eab, palette)
            });
        }
        EabCommand::Show { kid, json } => match Eab::find_any_by_kid(&kid, &database).await? {
            None => return Err(not_found(&kid)),
            Some(eab) if json => println!("{}", admin::render_eab_json(&eab)),
            Some(eab) => println!("{}", render::render_eab_line(&eab, palette)),
        },
        EabCommand::Revoke { kid } => {
            if !Eab::revoke(&kid, &database).await? {
                return Err(not_found(&kid));
            }
            println!("Revoked EAB key {kid}.");
        }
    }
    Ok(())
}

fn not_found(kid: &str) -> CliError {
    CliError(format!("no such EAB credential: {kid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn show_and_revoke_refuse_an_unknown_kid() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let expected = CliError("no such EAB credential: kid-nope".to_string());

        for command in [
            EabCommand::Show {
                kid: "kid-nope".to_string(),
                json: false,
            },
            EabCommand::Revoke {
                kid: "kid-nope".to_string(),
            },
        ] {
            let error = run_eab_command(command, Palette::plain(), database.clone())
                .await
                .expect_err("an unknown kid must fail");
            assert_eq!(error, expected);
        }
    }

    /// `revoke` matches on the `kid` alone, so revoking twice is idempotent
    /// and still reports success — only an unknown `kid` is an error.
    #[tokio::test]
    async fn a_created_key_shows_lists_and_revokes() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("test".to_string()), None, &database)
            .await
            .unwrap();

        for command in [
            EabCommand::Create {
                label: None,
                profile: Some("default".to_string()),
                json: true,
            },
            EabCommand::List {
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: true,
            },
            EabCommand::Show {
                kid: eab.kid.to_string(),
                json: true,
            },
            EabCommand::Show {
                kid: eab.kid.to_string(),
                json: false,
            },
            EabCommand::Revoke {
                kid: eab.kid.to_string(),
            },
        ] {
            run_eab_command(command, Palette::plain(), database.clone())
                .await
                .unwrap();
        }

        run_eab_command(
            EabCommand::Revoke {
                kid: eab.kid.to_string(),
            },
            Palette::plain(),
            database.clone(),
        )
        .await
        .expect("revoking an already-revoked key is a no-op, not a failure");

        assert_eq!(
            Eab::find_any_by_kid(eab.kid.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            "revoked"
        );
    }
}
