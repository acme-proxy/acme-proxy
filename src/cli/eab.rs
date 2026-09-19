use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, EabDeleteOutcome};
use crate::auditor::admin as audit_admin;
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::sqlite::db::Database;
use crate::sqlite::eab::{BoundAccounts, DeletedEab, Eab};
use acme_proxy_core::palette::Palette;

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
    /// Revoke a key. The row stays, so accounts registered with it still
    /// resolve to it (and to its label, for `eab` filter checks).
    Revoke { kid: String },
    /// Delete a key. Accounts registered with it are kept unless told
    /// otherwise, and then no longer resolve to any credential, so every `eab`
    /// filter check refuses them.
    Delete {
        kid: String,
        /// Also deactivate every account registered with it. Their orders are
        /// kept, so their certificates stay revocable.
        #[arg(long, conflicts_with = "delete_accounts")]
        deactivate_accounts: bool,
        /// Also hard-delete every account registered with it, and their orders.
        /// Refused while any of those orders holds a live certificate.
        #[arg(long)]
        delete_accounts: bool,
    },
}

pub async fn run_eab_command(
    command: EabCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        EabCommand::Create {
            label,
            profile,
            json,
        } => {
            let eab = Eab::create(label, profile, &database).await?;
            audit_admin::record_cli_action(&database, |actor, client| {
                audit_admin::eab_created(
                    actor,
                    client,
                    &eab.kid.to_string(),
                    eab.profile.as_deref(),
                    eab.label.as_deref(),
                )
            })
            .await;
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
            let subject = Eab::find_any_by_kid(&kid, &database).await?;
            if !Eab::revoke(&kid, &database).await? {
                return Err(not_found(&kid));
            }
            // A repeat revoke changes nothing, so it records nothing — the
            // `RevokeOutcome::AlreadyRevoked` rule on the certificate side.
            if subject.as_ref().is_some_and(|eab| eab.status == "active") {
                let profile = subject.as_ref().and_then(|eab| eab.profile.as_deref());
                audit_admin::record_cli_action(&database, |actor, client| {
                    audit_admin::eab_revoked(actor, client, &kid, profile)
                })
                .await;
            }
            println!("Revoked EAB key {kid}.");
        }
        EabCommand::Delete {
            kid,
            deactivate_accounts,
            delete_accounts,
        } => {
            let accounts = if delete_accounts {
                BoundAccounts::Delete
            } else if deactivate_accounts {
                BoundAccounts::Deactivate
            } else {
                BoundAccounts::Keep
            };
            match admin::confirm_delete_eab(&kid, accounts, yes, reader, database.clone()).await? {
                EabDeleteOutcome::NotFound => return Err(not_found(&kid)),
                EabDeleteOutcome::LiveCertificates {
                    accounts,
                    certificates,
                } => {
                    return Err(CliError::bad_request(admin::eab_live_certificates_refusal(
                        &kid,
                        accounts,
                        certificates,
                    )));
                }
                EabDeleteOutcome::Cancelled => println!("Cancelled."),
                EabDeleteOutcome::Deleted(deleted) => {
                    audit_admin::record_cli_actions(&database, |actor, client| {
                        audit_admin::eab_deleted_records(actor, client, &deleted)
                    })
                    .await;
                    println!("{}", deleted_line(&kid, &deleted));
                }
            }
        }
    }
    Ok(())
}

/// What `eab delete` prints once it has happened.
fn deleted_line(kid: &str, deleted: &DeletedEab) -> String {
    match deleted.accounts {
        BoundAccounts::Keep => format!(
            "Deleted EAB key {kid}; {} account(s) registered with it were kept.",
            deleted.remaining
        ),
        BoundAccounts::Deactivate => format!(
            "Deleted EAB key {kid}; {} account(s) deactivated, their orders kept.",
            deleted.deactivated.len()
        ),
        BoundAccounts::Delete => format!(
            "Deleted EAB key {kid} ({} account(s), {} order(s) deleted).",
            deleted.deleted.len(),
            deleted
                .deleted
                .iter()
                .map(|(_, orders)| orders)
                .sum::<u64>()
        ),
    }
}

fn not_found(kid: &str) -> CliError {
    CliError::bad_request(format!("no such EAB credential: {kid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn show_revoke_and_delete_refuse_an_unknown_kid() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let expected = CliError::bad_request("no such EAB credential: kid-nope".to_string());

        for command in [
            EabCommand::Show {
                kid: "kid-nope".to_string(),
                json: false,
            },
            EabCommand::Revoke {
                kid: "kid-nope".to_string(),
            },
            EabCommand::Delete {
                kid: "kid-nope".to_string(),
                deactivate_accounts: false,
                delete_accounts: true,
            },
        ] {
            let error = run_eab_command(
                command,
                true,
                Palette::plain(),
                &mut &b""[..],
                database.clone(),
            )
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
            run_eab_command(
                command,
                true,
                Palette::plain(),
                &mut &b""[..],
                database.clone(),
            )
            .await
            .unwrap();
        }

        run_eab_command(
            EabCommand::Revoke {
                kid: eab.kid.to_string(),
            },
            true,
            Palette::plain(),
            &mut &b""[..],
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

    /// `eab_kid`'s credential with one bound account holding a certificate that
    /// expires at `not_after`.
    async fn bound_account(
        database: &Arc<Database>,
        not_after: Option<i64>,
    ) -> (Eab, crate::sqlite::account::Account) {
        let eab = Eab::create(Some("tenant".to_string()), None, database)
            .await
            .unwrap();
        let (mut account, _) = crate::sqlite::account::Account::find_or_create(
            "default",
            &[7u8],
            vec![],
            &acme_proxy_core::audit::ClientContext::default(),
            database,
        )
        .await
        .unwrap();
        account.set_eab_kid(eab.kid, database).await.unwrap();
        crate::testutil::certified_order(database, account.id, not_after).await;
        (eab, account)
    }

    async fn delete(
        kid: &Eab,
        deactivate_accounts: bool,
        delete_accounts: bool,
        database: &Arc<Database>,
    ) -> Result<(), CliError> {
        run_eab_command(
            EabCommand::Delete {
                kid: kid.kid.to_string(),
                deactivate_accounts,
                delete_accounts,
            },
            true,
            Palette::plain(),
            &mut &b""[..],
            database.clone(),
        )
        .await
    }

    async fn audit_events(database: &Database) -> Vec<String> {
        let (rows, _) = crate::sqlite::audit::AuditEntry::search(
            &crate::sqlite::audit::AuditQuery {
                limit: 50,
                ..Default::default()
            },
            database,
        )
        .await
        .unwrap();
        rows.into_iter().map(|row| row.event).collect()
    }

    /// `--delete-accounts` over a live certificate is refused with the shared
    /// wording, writes no audit row, and changes nothing; deactivating instead
    /// goes through and writes one row per account plus the credential's.
    #[tokio::test]
    async fn delete_with_accounts_refuses_a_live_certificate_and_deactivating_does_not() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, account) = bound_account(&database, None).await;

        let error = delete(&eab, false, true, &database)
            .await
            .expect_err("a live certificate must refuse the delete");
        assert_eq!(
            error,
            CliError::bad_request(admin::eab_live_certificates_refusal(
                &eab.kid.to_string(),
                1,
                1
            ))
        );
        assert!(audit_events(&database).await.is_empty());

        delete(&eab, true, false, &database).await.unwrap();
        let mut events = audit_events(&database).await;
        events.sort();
        assert_eq!(events, ["account_deactivated", "eab_deleted"]);
        assert_eq!(
            crate::sqlite::account::Account::find_any_by_id(
                account.id.to_string().as_str(),
                &database
            )
            .await
            .unwrap()
            .unwrap()
            .status,
            "deactivated"
        );
    }

    /// With nothing live, `--delete-accounts` deletes the account and audits
    /// both the account and the credential; a plain delete audits only the
    /// credential.
    #[tokio::test]
    async fn delete_audits_the_credential_and_every_account_it_took() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, _) = bound_account(&database, Some(1)).await;
        delete(&eab, false, true, &database).await.unwrap();
        let mut events = audit_events(&database).await;
        events.sort();
        assert_eq!(events, ["account_deleted", "eab_deleted"]);

        let kept = Eab::create(None, None, &database).await.unwrap();
        delete(&kept, false, false, &database).await.unwrap();
        assert_eq!(audit_events(&database).await[0], "eab_deleted");
    }

    #[test]
    fn deleted_line_says_what_became_of_the_accounts() {
        use crate::sqlite::eab::DeletedEab;

        let eab = || Eab {
            kid: uuid::Uuid::nil(),
            secret: Vec::new(),
            label: None,
            profile: None,
            status: "active".to_string(),
            created_at: 0,
        };
        let kid = uuid::Uuid::nil().to_string();
        let kept = DeletedEab {
            eab: eab(),
            accounts: BoundAccounts::Keep,
            deactivated: Vec::new(),
            deleted: Vec::new(),
            remaining: 3,
        };
        assert!(deleted_line(&kid, &kept).ends_with("3 account(s) registered with it were kept."));
        let deactivated = DeletedEab {
            accounts: BoundAccounts::Deactivate,
            ..kept
        };
        assert!(deleted_line(&kid, &deactivated).contains("0 account(s) deactivated"));
        let deleted = DeletedEab {
            eab: eab(),
            accounts: BoundAccounts::Delete,
            deactivated: Vec::new(),
            deleted: Vec::new(),
            remaining: 0,
        };
        assert!(deleted_line(&kid, &deleted).ends_with("(0 account(s), 0 order(s) deleted)."));
    }
}
