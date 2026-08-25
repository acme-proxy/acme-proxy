use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin;
use crate::audit::ALL_AUDIT_EVENTS;
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::sqlite::audit::AuditQuery;
use crate::sqlite::db::Database;

#[derive(Subcommand)]
pub enum AuditCommand {
    /// List audit rows, newest first.
    List {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long = "account-id")]
        account_id: Option<String>,
        #[arg(long = "order-id")]
        order_id: Option<String>,
        #[arg(long = "cert-serial")]
        cert_serial: Option<String>,
        /// One of `certificate_issued`, `certificate_issue_failed`,
        /// `certificate_revoked`, `certificate_revoke_failed`.
        #[arg(long)]
        event: Option<String>,
        /// `success` or `failure`.
        #[arg(long)]
        outcome: Option<String>,
        /// Only rows from the last N days.
        #[arg(long = "since-days")]
        since_days: Option<u64>,
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one audit row in full.
    Show {
        id: i64,
        #[arg(long)]
        json: bool,
    },
    /// Delete audit rows older than a number of days.
    ///
    /// The only command in this binary that destroys audit history, which is
    /// why it prompts with the number of rows it is about to remove.
    Cleanup {
        #[arg(long = "older-than")]
        older_than: u64,
    },
}

/// Rejects an `--event`/`--outcome` this build does not know.
///
/// Refused here rather than passed through to SQL, where an unknown value is
/// not an error but an empty result — and "no rows" for a typo'd filter is the
/// single most misleading answer an audit tool can give.
fn check_filters(event: Option<&str>, outcome: Option<&str>) -> Result<(), CliError> {
    if let Some(event) = event
        && crate::audit::AuditEvent::parse(event).is_none()
    {
        let known: Vec<&str> = ALL_AUDIT_EVENTS.iter().map(|e| e.as_str()).collect();
        return Err(CliError(format!(
            "unknown --event `{event}`; known events are {}",
            known.join(", ")
        )));
    }
    if let Some(outcome) = outcome
        && !matches!(outcome, "success" | "failure")
    {
        return Err(CliError(format!(
            "unknown --outcome `{outcome}`; expected `success` or `failure`"
        )));
    }
    Ok(())
}

pub async fn run_audit_command(
    command: AuditCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AuditCommand::List {
            profile,
            account_id,
            order_id,
            cert_serial,
            event,
            outcome,
            since_days,
            limit,
            offset,
            json,
        } => {
            check_filters(event.as_deref(), outcome.as_deref())?;
            let window = Window::resolve(limit, offset);
            let query = AuditQuery {
                profile,
                account_id,
                order_id,
                cert_serial,
                event,
                outcome,
                since: since_days.map(admin::audit_cutoff),
                limit: window.limit,
                offset: window.offset,
            };
            let (entries, total) = admin::list_audit(&query, database).await?;
            render::print_page(
                &entries,
                total,
                window,
                json,
                crate::sqlite::audit::AuditEntry::to_json,
                |entry| render::render_audit_line(entry, palette),
            );
        }
        AuditCommand::Show { id, json } => {
            let Some(entry) = admin::find_audit(id, database).await? else {
                return Err(CliError(format!("audit row {id} not found")));
            };
            if json {
                println!("{}", entry.to_json());
            } else {
                print!("{}", render::render_audit_detail_text(&entry, palette));
            }
        }
        AuditCommand::Cleanup { older_than } => {
            match admin::confirm_cleanup_audit(older_than, yes, reader, database).await? {
                None => println!("Cancelled."),
                Some(removed) => println!("Removed {removed} audit row(s)."),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_self::audit::{Actor, AuditRecord};
    use acme_proxy_self::sqlite::audit::AuditEntry;
    use acme_proxy_self::sqlite::db::Database;

    // The crate refers to itself as `crate`; this alias keeps the imports above
    // readable next to the `crate::` paths in the module body.
    use crate as acme_proxy_self;

    async fn db_with_rows() -> Arc<Database> {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        for event in ALL_AUDIT_EVENTS {
            AuditEntry::insert(
                AuditRecord::new(*event, "default", Actor::acme("acct-1"))
                    .with_account("acct-1")
                    .with_serial("0a0b"),
                &db,
            )
            .await
            .unwrap();
        }
        db
    }

    /// A typo'd filter must be an error, not an empty result. "No rows" for a
    /// misspelt `--event` is the most misleading answer an audit tool can give,
    /// because it looks exactly like "nothing happened".
    #[test]
    fn an_unknown_event_or_outcome_is_refused_by_name() {
        assert!(check_filters(None, None).is_ok());
        assert!(check_filters(Some("certificate_issued"), Some("success")).is_ok());

        let error = check_filters(Some("certificate_renewed"), None).unwrap_err();
        assert!(error.0.contains("certificate_renewed"), "{error}");
        // The message lists what *is* accepted, so the operator can fix it
        // without reaching for the docs.
        assert!(error.0.contains("certificate_issued"), "{error}");
        assert!(error.0.contains("certificate_revoke_failed"), "{error}");

        let error = check_filters(None, Some("maybe")).unwrap_err();
        assert!(error.0.contains("maybe"), "{error}");
        assert!(error.0.contains("success"), "{error}");
    }

    /// `AuditCommand::List` is an enum variant, so there is no functional
    /// record update to lean on — each shape is spelled out.
    fn list(json: bool) -> AuditCommand {
        AuditCommand::List {
            profile: None,
            account_id: None,
            order_id: None,
            cert_serial: None,
            event: None,
            outcome: None,
            since_days: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json,
        }
    }

    fn list_window(limit: i64, offset: i64) -> AuditCommand {
        AuditCommand::List {
            profile: None,
            account_id: None,
            order_id: None,
            cert_serial: None,
            event: None,
            outcome: None,
            since_days: None,
            limit,
            offset,
            json: false,
        }
    }

    fn list_event(event: &str) -> AuditCommand {
        AuditCommand::List {
            profile: None,
            account_id: None,
            order_id: None,
            cert_serial: None,
            event: Some(event.to_string()),
            outcome: None,
            since_days: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: false,
        }
    }

    /// Every filter set at once, so none of them is a predicate that fails to
    /// build once combined.
    fn list_every_filter() -> AuditCommand {
        AuditCommand::List {
            profile: Some("default".to_string()),
            account_id: Some("acct-1".to_string()),
            order_id: Some("order-1".to_string()),
            cert_serial: Some("0a0b".to_string()),
            event: Some("certificate_issued".to_string()),
            outcome: Some("success".to_string()),
            since_days: Some(7),
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: false,
        }
    }

    /// Both output shapes of `list`, plus the clamps: a `--limit 0` or a
    /// negative `--offset` is nonsense the command corrects rather than a SQL
    /// error the operator has to decode.
    #[tokio::test]
    async fn list_runs_in_both_shapes_and_clamps_a_nonsense_window() {
        let db = db_with_rows().await;
        let mut reader: &[u8] = &[];

        run_audit_command(list(false), true, Palette::plain(), &mut reader, db.clone())
            .await
            .unwrap();
        run_audit_command(list(true), true, Palette::plain(), &mut reader, db.clone())
            .await
            .unwrap();
        run_audit_command(
            list_window(0, -5),
            true,
            Palette::plain(),
            &mut reader,
            db.clone(),
        )
        .await
        .unwrap();
        run_audit_command(list_every_filter(), true, Palette::plain(), &mut reader, db)
            .await
            .unwrap();
    }

    /// The filter check runs before the query, so a bad `--event` fails without
    /// touching the database.
    #[tokio::test]
    async fn list_refuses_an_unknown_event_before_querying() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut reader: &[u8] = &[];
        let error = run_audit_command(list_event("nope"), true, Palette::plain(), &mut reader, db)
            .await
            .unwrap_err();
        assert!(error.0.contains("unknown --event"), "{error}");
    }

    #[tokio::test]
    async fn show_renders_both_shapes_and_names_an_unknown_id() {
        let db = db_with_rows().await;
        let mut reader: &[u8] = &[];

        for json in [false, true] {
            run_audit_command(
                AuditCommand::Show { id: 1, json },
                true,
                Palette::plain(),
                &mut reader,
                db.clone(),
            )
            .await
            .unwrap();
        }

        let error = run_audit_command(
            AuditCommand::Show {
                id: 9_999,
                json: false,
            },
            true,
            Palette::plain(),
            &mut reader,
            db,
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("9999"), "{error}");
    }

    /// Declining leaves the trail alone; accepting prunes by age.
    #[tokio::test]
    async fn cleanup_honours_the_prompt() {
        let db = db_with_rows().await;

        let mut declined: &[u8] = b"n\n";
        run_audit_command(
            AuditCommand::Cleanup { older_than: 0 },
            false,
            Palette::plain(),
            &mut declined,
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            AuditEntry::count_older_than(i64::MAX, &db).await.unwrap(),
            4
        );

        // Nothing is a year old, so an accepted sweep still removes nothing —
        // the cutoff, not the confirmation, is what bounds it.
        let mut reader: &[u8] = &[];
        run_audit_command(
            AuditCommand::Cleanup { older_than: 365 },
            true,
            Palette::plain(),
            &mut reader,
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            AuditEntry::count_older_than(i64::MAX, &db).await.unwrap(),
            4
        );
    }
}
