//! `acme-proxy transfer --to <url>` — copy every row into the other backend.
//!
//! The move an operator makes once: a SQLite file that has outgrown one host,
//! into the PostgreSQL cluster the three roles can then be spread across. The
//! direction is not a flag — the configured `database.url` is the source, the
//! `--to` URL is the target, and each one's scheme says which backend it is,
//! so the reverse is the same command with the two swapped.
//!
//! Everything about *how* the copy works is
//! [`acme_proxy_store::transfer`]'s business. What lives here is the four
//! things that have to be true before it starts, each refused by name:
//!
//! - the target is reachable and its schema is current — this command does not
//!   migrate it, because applying a schema belongs to `migrate`/`init` and the
//!   `worker` role and nothing else ([ADR 0003]);
//! - the target is empty, with **no override**: a copy into a database that
//!   already holds rows is not a merge, and the `INSERT`s would collide
//!   halfway through on whichever primary key happened to clash first;
//! - the two URLs are not the same database;
//! - and the operator has been told the one thing no check can establish —
//!   **the source server must be stopped**. A worker mid-issuance writes rows
//!   the copy has already walked past, and a torn snapshot looks exactly like
//!   a good one.
//!
//! [ADR 0003]: ../../doc/src/dev/adr/0003-migrations-frozen-and-explicit.md

use std::io::BufRead;
use std::sync::Arc;

use acme_proxy_admin::admin;
use acme_proxy_core::logfields::redact_url;
use acme_proxy_jobs::auditor::admin as audit_admin;
use acme_proxy_store::db::Database;
use acme_proxy_store::transfer;

use crate::cli::CliError;

pub async fn run_transfer_command(
    to: &str,
    json: bool,
    yes: bool,
    reader: &mut impl BufRead,
    source_url: &str,
    database: Arc<Database>,
) -> Result<(), CliError> {
    if same_database(source_url, to) {
        return Err(CliError::bad_request(format!(
            "the source and the target are the same database ({})",
            redact_url(source_url)
        )));
    }

    let target = Database::open(to).await.map_err(|error| {
        CliError::failed(format!(
            "cannot open the target {}: {error}",
            redact_url(to)
        ))
    })?;

    // Not migrated here on purpose; see the module doc.
    let pending = target.pending_migrations().await?;
    if !pending.is_empty() {
        return Err(CliError::bad_request(format!(
            "the target's schema is {} migration(s) behind; run \
             `ACME_PROXY_DATABASE__URL={} acme-proxy migrate` first",
            pending.len(),
            redact_url(to)
        )));
    }

    let occupied = transfer::non_empty_tables(&target).await?;
    if !occupied.is_empty() {
        let held = occupied
            .iter()
            .map(|table| format!("{} ({} row(s))", table.table, table.rows))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CliError::bad_request(format!(
            "the target already holds rows, and a transfer is a copy rather than \
             a merge: {held}. Start from an empty database — create one and run \
             `acme-proxy migrate` against it"
        )));
    }

    let counts = transfer::non_empty_tables(&database).await?;
    let total: u64 = counts.iter().map(|table| table.rows).sum();
    if total == 0 {
        println!("The source holds no rows; there is nothing to copy.");
        return Ok(());
    }

    let prompt = format!(
        "Copy {total} row(s) from {} to {}?\n\
         The source server must be stopped, or the copy is a torn snapshot.\n\
         Continue?",
        redact_url(source_url),
        redact_url(to)
    );
    if !admin::confirm(&prompt, yes, reader) {
        println!("Cancelled.");
        return Ok(());
    }

    let report = database.transfer_to(&target).await?;

    audit_admin::record_cli_action(&database, |actor, client| {
        audit_admin::database_transferred(actor, client, report.total())
    })
    .await;

    if json {
        let tables: Vec<serde_json::Value> = report
            .tables
            .iter()
            .map(|table| serde_json::json!({ "table": table.table, "rows": table.rows }))
            .collect();
        println!(
            "{}",
            serde_json::json!({ "tables": tables, "total": report.total() })
        );
    } else {
        for table in &report.tables {
            println!("  {:<24} {}", table.table, table.rows);
        }
        println!(
            "Copied {} row(s) into {} table(s).",
            report.total(),
            report.tables.len()
        );
    }
    Ok(())
}

/// Are these two URLs the same database?
///
/// A best-effort string comparison, and deliberately not more: resolving
/// whether two DSNs reach one cluster means a connection and a round trip, and
/// the case this actually catches is the operator who pasted the same URL
/// twice. A copy into itself would otherwise fail on the first primary key,
/// after the prompt has already said it was about to move every row.
fn same_database(source: &str, target: &str) -> bool {
    source.trim_end_matches('/') == target.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_pasted_twice_is_the_same_database() {
        assert!(same_database("sqlite://acme.db", "sqlite://acme.db"));
        assert!(same_database("postgres://a@h/db", "postgres://a@h/db/"));
    }

    /// The case the whole command exists for, which must not be refused.
    #[test]
    fn the_two_backends_are_not_the_same_database() {
        assert!(!same_database(
            "sqlite://acme.db",
            "postgres://acme@db.internal/acme"
        ));
        assert!(!same_database("sqlite://a.db", "sqlite://b.db"));
    }
}
