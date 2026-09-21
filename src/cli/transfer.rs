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
    use crate::cli::CliErrorKind;
    use acme_proxy_core::testutil::TempDir;
    use acme_proxy_store::audit::{AuditEntry, AuditQuery};
    use acme_proxy_store::testutil as fixtures;

    /// The `database.url` the command is told the source is.
    ///
    /// Only [`same_database`] and the two messages read it — the source itself
    /// arrives as an already-open handle — so it does not have to name the
    /// in-memory database the tests actually pass, and cannot.
    const SOURCE_URL: &str = "sqlite://source.db";

    /// A source holding one row in every table the manifest names.
    async fn seeded_source() -> Arc<Database> {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        fixtures::seed_every_table(&database).await;
        database
    }

    /// A migrated, empty SQLite file, and the URL that names it.
    ///
    /// A file rather than `sqlite::memory:`, because the command opens the
    /// target itself from the string: an in-memory URL has no `://` for
    /// `Database::open` to route on, and would hand every connection its own
    /// empty database even if it had one.
    async fn migrated_target(dir: &TempDir, name: &str) -> String {
        let url = format!("sqlite://{}", dir.join(name).display());
        let database = Database::connect_and_migrate(&url)
            .await
            .expect("a fresh SQLite file migrates");
        database.close().await;
        url
    }

    /// Every table of the database at `url`, by name and row count.
    async fn counts(url: &str) -> Vec<(&'static str, u64)> {
        let database = Database::open(url).await.expect("the target reopens");
        let counts = fixtures::row_counts(&database).await;
        database.close().await;
        counts
    }

    #[tokio::test]
    async fn the_same_url_twice_is_refused_before_anything_is_opened() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        let error =
            run_transfer_command(SOURCE_URL, false, true, &mut &b""[..], SOURCE_URL, database)
                .await
                .expect_err("a database is not copied into itself");

        assert_eq!(error.kind(), CliErrorKind::BadRequest);
        assert!(error.message.contains("the same database"), "{error}");
    }

    #[tokio::test]
    async fn an_unopenable_target_is_refused_by_name() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        let error = run_transfer_command(
            "mysql://acme@db.internal/acme",
            false,
            true,
            &mut &b""[..],
            SOURCE_URL,
            database,
        )
        .await
        .expect_err("a scheme this server does not speak");

        assert_eq!(error.kind(), CliErrorKind::Failed);
        assert!(error.message.contains("cannot open the target"), "{error}");
    }

    /// The target is not migrated here, and the refusal says who does it.
    ///
    /// `Database::open` creates a missing SQLite file but applies nothing, so
    /// a `--to` naming a path that does not exist yet lands here rather than
    /// quietly gaining a schema from the command that was asked to copy rows
    /// ([ADR 0003]).
    ///
    /// [ADR 0003]: ../../doc/src/dev/adr/0003-migrations-frozen-and-explicit.md
    #[tokio::test]
    async fn an_unmigrated_target_is_refused_and_says_what_to_run() {
        let dir = TempDir::new("transfer-unmigrated");
        let url = format!("sqlite://{}", dir.join("target.db").display());
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        let error = run_transfer_command(&url, false, true, &mut &b""[..], SOURCE_URL, database)
            .await
            .expect_err("an empty file is not a migrated database");

        assert_eq!(error.kind(), CliErrorKind::BadRequest);
        assert!(error.message.contains("migration(s) behind"), "{error}");
        assert!(error.message.contains("acme-proxy migrate"), "{error}");
    }

    /// A target holding rows is refused, and the refusal names them.
    ///
    /// "The target is not empty" is not something an operator can act on;
    /// "`accounts` (2 row(s))" is. There is no flag that overrides this.
    #[tokio::test]
    async fn a_target_that_holds_rows_is_refused_and_lists_them() {
        let dir = TempDir::new("transfer-occupied");
        let url = migrated_target(&dir, "target.db").await;
        let occupied = Arc::new(Database::open(&url).await.unwrap());
        fixtures::seed_every_table(&occupied).await;
        occupied.close().await;

        let error = run_transfer_command(
            &url,
            false,
            true,
            &mut &b""[..],
            SOURCE_URL,
            seeded_source().await,
        )
        .await
        .expect_err("a copy into a populated database is not a merge");

        assert_eq!(error.kind(), CliErrorKind::BadRequest);
        assert!(error.message.contains("already holds rows"), "{error}");
        assert!(error.message.contains("accounts"), "{error}");
    }

    /// An empty source stops before the prompt.
    ///
    /// Asserted through `yes = false` and a reader at EOF: `confirm` reads EOF
    /// as a decline, so if this returned by way of the prompt it would still
    /// be `Ok(())` — but the early return is what makes it one without ever
    /// asking a question about zero rows.
    #[tokio::test]
    async fn an_empty_source_copies_nothing() {
        let dir = TempDir::new("transfer-empty");
        let url = migrated_target(&dir, "target.db").await;
        let database = Arc::new(Database::connect_in_memory().await.unwrap());

        run_transfer_command(&url, false, false, &mut &b""[..], SOURCE_URL, database)
            .await
            .expect("nothing to copy is not a failure");

        assert!(
            counts(&url).await.iter().all(|(_, rows)| *rows == 0),
            "the target is untouched"
        );
    }

    #[tokio::test]
    async fn a_declined_prompt_copies_nothing_and_writes_no_audit_row() {
        let dir = TempDir::new("transfer-declined");
        let url = migrated_target(&dir, "target.db").await;
        let source = seeded_source().await;
        let before = AuditEntry::search(&AuditQuery::default(), &source)
            .await
            .unwrap()
            .1;

        run_transfer_command(
            &url,
            false,
            false,
            &mut b"n\n".as_slice(),
            SOURCE_URL,
            source.clone(),
        )
        .await
        .expect("a decline is not a failure");

        assert!(
            counts(&url).await.iter().all(|(_, rows)| *rows == 0),
            "a decline copies nothing"
        );
        assert_eq!(
            AuditEntry::search(&AuditQuery::default(), &source)
                .await
                .unwrap()
                .1,
            before,
            "a declined transfer is not an administrative action"
        );
    }

    /// The copy, and the row it leaves behind on the source.
    ///
    /// The counts are taken before the call on purpose: `record_cli_action`
    /// writes `database_transferred` to the **source** once the copy is done,
    /// so comparing the two databases afterwards would report `audit_log` off
    /// by one and be right.
    #[tokio::test]
    async fn a_confirmed_transfer_copies_every_row_and_records_it_on_the_source() {
        let dir = TempDir::new("transfer-confirmed");
        let url = migrated_target(&dir, "target.db").await;
        let source = seeded_source().await;
        let before = fixtures::row_counts(&source).await;

        run_transfer_command(
            &url,
            false,
            false,
            &mut b"y\n".as_slice(),
            SOURCE_URL,
            source.clone(),
        )
        .await
        .expect("the copy should succeed");

        assert_eq!(
            counts(&url).await,
            before,
            "the target holds what was there"
        );

        let (rows, _) = AuditEntry::search(
            &AuditQuery {
                limit: 10,
                ..AuditQuery::default()
            },
            &source,
        )
        .await
        .unwrap();
        let recorded = rows
            .iter()
            .find(|row| row.event == "database_transferred")
            .expect("moving every row is an administrative action");
        assert_eq!(recorded.actor_kind, "cli");
    }

    /// Both output modes copy the same thing, which is all a test can say
    /// about them: nothing here captures stdout.
    #[tokio::test]
    async fn both_output_modes_report_the_same_copy() {
        let dir = TempDir::new("transfer-output");

        for (index, json) in [true, false].into_iter().enumerate() {
            let url = migrated_target(&dir, &format!("target-{index}.db")).await;
            let source = seeded_source().await;
            let before = fixtures::row_counts(&source).await;

            run_transfer_command(&url, json, true, &mut &b""[..], SOURCE_URL, source)
                .await
                .expect("the copy should succeed");

            assert_eq!(counts(&url).await, before, "json = {json}");
        }
    }

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
