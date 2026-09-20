//! Copying every row from one backend to the other.
//!
//! `database.url`'s scheme picks the backend ([ADR
//! 0014](../../../doc/src/dev/adr/0014-postgresql-beside-sqlite.md)), but an
//! operator moving from a SQLite file to a PostgreSQL cluster cannot start
//! empty: the order row is a certificate's only record, so a deployment that
//! left it behind would leave every certificate it has ever issued impossible
//! to revoke. That is the outcome `admin::live_certificates_refusal` exists to
//! prevent, and this module is how the other half of it is avoided.
//!
//! ## What it is not
//!
//! Not a backup, not an upgrade, and **not safe against a running server**.
//! Nothing here can detect one — a worker mid-issuance writes rows this copy
//! has already walked past, and the result is a torn snapshot that looks fine.
//! The caller asks the operator; `acme-proxy transfer` states it in the prompt.
//!
//! ## The manifest, and why it is declared
//!
//! [`TABLES`] names all 140 columns of all 15 tables, in dependency order. It
//! is declared rather than read from the source at copy time because the seam
//! decodes into a *known* Rust type — there is no "read this column as
//! whatever it is", and inventing one would mean deciding at runtime whether
//! SQLite's untyped BLOB is a `bytea` or a `uuid`, which is precisely the
//! ambiguity [`crate::sql::NullKind`] exists to avoid.
//!
//! The declaration's hazard is the one ADR 0003 names for a table rebuild: *a
//! forgotten column is dropped silently*. `the_manifest_names_every_column`
//! answers it the same way, by introspecting the live schema on both backends
//! and refusing a manifest that has drifted from it. **A migration that adds a
//! column must add it here**, and that test is what says so.
//!
//! ## Order, and the two things that are not just rows
//!
//! Tables are copied parents first, because the six foreign keys are enforced
//! on both backends — SQLite's because `open_sqlite` pins `foreign_keys(true)`.
//!
//! `audit_log.id` is the exception to "a row is a row". It is
//! `GENERATED ALWAYS AS IDENTITY` on PostgreSQL, so an explicit id needs
//! `OVERRIDING SYSTEM VALUE`, and the identity sequence has to be advanced
//! afterwards or the first audit row written after the transfer collides. The
//! id is one an operator types (`acme-proxy audit show <id>`), so preserving it
//! is not optional.

use crate::db::Database;
use crate::sql::{self, Dialect, Value};

/// The Rust type a column's values are carried as.
///
/// One per [`Value`] variant that a column can hold. The copy reads
/// `Option<T>` and writes the `Value` back, so a `NULL` keeps the type its
/// column declared and PostgreSQL accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    Uuid,
    Text,
    Blob,
    I64,
    Bool,
}

/// One table, and every column of it.
#[derive(Debug, Clone, Copy)]
pub struct TableSpec {
    /// The table's name, which is also its name in both dialects.
    pub name: &'static str,
    /// The column(s) a batch is ordered and resumed by. Every table has a
    /// primary key; `revocations` is the only composite one.
    pub key: &'static [&'static str],
    /// Every column, in the order the schema declares them.
    pub columns: &'static [(&'static str, ColumnKind)],
}

use ColumnKind::{Blob, Bool, I64, Text, Uuid};

/// Every table, **parents before children**.
///
/// The six foreign keys are `orders → accounts`, `authorizations → orders`,
/// `challenges → authorizations`, `upstream_orders → orders`, and
/// `admin_sessions`/`admin_recovery_codes → admin_users`. `_sqlx_migrations`
/// is deliberately absent: each backend owns its own set and its own
/// checksums, and copying one over the other would make the target's schema
/// claim a history it does not have.
pub const TABLES: &[TableSpec] = &[
    // --- no parents -------------------------------------------------------
    TableSpec {
        name: "nonces",
        key: &["value"],
        columns: &[("value", Text), ("created_at", I64)],
    },
    TableSpec {
        name: "eab_keys",
        key: &["kid"],
        columns: &[
            ("kid", Uuid),
            ("secret", Blob),
            ("label", Text),
            ("profile", Text),
            ("status", Text),
            ("created_at", I64),
        ],
    },
    TableSpec {
        name: "jobs",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("kind", Text),
            ("dedup_key", Text),
            ("payload", Text),
            ("status", Text),
            ("run_at", I64),
            ("attempts", I64),
            ("max_attempts", I64),
            ("deadline", I64),
            ("lease_until", I64),
            ("lease_owner", Text),
            ("last_error", Text),
            ("created_at", I64),
            ("updated_at", I64),
        ],
    },
    TableSpec {
        name: "audit_log",
        key: &["id"],
        columns: &[
            ("id", I64),
            ("created_at", I64),
            ("event", Text),
            ("outcome", Text),
            ("profile", Text),
            ("actor_kind", Text),
            ("actor_id", Text),
            ("account_id", Text),
            ("order_id", Text),
            ("cert_serial", Text),
            ("identifiers", Text),
            ("client_ip", Text),
            ("client_ptr", Text),
            ("user_agent", Text),
            ("request_id", Text),
            ("reason", Text),
            ("detail", Text),
        ],
    },
    TableSpec {
        name: "revocations",
        key: &["issuer", "serial"],
        columns: &[
            ("issuer", Text),
            ("serial", Text),
            ("revoked_at", I64),
            ("reason", I64),
            ("not_after", I64),
        ],
    },
    TableSpec {
        name: "crls",
        key: &["issuer"],
        columns: &[
            ("issuer", Text),
            ("crl_number", I64),
            ("der", Blob),
            ("this_update", I64),
            ("next_update", I64),
        ],
    },
    TableSpec {
        name: "http01_tokens",
        key: &["token"],
        columns: &[
            ("token", Text),
            ("key_authorization", Text),
            ("created_at", I64),
            ("expires_at", I64),
        ],
    },
    TableSpec {
        name: "admin_users",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("username", Text),
            ("password_hash", Text),
            ("status", Text),
            ("totp_secret", Blob),
            ("totp_pending_secret", Blob),
            ("totp_last_step", I64),
            ("created_at", I64),
            ("updated_at", I64),
            ("last_login_at", I64),
            ("role", Text),
            ("contact_email", Text),
            ("known_login_ips", Text),
        ],
    },
    // --- children ---------------------------------------------------------
    TableSpec {
        name: "accounts",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("profile", Text),
            ("pubkey", Blob),
            ("contact", Text),
            ("status", Text),
            ("created_at", I64),
            ("created_ip", Text),
            ("created_ptr", Text),
            ("last_seen_at", I64),
            ("last_seen_ip", Text),
            ("last_seen_ptr", Text),
            ("eab_kid", Uuid),
            ("terms_of_service_agreed", Bool),
        ],
    },
    TableSpec {
        name: "orders",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("profile", Text),
            ("account_id", Uuid),
            ("status", Text),
            ("identifiers", Text),
            ("expires", I64),
            ("not_before", I64),
            ("not_after", I64),
            ("error", Text),
            ("certificate", Text),
            ("replaces", Text),
            ("created_at", I64),
            ("created_ip", Text),
            ("created_ptr", Text),
            ("cert_serial", Text),
            ("cert_pubkey", Blob),
            ("revoked_at", I64),
            ("revocation_reason", I64),
            ("cert_not_after", I64),
        ],
    },
    TableSpec {
        name: "authorizations",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("order_id", Uuid),
            ("identifier", Text),
            ("status", Text),
            ("expires", I64),
            ("created_at", I64),
        ],
    },
    TableSpec {
        name: "challenges",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("authz_id", Uuid),
            ("type", Text),
            ("token", Text),
            ("status", Text),
            ("validated", I64),
            ("created_at", I64),
            ("error", Text),
        ],
    },
    TableSpec {
        name: "upstream_orders",
        key: &["order_id"],
        columns: &[
            ("order_id", Uuid),
            ("upstream_order_url", Text),
            ("upstream_finalize_url", Text),
            ("upstream_certificate_url", Text),
            ("csr_der", Blob),
            ("status", Text),
            ("error", Text),
            ("created_at", I64),
            ("updated_at", I64),
            ("client_ip", Text),
            ("client_ptr", Text),
            ("user_agent", Text),
            ("request_id", Text),
        ],
    },
    TableSpec {
        name: "admin_sessions",
        key: &["token_hash"],
        columns: &[
            ("token_hash", Text),
            ("user_id", Uuid),
            ("csrf_token", Text),
            ("state", Text),
            ("mfa_attempts", I64),
            ("created_at", I64),
            ("expires_at", I64),
            ("last_seen_at", I64),
            ("created_ip", Text),
            ("user_agent", Text),
        ],
    },
    TableSpec {
        name: "admin_recovery_codes",
        key: &["id"],
        columns: &[
            ("id", Uuid),
            ("user_id", Uuid),
            ("code_hash", Text),
            ("created_at", I64),
            ("used_at", I64),
        ],
    },
];

/// How many rows are read and written per round trip.
///
/// The copy streams by key rather than by `OFFSET`, which over a large
/// `audit_log` would be quadratic.
const BATCH: i64 = 1000;

/// What a table contributed, for the caller to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCount {
    pub table: &'static str,
    pub rows: u64,
}

/// What the whole transfer moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReport {
    pub tables: Vec<TableCount>,
}

impl TransferReport {
    /// Every row copied, across every table.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.tables.iter().map(|table| table.rows).sum()
    }
}

/// The tables of `database` that already hold rows.
///
/// What a caller checks before offering to copy into it. Returning the names
/// rather than a bool is deliberate: "the target is not empty" is not a
/// message an operator can act on, and "`accounts` holds 4 rows" is.
pub async fn non_empty_tables(database: &Database) -> Result<Vec<TableCount>, sqlx::Error> {
    let mut found = Vec::new();
    for table in TABLES {
        let rows = count(table.name, database).await?;
        if rows > 0 {
            found.push(TableCount {
                table: table.name,
                rows,
            });
        }
    }
    Ok(found)
}

/// How many rows `table` holds.
async fn count(table: &'static str, database: &Database) -> Result<u64, sqlx::Error> {
    let sql = format!("SELECT COUNT(*) FROM {table};");
    let count: i64 = sql::query(sqlx::AssertSqlSafe(sql))
        .fetch_one(database)
        .await?
        .try_get(0usize)?;
    Ok(u64::try_from(count).unwrap_or(0))
}

impl Database {
    /// Copies every row of this database into `target`.
    ///
    /// The whole copy is **one transaction on the target**, so a failure
    /// anywhere leaves it exactly as it was rather than half-populated. The
    /// source is only read.
    ///
    /// The caller is responsible for the two things this cannot check: that
    /// `target`'s schema is current (ask [`Database::pending_migrations`]) and
    /// that nothing is writing to the source. See the module doc.
    pub async fn transfer_to(&self, target: &Database) -> Result<TransferReport, sqlx::Error> {
        let mut tx = target.write_transaction().await?;
        let mut tables = Vec::with_capacity(TABLES.len());

        for spec in TABLES {
            let rows = copy_table(spec, self, &mut tx).await?;
            tables.push(TableCount {
                table: spec.name,
                rows,
            });
        }

        // The identity sequence has to catch up with the ids just inserted, or
        // the first audit row written after the transfer collides on the
        // primary key. Inside the transaction, so a rollback takes it too.
        if target.dialect() == Dialect::Postgres {
            sql::query(
                "SELECT setval(pg_get_serial_sequence('audit_log', 'id'), \
                 (SELECT COALESCE(MAX(id), 1) FROM audit_log));",
            )
            .fetch_one(tx.conn())
            .await?;
        }

        tx.commit().await?;
        Ok(TransferReport { tables })
    }
}

/// Reads `spec` from `source` in key order and writes it to `tx`.
async fn copy_table(
    spec: &TableSpec,
    source: &Database,
    tx: &mut crate::db::Tx,
) -> Result<u64, sqlx::Error> {
    let names = spec
        .columns
        .iter()
        .map(|(name, _)| quote(name))
        .collect::<Vec<_>>()
        .join(", ");
    let order = spec
        .key
        .iter()
        .map(|name| quote(name))
        .collect::<Vec<_>>()
        .join(", ");

    let mut after: Option<Vec<Value>> = None;
    let mut copied = 0u64;

    loop {
        let batch = read_batch(spec, source, &names, &order, after.as_deref()).await?;
        if batch.is_empty() {
            return Ok(copied);
        }

        after = Some(key_of(spec, batch.last().expect("the batch is not empty")));
        copied += batch.len() as u64;
        write_batch(spec, &names, &batch, tx).await?;

        if batch.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            return Ok(copied);
        }
    }
}

/// One batch of rows, resumed after `after`'s key.
///
/// Keyset pagination rather than `LIMIT`/`OFFSET`: the tables this walks
/// include `audit_log`, where an offset scan would re-read everything already
/// copied on every batch. `(a, b) > (?, ?)` row comparison is the one spelling
/// both dialects accept for the composite key.
async fn read_batch(
    spec: &TableSpec,
    source: &Database,
    names: &str,
    order: &str,
    after: Option<&[Value]>,
) -> Result<Vec<Vec<Value>>, sqlx::Error> {
    let table = spec.name;
    let where_clause = match after {
        None => String::new(),
        Some(_) => {
            let markers = vec!["?"; spec.key.len()].join(", ");
            match spec.key.len() {
                1 => format!(" WHERE {order} > {markers}"),
                _ => format!(" WHERE ({order}) > ({markers})"),
            }
        }
    };
    let sql = format!("SELECT {names} FROM {table}{where_clause} ORDER BY {order} LIMIT {BATCH};");

    let mut query = sql::query(sqlx::AssertSqlSafe(sql));
    for value in after.unwrap_or(&[]) {
        query = query.bind(value.clone());
    }

    let rows = query.fetch_all(source).await?;
    rows.iter()
        .map(|row| {
            spec.columns
                .iter()
                .map(|(name, kind)| read(row, name, *kind))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Writes one batch as a single multi-row `INSERT`.
async fn write_batch(
    spec: &TableSpec,
    names: &str,
    batch: &[Vec<Value>],
    tx: &mut crate::db::Tx,
) -> Result<(), sqlx::Error> {
    let table = spec.name;
    let row = format!("({})", vec!["?"; spec.columns.len()].join(", "));
    let values = vec![row; batch.len()].join(", ");

    // `audit_log.id` is `GENERATED ALWAYS AS IDENTITY` on PostgreSQL, which
    // refuses an explicit id without this. The id is one an operator types, so
    // it is not the server's to reassign.
    let overriding = match (tx.conn().dialect(), table) {
        (Dialect::Postgres, "audit_log") => " OVERRIDING SYSTEM VALUE",
        _ => "",
    };

    let sql = format!("INSERT INTO {table} ({names}){overriding} VALUES {values};");
    let mut query = sql::query(sqlx::AssertSqlSafe(sql));
    for row in batch {
        for value in row {
            query = query.bind(value.clone());
        }
    }
    query.execute(tx.conn()).await?;
    Ok(())
}

/// The key columns of one already-read row, for the next batch to resume from.
fn key_of(spec: &TableSpec, row: &[Value]) -> Vec<Value> {
    spec.key
        .iter()
        .map(|key| {
            let index = spec
                .columns
                .iter()
                .position(|(name, _)| name == key)
                .expect("a key column is one of the table's columns");
            row[index].clone()
        })
        .collect()
}

/// Reads one column at the type its [`ColumnKind`] declares.
fn read(row: &sql::Row, name: &str, kind: ColumnKind) -> Result<Value, sqlx::Error> {
    Ok(match kind {
        ColumnKind::Uuid => match row.try_get::<Option<uuid::Uuid>>(name)? {
            Some(value) => Value::Uuid(value),
            None => Value::Null(sql::NullKind::Uuid),
        },
        ColumnKind::Text => match row.try_get::<Option<String>>(name)? {
            Some(value) => Value::Text(value),
            None => Value::Null(sql::NullKind::Text),
        },
        ColumnKind::Blob => match row.try_get::<Option<Vec<u8>>>(name)? {
            Some(value) => Value::Blob(value),
            None => Value::Null(sql::NullKind::Blob),
        },
        ColumnKind::I64 => match row.try_get::<Option<i64>>(name)? {
            Some(value) => Value::I64(value),
            None => Value::Null(sql::NullKind::I64),
        },
        ColumnKind::Bool => match row.try_get::<Option<bool>>(name)? {
            Some(value) => Value::Bool(value),
            None => Value::Null(sql::NullKind::Bool),
        },
    })
}

/// Quotes an identifier, in the one spelling both dialects share.
///
/// `challenges.type` and `jobs.kind` are not reserved in either, but the copy
/// builds its own SQL and a column named by the schema should not have to be
/// checked against two keyword lists.
fn quote(name: &str) -> String {
    format!("\"{name}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every column of every table is in the manifest, and nothing else is.
    ///
    /// The guard the whole module rests on. A manifest that has fallen behind
    /// the schema does not fail — it *succeeds*, having silently left a column
    /// behind, which is ADR 0003's stated hazard for a table rebuild wearing
    /// different clothes. So the manifest is checked against the live schema
    /// rather than trusted, on whichever backend the test is running.
    ///
    /// Add a migration that adds a column and this is what tells you the copy
    /// needs to know about it.
    #[tokio::test]
    async fn the_manifest_names_every_column() {
        let database = Database::connect_for_test().await.unwrap();

        for spec in TABLES {
            let declared: Vec<&str> = spec.columns.iter().map(|(name, _)| *name).collect();
            let live = live_columns(&database, spec.name).await;
            assert_eq!(
                live, declared,
                "the manifest for `{}` has drifted from the schema; a column \
                 missing here is a column the transfer would drop",
                spec.name
            );
        }
    }

    /// And every table is in the manifest.
    ///
    /// The column check above only looks at tables the manifest already names,
    /// so a whole new table would slip past it.
    #[tokio::test]
    async fn the_manifest_names_every_table() {
        let database = Database::connect_for_test().await.unwrap();

        let mut live = live_tables(&database).await;
        let mut declared: Vec<String> = TABLES.iter().map(|s| s.name.to_string()).collect();
        live.sort();
        declared.sort();

        assert_eq!(
            live, declared,
            "every table but `_sqlx_migrations` is copied; one missing here is \
             one the transfer would leave behind"
        );
    }

    /// A parent is always copied before its children.
    ///
    /// Both backends enforce the six foreign keys, so an order inserted before
    /// its account fails. Checked against the manifest's own order rather than
    /// the schema's, since that order is the thing under test.
    #[test]
    fn the_manifest_is_in_dependency_order() {
        const EDGES: &[(&str, &str)] = &[
            ("orders", "accounts"),
            ("authorizations", "orders"),
            ("challenges", "authorizations"),
            ("upstream_orders", "orders"),
            ("admin_sessions", "admin_users"),
            ("admin_recovery_codes", "admin_users"),
        ];

        let position = |name: &str| {
            TABLES
                .iter()
                .position(|spec| spec.name == name)
                .unwrap_or_else(|| panic!("{name} should be in the manifest"))
        };

        for (child, parent) in EDGES {
            assert!(
                position(parent) < position(child),
                "{parent} must be copied before {child}, or the foreign key refuses the row"
            );
        }
    }

    /// The key of every table is one of its own columns.
    ///
    /// `key_of` indexes the row by the key's position in `columns`, so a key
    /// naming a column the manifest does not carry would panic mid-copy rather
    /// than here.
    #[test]
    fn every_key_is_a_column_of_its_table() {
        for spec in TABLES {
            assert!(!spec.key.is_empty(), "{} declares no key", spec.name);
            for key in spec.key {
                assert!(
                    spec.columns.iter().any(|(name, _)| name == key),
                    "{}.{key} is a key but not a column",
                    spec.name
                );
            }
        }
    }

    /// The tables the live schema holds, `_sqlx_migrations` aside.
    async fn live_tables(database: &Database) -> Vec<String> {
        let sql = match database.dialect() {
            Dialect::Sqlite => {
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations';"
            }
            Dialect::Postgres => {
                "SELECT table_name FROM information_schema.tables \
                 WHERE table_schema = ANY (current_schemas(false)) \
                 AND table_type = 'BASE TABLE' AND table_name <> '_sqlx_migrations';"
            }
        };
        sql::query(sql)
            .fetch_all(database)
            .await
            .expect("the catalog should be readable")
            .iter()
            .map(|row| row.try_get::<String>(0usize).expect("a name"))
            .collect()
    }

    /// The columns of `table`, in declaration order.
    async fn live_columns(database: &Database, table: &str) -> Vec<String> {
        match database.dialect() {
            Dialect::Sqlite => sql::query(sqlx::AssertSqlSafe(format!(
                "SELECT name FROM pragma_table_info('{table}');"
            )))
            .fetch_all(database)
            .await
            .expect("the table should exist")
            .iter()
            .map(|row| row.try_get::<String>(0usize).expect("a name"))
            .collect(),
            Dialect::Postgres => sql::query(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = ANY (current_schemas(false)) AND table_name = ? \
                 ORDER BY ordinal_position;",
            )
            .bind(table)
            .fetch_all(database)
            .await
            .expect("the table should exist")
            .iter()
            .map(|row| row.try_get::<String>(0usize).expect("a name"))
            .collect(),
        }
    }
}
