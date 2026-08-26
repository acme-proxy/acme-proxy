use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Error, Pool, Sqlite, SqlitePool, migrate::MigrateDatabase};
use tracing::{error, info};

static MIGRATOR: Migrator = sqlx::migrate!(); // defaults to "./migrations"

pub struct Database {
    pub pool: Pool<Sqlite>,
}

impl Database {
    /// Connects to the `SQLite` database at `url`, creating the file if it does
    /// not exist yet, then runs the embedded migrations.
    pub async fn connect(url: &str) -> Result<Database, Error> {
        if !Sqlite::database_exists(url).await.unwrap_or(false) {
            info!(event = "db_creation_started", outcome = "progress", database_url = %url);
            Sqlite::create_database(url).await?;
            info!(event = "db_creation_completed", outcome = "success", database_url = %url);
        }

        let options = SqliteConnectOptions::from_str(url)?
            // The schema's `ON DELETE CASCADE` rules only bite when foreign keys
            // are enforced. sqlx enables them by default, but the schema depends
            // on it, so state it here rather than inherit it.
            .foreign_keys(true)
            // Every response writes a nonce row. Under the default rollback
            // journal a write takes an exclusive lock on the whole database, so
            // the pool serializes; WAL lets readers continue during a write.
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePool::connect_with(options).await?;

        run_migrations(&pool).await?;

        Ok(Database { pool })
    }

    /// Builds a throwaway in-memory database with migrations applied. Pinned to
    /// a single connection so the whole test shares one in-memory database
    /// (each `SQLite` connection otherwise gets its own).
    pub async fn connect_in_memory() -> Result<Database, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true))
            .await?;

        run_migrations(&pool).await?;

        Ok(Database { pool })
    }
}

async fn run_migrations(pool: &Pool<Sqlite>) -> Result<(), Error> {
    MIGRATOR.run(pool).await.map_err(|error| {
        // Startup-only, and the caller exits on error — but a `Result`-returning
        // function should not decide that on its own by panicking.
        error!(event = "db_migration_failed", outcome = "failure", error = %error);
        Error::Migrate(Box::new(error))
    })?;
    info!(event = "db_migration_completed", outcome = "success");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random::random_token;

    #[tokio::test]
    async fn connect_creates_file_and_runs_migrations() {
        // A unique temp path so the "database does not exist → create it" branch
        // runs (the in-memory helper never exercises it).
        let file =
            std::env::temp_dir().join(format!("acme-proxy-test-{}.db", uuid::Uuid::now_v7()));
        let url = format!("sqlite://{}", file.display());

        let database = Database::connect(&url).await.unwrap();

        // Migrations applied: the `nonces` table exists and is queryable.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nonces;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        // WAL and foreign-key enforcement are on: the schema's CASCADE rules
        // depend on the latter.
        let journal: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);

        database.pool.close().await;
        // WAL leaves sidecar files behind.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", file.display()));
        }
    }

    /// Every foreign key is indexed. Without these, each child lookup is a full
    /// table scan — `Authorization::find_by_order` runs on every order read.
    #[tokio::test]
    async fn foreign_keys_and_the_nonce_sweep_are_indexed() {
        let database = Database::connect_in_memory().await.unwrap();
        let names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index';")
                .fetch_all(&database.pool)
                .await
                .unwrap();

        for expected in [
            "idx_orders_account_id",
            "idx_authorizations_order",
            "idx_challenges_authz",
            "idx_nonces_created_at",
            "idx_orders_cert_serial",
            "idx_orders_replaces_claim",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing index {expected}; have {names:?}"
            );
        }
    }

    /// The declared width of every column holding a [`random_token`] value must
    /// match what that function actually produces.
    ///
    /// `nonces.value` was declared `VARCHAR(36)` — accurate for the UUID v4 it
    /// held until the nonce moved to the CSPRNG, and false from that moment on.
    /// It stayed false because SQLite gives the column TEXT affinity and
    /// enforces no length, so nothing anywhere could notice. This is what
    /// notices: change `TOKEN_BYTES` and the failure lands here, beside the
    /// migration that has to be written.
    #[tokio::test]
    async fn declared_token_widths_match_random_token() {
        let database = Database::connect_in_memory().await.unwrap();
        let expected = format!("VARCHAR({})", random_token().len());

        for (table, column) in [("nonces", "value"), ("challenges", "token")] {
            assert_eq!(
                declared_type(&database, table, column).await,
                expected,
                "{table}.{column} declares a width the value no longer has"
            );
        }
    }

    /// The declared type of every column holding a row id.
    ///
    /// The [`random_token`] twin above, for the other family of values the
    /// schema declares a type for. Ids are the 16 bytes of a UUID
    /// ([`crate::sqlite::id`]), stored as a BLOB rather than as the 36
    /// characters of its rendering, and this is what notices a column that went
    /// back to text — or a new table added with a `VARCHAR(36)` id out of
    /// habit.
    ///
    /// It matters for the reason the widths do: SQLite gives a declared type an
    /// affinity and enforces nothing, where the PostgreSQL set these
    /// declarations will be transcribed into (`TODO.md`) has a native `uuid`
    /// and does enforce it. `nonces.value` is what a stale declaration looks
    /// like once nothing can notice it.
    #[tokio::test]
    async fn every_id_column_is_declared_a_blob() {
        let database = Database::connect_in_memory().await.unwrap();

        let minted = crate::sqlite::id::mint();
        assert_eq!(
            minted.get_version_num(),
            7,
            "ids are UUID v7 (RFC 9562 §5.7)"
        );
        assert_eq!(minted.as_bytes().len(), 16, "which is what a column holds");

        for (table, column) in [
            ("accounts", "id"),
            ("accounts", "eab_kid"),
            ("orders", "id"),
            ("orders", "account_id"),
            ("authorizations", "id"),
            ("authorizations", "order_id"),
            ("challenges", "id"),
            ("challenges", "authz_id"),
            ("eab_keys", "kid"),
            ("upstream_orders", "order_id"),
            ("admin_users", "id"),
            ("admin_sessions", "user_id"),
            ("admin_recovery_codes", "id"),
            ("admin_recovery_codes", "user_id"),
            ("jobs", "id"),
        ] {
            assert_eq!(
                declared_type(&database, table, column).await,
                "BLOB",
                "{table}.{column} holds a row id"
            );
        }

        // Asserted by name so neither reads as an oversight later. `audit_log`
        // has no foreign keys on purpose — its rows outlive their subjects, so
        // these two name a row that may be gone rather than pointing at one,
        // and they sit beside `actor_id` and `request_id`, which are free-form.
        for column in ["account_id", "order_id"] {
            assert_eq!(
                declared_type(&database, "audit_log", column).await,
                "VARCHAR(36)",
                "audit_log.{column} is deliberately still text"
            );
        }
    }

    /// Version of `20260827120000_uuid_ids_as_blobs.sql`, the migration that
    /// converted every id column from its 36-character rendering to the 16
    /// bytes behind it.
    const BLOB_IDS: i64 = 20_260_827_120_000;

    /// Every row survives the conversion to BLOB ids, with its id intact and
    /// its foreign keys still resolving.
    ///
    /// This is the only thing standing between a mistyped column list and
    /// silent data loss, and there are two ways to lose a row there. An
    /// `INSERT ... SELECT` drops any column it does not name, quietly. And
    /// `DROP TABLE` under `foreign_keys = ON` fires `ON DELETE CASCADE` into
    /// every child, so a rebuild that drops a parent while a rebuilt child
    /// already references it empties the child — with no error, and nothing
    /// else in this suite would notice, since a fresh database has no rows to
    /// lose.
    ///
    /// So the fixture is a database at the migration *before* that one, seeded
    /// through raw SQL with a v4 id in every column that was about to move,
    /// including the nullable `accounts.eab_kid` (where an unconvertible value
    /// would become `NULL` rather than failing a `NOT NULL`) and the columns
    /// deliberately left as text beside them.
    #[tokio::test]
    async fn the_blob_migration_preserves_every_row() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::from_str("sqlite::memory:")
                    .unwrap()
                    .foreign_keys(true),
            )
            .await
            .unwrap();

        let mut converted = None;
        for migration in MIGRATOR.iter() {
            if migration.version == BLOB_IDS {
                converted = Some(migration);
                break;
            }
            sqlx::raw_sql(migration.sql.clone())
                .execute(&pool)
                .await
                .unwrap();
        }
        let converted = converted.expect("the id migration is in the embedded set");

        sqlx::raw_sql(SEED_V4_ROWS).execute(&pool).await.unwrap();
        sqlx::raw_sql(converted.sql.clone())
            .execute(&pool)
            .await
            .unwrap();

        // Every table kept its row, and every id is now the 16 bytes of the v4
        // it held. `accounts.eab_kid` is the nullable one, and carries a value
        // here for exactly that reason.
        let account: (Vec<u8>, Option<Vec<u8>>) =
            sqlx::query_as("SELECT id, eab_kid FROM accounts;")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            uuid::Uuid::from_slice(&account.0).unwrap().to_string(),
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            uuid::Uuid::from_slice(&account.1.expect("eab_kid survived"))
                .unwrap()
                .to_string(),
            "99999999-9999-4999-8999-999999999999"
        );

        for table in [
            "orders",
            "authorizations",
            "challenges",
            "upstream_orders",
            "eab_keys",
            "admin_users",
            "admin_sessions",
            "admin_recovery_codes",
            "jobs",
            "audit_log",
        ] {
            // `AssertSqlSafe` for `Job::claim_next`'s reason: sqlx refuses a
            // query string that is not `'static`, and the table name here comes
            // from the literal list above rather than from any input.
            let rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM {table};"
            )))
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(rows, 1, "{table} lost its row");
        }

        // The foreign keys resolve across the conversion — a join is what
        // proves both sides were converted the same way, where two counts
        // would pass even if they had not been.
        let joined: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM challenges c \
             JOIN authorizations a ON a.id = c.authz_id \
             JOIN orders o ON o.id = a.order_id \
             JOIN accounts acct ON acct.id = o.account_id;",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(joined, 1, "the account → challenge chain no longer joins");

        let violations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(violations, 0);

        // The columns that deliberately did not move still hold their text.
        let replaces: String = sqlx::query_scalar("SELECT replaces FROM orders;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(replaces, "aaa.bbb", "an ARI certID is not one of our ids");
        let audited: String = sqlx::query_scalar("SELECT account_id FROM audit_log;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            audited, "11111111-1111-4111-8111-111111111111",
            "audit_log names a row that may be gone, and stays text"
        );

        // And the CASCADE the staging detour exists to protect is still wired:
        // it must survive the rebuild, not merely be absent during it.
        sqlx::raw_sql("DELETE FROM accounts;")
            .execute(&pool)
            .await
            .unwrap();
        for table in ["orders", "authorizations", "challenges"] {
            // `AssertSqlSafe` for `Job::claim_next`'s reason: sqlx refuses a
            // query string that is not `'static`, and the table name here comes
            // from the literal list above rather than from any input.
            let rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM {table};"
            )))
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(rows, 0, "deleting the account did not cascade into {table}");
        }
    }

    /// One row per table, each carrying a UUID v4 in every id column — the
    /// shape a database written before `sqlite::id` existed holds.
    const SEED_V4_ROWS: &str = "\
INSERT INTO accounts (id, profile, pubkey, contact, status, created_at, eab_kid) VALUES
  ('11111111-1111-4111-8111-111111111111', 'default', X'AA', '[]', 'valid', 100,
   '99999999-9999-4999-8999-999999999999');
INSERT INTO eab_keys (kid, secret, label, profile, status, created_at) VALUES
  ('99999999-9999-4999-8999-999999999999', X'CC', 'lab', NULL, 'active', 99);
INSERT INTO orders (id, profile, account_id, status, identifiers, expires, created_at, replaces)
VALUES
  ('33333333-3333-4333-8333-333333333333', 'default',
   '11111111-1111-4111-8111-111111111111', 'pending', '[]', 200, 102, 'aaa.bbb');
INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) VALUES
  ('44444444-4444-4444-8444-444444444444', '33333333-3333-4333-8333-333333333333',
   '{\"type\":\"dns\",\"value\":\"a.example\"}', 'pending', 200, 103);
INSERT INTO challenges (id, authz_id, type, token, status, created_at, error) VALUES
  ('55555555-5555-4555-8555-555555555555', '44444444-4444-4444-8444-444444444444',
   'http-01', 'tok', 'pending', 104, '{\"e\":1}');
INSERT INTO upstream_orders (order_id, upstream_order_url, csr_der, status, created_at,
                             updated_at, request_id) VALUES
  ('33333333-3333-4333-8333-333333333333', 'https://up/o', X'DD', 'processing', 105, 105,
   'req-abc');
INSERT INTO admin_users (id, username, password_hash, status, created_at, updated_at) VALUES
  ('66666666-6666-4666-8666-666666666666', 'root', 'h', 'active', 106, 106);
INSERT INTO admin_sessions (token_hash, user_id, csrf_token, state, created_at, expires_at,
                            last_seen_at) VALUES
  ('deadbeef', '66666666-6666-4666-8666-666666666666', 'csrf', 'active', 107, 999, 107);
INSERT INTO admin_recovery_codes (id, user_id, code_hash, created_at) VALUES
  ('77777777-7777-4777-8777-777777777777', '66666666-6666-4666-8666-666666666666', 'ch', 108);
INSERT INTO jobs (id, kind, dedup_key, payload, status, run_at, max_attempts, created_at,
                  updated_at, lease_owner) VALUES
  ('88888888-8888-4888-8888-888888888888', 'k', 'dk', '{}', 'ready', 109, 5, 109, 109,
   'runner-1');
INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind, account_id, order_id)
VALUES
  (110, 'certificate_issued', 'success', 'default', 'acme',
   '11111111-1111-4111-8111-111111111111', '33333333-3333-4333-8333-333333333333');
";

    /// The `pragma_table_info` lookup both declaration guards above run.
    async fn declared_type(database: &Database, table: &str, column: &str) -> String {
        let columns: Vec<(String, String)> =
            sqlx::query_as("SELECT name, type FROM pragma_table_info(?);")
                .bind(table)
                .fetch_all(&database.pool)
                .await
                .unwrap();

        columns
            .into_iter()
            .find(|(name, _)| name == column)
            .map(|(_, declared)| declared)
            .unwrap_or_else(|| panic!("no column {table}.{column}"))
    }

    /// RFC 9773 §5's "not already been marked as replaced" holds even when two
    /// newOrder requests race: `check_replaces` reads in one transaction and the
    /// order is inserted in another, so the database is what actually decides.
    ///
    /// The partial predicate matters as much as the uniqueness — an order that
    /// falls to `invalid` has to free its predecessor, or a failed replacement
    /// would block every retry for good.
    #[tokio::test]
    async fn one_predecessor_can_only_be_claimed_by_one_live_order() {
        let database = Database::connect_in_memory().await.unwrap();
        let cert_id = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        let insert = |id: &'static str, status: &'static str| {
            let pool = database.pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, \
                     replaces, created_at) VALUES (?, 'default', 'acct', ?, '[]', 0, ?, 0);",
                )
                .bind(id)
                .bind(status)
                .bind(cert_id)
                .execute(&pool)
                .await
            }
        };

        insert("first", "pending").await.unwrap();

        // A second live claim on the same predecessor is refused, and the error
        // names the offending column — which is what `is_replaces_conflict`
        // matches on to tell this apart from the authorization and challenge
        // constraints inserted in the same transaction. SQLite reports the
        // columns of a partial unique index, never the index's own name, so
        // this assertion is what keeps that matcher honest.
        let error = insert("second", "pending").await.unwrap_err();
        match &error {
            sqlx::Error::Database(db) => {
                assert!(db.is_unique_violation(), "got {error}");
                assert!(
                    db.message().contains("orders.replaces"),
                    "the violation must name the column, got {:?}",
                    db.message()
                );
            }
            other => panic!("expected a database error, got {other}"),
        }

        // An `invalid` order is outside the index, so a retry after a failed
        // replacement is accepted.
        insert("third", "invalid").await.unwrap();

        // And once the first claim goes invalid, the predecessor is free again.
        sqlx::query("UPDATE orders SET status = 'invalid' WHERE id = 'first';")
            .execute(&database.pool)
            .await
            .unwrap();
        insert("fourth", "pending").await.unwrap();
    }

    /// The status columns are pinned to their state machines, so a typo in one
    /// of the raw-string transitions scattered across the models fails loudly
    /// rather than parking a row in an unreachable state.
    #[tokio::test]
    async fn status_columns_reject_values_outside_the_state_machine() {
        let database = Database::connect_in_memory().await.unwrap();

        let result = sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('a', 'default', X'00', '[]', 'definitely-not-a-status', 0);",
        )
        .execute(&database.pool)
        .await;
        assert!(result.is_err(), "an unknown account status must be refused");

        // And a legitimate one is accepted.
        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('a', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
    }

    /// Deleting a parent takes its children with it. Before this the constraints
    /// had no referential action at all, so an account could never be deleted —
    /// which blocked any retention work.
    #[tokio::test]
    async fn deleting_an_account_cascades_to_its_orders() {
        let database = Database::connect_in_memory().await.unwrap();

        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, created_at) \
             VALUES ('ord', 'default', 'acct', 'pending', '[]', 0, 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) \
             VALUES ('az', 'ord', '{}', 'pending', 0, 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO challenges (id, authz_id, type, token, status, created_at) \
             VALUES ('ch', 'az', 'http-01', 't', 'pending', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM accounts WHERE id = 'acct';")
            .execute(&database.pool)
            .await
            .unwrap();

        for (table, query) in [
            ("orders", "SELECT COUNT(*) FROM orders;"),
            ("authorizations", "SELECT COUNT(*) FROM authorizations;"),
            ("challenges", "SELECT COUNT(*) FROM challenges;"),
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .fetch_one(&database.pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "{table} should have been cascaded away");
        }
    }

    /// An order cannot carry two authorizations for the same identifier.
    #[tokio::test]
    async fn an_order_cannot_have_duplicate_authorizations_for_one_identifier() {
        let database = Database::connect_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, created_at) \
             VALUES ('ord', 'default', 'acct', 'pending', '[]', 0, 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        let insert = |id: &'static str| {
            sqlx::query(
                "INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) \
                 VALUES (?, 'ord', '{\"type\":\"dns\",\"value\":\"example.com\"}', 'pending', 0, 0);",
            )
            .bind(id)
            .execute(&database.pool)
        };

        insert("az1").await.unwrap();
        assert!(
            insert("az2").await.is_err(),
            "a second authorization for the same identifier must be refused"
        );
    }
}
