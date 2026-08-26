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
            let columns: Vec<(String, String)> =
                sqlx::query_as("SELECT name, type FROM pragma_table_info(?);")
                    .bind(table)
                    .fetch_all(&database.pool)
                    .await
                    .unwrap();

            let declared = columns
                .iter()
                .find(|(name, _)| name == column)
                .map(|(_, declared)| declared.as_str())
                .unwrap_or_else(|| panic!("no column {table}.{column}"));

            assert_eq!(
                declared, expected,
                "{table}.{column} declares a width the value no longer has"
            );
        }
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
