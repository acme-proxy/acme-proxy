//! The connection, and the only holder of the pool.
//!
//! **Opening a database never migrates it.** [`Database::open`] connects;
//! [`Database::migrate`] applies the embedded set and
//! [`Database::pending_migrations`] reports what is unapplied. Applying the
//! schema is a named act with two callers — `acme-proxy migrate`/`init`, and a
//! `serve` running the `worker` role — rather than a side effect of opening a
//! file, since two processes starting together would otherwise race
//! `MIGRATOR.run` with no lock between them. `tests/layering.rs`
//! (`only_the_schema_owners_apply_migrations`) keeps it at two callers.
//!
//! **The pool is private to this crate.** A caller elsewhere opens a [`Tx`]
//! through [`Database::transaction`] or reads [`Database::pool_stats`];
//! [`Database::raw_pool`] exists for test fixtures only, and `tests/layering.rs`
//! fails when production code calls it. [`Database::close`] is how the failure
//! suites simulate an outage.
//!
//! Two pragmas are pinned on every connection: `foreign_keys` (the schema's
//! `ON DELETE CASCADE` depends on it) and `journal_mode = WAL` (every ACME
//! response writes a nonce row, and the rollback journal takes a database-wide
//! lock per write).
//!
//! The tests at the bottom of this file are the migration guards: every
//! rebuild's row preservation, and every declared width pinned to the constant
//! it follows.

use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Error, Pool, Sqlite, SqlitePool, migrate::MigrateDatabase};
use tracing::{error, info};

use crate::sql::{Dialect, Exec};

/// The SQLite set, frozen and append-only since 0.1.0.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The PostgreSQL set. A schema of its own rather than a transcription: the
/// SQLite files carry table rebuilds that exist only because SQLite cannot add
/// a `CHECK`, and replaying those here would be archaeology rather than a
/// schema. Append-only from its own first release, on the same rule.
static PG_MIGRATOR: Migrator = sqlx::migrate!("./migrations-postgres");

/// The connection pool, and the only way to reach it.
///
/// The pool is private to this crate: everything else goes through a table
/// module, [`Database::transaction`] or [`Database::pool_stats`]. That is what
/// keeps SQL — and the dialect it is written in — in one crate.
pub enum Database {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

/// One database transaction, handed out by [`Database::transaction`].
///
/// A wrapper rather than `sqlx::Transaction` itself, so the pool it is drawn
/// from stays this crate's business: a caller outside it can open a
/// transaction without being able to reach the pool. It derefs to the
/// connection, so `tx.conn()` is what every table method taking an executor or a
/// `&mut SqliteConnection` is handed. Dropped without [`Tx::commit`], it rolls
/// back — `sqlx`'s own rule, unchanged.
pub enum Tx {
    Sqlite(sqlx::Transaction<'static, Sqlite>),
    Postgres(sqlx::Transaction<'static, Postgres>),
}

impl Tx {
    /// Commits the transaction.
    pub async fn commit(self) -> Result<(), Error> {
        match self {
            Tx::Sqlite(tx) => tx.commit().await,
            Tx::Postgres(tx) => tx.commit().await,
        }
    }

    /// The connection underneath, for a statement to run on.
    ///
    /// Replaces the `Deref` this used to carry: the target was
    /// `SqliteConnection`, which is exactly the dialect this enum exists to
    /// stop naming. `tx.conn()` is what `tx.conn()` used to be.
    pub fn conn(&mut self) -> Exec<'_> {
        match self {
            Tx::Sqlite(tx) => Exec::SqliteConn(tx),
            Tx::Postgres(tx) => Exec::PgConn(tx),
        }
    }
}

/// The pool's occupancy at one instant, for the metrics gauge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStats {
    /// Every connection the pool currently holds.
    pub size: u32,
    /// Those of them not checked out.
    pub idle: usize,
}

impl Database {
    /// Which dialect this database speaks.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        match self {
            Database::Sqlite(_) => Dialect::Sqlite,
            Database::Postgres(_) => Dialect::Postgres,
        }
    }

    /// This database as a target for one statement.
    #[must_use]
    pub fn exec(&self) -> Exec<'_> {
        match self {
            Database::Sqlite(pool) => Exec::SqlitePool(pool),
            Database::Postgres(pool) => Exec::PgPool(pool),
        }
    }

    /// Begins a transaction.
    pub async fn transaction(&self) -> Result<Tx, Error> {
        Ok(match self {
            Database::Sqlite(pool) => Tx::Sqlite(pool.begin().await?),
            Database::Postgres(pool) => Tx::Postgres(pool.begin().await?),
        })
    }

    /// Begins a transaction that holds the **write lock from its first
    /// statement** (`BEGIN IMMEDIATE`), for one that reads and then writes on
    /// what it read while another process may be writing.
    ///
    /// A plain [`transaction`](Self::transaction) is deferred: it takes a read
    /// snapshot at its first `SELECT` and asks for the write lock only at its
    /// first write. In WAL mode, if another connection committed in between,
    /// that upgrade fails at once with `SQLITE_BUSY_SNAPSHOT` — `busy_timeout`
    /// cannot help, since waiting would not make the snapshot current. Taking
    /// the lock up front makes the transaction wait its turn under
    /// `busy_timeout` instead, and then read what it writes against.
    pub async fn write_transaction(&self) -> Result<Tx, Error> {
        Ok(match self {
            Database::Sqlite(pool) => Tx::Sqlite(pool.begin_with("BEGIN IMMEDIATE").await?),
            // PostgreSQL needs nothing here. The hazard this exists for is a
            // WAL snapshot going stale between a read and the write that rests
            // on it, which `SQLITE_BUSY_SNAPSHOT` reports and `busy_timeout`
            // cannot help. Row-level locking means the same read-then-write
            // either blocks or re-evaluates against what it locked.
            Database::Postgres(pool) => Tx::Postgres(pool.begin().await?),
        })
    }

    /// The pool's size and idle count, read now rather than tracked.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        match self {
            Database::Sqlite(pool) => PoolStats {
                size: pool.size(),
                idle: pool.num_idle(),
            },
            Database::Postgres(pool) => PoolStats {
                size: pool.size(),
                idle: pool.num_idle(),
            },
        }
    }

    /// The pool itself, **for test fixtures only**: raw SQL that sets up or
    /// inspects state no table module writes or reads (a back-dated row, a
    /// forced constraint violation).
    ///
    /// Public because the integration tests under `tests/` are another crate.
    /// Production code must not call it — `tests/layering.rs` fails the build
    /// when it appears outside `crates/store/` and outside a `#[cfg(test)]`
    /// module.
    #[doc(hidden)]
    #[must_use]
    pub fn raw_pool(&self) -> &Pool<Sqlite> {
        match self {
            Database::Sqlite(pool) => pool,
            Database::Postgres(_) => {
                panic!("raw_pool() is a SQLite test fixture; this database is PostgreSQL")
            }
        }
    }

    /// Closes the pool: every later query fails with `PoolClosed`.
    ///
    /// Waits for checked-out connections to be returned. Also how a test
    /// simulates the database going away underneath a running server.
    pub async fn close(&self) {
        match self {
            Database::Sqlite(pool) => pool.close().await,
            Database::Postgres(pool) => pool.close().await,
        }
    }

    /// Opens the database at `url`, whose **scheme picks the backend**.
    /// **Does not migrate.**
    ///
    /// `sqlite:` creates the file if it is not there yet, and pins the two
    /// pragmas the schema depends on. `postgres:`/`postgresql:` expects the
    /// database to exist — creating one is a privileged act an operator
    /// performs, not something a server does to a cluster it was pointed at.
    /// Any other scheme is refused by name here, rather than as a driver error
    /// several frames down.
    ///
    /// Applying the schema is a separate, named act: [`migrate`](Self::migrate),
    /// `acme-proxy migrate`, or the `worker` role at startup. It used to happen
    /// here, which meant every subcommand — `audit list`, `completions`, a
    /// health check — silently upgraded the schema of whatever database it was
    /// pointed at, and two processes starting together raced `MIGRATOR::run`
    /// with no lock between them (`SQLite` gives `sqlx` none; PostgreSQL does,
    /// an advisory lock, so there the one-owner rule is belt and braces).
    ///
    /// A caller that needs the schema present asks
    /// [`pending_migrations`](Self::pending_migrations) and refuses by name, or
    /// uses [`connect_and_migrate`](Self::connect_and_migrate).
    pub async fn open(url: &str) -> Result<Database, Error> {
        match scheme_of(url) {
            Some("sqlite") => Self::open_sqlite(url).await,
            Some("postgres" | "postgresql") => Self::open_postgres(url).await,
            _ => Err(Error::Configuration(
                format!(
                    "unsupported database URL scheme in `{}`: expected one of \
                     sqlite://, postgres:// or postgresql://",
                    acme_proxy_core::logfields::redact_url(url)
                )
                .into(),
            )),
        }
    }

    async fn open_sqlite(url: &str) -> Result<Database, Error> {
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

        Ok(Database::Sqlite(SqlitePool::connect_with(options).await?))
    }

    async fn open_postgres(url: &str) -> Result<Database, Error> {
        // Neither pragma has an analogue: foreign keys are always enforced and
        // there is no journal mode to choose. The pool is bounded because,
        // unlike a file, a cluster has a global connection limit that several
        // role processes share.
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await?;

        Ok(Database::Postgres(pool))
    }

    /// [`open`](Self::open) followed by [`migrate`](Self::migrate).
    ///
    /// For the two callers that own the schema — `acme-proxy migrate` and
    /// `acme-proxy init` — and for tests over a file-backed database, which
    /// want the same thing in one step.
    pub async fn connect_and_migrate(url: &str) -> Result<Database, Error> {
        let database = Self::open(url).await?;
        database.migrate().await?;
        Ok(database)
    }

    /// Applies every embedded migration that has not run yet.
    ///
    /// Idempotent: `sqlx` tracks each file by version and checksum, so running
    /// this against an up-to-date database does nothing.
    pub async fn migrate(&self) -> Result<(), Error> {
        match self {
            Database::Sqlite(pool) => run_migrations(&MIGRATOR, pool).await,
            Database::Postgres(pool) => run_migrations(&PG_MIGRATOR, pool).await,
        }
    }

    /// The migration set this database is measured against.
    fn migrator(&self) -> &'static Migrator {
        match self {
            Database::Sqlite(_) => &MIGRATOR,
            Database::Postgres(_) => &PG_MIGRATOR,
        }
    }

    /// The versions of the embedded migrations this database has not applied.
    ///
    /// Empty means the schema is current. What the roles that must **not**
    /// migrate check before serving, so an unmigrated database stops them by
    /// name rather than failing later as a missing table.
    ///
    /// A database with no `_sqlx_migrations` table has applied nothing — that
    /// is a freshly created file, not an error.
    pub async fn pending_migrations(&self) -> Result<Vec<i64>, Error> {
        let applied: std::collections::HashSet<i64> = if self.migrations_table_exists().await? {
            crate::sql::query("SELECT version FROM _sqlx_migrations;")
                .fetch_all(self)
                .await?
                .iter()
                .map(|row| row.try_get::<i64>(0usize))
                .collect::<Result<_, _>>()?
        } else {
            std::collections::HashSet::new()
        };

        Ok(self
            .migrator()
            .iter()
            .filter(|migration| !migration.migration_type.is_down_migration())
            .map(|migration| migration.version)
            .filter(|version| !applied.contains(version))
            .collect())
    }

    /// Builds a throwaway in-memory database with migrations applied. Pinned to
    /// a single connection so the whole test shares one in-memory database
    /// (each `SQLite` connection otherwise gets its own).
    pub async fn connect_in_memory() -> Result<Database, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true))
            .await?;

        run_migrations(&MIGRATOR, &pool).await?;

        Ok(Database::Sqlite(pool))
    }
}

/// Is there a `_sqlx_migrations` table to read?
///
/// Asked before reading it rather than by reading it and swallowing the error.
/// On SQLite a missing table is a clean `Err(Database(_))` the caller can
/// treat as "nothing applied"; on PostgreSQL the failed statement aborts the
/// surrounding transaction, so the next query in the same connection fails too
/// and the cause is three frames away from the mistake.
impl Database {
    async fn migrations_table_exists(&self) -> Result<bool, Error> {
        let sql = match self {
            Database::Sqlite(_) => {
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = '_sqlx_migrations';"
            }
            Database::Postgres(_) => {
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_name = '_sqlx_migrations';"
            }
        };
        let count: i64 = crate::sql::query(sql)
            .fetch_one(self)
            .await?
            .try_get(0usize)?;
        Ok(count > 0)
    }
}

/// The scheme of a URL, lower-cased, or `None` if it has none.
fn scheme_of(url: &str) -> Option<&str> {
    let scheme = url.split("://").next()?;
    (scheme != url).then_some(scheme)
}

async fn run_migrations<DB>(migrator: &Migrator, pool: &Pool<DB>) -> Result<(), Error>
where
    DB: sqlx::Database,
    DB::Connection: sqlx::migrate::Migrate,
{
    migrator.run(pool).await.map_err(|error| {
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

    use acme_proxy_core::random::random_token;

    #[tokio::test]
    async fn connect_creates_file_and_runs_migrations() {
        // A unique temp path so the "database does not exist → create it" branch
        // runs (the in-memory helper never exercises it).
        let file =
            std::env::temp_dir().join(format!("acme-proxy-test-{}.db", uuid::Uuid::now_v7()));
        let url = format!("sqlite://{}", file.display());

        let database = Database::connect_and_migrate(&url).await.unwrap();

        // Migrations applied: the `nonces` table exists and is queryable.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nonces;")
            .fetch_one(database.raw_pool())
            .await
            .unwrap();
        assert_eq!(count, 0);

        // WAL and foreign-key enforcement are on: the schema's CASCADE rules
        // depend on the latter.
        let journal: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(database.raw_pool())
            .await
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(database.raw_pool())
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);

        database.close().await;
        // WAL leaves sidecar files behind.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", file.display()));
        }
    }

    /// A `Tx` keeps `sqlx`'s transaction semantics through the wrapper: a
    /// commit lands, a drop rolls back, and the pool reports its occupancy.
    #[tokio::test]
    async fn a_transaction_commits_or_rolls_back_through_the_wrapper() {
        let database = Database::connect_in_memory().await.unwrap();

        let mut tx = database.transaction().await.unwrap();
        crate::sql::query("INSERT INTO nonces VALUES ('dropped', 0);")
            .execute(tx.conn())
            .await
            .unwrap();
        drop(tx);
        assert_eq!(count(&database).await, 0, "a dropped Tx rolls back");

        let mut tx = database.transaction().await.unwrap();
        crate::sql::query("INSERT INTO nonces VALUES ('kept', 0);")
            .execute(tx.conn())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(count(&database).await, 1, "a committed Tx lands");

        // `connect_in_memory` pins the pool to one connection. Whether it reads
        // idle yet is a race with `sqlx` handing it back, so only the bound is
        // asserted.
        let stats = database.pool_stats();
        assert_eq!(stats.size, 1);
        assert!(stats.idle <= 1, "{stats:?}");

        database.close().await;
        let refused = crate::sql::query("SELECT 1;")
            .execute(database.raw_pool())
            .await;
        assert!(refused.is_err(), "a closed pool refuses work");
    }

    async fn count(database: &Database) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM nonces;")
            .fetch_one(database.raw_pool())
            .await
            .unwrap()
    }

    /// Every foreign key is indexed. Without these, each child lookup is a full
    /// table scan — `Authorization::find_by_order` runs on every order read.
    #[tokio::test]
    async fn foreign_keys_and_the_nonce_sweep_are_indexed() {
        let database = Database::connect_in_memory().await.unwrap();
        let names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index';")
                .fetch_all(database.raw_pool())
                .await
                .unwrap();

        for expected in [
            "idx_orders_account_id",
            "idx_authorizations_order",
            "idx_challenges_authz",
            "idx_nonces_created_at",
            "idx_orders_cert_serial",
            "idx_orders_replaces_claim",
            // Not a foreign key, but `eab delete` and `account list --eab-kid`
            // look accounts up by it.
            "idx_accounts_eab_kid",
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

    /// The width `revocations.issuer` and `crls.issuer` declare is the length of
    /// [`acme_proxy_core::cert::issuer_id`], the `declared_token_widths_match_random_token`
    /// rule applied to the other derived value this schema stores.
    #[tokio::test]
    async fn declared_issuer_widths_match_the_issuer_id() {
        let database = Database::connect_in_memory().await.unwrap();
        let expected = format!(
            "VARCHAR({})",
            acme_proxy_core::cert::issuer_id(b"any key").len()
        );

        for (table, column) in [("revocations", "issuer"), ("crls", "issuer")] {
            assert_eq!(
                declared_type(&database, table, column).await,
                expected,
                "{table}.{column} declares a width the issuer id does not have"
            );
        }
    }

    /// The declared type of every column holding a row id.
    ///
    /// The [`random_token`] twin above, for the other family of values the
    /// schema declares a type for. Ids are the 16 bytes of a UUID
    /// ([`crate::id`]), stored as a BLOB rather than as the 36
    /// characters of its rendering, and this is what notices a column that went
    /// back to text — or a new table added with a `VARCHAR(36)` id out of
    /// habit.
    ///
    /// It matters for the reason the widths do: SQLite gives a declared type an
    /// affinity and enforces nothing, where the PostgreSQL set these
    /// declarations will be transcribed into (issue #4) has a native `uuid`
    /// and does enforce it. `nonces.value` is what a stale declaration looks
    /// like once nothing can notice it.
    #[tokio::test]
    async fn every_id_column_is_declared_a_blob() {
        let database = Database::connect_in_memory().await.unwrap();

        let minted = crate::id::mint();
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

    const AUDIT_LOG_ADMIN_ACTIONS: i64 = 20_260_909_120_000;

    /// `20260909120000` rebuilds `audit_log` to drop the `event` `CHECK` (the
    /// Rust `AuditEvent` enum is the authority now). A rebuild is where a
    /// mistyped column list loses a row silently — `audit_log` has no foreign
    /// keys, so this is the simple case, but the guard is the same: seed a row
    /// with every column populated, apply the migration, and assert the row
    /// came back whole, that an event name no enum variant spells now inserts,
    /// and that the three indexes the `DROP` took were re-created.
    #[tokio::test]
    async fn the_audit_log_rebuild_keeps_every_row_and_relaxes_the_event_check() {
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
            if migration.version == AUDIT_LOG_ADMIN_ACTIONS {
                converted = Some(migration);
                break;
            }
            sqlx::raw_sql(migration.sql.clone())
                .execute(&pool)
                .await
                .unwrap();
        }
        let converted = converted.expect("the audit-log rebuild is in the embedded set");

        sqlx::raw_sql(
            "INSERT INTO audit_log \
             (id, created_at, event, outcome, profile, actor_kind, actor_id, account_id, \
              order_id, cert_serial, identifiers, client_ip, client_ptr, user_agent, \
              request_id, reason, detail) VALUES \
             (41812, 1700, 'certificate_revoked', 'success', 'le', 'admin', 'root', \
              'acct-1', 'order-1', '0a0b', '[\"a.example\"]', '203.0.113.7', 'host.example', \
              'certbot', 'req-9', '1', 'by operator');",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(converted.sql.clone())
            .execute(&pool)
            .await
            .unwrap();

        let row = crate::sql::query(
            "SELECT id, event, actor_id, account_id, order_id, cert_serial, identifiers, \
             client_ip, user_agent, reason, detail FROM audit_log;",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.try_get::<i64>("id").unwrap(),
            41812,
            "the id has to survive, `audit show <id>` uses it"
        );
        assert_eq!(
            row.try_get::<String>("event").unwrap(),
            "certificate_revoked"
        );
        assert_eq!(
            row.try_get::<Option<String>>("actor_id")
                .unwrap()
                .as_deref(),
            Some("root")
        );
        assert_eq!(
            row.try_get::<Option<String>>("account_id")
                .unwrap()
                .as_deref(),
            Some("acct-1")
        );
        assert_eq!(
            row.try_get::<Option<String>>("order_id")
                .unwrap()
                .as_deref(),
            Some("order-1")
        );
        assert_eq!(
            row.try_get::<String>("identifiers").unwrap(),
            "[\"a.example\"]"
        );
        assert_eq!(
            row.try_get::<Option<String>>("cert_serial")
                .unwrap()
                .as_deref(),
            Some("0a0b")
        );
        assert_eq!(
            row.try_get::<Option<String>>("client_ip")
                .unwrap()
                .as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            row.try_get::<Option<String>>("detail").unwrap().as_deref(),
            Some("by operator")
        );

        // `account_id` / `order_id` stay text — no FK, they name a row that may
        // be gone (`every_id_column_is_declared_a_blob` also asserts this).
        assert_eq!(
            declared_type_on(&pool, "audit_log", "account_id").await,
            "VARCHAR(36)"
        );

        // The dropped `event` CHECK: a value no `AuditEvent` variant spells now
        // inserts. `outcome` and `actor_kind` keep theirs.
        sqlx::raw_sql(
            "INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind) \
             VALUES (1701, 'operator_teleported', 'success', '', 'admin');",
        )
        .execute(&pool)
        .await
        .unwrap();
        let bad_actor = sqlx::raw_sql(
            "INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind) \
             VALUES (1702, 'account_deleted', 'success', '', 'robot');",
        )
        .execute(&pool)
        .await;
        assert!(
            bad_actor.is_err(),
            "the actor_kind CHECK still guards the column"
        );

        // The three indexes the DROP took, re-created by the migration.
        let indexes: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index';")
                .fetch_all(&pool)
                .await
                .unwrap();
        for expected in [
            "idx_audit_log_created_at",
            "idx_audit_log_account_id",
            "idx_audit_log_cert_serial",
        ] {
            assert!(
                indexes.iter().any(|name| name == expected),
                "{expected} was not re-created"
            );
        }
    }

    /// [`declared_type`] against a bare pool rather than a [`Database`].
    async fn declared_type_on(pool: &sqlx::SqlitePool, table: &str, column: &str) -> String {
        let columns: Vec<(String, String)> =
            sqlx::query_as("SELECT name, type FROM pragma_table_info(?);")
                .bind(table)
                .fetch_all(pool)
                .await
                .unwrap();
        columns
            .into_iter()
            .find(|(name, _)| name == column)
            .map(|(_, declared)| declared)
            .unwrap_or_else(|| panic!("no column {table}.{column}"))
    }

    /// One row per table, each carrying a UUID v4 in every id column — the
    /// shape a database written before `crate::id` existed holds.
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
                .fetch_all(database.raw_pool())
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

        crate::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();

        let insert = |id: &'static str, status: &'static str| {
            let pool = database.raw_pool().clone();
            async move {
                crate::sql::query(
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
        crate::sql::query("UPDATE orders SET status = 'invalid' WHERE id = 'first';")
            .execute(database.raw_pool())
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

        let result = crate::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('a', 'default', X'00', '[]', 'definitely-not-a-status', 0);",
        )
        .execute(database.raw_pool())
        .await;
        assert!(result.is_err(), "an unknown account status must be refused");

        // And a legitimate one is accepted.
        crate::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('a', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();
    }

    /// Deleting a parent takes its children with it. Before this the constraints
    /// had no referential action at all, so an account could never be deleted —
    /// which blocked any retention work.
    #[tokio::test]
    async fn deleting_an_account_cascades_to_its_orders() {
        let database = Database::connect_in_memory().await.unwrap();

        crate::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();
        crate::sql::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, created_at) \
             VALUES ('ord', 'default', 'acct', 'pending', '[]', 0, 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();
        crate::sql::query(
            "INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) \
             VALUES ('az', 'ord', '{}', 'pending', 0, 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();
        crate::sql::query(
            "INSERT INTO challenges (id, authz_id, type, token, status, created_at) \
             VALUES ('ch', 'az', 'http-01', 't', 'pending', 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();

        crate::sql::query("DELETE FROM accounts WHERE id = 'acct';")
            .execute(database.raw_pool())
            .await
            .unwrap();

        for (table, query) in [
            ("orders", "SELECT COUNT(*) FROM orders;"),
            ("authorizations", "SELECT COUNT(*) FROM authorizations;"),
            ("challenges", "SELECT COUNT(*) FROM challenges;"),
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .fetch_one(database.raw_pool())
                .await
                .unwrap();
            assert_eq!(count, 0, "{table} should have been cascaded away");
        }
    }

    /// An order cannot carry two authorizations for the same identifier.
    #[tokio::test]
    async fn an_order_cannot_have_duplicate_authorizations_for_one_identifier() {
        let database = Database::connect_in_memory().await.unwrap();
        crate::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();
        crate::sql::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, created_at) \
             VALUES ('ord', 'default', 'acct', 'pending', '[]', 0, 0);",
        )
        .execute(database.raw_pool())
        .await
        .unwrap();

        let insert = |id: &'static str| {
            crate::sql::query(
                "INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) \
                 VALUES (?, 'ord', '{\"type\":\"dns\",\"value\":\"example.com\"}', 'pending', 0, 0);",
            )
            .bind(id)
            .execute(database.raw_pool())
        };

        insert("az1").await.unwrap();
        assert!(
            insert("az2").await.is_err(),
            "a second authorization for the same identifier must be refused"
        );
    }
}
