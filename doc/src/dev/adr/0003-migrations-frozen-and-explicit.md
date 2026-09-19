# ADR 0003: Migrations are append-only and applied only by the schema owners

## Status

Accepted.

## Context

The schema is the one surface this project promises not to break (ADR 0001),
and `sqlx` enforces that promise mechanically: it records a checksum for every
migration it applies. Editing a committed file does not quietly diverge a
deployment's schema. It makes the next startup fail with a checksum mismatch.
Before the first release, a schema change meant editing the migration in place
and deleting `sqlite.db`. That stopped being possible once a database outside
the repository had run the files.

SQLite adds its own constraints:

- It cannot add a `CHECK`, `UNIQUE` or foreign key to an existing table.
- It gives `VARCHAR(n)` TEXT affinity and enforces no length.
- Under `foreign_keys = ON`, `DROP TABLE` performs an implicit `DELETE FROM`,
  which fires `ON DELETE CASCADE` into every child table.
- It gives `sqlx` no migration lock.

Migrations used to run inside `Database::connect`. That made every subcommand an
upgrade step. Once the server could run as several processes
(ADR@role-processes), two processes starting together raced `MIGRATOR::run` with
nothing to serialise them.

## Decision

**Append-only.** Every file in `crates/store/migrations/` is frozen, comments
included. A schema change is a new file (`sqlx migrate add <name>`):

- A new column is a new `ALTER TABLE … ADD COLUMN` file, even when it plainly
  belongs to an existing table.
- A new or dropped `CHECK`, `UNIQUE` or foreign key is a table rebuild, written
  in a new migration.
- A wrong declared width is also a rebuild. Where a width follows a constant in
  the code, a test pins the two together.
- A rebuild re-creates the table's indexes, since `DROP TABLE` takes them with
  it. It also names every column in its `INSERT … SELECT`, since a forgotten
  column is dropped silently. Rows in a table with children are parked in
  constraint-free `CREATE TABLE … AS SELECT` copies before anything is dropped,
  then put back parent-first. Otherwise the cascade empties the children.

**Applied explicitly.** `Database::open` connects and never migrates.
`Database::migrate` has two callers:

- `acme-proxy migrate` and `acme-proxy init`;
- a `serve` process that runs the `worker` role
  (`server::apply_or_require_schema`).

Every other entry point calls `pending_migrations` and refuses by name, pointing
at `acme-proxy migrate`. A default single-process `serve` includes the worker
role, so it still migrates a fresh database on its own.

**The pool is private to `crates/store/`.** Everything else goes through a table
module, `Database::transaction()` (a `Tx` that derefs to the connection) or
`Database::pool_stats()`. `Database::raw_pool()` exists for test fixtures only.
The connection pins two pragmas:

- `foreign_keys(true)`, because the schema's `ON DELETE CASCADE` depends on it;
- `journal_mode = WAL`, because every ACME response writes a nonce row, and the
  default rollback journal takes a database-wide exclusive lock on each write.

**Runtime queries.** Queries use `sqlx::query(...)`, not the compile-time
`query!` macros, so building needs no `DATABASE_URL`.

## Consequences

- An upgrade is starting the new binary. There is no dump/restore procedure.
- Several constraints were declared before anything wrote to them:
  `admin_users.totp_*` and `admin_sessions.state`'s `'pending_mfa'`. Adding them
  afterwards would have cost a rebuild each.
- Stale comments stay stale. Three migrations still call the relay backend
  `acme_proxy`. Treat grep results in `crates/store/migrations/` as read-only.
- `sqlx::migrate!()` embeds the migration set at compile time. Adding a file
  does not invalidate the build on its own; touch `crates/store/src/db.rs`.
- SQL, and the dialect it is written in, lives in one crate. That is what keeps
  a second backend (PLAN.md #2) a contained change.

## Enforced by

- `sqlx`'s checksums, at startup.
- `only_the_schema_owners_apply_migrations` and
  `production_code_never_reaches_the_raw_pool` in `tests/layering.rs`.
- Rebuild guards in `crates/store/src/db.rs`:
  - `the_blob_migration_preserves_every_row`;
  - `the_audit_log_rebuild_keeps_every_row_and_relaxes_the_event_check`.
- Width pins in the same file:
  - `declared_token_widths_match_random_token`;
  - `declared_issuer_widths_match_the_issuer_id`;
  - `every_id_column_is_declared_a_blob`.
