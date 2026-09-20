# ADR 0014: PostgreSQL is chosen by the URL's scheme, over one set of queries

## Status

Accepted.

## Context

SQLite across processes is safe on one local disk and not across hosts. The
role split ([ADR 0007](0007-role-processes.md)) lets `acme`, `admin` and
`worker` run as separate processes, but only as separate processes on one
filesystem, so the deployment page promised PostgreSQL for as long as it did
not exist.

Two earlier decisions had already paid for most of it. [ADR
0003](0003-migrations-frozen-and-explicit.md) keeps the pool private to
`crates/store/`, so SQL and the dialect it is written in live in one crate.
[ADR 0004](0004-uuid-v7-blob-ids.md) chose UUID v7 partly because a v4 primary
key costs PostgreSQL a page split and a full-page WAL write per row. What was
left was a real fork: two pool types, two row types, two parameter syntaxes,
and around 350 bind sites.

The obvious answers were both bad. `sqlx::Any` cannot carry a `Uuid` at all —
its type set is `Null`/`Bool`/`SmallInt`/`Integer`/`BigInt`/`Real`/`Double`/
`Text`/`Blob` — and it does not translate SQL. Writing every statement twice
doubles the SQL and guarantees the two copies drift, which is the one failure
mode nothing here would catch: a query used by an operator listing can be wrong
for months.

What made a single set of queries possible is that almost nothing in this
schema is dialect-specific to begin with. Every timestamp is an epoch-second
integer, so there is no `strftime`, `julianday`, `datetime()` or date type
anywhere. There is no `CAST`, no `||` concatenation, no `LIKE`, no
`GROUP_CONCAT`, no `IFNULL`, no CTE and no window function. `RETURNING`,
`ON CONFLICT … DO NOTHING`, `DO UPDATE … excluded.*`, partial unique indexes
and bound `LIMIT`/`OFFSET` are already spelled the way both accept.

## Decision

- **The scheme of `database.url` picks the backend**, at `Database::open`.
  `sqlite:` creates the file; `postgres:`/`postgresql:` expects the database to
  exist, because creating one is an operator's act and not something a server
  does to a cluster it was pointed at. Any other scheme is refused by name.
- **One set of queries, in `crates/store/src/sql.rs`.** A statement is a
  `sql::Query` carrying its SQL and a `Vec<Value>` until a `sql::Exec` says
  which driver is on the other end. `sql::Row` hides which row came back and
  `sql::Builder` replaces `sqlx::QueryBuilder`. Nothing outside that module
  names either driver.
- **Statements keep `?` and the seam rewrites to `$1…$n`.** Writing `$n` in the
  source would have worked on both — sqlx's SQLite driver parses a `$N` marker
  and binds argument `N` — but three things here build SQL by concatenation:
  the `live_certificate!` predicate spliced into the middle of three
  statements, the `IN (?, ?, …)` lists expanded per element, and the `format!`ed
  fragments in `job::claim_next` and `job::settle`. Every number would then be
  a hand-maintained constant. One rewrite at the edge cannot drift.
- **An absent value carries the type it would have had.** SQLite has no typed
  null; PostgreSQL sends a type OID per parameter and refuses `column
  "eab_kid" is of type uuid but expression is of type bigint`. Every bind site
  knows the type statically, so `Value::Null(NullKind)` costs nothing and is
  declared nowhere twice.
- **Three things fork, and each asks `Dialect`.** The identifier search
  (`json_each`/`json_extract`/`instr` against
  `jsonb_array_elements`/`->>`/`strpos`); the unique-violation matchers; and
  the `_sqlx_migrations` probe, which asked by reading the table and swallowing
  the error, where on PostgreSQL a failed statement aborts the surrounding
  transaction. Nothing else may fork without a line here.
- **`strpos`, never `position(needle in haystack)`.** It takes its arguments
  the other way round, so one `push_bind` sequence would bind the two dialects
  in different orders — a wrong answer rather than an error.
- **Two migration sets, both append-only.** `migrations/` for SQLite, frozen
  since 0.1.0; `migrations-postgres/` from its own first release. The
  PostgreSQL set is **not** a transcription: the SQLite files carry three table
  rebuilds that exist only because SQLite cannot add a `CHECK`, a `UNIQUE` or a
  foreign key to an existing table, plus a text-to-blob id conversion, and no
  PostgreSQL deployment has that history to replay. Every declared width *is*
  transcribed literally.
- **A unique constraint PostgreSQL must name is named in the migration.**
  SQLite reports the offending columns and gives sqlx no constraint name;
  PostgreSQL reports the constraint and never the columns. A matcher passes
  both spellings, so the index name is part of the schema rather than whatever
  the server happened to generate.
- **The database URL is redacted wherever it is printed.** A DSN carries
  `user:password@`; the startup log line and the `SIGHUP` refusal both go
  through `logfields::redact_url`.

## Consequences

- One binary and one container image serve both, and a deployment moves from
  SQLite to PostgreSQL by changing one key — there is no migration path for the
  *data*, which is a separate problem nobody has asked for yet.
- `Tx` no longer derefs to `SqliteConnection`. `tx.conn()` is what `&mut *tx`
  was, and `JobQueue::enqueue_in` takes a `sql::Exec` — the one SQLite-typed
  signature that had leaked outside `crates/store/`.
- A declared `VARCHAR(n)` is now enforced. SQLite ignores the width, which is
  how `nonces.value` stayed `VARCHAR(36)` after the nonce became a
  43-character token; on PostgreSQL that would have rejected every nonce the
  server mints. The width pins in `db.rs` are what keep the two honest.
- `sqlx/postgres` brings RustCrypto (`sha2`, `hmac`, `md-5`, `stringprep`) for
  SCRAM-SHA-256. That is a second crypto stack in the graph, which [ADR
  0009](0009-dependency-policy.md) argues against; its clause is narrowed
  rather than worked around, because there is no configuration of the driver
  that avoids it. TLS stays on `ring` (`tls-rustls-ring`), and sqlx builds its
  `ClientConfig` with `builder_with_provider` rather than `install_default`, so
  the "nothing installs process-global state" rule is untouched.
- PostgreSQL gives sqlx an advisory migration lock, which SQLite does not. The
  one-owner rule in ADR 0003 is therefore belt and braces there rather than
  load-bearing — it stays, because the rule is about which *process* may own
  the schema, not only about the race.
- The coverage floor cannot see this backend: a dialect arm not taken is not an
  uncovered line. That is what the CI job and its `REQUIRE` guard are for.

## Enforced by

- `tests/postgres.rs`, which runs the dialect-sensitive paths against both
  backends, and `postgres_is_available_when_it_is_required`, which fails rather
  than skips when `ACME_PROXY_REQUIRE_POSTGRES` is set.
- The `postgres` job in `.github/workflows/ci.yml`, which sets that variable
  and also runs `roles` and `reload` — several processes over one database,
  which is the deployment this exists for.
- `sql::tests::numbering_is_contiguous_from_one` and the literal-skipping cases
  beside it.
- `production_code_never_reaches_the_raw_pool` and
  `only_the_schema_owners_apply_migrations` (`tests/layering.rs`), unchanged.
- `declared_token_widths_match_random_token`,
  `declared_issuer_widths_match_the_issuer_id` and
  `every_id_column_is_declared_a_blob` (`crates/store/src/db.rs`).
- `logfields::tests`, for the redaction, and
  `reload::tests::a_refusal_over_a_dsn_keeps_the_host_and_drops_the_password`.
