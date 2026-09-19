# ADR 0005: A Rust enum owns each vocabulary, and SQL checks only the closed ones

## Status

Accepted.

## Context

Many columns hold a word from a fixed list: an order's status, an audit event,
an operator's role, a job's kind. There are two places the list can be enforced:
a SQL `CHECK` constraint, or a Rust type.

A `CHECK` catches a typo before it parks a row in a state nothing can reach. But
SQLite cannot alter one without rebuilding the table ([ADR
0003](0003-migrations-frozen-and-explicit.md)). Once a vocabulary grows, its
constraint becomes a migration per new word, and a rolling upgrade breaks: an
older binary refuses to write a word only a newer one knows.

String literals in Rust are worse than either. Before
`crates/store/src/status.rs` existed, about 30 comparisons against literals were
spread across handlers, storage and the relay flow. A typo compiled, and
silently changed policy.

## Decision

- **Every vocabulary is a Rust enum**, and the enum is the authority. Values are
  written only through its `as_str()`, and read back through a parse that
  handles an unknown word explicitly.
- **Closed vocabularies also keep a `CHECK`.** Every `status` column
  (`accounts`, `orders`, `authorizations`, `challenges`, `jobs`,
  `upstream_orders`, `eab_keys`, `admin_users`) changes only with its state
  machine. The enums in `status.rs` reproduce their columns' existing strings
  byte for byte, so the frozen constraints stay valid.
- **Open vocabularies carry no `CHECK`.** These are vocabularies that grow with
  features:
  - `audit_log.event`. `20260909120000` rebuilt the table to drop that
    `CHECK` when the administrative actions widened it. `AuditEvent` is the
    authority, and `AuditEvent::outcome` is an exhaustive match, so a new name
    must classify itself as a success or a failure.
  - `admin_users.role`. `NULL` reads as `admin`, so an operator created before
    the column existed keeps full authority. Any other unknown value folds to
    `viewer`, the least privilege.
  - `jobs.kind`, which is an open set by design.
- **Operator surfaces refuse an unknown value by name** ([Admin
  CLI](../../operations/cli.md)) wherever the vocabulary is closed, since "no
  rows" reads exactly like "nothing is in that state". `--kind` is the
  exception, because kinds are an open set.
- `Job::status` and `UpstreamOrder::status` stay `String` in their models. An
  older binary must still render a row a newer one wrote. Their enums exist for
  the operator surface.

## Consequences

- A new audit event or role is a Rust change and a changelog line, with no
  migration.
- A value written by hand into the database is handled by the parse rule, never
  trusted: a garbage role reads as `viewer`.
- The database alone no longer guarantees that `audit_log.event` holds a known
  word. The insert path binds `AuditEvent::as_str()`, never a free string.

## Enforced by

- The `CHECK (status IN (…))` constraints in the migrations.
- `EVENT_COUNT` and `ALL_AUDIT_EVENTS` in `crates/core/src/audit/mod.rs`, a
  compile-time assertion that no variant is missing from the list.
- `AdminRole::from_storage` in `crates/store/src/admin_user.rs`.
- `the_audit_log_rebuild_keeps_every_row_and_relaxes_the_event_check`
  (`crates/store/src/db.rs`).
