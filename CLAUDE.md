# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**This file is one of three**, and each is an index rather than a manual. This one holds what is true of the whole repository: what the server is, the commands, CI, and the rules every change must keep. **`crates/CLAUDE.md`** (the crate map and the traps in the code) and **`tests/CLAUDE.md`** (the harness and the suites) are loaded when working in their subtree — read the one for the subtree you are about to touch.

**Where the knowledge lives — each fact in exactly one place:**

- **What the server does, for an operator:** the mdBook in `doc/src/` (`mdbook build doc/`). Every configuration key is documented in exactly one page there, with its default and its environment variable; `configuration/reference.md` is the index.
- **Why a design is the way it is:** the ADRs in `doc/src/dev/adr/`. The index there also lists the decisions argued in a module doc or a book page instead.
- **What a module guarantees, and the traps in changing it:** that module's own `//!` doc. Read it before editing the module.
- **This file:** only the rules a change must keep, as one line each, pointing at where the reasoning lives.

## What this is

An **ACME (RFC 8555) server** in Rust/[axum](https://docs.rs/axum), serving certificate clients (certbot, acme.sh, lego) over the full account → order → authorization → challenge → finalize → certificate flow, plus revocation. **One binary over a Cargo workspace**: the `acme-proxy` package at the root (`src/cli/`, `main.rs`, every suite in `tests/`) over nine library crates in `crates/`, bottom-up `core`, `store`, `net`, `policy`, `jobs`, `signer`, `protocol`, `admin`, `server` ([ADR 0002](doc/src/dev/adr/0002-workspace-layering.md)). At **0.5.0**.

An ACME endpoint is a **profile** (`[profiles.<name>]`, served at `/profile/<name>/…`); at least one is required, and each has its own signer, filters, challenge validators and EAB requirement over one listener and one database. The process runs as up to three **roles** — `acme`, `admin`, `worker` — all three by default, and only the worker holds a signing key ([ADR 0007](doc/src/dev/adr/0007-role-processes.md)).

| Subsystem | Code | Operator docs (`doc/src/`) | Decision |
|---|---|---|---|
| Accounts, orders, authorizations | `crates/protocol/src/acme/` | `core/concepts.md`, `features/` | [ADR 0006](doc/src/dev/adr/0006-no-slow-or-privileged-work-in-a-request.md) |
| JWS verification | `crates/protocol/src/extractors/acme.rs`, `crates/core/src/jws/` | — | `dev/architecture.md` |
| Challenge validation (`http-01`, `dns-01`, `tls-alpn-01`) | `crates/net/src/challenge/`, `crates/protocol/src/acme/validate.rs` | `challenges/` | [ADR 0006](doc/src/dev/adr/0006-no-slow-or-privileged-work-in-a-request.md) |
| Signers (`local_ca`, `relay`, `custom`), issuance | `crates/signer/`, `crates/protocol/src/acme/issue.rs` | `signers/` | [ADR 0007](doc/src/dev/adr/0007-role-processes.md) |
| Revocation and the CRL | `crates/protocol/src/acme/revoke.rs`, `crates/signer/src/local_ca/crl.rs` | `operations/revocation.md` | [ADR 0008](doc/src/dev/adr/0008-shared-state-in-the-database.md) |
| Access control (the filter policy) | `crates/policy/src/filter/` | `filters/` | `filter/policy.rs` `//!` |
| IPAM (NetBox, phpIPAM, script) | `crates/policy/src/ipam/` | `ipam/` | `ipam/mod.rs` `//!` |
| Background jobs | `crates/jobs/src/jobs/` | `configuration/reference.md` `[jobs]` | `jobs/mod.rs` `//!` |
| Notifications, expiry digest | `crates/jobs/src/notify/` | `notifications/` | `notify/expiry.rs` `//!` |
| Audit trail | `crates/core/src/audit/`, `crates/jobs/src/auditor/` | `operations/audit.md` | [ADR 0005](doc/src/dev/adr/0005-rust-enums-own-the-vocabularies.md) |
| Metrics | `crates/jobs/src/metrics.rs` | `operations/monitoring.md`, `operations/grafana.md` | [ADR 0011](doc/src/dev/adr/0011-metrics-on-prometheus-client.md) |
| Reload on `SIGHUP` | `crates/server/src/reload.rs` | `operations/reload.md` | [ADR 0008](doc/src/dev/adr/0008-shared-state-in-the-database.md) |
| The SQLite/PostgreSQL seam | `crates/store/src/sql.rs` | `dev/database.md` | [ADR 0014](doc/src/dev/adr/0014-postgresql-beside-sqlite.md) |
| Role processes | `crates/server/src/roles.rs` | `getting_started/deployment.md` | [ADR 0007](doc/src/dev/adr/0007-role-processes.md) |
| Web admin (`/ui`, `/api`) | `crates/admin/src/webadmin/` | `operations/webadmin.md`, `operations/webadmin_users.md` | `webadmin/session.rs` `//!` |
| Admin CLI | `src/cli/`, `crates/admin/src/admin/` | `operations/cli.md` | — |
| EAB, key rollover, ARI, TLS termination | `crates/core/src/eab.rs`, `key_change.rs`, `crates/net/src/tls.rs` | `features/` | — |

## Pre-1.0: only the schema is frozen

Before 1.0.0 the database schema is the **only** compatibility guarantee; config keys, profile names, the admin API, log event names and the CLI may all change ([ADR 0001](doc/src/dev/adr/0001-pre-1-0-compatibility.md), canonical text in `CHANGELOG.md`'s Compatibility section). A breaking change owes exactly three things:

1. An entry under the release's `### Breaking` heading in `CHANGELOG.md`, naming the old spelling and the new one.
2. A removed or renamed config key **refused by name at startup** wherever practical. A key must still parse to be refused, so removed fields stay in the config types.
3. **Never an alias, a dual syntax or a legacy lowering.** Delete the old shape.

## Commands

```bash
cargo build                 # build the binary (the root package of the workspace)
RUST_LOG=info cargo run     # serve on [::]:3000 by default; `serve` is the default subcommand
cargo run -- migrate        # apply the embedded migrations and exit
cargo run -- init           # migrate, then generate the CA / upstream account / self-signed TLS
cargo nextest run --workspace   # all tests — nextest, never `cargo test` (see Testing)
cargo fmt                   # format
cargo clippy --workspace --all-targets   # lint
cargo llvm-cov nextest --workspace --summary-only   # coverage (needs cargo-llvm-cov, cargo-nextest, llvm-tools-preview)
mdbook build doc/ && python3 doc/lint.py            # the book, and its style gate
```

The same binary carries every admin subcommand (`account`, `order`, `jobs`, `audit`, `nonce`, `profile`, `upstream`, `eab`, `filter`, `admin user|session`, `completions`, `man`); `doc/src/operations/cli.md` is their reference. Rules for changing them:

- **Every listing is paged** (`--limit`/`--offset`, `src/cli/window.rs`), prints `N of M row(s)`, and answers `{items, total, limit, offset}` under `--json` — member for member the admin API's envelope.
- **An unknown value for a closed vocabulary is refused by name** (`--status`, `--event`, `--outcome`, `--role`); passing it to SQL would answer "no rows", which reads like "nothing is in that state". `--kind` is the exception: job kinds are an open set.
- **No secret in argv.** There is no `--password` flag (a test asserts clap rejects one); secrets arrive on stdin or from a file.
- **`completions` and `man` are answered before `Config::load` and `Database::connect`** in `main.rs`, because `connect` creates its file. Keep them there.
- **`clap_complete` stays at `~4.5`**: 4.6's bash backend breaks completion for a binary named with a `-`. `the_bash_script_is_internally_consistent` is the guard.
- **Colour is semantic and never reaches `--json`**; `Palette::plain()` returns its argument unchanged; colour wraps a field after it is padded.
- **A subcommand other than `serve` installs no subscriber** unless `--log-level` or a non-empty `RUST_LOG` asks, and then logs to stderr — stdout is what a script parses.
- **The CLI never builds a signing backend** (`tests/layering.rs`): `order revoke` goes through the same queue and ledger `POST /revokeCert` does.
- Confirm-gated commands (`delete`, `cleanup`, `jobs cancel`, `totp reset`) prompt unless `--yes`; a delete that would remove an order holding a live certificate is refused on every surface, with no override.

## CI

`.github/workflows/ci.yml`. **Every cargo command takes `--workspace`** — at a root that is also a package, a bare one acts on that package alone. `doc/src/dev/contributing.md` has the full list with reasons.

- **test** — `fmt --check`, `clippy -D warnings`, `llvm-cov nextest --fail-under-lines 97` (`main.rs` excluded), `cargo test --doc`, and `cargo doc` with `-D warnings -A rustdoc::private_intra_doc_links`.
- **msrv** — `cargo check --locked` on the `rust-version` from `Cargo.toml`.
- **hsm** — clippy and the suite with `--features acme-proxy-signer/hsm` against SoftHSM2.
- **postgres** — the whole `acme-proxy-store` suite plus `tests/postgres.rs`, `roles` and `reload` against a real server, with `ACME_PROXY_REQUIRE_POSTGRES=1` so a skip is a failure. Separate from **test** for `hsm`'s reason: the coverage floor is a ratchet over one configuration.
- **supply-chain** — `cargo deny check`, with `all-features = true`.
- **sbom** — regenerates `sbom.cdx.json` and fails on drift; regenerate it when `Cargo.lock` changes and when cutting a release.
- **docs** — `mdbook build doc/` and `python3 doc/lint.py`.
- **e2e** (nightly) — a subset of the container lab in `tests/e2e/`.
- **image** (push to `main`, after every job above) — calls `release.yml` to publish `:edge`. A release tag runs `release.yml` directly.

**Branches** ([ADR 0013](doc/src/dev/adr/0013-trunk-and-release-branches.md)): every PR targets `main`, the trunk; `X.Y.0` is tagged there. A patch goes to `main` first and is cherry-picked (`-x`) onto `release/X.Y`, cut from `X.Y.0` when first needed, and tagged there. `release.yml`'s `guard` refuses a tag off its line.

A handler carrying `#[instrument]` reports far lower coverage than it has; check `cargo llvm-cov report --text` for the file before writing tests against the percentage.

## Database and migrations

[ADR 0003](doc/src/dev/adr/0003-migrations-frozen-and-explicit.md) has the reasoning; `doc/src/dev/database.md` the schema.

- **Two backends, chosen by `database.url`'s scheme** ([ADR 0014](doc/src/dev/adr/0014-postgresql-beside-sqlite.md)). The SQL is written **once**, in `crates/store/src/sql.rs` — the only module that names either driver. Statements keep `?` and the seam rewrites to `$1…$n` for PostgreSQL. Three things fork and each asks `Dialect`: the identifier search, the unique-violation matchers and the `_sqlx_migrations` probe. Nothing else may.
- **Both migration directories are append-only** — `crates/store/migrations/` (SQLite) and `crates/store/migrations-postgres/`. Never edit a committed file, not even a comment — `sqlx` checksums each one and an edit fails every existing deployment at startup. A schema change is `sqlx migrate add <name>` in **each** set.
- A new column is a new `ADD COLUMN` file. A new or dropped `CHECK`/`UNIQUE`/foreign key, or a wrong declared width, is a **table rebuild** in a new file — which must re-create the table's indexes, name every column, and park child rows before any `DROP` (the cascade hazard).
- **Only `migrate`, `init` and a `worker`-role `serve` apply migrations**; everything else refuses a schema that is behind (`tests/layering.rs`).
- **The pool is private to `crates/store/`.** Use a table module, `Database::transaction()` or `pool_stats()`; `raw_pool()` is for test fixtures only.
- Runtime `sqlx::query(...)`, not `query!`, so no `DATABASE_URL` is needed to build.
- Ids are UUID v7 — BLOBs on SQLite, native `uuid` on PostgreSQL, one Rust type for both. An id parameter typed `&str` came from outside and parses, a `Uuid` came from a row ([ADR 0004](doc/src/dev/adr/0004-uuid-v7-blob-ids.md)).
- **A bound `None` carries its column's type** (`Value::Null(NullKind)`): PostgreSQL types every parameter and rejects a `bigint` null against a `uuid` column.
- An open vocabulary (audit events, roles, job kinds) is a Rust enum with no SQL `CHECK` ([ADR 0005](doc/src/dev/adr/0005-rust-enums-own-the-vocabularies.md)).

## Configuration

`Config::load()` (`crates/core/src/config/`) layers built-in defaults → an optional `config.toml` (`ACME_PROXY_CONFIG` points elsewhere; `config.toml.example` shows every key) → `ACME_PROXY_*` environment variables, with `__` between nested keys. Global `[signer]`/`[filter]`/`[challenge]`/`[eab]`/`[order]`/`[ipam]`/`[notify]`/`[meta]` are the base each profile overlays **key by key**; arrays replace wholesale. Adding a key is a recipe in `doc/src/dev/contributing.md`. The traps:

- **Every list field carries `#[serde(deserialize_with = "string_list")]`**: it splits a comma-separated environment variable, at any depth, and reads the empty string as `[]`. There is no list-key registry; `every_list_field_reads_a_comma_separated_string` refuses a field without it.
- The environment source pins **`prefix_separator("_")`**; without it every `ACME_PROXY_*` variable is ignored.
- **A key is documented in exactly one book page** (`doc/lint.py` refuses a second).

## Testing

- **`cargo nextest run --workspace` is required, not preferred.** Tests that exec a script they just wrote fail `ETXTBSY` intermittently under the threads of `cargo test`.
- **A test calling `Config::load()` holds `acme_proxy_core::config::ENV_LOCK`** (or `testutil::EnvGuard`).
- Tests use an in-memory SQLite and an in-memory CA; nothing reaches a real network. The harness and its rules are in `tests/CLAUDE.md`.
- **A store test calls `Database::connect_for_test()`**, which is PostgreSQL when `TEST_POSTGRES_URL` is set and in-memory SQLite otherwise — so CI runs all 239 on each backend. `connect_in_memory()` stays and *means* SQLite: the seven tests that read `pragma_table_info`/`sqlite_master` or replay the migration set call it, and that is their whole opt-out.
- **`tests/postgres.rs` runs the dialect-sensitive paths against both backends** and skips when `TEST_POSTGRES_URL` is unset. A new fork in `sql.rs` owes it a case.
- **Assert a constraint violation with `sql::is_check_violation`/`is_foreign_key_violation`/`is_unique_violation`**, never on the driver's message text — the two dialects word every one of them differently.

## Conventions

- **URLs derive from `server.base_url`** — never hardcode one (`tests/config_driven.rs` runs the flow on a non-default one).
- **Handlers reject input with `Problem`** (`crates/core/src/error.rs`), an RFC 8555 `application/problem+json` document. The extractor has already checked media type, `crit`, `url` and nonce; do not repeat them. A dynamic status or header means returning `Result<Response, Problem>`.
- **Errors derive `thiserror`, `anyhow` is used without `.context()`, and only startup may panic** ([ADR 0010](doc/src/dev/adr/0010-error-types.md)).
- **Logging follows nine rules enforced by `tests/logging_convention.rs`** — `event` first as a bare literal from a closed subsystem list, `outcome` second, one name at one level, units on numeric fields. Read the test's header before adding a call site. `doc/src/operations/monitoring.md` is the operator catalogue; an event it names must still be emitted.
- **Grep `tests/e2e/` before renaming an event**; `server_startup` on stdout is the e2e readiness gate, so renaming it fails the lab as a start timeout.
- **One `State<AppState>`** per handler — two `State<Arc<…>>` extractors trip axum's inference.
- **No `#[instrument]` in `crates/admin/src/webadmin/` or the job runner (`crates/jobs/src/jobs/runner.rs`)** — the attribute moves a body into a generated block that reports almost no coverage.
- **Dependencies:** `ring` is the only crypto backend, nothing installs process-global state, and a crate already in the graph is preferred to a new one ([ADR 0009](doc/src/dev/adr/0009-dependency-policy.md)).
- Comments, doc comments and error strings are in **English**. Edition **2024**.
