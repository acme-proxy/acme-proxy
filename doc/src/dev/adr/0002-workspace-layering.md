# ADR 0002: One binary over a layered workspace of lockstep crates

## Status

Accepted.

## Context

The server was one crate of about 106,000 lines. Every change recompiled all of
it, and nothing but review stopped the web admin from issuing SQL or the
notifier from reaching into a signer. Layering held by convention, and a
convention is broken by the first drive-by import that compiles.

The code was not meant as a library for anyone else. It exists so the binary
and the integration tests can reach it. That shapes what a split has to buy:
compiler-enforced edges and faster rebuilds, not a public API.

## Decision

- **One binary, nine library crates.** The `acme-proxy` package at the
  repository root holds the `clap` command tree (`src/cli/`), `main.rs` and
  every suite in `tests/`. The libraries under `crates/` are, bottom-up: `core`,
  `store`, `net`, `policy`, `jobs`, `signer`, `protocol`, `admin`, `server`. The
  crate map is in [Architecture](../architecture.md#the-workspace).
- **A crate names only crates beneath it.** Cargo refuses a cycle but accepts an
  edge that skips across a layer, so the intended edges are pinned in a table
  (`CRATE_DEPS` in `tests/layering.rs`) and a test compares every member's
  `[dependencies]` against it. Adding an edge means editing that table on
  purpose.
- **Lockstep, with no semver promise.** Every member takes
  `version.workspace`, and every internal dependency is pinned with `=` in
  `[workspace.dependencies]`. An item becomes `pub` only because another crate
  needs it, not because it is an API.
- **Test scaffolding lives per crate, behind a `test-util` feature**
  (`#[cfg(any(test, feature = "test-util"))] pub mod testutil`). Only other
  crates' `[dev-dependencies]` turn it on, so no normal build ships it. A
  fixture belongs to the lowest crate its types allow.
- **Every cargo command takes `--workspace`.** At a root that is also a package,
  a bare command acts on that package alone, and the library crates would drop
  out of lint, tests and coverage with nothing going red.

## Consequences

- A handler cannot reach the runtime that serves it, and the job queue cannot
  reach the filters. The compiler refuses the import.
- A doc link cannot point *up* the graph, since a crate cannot link to its
  dependants. Such a mention is a plain code span instead.
- A member's unit tests run in the member's own directory. A test that reads a
  repository file anchors on `env!("CARGO_MANIFEST_DIR")`.
- `tracing` targets are the crate paths (`acme_proxy_store::db`, …). The
  default filter `acme_proxy=info` still covers them all because `EnvFilter`
  matches targets by string prefix.
- All ten packages are published together. A release bumps the workspace version
  once, and every `=` pin with it.

## Enforced by

- Cargo, for cycles.
- `crate_dependencies_follow_the_layers` in `tests/layering.rs`, for edges
  across a layer.
- The CI jobs, each of which passes `--workspace`
  (`.github/workflows/ci.yml`).
