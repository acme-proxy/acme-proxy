# CLAUDE.md — `crates/` (and `src/cli/`)

The code itself: the nine library crates, plus the binary's command tree in
`src/cli/`. The repository-wide rules (commands, CI, the migration freeze, the
conventions every crate follows) are in `../CLAUDE.md`; the harness and the
integration suites are in `tests/CLAUDE.md`.

**Where the knowledge lives.** This file holds only what you must know *before*
editing, as one line each. The reasoning is elsewhere, in exactly one place:

- **A module's invariants are in its own `//!` doc** — read it before changing
  the module. Most files open with the rules they rest on and the traps a change
  would fall into.
- **Decisions that span modules are ADRs**, in `doc/src/dev/adr/`; the index
  also lists the decisions argued in a module doc or a book page.
- **The design overview** is `doc/src/dev/architecture.md` (the request flow,
  the extractor, the order lifecycle, the signing-key seam), and the schema's
  reasoning is `doc/src/dev/database.md`.

## Crates

| Crate (`crates/<dir>`) | Modules | Depends on |
|---|---|---|
| `acme-proxy-core` (`core`) | `audit` (the vocabulary), `cert`, `client`, `config`, `eab`, `error`, `identifier`, `jws`, `key_change`, `logfields`, `palette`, `pemfile`, `random`, `routes`, `script_hook`, `templating` | — |
| `acme-proxy-store` (`store`) | one module per table, **at the crate root** (`acme_proxy_store::order::Order`), plus `sql` (the dialect seam), `migrations/` and `migrations-postgres/` | core |
| `acme-proxy-net` (`net`) | `challenge`, `dns`, `egress`, `http_client`, `listener`, `proxy`, `tls` | core |
| `acme-proxy-policy` (`policy`) | `filter`, `ipam` | core, net |
| `acme-proxy-jobs` (`jobs`) | `auditor`, `jobs`, `metrics`, `notify` | core, net, store |
| `acme-proxy-signer` (`signer`) | `local_ca`, `relay`, `custom`, `info`, **at the crate root**; owns the `hsm` feature | core, jobs, net, store |
| `acme-proxy-protocol` (`protocol`) | `acme` (the services), `extractors`, `handlers`, `middlewares`, `profile`, `router` | everything above |
| `acme-proxy-admin` (`admin`) | `admin` (the operation layer), `webadmin` | protocol and below, not net |
| `acme-proxy-server` (`server`) | the runtime, **at the crate root** (`acme_proxy_server::serve_on`): roles, assembly, generations, sockets, `reload`, `logging` | all of the above |
| `acme-proxy` (repository root) | `src/cli/`, `main.rs`, every suite in `tests/` | all of the above |

The layering, lockstep publishing and `test-util` scaffolding are
[ADR 0002](../doc/src/dev/adr/0002-workspace-layering.md).

- **An edge is added by editing `CRATE_DEPS`** in `tests/layering.rs` on
  purpose; the test pins every member's `[dependencies]` to it.
- A doc link cannot point **up** the graph — write a plain code span instead.
- Test scaffolding goes in the **lowest** crate its types allow, behind
  `test-util`. A unit test reading a repository file anchors on
  `env!("CARGO_MANIFEST_DIR")`.
- `tracing` targets are crate paths; `acme_proxy=info` still covers them all.

## The request path

A signed POST passes, in order: the nonce middleware (`middlewares/nonce.rs`,
minting only where RFC 8555 asks), the filter middleware, then the extractor
(`extractors/acme.rs`, whose `//!` lists its checks in order), then a handler
that is extractor → `acme::*` service → response. **Rules live in the service**
(`crates/protocol/src/acme/`), which the CLI, the panel and the job handlers
call too; a handler keeps only what is HTTP.

## Invariants and traps

**ACME**

- Every signed route takes `AcmeRequest<T>`, `AcmePostAsGet` or
  `AcmeOptionalPayload<T>`. Never re-check media type, `crit`, `url` or nonce by
  hand.
- **No request path names a signing backend** — no `SignerBackend`,
  `Revoker::Backend`, `from_config` or `build_backends`
  ([ADR 0006](../doc/src/dev/adr/0006-no-slow-or-privileged-work-in-a-request.md),
  enforced by `tests/layering.rs`). Requests use the read side, `SignerInfo`.
- Multi-row state changes are **one transaction**: an order with its
  authorizations and challenges; the finalize claim with its `signer_issue`
  row; a validation verdict with the order promotion (the "all valid?" read
  happens inside it); a deactivation with the order's demotion.
- A verdict is terminal. A job answers `Retry` only when the attempt could not
  happen at all.
- Revocation compares the **exact DER** submitted, never a key re-derived from
  it; `alreadyRevoked` only after the request is authorized.
- `index_link` **appends** `Link`, never sets it — a handler's own `Link`
  (terms of service) must survive.
- `GET /crl` and `GET /ca.pem` sit **inside** the profile router, behind its
  filter policy. An address-based policy that must let relying parties fetch the
  CRL needs a `path` rule for it.

**Jobs, signers, reload**

- A backend never returns a `JobHandler`; it hands over **state**
  (`crl_refresher`, the relay's state), because the registry refuses a second
  handler for a kind. One handler per kind, over every profile.
- `abandon` fires exactly once. A sweep never answers `Failed`.
- `LocalCa` overwrites **every** CSR extension (`NoCa`, not `ExplicitNoCa`);
  both signing calls stay under `spawn_blocking`, unconditionally.
- rustls: pass the provider explicitly, **never** `install_default`.
- The shared resolver stays **uncached** (a `dns-01` record published moments
  ago); `reverse_dns` keeps its own cached one.
- Reload: nothing awaits between the `send_replace` calls; notifiers and the
  registry publish before the routers. A `FROZEN` projection that reaches a
  credential must be opaque. See `crates/server/src/reload.rs`.
- `pemfile::write_atomic`'s scratch name is `<path>.<pid>.tmp`, and both halves
  are load-bearing.

**Policy**

- Filter: Kleene logic, a rule's stages are the **intersection** of its checks',
  per-request memoisation is mandatory, regexes are auto-anchored, `deny` wins,
  and a request with no client address fails closed. See
  `crates/policy/src/filter/policy.rs` and `mod.rs`.
- `IpamError` has no "denied" variant; only `AddressNames::Unknown` refuses.

**Storage**

- **`sql.rs` is the only module naming a driver** ([ADR
  0014](../doc/src/dev/adr/0014-postgresql-beside-sqlite.md)). Write one
  statement with `?` markers; the seam renumbers for PostgreSQL. A fragment that
  genuinely differs asks `Dialect` and owes `tests/postgres.rs` a case.
- A bound `None` carries its column's type — `Option<Uuid>` is
  `Null(NullKind::Uuid)`, never a bare null.
- **No SQLite scalar built-in without a PostgreSQL twin.** `MAX(x, 0)` is the
  worked example: SQLite's scalar two-argument max, an aggregate there. Spell it
  `CASE WHEN … END` rather than adding a fourth `Dialect` fork.
- `Tx` does **not** deref to a connection: `tx.conn()` is what `&mut *tx` was.
- An id parameter typed `&str` parses (it came from outside); `Uuid` came from
  a row. No `_uuid` twins (`crates/store/src/id.rs`).
- `Database::open` never migrates, and its scheme picks the backend. The pool is
  private to `store`; `raw_pool()` is SQLite-only and for test fixtures only.
- `Order::search` is the one listing filter. Add a predicate there, not in a
  front end.
- A new `AuditEvent` goes into `ALL_AUDIT_EVENTS` and bumps `EVENT_COUNT`; its
  `outcome` arm is exhaustive.

**Web admin and CLI**

- A mutating web route takes `AuthenticatedWrite`, `AdminWrite` or
  `SelfServiceWrite` and is listed in `mutating_endpoints()`
  (`tests/admin_api.rs`) or `mutating_page_endpoints()`
  (`tests/admin_pages.rs`) with its `RequiredTier`. A missing entry is a review
  catch.
- `EnrolWrite` refuses a `pending_mfa` session whose user already has a factor.
  `record_success` happens only after the second factor.
- Page templates are `.html` (escaped), never `.j2`. A fragment swaps
  `outerHTML` and keeps its target's `id`. htmx's provenance is
  `crates/admin/src/webadmin/static/README.md`.
- `handlers/params.rs`: a blank query value is absent, and `#[serde(default)]`
  must accompany `deserialize_with`.
- **No `#[instrument]` in `webadmin/` or `jobs/runner.rs`.**
- CLI command bodies return `CliError` and never print or exit; only
  `src/main.rs` does. `Palette::plain()` is the identity, `--json` never sees a
  palette, and colour wraps a field **after** it is padded.
- The logging stack composes its filter with `and_then`, never `with_filter`,
  and puts the format layer inside (`crates/server/src/logging.rs`).

## Unit tests

Inline `#[cfg(test)] mod tests` beside the code; the module and its tests are
one file. The catalogue is the test names themselves — read the `tests` module
of the file you are changing. Two things to know:

- A file carrying `#[instrument]` reports far lower coverage than it has; check
  `cargo llvm-cov report --text` for that file before writing tests against the
  percentage.
- The migration guards (row preservation across every rebuild, declared widths
  pinned to their constants) are at the bottom of `crates/store/src/db.rs`.
