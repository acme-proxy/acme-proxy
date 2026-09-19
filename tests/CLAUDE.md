# CLAUDE.md — `tests/`

The harness and the suites that drive the app from outside. The repository-wide
rules are in `../CLAUDE.md`; the code each suite exercises is described in
`crates/CLAUDE.md` and in the module docs. **Each suite's own `//!` header says
what it proves and what it deliberately leaves to the inline tests** — read it
before adding a case, and put a new case in the suite whose header claims it.

## Rules

- **`cargo nextest run --workspace`, never `cargo test`.** The `custom` script
  tests exec a file they just wrote, and under threads that intermittently fails
  `ETXTBSY`. The explanation is in `doc/src/dev/testing.md`.
- **Hold `ENV_LOCK` around `Config::load()`** (or use `testutil::EnvGuard`):
  `ACME_PROXY_*` and `ACME_PROXY_CONFIG` are process state.
- **Build apps only through `tests/common/mod.rs`** (`test_app_*`,
  `test_admin_app*`) and drive them with `common::acme` (`post`, `register`,
  `finalize`, `trigger`, …). Its `//!` holds the harness rules: profiles served
  from the read side, a real worker in every app, `ConnectInfo` inserted by hand
  because `oneshot` has no socket.
- **`trigger` and `finalize` decide nothing.** Poll with `await_challenge` /
  `await_order` (or the `*_and_settle` pairs); a CRL with `await_crl_listing`.
- **Assert with `assert_problem`, not a bare status** — `unauthorized` and
  `rejectedIdentifier` are both `403`.
- **Import `TestSigner`** wherever you call `signer.sign(…)`.
- **A new mutating web route joins `mutating_endpoints()`**
  (`admin_api.rs`) or **`mutating_page_endpoints()`** (`admin_pages.rs`),
  with its `RequiredTier`. The CSRF, role and audit guards all run over those
  tables.
- The admin harness mounts an **inactive** filter policy; a test about the
  policy itself uses `test_admin_app_logged_in_with_filter`.
- **Nothing reaches a real network.** Four suites touch the disk or a
  loopback socket, each for a stated reason: `roles.rs` (a file-backed database
  and several processes), `reload.rs` (a real `config.toml` and real ports),
  `filters.rs` (the IPAM mocks on loopback, and scripts) and `custom_signer.rs`
  (scripts).
- Two suites read the repository's own source rather than running it:
  `layering.rs` (crate edges, the raw pool, signers on the request path, the
  schema owners) and `logging_convention.rs` (the nine logging rules). Read the
  one that applies before adding a module or a log line.
- `reload.rs`'s two refusal assertions — a frozen key refused with the old
  configuration still serving, an unbindable address refused with the running
  socket still serving — must never be dropped.

## The e2e lab

`tests/e2e/` runs certbot, acme.sh and lego against a real `acme-proxy` in
containers. Everything about it — running, design, what each scenario proves,
known gaps — is in `tests/e2e/README.md`. The traps:

- Every test is `#[ignore]`d. Run with
  `cargo nextest run -E 'binary(e2e)' --run-ignored all`; a bare
  `cargo nextest run e2e` matches **nothing** and says `0 tests run`, not an
  error.
- CI runs only a subset, nightly. A scenario nothing runs rots: a behaviour
  change lands green and the scenario keeps asserting the old one.
- Every `certbot renew` needs `--no-random-sleep-on-renew`, or it sleeps up to
  eight minutes.
- A file the image build needs gets a `!` line in the root `.dockerignore`,
  which is an allowlist.
- A lego scenario needs `server.tls.enabled` plus `--tls-skip-verify`, and
  `lego run` takes its flags after the subcommand.
- Event names the lab greps for are grep-before-renaming, and `server_startup`
  on stdout is the container readiness gate.
