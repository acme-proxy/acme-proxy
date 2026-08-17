# Contributing to acme-proxy

Thank you for your interest in contributing to `acme-proxy`! Whether you're
fixing a bug, adding a new feature, or improving documentation, your help is
welcome.

## Development environment

To start developing, ensure you have the following installed:
- [Rust](https://rustup.rs/) (latest stable version)
- `sqlite3` (for database inspection, though `sqlx` handles migrations)
- [mdBook](https://rust-lang.github.io/mdBook/) (if you want to build this
  documentation locally)

### Initial setup

Clone the repository and build the project:
```bash
git clone https://github.com/acme-proxy/acme-proxy.git
cd acme-proxy
cargo build
```

## Testing

The suite is what holds RFC 8555 compliance in place, and CI enforces a
coverage floor, so a change that adds a branch generally has to add a test for
it.

Before submitting a pull request, run the full suite with **nextest**:
```bash
cargo nextest run
```

> Use `cargo nextest run`, not `cargo test`. This is a requirement, not a
> preference: several tests execute a script file they have just written, and
> under `cargo test` — which runs tests as threads of a single process — another
> thread's `Command::spawn` can fork while the file's write descriptor is still
> open, failing with `ETXTBSY` roughly one run in three. nextest's
> process-per-test isolation removes the race entirely. See [Testing &
> Coverage](testing.md).

### What CI will check

Your pull request has to pass all of these:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo llvm-cov nextest --fail-under-lines 97
cargo test --doc          # llvm-cov skips doc-tests
cargo deny check          # supply-chain audit, against deny.toml
```

Note the coverage floor is enforced, so new code generally needs new tests.
`cargo test --doc` is the only thing that compiles the startup example in
`src/lib.rs`.

### Writing tests
- **Unit Tests:** Keep them close to the code (in the same file, in a `mod
  tests`).
- **Integration Tests:** Located in the `tests/` directory. These tests spin up
  a full in-memory axum router and SQLite database to test the entire ACME flow.

See the [Testing & Coverage](testing.md) page for more details.

## Code style

- Format your code using `cargo fmt`.
- Ensure all lints pass by running `cargo clippy --all-targets -- -D warnings`.
- Document public APIs using rustdoc comments (`///`).
- Comments, doc comments and error-message strings are written in **English**,
  as are identifiers and log messages.
- Every `tracing` call carries `event = "<subsystem>_<outcome>"` as its
  **first** field, as a string literal rather than a computed value, so the name
  stays greppable. Several are asserted by the end-to-end suite — grep before
  renaming one.
- The crate is edition 2024; see `rust-version` in `Cargo.toml` for the minimum
  toolchain.

## Changing the database schema

**`migrations/` is append-only as of 0.1.0.** Add a migration; never edit a
committed one:

```bash
sqlx migrate add add_widget_table
```

`sqlx` tracks each migration by a checksum, so editing a file that has already
run turns every existing deployment into a startup failure. This reverses the
rule that held before the first release, when the server had never been deployed
and a schema change meant editing the migration and running `rm -f sqlite.db*`.

Two consequences:

- **A new column is a new file**, even when it plainly belongs to an existing
  table. `ALTER TABLE ADD COLUMN` is cheap; putting it in the original `CREATE
  TABLE` is what breaks.
- **A new `CHECK`, `UNIQUE` or foreign key needs a table rebuild**, because
  SQLite cannot add one to an existing table. Write the rebuild in the new
  migration, and remember that an `INSERT … SELECT` silently drops any column
  you forget to name.

## Changing a configuration key

The schema is the only frozen surface. Before 1.0.0, renaming or removing a
configuration key is a normal change rather than one to design around — that is
what keeps the code free of a compatibility layer for every shape a section has
ever had. What such a change owes:

- **An entry in the changelog** under the release's `### Breaking` heading,
  naming the old spelling and the new one. See
  [Compatibility](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility).
- **A startup error naming the replacement**, where practical, so an unmigrated
  configuration stops the server instead of coming up looking configured and
  doing nothing. `src/filter/build.rs`'s `refuse_removed_keys` and the
  `signer.backend = "acme_proxy"` arm in `src/signer/mod.rs` are the worked
  examples. A key must still *parse* to be refused by name, which is why the
  removed `[filter]` fields survive in `src/config/types/filter.rs` and in
  `LIST_KEYS`; an unregistered one fails as an opaque serde error instead.
- **No alias, no dual syntax, no legacy lowering.** Delete the old shape. The
  refusals themselves are one-line diagnostics and go away at 1.0.0.

## Submitting a pull request

1. Fork the repository and create your branch from `main`.
2. Write clear, descriptive commit messages.
3. If you've added code that should be tested, add tests.
4. If you've changed APIs, update the documentation in this `mdBook`.
5. Open a PR, describing the problem you're solving and how you fixed it.

## Architecture guidelines

If you are proposing a large feature (like a new Signer or Filter), please
review the [Architecture & Design](architecture.md) documentation first. It's
often best to open an Issue to discuss the design before writing extensive code.
