# Contributing to acme-proxy

Contributions are welcome. The full guide — development environment, test
layout, coverage, and how to change the schema — is the
[Contributing](https://acme-proxy.github.io/acme-proxy/dev/contributing.html)
chapter of the book, with the design background in
[Architecture](https://acme-proxy.github.io/acme-proxy/dev/architecture.html).

This file exists so the guidance is one click away from the repository, and to
state the three things that trip up a first change.

## Three things to know before your first change

**Run `cargo nextest run`, not `cargo test`.** This is required, not preferred.
Several tests execute a script file they have just written; under `cargo test`,
which runs tests as threads of one process, that intermittently fails with
`ETXTBSY` — another thread's `Command::spawn` forks while the write descriptor
is still open. Nothing in the test can avoid it. nextest's process-per-test
isolation removes it entirely.

```bash
cargo install cargo-nextest
cargo nextest run
```

**`migrations/` is append-only — and it is the only thing that is.** Every file
there is frozen as of 0.1.0. `sqlx` records each migration's checksum, so
editing a committed file makes every existing deployment fail at startup with a
mismatch — it does not silently diverge. A schema change is
`sqlx migrate add <name>`, always. Two consequences catch people out: a new
column is a **new file** even when it obviously belongs to an existing table,
and a new `CHECK`/`UNIQUE`/foreign key needs a full table rebuild, because
SQLite cannot add one in place.

Everything else is fair game before 1.0.0 — renaming or removing a configuration
key is a normal change, not one to avoid. What it owes: an entry in
[`CHANGELOG.md`](CHANGELOG.md#compatibility) under `### Breaking`, and a startup
error naming the old spelling and the new one where practical, so an unmigrated
configuration stops the server rather than coming up looking configured. Never
an alias or a dual syntax — delete the old shape.

**CI is strict about formatting and lints.** `cargo fmt --all --check` and
`cargo clippy --all-targets -- -D warnings` both gate the build, as does a
coverage floor. Run them before pushing:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo nextest run
```

## Documentation changes

The book lives in `doc/` and is built with
[mdBook](https://rust-lang.github.io/mdBook/):

```bash
cargo install mdbook mdbook-mermaid
mdbook serve doc/          # http://localhost:3000
python3 doc/lint.py        # style gate: wrapping, links, anchors, duplicate keys
```

`doc/lint.py` checks the mechanical half of the house style — 80-column prose,
no numbered headings, tagged code fences, resolving links and anchors, and no
configuration key documented in two files. CI runs it, so run it locally first.

Adding a page means adding it to `doc/src/SUMMARY.md` as well: `create-missing`
is off, so a `SUMMARY` entry with no file fails the build rather than creating a
stub.

## Reporting a security issue

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
