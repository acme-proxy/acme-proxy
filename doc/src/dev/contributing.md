# Contributing to acme-proxy

Thank you for your interest in contributing to `acme-proxy`! Whether you're
fixing a bug, adding a new feature, or improving documentation, your help is
welcome.

## Development environment

To start developing, ensure you have the following installed:
- [Rust](https://rustup.rs/) (latest stable version)
- `sqlite3` (for database inspection, though `sqlx` handles
  migrations)
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
cargo nextest run --workspace
```

`--workspace` is not optional. The repository root is both the `acme-proxy`
package and the root of a workspace of library crates under `crates/`, and a
bare cargo command at such a root acts on the root package alone — the unit
tests of every library crate would simply not run.

> Use `cargo nextest run --workspace`, not `cargo test`. This is a requirement,
not a
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
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov nextest --workspace --fail-under-lines 97
cargo test --workspace --doc   # llvm-cov skips doc-tests
cargo deny check               # supply-chain audit, against deny.toml
RUSTDOCFLAGS="-D warnings -A rustdoc::private_intra_doc_links" \
  cargo doc --workspace --no-deps --all-features   # every intra-doc link
mdbook build doc/ && python3 doc/lint.py           # this book
```

`cargo test --doc` compiles the doc examples but not the intra-doc links, of
which the workspace has a great many; `cargo doc -D warnings` is what catches a
link a rename broke. Private intra-doc links are allowed on purpose: the library
exists for the binary and the tests, and a public item explaining itself by
naming the private thing it delegates to is the good outcome.

`doc/lint.py` holds the book to its own conventions: 80-column prose, no
numbered headings, every fence tagged, every relative link and anchor
resolving, every ADR listed, and **no configuration key documented in two
files** — two copies of a default drift silently.

Two more jobs check what the ones above cannot:

- **`msrv`** reads `rust-version` out of `Cargo.toml` and runs `cargo check
  --locked --workspace --all-targets --all-features` on exactly that toolchain,
  so the minimum stated there is one CI has verified.
- **`hsm`** runs clippy and the suite with `--features acme-proxy-signer/hsm`
  against SoftHSM2. `--all-targets` enables no features, so without this job the
  PKCS#11 code would be neither linted nor tested; it is not folded into the
  coverage job, whose floor a feature-gated file sits outside of.

The `sbom` job additionally regenerates `sbom.cdx.json` and fails if it differs
from the commit — see [Changing dependencies](#changing-dependencies).

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
- Ensure all lints pass by running `cargo clippy --workspace --all-targets -- -D
  warnings`.
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

**`crates/store/migrations/` is append-only as of 0.1.0.** Add a migration; never edit a
committed one:

```bash
sqlx migrate add add_widget_table
```

`sqlx` tracks each migration by a checksum, so editing a file that has already
run turns every existing deployment into a startup failure. One build-system
trap while you work: `sqlx::migrate!()` embeds the set at **compile** time and
adding or removing a file under `crates/store/migrations/` does not on its own
invalidate the build, so a test can be run against the previous set — `touch
crates/store/src/db.rs` after changing the directory. This reverses the rule
that held before the first release, when the server had never been deployed and
a schema change meant editing the migration and running `rm -f sqlite.db*`.

Three consequences:

- **A new column is a new file**, even when it plainly belongs to an existing
  table. `ALTER TABLE ADD COLUMN` is cheap; putting it in the original `CREATE
  TABLE` is what breaks.
- **A new `CHECK`, `UNIQUE` or foreign key needs a table rebuild**, because
  SQLite cannot add one to an existing table. Write the rebuild in the new
  migration, and remember the two things a rebuild loses silently: an
  `INSERT … SELECT` drops any column you forget to name, and `DROP TABLE`
  takes the table's indexes with it — including ones declared in an earlier
  migration, which will not run again to put them back.
- **A wrong declared width is a rebuild too.** SQLite gives `VARCHAR(n)` TEXT
  affinity and enforces no length, so a width that no longer matches its data
  costs nothing at runtime and is wrong everywhere else — in what `.schema`
  tells an operator, and in any port to a dialect that does check.
  `20260826120000_declared_widths_for_random_tokens.sql` is the worked
  example. Where the width follows a constant in `src/`, pin the two together
  with a test; that file's `VARCHAR(43)` is `TOKEN_BYTES` and nothing else, so
  a change to the constant has to reach the schema.

## Adding a configuration key

A key is a field on one of the section structs under
`crates/core/src/config/types/`, with a `#[serde(default)]` that makes the whole
section optional. Beyond the field itself, a new key owes:

- **Documentation in exactly one book page**, as a `### Reference` entry naming
  its environment variable, plus an entry in `config.toml.example` (which a test
  deserializes, so it cannot rot into invalid TOML). `doc/lint.py` refuses a key
  documented in two pages.
- **A decision about scope.** A section listed in `PROFILE_SECTIONS` is
  per-profile and inherited key by key (see [Profiles](../core/profiles.md));
  one describing the process — `[jobs]`, `[audit]`, `[metrics]`, `[proxy]`,
  `[admin]` — is not.
- **A decision about reload.** A reload rebuilds everything from the new
  configuration, so a key reloads unless something snapshots it at startup.
  Only `database.url` is refused on `SIGHUP` (`FROZEN` in
  `crates/server/src/reload.rs`); a new key joins it only with a reason.

**A list-valued key has one more obligation, and one thing to know:**

- `#[serde(deserialize_with = "string_list")]` on the field. An environment
  variable can only carry a string, and this is what splits `a,b` into a list,
  at any depth: inside a profile or inside a named table
  (`[filter.check.<name>]`, `[notify.webhook.<name>]`, …) alike. It also reads
  a variable set to the empty string (a `${VAR:-}` shell default) as `[]`.
  Without it the key loads from a file and fails from the environment;
  `every_list_field_reads_a_comma_separated_string` refuses the omission.
- A value containing a literal comma, such as a regex with `{2,3}`, can only be
  set from the file, since the comma is the separator.

The environment source pins `prefix_separator("_")`. Without it, `config`
reuses the nested separator `__` after the prefix and silently ignores every
`ACME_PROXY_*` variable.

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
  doing nothing. `crates/policy/src/filter/build.rs`'s `refuse_removed_keys` and
  the `signer.backend = "acme_proxy"` arm in `crates/signer/src/lib.rs` are the
  worked examples. A key must still *parse* to be refused by name, which is why
  the removed `[filter]` fields survive in
  `crates/core/src/config/types/filter.rs`; a field that is gone fails as an
  opaque serde error instead.
- **No alias, no dual syntax, no legacy lowering.** Delete the old shape. The
  refusals themselves are one-line diagnostics and go away at 1.0.0.

## Changing dependencies

`sbom.cdx.json` at the repository root is a committed [CycloneDX
1.5](https://cyclonedx.org/) inventory of the dependency closure that ships in
the binary — the artifact ASVS 5.0 V15.1.2 asks for, alongside the `cargo deny`
gate. It is scoped `--all-features --target all`, so the `hsm`/`cryptoki` path
and every platform-gated crate are covered; dev-dependencies are excluded, since
they cannot reach a released build.

Regenerate it after any change to `Cargo.toml` or `Cargo.lock`, and when cutting
a release (it records the crate version). The `sbom` CI job runs the same recipe
and fails on any difference:

```bash
export SOURCE_DATE_EPOCH=0
cargo metadata --locked --format-version 1 >/dev/null
cargo cyclonedx --all-features --target all --spec-version 1.5 \
  --format json --override-filename sbom.cdx -q
jq --arg from "path+file://$PWD" --arg to "path+file:///acme-proxy" \
  'walk(if type == "string" then ((if startswith($from) then $to + .[($from | length):] else . end) | gsub("path\\+file:///acme-proxy#acme-proxy@"; "path+file:///acme-proxy#")) else . end) | del(.metadata.timestamp)' \
  sbom.cdx.json > sbom.cdx.json.tmp
mv sbom.cdx.json.tmp sbom.cdx.json
rm -f crates/*/sbom.cdx.json
```

The tool writes one document per workspace member. The committed one is the
binary's, whose closure already names every library crate, so the per-member
copies are deleted rather than committed.

`cargo install cargo-cyclonedx@0.5.9 --locked` provides the generator; keep the
version in step with the pin in `.github/workflows/ci.yml`, since it is written
into the document. `SOURCE_DATE_EPOCH` makes the output reproducible (it also
suppresses the otherwise-random `serialNumber`); the `jq` pass drops the
wall-clock timestamp and rewrites the `bom-ref` values the tool derives from
the checkout path — both the absolute directory it embeds and the `name@`
segment it drops when that directory's basename happens to equal the crate
name, so the file is identical whether it was regenerated in a worktree named
`acme-proxy` or anything else.

## Cutting a release

Every crate of the workspace is published to crates.io together, at the
binary's version: the library crates are internal, with no semver promise of
their own, and exist on crates.io only so `cargo install acme-proxy` can build.

1. Bump `version` in `[workspace.package]` of the root `Cargo.toml` and every
   `=x.y.z` pin on an `acme-proxy-*` crate in `[workspace.dependencies]`,
   together — the exact pins are what keep the crates in step.
2. Regenerate `sbom.cdx.json` (above); it records the version.
3. Check the whole set packages and builds from its own archives, then publish
   it, in dependency order:

   ```bash
   cargo publish --workspace --dry-run
   cargo publish --workspace
   ```

   Publishing a workspace in one command needs cargo 1.90 or later, below the
   minimum supported Rust version.
4. Once that commit is on `main` and its CI run is green, push the bare version
   as a tag:

   ```bash
   git tag -a 0.6.0 -m 0.6.0 && git push origin 0.6.0
   ```

   The tag triggers `.github/workflows/release.yml`, which builds the image on
   an amd64 and an arm64 runner and publishes `ghcr.io/acme-proxy/acme-proxy`
   as `X.Y.Z` and `latest`, with a provenance attestation.
   [ADR 0012](adr/0012-container-images-are-built-natively-per-architecture.md)
   explains its shape. Its `guard` job stops the release, with nothing
   published, in three cases:

   - **The tag is not the workspace version, or a crate pin is stale.** The
     tag is most likely mistyped: delete it and push the right one. If step 1
     was incomplete, fix the manifest on `main` first.
   - **There is no CI run on `main` for the commit.** The tag is on a commit
     that was never pushed to `main`. Move the tag.
   - **CI is pending or failed.** Wait for it, or fix it, then use
     "Re-run all jobs" on the release run for the same tag.

   To rehearse the workflow without publishing, run it from a branch under
   "Run workflow". It builds both architectures and pushes nothing.

   The first time the package is published, it is private, even though the
   repository is public. In the package's settings, make it inherit access from
   the repository, then check that `podman pull` works with no credentials.

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
