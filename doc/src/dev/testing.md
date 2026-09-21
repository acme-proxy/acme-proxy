# Testing & Coverage

`acme-proxy` relies on a multi-layered testing strategy combining lightning-fast
unit/integration tests with real-world End-to-End (E2E) scenarios.

## Prerequisites

- **cargo-nextest**: The project **requires** `cargo nextest` to execute the
  integration suite. `nextest` runs each test in its own isolated process. This
  is load-bearing because tests involving the `custom` scripts exec generated
  bash files. Under standard `cargo test` (which runs in threads), file
  descriptor sharing causes intermittent `ETXTBSY` failures.
- **llvm-cov**: For coverage reporting.
- **Podman / Docker**: Required for running the E2E suite.

Install the required Rust tools:
```bash
cargo install cargo-nextest cargo-llvm-cov
rustup component add llvm-tools-preview
```

## Running the unit & integration suite

To run the complete in-memory test suite:
```bash
cargo nextest run --workspace
```
These tests utilize an in-memory SQLite database and an in-memory Local CA. No
disk writes or network calls are made.

**A test that calls `Config::load()` holds `ENV_LOCK`**
(`acme_proxy_core::config::ENV_LOCK`, or `testutil::EnvGuard`, which holds it
for you). `ACME_PROXY_*` and `ACME_PROXY_CONFIG` are process state: a test
setting one while another loads makes the second read the first's variables.
There is one lock for every crate on purpose, since a per-module lock would
serialise a module against itself and nothing else.

**A test that triggers a challenge or finalizes an order must poll for the
result.** Validation and issuance run in the job queue, and every test app runs
a real worker, so the response only says `processing`. `await_order` and
`await_challenge` in `tests/common/` are the helpers.

## The `hsm` feature (PKCS#11)

`crates/signer/src/local_ca/pkcs11.rs` is behind the `hsm` feature, so the
command above neither compiles nor lints it — `--all-targets` does not enable
features. Run it explicitly:

```bash
cargo nextest run --workspace --features acme-proxy-signer/hsm
cargo clippy --workspace --all-targets --features acme-proxy-signer/hsm -- -D warnings
```

The PKCS#11 tests create a **SoftHSM2** token in a temporary directory, generate
a P-256 key inside it, self-sign a CA certificate *through the token*, and then
drive the real `LocalCa` end to end — issuing a leaf that must verify against
that CA, and a CRL that must too. The key is generated through `cryptoki`
itself, so `softhsm2` is the only prerequisite; `opensc`/`pkcs11-tool` is not
needed.

```bash
# Debian/Ubuntu
sudo apt install softhsm2
# Arch
sudo pacman -S softhsm
```

When no SoftHSM2 module is found the PKCS#11 tests **skip** with a message
rather than failing, so `--features hsm` stays green without it. CI has a
dedicated `hsm` job — separate from `test` so the coverage floor, which a
feature-gated file sits outside of entirely, does not fight the feature.

> `cargo nextest` matters more than usual here: `SOFTHSM2_CONF` is
> process-global and read at `C_Initialize`, and the PKCS#11 context is cached
> per module for the life of the process. Process-per-test isolation is what
> keeps those from leaking between tests.

## Code coverage

CI enforces a hard floor of **97% of lines**, over every package in the
workspace (`main.rs` is excluded — it is pure socket and exit wiring). The
shortest way to see the same number locally:

```bash
cargo llvm-cov nextest --workspace --summary-only
```

CI splits that in two, because it wants several views of one test run: the run
itself with `--no-report`, then `lcov.info`, an HTML tree and the summary that
gates, each generated from the profiles left on disk.

> **`--workspace` has to reach the report, and the `report` subcommand cannot
> take it.** `cargo llvm-cov report` rejects the flag, and with no package
> selection it measures the package cargo picks — at a root that is also a
> package, the root package alone. Reporting from saved profiles at workspace
> scope is `cargo llvm-cov --no-run --workspace`, which is what CI uses:
>
> ```bash
> cargo llvm-cov --no-run --workspace --summary-only \
>   --ignore-filename-regex 'src/main\.rs' --fail-under-lines 97
> ```
>
> Not `-p` once per member either: a crate built twice under different features
> contributes two coverage maps that way, and its lines are counted twice.

> **Gotcha:** a handler annotated with `#[instrument]` reports far lower
> coverage than it actually has. The attribute moves the body into a generated
> `async` block, so the signature lines show zero hits and the body lines carry
> no region at all — `handlers/authz.rs` sits around 40% while
> `tests/challenges.rs` drives nearly every branch in it. Check `cargo llvm-cov
> report --text` for the file before writing tests against the percentage.
> (Installing a `tracing` subscriber in tests does *not* fix this; measured, it
> moves the total by 0.03 points.)

> **Which is why `crates/admin/src/webadmin/` carries no `#[instrument]` at
all.** It is a
> rule for that module, not a preference: the access middleware already opens
> the request span, so the attribute would buy nothing and cost the module's
> reported coverage.

### The password KDF is slow on purpose

`admin::password` runs PBKDF2-HMAC-SHA256 at 600 000 iterations — roughly 85 ms
in a release build. Unoptimised, `ring` takes **~1.1 s** for the same hash, and
the admin suites pay it at least twice per test (the harness creates an
operator and signs in). With twenty of them in parallel that was most of the
suite's CPU time and a 40-second critical path. So the workspace `Cargo.toml`
builds `ring` at `opt-level = 3` in the dev and test profiles
(`[profile.dev.package.ring]`), which brings a debug build to ~90 ms per hash.
Only `ring` is raised: the loop is compiled entirely inside it, and optimising
the workspace crates instead measurably changes nothing.

The override lives in `Cargo.toml` because nothing else reaches the build
nextest runs: `cargo --config … nextest run` and
`CARGO_PROFILE_DEV_PACKAGE_RING_OPT_LEVEL` are both silently ignored there.

The `admin::password` unit tests still mostly go through a private
`hash_with_iterations` at a cheap setting — the same code path, the same salt
generation and encoding, without 600 000 rounds dozens of times over. Two
deliberately pay the real cost: the encoding must reflect the real constants,
and the dummy hash must cost what a real row costs, or an unknown username would
answer faster and enumerate the operator table.

If you add a test that signs in, expect it to cost one real hash.

## Testing the web admin

`tests/admin_api.rs` drives the real `build_admin_app` through
`tower::ServiceExt::oneshot`, the same way `tests/orders.rs` drives the ACME
side. The harness helpers live in `tests/common/mod.rs`:

| Helper | |
| --- | --- |
| `admin_config()` | a `Config` with `[admin]` enabled |
| `test_admin_app(config)` | the admin router + its database |
| `test_admin_app_with_signer(config)` | also returns the signer, for tests that must *issue* before revoking |
| `test_admin_app_logged_in(config)` | creates one operator, signs in, returns an `AdminSessionHandle` |
| `admin_request(app, method, path, session, body)` | one request, optionally authenticated |
| `admin_login`, `session_cookie_token`, `json_body` | |

`test_admin_app` and `test_app_full` share `one_profile`, so the two cannot
drift into mounting subtly different endpoints.

**The CSRF table is the regression suite.** `mutating_endpoints()` in
`tests/admin_api.rs` lists every unsafe method and path, and two tests assert
each of them refuses a missing, wrong, and foreign token. `AuthenticatedWrite`
already makes the check structural — a mutating handler cannot reach a session
without it — but the residual risk is a new handler taking `Authenticated` by
mistake, and that table is what catches it. **A new endpoint under `/api` that
is not in that list is a review catch.**

## E2E testing (real clients)

The E2E suite spins up complete environments using `testcontainers-rs` to run
real ACME clients (`certbot`, `acme.sh`, `lego`) against the proxy.

The E2E suite is `#[ignore]`d by default to keep the main test cycle fast. You
must have Podman or Docker running.

Run the E2E suite with:
```bash
cargo nextest run -E 'binary(e2e)' --run-ignored all
# or, with plain cargo:
cargo test --test e2e -- --ignored
```

> **Do not run `cargo nextest run e2e`.** nextest's bare positional filter
> matches against test *names*, not binary ids, and none of this suite's test
> names contain the substring "e2e" — so that command silently matches nothing
> and reports `0 tests run` rather than failing. The `-E 'binary(e2e)'`
> expression is what selects the binary.

Rootless Podman is auto-detected: the harness points `DOCKER_HOST` at the user's
podman socket if unset, and fails with a clear message naming `systemctl --user
start podman.socket` rather than starting it itself.

The `tests/e2e/common.rs` harness automatically builds the necessary container
images from the `Containerfile`s in the repository, provisions a dedicated
podman network, and asserts on the container logs. It tests complex scenarios
like Key Rollover (via `lego`), NetBox filter mocks, and full TLS-ALPN-01
responses.
