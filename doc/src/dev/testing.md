# Testing & Coverage

`acme-proxy` relies on a multi-layered testing strategy combining lightning-fast unit/integration tests with real-world End-to-End (E2E) scenarios.

## Prerequisites

- **cargo-nextest**: The project **requires** `cargo nextest` to execute the integration suite. `nextest` runs each test in its own isolated process. This is load-bearing because tests involving the `custom` scripts exec generated bash files. Under standard `cargo test` (which runs in threads), file descriptor sharing causes intermittent `ETXTBSY` failures.
- **llvm-cov**: For coverage reporting.
- **Podman / Docker**: Required for running the E2E suite.

Install the required Rust tools:
```bash
cargo install cargo-nextest cargo-llvm-cov
rustup component add llvm-tools-preview
```

## Running the Unit & Integration Suite

To run the complete in-memory test suite:
```bash
cargo nextest run
```
These tests utilize an in-memory SQLite database and an in-memory Local CA. No disk writes or network calls are made.

## The `hsm` Feature (PKCS#11)

`src/signer/local_ca/pkcs11.rs` is behind the `hsm` feature, so the command
above neither compiles nor lints it — `--all-targets` does not enable features.
Run it explicitly:

```bash
cargo nextest run --features hsm
cargo clippy --all-targets --features hsm -- -D warnings
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
dedicated `hsm` job — separate from `test` so the 96% coverage floor, which a
feature-gated file sits outside of entirely, does not fight the feature.

> `cargo nextest` matters more than usual here: `SOFTHSM2_CONF` is process-global
> and read at `C_Initialize`, and the PKCS#11 context is cached per module for
> the life of the process. Process-per-test isolation is what keeps those from
> leaking between tests.

## Code Coverage

CI enforces a hard floor with `cargo llvm-cov nextest --fail-under-lines 96`
(`main.rs` is excluded — it is pure socket and exit wiring). Locally:

```bash
cargo llvm-cov nextest --summary-only
```

> **Gotcha:** a handler annotated with `#[instrument]` reports far lower coverage
> than it actually has. The attribute moves the body into a generated `async`
> block, so the signature lines show zero hits and the body lines carry no region
> at all — `handlers/authz.rs` sits around 40% while `tests/challenges.rs` drives
> nearly every branch in it. Check `cargo llvm-cov report --text` for the file
> before writing tests against the percentage. (Installing a `tracing` subscriber
> in tests does *not* fix this; measured, it moves the total by 0.03 points.)

> **Which is why `src/webadmin/` carries no `#[instrument]` at all.** It is a
> rule for that module, not a preference: the access middleware already opens
> the request span, so the attribute would buy nothing and cost the module's
> reported coverage.

### The password KDF is slow on purpose

`admin::password` runs PBKDF2-HMAC-SHA256 at 600 000 iterations — roughly 85 ms
in a release build and **1.3 s in a debug build**, which is what the test suite
runs. Two tests deliberately pay it (the encoding must reflect the real
constants, and the dummy hash must cost what a real row costs, or an unknown
username would answer faster and enumerate the operator table). Everything else
goes through a private `hash_with_iterations` at a cheap setting — the same code
path, the same salt generation and encoding, at a cost the suite can afford.

If you add a test that signs in, expect it to cost one real hash unless you
build the user with a cheap one.

## Testing the Web Admin

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

## E2E Testing (Real Clients)

The E2E suite spins up complete environments using `testcontainers-rs` to run real ACME clients (`certbot`, `acme.sh`, `lego`) against the proxy.

The E2E suite is `#[ignore]`d by default to keep the main test cycle fast. You must have Podman or Docker running.

Run the E2E suite with:
```bash
cargo nextest run -E 'binary(e2e)' --run-ignored all
# or, with plain cargo:
cargo test --test e2e -- --ignored
```

> **Do not run `cargo nextest run e2e`.** nextest's bare positional filter matches
> against test *names*, not binary ids, and none of this suite's test names
> contain the substring "e2e" — so that command silently matches nothing and
> reports `0 tests run` rather than failing. The `-E 'binary(e2e)'` expression is
> what selects the binary.

Rootless Podman is auto-detected: the harness points `DOCKER_HOST` at the user's
podman socket if unset, and fails with a clear message naming
`systemctl --user start podman.socket` rather than starting it itself.

The `tests/e2e/common.rs` harness automatically builds the necessary container images from the `Containerfile`s in the repository, provisions a dedicated podman network, and asserts on the container logs. It tests complex scenarios like Key Rollover (via `lego`), NetBox filter mocks, and full TLS-ALPN-01 responses.
