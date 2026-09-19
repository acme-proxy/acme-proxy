# ADR 0009: Dependencies are pure Rust on `ring`, add no global state, and earn their place

## Status

Accepted. The metrics clause is superseded by
[ADR 0011](0011-metrics-on-prometheus-client.md): latency histograms were the
case where a metrics library would earn its place, and they arrived.

## Context

A certificate authority's dependency graph is part of its attack surface, and
this one is audited by `cargo deny` at `all-features = true` and inventoried in
a committed SBOM. Every crate added is one more crate to audit, one more licence
to allow, and one more release to track.

Two kinds of cost are easy to miss when choosing a dependency:

- **A second crypto stack or a C toolchain.** `aws-lc-rs` or OpenSSL makes the
  build depend on a C compiler, and it means two implementations of the same
  primitives to keep patched.
- **Process-global state.** A library that installs a global (a rustls
  `CryptoProvider::install_default`, a metrics recorder, a global HTTP client)
  makes behaviour depend on which code ran first. In a test suite that means two
  tests sharing counters or a provider, with the outcome depending on test
  order.

## Decision

- **`ring` is the only crypto backend.** `rcgen`, `rustls`, `tokio-rustls`,
  `hickory-proto`'s TSIG signing and `lettre`'s SMTP TLS are all built on it.
  There is no `aws-lc-rs`, no `native-tls` and no OpenSSL. `subtle` supplies the
  one constant-time comparison `ring` no longer offers.
- **No global installs.** The rustls provider is passed to every config builder
  explicitly and never installed as the process default. The metrics registry is
  a value held by the assembly, never a global recorder.
- **Prefer an edge to a crate.** Before a new crate is added, check whether the
  capability is already in the graph through something else. `hyper` (via
  `axum`), `hickory-proto` (via the resolver), `x509-parser` (via `rcgen`),
  `percent-encoding` (via `url`) and `subtle` (via `rustls`) were each promoted
  to direct dependencies rather than replaced by a fresh one.
- **Hand-roll a small, stable protocol rather than import a stack.** Examples:
  - RFC 6238 TOTP on `ring`;
  - password hashing with `ring`'s PBKDF2 rather than four crates for Argon2;
  - the relay's ACME client on `hyper`;
  - the Prometheus text format.

  Each is a page of code against a frozen specification, with its own tests.
- **Choose by maintenance and safety as well as features.** For example,
  `cryptoki` rather than `pkcs11`, because it wraps sessions in safe types and
  tracks the OASIS specification.
- **Each dependency's own reason stays beside it** in `Cargo.toml`, as a
  one-line comment.

## Consequences

- `cargo build` needs only a Rust toolchain.
- A test can build two registries or two TLS configurations without them
  interfering with each other.
- A hand-rolled protocol is code this project owns. Each one carries its own RFC
  test vectors (HOTP and TOTP) or an end-to-end test against a real counterpart
  (the relay client against the e2e lab's ACME server).
- The validators deliberately trust no root store (RFC 8555 §8.3, RFC 8737 §3:
  the responder's certificate is the proof, not an identity). The relay client
  is the opposite case, a client of a real CA, and uses `webpki-roots`.
- When a library would genuinely earn its place, as histograms would for
  metrics, adopting it is a new decision that supersedes this one for that
  subsystem.

## Enforced by

- `cargo deny check` with `all-features = true` (`deny.toml`), and the SBOM
  drift check (the `supply-chain` and `sbom` CI jobs).
- Otherwise review only.
