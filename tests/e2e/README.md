# End-to-end test suite

Real ACME clients (certbot, acme.sh, lego) driven against a real `acme-proxy`,
entirely inside containers started by [`testcontainers-rs`](https://docs.rs/testcontainers).
**Docker or Podman is the only prerequisite** — clients run from images built
from the `Containerfile`s in this tree, and `acme-proxy`/the DNS test server
are built the same way, so nothing needs installing on the host beyond the
container runtime itself.

Beyond the REST-flow checks (register/order/update/deactivate against
`challenge.bypass = true`, the default), this suite covers what a host-based
suite could not without root or extra tooling:

- **dns-01**: needs a real DNS server the test controls, publishing records
  the moment a client asks for one.
- **tls-alpn-01** and **http-01 on their real default ports** (443/80):
  binding a privileged port on the bare host needs root. A container's own
  root can bind <1024 with no host privilege at all (isolated network
  namespace), so this suite exercises the real defaults rather than a
  remapped port.
- **EAB**: needs a key actually provisioned through the admin CLI and a
  server actually configured with `eab.enabled = true` to prove enforcement
  — see "Why `eab.rs` isn't a hardcoded credential" below.
- **`reverse_dns`**: needs a real PTR record, and one client address with a
  forward-confirmed PTR and one address genuinely without one, to prove the
  filter's Denied-vs-Internal split actually works against a real resolver —
  see "reverse_dns: a real bug it caught" below.
- **Admin CLI**: proving `acme-proxy account list`/`order list` reflect
  reality means running them against a database a real client has actually
  written to, not a hand-seeded one.
- **Key rollover**: needs a client that will actually perform RFC 8555
  §7.3.5's nested-JWS dance — see "key_change.rs: the one client left that
  still does this" below.

> An earlier version of this suite was shell scripts driving
> `podman-compose` (`tests/e2e/all`, per-script paths under
> `tests/e2e/{certbot,acme-sh,...}/`). It was fully rewritten in Rust using
> `testcontainers-rs`, compatible with both Podman and Docker; nothing from
> that version remains in this tree.

## Running

```bash
cargo nextest run -E 'binary(e2e)' --run-ignored all   # every scenario
cargo test --test e2e -- --ignored                      # or plain cargo test
```

Every test in this suite is `#[ignore]`d, so a plain `cargo nextest run`/
`cargo test` skips all of them — `-E 'binary(e2e)' --run-ignored all` (or
`--test e2e -- --ignored` with plain `cargo test`) is required to actually
run them. Not run by CI (`.github/workflows/ci.yml` runs neither flag) — this
is a manual check, driven by a real container runtime the CI environment
doesn't provide.

The first run of any test builds seven images (`bind-e2e`, `acme-proxy-e2e`,
`netbox-mock-e2e`, `phpipam-mock-e2e`, `certbot-e2e`, `acmesh-e2e`,
`lego-e2e`), guarded by a
cross-process `flock` so nextest's one-process-per-test model doesn't race
the same `podman build`/`docker build` from multiple tests at once; every
later test in the same run reuses those images. Each test then gets its own
dedicated network and set of containers (`Lab::new` in `common.rs`), torn
down when the test's `Lab` is dropped.

Because `ensure_images_built`'s skip guard is keyed on `NEXTEST_RUN_ID` (a
fresh id every run — see its comment), the seven `build` commands are reissued
on *every* invocation, not just the first ever; whether anything actually
recompiles is entirely down to the container engine's own layer cache. The
three images that compile Rust (`acme-proxy-e2e` from the root
`Containerfile`, `netbox-mock-e2e` and `phpipam-mock-e2e` from their own) use
a
[`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef) three-stage split
(`chef` → `planner` → `builder`) so the dependency-compilation layer is keyed
on `Cargo.toml`/`Cargo.lock` content alone, not the whole source tree — a
source-only edit leaves that layer cached and only re-runs the fast
single-crate final build, instead of recompiling every dependency crate from
scratch on every run. Every stage in every Containerfile under this
directory (and the root one) is `FROM debian:trixie-slim` on purpose, with no
upstream language images and no third-party images — keep it that way rather
than reaching for `rust:*`/`golang:*`/`alpine:*`/`lukemathwalker/cargo-chef:*`
in a future edit. Three of the seven install their tool from source/tarball
instead of `apt` because trixie's packaged version isn't new enough:
`rustc`/`cargo` (1.85 main / 1.94 backports, below this crate's
`rust-version = "1.97"` MSRV) come from `rustup`; Go (trixie's `golang-go` is
1.24, below `lego`'s `go 1.25.0` requirement) comes from the pinned, checksum-
verified tarball at `go.dev/dl`; `acme.sh` has no Debian package at all, so
it's a pinned upstream release tarball, the same reasoning `lego.Containerfile`
already uses for `lego` itself (see "key_change.rs" below).

## Design

`tests/e2e/common.rs`'s `Lab` is the harness every scenario builds on:

- **Image building** (`ensure_images_built`) resolves the container runtime
  (`docker` if present, else `podman`; overridable via `CONTAINER_RUNTIME`),
  points `DOCKER_HOST` at the rootless-Podman socket if it isn't already
  set — failing with a clear message if `podman.socket` isn't already
  active rather than starting it itself — and builds all seven images once
  per run behind the flock described above.
- **`Lab::new(env)`** starts a dedicated bridge network plus `dns`,
  `acme-proxy`, `certbot`, `acme-sh`, `lego`, `netbox-mock` and
  `phpipam-mock` containers. Both mocks start for every lab, so a scenario
  picks its inventory purely through `ipam.backend`.
  `env` is a list of `ACME_PROXY_*` environment variables passed straight to
  the `acme-proxy` container — every scenario knob (`challenge.enabled`,
  `challenge.bypass`, `eab.enabled`, `dns.resolver`, `server.tls.enabled`,
  ...) is an existing config key, so no server code changes are needed to
  make a new scenario testable. A few placeholder tokens
  (`DNS_SERVER_HOST`, `CERTBOT_IP`, `ACMESH_IP`, `LEGO_IP`, `NETBOX_IP`,
  `UPSTREAM_URL`) get substituted with the actual container addresses once
  they're known, so a test can reference "the certbot container's address"
  before that address exists.
- **`Lab::new_with_upstream`** additionally starts a second `acme-proxy`
  instance (for the `relay` relaying signer backend) and
  **`Lab::new_with_files`** copies files into the primary `acme-proxy`
  container *before* it starts, via testcontainers' `with_copy_to` — for
  scenarios like the `custom` signer where `signer.custom.script_path` must
  exist at startup, not be injected into an already-running (and possibly
  already-failed-to-start) container.
- **`exec_in`/`exec_in_with_output`** run a script inside a given container
  (`sh -c <script>`, passed as a single argv element — no host-shell
  quoting to worry about, so multi-line scripts and even raw file contents
  with embedded newlines can be passed directly; no `echo`/backslash-escape
  tricks needed).
- **`get_proxy_logs`/`get_proxy_upstream_logs`/`get_netbox_mock_logs`/
  `get_phpipam_mock_logs`** grep a
  container's log for a marker proving something real happened — the same
  pattern the unit suite uses (e.g. `challenge_dns_01_matched`,
  `certificate_revoked`, `account_key_changed`).
- **`dns_add_a`/`dns_add_ptr`** push real records into the `dns` (BIND)
  container via `nsupdate` over RFC 2136 + TSIG, the same mechanism
  `acme-proxy` itself would use for a real deployment.

## What each scenario proves

- **`certbot.rs`** — the full account lifecycle through certbot: register,
  show account, order, revoke, unregister (deactivate).
- **`acme_sh.rs`** — the same lifecycle through acme.sh: register, order,
  update account contact, deactivate account.
- **`http_01.rs`** / **`dns_01.rs`** / **`tls_alpn_01.rs`** — real challenge
  validation per type (`challenge.bypass = false`), each grepping
  `get_proxy_logs()` for that validator's own success marker
  (`challenge_http_01_matched`, `challenge_dns_01_matched`,
  `challenge_tls_alpn_01_matched`) so a scenario can only pass if the server
  actually ran real validation, not because bypass was left on. See
  "tls-alpn-01: a third client, and real TLS" below for why `tls_alpn_01.rs`
  uses lego instead of certbot/acme.sh.
- **`key_change.rs`** — `POST /keyChange` (RFC 8555 §7.3.5) via lego's
  `accounts keyrollover`. See "key_change.rs: the one client left that still
  does this" below.
- **`eab.rs`** — External Account Binding: a key actually provisioned via
  `acme-proxy eab create`, checked against both the negative case (no EAB
  fields → `externalAccountRequired`) and the positive case for both
  certbot and acme.sh. See "Why `eab.rs` isn't a hardcoded credential" below.
- **`filters.rs`** — one allowed and one denied case per filter
  (`allowed_ip`, `identifiers`, `reverse_dns`, `custom`, `ipam`).
  `allowed_ip`/`reverse_dns` are connection-level filters — they block even
  the unauthenticated `GET /directory` — so their denied case is checked
  with a direct `curl` from inside the denied client's own container rather
  than through the client itself: acme.sh in particular treats an
  unexpected 403 there as transient and burns time retrying before
  surfacing a client-internal error that has nothing to do with the
  server's (correct) refusal. `identifiers` denies at `newOrder`, which
  needs a fully authenticated, signed request, so it drives a real
  `certbot certonly` for both cases and greps certbot's own paraphrase of
  the problem document ("denied by policy") rather than the raw ACME error
  type, since that's what certbot actually prints. `custom` writes a real
  shell script into the `acme-proxy` container (`ACME_FILTER_*` env
  contract) and denies one identifier by name. The `ipam` filter gets three
  scenarios, against the `netbox-mock` and `phpipam-mock` services (small
  Rust `axum` servers answering the endpoints each backend calls — a real
  NetBox is postgres + redis + the application, out of all proportion for
  testing one filter):
  - `test_netbox` proves both the direct IP-object match (certbot owns
    `allowed.example.com`) and the device-fallback path (acme.sh owns
    `machine.example.com` only through the *device* its address is assigned
    to) are wired to real HTTP requests, not just a stub — the denied case
    asks for `machine.example.com` from certbot, a name that exists in
    NetBox and another client legitimately owns, proving the filter binds
    names to the asking address rather than pooling everything NetBox knows.
  - `test_netbox_fhrp_group_membership` turns on the `vip` and `fhrp`
    sources. acme.sh's interface is recorded in FHRP group 41, which holds
    `service.example.com`, and certbot's is in no group: both ask for that
    name and only acme.sh gets it. This is the membership property the source
    exists for — a group is reachable only through an assignment naming the
    client's own interface, never by the name being requested. acme.sh's
    device also carries a role-tagged VIP, so `vip` is exercised in the same
    run.
  - `test_phpipam` is `test_netbox`'s mirror against the other product.
  - `test_phpipam_unknown_address` covers the one behaviour that genuinely
    differs: an address phpIPAM has never heard of answers `404`, which must
    **deny** the order rather than 500 it. It is a separate, TLS-enabled lab
    because lego is the only container the phpIPAM mock holds no row for, and
    lego refuses a plain-HTTP ACME server outright — the same reason
    `key_change.rs` and `tls_alpn_01.rs` enable TLS for their lego runs. Any
    new lego scenario needs `ACME_PROXY_SERVER__TLS__ENABLED=true` plus
    `--tls-skip-verify`, and `lego run` takes its flags *after* the
    subcommand, not before it.
- **`profiles.rs`** — two ACME endpoints (`default`/`second`) in one
  process: cross-profile isolation, per-profile CAs and filters, distinct
  CRLs.
- **`admin_cli.rs`** — registers and orders through certbot, then runs
  `acme-proxy account list --json`/`order list --json` inside the *running*
  `acme-proxy` container and asserts the output names the same contact and
  identifier the client used — proving the admin CLI reads the same
  database a real deployment would, not a hand-seeded fixture. Like `eab
  create`, its tracing output lands on stdout ahead of its own JSON, so the
  test pulls out the line that looks like JSON rather than assuming the
  whole output parses.
- **`custom_signer.rs`** — `signer.backend = "custom"`, delegating issuance
  to a real, self-contained `openssl`-backed script (not a stub) copied into
  the `acme-proxy` container via `Lab::new_with_files` before it starts. The
  issued leaf's issuer is checked against the script's own CA, proving
  delegation actually happened rather than falling back to `local_ca`'s
  default one.
- **`relay_signer.rs`** — the relaying `relay` signer backend
  against a second `acme-proxy` instance (`Lab::new_with_upstream`), both
  the `bypass` and `dns01` upstream challenge strategies.
- **`ari.rs`** — `GET /renewalInfo/{certID}` (RFC 9773): a real certificate
  is issued, its serial extracted with `openssl`, and the resulting ARI URL
  is checked for a `suggestedWindow`.

## Why `eab.rs` isn't a hardcoded credential

An earlier version of this check sent a hardcoded kid/HMAC pair that was
never created through `acme-proxy eab create` and ran against a server left
at the default `eab.enabled = false` — so even executed by hand it never
validated server-side enforcement. `eab.rs` provisions a real key via the
admin CLI against a server with EAB actually turned on.

## tls-alpn-01: a third client, and real TLS

Neither certbot nor acme.sh implement a tls-alpn-01 responder (unlike
http-01/dns-01, which both expose hooks a script can drive). lego
(`github.com/go-acme/lego`) does, via `--tls`, so it's used as a
supplementary third tool for `tls_alpn_01.rs` — not a replacement for
certbot/acme.sh anywhere else in this suite.

`tls_alpn_01.rs` is also the one `http_01`/`dns_01`/`tls_alpn_01` scenario
that turns `server.tls.enabled` on: lego refuses a plain-http directory URL
outright (an unconditional check with no bypass flag, unlike certbot/acme.sh
which tolerate it), so `acme-proxy` serves HTTPS with the self-signed
certificate `tls::from_config` generates on first run, and lego is given
`--tls-skip-verify` to accept it.

## key_change.rs: the one client left that still does this

RFC 8555 §7.3.5 account key rollover used to have client-driven coverage via
acme.sh's `--update-account-key`. That flag no longer exists: acme.sh
removed it with no replacement (confirmed by grepping the installed
script's own `--help` output and source — no `--update-account-key`,
`--rotate-account-key`, or any other rollover command remains). certbot has
never had it — its vendored `acme` library (`acme.messages`/`acme.client`)
implements no key-change request at all (confirmed the same way: nothing
matching `key`/`change`/`rollover` in either module), and the feature
request (certbot/certbot#9761) has sat open and unplanned.

lego added `accounts keyrollover` in v5.0.0 (go-acme/lego#2950). Alpine's
`lego` package is still on the 4.x line (which predates it), so
`tests/e2e/lego.Containerfile` builds a pinned v5.3.1 release from source
instead of `apk add lego` — the same version the pre-rewrite shell suite
pinned as `docker.io/goacme/lego:v5.3.1`, which is presumably why this went
unnoticed until the client images were rebuilt locally. `key_change.rs`
issues a certificate, rolls the account key over (`lego accounts
keyrollover`, confirmed non-interactively with a piped `Y`), then issues a
second certificate on the same account to prove the *new* key is what
actually works afterward, not just that lego believes the rollover
succeeded — the same "prove the real effect" pattern every other scenario
here relies on (`get_proxy_logs()` for the `account_key_changed` marker).

## reverse_dns: a real bug it caught

Running this for the first time caught a real, pre-existing bug: `certbot`
(with a PTR record) passed immediately, but `acme-sh` (without one) got a
**500** instead of the expected 403. `reverse_dns.rs`'s unit tests
deliberately distinguish "no PTR record" (`FilterError::Denied`, the
client's fault) from "the resolver failed" (`FilterError::Internal`, ours)
— but `HickoryResolver::reverse`/`forward`/`txt` (`src/dns.rs`) surfaced
*both* NXDOMAIN and an empty NOERROR answer as `Err`, never as `Ok` with
zero records, so the "no PTR record" branch was unreachable outside of a
test using a hand-written stub. Every existing Rust unit test for
`reverse_dns` does exactly that — stubs the resolver by hand — so nothing
had ever exercised this against a real one before. Fixed by checking
hickory's own `NetError::is_no_records_found()` in all three methods before
treating a lookup failure as an error; `dns_01.rs`'s server-side validator
was never affected, since both cases already mapped to the same
`ChallengeError::Dns` there.

## Known gaps / follow-up (not in this pass)

- **`server.tls.enabled`** as a feature in its own right (independent of
  what `tls_alpn_01.rs` needs to make lego work) isn't exercised here.
- A hand-built-JWS scenario for certbot's key rollover (using its vendored
  `acme.jws`/`josepy` libraries directly, since its CLI exposes no command)
  was prototyped and works, but wasn't kept: it would mean re-implementing
  a meaningful slice of this server's own JWS logic inside the test rather
  than exercising a real client's own documented interface, and
  `key_change.rs` already gets equivalent real-client coverage more cheaply
  via lego.
