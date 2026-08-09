# acme-proxy

An ACME (RFC 8555) server in Rust, built on [axum](https://docs.rs/axum). It sits
between your internal clients — certbot, acme.sh, lego, Traefik, Caddy — and the
certificate authority that actually signs, whether that is an embedded local CA,
an upstream public CA, or a legacy PKI reached through a script.

📖 **[Full documentation](https://acme-proxy.github.io/acme-proxy/)** — start with the
[Quick Start](https://acme-proxy.github.io/acme-proxy/getting_started/quick_start.html).

> **First release (0.1.0).** The database schema is frozen: `migrations/` is
> append-only from here, so upgrading is a matter of starting the new binary
> against the existing database. Everything else — configuration keys, the JSON
> admin API, log event names — may still move before 1.0.0, and breaking changes
> will be called out in [CHANGELOG.md](CHANGELOG.md).

## Why

Internal hosts need TLS certificates, but they cannot easily satisfy a public CA:
they are unreachable from the Internet, and handing every one of them DNS API
credentials — or a scarce commercial EAB credential — is not an option.

`acme-proxy` terminates ACME locally. Clients prove control to *it*, under
whatever policy you configure, and it decides how the certificate is actually
produced.

## Signer backends

| Backend | What it does |
| --- | --- |
| `local_ca` | Signs directly with an embedded CA (self-generated, or your own intermediate). Publishes a CRL. The issuing key can live in a **PKCS#11 token** (YubiKey, HSM) instead of a file — `--features hsm`. |
| `acme_proxy` | Relays to a real upstream ACME CA, solving the upstream's DNS-01 challenges itself with a single centrally held RFC 2136 TSIG key. One upstream account multiplexed across all your clients. |
| `custom` | Shells out to a script — for a legacy PKI, an HSM, or an internal API that does not speak ACME. |

## Features

- **Full RFC 8555 flow** — account, order, authorization, challenge, finalize,
  certificate, plus revocation and `POST`-as-`GET`.
- **All three challenge types** — `http-01`, `dns-01`, `tls-alpn-01`, with
  wildcard support via `dns-01`. Validation is on by default.
- **Profiles** — several independent ACME endpoints in one process, over one
  listener and one database, each with its own signer, filters, challenges and
  EAB policy. Accounts and orders are isolated per profile.
- **Access control** — IP allowlists, forward-confirmed reverse DNS, identifier
  allow/deny rules, a NetBox IPAM integration, and custom script hooks.
- **Extensions** — External Account Binding (§7.3.4), key rollover (§7.3.5),
  Renewal Information / ARI (RFC 9773).
- **Notifications** — email, Mattermost/Slack webhooks, or a custom script, on
  issuance, revocation, account and challenge events.
- **Audit trail** — one row per issuance *and per refusal*, naming the actor, the
  address it came from, that address's reverse name, the identifiers and the
  request id. Accounts and orders additionally record where they were created
  and last seen from. Nothing is ever compared against these; they answer "who
  asked for this certificate, and from where".
- **Admin CLI** in the same binary — accounts, orders, the audit trail, EAB
  credentials, upstream registration, revocation.
- **Web admin** (optional, off by default) — a second listener serving both HTML
  pages and a JSON API over the same operations, behind password authentication,
  a TOTP second factor with recovery codes, and a session cookie. Loopback by
  default; refuses to bind elsewhere without TLS.
- **Optional TLS termination**, or run it behind a reverse proxy.

## Quick start

```toml
# config.toml
[challenge]
bypass = true          # testing only — see the docs before deploying

[profiles.default]
```

```bash
cargo build --release
./target/release/acme-proxy serve
```

The ACME directory is then at
`http://localhost:3000/profile/default/directory`. Point a client at it:

```bash
certbot certonly --server http://localhost:3000/profile/default/directory \
  --standalone -d internal.example.com --agree-tos -m admin@example.com
```

`serve` is the default subcommand. Configuration comes from `config.toml` in the
working directory (or `ACME_PROXY_CONFIG`), overridden by `ACME_PROXY_*`
environment variables; `config.toml.example` documents every key.

## Building & testing

Requires a Rust toolchain matching `rust-version` in `Cargo.toml` (edition 2024).

```bash
cargo build
cargo nextest run       # NOT `cargo test` — see doc/src/dev/testing.md
cargo fmt
cargo clippy --all-targets -- -D warnings
```

`cargo nextest` is required rather than preferred: several tests execute script
files they have just written, which fails intermittently with `ETXTBSY` under
`cargo test`'s thread-per-test model.

The end-to-end suite runs real ACME clients against a real server in containers
and is `#[ignore]`d by default:

```bash
cargo nextest run -E 'binary(e2e)' --run-ignored all
```

## Documentation

The book under `doc/` is built with [mdBook](https://rust-lang.github.io/mdBook/)
and published on every push to `main`:

```bash
cargo install mdbook mdbook-mermaid
mdbook serve doc/
```

Contributions welcome — see
[Contributing](https://acme-proxy.github.io/acme-proxy/dev/contributing.html).

## License

MIT
