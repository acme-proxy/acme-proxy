# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation

- Four new chapters: **Protocol Support** (an RFC 8555 conformance summary and
  what is deliberately not implemented), **Security Model** and **Hardening
  Checklist**, and **Database Schema** — the eleven tables, their constraints,
  and why `audit_log` deliberately has no foreign keys.
- Fourteen diagrams where prose was carrying branching, positional or state
  facts: the JWS verification pipeline, the order and authorization state
  machines, the relay's two stacked ACME conversations, the filter hooks on the
  request path, the MFA sign-in states, deployment topology, and an ER diagram
  of the schema.
- `[challenge]`'s keys were documented both in the configuration reference and
  in the challenges chapter, and the two copies had drifted. The chapter now
  owns them, and the reference carries an index of **every** section — with the
  seven that a `[profiles.<name>]` block may override marked as such, a fact
  that had not been written down anywhere.
- One voice across the book: sentence-case headings, no numbered headings for
  unordered content, 80-column prose, and no marketing register.
- `config.toml.example` gained a section index and per-section markers for what
  is overridable per profile.
- `CONTRIBUTING.md` and `SECURITY.md`, issue and pull-request templates, README
  badges, a container install path and the MSRV stated numerically.

### Added

- `doc/lint.py`, a style and link gate for the book, run by a new **docs** CI
  job that builds the book on pull requests — the deploy workflow only ran after
  merge, so a broken `SUMMARY.md` entry was previously found too late.

### Changed

- `Cargo.toml` declares `description`, `repository`, `documentation`, `homepage`,
  `readme`, `keywords` and `categories`, and a `docs.rs` block building with all
  features, so the PKCS#11 module is documented rather than absent.
- Crate-level and module-level rustdoc: the module map now covers the web admin,
  the audit trail and the CLI, and the six modules that had no `//!` at all —
  `handlers`, `extractors`, `sqlite`, `admin`, `middlewares`, `cli` — have one.
  The `notify` payload structs, a plugin-facing data contract, are documented.

### Fixed

- Two French comments in `src/handlers/helpers.rs`, contrary to the project's
  stated English-only rule.
- The `### Reference` entries throughout the book depended on invisible trailing
  double-spaces for their line breaks, which an editor trimming on save would
  have silently broken — and had already broken in twelve places. They are now a
  single line that cannot break that way.
- Several run-on paragraphs in the troubleshooting guide, where
  `Symptoms`/`Cause`/`Fix` lines were rendering joined into one block.
- `mdbook.yml` pinned `mdbook-version: latest` and installed `mdbook-mermaid`
  from source; both tools are now version-pinned, and every action in that
  workflow is SHA-pinned like `ci.yml`'s.

## [0.1.0] — 2026-08-09

First release.

### The compatibility promise

**The database schema is frozen.** `migrations/` is append-only from this release
on: a schema change is a new migration file, never an edit to a committed one.
Upgrading is therefore just starting the new binary against the existing
database — there is no dump/restore step, and no upgrade procedure beyond
replacing the binary.

Everything else may still move before 1.0.0 — configuration keys, the JSON admin
API, and log event names. Breaking changes will be listed here.

### ACME (RFC 8555)

- The full flow: `newNonce`, `newAccount`, `newOrder`, authorizations,
  challenges, `finalize`, certificate retrieval, and `POST`-as-`GET` throughout.
- Certificate revocation (§7.6), authorized by either the order's account key or
  the certificate's own key pair.
- Account management: contact updates, deactivation, and find-or-create by public
  key.
- Authorization deactivation (§7.5.2).
- Problem documents (`application/problem+json`) for every refusal, with
  `subproblems` on multi-identifier rejections (§6.7.1).
- Directory `meta` members, including a terms-of-service requirement that
  `newAccount` then enforces (§7.3.3).

### Extensions

- **External Account Binding** (§7.3.4) — credentials minted out of band, stored
  in the database and revocable without a restart.
- **Key rollover** (§7.3.5).
- **Renewal Information / ARI** (RFC 9773) — renewal windows, `explanationURL`
  passthrough, and `replaces` on `newOrder`.

### Challenge validation

- `http-01`, `dns-01` and `tls-alpn-01`, selectable per profile, validated inline
  under a configurable timeout.
- Wildcard identifiers, accepted only where `dns-01` is enabled.
- Validation is **on by default**; `challenge.bypass` turns it off for testing.

### Signer backends

- `local_ca` — an embedded CA that generates itself on first run, issues leaves,
  and publishes an RFC 5280 CRL at `GET /crl`. The issuing key may live in a
  **PKCS#11 token** (`--features hsm`).
- `acme_proxy` — relays to a real upstream ACME CA, solving the upstream's
  challenges itself via RFC 2136 dns-01, an http-01 responder, or bypass. One
  upstream account multiplexed across every local client.
- `custom` — delegates issuance and revocation to an operator-supplied script.

### Access control

- Pluggable filters, off by default: `allowed_ip`, `reverse_dns`, `identifiers`,
  `netbox` (IPAM-backed) and `custom`.
- Client-address resolution through trusted proxies, with a configurable
  forwarded-for header.

### Profiles

- Several independent ACME endpoints in one process, over one listener and one
  database, each with its own signer, filters, challenge validators and EAB
  policy. Accounts and orders are isolated per profile.

### Traceability and audit

- Accounts and orders record the address and reverse name they were created
  from; accounts additionally record where their key was last seen.
- An append-only `audit_log`, one row per CA action **and per refusal**, carrying
  the actor, address, reverse name, identifiers, User-Agent and request id.
- Readable through `acme-proxy audit list|show`, `GET /api/audit` and `/ui/audit`;
  pruned only from the host or by `audit.retention_days`.

### Administration

- An admin CLI in the same binary: accounts, orders, the audit trail, nonces, EAB
  credentials, upstream registration, revocation, and web admin operators.
- An optional **web admin** on its own listener, serving HTML pages and a JSON
  API over the same operations — behind password authentication, a TOTP second
  factor with recovery codes, session cookies, CSRF and origin checks, and a
  login rate limiter. Off by default, loopback by default, and it refuses to bind
  elsewhere without TLS.

### Operations

- Optional TLS termination on either listener, from supplied PEM or a
  self-signed certificate generated on first run.
- Notifications on issuance, revocation, account and challenge events, over
  email, Mattermost/Slack webhooks or a custom script.
- Structured logging with stable `event` names, request correlation, and an
  access line; JSON output for log pipelines.
- Admission control, request timeouts and body limits on the ACME routes.
- Graceful shutdown on SIGTERM.

[Unreleased]: https://github.com/acme-proxy/acme-proxy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/acme-proxy/acme-proxy/releases/tag/v0.1.0
