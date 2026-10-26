# Endpoints

`acme-proxy` is a multi-tenant ACME server. It serves ACME entirely through
**Endpoints**.

A single process, running on a single port with a single database, can host
multiple isolated ACME endpoints. Each endpoint is mounted under the
`/endpoint/<name>/directory` namespace.

## Why use endpoints?
- Serve an internal self-signed CA at `/endpoint/local/directory` for dev
  environments.
- Serve a strict Let's Encrypt relay at `/endpoint/prod/directory` for
  production services.
- Apply different network filters (e.g., strict IP allowlists for production,
  bypass for dev) without needing to run multiple binary instances.

## One process, several endpoints

Everything below the router is per endpoint — its own signer, filters, challenge
validators and EAB policy. Everything above it is shared: one socket, one
database, one process.

```mermaid
graph TD
    REQ["Incoming request"] --> ROOT["Root router<br/>/health, /, tracing, hardening headers"]
    ROOT -->|"/endpoint/dev/*"| PDEV["Endpoint: dev"]
    ROOT -->|"/endpoint/prod/*"| PPROD["Endpoint: prod"]
    ROOT -->|"/endpoint/staging/*"| PSTG["Endpoint: staging"]

    PDEV --> SDEV["signer: local_ca<br/>filters: none"]
    PPROD --> SPROD["signer: relay<br/>filters: ipam"]
    PSTG --> SSTG["signer: local_ca<br/>filters: none"]

    SDEV --> B1["signer backend #1"]
    SSTG --> B1
    SPROD --> B2["signer backend #2"]

    B1 --> DB[("one database<br/>rows tagged by endpoint")]
    B2 --> DB
```

Note the **fan-in**: `dev` and `staging` have identical `[signer]` sections, so
they share one backend instance rather than constructing two. Two endpoints
sharing `ca.key` while differing elsewhere is a startup error: one CA key under
two configurations would issue under two policies from one identity — two
different `crl_distribution_points` for one CRL, say — and that is refused
rather than left to half-work.

## Hard database isolation
Endpoints act as a strict isolation boundary in the database.

The `accounts` table uses a constraint: `UNIQUE(endpoint, pubkey)`. This means
if a client registers a key at `/endpoint/default`, and then uses the exact same
cryptographic key to connect to `/endpoint/le`, the database creates two
**independent ACME accounts**. This ensures endpoints cannot cross-pollinate
authorizations, orders, or nonces.

## Inheritance and configuration
Endpoints inherit from the base (global) configuration keys. An endpoint only
needs to override the specific keys that differ.

**Eight sections can be overridden**, and no others: `signer`, `filter`,
`ipam`, `challenge`, `eab`, `order`, `notify` and `meta`. Everything else — the
listen socket, the database, logging, audit, the admin listener — is
process-wide.

```mermaid
graph LR
    ENV["ACME_PROXY_* env"] --> BASE
    FILE["config.toml"] --> BASE["Base configuration"]
    BASE --> MERGE{{"merge, per key"}}
    OVR["[endpoints.prod]<br/>only the keys that differ"] --> MERGE
    MERGE --> EFF["Effective configuration<br/>for endpoint 'prod'"]
```

**Inheritance is per key, not per section.** An endpoint that sets only
`challenge.bypass` keeps the *global* `challenge.enabled` rather than reverting
it to the compiled default. Arrays, however, replace wholesale — they never
append. Precedence is: endpoint key, then global key, then compiled default.

That split is why `[filter]` is shaped the way it is. `filter.rules` is an
array, so an endpoint naming its own rules replaces the sequence outright —
which is right, because order *is* the policy. `[filter.check.<name>]` and
`[filter.rule.<name>]` are tables, so they merge per key, and an endpoint can
dry-run one rule without restating anything:

```toml
[endpoints.staging.filter.rule.inventory-owned]
mode = "warn"
```

An endpoint inherits every globally defined check and cannot remove one, which
costs nothing: a check no selected rule names is never built. A global
`[filter]` section can therefore carry a library of checks and each endpoint
pick the subset its own `filter.rules` uses.

```toml
[signer]
backend = "local_ca"

[filter]
rules = ["corp-only"] # The base selection; each endpoint may replace it

# The library. Both checks and both rules are declared once, globally.
[filter.check.corp-net]
type  = "allowed_ip"
allow = ["10.0.0.0/8"]

[filter.check.corp-names]
type  = "identifiers"
allow = ["*.corp.example.com"]

[filter.rule.corp-only]
when = "corp-net"
then = "allow"

[filter.rule.named-and-corp]
when = "corp-net and corp-names"
then = "allow"

# Endpoint 1: Uses the global local_ca, and the inherited address-only rule.
# `corp-names` is named by no rule it selects, so it is never built.
[endpoints.default]
enabled = true

# Endpoint 2: Relays to Let's Encrypt, and replaces the selection with the
# stricter rule — which is what pulls `corp-names` into existence here.
[endpoints.le]
enabled = true
signer.backend = "relay"
signer.relay.directory_url = "https://acme-v02.api.letsencrypt.org/directory"
filter.rules = ["named-and-corp"]
```

`acme-proxy filter show --endpoint <name>` prints the built policy for one
endpoint, which is the quickest way to confirm an endpoint selected what you
intended. A check that no selected rule names is reported as
`filter_check_unused` — an advisory, not an error.

At runtime, `acme-proxy` deduplicates the signer backends in memory so that two
endpoints sharing the exact same signer configuration (e.g., two endpoints using
the same `local_ca`) don't duplicate background polling threads or memory
overhead.
