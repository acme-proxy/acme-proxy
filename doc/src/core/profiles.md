# Profiles

`acme-proxy` is a multi-tenant ACME server. It serves ACME entirely through
**Profiles**.

A single process, running on a single port with a single database, can host
multiple isolated ACME endpoints. Each profile is mounted under the
`/profile/<name>/directory` namespace.

## Why use profiles?
- Serve an internal self-signed CA at `/profile/local/directory` for dev
  environments.
- Serve a strict Let's Encrypt relay at `/profile/prod/directory` for production
  services.
- Apply different network filters (e.g., strict IP allowlists for production,
  bypass for dev) without needing to run multiple binary instances.

## One process, several endpoints

Everything below the router is per profile — its own signer, filters, challenge
validators and EAB policy. Everything above it is shared: one socket, one
database, one process.

```mermaid
graph TD
    REQ["Incoming request"] --> ROOT["Root router<br/>/health, /, tracing, hardening headers"]
    ROOT -->|"/profile/dev/*"| PDEV["Profile: dev"]
    ROOT -->|"/profile/prod/*"| PPROD["Profile: prod"]
    ROOT -->|"/profile/staging/*"| PSTG["Profile: staging"]

    PDEV --> SDEV["signer: local_ca<br/>filters: none"]
    PPROD --> SPROD["signer: relay<br/>filters: ipam"]
    PSTG --> SSTG["signer: local_ca<br/>filters: none"]

    SDEV --> B1["Arc&lt;dyn SignerBackend&gt; #1"]
    SSTG --> B1
    SPROD --> B2["Arc&lt;dyn SignerBackend&gt; #2"]

    B1 --> DB[("one SQLite file<br/>rows tagged by profile")]
    B2 --> DB
```

Note the **fan-in**: `dev` and `staging` have identical `[signer]` sections, so
they share one backend instance rather than constructing two. That is not an
optimisation detail — two `local_ca` instances over the same files would each
rewrite the CRL from their own in-memory ledger, so two profiles sharing
`ca.key` while differing elsewhere is a startup error rather than a race.

## Hard database isolation
Profiles act as a strict isolation boundary in the SQLite database.

The `accounts` table uses a constraint: `UNIQUE(profile, pubkey)`. This means if
a client registers a key at `/profile/default`, and then uses the exact same
cryptographic key to connect to `/profile/le`, the database creates two
**independent ACME accounts**. This ensures endpoints cannot cross-pollinate
authorizations, orders, or nonces.

## Inheritance and configuration
Profiles inherit from the base (global) configuration keys. A profile only needs
to override the specific keys that differ.

**Seven sections can be overridden**, and no others: `signer`, `filter`,
`challenge`, `eab`, `order`, `notify` and `meta`. Everything else — the listen
socket, the database, logging, audit, the admin listener — is process-wide.

```mermaid
graph LR
    ENV["ACME_PROXY_* env"] --> BASE
    FILE["config.toml"] --> BASE["Base configuration"]
    BASE --> MERGE{{"merge, per key"}}
    OVR["[profiles.prod]<br/>only the keys that differ"] --> MERGE
    MERGE --> EFF["Effective configuration<br/>for profile 'prod'"]
```

**Inheritance is per key, not per section.** A profile that sets only
`challenge.bypass` keeps the *global* `challenge.enabled` rather than reverting
it to the compiled default. Arrays, however, replace wholesale — they never
append. Precedence is: profile key, then global key, then compiled default.

```toml
[signer]
backend = "local_ca"

[filter]
enabled = [] # By default, no filters

# Profile 1: Uses the global local_ca and no filters
[profiles.default]
enabled = true

# Profile 2: Relays to Let's Encrypt and enforces IP filters
[profiles.le]
enabled = true
signer.backend = "relay"
signer.relay.directory_url = "https://acme-v02.api.letsencrypt.org/directory"
filter.enabled = ["allowed_ip"]
filter.allowed_ip.allow = ["10.0.0.0/8"]
```

At runtime, `acme-proxy` deduplicates the signer backends in memory so that two
profiles sharing the exact same signer configuration (e.g., two profiles using
the same `local_ca`) don't duplicate background polling threads or memory
overhead.
