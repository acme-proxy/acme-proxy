# Profiles

`acme-proxy` is a multi-tenant ACME server. It serves ACME entirely through **Profiles**. 

A single process, running on a single port with a single database, can host multiple isolated ACME endpoints. Each profile is mounted under the `/profile/<name>/directory` namespace.

## Why use Profiles?
- Serve an internal self-signed CA at `/profile/local/directory` for dev environments.
- Serve a strict Let's Encrypt relay at `/profile/prod/directory` for production services.
- Apply different network filters (e.g., strict IP allowlists for production, bypass for dev) without needing to run multiple binary instances.

## Hard Database Isolation
Profiles act as a strict isolation boundary in the SQLite database.

The `accounts` table uses a constraint: `UNIQUE(profile, pubkey)`. 
This means if a client registers a key at `/profile/default`, and then uses the exact same cryptographic key to connect to `/profile/le`, the database creates two **independent ACME accounts**. 
This ensures endpoints cannot cross-pollinate authorizations, orders, or nonces.

## Inheritance and Configuration
Profiles inherit from the base (global) configuration keys. A profile only needs to override the specific keys that differ.

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
signer.backend = "acme_proxy"
signer.acme_proxy.directory_url = "https://acme-v02.api.letsencrypt.org/directory"
filter.enabled = ["allowed_ip"]
filter.allowed_ip.allow = ["10.0.0.0/8"]
```

At runtime, `acme-proxy` deduplicates the signer backends in memory so that two profiles sharing the exact same signer configuration (e.g., two profiles using the same `local_ca`) don't duplicate background polling threads or memory overhead.
