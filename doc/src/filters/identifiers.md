# Identifiers Filter

The `identifiers` filter controls which domains, IPs, or URIs a client is allowed to request a certificate for. This is crucial for preventing a compromised client from requesting a certificate for a sensitive internal domain.

## Type Flattening and `cn` Handling
A Certificate Signing Request (CSR) can contain identifiers in multiple places (Subject Alternative Names (SANs) and the legacy Subject Common Name (CN)). 
`acme-proxy` **flattens** all of these into a single list of typed identifiers (`dns`, `ip`, `email`, `uri`, `other`, `cn`).

- **Deny applies everywhere**: A `deny` rule applies to every single type. If you deny `*.evil.com`, a client cannot sneak it into the Subject Common Name to bypass the filter.
- **Allow skips `cn`**: `allow` rules explicitly skip the `cn` type (`SUBJECT_ONLY_TYPES`). A CN is legacy metadata and often contains human labels (e.g., `"rcgen self signed cert"`). It is not a true identifier the certificate is *for*, so it is exempt from strict allow-listing.

## Regex Anchoring
All matching is performed via Regular Expressions (Regex). 
> **Security Notice**: `acme-proxy` automatically anchors all regexes as `^(?:pattern)$` and makes them case-insensitive.
> You do not need to manually anchor your regexes. This prevents substring bypasses (e.g., an unanchored `example\.com` would accidentally match `example.com.evil.net`).

## Configuration

```toml
[filter.identifiers]
allowed_types = ["dns", "cn"]
allow_wildcards = false
allow = [".*\\.internal\\.corp"]
deny = ["internal\\.corp"]
```

### Reference

**`allowed_types`** (`Array`)  
*Default: `["dns", "cn"]` | Env: `ACME_PROXY_FILTER__IDENTIFIERS__ALLOWED_TYPES`*  
List of identifier types permitted (e.g., `dns`, `ip`, `email`, `uri`, `other`, `cn`).

**`allow`** (`Array`)  
*Default: `[]` | Env: `ACME_PROXY_FILTER__IDENTIFIERS__ALLOW`*  
List of regex patterns to allow.

**`deny`** (`Array`)  
*Default: `[]` | Env: `ACME_PROXY_FILTER__IDENTIFIERS__DENY`*  
List of regex patterns to deny.

**`allow_wildcards`** (`Boolean`)  
*Default: `false` | Env: `ACME_PROXY_FILTER__IDENTIFIERS__ALLOW_WILDCARDS`*  
Whether to allow wildcard CSRs (e.g., `*.example.com`).
