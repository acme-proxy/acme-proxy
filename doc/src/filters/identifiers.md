# Identifiers Filter

The `identifiers` filter controls which domains, IPs, or URIs a client is
allowed to request a certificate for. This is crucial for preventing a
compromised client from requesting a certificate for a sensitive internal
domain.

## Type flattening and `cn` handling
A Certificate Signing Request (CSR) can contain identifiers in multiple places
(Subject Alternative Names (SANs) and the legacy Subject Common Name (CN)).
`acme-proxy` **flattens** all of these into a single list of typed identifiers
(`dns`, `ip`, `email`, `uri`, `other`, `cn`).

- **Deny applies everywhere**: A `deny` rule applies to every single type. If
  you deny `*.evil.com`, a client cannot sneak it into the Subject Common Name
  to bypass the filter.
- **Allow skips `cn`**: `allow` rules explicitly skip the `cn` type
  (`SUBJECT_ONLY_TYPES`). A CN is legacy metadata and often contains human
  labels (e.g., `"rcgen self signed cert"`). It is not a true identifier the
  certificate is *for*, so it is exempt from strict allow-listing.

## Regex anchoring
All matching is performed via Regular Expressions (Regex).
> **Security Notice**: `acme-proxy` automatically anchors all regexes as
> `^(?:pattern)$` and makes them case-insensitive. You do not need to manually
> anchor your regexes. This prevents substring bypasses (e.g., an unanchored
> `example\.com` would accidentally match `example.com.evil.net`).

## Configuration

```toml
[filter]
rules = ["corp-names-only"]

[filter.check.corp-names]
type = "identifiers"
allowed_types = ["dns", "cn"]
allow = ["*.corp.example.com", "corp.example.com"]
deny  = ["secret.corp.example.com"]
allow_wildcards = false

[filter.rule.corp-names-only]
when = "corp-names"
then = "allow"
```

`allow`/`deny` take globs, where `*` is one label — so `*.corp.example.com` does
not cover `corp.example.com` and both are listed, exactly as they would be in a
certificate. `allow_regex`/`deny_regex` take anchored regexes and are unioned
with the globs, for what a glob cannot express. The keys and their defaults are
documented under [Checks](checks.md#keys-by-type).

Two instances of this type with different lists are ordinary, which is the usual
way to say "these names from this network, those names from that one":

```toml
[filter.rule.tenant-a]
when = "tenant-a-net and tenant-a-names"
then = "allow"

[filter.rule.tenant-b]
when = "tenant-b-net and tenant-b-names"
then = "allow"
```
