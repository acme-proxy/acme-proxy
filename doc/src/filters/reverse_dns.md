# Reverse DNS Filter

The `reverse_dns` filter provides advanced access control by resolving the
client's IP address back to its associated hostnames via DNS PTR records.

This allows you to write policies based on the physical infrastructure naming
convention rather than static IP addresses, which is incredibly useful in
environments with dynamic IP allocation.

## Resolution logic
When a client connects, the filter performs the following:
1. It queries the DNS for PTR records associated with the client's IP.
2. **Forward Confirmation (Optional)**: If `require_forward_confirm = true` (the
   default), it takes the resulting hostnames and queries their A/AAAA records
   to ensure they point back to the original client IP. This prevents malicious
   actors from setting up a fake PTR record on an IP they control to spoof an
   internal hostname.
3. The resulting, validated hostnames are then checked against the `allow` and
   `deny` regex lists.

> **Crucial Detail**: `acme-proxy` applies the `deny` list across **every** PTR
> candidate returned by the DNS query, not just the one that would otherwise be
> accepted. If a client's IP resolves to `good.internal` AND `evil.hacker.net`,
> and your deny list blocks `evil`, the connection is denied, even if `good`
> matches the allow list.

## Timeout budget
DNS queries happen on the hot path — this is a connection-level filter, so it
runs on **every** non-exempt request, `newNonce` included. The filter operates
with a strict `timeout_ms` budget across all DNS queries so slow nameservers
cannot tie up the ACME server.

To keep that affordable, `reverse_dns` builds its **own, caching** resolver —
deliberately unlike every other DNS consumer in the server, which shares one
uncached resolver. A PTR lookup for an address that keeps connecting is exactly
what a cache is for, whereas the shared resolver must stay uncached so a
`dns-01` TXT record published moments before a challenge is triggered is not
defeated by a cached negative answer. Both honour `dns.resolver`.

## Configuration

```toml
[filter.reverse_dns]
# Require the PTR record to correctly forward-resolve back to the IP
require_forward_confirm = true
timeout_ms = 2000

# Allow connections from any host in the specific internal domain
allow = [".*\\.internal\\.company\\.com"]

# Deny connections from the guest network infrastructure
deny = [".*\\.guest\\.company\\.com"]
```

### Reference

**`require_forward_confirm`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_FILTER__REVERSE_DNS__REQUIRE_FORWARD_CONFIRM`*

Require the PTR record to correctly forward-resolve back to the IP.

**`allow`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__REVERSE_DNS__ALLOW`*

List of regex patterns to allow.

**`deny`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__REVERSE_DNS__DENY`*

List of regex patterns to deny.

**`timeout_ms`** (`Integer`) — *Default: `2000` | Env: `ACME_PROXY_FILTER__REVERSE_DNS__TIMEOUT_MS`*

Timeout budget for DNS queries.
