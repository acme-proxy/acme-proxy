# Allowed IP Filter

The `allowed_ip` filter provides network-level access control based on the
client's IP address. It can operate as an allowlist, a blocklist, or both.

## How it works
This filter implements standard `allow`/`deny` semantics using CIDR matching:
- **Deny wins**: The `deny` list is checked first. If a client matches any CIDR
  in the deny list, the request is immediately rejected.
- **Allow list**: If an `allow` list is provided, the client must match at least
  one CIDR. If the list is empty, no allow constraint is imposed (functioning
  purely as a blocklist).

## Client IP resolution & proxies
`acme-proxy` resolves the client IP securely. If the server is behind a reverse
proxy, the proxy must be trusted. Trusted proxies are declared under
**`[filter]`**, not `[server]`:
```toml
[filter]
trusted_proxies = ["10.0.0.0/8"]
forwarded_header = "x-forwarded-for"   # the default
```

> **Get the section right.** Unknown keys are ignored rather than rejected, so
> `trusted_proxies` written under `[server]` is silently dropped — no warning,
> no startup error. The forwarded header is then never believed, and every
> request is attributed to the reverse proxy's own address instead of the
> client's.

When a connection originates from a trusted proxy, `acme-proxy` walks the
forwarded-for header right-to-left, skipping trusted hops until it finds the
true client IP. Requests arriving from an address that is *not* in
`trusted_proxies` are attributed to their peer address, and any forwarded header
they carry is ignored — which is what makes a spoofed `X-Forwarded-For` header
useless. IP addresses are canonicalized internally (`IpAddr::to_canonical()`),
meaning IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`) are properly
treated as IPv4.

> **Important (Fail Closed)**: The filter subsystem operates with strict
> fail-closed semantics. If the client IP cannot be determined (e.g.,
> misconfigured reverse proxy or missing `TapIo` wrapper),
> `ConnectionContext::require_client_ip()` fails. The filter will deny access
> rather than assuming the client is safe.

## Configuration

```toml
[filter.allowed_ip]
# Deny external bad actors
deny = ["198.51.100.0/24", "203.0.113.0/24"]
# Allow internal networks
allow = ["10.0.0.0/8", "192.168.0.0/16"]
```

### Reference

**`allow`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__ALLOWED_IP__ALLOW`*

List of CIDRs allowed to connect.

**`deny`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__ALLOWED_IP__DENY`*

List of CIDRs explicitly denied.

If both `allow` and `deny` are empty, `acme-proxy` will emit a fatal error at
startup, as an empty IP filter is a no-op.
