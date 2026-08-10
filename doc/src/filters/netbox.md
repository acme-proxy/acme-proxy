# NetBox Filter

The `netbox` filter integrates with a NetBox IPAM instance. It allows
`acme-proxy` to query the source of truth to determine if the client IP
requesting the certificate is actually registered and permitted to request the
specific DNS names in the CSR.

## Matching logic
This filter operates exclusively on the `check_identifiers` hook. When a client
finalizes an order:
1. `acme-proxy` takes the client's IP and queries NetBox for the corresponding
   IP address object.
2. It looks for a specific Custom Field (e.g., `acme_allowed_names`) on that IP
   object.
3. If the IP object has no such field, it falls back to checking the parent
   Device or VirtualMachine.
4. It compares the requested identifiers against the allowed names.

> **Exact Matching**: Matching is exact, case-insensitive, and
> trailing-dot-insensitive. If NetBox lists `*.example.com`, the client MUST
> request exactly `*.example.com` (a literal wildcard request). It will not
> magically authorize `foo.example.com`.

## Failure semantics (Internal vs Denied)
The NetBox filter's most consequential design choice is how it handles transport
failures. If NetBox is unreachable, times out, or returns a 500, the filter
returns an `Internal` error, which translates to an HTTP `500 Internal Server
Error` for the ACME client.

**It does NOT return a `Denied` (403).** This ensures that a transient NetBox
outage causes a retryable error for the client, rather than permanently failing
open or permanently refusing the ACME order.

## Configuration

```toml
[filter.netbox]
url = "https://netbox.internal.company.com"
token = "your_netbox_api_token"
custom_field = "acme_allowed_names"
use_dns_name = true
device_fallback = true
ca_cert_path = ""
insecure_skip_verify = false
timeout_ms = 5000
```

### Reference

**`url`** (`String`) — *Default: `""` | Env: `ACME_PROXY_FILTER__NETBOX__URL`*

Base URL of the NetBox instance.

**`token`** (`String`) — *Default: `""` | Env: `ACME_PROXY_FILTER__NETBOX__TOKEN`*

NetBox API token.

**`custom_field`** (`String`) — *Default: `"acme_allowed_names"` | Env: `ACME_PROXY_FILTER__NETBOX__CUSTOM_FIELD`*

Custom field holding the permitted names.

**`use_dns_name`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_FILTER__NETBOX__USE_DNS_NAME`*

Whether the IP address object's own `dns_name` counts as permitted.

**`device_fallback`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_FILTER__NETBOX__DEVICE_FALLBACK`*

Whether to fallback to the assigned device/VM's custom field if the IP has none.

**`ca_cert_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_FILTER__NETBOX__CA_CERT_PATH`*

Extra CA certificates (PEM) to trust for the NetBox connection.

**`insecure_skip_verify`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_FILTER__NETBOX__INSECURE_SKIP_VERIFY`*

Skip verification of NetBox's TLS certificate.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_FILTER__NETBOX__TIMEOUT_MS`*

Timeout budget in milliseconds for the lookup.
