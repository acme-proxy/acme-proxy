# Custom Script Filter

The `custom` filter lets operators write arbitrary scripts (Bash, Python, …) to
decide whether a connection or a CSR should be permitted. Use it for policy that
cannot be expressed with the built-in filters.

## Configuration

`custom` is a **named map**, so several independent scripts can run in a defined
order. Two keys switch it on: `filter.enabled` activates the filter, and
`filter.custom_enabled` selects which scripts run and in what order.

```toml
[filter]
enabled = ["custom"]
custom_enabled = ["threat-intel"]

[filter.custom.threat-intel]
script_path = "/etc/acme-proxy/scripts/threat-intel.sh"
timeout_ms = 5000
pass_stdin = true
args = ["--strict"]
```

> Entry names must match `^[a-z0-9-]+$`. An underscore — `threat_intel` — is a
> **startup error**, not a warning. So is listing an entry in `custom_enabled`
> with no matching `[filter.custom.<name>]` table.

### Reference

Which entries run, and in what order, is `filter.custom_enabled` — a `[filter]`
key, documented with the rest of them in [Filters](index.md#reference). The keys
below are per entry, and each `<NAME>` in an environment variable is that
entry's own name uppercased.

**`script_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_FILTER__CUSTOM__<NAME>__SCRIPT_PATH`*

Path to the executable script.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_FILTER__CUSTOM__<NAME>__TIMEOUT_MS`*

Maximum execution time in milliseconds.

**`pass_stdin`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_FILTER__CUSTOM__<NAME>__PASS_STDIN`*

Whether to write the JSON context to the script's standard input. Set it to
`false` for a script that reads only environment variables — it then never has
to drain stdin.

**`args`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_FILTER__CUSTOM__<NAME>__ARGS`*

Static arguments passed to the script. The hook is **not** among them; it
arrives as an environment variable.

## Hooks

The script is invoked at both filter hooks, distinguished by `ACME_FILTER_HOOK`:

| `ACME_FILTER_HOOK` | When | Refusal becomes |
| --- | --- | --- |
| `connection` | Every non-exempt request | `403 access_denied` |
| `identifiers` | At `newOrder` and at `finalize` | `403 rejectedIdentifier` (newOrder) / `400 badCSR` (finalize) |

If your script only cares about one hook, branch on this variable and `exit 0`
otherwise — the script is called for both.

## Data passing

### Environment variables

**`connection` hook:**

| Variable | Value |
| --- | --- |
| `ACME_FILTER_HOOK` | `connection` |
| `ACME_FILTER_CLIENT_IP` | The resolved client address, canonicalized (an IPv4-mapped IPv6 address is flattened to IPv4). Empty when unknown. |
| `ACME_FILTER_METHOD` | HTTP method |
| `ACME_FILTER_PATH` | Request path |

**`identifiers` hook:**

| Variable | Value |
| --- | --- |
| `ACME_FILTER_HOOK` | `identifiers` |
| `ACME_FILTER_CLIENT_IP` | As above |
| `ACME_FILTER_ACCOUNT_ID` | The authenticated ACME account |
| `ACME_FILTER_STAGE` | `newOrder` or `CSR` |
| `ACME_FILTER_IDENTIFIERS` | Comma-joined identifier values |

### JSON on stdin

When `pass_stdin` is `true` (the default), a JSON **object** — not a bare array
— is written to the script's standard input.

`connection`:
```json
{"hook":"connection","client_ip":"203.0.113.5","method":"POST","path":"/newOrder"}
```

`identifiers`:
```json
{
  "hook": "identifiers",
  "client_ip": "203.0.113.5",
  "account_id": "…",
  "stage": "newOrder",
  "identifiers": [{"type": "dns", "value": "a.example.com"}]
}
```

`client_ip` is `null` rather than a string when the address is unknown.

At the `CSR` stage the `identifiers` list is the flattened projection of the
whole CSR — SANs *and* the subject Common Name — so entries of type `ip`,
`email`, `uri`, `other` and `cn` appear alongside `dns`. That is deliberate: a
deny rule cannot be dodged by moving a name from a SAN into the CN.

## Return codes

- **`0`** — permitted.
- **Any non-zero exit** — denied. This includes exit code 255 and death by
  signal; the check is simply "did it exit successfully".
- **Timeout, or failure to spawn** — treated as an internal error (`500`), so
  the client retries rather than seeing a permanent refusal.

On denial, the reason sent to the ACME client is the **first non-empty line of
stdout**, falling back to the first non-empty line of stderr, and finally to a
generic "script exited with status …" message. Keep it to one line, and remember
it is client-visible — do not leak internal detail into it.

## Execution model and security

1. **Environment clearing (`env_clear`)**: the child runs with a scrubbed
   environment, inheriting only a minimal `PATH` and the `ACME_FILTER_*`
   variables above. The server's own environment may hold secrets — the RFC 2136
   TSIG key, the NetBox token, the SMTP password — and a filter script has no
   business reading them.
2. **Zombie prevention (`kill_on_drop`)**: execution is wrapped in a Tokio
   timeout with `kill_on_drop(true)`. A timeout alone only drops the future, so
   without this a hung script would outlive its deadline and leak a process per
   request.
3. **Cost**: the `connection` hook runs on **every** non-exempt request,
   including `newNonce`. A script doing network I/O there will dominate your
   latency; prefer the `identifiers` hook when the policy only concerns names.
