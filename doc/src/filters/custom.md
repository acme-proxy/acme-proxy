# Custom Script Filter

The `custom` filter lets operators write arbitrary scripts (Bash, Python, …) to
decide whether a connection or a CSR should be permitted. Use it for policy that
cannot be expressed with the built-in filters.

## Configuration

```toml
[filter]
rules = ["scripted"]

[filter.check.check-network]
type        = "custom"
script_path = "/etc/acme-proxy/filters/check-network.sh"
timeout_ms  = 5000
pass_stdin  = true
args        = []

[filter.rule.scripted]
when = "check-network"
then = "allow"
```

`custom` is an ordinary check type: there is no separate selection list, because
`filter.rules` already says which checks run and in what order. Several
`[filter.check.<name>]` entries may point at the same script — each is told
which one invoked it through `ACME_FILTER_CHECK_NAME`, so one script can serve
them all and branch on it.

The keys and their defaults are documented under
[Checks](checks.md#keys-by-type). An empty `script_path` on a check some rule
names is a startup error.

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
