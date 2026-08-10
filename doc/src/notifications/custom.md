# Custom Script Notifications

The `custom` notification backend runs a local script (Bash, Python, Go, …) when
an ACME event occurs. Use it to integrate with internal ticketing systems,
custom logging infrastructure, or alerting pipelines that a plain HTTP webhook
cannot satisfy.

## Configuration

`custom` is a **named map**, exactly like `[filter.custom]`. Two keys switch it
on: `notify.enabled` activates the backend, and `notify.custom_enabled` selects
*which* scripts run, and in what order.

```toml
[notify]
enabled = ["custom"]
custom_enabled = ["ticket-creator"]

[notify.custom.ticket-creator]
script_path = "/etc/acme-proxy/scripts/ticket-creator.sh"
timeout_ms = 10000
args = []
events = ["certificate_issued", "certificate_revoked"]
```

Three ways to get this wrong, all of which fail at **startup** rather than at
delivery time:

- Listing `"custom"` in `notify.enabled` while `custom_enabled` is empty.
- Naming an entry in `custom_enabled` that has no `[notify.custom.<name>]`
  table.
- Using an entry name outside `^[a-z0-9-]+$` — `ticket_creator` (underscore) is
  rejected; `ticket-creator` is fine.

One process is spawned per enabled script per event.

### Reference

**`script_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__CUSTOM__<NAME>__SCRIPT_PATH`*

Path to the executable. Required.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_NOTIFY__CUSTOM__<NAME>__TIMEOUT_MS`*

Maximum execution time. A script still running when this expires is killed.

**`args`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__CUSTOM__<NAME>__ARGS`*

Static arguments passed to the script on every invocation.

**`events`** (`Array`) — *Default: all six events | Env: `ACME_PROXY_NOTIFY__CUSTOM__<NAME>__EVENTS`*

Which events this script reacts to. Valid names are `profile_mounted`,
`account_created`, `account_deactivated`, `certificate_issued`,
`certificate_revoked`, `challenge_failed`. An unrecognised name is a startup
error.

## Execution model and security

1. **Environment clearing (`env_clear`)**: the child runs with a scrubbed
   environment, inheriting only a minimal `PATH` and the injected
   `ACME_NOTIFY_*` variables. The server's own environment may hold secrets —
   `notify.email.smtp_password`, the RFC 2136 TSIG key, the NetBox token — and a
   notification script has no business reading them.
2. **Zombie prevention (`kill_on_drop`)**: the script runs under a Tokio timeout
   with `kill_on_drop(true)`. A `tokio::time::timeout` only drops the future, so
   without this a timed-out script would outlive its deadline and leak a process
   per event.
3. **Fire and forget**: delivery runs in a background task. A failing or hanging
   script can never delay or fail the ACME response that triggered it; failures
   are logged (`event = "notify_delivery_failed"`) and dropped, with no retry.

## Data passing

The script receives context **both** ways.

### Environment variables

All seven are always set. Ones that do not apply to the event are set to the
empty string rather than omitted, so a script can read them unconditionally.

| Variable | Value |
| --- | --- |
| `ACME_NOTIFY_HOOK` | The event name, e.g. `certificate_issued`. |
| `ACME_NOTIFY_PROFILE` | The profile the event occurred in. |
| `ACME_NOTIFY_CLIENT_IP` | The ACME client's address; empty when no request was in scope (e.g. `profile_mounted`, or an asynchronous relay completion). |
| `ACME_NOTIFY_ACCOUNT_ID` | The account, when the event has one. |
| `ACME_NOTIFY_ORDER_ID` | The order, when the event has one. |
| `ACME_NOTIFY_CERT_SERIAL` | The certificate serial, on `certificate_issued` / `certificate_revoked`. |
| `ACME_NOTIFY_IDENTIFIERS` | Comma-joined identifier values. Only populated for `certificate_issued`. |

> There is no `ACME_NOTIFY_EVENT`; the event name is `ACME_NOTIFY_HOOK`.

### JSON on stdin

A JSON object is **always** written to the script's standard input. It is the
event's own fields plus a `"hook"` key naming the event — the same data the
[templating backends](templates.md) render from. For example, on
`certificate_issued`:

```json
{
  "hook": "certificate_issued",
  "profile": "default",
  "order_id": "…",
  "account_id": "…",
  "cert_serial": "…",
  "identifiers": ["a.example.com", "b.example.com"],
  "client_ip": "203.0.113.5"
}
```

The exact fields per event are listed in [Customizing
Templates](templates.md#context-variables) — the template context and the stdin
payload carry the same values.

> The issued **certificate itself is never passed** to a notification script, on
> stdin or otherwise. Only its serial and the identifiers it covers are
> available. A script that needs the PEM must fetch it out of band.

## Example

```bash
#!/bin/bash
# /etc/acme-proxy/scripts/ticket-creator.sh
set -euo pipefail

payload=$(cat)   # the JSON described above

case "$ACME_NOTIFY_HOOK" in
  certificate_issued)
    echo "issued ${ACME_NOTIFY_CERT_SERIAL} for ${ACME_NOTIFY_IDENTIFIERS}" \
      >> /var/log/acme-issuance.log
    ;;
  certificate_revoked)
    # ACME_NOTIFY_IDENTIFIERS is empty for this event — read the payload
    # if you need more than the serial.
    reason=$(echo "$payload" | jq -r '.reason // "unspecified"')
    curl -sS -X POST https://tickets.internal/api/incidents \
      -H 'Content-Type: application/json' \
      -d "{\"serial\":\"$ACME_NOTIFY_CERT_SERIAL\",\"reason\":\"$reason\"}"
    ;;
esac
```

See [Custom Plugins Examples](../dev/custom_plugins.md) for more.
