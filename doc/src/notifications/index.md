# Notifications

The `notify` subsystem alerts operators on lifecycle events within the ACME
server.

## Supported Events

| Event | Fired when |
| --- | --- |
| `profile_mounted` | A profile is initialized at startup. |
| `account_created` | A client registers a new account. |
| `account_deactivated` | An account is deactivated. |
| `certificate_issued` | An order is finalized and a certificate is minted. |
| `certificate_revoked` | A certificate is revoked, via the ACME API or the admin CLI. |
| `challenge_failed` | A domain-control validation attempt fails. |

These six names are the only valid values wherever a backend's `events` list is
configured. An unrecognised name is a **startup error**, not a silently ignored
entry.

## Backends

- **[Email](email.md)** — SMTP, via `lettre`.
- **[Mattermost](mattermost.md)** — incoming webhooks (Slack-compatible).
- **[Custom Script](custom.md)** — shell out to a local script.

Email and Mattermost render their messages with MiniJinja templates you can
override; see [Customizing Templates](templates.md).

## Configuration

```toml
[notify]
# Which backends are active. Empty (the default) means no notifications at all.
enabled = ["email", "mattermost"]

# Which [notify.custom.<name>] entries to run, when "custom" is listed above.
custom_enabled = []

# Optional directory of template overrides, checked per template file before
# falling back to the compiled-in default.
template_dir = "/etc/acme-proxy/templates"
```

### Reference

**`enabled`** (`Array`)  
*Default: `[]` | Env: `ACME_PROXY_NOTIFY__ENABLED`*  
Active backends: any of `email`, `mattermost`, `custom`. Empty means the
subsystem is off.

**`custom_enabled`** (`Array`)  
*Default: `[]` | Env: `ACME_PROXY_NOTIFY__CUSTOM_ENABLED`*  
Which entries under `[notify.custom.<name>]` to run, and in what order. Listing
`"custom"` in `enabled` while leaving this empty is a startup error, as is naming
an entry that has no table. Same shape as `filter.custom_enabled`.

**`template_dir`** (`String`)  
*Default: `""` | Env: `ACME_PROXY_NOTIFY__TEMPLATE_DIR`*  
Directory searched for template overrides. Lookup is **per file**, so overriding
one message (say `email/certificate_issued.body.j2`) leaves every other message at
its compiled-in default. Empty means defaults only.

Each backend additionally takes its own `events` list and `timeout_ms`; see the
backend pages.

## Delivery semantics

Dispatch is **fire-and-forget**: an event is handed to a background task and the
ACME response proceeds immediately. A notification backend can never delay or
fail the request that triggered it, and failures are logged
(`event = "notify_delivery_failed"`) rather than retried.

The one refinement to "detached": at shutdown the dispatcher makes a bounded
attempt to drain tasks still in flight, so a notification generated moments
before a restart is usually still delivered.
