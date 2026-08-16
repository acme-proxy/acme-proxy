# Notifications

The `notify` subsystem alerts operators on lifecycle events within the ACME
server.

## Supported events

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

**`enabled`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__ENABLED`*

Active backends: any of `email`, `mattermost`, `custom`. Empty means the
subsystem is off.

**`custom_enabled`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__CUSTOM_ENABLED`*

Which entries under `[notify.custom.<name>]` to run, and in what order. Listing
`"custom"` in `enabled` while leaving this empty is a startup error, as is
naming an entry that has no table.

**`template_dir`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__TEMPLATE_DIR`*

Directory searched for template overrides. Lookup is **per file**, so overriding
one message (say `email/certificate_issued.body.j2`) leaves every other message
at its compiled-in default. Empty means defaults only.

Each backend additionally takes its own `events` list and `timeout_ms`; see the
backend pages.

## Delivery semantics

Dispatch is **fire-and-forget**: the event is written to the durable job queue
and the ACME response proceeds immediately. A notification backend can never
delay or fail the request that triggered it.

Delivery itself is a `notify_deliver` job, one row **per backend per event**, so
one flaky webhook is retried without re-sending through an email backend that
already succeeded. Two consequences worth planning around:

- **A row outlives the process that wrote it.** A notification generated moments
  before a restart is delivered by whoever starts next, rather than lost. There
  is no drain at shutdown to configure or wait for.
- **A failure is retried, unless it never could have worked.** A refused SMTP
  connection, a timeout, a 429 or a 5xx from a webhook goes back in the queue
  under `jobs.max_attempts` and the shared backoff. A template that does not
  render, a `webhook_url` that does not parse and any other 4xx are refused on
  the first attempt — retrying would reach the same answer four more times and
  delay the log line saying so.

Every attempt logs `notify_delivered` or `notify_delivery_failed`. When the
attempts run out, one `notify_delivery_abandoned` says the notification is
genuinely lost — that is the line to alert on. Because the `custom` backend's
contract is an exit code with no way to say "never retry", **every** failure of
a custom script is treated as retryable.
