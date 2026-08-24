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
| `certificates_expiring` | The periodic expiry digest, one per profile. |

These seven names are the only valid values wherever a backend's `events` list
is configured. An unrecognised name is a **startup error**, not a silently
ignored entry.

`certificates_expiring` is the one that is not a thing that just happened. The
first six describe a single account, order or certificate, at the moment it
changed; this one is a digest sent on a schedule, listing the certificates on
one profile that expire inside a configured window. It sends nothing until
[`notify.expiry.lead_days`](#expiry-digest) is set, so leaving it in an
`events` list costs nothing.

## Backends

- **[Email](email.md)** — SMTP, via `lettre`.
- **[Webhook](webhook.md)** — any HTTP endpoint, with the URL, method, headers
  and body all configured. This is how Slack, Mattermost, Teams, Telegram and
  Matrix are reached: they differ in those four values and nothing else, so
  each is a configuration entry rather than a backend of its own.
- **[Custom Script](custom.md)** — shell out to a local script, for a channel
  that is not an HTTP request at all.

Email and webhook render their messages with MiniJinja templates you can
override; see [Customizing Templates](templates.md).

## Configuration

```toml
[notify]
# Which backends are active. Empty (the default) means no notifications at all.
enabled = ["email", "webhook"]

# Which [notify.webhook.<name>] entries to POST to, when "webhook" is listed
# above.
webhook_enabled = ["slack"]

# Which [notify.custom.<name>] entries to run, when "custom" is listed above.
custom_enabled = []

# Optional directory of template overrides, checked per template file before
# falling back to the compiled-in default.
template_dir = "/etc/acme-proxy/templates"
```

### Reference

**`enabled`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__ENABLED`*

Active backends: any of `email`, `webhook`, `custom`. Empty means the
subsystem is off. `"mattermost"` was removed in favour of `webhook` and is
refused by name.

**`webhook_enabled`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__WEBHOOK_ENABLED`*

Which entries under `[notify.webhook.<name>]` to POST to, and in what order.
Listing `"webhook"` in `enabled` while leaving this empty is a startup error,
as is naming an entry that has no table.

**`custom_enabled`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_NOTIFY__CUSTOM_ENABLED`*

Which entries under `[notify.custom.<name>]` to run, and in what order. The
same two startup errors apply.

**`template_dir`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__TEMPLATE_DIR`*

Directory searched for template overrides. Lookup is **per file**, so overriding
one message (say `email/certificate_issued.body.j2`) leaves every other message
at its compiled-in default. Empty means defaults only.

Each backend additionally takes its own `events` list and `timeout_ms`; see the
backend pages.

### Expiry digest

A certificate approaching its notAfter is the one thing the events above cannot
report: nothing *happens* when a certificate is a fortnight from expiring. The
`[notify.expiry]` table adds a periodic sweep that looks, and sends **one
message per profile** listing what it found.

Deliberately not one message per certificate. A renewal is a *new* order, so
the certificate it replaced still reaches its own expiry on schedule — a
per-certificate reminder therefore fires for every certificate the CA has ever
issued, on its way out, in exactly the deployments where the automation is
working. Instead, each entry in the digest says whether something has already
taken its place, and the entries where nothing has are the ones worth acting
on.

That annotation is drawn from two signals, and the message says which was used:
the successor order's own `replaces` field (RFC 9773 §5 — exact, but only from
clients that send one), or a later, unrevoked certificate of the **same
account** covering **all** of the same names. Both are deliberately narrow. A
certificate wrongly marked as already renewed is one an operator skips over
while it lapses; one wrongly left unmarked is a line of noise.

**`expiry.lead_days`** (`Integer`) — *Default: `0` | Env: `ACME_PROXY_NOTIFY__EXPIRY__LEAD_DAYS`*

How far ahead to look. **`0` is off** — the sweep is never scheduled at all,
the same shape `audit.retention_days` and `jobs.retention_days` use.

**`expiry.interval_days`** (`Integer`) — *Default: `7` | Env: `ACME_PROXY_NOTIFY__EXPIRY__INTERVAL_DAYS`*

How often the digest is sent. There is deliberately no per-certificate rate
limit beside it: the digest is the rate limit. A digest with nothing to report
is not sent, so the absence of a message is what "everything is renewed" looks
like.

**`expiry.max_entries`** (`Integer`) — *Default: `50` | Env: `ACME_PROXY_NOTIFY__EXPIRY__MAX_ENTRIES`*

The most certificates one message lists. The number that matched is carried
whole regardless, so a truncated digest still says how many it did not name.

The schedule is a row in the durable job queue rather than a timer, so it
survives a restart: a server restarting more often than `interval_days` still
sends its digest on time instead of resetting the clock each start.

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
  render, a `url` that does not parse and any other 4xx are refused on the
  first attempt — retrying would reach the same answer four more times and
  delay the log line saying so.

Every attempt logs `notify_delivered` or `notify_delivery_failed`. When the
attempts run out, one `notify_delivery_abandoned` says the notification is
genuinely lost — that is the line to alert on. Because the `custom` backend's
contract is an exit code with no way to say "never retry", **every** failure of
a custom script is treated as retryable.
