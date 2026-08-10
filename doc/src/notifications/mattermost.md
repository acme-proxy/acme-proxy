# Mattermost / Slack Notifications

The `mattermost` notification backend sends webhooks to Mattermost (or Slack,
which shares the same incoming webhook API structure).

This is ideal for alerting Security Operations Centers (SOC) or DevOps teams in
real-time when certificates are issued or revoked.

## Delivery semantics
Like all notifications in `acme-proxy`, webhook dispatch is asynchronous and
non-blocking:
1. A background Tokio task renders the message from its [MiniJinja
   template](templates.md) and POSTs the JSON payload over `hyper`, sharing the
   same outbound HTTP transport and `webpki-roots` TLS configuration as the rest
   of the server's egress. (The project deliberately does not pull in `reqwest`
   for this.)
2. A strict `timeout_ms` prevents the task from hanging indefinitely if the
   webhook endpoint is unresponsive.
3. **Fire and Forget**: If the request fails or times out, the error is logged,
   but the ACME transaction succeeds regardless.

## Configuration

```toml
[notify]
enabled = ["mattermost"]

[notify.mattermost]
webhook_url = "https://mattermost.internal.corp/hooks/xxxxxxxxxxx"
username = "ACME Proxy Bot"
channel = "pki-alerts"
events = ["certificate_issued", "certificate_revoked", "account_created"]
timeout_ms = 5000
```

### Reference

**`webhook_url`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__MATTERMOST__WEBHOOK_URL`*

The incoming webhook URL provided by Mattermost/Slack.

**`channel`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__MATTERMOST__CHANNEL`*

Optional override for the webhook's default channel.

**`username`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__MATTERMOST__USERNAME`*

Optional override for the webhook's default display username.

**`events`** (`Array`) — *Default: `["profile_mounted", "account_created", "account_deactivated", "certificate_issued", "certificate_revoked", "challenge_failed"]` | Env: `ACME_PROXY_NOTIFY__MATTERMOST__EVENTS`*

Lifecycle events this backend reacts to.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_NOTIFY__MATTERMOST__TIMEOUT_MS`*

Timeout budget for the HTTP POST request.
