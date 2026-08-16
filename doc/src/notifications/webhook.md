# Webhook Notifications

The `webhook` backend makes one HTTP request per event, with the URL, the
method, the headers and the body all stated in configuration.

That is the whole design. Slack, Mattermost, Microsoft Teams, Telegram and
Matrix differ in those four values and in nothing else — the transport, the
timeout, the TLS stack, the proxy and the retry rules are the same for all of
them — so a chat provider is an entry in a table here rather than a backend in
the binary. See [Provider recipes](#provider-recipes) below for a
copy-pasteable entry per provider.

## Configuration

Entries are **named**, selected and ordered by `webhook_enabled`, exactly like
[`[notify.custom]`](custom.md). Two entries are two independent deliveries: a
retry never re-sends through one that already succeeded.

```toml
[notify]
enabled = ["webhook"]
webhook_enabled = ["slack", "oncall"]

[notify.webhook.slack]
url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX"
body = '{"text": {{ message | tojson }}}'

[notify.webhook.oncall]
url = "https://chat.internal.corp/api/v1/rooms/pki/messages"
events = ["certificate_revoked", "challenge_failed"]

[notify.webhook.oncall.headers]
Authorization = "Bearer s3cret"
```

An entry name must match `^[a-z0-9-]+$`: it is also an environment-variable
segment, which the configuration loader lowercases, so anything else could name
one entry in a file and a silently different one through the environment.

## How a body is rendered

Rendering has two stages, and the split is what lets you restyle every message
without restructuring any payload, or the reverse:

1. **The message.** `webhook/<event>.j2` renders human-readable text. These are
   embedded in the binary and overridable file by file through
   [`notify.template_dir`](templates.md) — override
   `webhook/certificate_issued.j2` and every other message stays at its
   default.
2. **The payload.** The entry's own `body` is a template with `message`, `hook`
   (the event name) and every field of the event in scope — the same fields
   [Customizing Templates](templates.md#context-variables) lists.

**`| tojson` is not decoration.** A `.j2` template has auto-escaping off, on
purpose, so a message holding a quote or a newline — a `challenge_failed`
quotes what the validator saw — would otherwise render a payload the provider
answers `400` to. That answer is permanent, so the delivery is refused on the
first attempt, for exactly the events you most wanted to hear about.

## Provider recipes

Everything below is the whole entry: no other key is needed. `message` is the
rendered text from stage 1.

| Provider | `method` | `body` | headers |
| --- | --- | --- | --- |
| Slack | `POST` | `{"text": {{ message \| tojson }}}` | — |
| Mattermost | `POST` | `{"text": {{ message \| tojson }}}` | — |
| Microsoft Teams | `POST` | `{"text": {{ message \| tojson }}}` | — |
| Google Chat | `POST` | `{"text": {{ message \| tojson }}}` | — |
| Telegram | `POST` | `{"chat_id": "-1001234567890", "text": {{ message \| tojson }}}` | — |
| Matrix | `PUT` | `{"msgtype": "m.text", "body": {{ message \| tojson }}}` | `Authorization: Bearer <token>` |

Notes on the two that are not simply a URL:

- **Telegram**'s URL is
  `https://api.telegram.org/bot<token>/sendMessage`, and the destination is the
  `chat_id` in the body rather than anything in the URL.
- **Matrix**'s URL is the room's send endpoint,
  `/_matrix/client/v3/rooms/<room>/send/m.room.message/<txn>`, on your own
  homeserver. The transaction id is meant to change per message; a fixed one
  makes the homeserver deduplicate, which is a deliberate choice worth knowing
  you are making.

Mattermost's `channel` and `username` overrides, which this backend replaced,
are two more members of the same object:

```toml
body = '{"channel": "pki-alerts", "username": "ACME Proxy", "text": {{ message | tojson }}}'
```

## Delivery semantics

Nothing here is specific to this backend — see
[Notifications](index.md#delivery-semantics) for the queue, the retries and the
one log line that means a notification was genuinely lost. Two points that bite
webhooks in particular:

- **A 4xx is permanent.** Every 4xx except `408` and `429` is the provider
  stating a reason — a webhook that has been deleted, a payload it will not
  accept — so it is refused on the first attempt rather than retried four more
  times. `5xx`, `429`, `408`, a timeout and a refused connection are retried.
  A refusal's response body is quoted in the log line, truncated: Slack's
  `invalid_payload` is usually the entire diagnosis.
- **Everything unusable is refused at startup**, not at delivery time: an empty
  or unparseable `url`, a scheme that is not `http`/`https`, a `method` outside
  `POST`/`PUT`/`PATCH`, a header a wire format will not carry, and a `body`
  that does not compile as a template.

The URL's path and every header value routinely carry the credential, so
nothing this server logs or reports ever renders more than the host and the
header names.

## Reference

**`url`** (`String`) — *Default: `""` | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__URL`*

The endpoint to call. Required once the entry is listed in `webhook_enabled`.

**`method`** (`String`) — *Default: `"POST"` | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__METHOD`*

`POST`, `PUT` or `PATCH`, in any case. Anything else is a startup error: a
webhook is a write, and a body on `GET` would be a request no provider answers.

**`headers`** (`Table`) — *Default: `{}` | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__HEADERS__<HEADER>`*

Extra request headers. Applied after the defaults, so an entry may override
`content-type` (`application/json`) or `user-agent` (`acme-proxy`). Header
names arrive lowercased from the environment, which HTTP does not care about.

**`body`** (`String`) — *Default: `{"text": {{ message | tojson }}}` | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__BODY`*

The request body, as a template. The default is the payload Slack, Mattermost,
Teams and Google Chat all accept, so those four need a `url` and nothing else.

**`events`** (`Array`) — *Default: all six | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__EVENTS`*

Lifecycle events this entry reacts to.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_NOTIFY__WEBHOOK__<NAME>__TIMEOUT_MS`*

Budget for one delivery attempt, connect and handshake included.
