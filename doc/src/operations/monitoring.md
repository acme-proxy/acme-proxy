# Monitoring & Observability

Running an ACME server in production requires visibility into its health,
request volume, and error rates. Today `acme-proxy` offers that through
**structured logging** and a **health endpoint**.

> **There is no `/metrics` endpoint.** A Prometheus exporter is on the roadmap
> (see `TODO.md` in the repository), but the binary does not currently expose
> one and there is no cargo feature to enable it. Alerting is built on the log
> stream described below.

## Health checks

- **Endpoint**: `GET /health`
- **Response**: `200 OK` with the body `{"healthy": true}`

The handler takes no application state: it does not query the database, and it
does not consult the signer. It answers `200` whenever the process is alive and
able to accept a connection, and it has no other failure mode. Treat it as a
**liveness** probe, not a readiness probe — it will not tell you that the disk
holding `sqlite.db` filled up.

What makes it worth polling is *where* it is mounted. `/health` lives on the
root router, not inside a profile, which means it is deliberately outside:

- the admission-control layer, so a saturated server still answers the probe
  (inside the limit, the probe was starved exactly when it mattered, and a load
  balancer would go on reporting the node healthy right up to the point where
  the probe could no longer get a slot);
- every profile's filter chain, so an IP allowlist never has to be widened for
  your load balancer;
- the `Replay-Nonce` middleware, so probing costs no database write; and
- the `Link: rel="index"` middleware.

`GET /` redirects to `/health`.

## Logging

`acme-proxy` uses the `tracing` crate, configured by the six keys in
[`[logging]`](../configuration/reference.md#logging) — filter, JSON or
human-readable output, `stdout` or `stderr`, ANSI colour, span timing, and
whether JSON fields sit at the top level. Every one of them is validated at
startup: an unknown value is a refusal to start with a message naming the key,
never a silent fallback.

Two of them are worth setting deliberately in production:

```toml
[logging]
# Structured fields become first-class keys rather than text to be re-parsed.
json_format = true
# ... and at the top level, which is what most pipelines want.
flatten_event = true
```

The rest of this page is about what those records contain.

### Log levels

```bash
RUST_LOG=acme_proxy=info   # operational logging (recommended for production)
RUST_LOG=acme_proxy=debug  # per-request detail, challenge validation steps,
                           # database writes, truncated response previews
                           # from http-01
```

There is no `trace` level to reach for: the crate emits nothing below `debug`.

`RUST_LOG` replaces the whole filter, so a bare `RUST_LOG=debug` also turns on
debug logging for every dependency. `acme-proxy` does not configure SQL
statement logging itself; to see `sqlx`'s own statement logs you must ask for
them explicitly, e.g. `RUST_LOG=acme_proxy=info,sqlx=debug`.

### Request correlation

Every request passes through one server-wide middleware that reads an incoming
`x-request-id` header or generates a UUID when absent, opens the `request` span,
and echoes the id back on the response. Every log line emitted while handling
that request is nested under that span and carries the id, so one client's
failing renewal can be pulled out of a busy log in a single query — and a
reverse proxy that already assigns request ids will have its value preserved
rather than replaced. A header whose bytes are not valid ASCII cannot be echoed
back, so it is replaced by a generated id and a `request_id_header_invalid` line
at `debug` says so.

The span carries `method`, `uri`, `version`, `request_id` and — for a request
that reached an ACME endpoint rather than `/health` — `profile`.

### The access line

Each request closes with exactly one `request_completed` record carrying
`status` and `latency_ms`. It is emitted under this crate's own target, so it is
visible at the default filter. Its level varies:

| Case | Level | `outcome` |
| --- | --- | --- |
| Response status is 5xx | `warn` | `failure` |
| `GET`/`HEAD` of `/health` or `/` | `debug` | `success` |
| Everything else | `info` | `success` |

This is the **only** event name emitted at more than one level, and the only one
whose `outcome` comes from the response rather than from its own name. Liveness
probes are at `debug` deliberately: at one probe per second per node they would
otherwise be most of the log. Set `RUST_LOG=acme_proxy=debug` to see them.

### Structured events

Every log record carries two fields you can build alerting on, and their shape
is enforced by a test rather than by convention (`tests/logging_convention.rs`).

**`event`** is a stable, greppable name, shaped `<subsystem>_<object>_<outcome>`
— always a literal in the source, so a name in a log greps straight back to the
line that wrote it. The subsystem prefix comes from a closed list, so a family
grep finds the whole family: `event = "certificate_revoke` reaches every
revocation refusal, `db_` reaches the storage layer, `challenge_http_01_`
reaches one validator. Challenge types are always spelled with separators
(`http_01`, `dns_01`, `tls_alpn_01`).

**`outcome`** is one of four values, and it exists so that "show me everything
that broke" is an exact match instead of a suffix glob. Failure is spelled a
dozen ways across the ~450 event names (`_failed`, but also `_invalid`,
`_mismatch`, `_missing`, `_unauthorized`, `_rejected`), so globbing on the name
silently misses most of it:

| `outcome` | Meaning |
| --- | --- |
| `success` | The operation completed. |
| `failure` | The operation did not. **This is the field to alert on.** |
| `progress` | An operation began or was asked for; its result is not yet known. Always paired with a `_started` or `_requested` name. |
| `advisory` | Nothing failed, but the operator should keep seeing it — a configuration posture like `tls_disabled` or `challenge_validation_bypassed`. |

Every `error`-level record is `outcome = "failure"`; an advisory sits at `warn`.

The events worth building alerts on:

| Event | Level | Meaning |
| --- | --- | --- |
| `request_completed` | info / warn / debug | One per request. See "The access line" above for the level. |
| `server_listening`, `profile_mounted` | info | Startup completed; one `profile_mounted` per enabled profile. |
| `server_fatal_error`, `server_socket_bind_failed`, `profile_init_failed` | error | The process is not serving. |
| `db_migration_failed` | error | Startup aborted before serving. |
| `request_shed` | warn | A request was refused with `503` + `Retry-After: 5` because `server.max_concurrent_requests` was saturated for longer than `admission_wait_ms`. Sustained occurrences mean the limit is too low, or something is retrying hot. |
| `request_deadline_exceeded` | warn | A request exceeded `server.request_timeout_ms`. |
| `request_blocked`, `filter_denied` | warn | A filter refused a request. Expected in normal operation; a spike is either an attack or a policy change that broke a legitimate client. |
| `challenge_validation_failed`, `challenge_failed`, `challenge_validation_timeout` | warn | Domain-control validation did not pass. The most useful signal that clients are misconfigured — or that egress to them is blocked. The `timeout` variant means nothing answered within `challenge.timeout_ms` at all. |
| `challenge_http_01_mismatch` | warn | The responder answered, but with the wrong key authorization. The body itself is never logged here; a truncated preview goes to `challenge_http_01_mismatch_body` at `debug`. |
| `nonce_replayed` | warn | A JWS carried a nonce that was unknown, already consumed or expired. Routine in small numbers (a client racing itself); a flood is a client stuck in a retry loop, or a replay attempt. |
| `key_change_rejected` | warn | `POST /keyChange` refused. `reason = bad_signature` means the inner JWS did not verify — somebody attempted a rollover they could not prove possession for. |
| `local_ca_leaf_issued`, `order_finalized` | info | A certificate was issued. |
| `certificate_revoked`, `certificate_revoke_signer_failed` | info / error | Revocation succeeded, or the signer refused it — in which case the order is left un-revoked for a retry. |
| `upstream_relay_succeeded`, `upstream_relay_failed` | info / warn | Outcome of one relayed issuance under the `relay` signer backend. |
| `upstream_bad_nonce_retry` | debug | Normal ACME churn against the upstream; only interesting in bulk. |
| `notify_delivery_failed` | warn | A notification backend could not deliver. Never affects the ACME response. |
| `tls_handshake_timeout`, `tls_handshake_failed` | debug | Only with `server.tls.enabled`. Deliberately below the default filter: on a public listener these are scanner background noise, and one `warn` per failed handshake is a flood, not a signal. |
| `nonce_reaper_swept` | debug | The periodic nonce cleanup ran. Its absence over a long window means the reaper task died. |
| `audit_write_failed` | warn | An [audit](audit.md) row could not be written. The failure is **swallowed deliberately** — a certificate the CA has already signed must not become a `500` the client retries into a second issuance — so this line is the *only* evidence that the trail has a hole in it. Alert on it. |
| `audit_reverse_dns_failed`, `audit_reverse_dns_timeout` | debug | A PTR lookup for a client address found nothing in time. Costs a `NULL` in one column, never a refused request. Routine where no reverse zone exists; turn `audit.reverse_dns` off there. |
| `audit_reaper_swept`, `audit_reaper_failed` | debug / warn | The daily retention sweep, only with a non-zero `audit.retention_days`. `audit_reaper_swept` carries the rows removed and the cutoff. |
| `ipam_netbox_tls_verification_disabled` | warn | Emitted on **every** start while `insecure_skip_verify` is set, deliberately not once-only. |
| `proxy_configured` | info | Emitted once at startup when [`[proxy]`](../configuration/reference.md#proxy) resolves to anything, and not at all otherwise. Carries `source` (`config`, `environment` or both), the two proxy URLs **with any password redacted**, and the `no_proxy` rule count. Worth reading on a first start: an inherited shell `https_proxy` is otherwise an invisible reason for every outbound call to behave differently. |

Only with `[admin]` enabled — see [Web Admin](webadmin.md):

| Event | Level | Meaning |
| --- | --- | --- |
| `admin_listening`, `admin_origin_resolved` | info | The web admin started. `admin_origin_resolved` carries the origin the CSRF check will compare against, and the resolved bind address — check these agree with how you actually reach the panel. |
| `admin_config_invalid` | error | `[admin]` cannot work; the process did not start. The message names the two keys that disagree. |
| `admin_no_users` | warn | The panel is enabled but has no operators — a running service with no way in. Fix with `acme-proxy admin user create`. |
| `admin_login_succeeded` | info | Carries `username` and `client_ip`. |
| `admin_login_failed` | warn | Carries `reason`: `wrong_password`, `unknown_user`, `account_disabled` or `rate_limited`. **The client is told none of this** — every failure returns one `invalid_credentials` — so this log line is the only place the distinction exists. A run of `unknown_user` from one address is somebody guessing usernames; a run of `rate_limited` is a brute-force attempt, or an operator locked out by their own retries. |
| `admin_logout` | info | Carries `scope = "one"` or `"all"`, and `surface = "api"` or `"ui"`. |
| `admin_password_hash_unreadable` | warn | A stored hash could not be decoded. The account is unusable until `acme-proxy admin user passwd` rewrites it, and nothing else will tell you. |
| `db_admin_user_created`, `db_admin_user_deleted`, `db_admin_user_password_changed`, `db_admin_user_status_changed` | info | The operator audit trail. |
| `db_admin_sessions_revoked`, `db_admin_session_deleted` | info | Sessions ended, by a password change, a disable, or an explicit revoke. `db_admin_sessions_revoked` carries `scope`: `user`, `user_except_current` (what a password change does, so the operator making it is not logged out by their own action) or `all`. |
| `admin_eab_created`, `admin_eab_revoked` | info | Carries the `kid` and the operator who did it — **never** the secret. |
| `admin_order_revoked`, `admin_order_deleted`, `admin_account_deleted`, `admin_nonces_cleaned` | info | Destructive admin actions, each naming the operator. Each carries `surface = "api"` or `"ui"`, since the JSON API and the HTML panel reach the same operation by different routes. |
| `admin_revoke_signer_failed` | error | The CA-side revocation failed, so the order is left un-revoked for a retry. Answered as `502` rather than `500`. |
| `admin_db_error` | error | A database failure on an admin route. The `sqlx` message is here and deliberately *not* in the response body, which says only "internal error". |
| `admin_session_reaper_swept` | debug | The periodic session sweep ran. |
| `admin_session_orphaned` | warn | A session outlived its user despite the FK cascade. Should be impossible; the session is deleted and refused. |

The full set is much broader than this table — around 450 names, of which the
ones above are the curated subset worth an alert. Because the subsystem prefix
is drawn from a closed list, an ad-hoc investigation can grep a whole family:
`event = "certificate_revoke` for every revocation refusal, `event = "replaces_`
for RFC 9773 correspondence, `event = "db_` for the storage layer.

### Suggested alerts

Without a metrics endpoint, these are log-derived rates. The first one is the
general case and subsumes most of the rest; the others are worth splitting out
because each has a different response:

- **`outcome = "failure"` above its usual rate** → something broke. This is the
  one query that catches every refusal, whatever the event is called, and it is
  the reason the field exists.
- `request_shed` above zero for more than a few minutes → the server is
  undersized, or a client is in a retry loop.
- `challenge_validation_failed` rising against a flat `local_ca_leaf_issued`
  rate → clients are asking and failing; check egress and the responder ports.
- Any `upstream_relay_failed` → issuance is broken for every client behind the
  relay, not just one.
- No `local_ca_leaf_issued` at all over a window longer than your shortest
  renewal interval → silent breakage.
- Any `audit_write_failed` → the audit trail is silently incomplete, and nothing
  else will tell you. See [Audit Trail](audit.md).
- `server_fatal_error`, `db_migration_failed`, `profile_init_failed` → page
  immediately.
