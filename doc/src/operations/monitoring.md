# Monitoring & Observability

Running an ACME server in production requires visibility into its health,
request volume, and error rates. `acme-proxy` offers three surfaces for that: a
**health endpoint**, **structured logging**, and a **Prometheus exporter**.

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

## Metrics

`GET /metrics` serves the OpenMetrics text format
(`application/openmetrics-text; version=1.0.0`), which Prometheus reads
natively. It is **off by
default** and lives on a **listener of its own** — a third socket beside the
ACME and admin ones, configured by
[`[metrics]`](../configuration/reference.md#metrics):

```toml
[metrics]
enabled      = true
bind_address = "127.0.0.1:3002"
```

The separate port *is* the access control. A scrape carries no credential and
none is checked: reaching the port at all is the permission, so restrict it the
way you restrict any other internal service — a firewall rule, a network policy,
or leaving it on loopback and scraping from the same host. The endpoint is
absent from the ACME and admin sockets entirely, so exposing the ACME listener
to the internet does not expose this.

```console
$ curl -s localhost:3002/metrics
# HELP acme_proxy_requests Requests served, by endpoint, matched route and response status.
# TYPE acme_proxy_requests counter
acme_proxy_requests_total{role="acme,admin,worker",profile="default",route="/newOrder",status="201"} 42
acme_proxy_requests_total{role="acme,admin,worker",profile="none",route="/health",status="200"} 8613
# HELP acme_proxy_request_duration_seconds Time to answer a request, by endpoint and matched route.
# TYPE acme_proxy_request_duration_seconds histogram
# UNIT acme_proxy_request_duration_seconds seconds
acme_proxy_request_duration_seconds_sum{role="acme,admin,worker",profile="default",route="/newOrder"} 0.84
acme_proxy_request_duration_seconds_count{role="acme,admin,worker",profile="default",route="/newOrder"} 42
acme_proxy_request_duration_seconds_bucket{role="acme,admin,worker",le="0.005",profile="default",route="/newOrder"} 3
…
acme_proxy_request_duration_seconds_bucket{role="acme,admin,worker",le="+Inf",profile="default",route="/newOrder"} 42
# HELP acme_proxy_certificates_issued Certificates signed, by endpoint.
# TYPE acme_proxy_certificates_issued counter
acme_proxy_certificates_issued_total{role="acme,admin,worker",profile="default"} 41
# HELP acme_proxy_certificate_issue_failures Issuance attempts the CA refused, by endpoint and ACME problem type.
# TYPE acme_proxy_certificate_issue_failures counter
acme_proxy_certificate_issue_failures_total{role="acme,admin,worker",profile="default",reason="badCSR"} 1
# HELP acme_proxy_certificate_issue_duration_seconds Time from an accepted finalize to a stored certificate, by endpoint.
# TYPE acme_proxy_certificate_issue_duration_seconds histogram
# UNIT acme_proxy_certificate_issue_duration_seconds seconds
acme_proxy_certificate_issue_duration_seconds_sum{role="acme,admin,worker",profile="default"} 45.0
acme_proxy_certificate_issue_duration_seconds_count{role="acme,admin,worker",profile="default"} 41
…
# HELP acme_proxy_database_pool_connections Connections in the SQLite pool.
# TYPE acme_proxy_database_pool_connections gauge
acme_proxy_database_pool_connections{role="acme,admin,worker",state="idle"} 4
acme_proxy_database_pool_connections{role="acme,admin,worker",state="busy"} 1
# EOF
```

A counter's `# TYPE` line names its family without `_total`, as OpenMetrics
requires; its series, which is what a query names, keep the suffix.

| Metric | Type | Labels |
| --- | --- | --- |
| `acme_proxy_requests_total` | counter | `role`, `profile`, `route`, `status` |
| `acme_proxy_request_duration_seconds` | histogram | `role`, `profile`, `route` |
| `acme_proxy_certificates_issued_total` | counter | `role`, `profile` |
| `acme_proxy_certificate_issue_failures_total` | counter | `role`, `profile`, `reason` |
| `acme_proxy_certificate_issue_duration_seconds` | histogram | `role`, `profile` |
| `acme_proxy_database_pool_connections` | gauge | `role`, `state` |

Six things are worth knowing about the numbers.

**`role` names the roles that process runs**, comma-separated —
`acme,admin,worker` for an all-in-one deployment, which is the default. The
counters are per-process memory by design, so a
[split deployment](../getting_started/deployment.md#running-the-roles-as-separate-processes)
is several scrape targets reporting the same family names, and this is what
tells them apart. Each process also needs its own `metrics.bind_address`.

**`route` is the matched route pattern, not the URI.** A request for
`/profile/le/order/9f3c…` is counted under `route="/order/{id}"`, and the
endpoint it reached becomes the `profile` label. Anything that matched no route
at all — a scanner, a typo — collapses into a single `route="<unmatched>"`
series rather than one series per path tried. Root-router requests such as
`/health` carry `profile="none"`.

**`reason` is the ACME problem type the CA refused with** (`badCSR`,
`serverInternal`), the same vocabulary
[`acme-proxy audit list --event certificate_issue_failed`](audit.md) prints.
Both are rendered from one record, so the metric and the trail cannot disagree
about what happened.

**The two histograms time different things.**
`acme_proxy_request_duration_seconds` runs from the request reaching the router
to its response head, with buckets from 5 ms to 10 s; it has no `status` label,
because a histogram multiplies every label by its bucket count.
`acme_proxy_certificate_issue_duration_seconds` runs from the finalize request
being accepted to the certificate being stored, whichever process signs it, with
buckets from 1 s to 1 h. It is measured from job timestamps, which are whole
seconds, and for a [relayed](../signers/relay.md) order it includes the
upstream CA's own validation. It is observed by the process that signs, so in a
split deployment it is on the `worker`'s scrape target.

**The counters survive a reload but not a restart.** `SIGHUP` rebuilds the
routers and keeps the registry, so a configuration change does not read as a
counter reset; a restart genuinely is a new process and starts from zero, which
is what `rate()` expects.

**The pool gauge is read from the pool.** `state="idle"` is connections the pool
holds but has not checked out and `state="busy"` those in use, so
`busy` is in-flight database work rather than a number this server maintains in
parallel.

A minimal scrape configuration:

```yaml
scrape_configs:
  - job_name: acme-proxy
    static_configs:
      - targets: ['ca.internal:3002']
```

A dashboard over all six families ships in the repository — see
[Grafana Dashboard](grafana.md).

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

Everything on this page is the **server's** log stream. The admin commands emit
none of it unless asked, with
[`--log-level`](cli.md#global-flags) or a non-empty `RUST_LOG`, and what they
then emit goes to stderr rather than into the output a script is parsing.

### Request correlation

Every request passes through one server-wide middleware that reads an incoming
`x-request-id` header or generates a UUID v7 when absent, opens the `request`
span, and echoes the id back on the response. Every log line emitted while
handling that request is nested under that span and carries the id, so one
client's
failing renewal can be pulled out of a busy log in a single query — and a
reverse proxy that already assigns request ids will have its value preserved
rather than replaced. A header whose bytes are not valid ASCII cannot be echoed
back, so it is replaced by a generated id and a `request_id_header_invalid` line
at `debug` says so.

The span carries `method`, `uri`, `version`, `request_id`, `client_ip` and —
for a request that reached an ACME endpoint rather than `/health` — `profile`.

`client_ip` is the peer address of the connection, replaced by the address
resolved from `filter.forwarded_header` where `filter.trusted_proxies` says the
peer is a reverse proxy. Both are per-profile settings, so a request that never
reaches a profile — `/health`, the `http-01` responder, anything admission
control sheds — always shows the peer. A request arriving over a socket with no
peer address at all leaves the field absent rather than reporting a placeholder.

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
dozen ways across the several hundred event names (`_failed`, but also
`_invalid`, `_mismatch`, `_missing`, `_unauthorized`, `_rejected`), so globbing
on the name silently misses most of it:

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
| `server_listening`, `profile_mounted` | info | Startup completed; one `profile_mounted` per enabled profile. `server_listening` is repeated by a reload that moved this socket, carrying the address it moved to. A reload emits `profile_mounted` only for an endpoint that was not previously served. |
| `profile_unmounted` | warn | A reload stopped serving an endpoint. Its accounts and orders stay in the database; an issuance still waiting on an upstream has no handler left to finish it. |
| `server_fatal_error`, `profile_init_failed` | error | The process is not serving. |
| `server_socket_bind_failed` | error | A socket could not be bound. At startup the process does not serve; on a reload nothing is applied and whatever was already listening keeps listening. |
| `server_listener_stopped` | info | A listener was switched off by a reload (`admin.enabled` or `metrics.enabled`). The socket is released; established connections finish. |
| `server_config_reloaded` | info | A `SIGHUP` applied. Carries `generation`, which counts from 1 and rises by one per reload — the quickest check that one landed — and `listeners_rebound`, naming any socket that moved. |
| `server_config_reload_refused` | warn | The new file changes a key that cannot change while the process runs. Nothing was applied; the `error` field names the key. |
| `server_config_reload_failed` | error | The new file did not load, or what it asks for could not be built. Nothing was applied. |
| `server_logging_filter_overridden` | warn | A reload changed `logging.filter` while something outranked it, so the edit had no effect. `source` names which: `"flag"` for a `--log-level` on the server's own command line, `"env"` for `RUST_LOG`. Both win on a reload exactly as they do at startup; drop the one named and reload again. |
| `db_migration_failed` | error | Startup aborted before serving. |
| `request_shed` | warn | A request was refused with `503` + `Retry-After: 5` because `server.max_concurrent_requests` was saturated for longer than `admission_wait_ms`. Sustained occurrences mean the limit is too low, or something is retrying hot. |
| `request_deadline_exceeded` | warn | A request exceeded `server.request_timeout_ms`. |
| `request_handler_panicked` | error | A route handler panicked. The client got a `500` in the listener's normal error shape rather than a dropped connection, and the process is unaffected — but a handler panic is always a bug. Alert on it. The `listener` (`acme` / `admin`) and, for the panel, `surface` (`api` / `page`) fields say where; the panic message is in `error`. |
| `filter_request_blocked`, `filter_denied` | warn | The filter policy refused a request. Expected in normal operation; a spike is either an attack or a policy change that broke a legitimate client. |
| `filter_rule_warned` | warn | A `mode = "warn"` rule matched and did **not** decide. This is the line a dry-run rollout is watched on: when it stops appearing for legitimate clients, the rule is safe to switch to `enforce`. |
| `challenge_validation_failed`, `challenge_failed`, `challenge_validation_timeout` | warn | Domain-control validation did not pass. The most useful signal that clients are misconfigured — or that egress to them is blocked. The `timeout` variant means nothing answered within `challenge.timeout_ms` at all. |
| `challenge_http_01_mismatch` | warn | The responder answered, but with the wrong key authorization. The body itself is never logged here; a truncated preview goes to `challenge_http_01_mismatch_body` at `debug`. |
| `challenge_validation_abandoned` | warn | The queue gave up on a validation — the attempts ran out, or the authorization expired under it. The challenge, its authorization and its order are marked `invalid` so the client stops polling. Distinct from `challenge_failed`, which means the check ran and the client's setup did not satisfy it; this one means the check never reached a verdict. |
| `challenge_validation_enqueue_failed` | error | A challenge was claimed but its validation job could not be written. The claim is released, so the client may trigger again; the request answers `500`. Alert on it — it means the database refused a write on the ACME path. |
| `server_role_no_worker` | warn | This process runs no `worker` role, so nothing in it drains the job queue and it holds no signing backend. Expected in a split deployment; a deployment where *no* process runs one issues nothing at all, because challenge validation, issuance, CRL signing, notifications and the sweeps are all queued work. |
| `server_schema_behind` | error | A process that does not own the schema found migrations unapplied and refused to serve. Run `acme-proxy migrate`, or start the `worker` role, before the others. |
| `nonce_replayed` | warn | A JWS carried a nonce that was unknown, already consumed or expired. Routine in small numbers (a client racing itself); a flood is a client stuck in a retry loop, or a replay attempt. |
| `key_change_rejected` | warn | `POST /keyChange` refused. `reason = bad_signature` means the inner JWS did not verify — somebody attempted a rollover they could not prove possession for. |
| `order_finalize_queued` | info | `finalize` accepted a CSR, claimed the order and queued its signing. Logged by the process serving ACME; the outcome is logged by the worker that signs. |
| `local_ca_leaf_issued`, `order_finalized` | info | A certificate was issued. Logged by the worker. |
| `order_finalize_bad_csr`, `order_finalize_issuance_failed` | warn / error | The signer backend rejected the CSR (the order goes `invalid` with `badCSR`), or failed to sign (the job retries). |
| `order_finalize_authority_withdrawn` | warn | The account, or one of the order's authorizations, was deactivated after `finalize` queued the signing. The order goes `invalid` with `unauthorized` and nothing is signed. |
| `order_finalize_abandoned` | warn | The queue gave up on an issuance — the attempts ran out, or the order expired under it — and marked the order `invalid` so the client stops polling. Carries the last reason. A steady stream means the backend is down; alert on it. |
| `certificate_revoked`, `certificate_revoke_signer_failed` | info / error | Revocation succeeded, or the signer refused it — in which case the order is left un-revoked for a retry. |
| `local_ca_crl_republished` | info | A revocation `acme-proxy order revoke` recorded without the CA key was signed into the CRL by the `local_ca_crl_regenerate` job. Carries the CA's `issuer` id. |
| `certificate_revoke_queued` | info | A revocation for a `relay` or `custom` backend was queued for the worker by a process that holds no backend — `revokeCert`, the panel or the CLI — which then waits on the job. Carries `order_id` and `job_id`. |
| `certificate_revoke_abandoned` | error | A queued revocation for a `relay` or `custom` backend was given up after its attempts ran out: the certificate is **still trusted**. Carries `order_id` and the last reason. Alert on it. |
| `local_ca_crl_not_stored` | error | `GET /crl` found no stored CRL for a CA. The worker stores one before it serves, so this means no worker has run with this CA yet — start one. |
| `local_ca_crl_pruned` | info | Revocation entries whose certificates had expired were dropped from the CRL (RFC 5280 §3.3). Carries `rows_removed` and the CA's `issuer` id. Silent when nothing expired, which is most days. |
| `local_ca_crl_prune_failed` | error | The daily CRL refresh failed for one CA — the database, or a CRL that could not be signed. Nothing is lost and the refresh tries again tomorrow, but the refresh is also what re-signs a CRL before its `nextUpdate`, so two days of this in a row deserve a look. |
| `local_ca_ledger_imported` | info | A CA met the database for the first time and imported the JSON ledger it kept beside `crl_path` before. Carries `rows_imported` and the new `crl_number`. Logged once per CA; the sidecar is not read again. |
| `local_ca_crl_initialization_failed` | error | A CA could not store its first CRL — usually a sidecar that will not import, named in `error`. That CA's revocations and `GET /crl` fail until it is fixed, rather than proceeding without the history the sidecar holds. |
| `local_ca_crl_export_failed` | error | The CRL was stored and is served, but writing its copy to `crl_path` failed. Only a static publication of that file is stale; the daily refresh writes it again. |
| `http_01_token_store_failed` | error | The relay could not publish, retract or look up an http-01 key authorization in the database. A failed publish retries the relay attempt; a failed lookup answers the upstream's fetch `500`. |
| `upstream_relay_succeeded`, `upstream_relay_failed` | info / warn | Outcome of one relayed issuance under the `relay` signer backend. |
| `job_run_completed` | info | One background job finished. Carries `job_kind`, the attempt it succeeded on, and `duration_ms`. |
| `job_run_retried` | warn | A job failed in a way that may not recur and went back in the queue. Carries the reason and the next `run_at`. Routine in ones; a steady stream of the same `job_kind` means whatever it talks to is unwell. |
| `job_run_abandoned` | error | A job was retired permanently — the handler refused it, the attempts ran out, or its deadline passed. For a `signer_relay_issue` job this is the moment the client's order goes `invalid`, so it is the line to alert on. |
| `job_run_panicked` | error | A job handler panicked. The job is retried straight away rather than holding its lease, but this is always a bug — alert on it. |
| `db_job_leases_reclaimed` | warn | Rows whose runner died holding the lease were returned to the queue. Expected once after an unclean shutdown; recurring means the runner is being killed mid-job. |
| `job_lease_lost` | warn | A job finished after its lease had already been reclaimed, so its result was discarded and another runner will repeat the work. Means an attempt is overrunning `jobs.lease_seconds`. |
| `job_deadline_passed` | warn | A job was claimed after its own deadline and retired without running. For a relay that means the local order had already expired. |
| `job_runner_retuned` | info | A configuration reload moved the runner's pacing, and it is now running under the new values — which `server_config_reloaded` alone does not tell you. Carries all five: `poll_interval_ms`, `lease_seconds`, `retry_base_seconds`, `retry_max_seconds` and `max_concurrent`. Silent when a reload leaves `[jobs]` alone. |
| `job_runner_started`, `job_runner_stopped` | info | The queue runner's lifecycle. `job_runner_stopped` carries how many leases it released on the way out; a *missing* one after a restart is why work waits out a lease instead of resuming immediately. Note the four table sweeps and every notification run through this runner, so a runner that is not started is a server that is not sweeping or notifying either. |
| `upstream_bad_nonce_retry` | debug | Normal ACME churn against the upstream; only interesting in bulk. |
| `notify_delivery_failed` | warn | One delivery attempt did not land. Never affects the ACME response, and no longer the end of the story: it carries `retryable`, and a `true` there means the delivery went back in the queue. |
| `notify_delivery_target_missing` | warn | A queued delivery names a profile or backend this process does not have. It is retried rather than dropped, since another process over the same database may be on a newer configuration; a target that really is gone ends in `notify_delivery_abandoned` once the attempts run out. |
| `notify_delivery_abandoned` | warn | A notification was given up on — the attempts ran out, or a backend reported a failure that could never succeed. **This is the line that means an operator was not told something.** Alert on it; `notify_delivery_failed` on its own is usually just a bad minute. |
| `notify_delivered` | info | One delivery landed. Carries the `backend`, the event `kind` and the attempt it succeeded on. |
| `notify_delivery_queued` | info | A delivery was written to the queue, one line per backend that wanted the event. Carries a `delivery_id` shared by that event's rows, which is how they are correlated. |
| `tls_handshake_timeout`, `tls_handshake_failed` | debug | Only with `server.tls.enabled`. Deliberately below the default filter: on a public listener these are scanner background noise, and one `warn` per failed handshake is a flood, not a signal. |
| `nonce_reaper_swept` | debug | The periodic nonce cleanup ran. It is a `nonce_sweep` job, so its absence over a long window means the job runner is unwell — check `job_runner_started`. |
| `audit_write_failed` | warn | An [audit](audit.md) row could not be written. The failure is **swallowed deliberately** — a certificate the CA has already signed must not become a `500` the client retries into a second issuance — so this line is the *only* evidence that the trail has a hole in it. Alert on it. |
| `audit_reverse_dns_failed`, `audit_reverse_dns_timeout` | debug | A PTR lookup for a client address found nothing in time. Costs a `NULL` in one column, never a refused request. Routine where no reverse zone exists; turn `audit.reverse_dns` off there. |
| `audit_reaper_swept`, `audit_reaper_failed` | debug / warn | The daily retention sweep, only with a non-zero `audit.retention_days`. `audit_reaper_swept` carries the rows removed and the cutoff. Runs as the `audit_sweep` job. |
| `order_reaper_swept`, `order_reaper_failed` | info / error | The daily order-retention sweep, one line **per profile**, carrying that profile's rows removed and cutoff. Runs as the `order_sweep` job, and only for profiles with a non-zero `order.retention_days`. It deletes expired, non-`valid` orders and cascades to their authorizations and challenges; a `valid` order is never swept, so revocation and renewal information stay available for every certificate actually issued. |
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
| `db_admin_user_created`, `db_admin_user_deleted`, `db_admin_user_password_changed`, `db_admin_user_status_changed`, `db_admin_user_role_changed`, `db_admin_user_contact_changed` | info | The operator audit trail. `db_admin_user_contact_changed` carries `cleared` (whether the notification address was removed rather than set). |
| `db_admin_sessions_revoked`, `db_admin_session_deleted` | info | Sessions ended, by a password change, a disable, or an explicit revoke. `db_admin_sessions_revoked` carries `scope`: `user`, `user_except_current` (what a password change does, so the operator making it is not logged out by their own action) or `all`. |
| `admin_eab_created`, `admin_eab_revoked`, `admin_eab_deleted` | info | Carries the `kid` and the operator who did it — **never** the secret. `admin_eab_deleted` carries `accounts`: `keep`, `deactivate` or `delete`. |
| `db_account_delete_blocked`, `db_order_delete_blocked`, `db_eab_delete_blocked` | info | An operator delete was refused because it would have removed the only record of a live certificate. Carries `live_certificates`. Nothing was changed. |
| `admin_order_revoked`, `admin_order_revoke_queued`, `admin_order_deleted`, `admin_account_contact_updated`, `admin_account_deactivated`, `admin_account_deleted`, `admin_nonces_cleaned`, `admin_session_revoked` | info | Admin writes, each naming the operator. Each carries `surface = "api"` or `"ui"`: the JSON API and the HTML panel run one shared action, so the same write logs the same line whichever surface it came through. |
| `admin_job_cancelled`, `admin_job_advanced`, `admin_job_revived` | info | An operator acting on the background queue through `/api/jobs` or `/ui/jobs`. (The `acme-proxy jobs` subcommand writes the matching audit rows but emits no log line: a non-`serve` invocation installs no subscriber.) Each carries `surface` and the operator. `admin_job_cancelled` on a `signer_relay_issue` job also carries `order_abandoned = true` and the `order_id` — the ACME order was marked `invalid` and the upstream mapping abandoned. `admin_job_revived` carries `attempts` (set to `max_attempts - 1`). |
| `admin_revoke_signer_failed` | error | The CA-side revocation failed, so the order is left un-revoked for a retry. Answered as `502` rather than `500`. |
| `admin_db_error` | error | A database failure on an admin route. The `sqlx` message is here and deliberately *not* in the response body, which says only "internal error". |
| `admin_session_reaper_swept` | debug | The periodic session sweep ran, as the `admin_session_sweep` job. |
| `admin_session_orphaned` | warn | A session outlived its user despite the FK cascade. Should be impossible; the session is deleted and refused. |

The full set is much broader than this table — several hundred names, of which
the ones above are the curated subset worth an alert. Because the subsystem
prefix is drawn from a closed list, an ad-hoc investigation can grep a whole
family: `event = "certificate_revoke` for every revocation refusal,
`event = "replaces_` for RFC 9773 correspondence, `event = "db_` for the
storage layer.

### Suggested alerts

Two sources, and they are complementary rather than alternatives. The metrics
are cheap to alert on and answer "how much"; the log stream answers "which one,
and why", and covers everything the metrics do not.

With [`[metrics]`](#metrics) enabled:

```promql
# Issuance is failing, whatever the reason.
rate(acme_proxy_certificate_issue_failures_total[15m]) > 0

# Nothing has been issued over a window longer than your shortest renewal
# interval -- silent breakage, and the one nothing else will tell you.
increase(acme_proxy_certificates_issued_total[6h]) == 0

# The server is shedding load: undersized, or a client is in a retry loop.
rate(acme_proxy_requests_total{status="503"}[5m]) > 0

# 5xx as a share of everything: this server failing, not clients being refused.
sum(rate(acme_proxy_requests_total{status=~"5.."}[5m]))
  / sum(rate(acme_proxy_requests_total[5m])) > 0.01

# The pool is saturated, so requests are queueing on a connection.
acme_proxy_database_pool_connections{state="idle"} == 0

# Requests are slow: the 95th percentile over a second, on any route.
histogram_quantile(0.95,
  sum(rate(acme_proxy_request_duration_seconds_bucket[5m])) by (le, route)) > 1
```

The `up` metric Prometheus synthesises per target also gives a liveness alert
for free, though `/health` remains the better probe for a load balancer since it
is on the ACME listener itself.

From the log stream, which reaches further. The first is the general case and
subsumes most of the rest; the others are worth splitting out because each has a
different response:

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
