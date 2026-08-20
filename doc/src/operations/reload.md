# Reloading the configuration

`acme-proxy` reloads its configuration on `SIGHUP`, without restarting:

```bash
sudo systemctl reload acme-proxy
# or, directly:
kill -HUP "$(pidof acme-proxy)"
```

Nothing is dropped. Connections stay open, in-flight ACME orders keep their
state, and queued background work keeps its place. What changes is what the
server does with the *next* request — and, if you moved a listener, on which
port it answers it.

A reload is a rebuild and a swap, not a patch. Both routers, every profile's
filter chain and challenge registry, the notification backends, the job
registry and both TLS acceptors are constructed fresh from the file on disk —
and only once every one of them has succeeded is any of it published.

## All or nothing

A reload either applies completely or changes nothing at all.

Three things stop one, and each says so in the log:

| Log event | What happened |
| --- | --- |
| `server_config_reload_refused` | A key that cannot change while the process runs did change. |
| `server_config_reload_failed` | The file did not load, or what it asks for could not be built. |
| `server_config_reloaded` | It applied. |

In the first two cases the server carries on with exactly the configuration it
already had. That matters more than it sounds: a reload that applied the
half it understood would leave a running server that no file on disk describes,
and "what is this thing actually running?" would stop having an answer.

Every success carries a `generation` — 1 for the configuration the process
started with, and one higher for each reload that landed. It is the quickest
way to answer "did my `SIGHUP` take?":

```bash
journalctl -u acme-proxy | grep server_config_reloaded
```

## What a reload cannot change

One key. A refusal names it, what the server is running, and what the file now
says:

```text
`database.url` cannot be changed while the server is running
(running with `sqlite://sqlite.db`, the file now says `sqlite://other.db`):
restart to apply it
```

| Key | Why a restart is needed |
| --- | --- |
| `database.url` | The connection pool is open, and the accounts and orders this CA has issued against it do not follow it elsewhere. A different database is a different CA. |

Everything else reloads. That was not always true, and the four keys that came
off this table most recently are worth knowing about because they are the ones
an operator is most likely to remember as frozen: the set of enabled profiles,
each profile's `[signer]` section, `dns.resolver` and `[proxy]`. See
[Adding and removing endpoints](#adding-and-removing-endpoints) below.

## What a reload does change

Everything else, including the things operators reach for most:

- **Access policy** — `[filter]` rules and checks, and the `[ipam]` inventory
  they consult. Tightening a rule takes effect on the next request.
- **The set of endpoints**, and each one's `[signer]` — see below.
- **Egress** — `dns.resolver` and `[proxy]`. Every outbound client is rebuilt,
  including the signer backends, which used to be the reason these two were
  frozen.
- **Notification backends** — a new webhook, a changed template directory, a
  different `events` list.
- **Challenge settings**, order and account policy, `[meta]`, `[eab]`.
- **TLS certificates** — `server.tls.cert_path` and `key_path` (and the admin
  listener's own pair) are re-read, so a renewed certificate is served to the
  next connection while established ones are undisturbed.
- **The listeners themselves** — see below.
- **The panel's templates** — `admin.template_dir` is recompiled. A template
  that does not parse fails the *reload*, so a mistake never reaches a browser.
- **Retention** — `audit.retention_days` and `jobs.retention_days`. A sweep
  already scheduled keeps its current time and picks the new cutoff up on its
  next run.
- **Background work** — every `[jobs]` key, so slowing a retry storm, widening a
  lease or raising concurrency mid-incident costs nothing. See below.
- **Logging** — every `[logging]` key, so raising the level or switching to JSON
  mid-incident costs nothing. The swap is the first thing a reload publishes, so
  the `server_config_reloaded` line that confirms it is already under the new
  settings. One caveat: `RUST_LOG` still outranks `logging.filter`, exactly as
  it does at startup, so with it set an edited filter changes nothing — the
  server says so with `server_logging_filter_overridden`.

For what each key means, see the [configuration
reference](../configuration/reference.md).

## Adding and removing endpoints

Add a `[profiles.<name>]` section and signal, and that endpoint starts serving:

```text
server_config_reloaded generation=2 profiles=["le", "staging"]
profile_mounted profile=staging directory=https://ca.example/profile/staging/directory
```

Remove it and signal again, and it stops. Endpoints that were already running
are not disturbed either way — no connection is dropped and no in-flight order
loses its state, which is the whole reason this is worth doing without a
restart.

Three things to know.

**`profile_mounted` fires only for an endpoint that was not there before.** It
is a lifecycle event, delivered to whichever `[notify]` backends are configured,
so re-firing it for every endpoint on every `SIGHUP` would make the notification
surface noisiest in exactly the config-managed deployments that would least want
it.

**Unmounting keeps the data.** The accounts and orders belonging to that
endpoint stay in the database and come back exactly as they were if you mount it
again — the profile name is what they are keyed on. Setting `enabled = false` is
the same thing as removing the section.

**Drain a `relay` endpoint before removing it.** Unmounting the last profile a
relaying backend serves takes its job handler with it, so any issuance still
waiting on the upstream has nothing left to finish it. Those rows sit in the
queue until the endpoint is mounted again, and the orders behind them expire.
Nothing else is affected, and no other backend has background work to lose.

## Editing a signer

A profile's `[signer]` section reloads, including the one an endpoint is
actively issuing with. The obvious worry — that a rebuilt local CA would forget
what it had revoked — is handled rather than avoided: the running CA hands its
revocation ledger to its replacement, so a revocation that lands *during* the
reload is not lost either, and `GET /crl` answers identically across the swap. A
relay serving `http-01` hands over its published key authorizations the same
way, so an upstream CA fetching one mid-reload still gets it.

A backend whose section did not move is not rebuilt at all. That matters most
with `key_source = "pkcs11"`: an ordinary reload does not log in to the token
again.

Two edges:

- **Changing where the CA material lives is a new CA.** Point `crl_path` at a
  different file and the endpoint starts from that file's revocation history,
  not the old one's. That is the intended reading of the key, but it is worth
  saying, because the certificates already issued do not move with it.
- **`[dns]` and `[proxy]` rebuild every backend.** They are not `[signer]` keys,
  but an outbound client caches them, so a change to either has to reach the
  signers to mean anything. Nothing is lost — the same handover applies.

## Moving a listener

All seven keys that decide where a socket is, or whether there is one, reload:
`server.bind_address`, `server.tls.enabled`, `admin.enabled`,
`admin.bind_address`, `admin.tls.enabled`, `metrics.enabled` and
`metrics.bind_address`. A reload that moved one says which:

```text
server_config_reloaded generation=2 listeners_rebound=["acme"]
```

Three things are worth knowing before you use it.

**A bad address refuses the reload; it does not take the socket down.** Every
new socket is bound *before* anything is published, so a port already in use, a
name that does not resolve or a privileged port you no longer have the
capability for is a `server_config_reload_failed` — with the listener that is
already running still answering on the address it always had. Fix the file and
signal again.

**Established connections are not disturbed.** A rebind replaces the socket new
connections arrive on; a request already in flight finishes, and a keep-alive
connection opened before the move stays usable until its client closes it. The
old socket stops accepting immediately, so nothing new arrives there.

**Turning TLS on or off does not move the socket at all.** The mode is decided
per connection, like the certificate: the next client to connect speaks the new
protocol on the same port, and `listeners_rebound` stays empty. Remember to move
`server.base_url` with it, or every signed request fails RFC 8555 §6.4's URL
check — the server warns `tls_base_url_mismatch` when it can see the two
disagree.

One caveat on the panel. Switching `admin.enabled` off releases the socket and
empties its router, so nothing answers on it — but it does not sign anybody out:
sessions live in the database and are waiting when you switch it back on. Use
`acme-proxy admin session revoke --all` if that is what you meant. Switching it
off and on again does clear the login-attempt lockout, since the limiter goes
with the panel.

## Retuning the job runner

All seven `[jobs]` keys reload. These are the knobs you reach for while
something is going wrong — an upstream CA rate-limiting you, a backlog draining
too slowly — so a restart to apply them would have dropped exactly the in-flight
orders you were trying to save.

The runner does not restart; it picks the new values up on its next pass and
says so:

```text
job_runner_retuned poll_interval_ms=250 lease_seconds=120 max_concurrent=16
```

That line is the confirmation worth grepping for. `server_config_reloaded` means
a generation was published; this means the runner is actually running under it.
It is only emitted when the pacing really moved, so reloads that touch other
sections stay quiet.

Each key lands at its own grain, and the differences are all in the same
direction — nothing already in flight is disturbed:

- **`poll_interval_ms`** takes effect immediately, without waiting out the old
  interval first.
- **`max_concurrent`** widens at once when raised. Lowered, it takes back the
  slots that are free and reaches the new figure as running jobs finish; no job
  is cancelled to get there sooner.
- **`lease_seconds`, `retry_base_seconds` and `retry_max_seconds`** apply to the
  next job claimed. One already running keeps the budget and the backoff it
  started under.
- **`max_attempts`** is frozen onto each job when it is queued, so a change
  applies to work queued from then on. Raising it is *not* a way to rescue a
  backlog that is about to give up — those rows keep the budget they were queued
  with.
- **`retention_days`** rebuilds the sweep, including registering it when it goes
  from `0` to a real value.

## Systemd

Add `ExecReload` to the unit so `systemctl reload` works:

```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
```

See [Deployment](../getting_started/deployment.md) for the rest of the unit.

## Two things to expect

Neither is a problem, but both look odd if you are not expecting them.

**Startup warnings repeat.** A reload re-emits the advisories that describe the
configuration it just applied — `challenge_validation_bypassed`,
`filter_disabled`, `tls_disabled` and the rest. That is deliberate: they are
written to stay visible for as long as the condition holds.

**`profile_mounted` does not repeat.** It is a lifecycle notification meaning
"this endpoint came up", delivered to whichever `[notify]` backends are
configured. Firing it on every reload would make the notification surface
noisiest in exactly the config-managed deployments that would least want it.

## Reloads a restart still handles better

Two edges, both brief and both identical to what a restart does:

- A request that was already in flight when the reload landed finishes under
  the *old* configuration. That includes the notification it may queue.
- For the moment it takes in-flight requests to drain, the old and new
  admission limits are both in force, so concurrency can briefly reach twice
  `server.max_concurrent_requests`.

If a change is important enough that neither is acceptable, restart.
