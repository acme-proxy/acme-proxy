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

A refusal names the key, what the server is running, and what the file now
says:

```text
`database.url` cannot be changed while the server is running
(running with `sqlite://sqlite.db`, the file now says `sqlite://other.db`):
restart to apply it
```

These are the keys that produce it. Everything not listed here reloads.

| Key | Why a restart is needed |
| --- | --- |
| `database.url` | The connection pool is open, and the accounts and orders this CA has issued against do not follow it elsewhere. |
| `[dns]`, `[proxy]` | Every outbound client caches these when it is built, including the signer backends, which are not rebuilt. |
| any profile's `[signer]` section | See below. |
| the set of enabled profiles | Mounting or unmounting an endpoint needs a signer backend built or dropped, so it follows the signer freeze. |

Two of these are worth spelling out, because the obvious guess is wrong.

**The signer freeze is not about the CA files.** Generating a CA happens only
when the files are absent, and a relay registers with its upstream only once,
so rebuilding a signer backend would be idempotent on both counts. The reason
is state that lives only in memory: a local CA rebuilds its whole CRL from its
own revocation ledger, so two of them over one `crl_path` would drop each
other's entries; and a relay serving `http-01` publishes key authorizations to
an in-memory store that a rebuild would empty — while an upstream CA is midway
through fetching one.

**The *global* `[signer]` section is not frozen.** Only each profile's resolved
one is. Profiles inherit key by key, so a global change that matters shows up
in some profile's resolved section anyway, and a global change every profile
overrides is a genuine no-op that would be silly to refuse.

### Sections whose value the refusal will not print

`[proxy]` and each profile's `[signer]` are compared as a whole, and both can
hold a credential: a proxy URL carries `user:password@`, and a signer section
reaches the HSM PIN, the RFC 2136 TSIG key and the upstream EAB secret. The
refusal above is logged, so printing those values would put them in journald
and every log shipper downstream — and the TSIG key is write access to the very
zone this CA validates against.

Those two are therefore compared by digest. The refusal still names the key,
and the signer one still names the profile, but the value reads:

```text
`profiles.*.signer` cannot be changed while the server is running
(running with `le=sha256:9f2a1c...`, the file now says `le=sha256:41b0de...`):
restart to apply it
```

That is enough to see *which* endpoint's signer moved, which is what the
message is for. To see what actually changed, diff the file. Sections that
cannot hold a credential — `dns.resolver`, `database.url` — still name the old
and the new value in full.

## What a reload does change

Everything else, including the things operators reach for most:

- **Access policy** — `[filter]` rules and checks, and the `[ipam]` inventory
  they consult. Tightening a rule takes effect on the next request.
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
