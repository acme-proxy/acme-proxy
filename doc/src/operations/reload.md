# Reloading the configuration

`acme-proxy` reloads its configuration on `SIGHUP`, without moving either
socket:

```bash
sudo systemctl reload acme-proxy
# or, directly:
kill -HUP "$(pidof acme-proxy)"
```

Nothing is dropped. Connections stay open, in-flight ACME orders keep their
state, queued background work keeps its place, and the ports never change. What
changes is what the server does with the *next* request.

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
`server.bind_address` cannot be changed while the server is running
(running with `[::]:3000`, the file now says `[::]:8443`): restart to apply it
```

These are the keys that produce it. Everything not listed here reloads.

| Key | Why a restart is needed |
| --- | --- |
| `database.url` | The connection pool is open, and the accounts and orders this CA has issued against do not follow it elsewhere. |
| `server.bind_address` | The socket is bound. |
| `server.tls.enabled` | Turning TLS on or off replaces the listener, not its settings. |
| `admin.enabled`, `admin.bind_address`, `admin.tls.enabled` | The same two reasons, for the panel's own socket. |
| `metrics.enabled`, `metrics.bind_address` | The same, for the metrics socket. There is no `metrics.tls.enabled` beside them — that listener has none. |
| every `[logging]` key | The tracing subscriber is installed once per process and cannot be replaced. |
| `[dns]`, `[proxy]` | Every outbound client caches these when it is built, including the signer backends, which are not rebuilt. |
| six of the seven `[jobs]` keys | The runner snapshotted its pacing when it started. `jobs.retention_days` is the exception and does reload. |
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
cannot hold a credential — `[logging]`, `dns.resolver`, `database.url` — still
name the old and the new value in full.

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
- **The panel's templates** — `admin.template_dir` is recompiled. A template
  that does not parse fails the *reload*, so a mistake never reaches a browser.
- **Retention** — `audit.retention_days` and `jobs.retention_days`. A sweep
  already scheduled keeps its current time and picks the new cutoff up on its
  next run.

For what each key means, see the [configuration
reference](../configuration/reference.md).

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
