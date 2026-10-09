# Separate Role Processes

`acme-proxy serve` runs three jobs in one process: serving ACME, serving the web
admin, and draining the job queue. `--role` splits them across processes of the
same binary, reading the same configuration.

| Role | Does | Holds |
| --- | --- | --- |
| `acme` | Serves ACME to certificate clients | The ACME listener |
| `admin` | Serves `/ui` and `/api` | The admin listener |
| `worker` | Drains the job queue; signs and revokes; owns the schema and the first-run material | The CA key or token, a relay's upstream account; no listener |

**All-in-one is still the default** and nothing about it changes: `acme-proxy
serve` with no `--role` behaves exactly as it always did. The split is worth
doing when you want privilege separation — the process parsing untrusted JWS and
CSRs from the internet is then not the one holding operator sessions, and
neither is the one making outbound connections to client-chosen hosts. Each can
run under its own uid and its own systemd sandbox.

**Only the worker holds signing material.** `finalize` queues the signing and
answers `processing`, a revocation is a database row or a queued job, and the
CA's certificate, its CRL and renewal information are served from `ca.pem` and
the database. So the `acme` and `admin` processes never read `ca.key`, never log
in to a PKCS#11 token and never use a relay's upstream account. Make `ca.key`
(`0600`) readable by the worker's uid alone; the others need `ca.pem` and the
database. A `custom` signer's script must still be present where `acme` runs if
it serves the CRL or renewal information, since those hooks answer a request.

Three things to get right:

1. **Initialise once, first.** `acme-proxy init` migrates the database and
   generates the CA key, the upstream account and any self-signed TLS
   certificate. Run it as the uid that should own those files. A process that
   does not run `worker` refuses to start against a schema that is behind,
   naming `acme-proxy migrate`, and without the CA certificate, naming
   `acme-proxy init` — so starting the others before the schema or the CA
   exists fails loudly rather than racing, and never generates a second CA.
2. **Give each process its own `metrics.bind_address`.** The counters are
   per-process memory, so three processes are three scrape targets; sharing one
   address means the second one to start fails to bind. Set
   `ACME_PROXY_METRICS__BIND_ADDRESS` per unit, point each at its own file with
   `ACME_PROXY_CONFIG`, or turn `metrics.enabled` off where you do not want it.
   Every series carries a `role` label naming the roles that process runs, so
   one scrape config can tell them apart.
3. **Run at least one worker.** A process without it logs
   `server_role_no_worker` at startup; a deployment without one issues nothing,
   because challenge validation, issuance, CRL signing, relay and custom
   revocations, notifications and the periodic sweeps are all queued work. A
   worker in another process picks a row up within the job poll interval, so
   clients see a second or so more `processing` than all-in-one; a revocation
   for a relay or custom profile still running when its request's deadline
   nears answers `503` with `Retry-After`, and asking again follows it.

## One systemd unit per role

A worked topology, one unit per role, each otherwise as in
[systemd](systemd.md):

```ini
# acme-proxy-worker.service
ExecStart=/usr/local/bin/acme-proxy serve --role worker
Environment=ACME_PROXY_METRICS__BIND_ADDRESS=127.0.0.1:3002

# acme-proxy-acme.service
ExecStart=/usr/local/bin/acme-proxy serve --role acme
Environment=ACME_PROXY_METRICS__BIND_ADDRESS=127.0.0.1:3012

# acme-proxy-admin.service
ExecStart=/usr/local/bin/acme-proxy serve --role admin
Environment=ACME_PROXY_METRICS__BIND_ADDRESS=127.0.0.1:3022
```

Run as containers instead, the same split is a Compose file with one service per
role; [Docker Compose, Roles Split](compose_roles.md) is the complete recipe.

## The database

**One host, one filesystem — on SQLite.** SQLite across processes is fine on a
local disk in WAL mode, and `busy_timeout` is already set — it is *not* safe on
NFS or across nodes. **Multi-node needs PostgreSQL**: point
[`database.url`](../configuration/reference.md#database) at a server instead of
a file, run `acme-proxy migrate` once, and the three roles can then live on
different hosts. Nothing else about the deployment changes.

An existing SQLite deployment moves across with its accounts, orders and audit
trail intact — stop the server, create and migrate the target, then
[`acme-proxy transfer --to <url>`](../operations/cli.md#moving-between-backends).
Starting the new deployment empty instead would leave every certificate it has
already issued impossible to revoke, so this is not an optional step.

## Operating a split deployment

Run one admin process either way; its login rate limiter is in memory, so two
would each get their own budget.

Each process reloads independently on `SIGHUP`, so a configuration change means
reloading all three.
