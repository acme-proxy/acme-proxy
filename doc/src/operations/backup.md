# Backup & Restore

Everything `acme-proxy` knows lives in two places: **the database**, and a
handful of **files** the configuration points at. A backup is both, taken on
the same schedule. This page lists them, gives the copy command for each
backend, and says what a restore does and does not bring back.

## What to back up

| What | Default path | Why it matters | If it is lost |
| --- | --- | --- | --- |
| The database | `sqlite.db` (+ `-wal`, `-shm`), or the PostgreSQL database `database.url` names | Accounts, orders, issued certificates, revocations, the CRL, EAB credentials, operators, the job queue and the audit trail | Every certificate already issued becomes impossible to revoke through this server, and every client must register again |
| The CA key | `signer.local_ca.key_path` (`ca.key`) | Signs every certificate and CRL | **Not recoverable.** A new CA means distributing trust again — see [The CA key is the exception](../security/rotation.md#the-ca-key-is-the-exception) |
| The CA certificate | `signer.local_ca.cert_path` (`ca.pem`) | The trust anchor clients installed | Recoverable only from wherever clients installed it |
| The upstream account key | `signer.relay.account_key_path` (`upstream_account.key`) and its `.kid` sidecar | The relay's identity at the upstream CA | Register a new upstream account; with an EAB-only upstream, that needs a fresh credential from the CA |
| The configuration | `config.toml`, or `ACME_PROXY_CONFIG` | Every endpoint, and the URLs clients stored | Rewritable, but every endpoint name and `server.base_url` must come back exactly, or clients' stored account URLs stop resolving |
| Secrets held outside the configuration | environment files, `*_file` paths | TSIG, IPAM, SMTP, OIDC and LDAP credentials | Re-issue each at its source — see [Secret Rotation](../security/rotation.md) |

Three files need **no** backup. `ca.crl` is an export the worker rewrites from
the database whenever a new CRL is signed, and `ca.json.lock` is always empty
(see [Revocation & CRL](revocation.md)). A self-signed `server.pem`/`admin.pem`
is generated again by `acme-proxy init`; back it up only if a client pins it.

A CA key held in a PKCS#11 token cannot be copied at all, by design. Its
recovery is planned differently — see
[Hardware Keys → Backup and disaster recovery](../signers/local_ca_hsm.md#backup-and-disaster-recovery).

In the published container image, every default path above resolves under
`/data`, so backing up that volume and the configuration covers everything
except the secrets you passed in the environment.

## SQLite

The database runs in WAL mode, so it is **three files**, and copying
`sqlite.db` on its own gives you a database missing every recent write. Two ways
to get a consistent copy:

```bash
# Online, against a running server: consistent by construction.
sqlite3 /var/lib/acme-proxy/acme.db ".backup /backup/acme-$(date +%F).db"

# Offline: stop every process first, then copy all three together.
systemctl stop acme-proxy
cp /var/lib/acme-proxy/acme.db* /backup/
systemctl start acme-proxy
```

`.backup` produces a single self-contained file with nothing to replay, and is
the one to schedule.

## PostgreSQL

`pg_dump` is the copy, and it is consistent while the server runs:

```bash
pg_dump --format=custom --file=/backup/acme-$(date +%F).dump \
  postgres://acme@db.internal/acme
```

A streaming replica is **not** a backup. It is what
[High Availability](../getting_started/high_availability.md#the-database) asks
for so that a failover loses nothing, but it copies a mistaken `DELETE` just as
faithfully as anything else.

## Restoring

1. **Stop every process** that uses the database — every role, on every host.
2. **Put the database back.** On SQLite, copy the backup into place as the
   `database.url` file and delete any stale `-wal` and `-shm` beside it. On
   PostgreSQL, restore into an empty database with `pg_restore`.
3. **Put the files back**, and check their owner and mode: `ca.key` must be
   `0600` and readable only by the uid that runs the `worker` role. A file
   restored from a backup often is not.
4. **Run `acme-proxy migrate`** if the backup predates the binary you are
   running. Migrations only move forward, so an older backup comes up to date,
   but a backup taken by a *newer* binary needs that newer binary.
5. **Start the worker first**, then the other roles, and watch for
   `server_startup` in the log.

A restore rolls the server back to the moment of the backup. Whatever happened
since is gone from its point of view:

- **Certificates issued since** are still valid and still trusted, but their
  orders are gone, so `acme-proxy order revoke` cannot find them, and an ACME
  client's `revokeCert` for one is refused as an unknown certificate. Nothing
  can put them on this server's CRL any more, which is the strongest reason to
  keep the backup interval short.
- **Revocations made since** are lost too: the CRL the restored server signs
  next no longer lists them. Revoke them again, from the audit trail of the
  lost period if you have it, or from your own records.
- **The CRL number goes back with the rest.** RFC 5280 expects it only to
  increase, and a relying party that cached a CRL signed after the backup may
  prefer it until its `nextUpdate`, so a revocation made in that window may not
  be seen until then.
- **Accounts registered since** no longer exist. Their clients get
  `accountDoesNotExist` and register again on their own.

## Testing a backup

A backup is only as good as the last restore that worked. Restore into a
scratch copy and ask it something, with the server untouched:

```bash
cp /backup/acme-2026-10-23.db /tmp/restore-test.db
ACME_PROXY_DATABASE__URL=sqlite:///tmp/restore-test.db \
  acme-proxy order list --limit 5
```

An admin command against a database whose schema is behind refuses by name,
which is itself a useful thing to learn before the day it matters.

## Moving to another backend

Changing backend is not a restore: `acme-proxy transfer --to <url>` copies
every row, ids and serials included, from the configured database into a new,
migrated, empty one. See
[Admin CLI → Moving between backends](cli.md#moving-between-backends).
