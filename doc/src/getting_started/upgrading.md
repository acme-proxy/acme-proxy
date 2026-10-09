# Upgrading

Replace the binary, **migrate**, and restart. The schema is **append-only as of
0.1.0** — a new release only ever adds migrations, never rewrites
the ones your database has already applied.

Migrations no longer run as a side effect of opening the database. `acme-proxy
serve` running the `worker` role (which the default does) still applies them at
startup, so a single-process deployment can simply restart; anything else — an
admin command, or a split deployment's `acme`/`admin` process — checks the
schema and refuses by name until `acme-proxy migrate` has run.

```bash
systemctl stop acme-proxy
install -m 0755 acme-proxy /usr/local/bin/acme-proxy
acme-proxy migrate          # explicit; the default `serve` would also do it
systemctl start acme-proxy
journalctl -u acme-proxy -n 50
```

A container is upgraded the same way, with the image tag in place of the binary:
pull the new tag, migrate with it against the same `/data`, then recreate the
container on it. With Docker Compose, after changing the `image:` line:

```bash
docker compose pull
docker compose stop acme-proxy
docker compose run --rm acme-proxy migrate
docker compose up -d
docker compose logs -n 50 acme-proxy
```

`migrate` after the service name replaces the image's default `serve` command
for that one container. A single-container deployment would also migrate as it
starts; running it as a step of its own stops the upgrade on the error, instead
of leaving a server in a restart loop. A split deployment must migrate before
any of its `acme` or `admin` containers start on the new tag — [Docker
Compose, Roles Split](compose_roles.md#upgrading) gives the order. The advice
below applies unchanged, the database backup first of all.

Worth knowing before you do it:

- **Take a copy of the database first.** SQLite in WAL mode means three files;
  copy them together with the server stopped, or use `sqlite3 acme.db ".backup
  backup.db"` on a running one. Migrations are not reversible, so a downgrade
  means restoring this copy.
  On PostgreSQL, `pg_dump` is the copy.
- **`db_migration_failed` at startup means the process is not serving.** The
  most likely cause is running an *older* binary against a database a newer one
  has already migrated.
- **Files outside the database are untouched.** The CA key and certificate, the
  exported `ca.crl`, the upstream account key and its `.kid` sidecar all
  persist across an upgrade — back them up on the same schedule as the database,
  since the CA key is the one thing that cannot be regenerated without
  redistributing trust. See [Trusting the CA](trusting_the_ca.md).
- **Read the changelog's `Breaking` section first.** Before 1.0.0 the schema is
  the only compatibility guarantee: configuration keys, profile names, the admin
  JSON API, log event names and the CLI may all have moved, and every such
  change is listed there. See
  [Compatibility](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility).
  A renamed key is normally refused by name at startup — the server stops with
  an error naming the replacement rather than coming up looking configured — so
  `acme-proxy filter show` and a `--help` are cheap pre-restart checks.
