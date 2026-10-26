# ADR 0016: Several instances of every role over one PostgreSQL is a supported topology

## Status

Accepted.

## Context

[ADR 0007](0007-role-processes.md) split the process into roles, [ADR
0008](0008-shared-state-in-the-database.md) moved the state they share into the
database, and [ADR 0014](0014-postgresql-beside-sqlite.md) added a backend that
several hosts can reach. Between them, two copies of each role over one
PostgreSQL mostly worked already, but nothing declared it, and three gaps made
it unsafe to rely on:

- The web admin's sign-in limiter was the one piece of shared state still
  counted in process memory, so a second admin process was a second
  brute-force budget. The book said to run exactly one.
- A worker generated a CA whenever `ca.key` was missing. A second worker host
  started without the copied key files minted a CA of its own, silently, and a
  endpoint then issued from two CAs over one database.
- The only probe was `/health`, which answers whenever the process accepts a
  connection. A load balancer could not tell that an instance had lost its
  database.

The multi-process test suites were also meant to run on PostgreSQL in CI, and
did not: both wrote a `sqlite://` URL of their own.

High availability was requested in issue #12, including across two sites, and
a Raft-replicated SQLite (dqlite) was suggested for that. Consensus is the
right requirement, but it belongs to the database's operations, not to this
server. A Raft group needs a majority, so two sites cannot survive losing
either one, whatever replicates the data. dqlite is a C library with no `sqlx`
driver ([ADR 0009](0009-dependency-policy.md)). It would also be a third
backend beside the seam ADR 0014 confined the dialects to. PostgreSQL already
fails over by consensus (Patroni with etcd, or a managed service), behind one
endpoint.

## Decision

- **Supported: any number of `acme`, `admin` and `worker` processes, on any
  number of hosts, over one PostgreSQL endpoint.** The endpoint follows the
  primary (a virtual IP, HAProxy or pgbouncer). Making that endpoint highly
  available, and spanning sites, is the database's concern and out of this
  server's scope.
- **No state that several processes see lives in a process.** The sign-in
  limiter is the `admin_login_buckets` table, and a reservation is one
  conditional `UPDATE`. That closes ADR 0008's last exception.
- **Each `local_ca` endpoint issues from exactly one CA, recorded in the
  database** (`endpoint_issuers`). A worker, `init` and a reload check their CA
  against it before building any backend. A different CA is refused, and so is
  no CA once one is recorded, rather than generating one. The first record is
  insert-if-absent. A deliberate change is `acme-proxy endpoint issuer accept`,
  which is audited.
- **Readiness is `GET /ready`**: a `SELECT 1` bounded to two seconds, on both
  listeners. `/health` stays liveness and touches nothing, so a database
  outage takes nodes out of rotation without restarting them.
- **The multi-process suites run on both backends**, with each test given its
  own PostgreSQL schema under `TEST_POSTGRES_URL`.

## Consequences

- A refused sign-in attempt costs one indexed `UPDATE`, which is far cheaper
  than the key derivation it saves. A limiter that cannot reach its table
  refuses the sign-in (fails closed).
- A worker's first start after the upgrade records the CA it loads. From then
  on, replacing `ca.pem`/`ca.key` without `endpoint issuer accept` stops every
  worker, by design. That is a breaking change for anyone who rotated a CA by
  swapping files.
- A job a dead worker held waits for its lease to run out (`jobs.lease_seconds`,
  or a handler's own lease) before another worker takes it. There is no lease
  heartbeat yet, because the lease is also the attempt's timeout and
  decoupling the two is its own change.
- Upgrades are not rolling: every process stops, `migrate` runs once, and
  everything starts on the new binary.
- SQLite stays a one-host backend.

## Enforced by

- `tests/roles.rs`: `two_admin_processes_share_one_login_budget`,
  `a_worker_without_key_files_refuses_rather_than_generating`,
  `a_second_worker_with_another_ca_refuses_to_start`,
  `two_workers_share_one_queue` and `a_job_held_by_a_dead_worker_is_reclaimed`.
  CI's `postgres` job runs them against PostgreSQL through `TempDir::shared`.
- `a_concurrent_burst_gets_exactly_the_limit`
  (`crates/store/src/admin_login_bucket.rs`).
- `crates/signer/src/local_ca/identity.rs` and its tests.
- `ready_follows_the_database_and_health_does_not` (`tests/basic_endpoints.rs`).
