# ADR 0007: One binary runs as role processes, and only the worker holds the CA key

## Status

Accepted.

## Context

A certificate authority has three very different kinds of work, and they carry
different risks:

- **Serving ACME** means parsing untrusted JWS and CSRs from the internet.
- **Serving the web admin** means holding operator sessions that can revoke
  certificates and mint EAB credentials.
- **Doing background work** means dialling hosts the clients chose, talking to
  an upstream CA, sending mail, and signing with the CA key.

In one process, a bug in the first kind of work reaches the key used by the
third. The obvious answer, separate binaries, would cost a second configuration
surface and a second release artefact. It would also create a protocol between
the binaries, where one database and one job queue already do the job.

## Decision

- **One binary, one configuration, several processes.**
  `acme-proxy serve --role acme,admin,worker` selects what a process does. With
  no `--role`, a process does all three, exactly as before the flag existed.
- **The three roles:**
  - `acme` serves ACME and the root router;
  - `admin` serves the panel;
  - `worker` drains the job queue and owns the schema ([ADR
    0003](0003-migrations-frozen-and-explicit.md)) and the first-run material.

  Each role only enqueues work it does not do itself. Every role may serve its
  own `/metrics`.
- **Only the worker builds a signing backend.** The signer is split in two
  (`crates/signer/`):
  - **`SignerInfo`**, the read side: the CA certificate, the stored CRL, a
    relay's lazily discovered directory and `http-01` store, and a `custom`
    script's read hooks. Every role builds it, from public material only.
  - **`SignerBackend`**, the write side: issue and revoke. Only the worker
    builds it, in `Assembly::build_parts`.

  `Profile` has no backend field at all. The job handlers take their backend
  from `GenerationParts::signers`.
- **The worker stores each CA's first CRL before it serves**
  (`store_first_crls`, at startup and before publishing a reload), since the
  read side never signs.
- **Roles are a flag, not a configuration key**, so they cannot change under
  `SIGHUP`. That is what lets a reload compare the same role set on both sides.
- **`ProcessRole` is not `sockets::Role`.** The first names the three *jobs* a
  process does. The second names the three *listeners* it holds (`acme`,
  `admin`, `metrics`). `worker` holds no socket, and `metrics` is a socket any
  role may serve, so neither set fits inside the other.

## Consequences

- An `acme` or `admin` process never reads `ca.key`, never logs in to a token,
  and never registers upstream. It starts even when it cannot read the key.
- An `acme` or `admin` process that finds no CA certificate refuses to start,
  naming `acme-proxy init`, because the first-run material belongs to the
  worker.
- Without a worker in the same process, queued work waits for one elsewhere. The
  process logs the advisory `server_role_no_worker`. A process that does not
  own the schema and finds it behind refuses with `server_schema_behind`.
- The wake-up is in-process. A worker in another process picks up a new row
  within `jobs.poll_interval_ms`, whereas the claim itself is race-free across
  processes.
- Counters live per process, so each process needs its own
  `metrics.bind_address`. A `role` label is added when the metrics are rendered.
- `--role` is parsed by clap, so an unknown name is refused before
  `Config::load` and before `Database::open`, which creates the database file.
- State that several processes share cannot live in memory or in a file one of
  them owns ([ADR 0008](0008-shared-state-in-the-database.md)).

The supported topologies are in
[Deployment](../../getting_started/deployment.md#running-the-roles-as-separate-processes).

## Enforced by

- `the_request_path_never_holds_a_signer` and `the_cli_never_builds_a_signer`
  (`tests/layering.rs`).
- `tests/roles.rs`, which starts acme and admin processes against a `key_path`
  that does not exist and drives an order to `valid` across three processes over
  one file-backed database.
- `an_unknown_role_is_refused_by_name` (`crates/server/src/roles.rs`).
- `info_from_config_agrees_with_the_backends_own_info`
  (`crates/signer/src/lib.rs`).
