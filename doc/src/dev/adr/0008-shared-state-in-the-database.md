# ADR 0008: State that more than one process can see lives in the database

## Status

Accepted. Its one exception, the web admin's login limiter, was closed by [ADR
0016](0016-multi-instance-deployment.md): the counter is the
`admin_login_buckets` table, so several admin processes are a supported
topology.

## Context

Several pieces of state used to live in process memory or in files beside the
binary. Each was correct only while exactly one process existed:

- **A local CA's revocations.** They lived in an in-memory ledger plus a JSON
  sidecar and a CRL file, and `GET /crl` served the in-memory DER. Each process
  rewrote both files at startup, and `order revoke` on the host wrote them
  beside a running server. Updates were lost, `crl_number` was duplicated, and
  the server served a stale CRL. A revocation could silently vanish from the
  CRL.
- **The relay's published `http-01` key authorizations**, held in an in-memory
  token store. The relay job publishes them, and the root router serves them,
  which may be in another process.
- **Reload.** Both of the above had to be handed from the outgoing
  configuration generation to the incoming one through an in-memory handover
  (`CarriedState`). Otherwise a reload would empty the CRL ledger or the token
  store under a live upstream fetch. Changing the endpoint set, `[signer]`,
  `[dns]` or `[proxy]` was therefore refused on `SIGHUP`.
- **Notification delivery.** A delivery queued by one process for an endpoint
  another process had not yet reloaded was retired as `Failed` for good.

Role processes ([ADR 0007](0007-role-processes.md)) turn every one of these from
a latent bug into a routine one.

## Decision

- **Revocation state is two tables**, keyed on the issuer: the hex SHA-256 of
  the CA certificate's SPKI, so two endpoints over one CA are one issuer.
  - `revocations` holds one row per serial. A repeat does nothing, so the first
    revocation's time and reason stand.
  - `crls` holds the current CRL for each issuer. It is replaced only through
    a compare-and-swap on `crl_number`
    (`StoredCrl::replace_if_number`), which keeps the number monotonic across
    processes.
  - `GET /crl` serves the stored row.
  - The old sidecar is imported once, in the same transaction as the first
    `crls` row, and never written again.
  - `signer.local_ca.crl_path` becomes an export that nothing reads back.
- **`http01_tokens`** holds the relay's key authorizations, keyed on the
  upstream's token and reaped by an hourly sweep.
- **A backend whose configuration did not change is reused on reload; one whose
  configuration changed is rebuilt.** The outgoing and incoming instances share
  the tables, so there is nothing to hand over. `CarriedState` is gone.
- **An unknown endpoint or backend is a bounded `Retry`, not `Failed`**, so a
  delivery survives a rolling reload across processes.
- **Files stay files where that is a security property.** `ca.key` (or its
  PKCS#11 token) and the upstream account key remain files. The database is
  readable by every role and by every backup, whereas a key file can be readable
  only by the worker's uid.

## Consequences

- `order revoke` beside a running `serve` appears in that server's `GET /crl`
  once its worker has signed, with no restart and no lost update.
- The endpoint set, each endpoint's signer, `[dns]` and `[proxy]` all reload. Of
  everything in the configuration, only `database.url` is still refused on
  `SIGHUP`.
- `crl_number` never goes backwards (RFC 5280 §5.2.3). A client that meets a
  lower number than it has cached keeps the cached CRL, which means it keeps
  trusting what was revoked.
- `admin.login_max_attempts` is counted in `admin_login_buckets`, one row per
  scope and client address. Reserving an attempt is one conditional `UPDATE`,
  so a burst spread over several admin processes gets no more guesses than one
  process would give it. It was the last thing counted in memory, and the
  reason one admin process used to be the supported topology.

The CRL store's concurrency rules are in `crates/signer/src/local_ca/crl.rs`.

## Enforced by

- `concurrent_revocations_through_two_instances_are_all_kept` and
  `two_cas_over_one_database_keep_separate_crls`
  (`crates/signer/src/local_ca/mod.rs`).
- `tests/crl.rs` and `tests/roles.rs`.
- `tests/http01_responder.rs`.
- `a_concurrent_burst_gets_exactly_the_limit`
  (`crates/store/src/admin_login_bucket.rs`) and
  `two_limiters_over_one_database_share_one_budget`
  (`crates/admin/src/webadmin/session.rs`).
- `an_unknown_endpoint_or_backend_is_retried_within_its_budget`
  (`crates/jobs/src/notify/job.rs`).
