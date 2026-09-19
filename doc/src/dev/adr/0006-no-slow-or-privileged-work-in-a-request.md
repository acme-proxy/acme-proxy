# ADR 0006: A request does no slow or privileged work; it queues it

## Status

Accepted.

## Context

Three ACME operations used to do their real work inside the HTTP request:

- **`POST /chall/{id}`** awaited the challenge validation. That reached out to
  an address the *client* named, over DNS, HTTP or TLS, to a host that may never
  answer. It held an admission permit for the whole of `challenge.timeout_ms`.
  Up to `server.max_concurrent_requests` clients pointing at black-holed
  addresses could pin every permit. It also forced a startup rule that the
  request timeout exceed the validation timeout.
- **`finalize`** called the signing backend. The process parsing untrusted JWS
  and CSRs from the internet therefore held `ca.key`, a PKCS#11 login or a
  relay's upstream account.
- **Revocation** called the backend too, from `POST /revokeCert`, from the admin
  panel, and from `order revoke` on the host. Run beside a live server, the last
  of these could silently drop a revocation from the CRL.

RFC 8555 already has the states that queued work needs. A challenge is
`processing` while "the server is working on it" (§7.1.6), an order is
`processing` while "the certificate is being issued" (§7.4), and §8.2 pairs both
with `Retry-After`. certbot, acme.sh and lego all poll.

## Decision

**A request claims, queues and answers. The worker does the work.**

- **Validation.** `POST /chall/{id}` claims the challenge
  (`pending → processing`, a compare-and-swap), writes a `challenge_validate`
  job, and answers `200` with the challenge reading `processing` plus
  `Retry-After`. See `crates/protocol/src/acme/validate.rs`.
- **Issuance.** `finalize` checks the CSR and runs the filter synchronously. It
  then claims the order and queues `signer_issue` **in one transaction**, and
  answers `processing` for every backend. See
  `crates/protocol/src/acme/issue.rs`.
- **Revocation.** A local CA's revocation is a `revocations` row and the order's
  stamp in one transaction; the worker then signs the CRL. A relay or `custom`
  revocation is a `signer_revoke` job that the request waits on, for up to
  `server.request_timeout_ms` less a second, answering `503` + `Retry-After` if
  the job is still running. See `crates/protocol/src/acme/revoke.rs`.
- **A verdict is terminal.** A check that ran records its answer, pass or fail.
  A job is retried only when the attempt could not happen at all: the database
  is unreachable, or this process does not mount the profile. A backend's own
  `BadCsr` makes the order `invalid`, not `ready` again, because the client was
  already told `processing` and polls for a terminal state.
- **No stranded claim.** A failed enqueue releases its claim. `abandon` records
  a failure rather than leaving the client polling forever. `recover` re-queues
  a challenge left `processing` with no live job.
- **Each kind has one handler, covering every profile.** A row names its
  subject, the subject names its profile, and the profile names its validators
  or backend. The job registry refuses a second handler for a kind anyway.

## Consequences

- `challenge.timeout_ms` bounds a job attempt, not an HTTP request. The only
  timeout rule left at startup concerns `signer.custom`'s read hooks, the one
  backend call still made inline.
- A client sees `processing` on every finalize, including against a local CA.
  This shipped under `### Breaking`.
- The request path never names a signing backend, which is what lets the CA key
  leave the ACME process entirely ([ADR 0007](0007-role-processes.md)).
- A request no longer holds a permit during outbound I/O to a host the client
  chose.
- The integration harness runs a real worker. A test that triggers or finalizes
  must poll for the outcome rather than read it from the response.

## Enforced by

- `the_request_path_never_holds_a_signer` and `the_cli_never_builds_a_signer`
  in `tests/layering.rs`.
- `check_request_timeout`, the remaining startup refusal.
- `tests/challenges.rs`, `tests/orders.rs` and `tests/revoke_cert.rs`, which
  drive each operation through the queue.
