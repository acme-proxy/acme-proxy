# Core Concepts & Glossary

Seven words carry most of the meaning in the rest of this book. This page
defines them once, in the order you meet them, so that every other page can use
them without re-explaining.

## Profile

A **profile** is an independent ACME endpoint, and the isolation boundary
everything else sits inside. Rather than running one process per environment,
you define several profiles in one; each is served at
`/profile/<name>/directory`.

Accounts and orders are isolated per profile — the same client key at two
profiles is two unrelated accounts — and each profile carries its own signer,
filters, challenge validation and EAB policy. A `dev` profile backed by a local
CA can sit beside a `prod` profile relaying to Let's Encrypt under strict NetBox
filtering, in one process, over one socket and one database.

See [Profiles & Routing](profiles.md).

## Signer

A **signer** is what actually produces the certificate once a client has been
authorized. Which one runs is a per-profile configuration choice, and the client
never sees the difference.

- **Local CA** — an embedded certificate authority signing directly. The issuing
  key is a file, or a PKCS#11 token.
- **ACME Proxy** — a relay that opens its own order with an upstream ACME CA and
  returns what that CA signs.
- **Custom script** — anything else: a legacy PKI, an internal API, a CA that
  does not speak ACME.

See [Signers](../signers/index.md).

## Filter

A **filter** is a policy applied to a request before anything is signed. Filters
answer "may this client ask for this?", which challenge validation does not: a
client can genuinely control a name and still have no business holding a
certificate for it from you.

All enabled filters must pass and the first denial wins. They act at two points
— on the connection, and on the identifiers, the latter running again at
`finalize` against the names in the CSR.

See [Filters](../filters/index.md).

## EAB (External Account Binding)

**External Account Binding** (RFC 8555 §7.3.4) makes `newAccount` require a
credential you minted out of band — a key identifier and an HMAC secret.
Reaching the directory is then no longer enough to register: an operator has to
have issued that client a credential first.

It runs in the other direction too. A commercial CA that granted you one scarce
EAB credential is exactly the case the relay backend exists for: one upstream
credential, any number of local ones.

See [External Account Binding](../features/eab.md).

## ARI (ACME Renewal Information)

**ACME Renewal Information** (RFC 9773) lets the CA tell a client *when* to
renew, rather than leaving it to guess from the expiry date. Two things follow:
a fleet spreads its renewals across a window instead of stampeding at the same
moment, and a CA that needs certificates replaced early can say so and be
listened to.

See [Renewal Information](../features/renewal_info.md).

## Order
An **order** is a client's request for a certificate. It names the identifiers
wanted and progresses through the states RFC 8555 defines:

- `pending` — created; one or more authorizations still need to be satisfied.
- `ready` — every authorization is `valid`; the client may now `finalize`.
- `processing` — issuance is under way but not finished.
- `valid` — the certificate is available.
- `invalid` — terminal failure.

```mermaid
stateDiagram-v2
    [*] --> pending: newOrder
    pending --> ready: every authorization valid
    ready --> pending: an authorization is deactivated (§7.5.2)
    ready --> processing: finalize, deferring backend
    ready --> valid: finalize, inline backend
    processing --> valid: upstream issued
    ready --> invalid: signer failure
    processing --> invalid: upstream refused
    pending --> invalid: an authorization failed, or expires passed
    valid --> [*]
    invalid --> [*]
```

`acme-proxy` enforces these transitions in the database itself, with a `CHECK`
constraint on the status column — see
[Database Schema](../dev/database.md#check-constraints-hold-the-state-machines).

`ready → pending` is the one backwards edge, and it exists only so §7.5.2 can
hold: deactivating an authorization on an order that already reached `ready` has
to demote it, or the order would be finalizable for a name no longer authorized.

Two details are easy to trip on:

- **`processing` only appears with a deferring backend.** The `acme_proxy` relay
  answers `finalize` with `processing` and completes in the background;
  `local_ca` and `custom` answer inline, so an order under those backends goes
  straight from `ready` to `valid` and never passes through `processing`.
- **Revocation is orthogonal to this machine.** RFC 8555 defines no "revoked"
  order status, so a revoked order's `status` stays `valid`. The revocation
  timestamp and reason are recorded separately and are visible only through the
  admin CLI — see [Revocation & CRL](../operations/revocation.md).

## Challenge

A **challenge** is the concrete proof that a client controls an identifier:
serving a token over HTTP, publishing a DNS TXT record, or presenting a special
certificate in a TLS handshake.

Each authorization carries one challenge per enabled type, and satisfying **any
one** of them makes the authorization `valid` — the others stay `pending` for
ever, which is correct rather than a stuck state.

See [Challenge Validation](../challenges/index.md).
