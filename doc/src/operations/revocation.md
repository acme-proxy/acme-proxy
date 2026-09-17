# Revocation & CRL

`acme-proxy` implements certificate revocation per RFC 8555 §7.6, and — with the
`local_ca` backend — publishes the resulting Certificate Revocation List.

## `POST /revokeCert`

Revocation is available to a client through the standard ACME endpoint,
advertised in the directory. The request payload carries the base64url DER of
the certificate and an optional `reason` code.

### Two ways to authorize it

RFC 8555 allows either, and `acme-proxy` accepts both:

1. **The order's account**, signing with its `kid` as usual.
2. **The certificate's own key pair**, signing with an embedded `jwk` and *no
   account at all*. This is the RFC's accountless case, and it is what lets the
   holder of a compromised key revoke it even if the ACME account is gone.

Because of the second form, this endpoint resolves authorization itself rather
than going through the usual account lookup, and it is deliberately **not**
gated on the account's status — a deactivated account can still revoke its
certificates.

### How the certificate is identified

The submitted DER is decoded, the order is looked up by the certificate's serial
number, and the stored leaf is then compared to the submitted bytes for an
**exact DER match**. A serial-only lookup would not be enough on its own; the
byte comparison is the safety net.

> One subtlety worth stating, because getting it wrong is a vulnerability: the
> key checked against the account is the one **stored** with the order, never a
> key re-derived from the submitted certificate. Re-deriving it would let anyone
> who merely observed the certificate on the wire revoke it, since the
> certificate contains its own public key.

### Responses

- **`200 OK`** — revoked.
- **`400 alreadyRevoked`** — the certificate was already revoked. This is
  checked *after* authorization, so an unauthorized caller cannot use the
  endpoint to probe whether a certificate has been revoked.
- **`400 badRevocationReason`** — the reason code is out of range.
- **`401 unauthorized`** — the signer is neither the order's account nor the
  certificate's key.

### Reason codes

Reason codes are RFC 5280 §5.3.1 values. Codes 7 and 11 are not valid CRL
reasons, and out-of-range values are meaningless; in all three cases
`acme-proxy` records the revocation with **no reason** rather than refusing it.
Revoking is always preferable to arguing about why.

## Ordering: the CA acts first

The signer backend's own `revoke` is called **before** the order is marked
revoked locally. The CA-side action is authoritative, so if the signer fails,
the order is deliberately left un-revoked and the operation can simply be
retried. A backend's `revoke` must therefore be **idempotent** — it may
legitimately be called again for a certificate it has already revoked.

## Revocation is orthogonal to the order state machine

RFC 8555 defines no "revoked" order status, so a revoked order's `status` stays
`valid`. The revocation timestamp and reason are stored in separate columns and
are **not** exposed in the ACME JSON a client polls.

They are visible through the admin CLI:

```bash
acme-proxy order show <id>          # prints revoked, reason and the serial
acme-proxy order show <id> --json   # the same as revokedAt / revocationReason
```

## Revoking as an operator

For an out-of-band compromise report that the certificate holder cannot or will
not act on:

```bash
acme-proxy order revoke <order-id> --reason 1
```

This calls the signer's `revoke` hook directly, exactly as the ACME endpoint
does. It is **not** confirm-gated — unlike `order delete` — because revocation
only ever tightens trust; there is no destructive outcome to protect against.

With `local_ca`, the command records the revocation in the database and stores
a new CRL there. A server already running over the same database serves that
CRL on its very next `GET /crl`; there is nothing to restart.

See [Admin CLI](cli.md).

## `GET /crl`

With the `local_ca` backend, the CRL (RFC 5280) is served unauthenticated at
`{base_url}/profile/<name>/crl`, with content type `application/pkix-crl`.

- It is **routed but deliberately not advertised** in the ACME directory. A CRL
  is CA infrastructure, not an ACME resource, so it has no directory entry.
- A valid, correctly signed **empty** CRL exists from the moment the CA is
  created, before anything has ever been revoked. Clients fetching it do not
  have to special-case "no revocations yet".
- It is signed again on every revocation, and by a daily refresh; see below.

The revocations and the current signed CRL live in the **database**, keyed by
the CA's key, so every process over one database — the server, `acme-proxy
order revoke`, a reloaded configuration — serves the same CRL. Backing up the
database backs up the revocations; there is no separate file to keep in step
with it.

`crl_path` still holds the current CRL, as PEM, rewritten every time a new one
is stored. It is an **export** for operators who publish the CRL from a static
web server: nothing ever reads it back, and losing it loses nothing. A second
file, `ca.json.lock`, sits beside it and is held while the export is written, so
two processes cannot leave an older CRL in place of a newer one. It is always
empty and needs no backup.

### Upgrading from a JSON ledger

Before revocations moved into the database, they were kept in a **JSON
sidecar** beside `crl_path` — the same path with the extension swapped to
`.json`, so `ca.crl` was accompanied by `ca.json`. The first time a CA meets a
database with no CRL for it, the sidecar is imported: every entry becomes a
revocation, and the CRL number resumes above the last one the sidecar
published. The server logs `local_ca_ledger_imported` when it happens, which is
at startup through the daily refresh's first pass, or at the first revocation
or CRL fetch if that comes sooner.

The import happens **once**. The sidecar is never read again nor written, so
edits to it after that change nothing. Keep it with an old backup if you like,
or delete it.

A sidecar that cannot be imported — a hand-edited serial that is not hex, say —
is logged as `local_ca_crl_initialization_failed`, naming the entry. Until it
is fixed, that CA's revocations and `GET /crl` fail rather than proceed without
the history the sidecar holds; the import is tried again on the next attempt.

### Expired entries are dropped

A revocation entry is not kept for ever. RFC 5280 §3.3 permits removing one once
the certificate itself has expired — nothing can present it any more — and this
is what stops the CRL growing for the life of the deployment. The prune runs
daily, starting shortly after startup.

The same daily pass re-signs a CRL that has less than half of its seven-day
validity left, even when nothing was revoked or pruned, so a quiet CA's CRL
never lapses. When neither applies, nothing is signed.

Two rules are worth knowing:

- An entry is dropped an hour after the certificate's own `notAfter`, not at it.
  A relying party whose clock is behind yours still considers the certificate
  valid for a moment, and that moment is exactly when it would otherwise accept
  one you revoked.
- An entry whose expiry is **unknown** is never dropped. That is any entry
  recorded before this server started tracking expiries (see below), and an
  unknown expiry is not an expired one.

Each CRL carries a `crlNumber` that only ever increases, including across a
restart, across a prune that shortens the list, and across several processes
signing for one CA. A client that meets a lower number than it has cached keeps
its cached CRL, so the number is stored with the CRL and a new one is only ever
stored over the one it was numbered after.

Sidecars written by 0.1.0 are a bare JSON array with no expiries and no number.
They are imported as-is, with the number resuming above anything that format
could have published. Their entries have no known expiry, so they stay on the
CRL.

### Telling clients where it is

A certificate does not point at this CRL until you say where to fetch it.
`signer.local_ca.crl_distribution_points` is that URL: set it, and every leaf
issued from then on carries a `cRLDistributionPoints` extension naming it (and
`ca_issuer_urls` does the same for the CA's own certificate). Both are empty by
default, so out of the box the CRL above is reachable only by somebody who
already knows this server exists.

Two things follow from a URL being signed into a certificate:

- **Certificates already issued keep the URL they were signed with**, for their
  whole validity. Changing the key changes nothing that is already out there,
  which is why the value is yours to choose rather than something derived from
  `server.base_url`.
- **The URL above is not automatically a good answer.** `/crl` is served by the
  profile router, so it sits behind that profile's filter policy; an
  address-based rule will refuse it to relying parties outside the allowlist.
  Either add a `path` check permitting `/crl` (see [The `path`
  check](../filters/path.md)) or publish a copy of `crl_path` somewhere
  unconditionally reachable and name *that*.

See [Local CA](../signers/local_ca.md#reference) for both keys.

### Other backends

- **`custom`** — the CRL comes from the script's `crl` hook, and only when
  `signer.custom.supports_crl = true`. Otherwise there is nothing to serve. See
  [Custom Script Signer](../signers/custom.md).
- **`relay`** — the upstream CA publishes its own CRL or OCSP responder;
  this server does not republish it.

## Interaction with renewal information

A certificate `acme-proxy` knows to be revoked is reported through
[ARI](../features/renewal_info.md) with a renewal window **entirely in the
past**, prompting a compliant client to renew immediately.

That check happens *before* the signer backend is consulted, so a locally
revoked certificate is never talked out of renewing by an upstream CA that has
not yet noticed.
