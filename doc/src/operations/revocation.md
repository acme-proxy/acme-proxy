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
acme-proxy order show <id>          # includes revokedAt / revocationReason
acme-proxy order show <id> --json
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

See [Admin CLI](cli.md).

## `GET /crl`

With the `local_ca` backend, the CRL (RFC 5280) is served unauthenticated at
`{base_url}/profile/<name>/crl`, with content type `application/pkix-crl`.

- It is **routed but deliberately not advertised** in the ACME directory. A CRL
  is CA infrastructure, not an ACME resource, so it has no directory entry.
- A valid, correctly signed **empty** CRL exists from the moment the CA is
  created, before anything has ever been revoked. Clients fetching it do not
  have to special-case "no revocations yet".
- It is regenerated on every revocation and at startup.

The durable record of revoked serials is a **JSON sidecar** beside `crl_path` —
the same path with the extension swapped to `.json`, so `ca.crl` is accompanied
by `ca.json`. The CRL's own DER is not read back to reconstruct state. **Back up
both files**: losing the sidecar loses the revocation ledger, and the next
regeneration would publish an empty CRL.

### Other backends

- **`custom`** — the CRL comes from the script's `crl` hook, and only when
  `signer.custom.supports_crl = true`. Otherwise there is nothing to serve. See
  [Custom Script Signer](../signers/custom.md).
- **`acme_proxy`** — the upstream CA publishes its own CRL or OCSP responder;
  this server does not republish it.

## Interaction with renewal information

A certificate `acme-proxy` knows to be revoked is reported through
[ARI](../features/renewal_info.md) with a renewal window **entirely in the
past**, prompting a compliant client to renew immediately.

That check happens *before* the signer backend is consulted, so a locally
revoked certificate is never talked out of renewing by an upstream CA that has
not yet noticed.
