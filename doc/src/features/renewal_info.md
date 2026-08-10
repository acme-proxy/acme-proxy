# Renewal Information (ARI)

`acme-proxy` implements the ACME Renewal Information extension (RFC 9773). ARI
allows a CA to signal to ACME clients when they should ideally renew their
certificates. This prevents the "stampede" effect where thousands of
certificates expire simultaneously, and allows the CA to orchestrate graceful
mass-revocations by shortening the renewal window.

## `GET /renewalInfo/{certID}`

This is an unauthenticated endpoint clients use to ask "when should I renew this
certificate?". The response provides a time window (Start and End).

The window is resolved in this order:

1. **Revoked certificates win.** If the certificate is known to be revoked
   locally (looked up by its serial), the answer is a window **entirely in the
   past**, prompting a compliant client to renew immediately. This is checked
   **before** the signer backend is consulted, so a locally revoked certificate
   is never talked out of renewing by an upstream CA that has not noticed yet.
2. **The backend's own opinion**, if it has one. The `relay` backend relays
   the upstream CA's answer verbatim, including RFC 9773 §4.2's optional
   `explanationURL` — so if Let's Encrypt signals early renewal, that reaches
   your internal clients unchanged. The `custom` backend can do the same through
   its `renewal_info` hook, but **only when `signer.custom.supports_renewal_info
   = true`**; otherwise the hook is never invoked.
3. **A local estimate**, when the backend has no opinion — always the case for
   `local_ca`. The certificate's `notBefore` and `notAfter` are read by
   **parsing the certificate itself**, and the suggested window runs from **⅔ to
   ¾ of the validity period**. For a 90-day certificate that is roughly day 60
   to day 67, leaving a comfortable margin before expiry rather than running up
   to it.

Spreading clients across that window is what prevents the "stampede" effect
where a whole fleet renews at the same moment.

## The `replaces` field

During a `newOrder` request, an ARI-aware client can include a `replaces` field
containing the `certID` of the certificate it intends to replace.

`acme-proxy` validates it against all three of RFC 9773 §5's correspondence
rules. The `certID` is decoded into an Authority Key Identifier and a serial
number, the predecessor order is looked up, and then:

1. **The AKI must match** the predecessor's issuer — the serial alone is not
   enough, since serials are only unique per issuer. (A certificate stored
   before this check existed may have no recorded AKI; that case falls back to
   matching on serial alone, for backwards compatibility.)
2. **The predecessor must belong to the requesting account.** You cannot claim
   to replace someone else's certificate.
3. **The new order must share at least one identifier** with the predecessor. A
   renewal that covers none of the same names is not a replacement.

Failing any of them is `malformed`; an unknown `certID` likewise.

**Concurrency guard**: a client cannot have two orders replacing the same
predecessor. A second `newOrder` naming a `replaces` value already claimed gets
`409 alreadyReplaced`. An order that later becomes `invalid` releases its claim,
so a failed attempt does not permanently block a retry.

The accepted `replaces` value is stored and reflected back on the `201` response
*and* on every subsequent poll of the order.
