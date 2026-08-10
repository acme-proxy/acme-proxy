# Key Rollover

`acme-proxy` fully supports Account Key Rollover (RFC 8555 §7.3.5) via the `POST
/keyChange` endpoint.

This allows a client to proactively rotate the cryptographic key-pair associated
with their ACME account without needing to register a new account or abandon
their existing authorizations and orders.

## Cryptographic verification

The key rollover process is highly secure and requires the client to prove
possession of **both** the old and the new key simultaneously to prevent
hijacking.

1. **Inner JWS**: The client constructs a JSON Web Signature (JWS) whose payload
   names the account and the new key, signed by the **new** key itself.
2. **Outer JWS**: That inner JWS becomes the payload of an outer JWS, signed by
   the **old** key currently on the account and carrying its `kid`.
3. `acme-proxy` unwraps this nested structure and verifies **both** signatures
   (ES256 or RS256, via `ring`). The outer signature proves the request comes
   from the current account holder; the inner one proves possession of the new
   key, so a key the requester does not control cannot be installed.
4. **Collision check**: the proxy checks that the new key does not already
   belong to another account. If it does, the request is rejected with `409
   Conflict` plus a `Location` header naming the account that already holds the
   key.
5. **Update**: the account's stored public key is replaced in a single
   statement.

Because accounts are keyed `UNIQUE(profile, pubkey)`, the collision check is
scoped per profile — the same key legitimately belonging to a different account
at a *different* profile is not a conflict.

## Client support

Many modern clients support key rollover natively. For instance, using `lego`:
```bash
lego --server https://acme.internal/profile/default/directory \
     --email "admin@example.com" \
     accounts keyrollover
```
*(Note: Ensure you are using a recent version of the client, as older clients
may lack support for the `keyChange` endpoint).*
