# Core Concepts & Glossary

This section explains the foundational concepts used within `acme-proxy`. Whether you are deploying it as an internal Local CA or as a secure relay to Let's Encrypt, understanding these terms will help you configure the server correctly.

## 1. Profile
A **Profile** is the core isolation boundary in `acme-proxy`. 
Instead of running multiple instances of the server for different environments, you can define multiple profiles. Every profile acts as an independent ACME server, exposed at `/profile/<name>/directory`.
- Accounts and orders are isolated per profile.
- Each profile has its own configuration for *Signers*, *Filters*, and *Challenge Validation*.
- Example: You might have a `dev` profile that uses a Local CA and bypasses network challenges, and a `prod` profile that relays to Let's Encrypt and enforces strict NetBox filtering.

## 2. Signer
A **Signer** is the component responsible for actually minting the TLS certificate once `acme-proxy` determines a client is authorized. 
- **Local CA**: An embedded, in-memory or on-disk Certificate Authority that signs certificates directly. Ideal for internal development and offline environments.
- **ACME Proxy**: A relay that forwards the signing request to an upstream CA (like Let's Encrypt, ZeroSSL, or Commercial CAs that support ACME).
- **Custom Script**: A mechanism to shell out to legacy enterprise PKI systems (e.g., passing the CSR to a bash script that calls a legacy API).

## 3. Filter
A **Filter** is an authorization policy applied to incoming ACME orders. Before `acme-proxy` even attempts to validate a challenge or forward an order, it runs the request through the configured filters.
- If *any* filter rejects the request, the order is denied immediately.
- Filters can inspect the client's IP address, the requested domain names, or query external systems like IPAMs (e.g., NetBox) to verify ownership.

## 4. EAB (External Account Binding)
**External Account Binding** (RFC 8555) is a security mechanism where the server requires a pre-shared key (a Key Identifier and an HMAC secret) to register a new ACME account. 
In `acme-proxy`, this ensures that even if an internal client can reach the ACME directory, they cannot request certificates unless you (the operator) have explicitly minted an EAB credential for them out-of-band.

## 5. ARI (ACME Renewal Information)
**ACME Renewal Information** (RFC 9773) is a modern extension that allows the CA to signal to the client *when* it should renew a certificate. `acme-proxy` supports this, allowing operators to dynamically adjust renewal windows (e.g., forcing all internal clients to renew early if a CA key needs to be rotated).

## 6. Order
An **Order** represents a client's request for a certificate. It contains the identifiers (e.g., domains) the client wants, and progresses through the states RFC 8555 defines:

- `pending` — created; one or more authorizations still need to be satisfied.
- `ready` — every authorization is `valid`; the client may now `finalize`.
- `processing` — issuance is under way but not finished.
- `valid` — the certificate is available.
- `invalid` — terminal failure.

`acme-proxy` enforces these transitions in the database itself, with a `CHECK` constraint on the status column.

Two details are easy to trip on:

- **`processing` only appears with a deferring backend.** The `acme_proxy` relay answers `finalize` with `processing` and completes in the background; `local_ca` and `custom` answer inline, so an order under those backends goes straight from `ready` to `valid` and never passes through `processing`.
- **Revocation is orthogonal to this machine.** RFC 8555 defines no "revoked" order status, so a revoked order's `status` stays `valid`. The revocation timestamp and reason are recorded separately and are visible only through the admin CLI — see [Revocation & CRL](../operations/revocation.md).

## 7. Challenge
A **Challenge** is the concrete proof that a client controls an identifier: serving a token over HTTP, publishing a DNS TXT record, or presenting a special certificate in a TLS handshake. Each authorization carries one challenge per enabled type, and satisfying **any one** of them makes the authorization `valid`. See [Challenge Validation](../challenges/index.md).
