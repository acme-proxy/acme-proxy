# Troubleshooting

This section covers common issues when operating `acme-proxy` in production.

## The server refuses to start

Several configuration mistakes are deliberately fatal at startup rather than
silently degrading at runtime. The log line names the problem in each case.

| Message | Cause | Fix |
| --- | --- | --- |
| `no enabled [profiles]` | No profile is defined, or all are `enabled = false`. The server serves ACME only through profiles. | Add `[profiles.default]`, or set `ACME_PROXY_PROFILES__DEFAULT__ENABLED=true`. |
| Unknown or empty `challenge.enabled` | The list is empty or names a type that does not exist. This is fatal **even with `challenge.bypass = true`** — a bypassing server still has to advertise a challenge type. | Use one or more of `http-01`, `dns-01`, `tls-alpn-01`. |
| `allowed_ip` enabled with both lists empty | An allowlist filter that permits everything is a no-op, and almost certainly a mistake. | Populate `filter.allowed_ip.allow` or `.deny`, or drop `allowed_ip` from `filter.enabled`. |
| `request_timeout_ms` too small | It must exceed `challenge.timeout_ms` and, if configured, `signer.custom.timeout_ms` — both run *inline* inside a request, so a smaller whole-request deadline would cut them off every time. | Raise `server.request_timeout_ms`. |
| Two profiles sharing `ca.key` but differing elsewhere | Two `local_ca` instances over the same files would each rewrite the CRL from their own in-memory ledger. | Make the `[signer]` sections identical (they then share one backend), or give each profile its own CA files. |
| An entry name with an underscore | `[filter.custom.*]`, `[notify.custom.*]` and profile names must match `^[a-z0-9-]+$`. | Use hyphens: `threat-intel`, not `threat_intel`. |
| A `custom` backend enabled with no entries | Listing `"custom"` in `filter.enabled`/`notify.enabled` while the matching `custom_enabled` is empty. | Populate `custom_enabled`, or drop `"custom"`. |
| Upstream requires EAB, no `.kid` sidecar | The `acme_proxy` backend has never registered with the upstream. | Run `acme-proxy upstream register --profile <name> --eab-kid …`, or set `signer.acme_proxy.eab.kid`/`hmac_key` in configuration. |
| `key_source = "pkcs11"` … `built without` | `signer.local_ca.key_source = "pkcs11"` on a binary with no PKCS#11 support. Deliberately fatal rather than falling back to the file key, which would silently leave the CA key on disk. | Rebuild with `cargo build --release --features hsm`. |
| A PKCS#11 key that is not the certified one | The token key's public key does not match `cert_path` — almost always a wrong `key_label`. | See [Hardware Keys](../signers/local_ca_hsm.md#troubleshooting). |

Failures specific to a hardware CA key — PIN, token, slot and mechanism
problems — have their own table in
[Hardware Keys (PKCS#11)](../signers/local_ca_hsm.md#troubleshooting).

## A wildcard order is rejected

**Symptoms**: `newOrder` for `*.example.com` returns `rejectedIdentifier` naming `dns-01`.
**Cause**: Wildcards can only be proven with a DNS challenge, so `acme-proxy` accepts them only when `dns-01` is among `challenge.enabled`.
**Fix**: Add `dns-01` to `challenge.enabled`. See [Challenge Validation](../challenges/index.md#wildcards).

## A client suddenly cannot order anything

**Symptoms**: Every order-side request from one client returns `unauthorized`.
**Cause**: The account has been deactivated — by the client itself, or by `acme-proxy account deactivate`. Deactivation is permanent and blocks all issuance.
**Fix**: The client must register a new account.

## SQLite Database Locks
**Symptoms**: The server logs show `database is locked` errors during high concurrency order creation.
**Cause**: The database may not be utilizing Write-Ahead Logging (WAL) or your filesystem does not support proper locking mechanisms (e.g., NFS).
**Fix**: Ensure `acme-proxy` is running on a local filesystem and `journal_mode = WAL` is applied. (The server automatically attempts to enable WAL on startup).

## Upstream Let's Encrypt Rate Limits
**Symptoms**: Order finalization fails with HTTP 429 Too Many Requests from the upstream CA.
**Cause**: When using the `acme_proxy` signer backend, all internal clients share a single external ACME account. Let's Encrypt applies rate limits (e.g., 50 certificates per registered domain per week).
**Fix**: Request a rate limit increase for the root domain you are relaying, or implement careful caching mechanisms on your internal servers to prevent excessive renewals.

## Network Challenge Blockages
**Symptoms**: Order stays in `pending` state, or challenge verification fails.
**Cause**: If `challenge.bypass = false`, the server must reach the internal client over HTTP (port 80) or DNS to verify domain ownership. Firewalls might be blocking this internal callback.
**Fix**: Ensure the host running `acme-proxy` has egress network access to reach the internal servers requesting certificates. 

## EAB Registration Fails
**Symptoms**: Client receives an error stating `External Account Binding is required`.
**Cause**: The client is connecting to a profile that requires EAB, but did not provide the `kid` and `hmac` credentials.
**Fix**: Create EAB credentials using the `acme-proxy eab create` CLI command and configure the client to use them.

## Order Finalization Fails (413 Payload Too Large)
**Symptoms**: Finalizing the order returns a 413 error.
**Cause**: The encoded Certificate Signing Request (CSR) exceeds the `server.max_body_bytes` limit (default 128 KiB).
**Fix**: Ensure your client is not generating excessively large CSRs or increase the limit in your configuration.

## Order Finalization Fails (`badCSR`: identifier mismatch)
**Symptoms**: Finalizing the order returns `400 badCSR` complaining about the requested identifiers.
**Cause**: The DNS Subject Alternative Names in your CSR are not *exactly* the set of names the order authorized. The comparison is set equality, so an extra name fails just as an omitted one does.
**Fix**: Configure your ACME client to put every ordered domain — and nothing else — into the CSR's SANs.

## Order Finalization Fails (`badCSR`: common name)
**Symptoms**: `400 badCSR`, "CSR common name is a domain the order does not cover".
**Cause**: The CSR's Subject Common Name looks like a DNS name that the order does not authorize. `acme-proxy` does **not** ignore the CN: a domain-shaped CN must be covered by the order, precisely so a name cannot be smuggled past the identifier filters by moving it out of the SANs.
**Fix**: Either add that name to the order, or drop the CN. A CN that is not domain-shaped — a human label like `rcgen self signed cert` — is tolerated and ignored. Note that the `local_ca` signer empties the subject entirely on the issued certificate, so a CN is never carried through to the leaf.

## Order Finalization Fails (`badCSR`: non-DNS SAN)
**Symptoms**: `400 badCSR` from the `local_ca` signer for a CSR containing an IP, email or URI SAN.
**Cause**: `local_ca` accepts DNS SANs only, and rejects anything else outright rather than stripping it.
**Fix**: Remove the non-DNS SANs from the CSR.

## Connection Refused or 503 Service Unavailable
**Symptoms**: High-throughput ACME clients receive HTTP 503 errors during bursts.
**Cause**: The server's load shedder activated because the number of concurrent in-flight requests exceeded `server.max_concurrent_requests`.
**Fix**: Increase `max_concurrent_requests` and `admission_wait_ms`, or configure your client to retry with exponential backoff.
