# DNS-01

The client publishes a TXT record proving control of the domain. This is the only
challenge type that can authorize a **wildcard**, and the only one that requires
no inbound connectivity to the client at all.

## How it works

1. The client is given a random `token`.
2. It computes the key authorization: `token + "." + base64url(SHA256(JWK
   thumbprint))`.
3. It publishes a TXT record at `_acme-challenge.<identifier>` whose value is
   **`base64url(SHA256(keyAuthorization))`**.
4. It triggers the challenge, and `acme-proxy` queries that name through
   `dns.resolver`.

> **The value is the digest, not the key authorization.** This is the single most
> common mistake when writing a DNS responder by hand: `http-01` serves the key
> authorization verbatim, `dns-01` serves the base64url-encoded SHA-256 **of** it.
> The two are not interchangeable.

`acme-proxy` matches **any** TXT record present at the name. That is required
rather than lenient: an order covering both `example.com` and `*.example.com`
produces two authorizations that publish two different values to the same
`_acme-challenge.example.com`, and both must be able to validate.

## Configuration

`dns-01` has no configuration table of its own. Enable it, and point
`dns.resolver` wherever your authoritative data lives:

```toml
[challenge]
enabled = ["dns-01"]

[dns]
# host:port of the nameserver every lookup goes through.
resolver = "10.0.0.53:53"
```

Leaving `dns.resolver` unset uses the system configuration
(`/etc/resolv.conf`).

## The resolver is deliberately uncached

The shared resolver performs no caching. This matters here more than anywhere
else: a client typically publishes its TXT record and triggers the challenge
seconds later, and a cached negative answer — an NXDOMAIN or empty NOERROR from
the moment before publication — would defeat validation for the whole negative-TTL
window.

(The one component that *does* cache is `filter.reverse_dns`, which builds its own
resolver. PTR lookups for an address that keeps connecting are exactly what a
cache is for.)

What this does not remove is propagation delay in your own DNS infrastructure. If
`dns.resolver` points at a recursive resolver rather than the authoritative
server, the record still has to reach it. Pointing straight at the authoritative
nameserver is the reliable choice for an internal deployment.

## Wildcards

```toml
[challenge]
enabled = ["dns-01"]     # required for *.example.com to be accepted at all
```

Without `dns-01` enabled, `newOrder` refuses a wildcard identifier with
`rejectedIdentifier`. With it enabled:

- the authorization is created on the base name, flagged `"wildcard": true`;
- it offers `dns-01` and nothing else, regardless of what else is enabled;
- the TXT record still goes to `_acme-challenge.example.com` — there is no
  `_acme-challenge.*.example.com`.

## Client support

Every major client implements `dns-01`, but each needs a provider plugin or hook
script to write the record: certbot's `--manual` with an auth hook or a DNS
plugin, `acme.sh --dns dns_<provider>`, lego's `--dns <provider>`.

If you would rather your clients did *not* hold DNS credentials, that is exactly
what the [`acme_proxy` signer backend](../signers/acme_proxy.md) exists for: your
clients prove control to `acme-proxy` however you like, and `acme-proxy` holds the
single RFC 2136 TSIG key that answers the upstream CA.

## Troubleshooting

| Event | Meaning |
| --- | --- |
| `challenge_dns_01_loaded` | TXT records were retrieved for the name. |
| `challenge_dns_01_matched` | One of them matched. Validation passed. |
| `challenge_validation_failed` | No record matched, or the lookup failed. |

If the lookup returns nothing, check in this order: the record exists at
`_acme-challenge.<name>` (not at the name itself); its value is the **digest**;
`dns.resolver` can actually see the zone; and the record has finished propagating
to whatever `dns.resolver` points at.

A TXT record split into multiple character-strings is reassembled by
concatenation before comparison, so a long value chunked by your DNS server is
handled correctly.
