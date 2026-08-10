# HTTP-01

The default challenge type. The client serves a token at a well-known path over
plain HTTP, and `acme-proxy` fetches it.

> **Not to be confused with the `http01` upstream strategy.** This page is about
> `acme-proxy` *validating* its own clients. The [ACME Proxy
> signer](../signers/acme_proxy.md#http01) has a `challenge_strategy = "http01"`
> that runs the same challenge type in the opposite direction — `acme-proxy`
> *serving* the file, to prove itself to an upstream CA. The two share the
> well-known path and nothing else, and are configured independently.

## How it works

1. The client is given a random `token` on the challenge object.
2. It computes the **key authorization**: `token + "." + base64url(SHA256(JWK
   thumbprint of its account key))`.
3. It serves that string at
   `http://<identifier>/.well-known/acme-challenge/<token>`.
4. It triggers the challenge with `POST /chall/{id}`.
5. `acme-proxy` resolves the identifier, fetches the URL, trims whitespace from
   the body, and compares it to the key authorization it computed independently.

The body is compared to the key authorization **verbatim** — unlike `dns-01`,
which compares a SHA-256 digest of it. Serving the digest here is a common
mistake when hand-rolling a responder.

Every ACME client implements a responder for this type, usually via a
`--standalone` mode or a webroot.

## Limitations

- **No wildcards.** `*.example.com` cannot be proven this way; use
  [`dns-01`](dns_01.md).
- **The name must resolve, and be reachable.** `acme-proxy` connects *to the
  client*, using `dns.resolver` to find it. A host behind a firewall that blocks
  inbound port 80 from the proxy cannot be validated.

## Configuration

```toml
[challenge]
enabled = ["http-01"]

[challenge.http_01]
port = 80
https_port = 443
follow_redirects = true
max_redirects = 5
max_response_bytes = 4096
```

### Reference

**`port`** (`Integer`) — *Default: `80` | Env: `ACME_PROXY_CHALLENGE__HTTP_01__PORT`*

Port the challenge is fetched from. RFC 8555 fixes this at 80 for the public
Internet; it is configurable here because internal deployments frequently cannot
bind low ports.

**`https_port`** (`Integer`) — *Default: `443` | Env: `ACME_PROXY_CHALLENGE__HTTP_01__HTTPS_PORT`*

Port used when a redirect sends the fetch to `https`.

**`follow_redirects`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_CHALLENGE__HTTP_01__FOLLOW_REDIRECTS`*

Follow 3xx responses. Required by the specification, and commonly needed in
practice — many hosts redirect all HTTP to HTTPS.

**`max_redirects`** (`Integer`) — *Default: `5` | Env: `ACME_PROXY_CHALLENGE__HTTP_01__MAX_REDIRECTS`*

Hop limit before the validation fails.

**`max_response_bytes`** (`Integer`) — *Default: `4096` | Env: `ACME_PROXY_CHALLENGE__HTTP_01__MAX_RESPONSE_BYTES`*

Cap on how much of the response body is read. A key authorization is under 100
bytes; this exists so a client cannot make the server read an unbounded stream.

The TLS certificate presented after a redirect to HTTPS is **not** validated
(RFC 8555 §8.3) — at validation time the client by definition does not yet have
a trusted certificate for the name.

## Redirects are an SSRF surface

Following redirects means a client can steer the server's fetch at an address of
its choosing. Boulder's usual mitigation — refusing to connect to RFC 1918 space
— cannot apply here, because serving private networks is the entire point of
this server.

What contains it instead:

- Only `http` and `https` schemes are followed.
- Only the two configured ports (`port` and `https_port`) are connected to.
- At most `max_redirects` hops.
- The shared `challenge.timeout_ms` bounds the whole attempt, redirects
  included.
- `follow_redirects = false` turns the surface off entirely.
- **The fetched body is never echoed back to the client.** The error a client
  sees reports only the body's *length* on a mismatch; a truncated preview is
  written to the log at `debug` level. This is what stops the challenge from
  becoming a general-purpose read primitive against your internal network.

If your threat model does not tolerate this, disable redirects, or use
[`dns-01`](dns_01.md), which makes no outbound connection to the client at all.

## Troubleshooting

Look for these events in the log:

| Event | Meaning |
| --- | --- |
| `challenge_http_01_loaded` | The fetch succeeded; a body was read. |
| `challenge_http_01_matched` | The body matched. Validation passed. |
| `challenge_http_01_mismatch` | The responder answered with the wrong content. Check that it is serving the key authorization, not just the token, and not the digest. |
| `challenge_http_01_redirect` | A redirect was followed; the target is logged. |
| `challenge_validation_failed` | The attempt failed. The detail says whether it was a connection error, a timeout, or a mismatch. |

A connection failure usually means one of: the name does not resolve through
`dns.resolver`; nothing is listening on `port`; or a firewall blocks the proxy's
egress to the client.
