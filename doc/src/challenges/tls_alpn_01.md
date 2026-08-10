# TLS-ALPN-01

Defined by **RFC 8737**. The client proves control by answering a TLS handshake
on port 443 with a special self-signed certificate, rather than by serving
anything over HTTP.

Its appeal is operational: validation happens entirely within the TLS layer, so
a host that terminates TLS but serves no plain HTTP at all can still be
validated, and nothing needs to be routed on port 80.

## How it works

1. The client is given a random `token` and computes the key authorization as
   usual.
2. It generates a **self-signed** certificate that contains:
   - a single `dNSName` SAN equal to the identifier being validated, and
   - a **critical** `id-pe-acmeIdentifier` extension (OID
     `1.3.6.1.5.5.7.1.31`) whose value is `SHA256(keyAuthorization)`.
3. It arranges for that certificate to be presented when a handshake arrives
   with SNI set to the identifier **and** ALPN protocol `acme-tls/1`.
4. `acme-proxy` performs that handshake and inspects the certificate it gets
   back.

The proof is verified without ever completing an application-layer exchange: the
certificate presented during the handshake *is* the answer.

## What `acme-proxy` checks

- Exactly **one** `dNSName` SAN, matching the identifier. Not "at least one".
- The `id-pe-acmeIdentifier` extension is present and marked **critical**, as
  RFC 8737 requires.
- Its value equals the expected digest, compared in **constant time**.

The presented certificate is otherwise untrusted by design — it is self-signed
and issued by the entity being challenged, so there is no chain to validate.

## Configuration

```toml
[challenge]
enabled = ["tls-alpn-01"]

[challenge.tls_alpn_01]
port = 443
```

### Reference

**`port`** (`Integer`) — *Default: `443` | Env: `ACME_PROXY_CHALLENGE__TLS_ALPN_01__PORT`*

Port the validation handshake connects to. RFC 8737 fixes this at 443 for the
public Internet; it is configurable here for internal deployments that cannot
bind it.

## Client support

Support is thinner than for the other two types:

- **lego** implements a responder (`--tls`). This is what the project's
  end-to-end suite uses.
- **certbot** and **acme.sh** do **not** implement a `tls-alpn-01` responder.
  Listing this type is harmless for them — they simply pick another enabled type
  — but it cannot be their only option.
- Servers that manage their own certificates, such as Caddy and Traefik,
  generally do support it natively.

If `tls-alpn-01` is the only entry in `challenge.enabled`, certbot and acme.sh
clients will not be able to complete an order at all.

## Limitations

- **No wildcards.** Use [`dns-01`](dns_01.md).
- Requires inbound connectivity from `acme-proxy` to the client on `port`, the
  same constraint as [`http-01`](http_01.md).
- The responder must serve the ACME certificate **only** for the `acme-tls/1`
  ALPN protocol, and its normal certificate otherwise. Serving it
  unconditionally would break ordinary traffic to that host for the duration.

## Troubleshooting

| Event | Meaning |
| --- | --- |
| `challenge_tls_alpn_01_loaded` | The handshake completed and a certificate was obtained. |
| `challenge_tls_alpn_01_matched` | The certificate carried the right digest. Validation passed. |
| `challenge_validation_failed` | Handshake failed, or the certificate did not satisfy the checks above. |

A handshake that fails outright usually means the responder did not negotiate
`acme-tls/1` — many TLS servers simply fall through to their normal certificate
when they do not recognise the ALPN protocol, and the certificate then has no
`id-pe-acmeIdentifier` extension to find.
