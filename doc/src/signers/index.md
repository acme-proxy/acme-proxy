# Signers

The signer is what actually produces a certificate, once the client has proved
control of its names and the filters have allowed the request. Everything before
this point is the same whichever backend you choose; everything after it is the
backend's business.

There are three, and they answer three different questions.

| Backend | Use it when | The certificate is signed by |
| --- | --- | --- |
| **[Local CA](local_ca.md)** | The certificates only need to be trusted by machines you control. | This server, from a CA key on disk or in a [PKCS#11 token](local_ca_hsm.md). |
| **[Relay](relay.md)** | You need publicly trusted certificates, but your clients cannot reach a public CA — or you have one scarce upstream credential to share. | A real upstream ACME CA, which this server becomes a client of. |
| **[Custom Script](custom.md)** | The authority already exists and does not speak ACME. | Whatever your script talks to: a legacy PKI, an internal API, an offline process. |

## Choosing one

Start from what has to trust the certificate:

- **Only your own machines?** `local_ca`. You distribute the CA certificate once
  (see [Trusting the CA](../getting_started/trusting_the_ca.md)) and the whole
  thing works offline, including revocation via
  [the CRL](../operations/revocation.md).
- **Browsers, partners, anything you do not control?** You need a public CA, so
  `relay`. Your internal clients keep proving control to *this* server —
  over HTTP, DNS or TLS, whichever suits them — while the upstream challenge is
  solved once, centrally, with a credential no client ever holds.
- **An existing corporate PKI that issues by ticket, script or API?** `custom`.
  It is the escape hatch, and it is deliberately a shell contract rather than a
  plugin API, so anything that can be scripted can be a signer.

Nothing stops you from running more than one. `[signer]` is a per-profile
section, so a `local_ca` at `/profile/dev` can sit beside a relay at
`/profile/prod` in the same process.

## What every backend has to provide

All three implement the same trait, and the shape of it is worth knowing because
it is what the rest of the server can rely on. It comes in two halves, split by
who holds the key: the **backend** — `issue`, `revoke` — is built only by the
process running the `worker` role, and the **read side** — the CRL, the trust
anchor, renewal information — is built by every process from public material,
so the one parsing client requests never holds signing material:

- **`issue`** — the only required capability. It receives the order's
  identifiers and the client's CSR and returns a chain, or refuses with
  `badCSR`.
- **`revoke`** — must be **idempotent**. Revoking twice is not an error, because
  the server cannot always know whether a previous attempt reached the
  authority.
- **`crl_der`** and **`renewal_info`** — optional, and default to "nothing to
  say here". `local_ca` publishes a CRL; the relay passes the upstream's renewal
  window through, [`explanationURL`](../features/renewal_info.md) and all.

`issue` never runs inside a client's request: `finalize` queues it, answers the
order `processing`, and the worker calls the backend. A backend may itself
answer **`processing`** rather than a certificate, meaning "this finishes
later". Only the relay does — signing upstream takes as long as the upstream
takes — and the order simply stays `processing` until it has.

## Configuration

```toml
[signer]
backend = "local_ca"   # or "relay", or "custom"
```

Each backend then reads its own table — `[signer.local_ca]`,
`[signer.relay]`, `[signer.custom]` — documented on its own page.

### Reference

**`backend`** (`String`) — *Default: `"local_ca"` | Env: `ACME_PROXY_SIGNER__BACKEND`*

Which backend issues certificates: `local_ca`, `relay` or `custom`. Any
other value is a startup error.

## Backends are shared by configuration, not per profile

Two profiles whose `[signer]` sections are **identical** share one backend
instance rather than constructing two. Revocations and the CRL live in the
database, keyed by the CA's key, so two instances over one CA would still agree
on what is revoked; what they could not agree on is everything else in the
section.

Two profiles sharing `ca.key` while differing anywhere else in `[signer]` is
therefore a **startup error**, not a race to discover later. See
[Profiles & Routing](../core/profiles.md).
