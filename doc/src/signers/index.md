# Signers

The signer is what actually produces a certificate, once the client has proved
control of its names and the filters have allowed the request. Everything before
this point is the same whichever backend you choose; everything after it is the
backend's business.

There are three, and they answer three different questions.

| Backend | Use it when | The certificate is signed by |
| --- | --- | --- |
| **[Local CA](local_ca.md)** | The certificates only need to be trusted by machines you control. | This server, from a CA key on disk or in a [PKCS#11 token](local_ca_hsm.md). |
| **[ACME Proxy](acme_proxy.md)** | You need publicly trusted certificates, but your clients cannot reach a public CA — or you have one scarce upstream credential to share. | A real upstream ACME CA, which this server becomes a client of. |
| **[Custom Script](custom.md)** | The authority already exists and does not speak ACME. | Whatever your script talks to: a legacy PKI, an internal API, an offline process. |

## Choosing one

Start from what has to trust the certificate:

- **Only your own machines?** `local_ca`. You distribute the CA certificate once
  (see [Trusting the CA](../getting_started/trusting_the_ca.md)) and the whole
  thing works offline, including revocation via
  [the CRL](../operations/revocation.md).
- **Browsers, partners, anything you do not control?** You need a public CA, so
  `acme_proxy`. Your internal clients keep proving control to *this* server —
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
it is what the rest of the server can rely on:

- **`issue`** — the only required capability. It receives the order's
  identifiers and the client's CSR and returns a chain, or refuses with
  `badCSR`.
- **`revoke`** — must be **idempotent**. Revoking twice is not an error, because
  the server cannot always know whether a previous attempt reached the
  authority.
- **`crl_der`** and **`renewal_info`** — optional, and default to "nothing to
  say here". `local_ca` publishes a CRL; the relay passes the upstream's renewal
  window through, [`explanationURL`](../features/renewal_info.md) and all.

A backend may also answer `issue` with **`processing`** rather than a
certificate, meaning "ask again later". Only the relay does — signing upstream
takes as long as the upstream takes. `local_ca` and `custom` answer inline, so
an order under those never passes through the `processing` state.

## Configuration

```toml
[signer]
backend = "local_ca"   # or "acme_proxy", or "custom"
```

Each backend then reads its own table — `[signer.local_ca]`,
`[signer.acme_proxy]`, `[signer.custom]` — documented on its own page.

### Reference

**`backend`** (`String`) — *Default: `"local_ca"` | Env: `ACME_PROXY_SIGNER__BACKEND`*

Which backend issues certificates: `local_ca`, `acme_proxy` or `custom`. Any
other value is a startup error.

## Backends are shared by configuration, not per profile

Two profiles whose `[signer]` sections are **identical** share one backend
instance rather than constructing two. This is a correctness rule, not an
optimisation: two `LocalCa` instances over the same files would each rewrite the
CRL from their own in-memory ledger, so the second would silently drop the
first's revocations.

Two profiles sharing `ca.key` while differing anywhere else in `[signer]` is
therefore a **startup error**, not a race to discover later. See
[Profiles & Routing](../core/profiles.md).
