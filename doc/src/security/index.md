# Security Model

`acme-proxy` is a certificate authority, or the thing standing in front of one.
Anything that can make it sign gets a certificate your infrastructure will
trust. This page states the trust boundaries and what each secret protects, and
links to the page that owns each detail.

It is a map, not a manual. Every claim here is explained in full somewhere else;
if you need to act rather than orient, go to
[the hardening checklist](hardening.md).

## What has to be true for a certificate to be issued

Four gates stand between a packet arriving and a certificate coming back. They
are independent, and **each covers something the others do not**.

| Gate | Answers | Default | Owned by |
| --- | --- | --- | --- |
| Connection filters | May this address talk to this endpoint at all? | off (`filter.rules = []`) | [Filters](../filters/index.md) |
| EAB | Is this client allowed to register an account here? | off | [EAB](../features/eab.md) |
| Challenge validation | Does the client actually control the name? | **on** | [Challenge Validation](../challenges/index.md) |
| Identifier filters | Is this client allowed *these particular names*? | off | [Filters](../filters/index.md) |

Two of the four are off by default, which makes the third load-bearing:

> With `challenge.bypass = true` and an empty `filter.rules`, every client
> that can reach the socket can obtain a certificate for every name it asks for.
> That combination is why validation is on by default.

The identifier gate runs **twice** — at `newOrder` and again at `finalize`
against the names actually in the CSR. That is not belt-and-braces: without the
second run, a name could be smuggled past the policy by keeping it out of the
order and putting it in the CSR. See
[Filters](../filters/index.md#the-two-hooks).

## What each secret protects

| Secret | Compromise gets an attacker | Stored |
| --- | --- | --- |
| The CA private key (`signer.local_ca.key_path`) | The ability to mint any certificate your fleet trusts, silently, for as long as the CA is trusted. There is no audit row for a signature made outside this server. | On disk at `0600`, created with `create_new` rather than chmod'ed after the fact. Can live in a [PKCS#11 token](../signers/local_ca_hsm.md) instead. |
| An EAB HMAC secret | The ability to register accounts at that profile, subject to every other gate. Revocable without a restart. | Retrievable bytes — HMAC verification needs the same secret back each time. See [Database Schema](../dev/database.md#secrets-are-stored-three-different-ways-on-purpose). |
| The upstream ACME account key (`signer.relay.account_key_path`) | Control of *your* account at the upstream CA, including revoking what it issued. | On disk at `0600`, beside a `.kid` sidecar naming the account. |
| An RFC 2136 TSIG key | The ability to write records in the zone it is scoped to. This is the credential the relay exists to **not** distribute. | Configuration, or `ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__TSIG_KEY_SECRET`. |
| A web admin password | Nothing on its own once a second factor is enrolled. Otherwise: an operator session. | One-way KDF, unreadable. |
| A web admin session cookie | An operator session until it expires — but **not** the ability to change the second factor, which takes the password again. | Only `hex(SHA-256(token))` is stored. |
| A NetBox API token | Read access to your IPAM. | Configuration; belongs in the environment variable. |

The CA key is the one whose loss is not recoverable by rotation: every
certificate it signed stays trusted until the CA itself is distrusted
everywhere. That is the argument for [hardware-backed
keys](../signers/local_ca_hsm.md), and for keeping an offline root and giving
`acme-proxy` only an intermediate — see
[Local CA](../signers/local_ca.md#multi-tier-pki-using-an-intermediate-ca).

## Two listeners, two exposure surfaces

The ACME listener and the [web admin](../operations/webadmin.md) listener are
separate sockets with separate TLS configuration, separate authentication and
separate defaults. They are not two paths on one server, and they should not sit
on one interface.

- The ACME listener answers unauthenticated clients by design. It carries the
  filter chain, the admission limiter and the nonce middleware.
- The admin listener is off by default, binds `127.0.0.1` by default, and
  carries **no filter chain and no admission control** — its availability
  concern is credential brute force, which the login limiter handles. Access
  control is the bind address, TLS, and the session.

Startup **refuses** a non-loopback `admin.bind_address` while
`admin.tls.enabled` is false. The session cookie is always `Secure`, which
browsers silently decline over plain HTTP off `localhost`; the symptom would be
"login succeeds, then immediately logs out" with nothing in any log.

See
[Deployment](../getting_started/deployment.md#exposing-the-web-admin-or-rather-not)
for where each socket belongs relative to a firewall.

## Trusting a forwarded address

Every IP-based decision — filters, the login limiter, what lands in the audit
trail — rests on which address the server believes the client has.

Behind a reverse proxy that address arrives in a header, and a header is written
by whoever is talking to you. `filter.trusted_proxies` is the allowlist of hops
whose forwarded-for header is believed; with it empty, the peer address is used
and the header is ignored. Setting the header name without setting
`trusted_proxies` does not make the header trusted.

The admin listener does **no** forwarded-header handling at all, deliberately:
trusting one without an allowlist would let any caller choose its own
rate-limiter key.

See [Allowed IP](../filters/allowed_ip.md#client-ip-resolution--proxies).

## The audit trail is the record, and it is not a control

Every issuance and every refusal is written to `audit_log` with the actor, the
address, that address's reverse name, the identifiers, the User-Agent and the
request id. Nothing in the server ever compares a live request against any of it
— address pinning breaks CGNAT and mobile clients, and that is a deliberate
non-feature.

Two properties make it evidence rather than logging:

- **It survives deletion of its subject.** `audit_log` has no foreign keys, so
  deleting an account or an order does not take its history with it. See
  [Database Schema](../dev/database.md#the-audit-trail-has-no-foreign-keys-deliberately).
- **Nothing in the web admin can erase it.** The panel's audit surface is
  read-only; pruning is `audit cleanup` on the host, or the
  `audit.retention_days` sweep. A stolen session that could erase the trail
  would make the trail prove nothing.

See [Audit Trail](../operations/audit.md).

## Where this server can be made to talk to something else

Three subsystems make outbound connections on behalf of a client's request,
which makes each one a request-forgery surface worth knowing about:

- **`http-01` validation follows redirects**, because RFC 8555 requires it.
  Boulder's mitigation — blocking RFC 1918 targets — does not apply here, since
  serving private networks is the entire point. What contains it instead: only
  `http`/`https`, only the two configured ports, at most `max_redirects` hops, a
  shared timeout, an off switch, and **the fetched body is never echoed into the
  client-visible error**. See
  [HTTP-01](../challenges/http_01.md#redirects-are-an-ssrf-surface).
- **The `custom` hooks** (signer, filter, notify) execute an operator-supplied
  script with request-derived data in its environment and on stdin. They run
  with `env_clear()`, a minimal `PATH`, a timeout and `kill_on_drop` — but the
  script is yours, and quoting its inputs is your job.
- **The relay backend** talks to an upstream ACME server and, with `dns01`,
  writes DNS records. Unlike `http-01` validation, it **validates** the
  upstream's TLS certificate against `webpki-roots`: there, the certificate is
  the only thing identifying the CA being handed your CSRs.

## What is out of scope

- **Availability of the ACME listener** beyond the admission limiter. There is
  no per-account quota and no rate limiting by identifier.
- **Confidentiality of issued certificates.** They are public objects; the audit
  trail records who received one.
- **CAA.** This server performs no CAA lookup — see
  [Protocol Support](../features/index.md#not-implemented).
- **Protecting the database file from a local root.** The SQLite file holds EAB
  secrets and TOTP secrets in a form the server can read back, which means so
  can anyone who can read the file. File modes are the boundary.
