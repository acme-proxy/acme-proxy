# Web Admin

A browser- and script-facing management interface for the server: the accounts
it has registered, the orders it has issued, the EAB credentials it honours,
and the nonce table.

It is a **second listener, on its own socket**, serving no ACME — and it is
**off by default**. A certificate authority should not grow a management
surface because somebody upgraded it.

It has two faces over the same operations: **HTML pages at `/ui`** for a
browser, and a **JSON API at `/api`** for a script. Neither is built on the
other; both are thin layers over the same `src/admin/` operations the
[CLI](cli.md) calls.

```toml
[admin]
enabled = true
```

> There is no sign-up page and never will be. The first operator is created
> from a shell on the host — see [Users & Sessions](webadmin_users.md).

## Why a second listener

The ACME listener is public, unauthenticated, and frequently internet-facing.
Everything about its defaults follows from that: admission control that sheds
load, a filter chain, a small body limit.

The admin listener has the opposite shape. It defaults to loopback, requires a
session on every route but sign-in, and deliberately carries **no admission
control** (the availability concern here is credential brute force, which the
login rate limiter handles and admission control would not touch) and **no
filter chain** (filters are a per-profile ACME concern; `filter.exempt_paths`
matches profile-stripped paths, so wiring them here would be a category error).

Access control on this listener is the bind address, TLS, and the session.

Putting both on one socket would have meant one set of defaults for two very
different threat models.

## Exposing it

The default binds loopback only:

```toml
[admin]
bind_address = "127.0.0.1:3001"
base_url     = "http://localhost:3001"
```

**The recommended way to reach it from elsewhere is an SSH tunnel**, which
needs no configuration change at all:

```console
$ ssh -N -L 3001:127.0.0.1:3001 ca.example.com
```

Then open `http://localhost:3001` locally. `admin.base_url` stays as it is,
because from the browser's point of view the panel really is on localhost.

### Binding to a real interface

Startup **refuses** a non-loopback `bind_address` while `admin.tls.enabled` is
`false`:

```
admin.bind_address `0.0.0.0:3001` is not loopback while admin.tls.enabled is
false: the session cookie is sent `Secure`, which a browser will not store over
plain HTTP on anything but localhost, so signing in would appear to succeed and
then fail silently. Set admin.tls.enabled = true, or bind 127.0.0.1 and reach
it through an SSH tunnel
```

This is an error rather than a warning on purpose. The session cookie is always
sent `Secure` — making that conditional is how a session cookie leaks — and
browsers accept a `Secure` cookie on `http://localhost` but silently refuse it
on `http://192.0.2.10:3001`. The operator would see "sign-in works, then I am
immediately signed out" with nothing in any log to explain it.

So a public bind means TLS:

```toml
[admin]
enabled      = true
bind_address = "0.0.0.0:3001"
base_url     = "https://admin.example.com:3001"

[admin.tls]
enabled = true
```

As with `[server.tls]`, a self-signed certificate for the host of
`admin.base_url` is generated on first start when the files are missing, and
the key is created `0600`. The paths default to `admin.pem`/`admin.key`,
separate from the ACME listener's — the two answer to different names and
should not share a certificate by accident.

## Authentication

Sign-in exchanges a username and password for an opaque session token:

- The token is 256 random bits, and only its **SHA-256** is stored. A database
  read — a backup, a `.dump`, an injection — yields nothing replayable.
- It travels in a `__Host-acme_admin_session` cookie, `HttpOnly; Secure;
  SameSite=Strict; Path=/`. The `__Host-` prefix is browser-enforced: it
  *requires* those attributes, so an edit that drops one breaks visibly.
- Sessions have both an absolute lifetime (`session_ttl_seconds`, never
  extended by activity) and an idle timeout
  (`session_idle_timeout_seconds`).
- Passwords are hashed with PBKDF2-HMAC-SHA256 at 600 000 iterations. A failed
  sign-in costs the same whether the username exists or not, so the endpoint
  cannot be used to enumerate operators — and every failure returns the same
  `invalid_credentials`, whatever the real cause. The *log* says which.

### CSRF

Every request with an unsafe method must carry an `X-CSRF-Token` header
matching the session's `csrfToken`, which sign-in and `GET /api/session` both
return.

`SameSite=Strict` is set as well, but it is **not sufficient on its own here**,
and the reason is specific: SameSite is scoped to the registrable domain, not
the origin — *different ports of the same host are same-site*. A panel on
`:3001` beside anything else on `:8080` of the same box is exactly what it does
not cover.

There is also an origin gate: a request whose `Origin` does not match
`admin.base_url`, or whose `Sec-Fetch-Site` says `cross-site`, is refused. That
is what covers sign-in itself, which by definition carries no session token
yet. Both headers are checked only when present, so a script or `curl` is
unaffected.

> `SameSite=Strict` also means clicking a link *into* the panel from another
> site will not carry your session. For an admin panel that is a feature, but
> it surprises people.

## The panel

Open `admin.base_url` in a browser: `/` redirects to `/ui/`, and anything under
it that needs a session bounces to `/ui/login`.

| Page | What is on it |
|---|---|
| `/ui/` | Counts for accounts, orders, EAB credentials and nonces, plus the mounted endpoints |
| `/ui/accounts` | Every account, filterable by profile, listed with the address its key was last seen from; a detail page carries both recorded addresses, the contact editor, deactivate and delete |
| `/ui/orders` | Every order, filterable by profile, status and account; a detail page shows the authorizations and challenges, and revokes or deletes |
| `/ui/eab` | Credentials, minting (the secret is shown **once**) and revocation |
| `/ui/audit` | The CA's audit trail — every issuance and every refusal, filterable, with a detail page per row. **Read-only**: there is no route here that prunes it |
| `/ui/nonces` | The table size, and a manual sweep |
| `/ui/profiles` | The endpoints this process serves, and a warning for any that bypass validation |

The account pages surface the CA's account-side traceability columns:
where `newAccount` was called from and the reverse name that address had at the
time (**Created from**), and when and where the key last authenticated a request
(**Last seen**, **Last seen from**). Each is shown only when it was recorded — a
reverse lookup that found nothing leaves the address alone, and an estate where
it can never succeed leaves both names blank rather than every row saying
"unknown". Nothing in the server ever *compares* against them; they answer "who
asked for this certificate, and from where", not "may this request proceed".

### How it is built

[htmx], vendored into the binary — no npm, no build step, no CDN. The
templates are [minijinja] and can be
[overridden on disk](webadmin_templates.md) without rebuilding.

Each list and detail route serves **two representations of one URL**: a whole
document for a normal navigation, and the bare fragment htmx is going to swap
when the request carries `HX-Request`. So `/ui/orders?status=valid` is a real,
bookmarkable URL whether you got there by clicking a filter or by typing it.

The CSRF token reaches the browser as an `hx-headers` attribute on `<body>` and
comes back as the same `X-CSRF-Token` header the API uses — the pages needed no
second CSRF mechanism, which is the main reason htmx was chosen over plain
forms.

Sign-in is the exception: a plain HTML form, no JavaScript, protected by the
origin gate rather than a token (there is no session to have one yet). It works
with scripting disabled.

## The API

Mounted at `/api`, unversioned. Every response is `application/json` with
`Cache-Control: no-store`.

| Method | Path | |
|---|---|---|
| `POST` | `/api/session` | sign in — `{username, password}` |
| `GET` | `/api/session` | who am I, and my `csrfToken` |
| `DELETE` | `/api/session[?all=true]` | sign out (of this browser, or all) |
| `GET` | `/api/session/mfa` | what a half-authenticated cookie still owes — `{step}` |
| `POST` | `/api/session/mfa` | finish the sign-in — `{code}`, a TOTP or a recovery code |
| `GET` | `/api/mfa` | `{totpEnabled, enrolmentPending, recoveryCodesRemaining}` |
| `POST` | `/api/mfa/totp` | begin an enrolment — **returns the secret, once** |
| `POST` | `/api/mfa/totp/confirm` | `{code}` — **returns the recovery codes, once** |
| `DELETE` | `/api/mfa/totp` | turn it off; `409` while `admin.require_mfa` is on |
| `POST` | `/api/mfa/recovery-codes` | reissue — **returns them once** |
| `GET` | `/api/accounts?profile=&limit=&offset=` | |
| `GET` | `/api/accounts/{id}` | |
| `GET` | `/api/accounts/{id}/orders?limit=&offset=` | |
| `PATCH` | `/api/accounts/{id}` | `{contact: [...]}` |
| `POST` | `/api/accounts/{id}/deactivate` | |
| `DELETE` | `/api/accounts/{id}` | cascades to the account's orders |
| `GET` | `/api/orders?profile=&accountId=&status=&limit=&offset=` | |
| `GET` | `/api/orders/{id}` | order + authorizations + challenges |
| `POST` | `/api/orders/{id}/revoke` | `{reason}` optional |
| `DELETE` | `/api/orders/{id}` | |
| `GET` | `/api/eab` | never shows a secret |
| `POST` | `/api/eab` | `{label, profile}` — **returns the secret, once** |
| `GET` | `/api/eab/{kid}` | |
| `POST` | `/api/eab/{kid}/revoke` | the row survives, moved to `revoked` |
| `GET` | `/api/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=` | read-only |
| `GET` | `/api/audit/{id}` | one row |
| `GET` | `/api/nonces` | `{count, ttlSeconds}` |
| `POST` | `/api/nonces/cleanup` | `{ttlSeconds}` optional |
| `GET` | `/api/profiles` | the endpoints actually mounted |
| `GET` | `/health` | unauthenticated, no database access |

Lists return an envelope, not a bare array — `total` is what the same filters
match *unpaged*, which is what a page control needs:

```json
{ "items": [ … ], "total": 137, "limit": 50, "offset": 0 }
```

`limit` defaults to 50 and is clamped to `admin.page_size_max` rather than
refused.

`POST /api/session` for an operator with a second factor answers `200` with
`{"mfaRequired": true, "step": "verify"}` and **no `user` member** — a
half-authenticated session must not read operator metadata. It is not a `401`:
the password *was* right, and a script has to be able to tell those apart. Send
the code to `POST /api/session/mfa`, which answers the ordinary session body and
a **new** cookie; the pending one is dead by then.

The two `…/session/mfa` routes are the only mutating endpoints that do not take
`X-CSRF-Token`. The sign-in page they serve is a plain form with no token to
send, exactly as `POST /api/session` has none, and the origin check covers both.

### Revocation

`POST /api/orders/{id}/revoke` resolves the signer from **the order's own
profile**. Two profiles can hold two different CAs, and revoking against the
wrong one would record nothing useful and leave the real CRL untouched. An
order belonging to a profile this process no longer mounts answers `409
profile_not_mounted` rather than guessing.

This is strictly better than the CLI's equivalent, which has to rebuild a
backend from configuration: the server already holds the live, deduplicated
instance, so a local CA's CRL is regenerated by the very object that serves
`GET /crl`.

### The audit trail is read-only here

`/api/audit` and `/ui/audit` list, filter, page and resolve a row by id, and
that is all they do. There is no route on this listener that deletes audit
history, and that is a deliberate limit rather than a missing feature: the first
thing a stolen session would do is erase what it had just done, and a trail the
watched thing can erase proves nothing. Pruning happens on the host with
`acme-proxy audit cleanup`, or on a schedule via `audit.retention_days`.

This is also why `/api/audit` contributes no entry to the CSRF test table — with
no mutating verb, there is nothing to protect. Every other verb on those paths is
unroutable. See [Audit Trail](audit.md).

### Errors

Not ACME problem documents. Every `Problem` type in this server is a hardcoded
`urn:ietf:params:acme:error:*` URN, and nothing on this listener is an ACME
error:

```json
{ "error": "not_found", "message": "no such account: acct-1" }
```

`error` is a stable snake_case code you may branch on; `message` is for a human
and may change. The codes: `bad_request`, `session_invalid`, `session_expired`,
`session_idle`, `invalid_credentials`, `csrf_failed`, `not_found`,
`method_not_allowed`, `order_not_issued`, `already_revoked`,
`profile_not_mounted`, `rate_limited`, `signer_failed`, `internal`.

The pages answer the same failures as HTML carrying the same code, with one
deliberate split: a refusal that is about **the row's state** — `409
already_revoked`, `order_not_issued` — comes back as a banner beside the button
you pressed, with the record still on screen, while a **server** problem
replaces the page. A missing session is neither: a browser gets `303` to
`/ui/login`, and an htmx request gets the `HX-Redirect` header, because a `303`
is followed by `fetch` before htmx ever sees it and the sign-in page would be
swapped into whatever you clicked.

## Driving it with curl

```console
$ curl -sc jar -X POST http://127.0.0.1:3001/api/session \
       -H 'content-type: application/json' \
       -d '{"username":"alice","password":"…"}'
{"csrfToken":"…","expiresAt":"…","user":{…}}

$ curl -sb jar 'http://127.0.0.1:3001/api/orders?limit=5'

$ curl -sb jar -X POST http://127.0.0.1:3001/api/eab \
       -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
       -d '{"label":"team-a"}'
```

## Security notes

- This is a second attack surface on a certificate authority. It is off by
  default, binds loopback, and needs a session — but everything the ACME side
  hardened (admission control, filters) is absent here by design, and that is
  worth knowing rather than discovering.
- Sign-in is protected by a fixed-window rate limiter
  (`admin.login_max_attempts` per `admin.login_window_seconds`, keyed on the
  client address). Over the limit, the password hash is not computed at all —
  600 000 iterations is a denial-of-service lever otherwise.
- **There is no forwarded-header handling on this listener.**
  `filter.trusted_proxies` governs the ACME listener only; honouring
  `X-Forwarded-For` here without an equivalent allowlist would let any caller
  spoof the key the rate limiter counts on. Behind a reverse proxy the limiter
  therefore counts the proxy, which is another reason to prefer an SSH tunnel.
- Every response carries `Content-Security-Policy: default-src 'none';
  script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src
  'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. No
  `unsafe-inline`, no `unsafe-eval` — affordable because htmx is served from
  this origin and drives everything through `hx-*` attributes rather than
  inline handlers. Alongside it: `no-store`, `nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: same-origin` and HSTS.
- `htmx.min.js` is a **vendored third-party file**, and `cargo deny` audits the
  crate graph and cannot see it. Its version, source URL, SHA-256 and licence
  are recorded in `src/webadmin/static/README.md`, which is the only provenance
  record there is — check it when you update.
- A **second factor (TOTP)** is available per operator, and
  `admin.require_mfa` makes it compulsory — see
  [Operators and sessions](webadmin_users.md#second-factor-totp). It is off by
  default, so the loopback bind plus an SSH tunnel remains the baseline posture
  and not a substitute for one.
- WebAuthn is **not** implemented. `webauthn-rs` 0.5 hard-depends on
  `openssl`/`openssl-sys` and is MPL-2.0, neither of which this tree carries;
  the design does not preclude it later (another factor is another branch in the
  same state machine, not a change to it).

## Configuration

See the [Configuration Reference](../configuration/reference.md) for every
`[admin]` and `[admin.tls]` key, and
[Customizing the Panel](webadmin_templates.md) for `admin.template_dir`.

[htmx]: https://htmx.org
[minijinja]: https://docs.rs/minijinja
