# Configuration Reference

This page is the structured reference for every core configuration parameter.

For deep dives into specific subsystems (Signers, Filters, Notifications, EAB),
see their dedicated chapters — linked at the bottom, and the place where those
sections' keys are documented.

## How configuration is resolved

Sources are layered, lowest precedence first:

1. **Built-in defaults** — everything documented below has one, so an empty
   configuration is valid apart from `[profiles]`.
2. **A configuration file** — `config.toml` in the working directory, or the
   path in `ACME_PROXY_CONFIG` (the extension may be omitted, in which case the
   format is inferred). A missing file is not an error.
3. **`ACME_PROXY_*` environment variables** — `__` separates nested keys, a
   single `_` separates the prefix. `server.tls.enabled` is
   `ACME_PROXY_SERVER__TLS__ENABLED`.

`config.toml.example` in the repository is the annotated companion to this page:
it lists every key with its default and its environment variable name in
context.

> **`[profiles]` is mandatory.** Everything else can be left at its default, but
> the server serves ACME only through profiles and refuses to start without at
> least one enabled. See [`[profiles]`](#profilesname) below.

## Every section, and where it is documented

Five sections are large enough to have a chapter of their own, and their keys
are documented there rather than restated here. This page stays the complete
**map**: every table `acme-proxy` reads appears below, whether or not its text
lives here.

**Overridable** marks the sections a `[profiles.<name>]` block may override.
Everything else is process-wide — one setting for the whole server, however many
endpoints it mounts.

| Section | Controls | Overridable | Documented |
| --- | --- | --- | --- |
| `[database]` | The SQLite file | no | [below](#database) |
| `[server]` | Listen socket, public URL, admission control | no | [below](#server) |
| `[server.tls]` | HTTPS on the ACME listener | no | [below](#servertls) |
| `[admin]` | The web admin listener and its sessions | no | [below](#admin) |
| `[admin.tls]` | HTTPS on the admin listener | no | [below](#admintls) |
| `[nonce]` | Replay-nonce freshness | no | [below](#nonce) |
| `[audit]` | Reverse lookups and retention for the trail | no | [below](#audit) |
| `[dns]` | The resolver every outbound lookup uses | no | [below](#dns) |
| `[logging]` | Filter, format, target | no | [below](#logging) |
| `[order]` | The ACME order object's lifetime | **yes** | [below](#order) |
| `[meta]` | Directory `meta` members | **yes** | [below](#meta) |
| `[profiles.<name>]` | An ACME endpoint | — | [below](#profilesname) |
| `[signer]` | How a certificate is obtained | **yes** | [Signers](../signers/index.md) |
| `[filter]` | Who may ask, and for what | **yes** | [Filters](../filters/index.md) |
| `[challenge]` | How control of a name is proven | **yes** | [Challenge Validation](../challenges/index.md#reference) |
| `[notify]` | Outbound notifications | **yes** | [Notifications](../notifications/index.md) |
| `[eab]` | External Account Binding | **yes** | [EAB](../features/eab.md) |

The criterion for the last five is **having a chapter**, not being overridable —
`[order]` and `[meta]` are overridable and documented here, because neither is
large enough to be worth a page. That is the whole rule; there is nothing
subtler going on.

`config.toml.example` in the repository carries the same list as a comment
header, with every key in context.

---

## `[database]`

**`url`** (`String`) — *Default: `"sqlite://sqlite.db"` | Env: `ACME_PROXY_DATABASE__URL`*

Database connection URL. Controls the SQLite persistence layer for accounts,
orders, and certificates.

---

## `[server]`

**`bind_address`** (`String`) — *Default: `"[::]:3000"` | Env: `ACME_PROXY_SERVER__BIND_ADDRESS`*

Network address the server binds and listens to.

**`base_url`** (`String`) — *Default: `"http://localhost:3000"` | Env: `ACME_PROXY_SERVER__BASE_URL`*

Public base URL advertised in the ACME directory, with no trailing slash. It is
**never derived from the request**, and every signed request's `url` field is
checked against it (RFC 8555 §6.4) — so behind a reverse proxy, or with TLS
enabled, this must be set to the public URL or every client is rejected.

**`max_concurrent_requests`** (`Integer`) — *Default: `100` | Env: `ACME_PROXY_SERVER__MAX_CONCURRENT_REQUESTS`*

How many ACME requests may be in flight at once before the server sheds load.

**`admission_wait_ms`** (`Integer`) — *Default: `50` | Env: `ACME_PROXY_SERVER__ADMISSION_WAIT_MS`*

How long a request may wait for a slot before it is refused. Past the limit a
request waits this long and then gets `503` + `Retry-After` — it is **shed, not
queued**.

**`request_timeout_ms`** (`Integer`) — *Default: `60000` | Env: `ACME_PROXY_SERVER__REQUEST_TIMEOUT_MS`*

Whole-request deadline. It **must exceed** `challenge.timeout_ms` and, when that
backend is installed, `signer.custom.timeout_ms` — both run inline inside a
request. The server refuses to start otherwise.

**`max_body_bytes`** (`Integer`) — *Default: `131072` | Env: `ACME_PROXY_SERVER__MAX_BODY_BYTES`*

Largest request body accepted (128 KiB).

> These four keys govern the ACME routes only. `GET /health` is mounted outside
> all of them.

> `trusted_proxies` and `forwarded_header` are **not** `[server]` keys — they
> live under `[filter]`. See [Filters](../filters/index.md#reference).

### `[server.tls]`

Full treatment in [TLS Termination](../features/tls_termination.md).

**`enabled`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_SERVER__TLS__ENABLED`*

Serve HTTPS on `bind_address` **instead of** cleartext — one listener, not two.
`base_url` is *not* rewritten for you; set it to `https://…` yourself or every
signed request fails the §6.4 URL check above.

**`cert_path`** (`String`) — *Default: `"server.pem"` | Env: `ACME_PROXY_SERVER__TLS__CERT_PATH`*

PEM certificate chain, leaf first. A self-signed certificate is generated and
written when either this or `key_path` is missing.

**`key_path`** (`String`) — *Default: `"server.key"` | Env: `ACME_PROXY_SERVER__TLS__KEY_PATH`*

Path to the private key.

**`handshake_timeout_ms`** (`Integer`) — *Default: `10000` | Env: `ACME_PROXY_SERVER__TLS__HANDSHAKE_TIMEOUT_MS`*

Budget for one TLS handshake. Handshakes run concurrently, off the accept path,
so this never delays another client.

---

## `[admin]`

The web admin interface — a **second listener**, on its own socket, serving no
ACME. Process-wide, so there is no `[profiles.<name>].admin`: an operator
manages every endpoint this process serves. Full treatment in
[Web Admin](../operations/webadmin.md).

**`enabled`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__ENABLED`*

Off by default: a certificate authority should not grow a management surface
because somebody upgraded it. Bootstrap it with `acme-proxy admin user create`;
there is no sign-up page.

**`bind_address`** (`String`) — *Default: `"127.0.0.1:3001"` | Env: `ACME_PROXY_ADMIN__BIND_ADDRESS`*

Loopback on purpose. This listener has no admission control, no filter chain and
— until `[admin.tls]` is on — no transport security.

**Startup refuses a non-loopback bind while `admin.tls.enabled` is `false`.**
The session cookie is always sent `Secure`, and a browser silently declines to
store one over plain HTTP on anything but `localhost`; the symptom would be
"sign-in works, then I am immediately signed out", with nothing in any log to
explain it. Either enable `[admin.tls]`, or keep the loopback bind and reach it
through an SSH tunnel:

```console
$ ssh -N -L 3001:127.0.0.1:3001 ca.example.com
```

It is also an error for this to equal `server.bind_address`.

**`base_url`** (`String`) — *Default: `"http://localhost:3001"` | Env: `ACME_PROXY_ADMIN__BASE_URL`*

The origin the panel is reached at. Load-bearing three times over: the CSRF
origin check compares against it, a generated self-signed certificate takes its
host, and the pages build absolute URLs from it — exactly as `server.base_url`
does for the ACME listener. Through a tunnel this stays `localhost`. The
resolved origin is logged at startup (`admin_origin_resolved`) so a mismatch is
visible before the first refused request.

**`session_ttl_seconds`** (`Integer`) — *Default: `43200` (12 h) | Env: `ACME_PROXY_ADMIN__SESSION_TTL_SECONDS`*

Absolute session lifetime. Never extended by activity: past it, the operator
signs in again.

**`session_idle_timeout_seconds`** (`Integer`) — *Default: `3600` (1 h) | Env: `ACME_PROXY_ADMIN__SESSION_IDLE_TIMEOUT_SECONDS`*

Idle lifetime, advanced on use — at most once a minute, so a polling page is not
a stream of database writes. Whichever deadline comes first wins.

**`login_max_attempts`** (`Integer`) / **`login_window_seconds`** (`Integer`) — *Defaults: `5` / `300` | Env: `ACME_PROXY_ADMIN__LOGIN_MAX_ATTEMPTS`, `ACME_PROXY_ADMIN__LOGIN_WINDOW_SECONDS`*

Failed sign-ins allowed from one address per window, then `429` with a
`Retry-After`. The password hash is deliberately expensive (PBKDF2-HMAC-SHA256
at 600 000 iterations), so this is an availability control as much as a
credential one: over the limit, the hash is not computed at all.

Keyed on the peer address. **There is no forwarded-header handling on this
listener** — `filter.trusted_proxies` governs the ACME one, and trusting
`X-Forwarded-For` here without an equivalent allowlist would let any caller
spoof the key. Behind a reverse proxy the limiter counts the proxy.

**`require_mfa`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__REQUIRE_MFA`*

Require a second factor (TOTP) of every operator. What this changes is the
operator who has **none**: with it on, their next sign-in lands on the enrolment
page and their session stays half-authenticated until they finish. An operator
who already has one is challenged whether this is set or not.

It deliberately does **not** refuse a password-only sign-in outright: enrolling
needs a session and a session would then need a factor, so that would brick the
panel including the way in to fix it.

Turning it on does not retroactively end sessions that predate it — `acme-proxy
admin session revoke --all` is the lever that does. While it is on and some
operator has no factor, every start logs `admin_mfa_enrolment_pending`. See
[Operators and sessions](../operations/webadmin_users.md#second-factor-totp).

**`max_body_bytes`** (`Integer`) — *Default: `65536` | Env: `ACME_PROXY_ADMIN__MAX_BODY_BYTES`*

Largest admin request body. An admin body is a small JSON object or a form,
never a certificate.

**`page_size_max`** (`Integer`) — *Default: `200` | Env: `ACME_PROXY_ADMIN__PAGE_SIZE_MAX`*

Ceiling on `?limit=` for the list endpoints; the default page size is 50. A
larger request is clamped, not refused.

**`template_dir`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__TEMPLATE_DIR`*

Override individual page templates on disk, mirroring `notify.template_dir`.
Empty means the compiled-in defaults. The override is per *file*: a directory
holding only `layout.html` restyles the chrome of every page and leaves the
other twenty at their defaults. Every template is compiled at startup, so a
broken override refuses to start rather than serving a `500` later. Applies to
the `/ui` pages only; the JSON API has nothing to template. See
[Customizing the Panel](../operations/webadmin_templates.md).

### `[admin.tls]`

HTTPS on `admin.bind_address` **instead of** cleartext — the same
one-listener-not-two shape as `[server.tls]`, and the same load-or-generate
provisioning.

**`enabled`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__TLS__ENABLED`*

Anything but `http://localhost` needs this on, or the browser will not store the
session cookie at all.

**`cert_path`** / **`key_path`** (`String`) — *Defaults: `"admin.pem"` / `"admin.key"` | Env: `ACME_PROXY_ADMIN__TLS__CERT_PATH`, `ACME_PROXY_ADMIN__TLS__KEY_PATH`*

PEM chain (leaf first) and its private key. When either is missing, a
self-signed certificate for the host of `admin.base_url` is generated and
written at startup; the generated key is created `0600`. Separate paths from
`[server.tls]` on purpose — the two listeners answer to different names and
should not share a certificate by accident.

**`handshake_timeout_ms`** (`Integer`) — *Default: `10000` | Env: `ACME_PROXY_ADMIN__TLS__HANDSHAKE_TIMEOUT_MS`*

As `[server.tls]`.

---

## `[challenge]`

Which challenge types each new authorization offers, whether they are validated
at all, and the per-type keys under `[challenge.http_01]` and
`[challenge.tls_alpn_01]`.

Documented in full in [Challenge Validation](../challenges/index.md#reference) —
this section is a per-profile subsystem with its own chapter, so its keys live
there rather than being restated here.

---

## `[order]`

**`validity_seconds`** (`Integer`) — *Default: `604800` (7 days) | Env: `ACME_PROXY_ORDER__VALIDITY_SECONDS`*

Lifetime of the ACME **order object** before it expires. This is housekeeping
for the order resource, not the issued certificate's validity — that is
`signer.local_ca.leaf_validity_days`, or whatever the delegating backend
decides.

---

## `[nonce]`

**`ttl_seconds`** (`Integer`) — *Default: `300` | Env: `ACME_PROXY_NONCE__TTL_SECONDS`*

Freshness window for JWS anti-replay nonces. Expired nonces are swept on an
interval for the life of the process.

---

## `[audit]`

Traceability and the CA's audit trail. **Process-wide, not per-profile** — the
trail describes the CA, not one of its endpoints, so this section may not appear
under `[profiles.<name>]`.

There is deliberately **no `enabled` key**. The address columns on accounts and
orders, and the `audit_log` table, are always written: recording who asked the
CA to sign something is what a CA does, not a feature to switch on. The only
thing here that can be turned off is the reverse lookup.

**`reverse_dns`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_AUDIT__REVERSE_DNS`*

Resolve a PTR record for the client's address and freeze it into the row beside
the address. Turn it off on an estate with no usable reverse zone: every lookup
would fail, every `*_ptr` column would end up `NULL` anyway, and all that would
be left is the round trip. Lookups go through `dns.resolver` like every other
DNS query this server makes.

**`reverse_dns_timeout_ms`** (`Integer`) — *Default: `2000` | Env: `ACME_PROXY_AUDIT__REVERSE_DNS_TIMEOUT_MS`*

Budget for one PTR lookup. Deliberately small: this runs inside a request that
has already done its real work, so a slow nameserver costs a `NULL` in one
column rather than latency on issuance. **Every failure is a `NULL`, never a
refused request.**

**`retention_days`** (`Integer`) — *Default: `0` | Env: `ACME_PROXY_AUDIT__RETENTION_DAYS`*

Delete `audit_log` rows older than this many days. `0` keeps everything for
ever, which is the right default for a trail whose value is that it is complete.
Any non-zero value spawns a daily sweep beside the nonce reaper, running the
same `DELETE` as `acme-proxy audit cleanup --older-than <days>`.

See [Audit Trail](../operations/audit.md).

---

## `[dns]`

**`resolver`** (`String`) — *Default: unset (system configuration, i.e. `/etc/resolv.conf`) | Env: `ACME_PROXY_DNS__RESOLVER`*

`host:port` of the nameserver **every** DNS lookup this server makes goes
through: the `dns-01` TXT query, the connect target that `http-01`/`tls-alpn-01`
resolve before reaching out, and `filter.reverse_dns`'s PTR and forward lookups.

The shared resolver is deliberately **uncached**, so a TXT record published
moments before a challenge is triggered is not defeated by a cached negative
answer. `filter.reverse_dns` is the one exception and keeps its own cached
resolver.

---

## `[meta]`

The optional `meta` members of the directory (§7.1.1). All are empty by default
and omitted from the directory when empty — never sent as an empty value.

**`terms_of_service`** (`String`) — *Default: `""` | Env: `ACME_PROXY_META__TERMS_OF_SERVICE`*

URL of your terms of service. **This one has teeth**: setting it turns on
§7.3.3, so `newAccount` then refuses any request without `termsOfServiceAgreed:
true` (`403 userActionRequired` + a `Link: rel="terms-of-service"` header), and
account objects begin reflecting `termsOfServiceAgreed`.

**`website`** (`String`) — *Default: `""` | Env: `ACME_PROXY_META__WEBSITE`*

Informational URL about the ACME server. Advertised only.

**`caa_identities`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_META__CAA_IDENTITIES`*

Hostnames this CA recognizes in CAA records. **Advertised only** — this server
performs no CAA checking.

---

## `[logging]`

All six keys are validated at startup: an unknown value is a refusal to start
with a message naming the key, never a silent fallback — a CA running at a log
level or to a destination its operator did not ask for is the worse failure.

What the resulting records actually contain, and what to alert on, is
[Monitoring & Observability](../operations/monitoring.md).

**`filter`** (`String`) — *Default: `"acme_proxy=info"` | Env: `ACME_PROXY_LOGGING__FILTER`*

`EnvFilter` directive, used **only when `RUST_LOG` is unset**. `RUST_LOG` wins
whenever it is present, and replaces the whole filter — a bare `RUST_LOG=debug`
therefore also turns on debug logging for every dependency.

**`json_format`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_LOGGING__JSON_FORMAT`*

Emit JSON instead of the human-readable format. Set this in production if you
ship logs to ELK, Loki, Datadog or similar: the structured fields become
first-class keys rather than text to be re-parsed.

**`target`** (`String`) — *Default: `"stdout"` | Env: `ACME_PROXY_LOGGING__TARGET`*

Where records are written: `stdout` or `stderr`. Any other value is a startup
error.

**`ansi`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_LOGGING__ANSI`*

ANSI colour in the human-readable format. Turn it off when the log is piped to a
file or a collector that does not strip escape sequences. Ignored when
`json_format` is on.

**`span_events`** (`String`) — *Default: `"none"` | Env: `ACME_PROXY_LOGGING__SPAN_EVENTS`*

Span lifecycle records: `none`, `close` or `full`. Any other value is a startup
error. `close` emits one record as each span ends, carrying the time spent busy
and idle inside it — the closest thing to per-operation timing available without
a metrics endpoint, and cheap enough to leave on. `full` adds
`new`/`enter`/`exit` and is a debugging tool.

**`flatten_event`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_LOGGING__FLATTEN_EVENT`*

JSON only: lift a record's own fields (`event`, and everything beside it) to the
top level instead of nesting them under `fields`. What most pipelines want; off
by default because a field can then collide with one of the format's own keys.

---

## `[profiles.<name>]`

An **ACME endpoint is a profile**. The server serves ACME only through them, and
**at least one enabled profile is required** — startup fails otherwise, with a
copy-pasteable minimal configuration in the error.

```toml
# The whole minimum. `enabled` defaults to true, so naming it is enough.
[profiles.default]
```

**`enabled`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_PROFILES__<NAME>__ENABLED`*

Parks a profile without deleting its configuration. It also doubles as the one
key an environment-only profile needs:
`ACME_PROXY_PROFILES__DEFAULT__ENABLED=true` defines a working profile with no
configuration file at all.

Load-bearing rules:

- **The mount path is derived from the name, never configured.** `[profiles.le]`
  answers at `{base_url}/profile/le/directory`. Names must match `^[a-z0-9-]+$`.
  The name is public API — it appears in every `kid` and order URL a client
  stores — so renaming a profile invalidates every client's saved account.
- **Inheritance is per key, not per section.** The global `[signer]`,
  `[filter]`, `[challenge]`, `[eab]`, `[order]`, `[notify]` and `[meta]`
  sections are the base each profile overlays. A profile that sets only
  `challenge.bypass` keeps the **global** `challenge.enabled` rather than
  reverting it to the compiled default. Precedence: profile key > global key >
  compiled default.
- **Arrays replace wholesale, never append.** A profile's `filter.enabled` fully
  replaces the global one.
- **Profiles are a database boundary, not just a URL prefix.** Accounts and
  orders carry a profile column, and accounts are keyed `UNIQUE(profile,
  pubkey)` — one client key used at two endpoints is two independent ACME
  accounts.
- **Signer backends are shared by configuration.** Two profiles with identical
  `[signer]` sections share one backend instance. Two profiles sharing a
  `local_ca` key path while differing elsewhere is a startup error.

```toml
[signer]
backend = "local_ca"

[filter]
enabled = []

# Inherits everything above.
[profiles.dev]

# Overrides two keys; keeps the rest.
[profiles.prod]
signer.backend = "acme_proxy"
signer.acme_proxy.directory_url = "https://acme-v02.api.letsencrypt.org/directory"
filter.enabled = ["allowed_ip"]
filter.allowed_ip.allow = ["10.0.0.0/8"]
```

See [Profiles & Routing](../core/profiles.md).

---

## Environment variable gotchas

These bite in production and produce no error, so they are worth knowing before
you configure anything through the environment.

**Array-valued keys are parsed from a comma-separated string.** That means a
value containing a literal comma cannot be expressed. A regex such as
`^host\d{2,3}\.example\.com$` is therefore **file-only** — through the
environment, `{2,3}` splits into two list entries.

**An array set to the empty string is *present*, not absent.** Shell defaults
like `ACME_PROXY_FILTER__ENABLED="${FILTERS:-}"` set the variable to `""`, which
the configuration layer cannot distinguish from a deliberate value — and
`"".split(',')` yields one empty element, not zero. `acme-proxy` collapses this
back to an empty list for every array key, so it is safe; just do not expect
`""` to mean "fall back to the file".

**A list-valued key *inside* a profile needs its runtime key registered.** The
loader scans the environment for `ACME_PROXY_PROFILES__<NAME>__…` before
building its sources, which is what makes e.g.
`ACME_PROXY_PROFILES__LE__CHALLENGE__ENABLED` work. This is handled
automatically; it is documented here because it is the mechanism a new key can
accidentally miss.

**Unknown keys are ignored, not rejected.** A misspelled key, or a key written
under the wrong section, is silently dropped. The most common instance of this
is `trusted_proxies` written under `[server]` when it belongs to `[filter]` —
see
[Allowed IP](../filters/allowed_ip.md).

---

## Sections documented elsewhere

The five sections with a chapter of their own, expanded — see [the map
above](#every-section-and-where-it-is-documented) for the rest.

- **`[signer]`** — [Signers](../signers/index.md):
  [local_ca](../signers/local_ca.md) and its
  [PKCS#11 keys](../signers/local_ca_hsm.md),
[acme_proxy](../signers/acme_proxy.md), [custom](../signers/custom.md)
- **`[filter]`** — [Filters](../filters/index.md):
  [allowed_ip](../filters/allowed_ip.md),
  [reverse_dns](../filters/reverse_dns.md),
[identifiers](../filters/identifiers.md), [netbox](../filters/netbox.md),
  [custom](../filters/custom.md)
- **`[challenge]`** — [Challenge Validation](../challenges/index.md#reference):
  [http-01](../challenges/http_01.md#reference),
  [dns-01](../challenges/dns_01.md),
  [tls-alpn-01](../challenges/tls_alpn_01.md#reference)
- **`[notify]`** — [Notifications](../notifications/index.md):
  [email](../notifications/email.md),
  [mattermost](../notifications/mattermost.md),
  [custom](../notifications/custom.md)
- **`[eab]`** — [External Account Binding](../features/eab.md)
