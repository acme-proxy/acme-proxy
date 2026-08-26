# ASVS 5.0 Assessment

A self-assessment of `acme-proxy` against [OWASP ASVS
5.0](https://owasp.org/www-project-application-security-verification-standard/),
whose text is vendored under `rfc/asvs-5.0/` in this repository.

- **Assessed at:** Level 2. Every L1 and L2 requirement in scope is given a
  status; L3 requirements are listed too, as information rather than as a bar
  being claimed.
- **Assessed against:** the tree at release 0.2.0.
- **Method:** source review. The evidence column names a file, not a promise —
  for a control requirement, the documentation on this site is context and the
  code is the evidence.

This is a **self-assessment and not a certification.** ASVS is explicit that a
verification claim means an assessor performed the work; nobody outside the
project has performed it here. Read this page as the maintainers' own answer to
"which recognised controls does this meet, and where does it fall short",
which is a useful thing to have written down and a different thing from an
audit.

## What was assessed

Three surfaces, kept apart because their controls genuinely differ:

| Surface | What it is | Where |
| --- | --- | --- |
| ACME listener | Unauthenticated by design, authenticated per request by JWS. Carries the filter chain, admission control and the nonce middleware. | `src/lib.rs`, `src/handlers/`, `src/extractors/`, `src/middlewares/` |
| Web admin | The only session-based, browser-facing surface. Off by default, loopback by default. | `src/webadmin/`, `src/admin/` |
| CLI and process | Answers to a shell on the host and holds no session. | `src/cli/`, `src/main.rs`, `src/config/` |

Most of V3, V6 and V7 apply only to the web admin. When it is disabled —
which is the default — those chapters have no surface to apply to at all.

### Chapter disposition

| Chapter | In scope | Note |
| --- | --- | --- |
| V1 Encoding and Sanitization | yes | |
| V2 Validation and Business Logic | yes | |
| V3 Web Frontend Security | yes | Web admin only |
| V4 API and Web Service | yes | GraphQL and WebSocket sections are n/a |
| V5 File Handling | partly | There is no upload feature; the sections that assume one are n/a |
| V6 Authentication | yes | Web admin and the CLI credential lifecycle |
| V7 Session Management | yes | Web admin only |
| V8 Authorization | yes | |
| V9 Self-contained Tokens | yes | The self-contained token here is the ACME JWS, not a session JWT |
| V10 OAuth and OIDC | **no** | No OAuth, no OIDC, no external identity provider, no token endpoint. Nothing in the chapter has a subject |
| V11 Cryptography | yes | |
| V12 Secure Communication | yes | |
| V13 Configuration | yes | |
| V14 Data Protection | yes | |
| V15 Secure Coding and Architecture | yes | |
| V16 Security Logging and Error Handling | yes | |
| V17 WebRTC | **no** | No WebRTC, no media, no signalling |

## Summary

Counts are of the requirements enumerated in the per-chapter tables below;
every requirement of every in-scope chapter is present, so the totals match
ASVS 5.0's own counts. **L1+L2** is the bar being assessed; the L3 column is
reported for information.

| Chapter | L1+L2 met | partial | gap | n/a | L3 (met / short / n/a) |
| --- | --- | --- | --- | --- | --- |
| V1 Encoding and Sanitization | 17 | 1 | 0 | 9 | 2 / 0 / 1 |
| V2 Validation and Business Logic | 11 | 0 | 0 | 0 | 0 / 1 / 1 |
| V3 Web Frontend Security | 16 | 1 | 0 | 2 | 6 / 4 / 2 |
| V4 API and Web Service | 4 | 0 | 0 | 6 | 6 / 0 / 0 |
| V5 File Handling | 4 | 0 | 0 | 5 | 0 / 0 / 4 |
| V6 Authentication | 24 | 3 | 0 | 8 | 6 / 3 / 3 |
| V7 Session Management | 14 | 2 | 0 | 2 | 0 / 1 / 0 |
| V8 Authorization | 7 | 0 | 0 | 0 | 4 / 2 / 0 |
| V9 Self-contained Tokens | 7 | 0 | 0 | 0 | 0 / 0 / 0 |
| V11 Cryptography | 10 | 3 | 0 | 1 | 5 / 2 / 3 |
| V12 Secure Communication | 6 | 1 | 0 | 2 | 0 / 2 / 1 |
| V13 Configuration | 8 | 5 | 0 | 0 | 4 / 4 / 0 |
| V14 Data Protection | 9 | 0 | 0 | 0 | 2 / 1 / 1 |
| V15 Secure Coding and Architecture | 10 | 1 | 1 | 1 | 8 / 0 / 0 |
| V16 Security Logging and Error Handling | 15 | 1 | 0 | 0 | 0 / 1 / 0 |
| **Total** | **162** | **18** | **1** | **36** | **43 / 21 / 16** |

The short version. **There is no L1 gap**, and at **L2 there is one**:
V15.1.2, an SBOM artifact. The four password-policy requirements that used to
sit here — V6.2.4 at L1, and V6.1.2 / V6.2.11 / V6.2.12 at L2 — were one
missing control seen from four angles, and closed as one:
`check_password_policy` now refuses a password that names this deployment, or
that appears in a compiled-in corpus of common passwords.

Everything else that falls short of *met* is either a **partial** — a control
that exists but does not reach everywhere the requirement asks — or a
**documented deviation**, where the project has knowingly chosen otherwise and
argued the choice already. Both have their own sections below.

Two chapters deserve a note on their shape. **V6 Authentication** carries the
most n/a rows because the web admin has one authentication pathway and no
out-of-band, biometric or federated factors — most of the chapter has no
subject here. **V16 Security Logging** is the only chapter with no L1
requirements at all and is met almost entirely, which is what you would hope
for in a certificate authority: the audit trail is the product.

## V1 Encoding and Sanitization

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 1.1.1 | Decode into canonical form once, before processing | 2 | met | The JWS protected header and payload are base64url-decoded exactly once in `src/extractors/acme.rs`, before any check reads them; a DNS identifier passes `normalize_dns_name` (`src/handlers/helpers.rs`) once, before storage and before the filter sees it |
| 1.1.2 | Output encoding as the final step, or by the interpreter | 2 | met | `minijinja` escapes at render time. The rule is per template *name*: `.html` auto-escapes, `.j2` does not — see `src/templating.rs` |
| 1.2.1 | Context-correct output encoding for HTTP/HTML | 1 | met | Every panel template is `.html` and therefore auto-escaped; `auto_escaping_is_on_for_pages_and_off_for_notify` pins both directions |
| 1.2.2 | Encode untrusted data in dynamically built URLs; safe protocols only | 1 | met | Panel URLs are built from server-side ids. The one place an untrusted URL is followed — an `http-01` redirect — is checked against a scheme allowlist in `Http01Validator::redirect_allowed` (`src/challenge/http_01.rs`) |
| 1.2.3 | Encode when building JavaScript or JSON | 1 | met | All JSON is produced by `serde_json`; no template writes into a `<script>` block |
| 1.2.4 | Parameterized database queries | 1 | met | Every statement in `src/sqlite/` is a runtime `sqlx::query` with `.bind()`. No query is assembled with `format!` |
| 1.2.5 | Protection against OS command injection | 1 | met | `ScriptHook::run` uses `Command::new(path)` with an argv vector and no shell (`src/script_hook.rs`); payloads go to stdin as JSON |
| 1.2.6 | LDAP injection | 2 | n/a | No LDAP client |
| 1.2.7 | XPath injection | 2 | n/a | No XPath |
| 1.2.8 | LaTeX injection | 2 | n/a | No LaTeX |
| 1.2.9 | Escape special characters in regular expressions | 2 | met | `compile_anchored` and the glob translation both run `regex::escape` over everything that is not the wildcard (`src/filter/mod.rs`) |
| 1.2.10 | CSV and formula injection | 3 | n/a | No CSV or spreadsheet export; the CLI emits text or JSON |
| 1.3.1 | Sanitize untrusted HTML from editors | 1 | n/a | No rich-text input anywhere |
| 1.3.2 | Avoid `eval()` and dynamic code execution | 1 | met | No dynamic code execution. The one place operator-supplied code runs is a `custom` script hook, which is a configured executable, not evaluated input |
| 1.3.3 | Sanitize before a dangerous context; trim over-long input | 2 | met | Contacts reject control characters, `User-Agent` is truncated to 256 characters before storage (`src/audit/mod.rs`), identifier lists are capped by `order.max_identifiers` |
| 1.3.4 | Sanitize user-supplied SVG | 2 | n/a | No user-supplied images |
| 1.3.5 | Sanitize user-supplied scriptable or template content | 2 | n/a | `template_dir` overrides are operator-supplied files on the host, not user input |
| 1.3.6 | SSRF protection by allowlist of protocols, domains, paths, ports | 2 | partial | Scheme, port and hop count are allowlisted for `http-01` redirects; **destination addresses deliberately are not**. See [Documented deviations](#documented-deviations) |
| 1.3.7 | No templates built from untrusted input | 2 | met | Template *sources* come only from the embedded table or `template_dir`; untrusted values are only ever bound as context |
| 1.3.8 | JNDI injection | 2 | n/a | No JNDI |
| 1.3.9 | Sanitize before memcache | 2 | n/a | No memcache |
| 1.3.10 | Sanitize format strings | 2 | met | Rust format strings are compile-time literals; a runtime string can never become one |
| 1.3.11 | Sanitize before mail systems (SMTP/IMAP injection) | 2 | met | `contact_shape_error` rejects control characters, `hfields` and multiple addresses before a contact can reach a `notify` template (`src/handlers/helpers.rs`) |
| 1.3.12 | Regular expressions free from exponential backtracking | 3 | met | The `regex` crate has no backtracking and guarantees linear time; patterns are operator configuration, not request input |
| 1.4.1 | Memory-safe strings and copies | 2 | met | Safe Rust. The `unsafe` blocks in the tree are `std::env::set_var` in tests and one PKCS#11 `Send` impl (`src/signer/local_ca/pkcs11.rs`) |
| 1.4.2 | Prevent integer overflow | 2 | met | Time and TTL arithmetic uses `saturating_add`/`saturating_sub` throughout `src/sqlite/`; release builds are not built with overflow checks disabled beyond the default |
| 1.4.3 | Release memory and resources; no dangling pointers | 2 | met | Ownership and `Drop`. Script hooks additionally set `kill_on_drop` so a timed-out child is reaped |
| 1.5.1 | Restrictive XML parser configuration (XXE) | 1 | n/a | No XML parser in the dependency graph |
| 1.5.2 | Safe deserialization of untrusted data | 2 | met | `serde` into concrete structs. No polymorphic or client-chosen types; `src/extractors/jws.rs` deliberately does not use `deny_unknown_fields` because RFC 8555 §6.2 allows extra header parameters, and every field it acts on is named |
| 1.5.3 | Consistent parsers for one data type | 3 | met | One JSON parser (`serde_json`) and one URL parser (`url`) in the tree |

## V2 Validation and Business Logic

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2.1.1 | Documented input validation rules | 1 | met | Identifier syntax and normalisation are specified in [Filters](../filters/identifiers.md); the ACME wire formats are RFC 8555's and the deviations are listed in [Protocol Support](../features/index.md) |
| 2.1.2 | Documented rules for combined data items | 2 | met | The order/CSR consistency rule — the CSR may name only what the order named — is stated in [Filters](../filters/index.md) and enforced at finalize |
| 2.1.3 | Documented business logic limits | 2 | met | `order.max_identifiers`, `server.max_body_bytes`, nonce TTL, order and authorization lifetimes and the admission limiter are all in [Configuration Reference](../configuration/reference.md) with their defaults |
| 2.2.1 | Validate input against expectations | 1 | met | Identifiers are normalised and type-checked, wildcards are refused when `dns-01` is off, contacts are shape-checked, the CSR is parsed and compared against the order |
| 2.2.2 | Validation enforced at a trusted service layer | 1 | met | Every check is server-side. The panel's only client-side code is htmx attribute dispatch |
| 2.2.3 | Combinations of related data items are reasonable | 2 | met | `a_wildcard_identifier_is_rejected_when_dns_01_is_disabled` and `a_csr_requesting_ca_powers_yields_a_leaf_without_them` in `tests/security.rs` are two of the pinned cases |
| 2.3.1 | Business logic flows only in the expected step order | 1 | met | The order state machine refuses out-of-sequence transitions: `an_order_missing_an_authorization_never_becomes_ready`, `an_expired_order_cannot_be_finalized`, `a_deactivated_account_cannot_finalize_a_ready_order` (`tests/security.rs`) |
| 2.3.2 | Business logic limits implemented as documented | 2 | met | `an_order_naming_more_identifiers_than_the_limit_is_refused` (`tests/security.rs`) |
| 2.3.3 | Transactions succeed in full or roll back | 2 | met | Multi-row writes run inside `pool.begin()`/`commit()` — order creation with its authorizations (`src/handlers/order.rs`), challenge validation (`src/handlers/authz.rs`), session promotion (`src/sqlite/admin_session.rs`) |
| 2.3.4 | Locking prevents double-booking of limited resources | 2 | met | Single-use resources are claimed by `UPDATE … WHERE … AND <unused>` and decided by `rows_affected == 1`, never by read-then-write: nonces, recovery codes (`src/sqlite/admin_recovery_code.rs`), the TOTP replay step (`src/sqlite/admin_user.rs`) and session promotion |
| 2.3.5 | Multi-user approval for high-value flows | 3 | gap | Issuance and revocation are single-actor operations. There is no second-operator approval, and no plan to add one — a CA that needs a quorum to sign is a different product |
| 2.4.1 | Anti-automation on expensive functions | 2 | met | The ACME listener carries an admission limiter with a queue budget and a request deadline (`src/middlewares/admission.rs`); the admin login path is rate-limited per address before the KDF runs (`LoginLimiter`, `src/webadmin/session.rs`) |
| 2.4.2 | Business flows require realistic human timing | 3 | n/a | Every consumer of the ACME API is a machine; timing gates would break the protocol |

## V3 Web Frontend Security

Applies to the web admin. With `admin.enabled = false`, the default, none of
this is exposed at all.

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 3.1.1 | Documented expected browser security features | 3 | partial | [Web Admin](../operations/webadmin.md#security-notes) states the cookie and CSRF requirements and the `Secure`-over-plain-HTTP failure mode; there is no statement of what the panel does when a browser lacks a feature |
| 3.2.1 | Prevent content being rendered in the wrong context | 1 | met | `default-src 'none'` plus `X-Content-Type-Options: nosniff` on every response; the API is nested under `/api` with its own JSON fallback so a page path never returns an API body |
| 3.2.2 | Text rendered as text, not HTML | 1 | met | Auto-escaping templates; no `innerHTML` outside htmx's own fragment swap of server-rendered HTML |
| 3.2.3 | Avoid DOM clobbering | 3 | met | The panel ships no application JavaScript — htmx is the only script, and everything is driven by `hx-*` attributes |
| 3.3.1 | `Secure` attribute and a `__Secure-`/`__Host-` prefix | 1 | met | `__Host-acme_admin_session`, which browsers accept only with `Secure`, `Path=/` and no `Domain` (`src/webadmin/session.rs`) |
| 3.3.2 | `SameSite` set according to purpose | 2 | met | `SameSite=Strict` on both the session cookie and its clearing form |
| 3.3.3 | `__Host-` prefix unless shared with other hosts | 2 | met | Same as 3.3.1 |
| 3.3.4 | `HttpOnly` for values scripts must not read | 2 | met | `HttpOnly` is set; the CSRF token travels in the page and the `x-csrf-token` request header, never in a readable cookie |
| 3.3.5 | Cookie name and value under 4096 bytes | 3 | met | A 32-byte token, base64url-encoded, plus a fixed name |
| 3.4.1 | HSTS on all responses, ≥ 1 year, `includeSubDomains` for L2 | 1 | met | `max-age=31536000; includeSubDomains`, applied by the shared `security_headers()` constructor to **both** listeners (`src/lib.rs`) |
| 3.4.2 | CORS `Access-Control-Allow-Origin` fixed or allowlisted | 1 | met | No CORS layer exists on either listener, so no `Access-Control-Allow-Origin` is ever emitted |
| 3.4.3 | CSP with `object-src 'none'` and `base-uri 'none'` | 2 | met | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` — no `unsafe-inline`, no `unsafe-eval` (`src/webadmin/mod.rs`). `object-src` falls back to `default-src 'none'` |
| 3.4.4 | `X-Content-Type-Options: nosniff` | 2 | met | `security_headers()` |
| 3.4.5 | Referrer policy | 2 | met | `Referrer-Policy: same-origin` on the admin listener |
| 3.4.6 | CSP `frame-ancestors` on every response | 2 | met | `frame-ancestors 'none'`, with `X-Frame-Options: DENY` alongside for older clients |
| 3.4.7 | CSP reports a violation-reporting location | 3 | gap | No `report-to`/`report-uri`. For a single-origin panel with no inline script, the report channel would have no consumer |
| 3.4.8 | `Cross-Origin-Opener-Policy` on document responses | 3 | gap | Not set. `frame-ancestors 'none'` covers framing but not shared `Window` access from a popup |
| 3.5.1 | Anti-forgery tokens or non-safelisted header fields | 1 | met | A per-session CSRF token in the `x-csrf-token` header on every unsafe method, plus an `Origin` check against `admin.base_url` — the module doc in `src/webadmin/session.rs` explains why `SameSite=Strict` alone is not enough here |
| 3.5.2 | Functionality cannot be called without a preflight | 1 | n/a | The panel does not rely on CORS preflight; it uses the token in 3.5.1 |
| 3.5.3 | Sensitive functionality uses unsafe HTTP methods | 1 | met | Every mutating route is `POST`/`DELETE`; `GET` routes are read-only. `mutating_endpoints()` and `mutating_page_endpoints()` are the lists that make this checkable |
| 3.5.4 | Separate applications on different hostnames | 2 | partial | The ACME and admin surfaces are separate *sockets* with separate TLS and separate defaults, and the admin binds loopback unless TLS is on. They are usually two **ports on one host**, and cookies are not port-scoped — see [Documented deviations](#documented-deviations) |
| 3.5.5 | Validate `postMessage` origins | 2 | n/a | No `postMessage` |
| 3.5.6 | No JSONP | 3 | met | None |
| 3.5.7 | No authorized data in script resources | 3 | met | The only script served is a static, unauthenticated copy of htmx |
| 3.5.8 | Authenticated resources embeddable only when intended | 3 | met | `Sec-Fetch` is not inspected, but `frame-ancestors 'none'`, `SameSite=Strict` and the CSRF token together mean no cross-origin embed carries the session |
| 3.6.1 | SRI for externally hosted client assets | 3 | met | Nothing is externally hosted. htmx is vendored under `src/webadmin/static/` and served from the same origin |
| 3.7.1 | Only supported, secure client-side technologies | 2 | met | HTML, CSS and htmx. No plugins |
| 3.7.2 | Automatic redirects only to allowlisted hosts | 2 | met | The panel's redirects are fixed relative paths (`/ui/`, the sign-in page); there is no `next=` parameter and no open-redirect surface |
| 3.7.3 | Notify before redirecting outside the application | 3 | n/a | The panel never redirects off-origin |
| 3.7.4 | HSTS preload | 3 | n/a | The panel is an internal service with an operator-chosen hostname; preloading is a decision for the operator's domain, not this software |
| 3.7.5 | Documented behaviour on browsers lacking security features | 3 | gap | See 3.1.1 |

## V4 API and Web Service

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 4.1.1 | Accurate `Content-Type` with charset | 1 | met | ACME responses are `application/json` or `application/problem+json`; panel pages are `text/html; charset=utf-8` via `axum::response::Html`; the two static assets set their own type with an explicit charset (`src/webadmin/pages/assets.rs`) |
| 4.1.2 | Only user-facing endpoints redirect HTTP to HTTPS | 2 | met | Neither listener redirects. `server.tls.enabled` makes the socket speak TLS **instead of** cleartext, not alongside it (`src/tls.rs`) |
| 4.1.3 | Intermediary-set header fields cannot be overridden by the user | 2 | met | A forwarded-for header is believed only from a hop in `filter.trusted_proxies`; with the list empty the header is ignored entirely and the peer address is used (`src/filter/client_ip.rs`). The admin listener does no forwarded-header handling at all, deliberately |
| 4.1.4 | Only supported HTTP methods are usable | 3 | met | `axum` routes declare their methods and answer `405` otherwise; both routers carry an explicit `method_not_allowed_fallback` so the refusal is a proper problem document rather than an empty body |
| 4.1.5 | Per-message digital signatures for highly sensitive requests | 3 | met | Every state-changing ACME request is a JWS signed by the account key, verified against a nonce and the request URL (RFC 8555 §6.2) — this is the protocol's own design, not an addition |
| 4.2.1 | Correct HTTP message framing (request smuggling) | 2 | met | `hyper` performs the framing and rejects conflicting `Content-Length`/`Transfer-Encoding`; the application never parses framing itself |
| 4.2.2 | Generated `Content-Length` matches the body | 3 | met | Response bodies are `axum` types; the length is computed, never asserted |
| 4.2.3 | No connection-specific header fields over HTTP/2 or HTTP/3 | 3 | met | `hyper` enforces this. No handler sets `Transfer-Encoding` |
| 4.2.4 | Reject CR/LF in HTTP/2 and HTTP/3 header fields | 3 | met | `http::HeaderValue` rejects control bytes on construction, in both directions |
| 4.2.5 | Avoid generating over-long URIs or header fields | 3 | met | Outbound URLs are built from configuration plus a bounded token or id; the `http-01` validator additionally caps redirect hops |
| 4.3.1 | GraphQL query cost limiting | 2 | n/a | No GraphQL |
| 4.3.2 | GraphQL introspection disabled | 2 | n/a | No GraphQL |
| 4.4.1 | WebSocket over TLS | 1 | n/a | No WebSocket |
| 4.4.2 | WebSocket handshake `Origin` check | 2 | n/a | No WebSocket |
| 4.4.3 | Dedicated WebSocket session tokens | 2 | n/a | No WebSocket |
| 4.4.4 | WebSocket tokens obtained through the authenticated session | 2 | n/a | No WebSocket |

## V5 File Handling

There is **no file upload feature**. The only client-supplied structured input
is a CSR inside a signed JWS, which is assessed under V2 and V11 rather than
here. The two paths that touch the filesystem on a request's behalf are the
embedded static-asset allowlist and the certificate-chain download.

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 5.1.1 | Documented permitted file types, extensions and sizes | 2 | n/a | No upload feature to document |
| 5.2.1 | Only accept files of a processable size | 1 | met | `server.max_body_bytes` (128 KiB) and `admin.max_body_bytes` (64 KiB) bound every request body, applied as `DefaultBodyLimit` at each router root |
| 5.2.2 | Extension matches content | 1 | n/a | No uploads |
| 5.2.3 | Compressed-file limits | 2 | n/a | Nothing is decompressed |
| 5.2.4 | Per-user file quota | 3 | n/a | No uploads |
| 5.2.5 | Reject symlinks in archives | 3 | n/a | No archives |
| 5.2.6 | Reject over-large images | 3 | n/a | No images |
| 5.3.1 | Untrusted files in a public folder are not executed | 1 | n/a | Nothing untrusted is written to a served directory |
| 5.3.2 | File paths built from trusted data, not user filenames | 1 | met | `GET /ui/static/{file}` is a two-arm `match`, not a filesystem lookup — `tower-http`'s `fs` feature is deliberately off (`src/webadmin/pages/assets.rs`). The `http-01` responder looks a token up in an in-memory store and touches no path |
| 5.3.3 | Ignore user path information when decompressing | 3 | n/a | Nothing is decompressed |
| 5.4.1 | Validate or ignore user filenames; set `Content-Disposition` | 2 | met | The chain download names the file from the **stored** order id, not the path segment, and sets `attachment; filename="…"` (`src/webadmin/pages/orders.rs`) |
| 5.4.2 | Served filenames are encoded or sanitized | 2 | met | Same: a generated identifier, so there is nothing to encode |
| 5.4.3 | Antivirus scanning of files from untrusted sources | 2 | n/a | No files are accepted from untrusted sources |

## V6 Authentication

Applies to the web admin and to the CLI commands that mint and rotate operator
credentials. The ACME listener authenticates *keys*, not people; that is
assessed under V9.

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 6.1.1 | Documented anti-automation and lockout behaviour | 1 | met | [Web Admin](../operations/webadmin.md#authentication) and the `login_max_attempts` / `login_window_seconds` entries in [Configuration Reference](../configuration/reference.md). The limiter is keyed on the peer **address**, never the username, so no attacker can lock an operator out by guessing at them |
| 6.1.2 | Documented list of context-specific words barred from passwords | 2 | met | Derived and documented: [Password policy](../operations/webadmin_users.md#the-context-specific-word-list) |
| 6.1.3 | Multiple authentication pathways documented together | 2 | met | There are two — a panel session and a shell on the host — and [Users & Sessions](../operations/webadmin_users.md) states which operations belong to which and why create and `passwd` stay on the host |
| 6.2.1 | Passwords at least 8 characters | 1 | met | `MIN_PASSWORD_LEN = 12`, counted in characters rather than bytes (`src/admin/password.rs`) |
| 6.2.2 | Users can change their password | 1 | partial | Only through `acme-proxy admin user passwd` on the host. An operator with no shell cannot rotate their own password |
| 6.2.3 | Password change requires current and new password | 1 | partial | `admin user passwd` takes only the new password. It answers to a shell that can already read and rewrite the database, so no password would add authority — but it does mean no *self-service* change path exists that could require one |
| 6.2.4 | Check against the top 3000 passwords | 1 | met | 13 918 entries compiled in (`src/admin/corpus/`); every shorter entry is already refused on length |
| 6.2.5 | No composition rules | 1 | met | Deliberately none. The three rules are about length, this deployment's own words and known-common passwords — none dictates shape (`src/admin/password.rs`) |
| 6.2.6 | Password fields use `type=password` | 1 | met | `templates/login.html` and the step-up field in `templates/account/_card.html` |
| 6.2.7 | Paste and password managers permitted | 1 | met | Standard inputs with `autocomplete="username"` / `"current-password"`; nothing blocks paste |
| 6.2.8 | Password verified exactly as received | 1 | met | `verify_password` hashes the bytes as received: no trimming, no case folding, and an over-long password is *rejected* rather than truncated. The policy check folds a copy to compare against the corpus and the word list, and never touches what is stored |
| 6.2.9 | Passwords of at least 64 characters permitted | 2 | met | `MAX_PASSWORD_LEN = 1024` bytes, a denial-of-service bound rather than a policy |
| 6.2.10 | No forced periodic rotation | 2 | met | Nothing expires a password. The stored form is self-describing, so raising the KDF cost re-encodes a row on its owner's next login instead of forcing a change |
| 6.2.11 | Context-specific word list used | 2 | met | `PasswordContext` in `src/admin/password.rs`, matched as a substring |
| 6.2.12 | Check against breached passwords | 2 | met | Same corpus: breach-derived (`xato-net`), filtered to the reachable length range |
| 6.3.1 | Credential-stuffing and brute-force controls | 1 | met | `LoginLimiter` refuses over the limit **before** the 600 000-iteration KDF runs, which makes it an availability control as much as a credential one (`src/webadmin/session.rs`) |
| 6.3.2 | No default accounts | 1 | met | The `admin_users` migration seeds no rows and there is no sign-up page; the first operator is created by `admin user create` on the host |
| 6.3.3 | MFA or a combination of single factors | 2 | partial | TOTP with recovery codes is implemented and `admin.require_mfa` enforces it for every operator — but it defaults to `false`, so a stock deployment is single-factor. [Hardening](hardening.md#the-web-admin) tells operators to turn it on. For L3 this would need a hardware factor; see [Documented deviations](#documented-deviations) |
| 6.3.4 | No undocumented pathways; consistent strength | 2 | met | The panel and API share one session layer, and every mutating route passes through `AuthenticatedWrite`, `PageSessionWrite` or `EnrolWrite`. The host CLI is the second pathway and is documented as such |
| 6.3.5 | Notify users of suspicious authentication attempts | 3 | gap | Every attempt is logged with its address and outcome, but nothing reaches the operator. `src/notify/` addresses certificate lifecycle, not people |
| 6.3.6 | Email not used as an authentication factor | 3 | met | It is not |
| 6.3.7 | Notify after changes to authentication details | 3 | gap | Same as 6.3.5 |
| 6.3.8 | Valid users not deducible from failed challenges | 3 | met | An unknown username still pays the KDF, against `password::dummy_hash()`, and every failure returns one `invalid_credentials` whatever the real cause (`src/admin/users.rs`) |
| 6.4.1 | Initial passwords and activation codes are random, policy-compliant and short-lived | 1 | n/a | Nothing generates an initial password; the operator supplies one on stdin or in `--password-file` |
| 6.4.2 | No password hints or secret questions | 1 | met | Neither exists |
| 6.4.3 | Secure forgotten-password reset that does not bypass MFA | 2 | met | Reset is `admin user passwd` on the host. It revokes every session the operator held and leaves the enrolled factor untouched, so the next sign-in still needs it |
| 6.4.4 | Lost MFA factor requires enrolment-level identity proofing | 2 | met | Either a single-use recovery code, or `admin user totp reset` on the host — the second being a strictly stronger proof than the live session plus password that enrolment took |
| 6.4.5 | Renewal reminders before an authenticator expires | 3 | n/a | No authentication factor expires |
| 6.4.6 | Administrators can reset but not choose a user's password | 3 | gap | `admin user passwd` sets the password, so whoever runs it knows it. This is a host-root operation on a machine that already holds the hashes |
| 6.5.1 | Lookup secrets and TOTPs usable only once | 2 | met | `AdminUser::claim_totp_step` is an `UPDATE … WHERE totp_last_step IS NULL OR totp_last_step < ?` decided by `rows_affected`, so a code resubmitted inside its own 30-second window is refused (`src/sqlite/admin_user.rs`); recovery codes are consumed by `UPDATE … WHERE id = ? AND used_at IS NULL` |
| 6.5.2 | Sub-112-bit lookup secrets hashed with an approved KDF and a 32-bit salt | 2 | met | Recovery codes carry 50 bits and are stored through `admin::password` — PBKDF2-HMAC-SHA256, 600 000 iterations, a 128-bit per-row salt |
| 6.5.3 | Seeds and codes from a CSPRNG | 2 | met | `ring::rand::SystemRandom` for the TOTP secret (`src/admin/totp.rs`) and every recovery code (`src/admin/recovery.rs`) |
| 6.5.4 | Lookup secrets have at least 20 bits of entropy | 2 | met | Ten characters from a 32-symbol alphabet: 50 bits, with zero modulo bias because 256 is a multiple of 32 |
| 6.5.5 | Defined lifetime for codes and TOTPs | 2 | met | 30-second step with RFC 6238 §5.2's one step of permitted skew either way (`SKEW_STEPS = 1`). A half-authenticated session additionally dies after `PENDING_MFA_TTL`, five minutes |
| 6.5.6 | Any factor can be revoked | 3 | met | `admin user totp reset`, `admin user disable`, `admin session revoke [--all]`, and recovery codes are superseded as a set on re-enrolment |
| 6.5.7 | Biometrics only as a secondary factor | 3 | n/a | No biometrics |
| 6.5.8 | TOTP checked against a trusted time source | 3 | met | The server's own clock; no client-supplied time reaches `totp::verify` |
| 6.6.1 | PSTN OTP restrictions | 2 | n/a | No SMS or voice factor |
| 6.6.2 | Out-of-band codes bound to their originating request | 2 | n/a | No out-of-band factor. The equivalent binding for TOTP is that the code is only accepted against the `pending_mfa` session that the password created |
| 6.6.3 | Rate-limit code-based out-of-band mechanisms | 2 | n/a | No out-of-band factor. TOTP guessing is bounded twice — `mfa_attempts` on the pending row and the five-minute `PENDING_MFA_TTL` |
| 6.6.4 | Rate-limit push notifications | 3 | n/a | No push factor |
| 6.7.1 | Certificates verifying authentication assertions protected from modification | 3 | met | Account public keys live in `accounts` under the database's file mode; a modified key is a key that no longer verifies its own account's requests |
| 6.7.2 | Challenge nonce at least 64 bits and unique | 3 | met | 256 bits from `ring::rand::SystemRandom`, unique by primary key and single-use by `rows_affected` (`src/sqlite/nonce.rs`) |
| 6.8.1 | Identity cannot be spoofed across identity providers | 2 | n/a | No identity provider |
| 6.8.2 | Signatures on authentication assertions validated | 2 | n/a | No external assertions. The equivalent for ACME JWS is V9.1.1 |
| 6.8.3 | SAML assertions processed once | 2 | n/a | No SAML |
| 6.8.4 | Authentication strength verified from the IdP | 2 | n/a | No identity provider |

## V7 Session Management

Applies to the web admin. The ACME listener holds no sessions: every request
carries its own signature and its own nonce.

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 7.1.1 | Documented inactivity timeout and absolute lifetime | 2 | met | `session_ttl_seconds` (12 h, never extended by activity) and `session_idle_timeout_seconds` (1 h) in [Configuration Reference](../configuration/reference.md), restated in [Web Admin](../operations/webadmin.md#authentication) |
| 7.1.2 | Documented concurrent-session policy | 2 | partial | The behaviour is definite — sessions are unlimited per operator, and `admin session revoke --all` is the lever — but no page states the limit as a policy |
| 7.1.3 | Federated session coordination documented | 2 | n/a | No federation |
| 7.2.1 | Session verification at a trusted backend | 1 | met | Every request resolves `hex(SHA-256(token))` against `admin_sessions` and re-checks state, expiry, idleness and the owner's status (`src/webadmin/session.rs`) |
| 7.2.2 | Dynamically generated tokens, not static secrets | 1 | met | `mint_token` per sign-in; there are no API keys on this listener |
| 7.2.3 | Reference tokens unique, CSPRNG, ≥ 128 bits | 1 | met | 256 bits from `ring::rand::SystemRandom`, base64url-encoded |
| 7.2.4 | New token on authentication, old one terminated | 1 | met | Sign-in deletes whatever session the request carried; completing MFA is a **rotation** — `AdminSession::promote` deletes the `pending_mfa` row and inserts a new one with a new token and a new CSRF token, in one transaction (`src/sqlite/admin_session.rs`) |
| 7.3.1 | Inactivity timeout | 2 | met | `session_idle_timeout_seconds`, checked per request and swept by the reaper |
| 7.3.2 | Absolute maximum session lifetime | 2 | met | `expires_at` is set at creation and never advanced |
| 7.4.1 | Terminated sessions cannot be reused | 1 | met | Sessions are reference tokens in a table; sign-out deletes the row |
| 7.4.2 | All sessions terminated when an account is disabled or deleted | 1 | met | `set_status("disabled")` and `set_password` both call `AdminSession::delete_for_user`; the liveness check also refuses a session whose owner is no longer active |
| 7.4.3 | Option to terminate other sessions after a factor changes | 2 | met | `confirm_totp_enrolment` and `disable_totp` both call `revoke_other_sessions`; a password change revokes every session unconditionally |
| 7.4.4 | Visible logout on every authenticated page | 2 | met | A "Sign out" control in `templates/layout.html`, which every page extends |
| 7.4.5 | Administrators can terminate sessions individually or globally | 2 | met | `admin session list` and `admin session revoke [--all]` |
| 7.5.1 | Full re-authentication before changing authentication attributes | 2 | met | `check_step_up` demands the password again before any change to an existing second factor, and the module doc explains the blast radius that makes it necessary (`src/webadmin/handlers/mfa.rs`) |
| 7.5.2 | Users can view and terminate their own sessions | 2 | partial | "Sign out everywhere" exists in the panel; **listing** one's own sessions is `admin session list` on the host only |
| 7.5.3 | Further authentication before highly sensitive operations | 3 | partial | Second-factor changes are gated by `check_step_up`. Certificate revocation and account deletion are not — a live session is sufficient authority for both |
| 7.6.1 | Federated re-authentication behaviour | 2 | n/a | No federation |
| 7.6.2 | Session creation requires explicit user action | 2 | met | A session exists only after a submitted sign-in form |

## V8 Authorization

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 8.1.1 | Documented function-level and data-specific rules | 1 | met | [Security Model](index.md#what-has-to-be-true-for-a-certificate-to-be-issued) states the four issuance gates; [Filters](../filters/index.md) specifies the policy engine; [Web Admin](../operations/webadmin.md#the-api) states that every route needs a session |
| 8.1.2 | Documented field-level rules | 2 | met | The ACME object shapes are RFC 8555's, and [Audit Trail](../operations/audit.md#what-gets-recorded) states which fields are recorded and that none of them reach an ACME object |
| 8.1.3 | Documented environmental and contextual attributes | 3 | met | Address, reverse name, IPAM ownership, request path and EAB identity are each documented under [Filters](../filters/checks.md), and the trust placed in a forwarded address under [Allowed IP](../filters/allowed_ip.md) |
| 8.1.4 | Documented use of contextual factors in decisions | 3 | met | The policy expression language, including how an `or` over an address check weakens a conjunction, is written out in [Hardening](hardening.md#an-or-is-a-hole-you-opened-deliberately) |
| 8.2.1 | Function-level access restricted to explicit permissions | 1 | met | ACME: `POST`-as-`GET` with a `kid` resolving to the owning account. Admin: three extractors every mutating route passes through |
| 8.2.2 | Data-specific access restricted (IDOR/BOLA) | 1 | met | Order, authorization and certificate reads check the requesting account owns the object; accounts and orders are additionally isolated **per profile**, so a `kid` naming another profile does not resolve (`src/extractors/acme.rs`) |
| 8.2.3 | Field-level access restricted (BOPLA) | 2 | met | Responses are built from explicit serializer functions, never by serializing a row |
| 8.2.4 | Adaptive controls from contextual attributes | 3 | met | The filter chain evaluates per request, not per session, so a change of address is re-evaluated on the next call |
| 8.3.1 | Authorization enforced at a trusted service layer | 1 | met | Extractors and middleware, server-side. No decision depends on anything the client sends unsigned |
| 8.3.2 | Authorization changes applied immediately | 3 | met | Sessions are reference tokens read from the database each request, so a disabled operator or a revoked session stops working on the next call. `filter reload` applies policy without a restart |
| 8.3.3 | Access based on the originating subject | 3 | partial | With the `relay` signer, one upstream account is deliberately multiplexed across every local client — that is the feature. The local gates decide, and the upstream sees only this server. See [Documented deviations](#documented-deviations) |
| 8.4.1 | Cross-tenant controls | 2 | met | Profiles are the tenancy boundary: accounts, orders, nonces and EAB credentials are scoped to one, and a `kid` from another profile fails the prefix check |
| 8.4.2 | Administrative access uses more than network location | 3 | partial | Password plus optional TOTP plus a session, with the bind address and TLS as further layers. There is no device posture assessment and no contextual risk analysis |

## V9 Self-contained Tokens

The self-contained token in this system is the **ACME JWS** on every
state-changing request (RFC 8555 §6.2), not a session JWT — the admin session
is a reference token and is assessed under V7.

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 9.1.1 | Signature validated before the contents are accepted | 1 | met | `verify_jws` verifies the signature over the protected header and payload before any handler sees the body (`src/extractors/acme.rs`, `src/extractors/signature.rs`) |
| 9.1.2 | Algorithm allowlist, no `none` | 1 | met | Exactly `ES256` on P-256 and `RS256` are accepted; anything else is `Unsupported algorithm`. The `alg` must additionally agree with the key type *and* the named curve, so `alg` alone never selects the verifier (`src/extractors/signature.rs`) |
| 9.1.3 | Key material from trusted pre-configured sources | 1 | met | A `kid` resolves to a stored account key whose URL prefix must match this profile's `base_url`; a `jwk` is the key being registered and is only ever trusted for `newAccount`/`revokeCert` as RFC 8555 §6.2 defines. `jwk` and `kid` together are refused, and a `crit` header is refused outright |
| 9.2.1 | Validity time span honoured | 1 | met | The equivalent is the nonce: single-use, and refused past `nonce.ttl_seconds`. Unknown, consumed and expired are made indistinguishable on purpose (`src/sqlite/nonce.rs`) |
| 9.2.2 | Token type checked against the intended purpose | 2 | met | The protected header must carry exactly the fields RFC 8555 §6.2 defines for the request kind; `newAccount` requires a `jwk`, everything else a `kid` |
| 9.2.3 | Audience restriction | 2 | met | The JWS `url` must equal `profile.base_url` plus the request path, byte for byte (RFC 8555 §6.4). A signature captured from one profile does not verify against another |
| 9.2.4 | Same key across audiences carries an audience restriction | 2 | met | Same mechanism: the audience is in the signed `url`, and the `kid` prefix pins the profile |

## V11 Cryptography

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 11.1.1 | Documented key management policy and lifecycle | 2 | partial | [Security Model](index.md#what-each-secret-protects) names every secret, what its compromise buys and how it is stored, and [Hardening](hardening.md#the-ca-key) covers the CA key specifically. What is not written down is a **rotation schedule** — see 13.1.4 |
| 11.1.2 | Cryptographic inventory maintained | 2 | met | The table in [Security Model](index.md#what-each-secret-protects), plus the per-algorithm rationale carried in the module docs of `src/admin/password.rs`, `src/admin/totp.rs` and `src/eab.rs` |
| 11.1.3 | Cryptographic discovery mechanisms | 3 | met | One backend: `ring`, plus `rustls` for TLS and `rcgen` for certificate construction. `grep -rn ring src/` is the discovery mechanism, and `cargo deny` fails the build on an unlisted crypto dependency |
| 11.1.4 | Inventory includes a post-quantum migration path | 3 | gap | No PQC migration plan. The ACME wire algorithms are RFC 8555's to change first |
| 11.2.1 | Industry-validated implementations | 2 | met | `ring` (BoringSSL-derived) for hashing, HMAC, PBKDF2, signature verification and the RNG; `rustls` for TLS. Nothing hand-rolls a primitive — `src/admin/totp.rs` composes `ring::hmac` per RFC 4226 and is checked against the RFC's published test vectors |
| 11.2.2 | Crypto agility | 2 | met | Password hashes are stored self-describing (`pbkdf2-sha256$600000$…`), so the algorithm or cost can change with a new branch in `verify_password` and `needs_rehash` re-encodes each row at its owner's next login — no migration. The signer backend, the CA key type and the key *source* (file or PKCS#11) are all configuration |
| 11.2.3 | Minimum 128 bits of security | 2 | partial | ECDSA P-256, SHA-256, HMAC-SHA-256 and 256-bit secrets are all at or above the bar. **RSA is accepted from 2048 bits** (`RSA_PKCS1_2048_8192_SHA256`), which is about 112 — see [Documented deviations](#documented-deviations) |
| 11.2.4 | Constant-time cryptographic operations | 3 | met | `ring::constant_time::verify_slices_are_equal` under the hood, and `subtle::ConstantTimeEq` for the TOTP comparison (`src/admin/totp.rs`) |
| 11.2.5 | Cryptographic modules fail securely | 3 | met | A verification failure is a refusal, never a fallback. A corrupt stored password hash is deliberately **not** folded into "wrong password" — it refuses and logs `admin_password_hash_unreadable` (`src/admin/users.rs`) |
| 11.3.1 | No insecure block modes or weak padding | 1 | partial | Nothing in the tree encrypts. `RS256` is RSASSA-PKCS1-v1_5, which RFC 8555 requires — a *signature* scheme, not the padding oracle this requirement targets. See [Documented deviations](#documented-deviations) |
| 11.3.2 | Only approved ciphers and modes | 1 | met | Transport encryption is `rustls` with safe defaults; the application encrypts nothing itself |
| 11.3.3 | Encrypted data protected against modification | 2 | n/a | No application-layer encryption |
| 11.3.4 | Single-use numbers not reused across key/data pairs | 3 | n/a | No application-layer encryption. ACME nonces are single-use by construction |
| 11.3.5 | Encrypt-then-MAC | 3 | n/a | No application-layer encryption |
| 11.4.1 | Approved hash functions | 1 | met | SHA-256 throughout. The one SHA-1 is `HMAC_SHA1_FOR_LEGACY_USE_ONLY` inside TOTP, which RFC 6238 §1.2 specifies and which every authenticator app assumes — the module doc in `src/admin/totp.rs` is the argument for not "fixing" it |
| 11.4.2 | Passwords stored with an approved, expensive KDF | 2 | met | PBKDF2-HMAC-SHA256 at 600 000 iterations with a 128-bit per-row salt — OWASP's current recommendation for the non-Argon2 case. See [Documented deviations](#documented-deviations) for why not Argon2id |
| 11.4.3 | Collision-resistant hashes of adequate length in signatures | 2 | met | SHA-256 for every signature and every integrity use. HMAC-SHA-1's security rests on the PRF property, not collision resistance |
| 11.4.4 | Approved KDF with key-stretching for password-derived keys | 2 | met | Same PBKDF2 parameters; recovery codes go through the identical path |
| 11.5.1 | Non-guessable values from a CSPRNG with ≥ 128 bits | 2 | met | Session tokens, CSRF tokens, EAB secrets, challenge tokens and ACME replay nonces are all 256 bits from `ring::rand::SystemRandom`, base64url-encoded, through the one `src/random.rs`. The nonce was a UUID v4 until 0.2.0 — 122 bits, and a form this requirement names explicitly |
| 11.5.2 | RNG works securely under heavy demand | 3 | met | `SystemRandom` draws from the OS CSPRNG; there is no userspace pool to exhaust |
| 11.6.1 | Approved algorithms for key generation and signatures | 2 | met | `rcgen` generates ECDSA P-256 by default; the accepted account-key algorithms are the two RFC 8555 defines. Key generation can be delegated to a PKCS#11 token, where the key never leaves the device |
| 11.6.2 | Approved key exchange with secure parameters | 3 | met | `rustls` with `with_safe_default_protocol_versions()`: TLS 1.2 and 1.3 only, and only its own vetted groups |
| 11.7.1 | Full memory encryption for data in use | 3 | n/a | A property of the host, not of this process |
| 11.7.2 | Data minimization during processing | 3 | partial | The CA key can live in a PKCS#11 token and never enter this process at all. EAB and TOTP secrets are necessarily readable, because both are verified by recomputing an HMAC — file mode is the boundary, and that is stated in [Security Model](index.md#what-each-secret-protects) |

## V12 Secure Communication

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 12.1.1 | Only current TLS versions, newest preferred | 1 | met | `with_safe_default_protocol_versions()` on the `rustls` ring provider — TLS 1.3 and 1.2 only (`src/tls.rs`) |
| 12.1.2 | Recommended cipher suites, forward secrecy for L3 | 2 | met | `rustls` ships no suite without forward secrecy and none that is not current; there is no knob to weaken it |
| 12.1.3 | mTLS client certificates validated before use | 2 | n/a | No mTLS. The one place a client certificate is inspected is `tls-alpn-01` validation, where the certificate *is* the challenge response and is checked for the RFC 8737 `acmeIdentifier` extension rather than for trust |
| 12.1.4 | Certificate revocation such as OCSP stapling | 3 | partial | As a **CA**, the server publishes a CRL with a JSON ledger as the authoritative record ([Revocation & CRL](../operations/revocation.md)). As a **TLS server** it does not staple |
| 12.1.5 | Encrypted Client Hello | 3 | gap | Not offered by `rustls` in a form this could adopt today |
| 12.2.1 | TLS for all client connectivity, no fallback | 1 | met | With `server.tls.enabled` the socket speaks TLS instead of cleartext; there is no downgrade path. HTTPS is on the [hardening checklist](hardening.md#before-it-serves-anything) for deployments that terminate elsewhere |
| 12.2.2 | Publicly trusted certificates on external services | 1 | n/a | This is an internal service by design; its clients trust the CA the operator installed |
| 12.3.1 | Encrypted protocols for all inbound and outbound connections | 2 | partial | The relay upstream, webhooks and IPAM are HTTPS. `http-01` validation is HTTP **because RFC 8555 §8.3 defines it that way**, and SQLite is a local file, not a connection |
| 12.3.2 | TLS clients validate certificates | 2 | met | The relay client validates against `webpki-roots` — there, the certificate is the only thing identifying the CA being handed your CSRs. The IPAM clients validate too; `insecure_skip_verify` exists, defaults off, and warns on **every** startup while on |
| 12.3.3 | TLS between internal HTTP services | 2 | met | Same set. The `http-01` exception above is the protocol's |
| 12.3.4 | Internal TLS uses trusted certificates | 2 | met | The IPAM clients take a `ca_bundle` so a NetBox behind an internal PKI is trusted specifically rather than by disabling verification (`src/config/types/ipam.rs`) |
| 12.3.5 | Strong mutual authentication between internal services | 3 | n/a | Single process; there are no intra-service hops |

## V13 Configuration

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 13.1.1 | All communication needs documented, including user-supplied destinations | 2 | met | [Security Model](index.md#where-this-server-can-be-made-to-talk-to-something-else) names all three outbound surfaces and says which of them a client can steer |
| 13.1.2 | Documented connection limits and behaviour at the limit | 3 | met | The SQLite pool size, the admission limiter's slots, its queue budget and its deadline are all in [Configuration Reference](../configuration/reference.md), and shedding at the limit is a `503` problem document |
| 13.1.3 | Documented resource-management strategy per external system | 3 | partial | Timeouts are documented per subsystem and every outbound call has one. **Retry policy** is documented for the job runner but not stated as a policy for the IPAM and webhook clients |
| 13.1.4 | Documented critical secrets and a rotation schedule | 3 | **gap** | The secrets are named and classified in [Security Model](index.md#what-each-secret-protects); no rotation schedule is given for any of them |
| 13.2.1 | Authenticated backend communication with non-shared credentials | 2 | partial | The relay upstream authenticates by account key and the IPAM clients by API token, both per-deployment. The database is a local file governed by file mode, not by a credential |
| 13.2.2 | Least privilege for backend accounts | 2 | partial | `custom` hooks run with `env_clear()`, a minimal `PATH`, a timeout and `kill_on_drop` (`src/script_hook.rs`); the systemd unit in [Deployment](../getting_started/deployment.md) runs as a dedicated `acme-proxy` user; the IPAM token needs read access only. The repository `Containerfile` sets **no `USER`** — see [Gaps](#gaps) |
| 13.2.3 | No default service credentials | 2 | met | Nothing ships with a credential. Every secret is either operator-supplied or generated on first start |
| 13.2.4 | Allowlist of external systems the application may contact | 2 | partial | The relay upstream, the IPAM host and the webhook URL are each a single configured destination — an allowlist of one. The `http-01` validator is the exception, and deliberately so |
| 13.2.5 | Server-level allowlist of destinations | 2 | partial | Same. The containment for `http-01` is scheme, port and hop count rather than destination |
| 13.2.6 | Documented per-connection configuration followed | 3 | met | Each client is built from its own configuration block at startup, so a broken setting stops the server rather than failing every later call |
| 13.3.1 | A secrets management solution; no secrets in source or artifacts | 2 | partial | No secret is in the source tree or the image. Every secret can come from the environment rather than the file, and the CA key can live in a **PKCS#11 token** — which is the L3 hardware-backed form. There is no vault integration, and the database necessarily holds EAB and TOTP secrets in retrievable form |
| 13.3.2 | Least privilege for secret access | 2 | met | Keys are created `0600` with `create_new` rather than chmod'ed afterwards (`src/pemfile.rs`); the database file mode is the documented boundary |
| 13.3.3 | Cryptographic operations inside an isolated security module | 3 | partial | Available but not required: `--features hsm` puts the issuing key in a PKCS#11 token, where it can be used and not copied ([Hardware Keys](../signers/local_ca_hsm.md)) |
| 13.3.4 | Secrets expire and rotate as documented | 3 | gap | Follows from 13.1.4. EAB credentials can be revoked without a restart; nothing expires on a schedule |
| 13.4.1 | No source-control metadata deployed | 1 | met | `.dockerignore` is an **allowlist** — `*` then `!Cargo.toml`, `!Cargo.lock`, `!src/`, `!migrations/` — so `.git` never enters the build context, and the final stage copies only the compiled binary |
| 13.4.2 | Debug modes disabled in production | 2 | met | Log level is configuration and defaults to `info`; there is no debug endpoint and no development mode. `challenge.bypass`, the one setting that genuinely weakens the server, is off by default and **warns on every startup** while on |
| 13.4.3 | No directory listings | 2 | met | Nothing is served from a directory. `tower-http`'s `fs` feature is off and static assets are a two-arm `match` |
| 13.4.4 | HTTP `TRACE` unsupported | 2 | met | Never routed; `axum` answers `405` |
| 13.4.5 | Documentation and monitoring endpoints not exposed unless intended | 2 | met | `/metrics` is a **separate listener**, off by default; `/health` is deliberately outside the filter chain and the hardening checklist tells operators not to forward it ([Monitoring](../operations/monitoring.md#health-checks)) |
| 13.4.6 | No detailed version information exposed | 3 | met | No `Server` header is set and no version appears in any response body |
| 13.4.7 | Web tier serves only specific extensions | 3 | met | The static allowlist is two filenames; everything else is a `404` |

## V14 Data Protection

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 14.1.1 | Sensitive data identified and classified | 2 | met | [Security Model](index.md#what-each-secret-protects) classifies every secret by what its compromise buys; [Database Schema](../dev/database.md#secrets-are-stored-three-different-ways-on-purpose) classifies each by the *form* it is stored in — one-way, retrievable, or never stored |
| 14.1.2 | Documented protection requirements per level | 2 | met | The same two pages, plus [Audit Trail](../operations/audit.md#retention) for retention |
| 14.2.1 | No sensitive data in URLs or query strings | 1 | met | The session token is in a cookie, the CSRF token in a header, the EAB secret in a response body shown once. No credential is ever a path or query parameter |
| 14.2.2 | Sensitive data not cached in server components | 2 | met | `Cache-Control: no-store` on every admin response — account contacts and a freshly minted EAB secret must not sit in a disk cache after the tab closes (`src/webadmin/mod.rs`) |
| 14.2.3 | Sensitive data not sent to untrusted parties | 2 | met | The only outbound payloads are the relay's own ACME traffic, a webhook to an operator-configured URL and IPAM lookups. No analytics, no third-party asset, no CDN |
| 14.2.4 | Documented controls implemented | 2 | met | Nonces and session tokens reach logs only as fingerprints (`src/sqlite/nonce.rs`, `src/sqlite/admin_session.rs`); proxy URLs are redacted before they are logged or `Debug`-formatted, pinned by `neither_debug_nor_redacted_leaks_the_password` (`src/proxy.rs`) |
| 14.2.5 | Caching only for expected content types (web cache deception) | 3 | met | `no-store` on the whole admin listener, and an unknown path returns a `404`, never a different valid file |
| 14.2.6 | Return the minimum sensitive data | 3 | met | An EAB secret is shown exactly once at creation; a session is displayed by the fingerprint of its token hash, never by the hash; `render_admin_session_json` is the one serializer |
| 14.2.7 | Retention classification and scheduled deletion | 3 | partial | `audit.retention_days` sweeps the trail and the job runner reaps nonces, expired sessions and stale orders. The default is `0` — keep everything — which is the right default for a trail whose value is that it is complete, and is a decision the operator is asked to make |
| 14.2.8 | Strip metadata from user-submitted files | 3 | n/a | No file uploads |
| 14.3.1 | Authenticated data cleared from client storage on termination | 1 | met | The panel keeps nothing in `localStorage` or `sessionStorage`; sign-out clears the cookie with a `Max-Age=0` `Set-Cookie` carrying the same attributes |
| 14.3.2 | Anti-caching response header fields | 2 | met | `Cache-Control: no-store` |
| 14.3.3 | No sensitive data in browser storage beyond session tokens | 2 | met | Only the session cookie exists |

## V15 Secure Coding and Architecture

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 15.1.1 | Documented remediation time frames for vulnerable components | 1 | partial | [Security Policy](https://github.com/acme-proxy/acme-proxy/blob/main/SECURITY.md) states that fixes land on `main` and in the next release, and `cargo deny` runs advisories on every CI run and on a schedule. No numeric time frame is committed to |
| 15.1.2 | An SBOM or equivalent inventory is maintained | 2 | **gap** | `Cargo.lock` is committed and `cargo deny check` gates licences, advisories and sources — but no SBOM artifact (CycloneDX or SPDX) is produced or published with a release |
| 15.1.3 | Documented resource-demanding functionality | 2 | met | The expensive paths are named and bounded: `http-01` and `dns-01` validation have timeouts, the PBKDF2 cost is documented as a denial-of-service lever with the limiter placed before it, and the admission limiter's shed-versus-queue reasoning is written out in `src/middlewares/admission.rs` |
| 15.1.4 | Risky third-party libraries highlighted | 3 | met | `deny.toml` is the allow list, run with `all-features = true`, and the rationale for *refusing* dependencies is recorded where the refusal was made — `src/admin/password.rs` on Argon2id, `TODO.md` on `webauthn-rs` |
| 15.1.5 | Dangerous functionality highlighted | 3 | met | [Security Model](index.md#where-this-server-can-be-made-to-talk-to-something-else) names the three request-forgery surfaces, and [Security Policy](https://github.com/acme-proxy/acme-proxy/blob/main/SECURITY.md) lists the behaviour that looks alarming and is deliberate |
| 15.2.1 | No components past the documented remediation window | 1 | met | The `Advisories, licenses & sources` CI job fails the build on a RUSTSEC advisory |
| 15.2.2 | Implemented defenses against availability loss | 2 | met | Admission limiter with a queue budget and a request deadline, body limits on both listeners, a login limiter ahead of the KDF, per-call timeouts on every outbound subsystem, and `kill_on_drop` on script hooks |
| 15.2.3 | Production contains no test or development functionality | 2 | met | Test helpers are `#[cfg(test)]` or behind `testutil`; there is no sample data, no seeded account and no development route |
| 15.2.4 | Dependencies from expected repositories | 3 | met | `cargo deny check sources` restricts registries, and `Cargo.lock` pins every transitive dependency by hash |
| 15.2.5 | Extra protection around dangerous functionality | 3 | met | Script hooks are the dangerous surface and run in a cleared environment with a minimal `PATH`, a deadline and `kill_on_drop`; the CA key can be moved into a PKCS#11 token; the [Containerfile](https://github.com/acme-proxy/acme-proxy/blob/main/Containerfile) is the network-isolation story |
| 15.3.1 | Return only the required subset of fields | 1 | met | Explicit serializers per resource; no row is serialized wholesale |
| 15.3.2 | Do not follow redirects unless intended | 2 | met | Intended, bounded and switchable: `follow_redirects` and `max_redirects` on the `http-01` validator, with scheme and port checked on every hop (`src/challenge/http_01.rs`) |
| 15.3.3 | Countermeasures against mass assignment | 2 | met | Request bodies deserialize into per-route structs holding only the fields that route accepts; nothing constructs a row from client JSON |
| 15.3.4 | Original client IP transferred correctly and used for decisions | 2 | met | `filter.trusted_proxies` is the allowlist of hops whose forwarded header is believed; empty means the header is ignored. The admin listener does none of this deliberately, so no caller can choose its own rate-limiter key (`src/filter/client_ip.rs`, `src/webadmin/session.rs`) |
| 15.3.5 | Explicit types and strict comparisons | 2 | met | Rust's type system; there is no coercion to juggle |
| 15.3.6 | JavaScript written to prevent prototype pollution | 2 | n/a | The panel ships no application JavaScript |
| 15.3.7 | Defenses against HTTP parameter pollution | 2 | met | `axum` extractors read from one named source per parameter — a path segment, a typed query struct, or a JSON body — never from a merged bag |
| 15.4.1 | Thread-safe access to shared objects | 3 | met | `Send`/`Sync` are checked at compile time; shared mutable state is behind `Mutex` or `Semaphore` (`LoginLimiter`, `Admission`) |
| 15.4.2 | State checks and dependent actions are atomic | 3 | met | The single-use idiom is one statement: `UPDATE … WHERE <still unused>` decided by `rows_affected`, never a read followed by a write. Key files are created with `create_new`, which is the atomic form of "exists?" then "create" |
| 15.4.3 | Consistent locking, contained in the owning code | 3 | met | Locks are held inside the type that owns the resource and never across an `await` |
| 15.4.4 | Resource allocation prevents starvation | 3 | met | The admission limiter refuses past its queue budget rather than queueing without bound — the reasoning for not using `GlobalConcurrencyLimitLayer` is written out in `src/middlewares/admission.rs` |

## V16 Security Logging and Error Handling

| # | Requirement | L | Status | Evidence |
| --- | --- | --- | --- | --- |
| 16.1.1 | A logging inventory exists | 2 | met | [Monitoring](../operations/monitoring.md#structured-events) enumerates every `event = "…"` name; [Audit Trail](../operations/audit.md) states what the trail records, where it lives, who can read it and how retention works |
| 16.2.1 | Log entries carry when, where, who, what | 2 | met | The access line carries method, URI, status, latency, client address, profile and a request id (`src/middlewares/access.rs`); an audit row carries actor, address, reverse name, identifiers, `User-Agent` and the same request id |
| 16.2.2 | Synchronized time sources; UTC or explicit offset | 2 | met | Timestamps come from the host clock as Unix seconds in the database and RFC 3339 in the log; host time sync is the operator's |
| 16.2.3 | Logs only go to documented destinations | 2 | met | One `tracing` subscriber built in one place — `prepare_logging` in `src/cli/logging.rs` — with `logging.target` naming the sink, so a reload cannot drift from startup |
| 16.2.4 | Logs readable by the log processor | 2 | met | `logging.json_format` produces one JSON object per line, with `flatten_event` for pipelines that want fields at the top level |
| 16.2.5 | Sensitive data logged according to its protection level | 2 | met | Nonces and session tokens appear only as fingerprints; proxy credentials are redacted; a password never enters a log or `argv` — `admin user passwd` reads from stdin or `--password-file` |
| 16.3.1 | All authentication operations logged | 2 | met | `admin_login_*`, `admin_mfa_verified`, `admin_mfa_attempts_exhausted`, `admin_logout` and `admin_password_hash_unreadable`, each with the outcome and the method used |
| 16.3.2 | Failed authorization attempts logged | 2 | met | Filter denials, `jws_url_mismatch`, `jws_jwk_and_kid_both_present`, `nonce_replayed` and the `*_failed` audit rows. `certificate_revoke_failed` is written *specifically* so a run of them is visible as somebody enumerating serials |
| 16.3.3 | Security events and control-bypass attempts logged | 2 | met | `challenge_validation_bypassed` and two other weakened-configuration warnings repeat on **every** startup so they cannot become background noise ([Hardening](hardening.md#ongoing)) |
| 16.3.4 | Unexpected errors and control failures logged | 2 | met | Backend, signer, DNS and IPAM failures each log with `outcome = "failure"` and their own event name |
| 16.4.1 | Logging components encode data to prevent log injection | 2 | met | JSON mode escapes structurally. In text mode the only client-controlled fields are the request URI, which `http::Uri` renders percent-encoded, and header values, which `HeaderValue::to_str` accepts only as visible ASCII — so a `User-Agent` carrying a control byte is dropped before it can be stored, let alone printed |
| 16.4.2 | Logs protected from unauthorized access and modification | 2 | met | The audit trail has **no foreign keys**, so deleting an account does not take its history; nothing in the panel can erase it — the audit surface is read-only and pruning is a host command ([Audit Trail](../operations/audit.md#why-it-survives-deletion)). The log stream itself is the operator's to protect |
| 16.4.3 | Logs transmitted to a logically separate system | 2 | partial | The server writes to stdout or a file in a format built for shipping, and [Monitoring](../operations/monitoring.md#logging) shows the pipeline — but shipping them is the deployment's job, not this process's |
| 16.5.1 | Generic message to the consumer on unexpected errors | 2 | met | Every ACME refusal is an RFC 8555 problem document with a fixed type; internal detail goes to the log and not the body. The `http-01` validator's fetched body is **never** echoed into a client-visible error, precisely because it is attacker-chosen |
| 16.5.2 | Secure operation when external resources fail | 2 | met | A check that cannot reach its authority answers *undecided* rather than "allow", so an IPAM outage degrades to a retryable `500` instead of failing open — the property [Filters](../filters/policy.md) is built around |
| 16.5.3 | Fail gracefully and securely; no fail-open | 2 | met | Startup **refuses** rather than degrading: a non-loopback `admin.bind_address` without TLS, an unknown challenge type, a deadline below `challenge.timeout_ms`. `tests/security.rs` is the regression set for the request-path equivalents |
| 16.5.4 | A last-resort handler for unhandled exceptions | 3 | gap | There is no `CatchPanicLayer`. A panic in a handler aborts that connection's task without a response; the process survives, and `panic = "abort"` is deliberately not set |

## Documented deviations

Places where this project has knowingly chosen differently from what ASVS
asks. Each was argued before this assessment existed; the assessment's job is
to surface them against the standard, not to reverse them.

**`http-01` validation does not block private addresses** — *V1.3.6, V13.2.4,
V13.2.5.* RFC 8555 requires following redirects, and Boulder's mitigation —
refusing RFC 1918 targets — cannot apply to a server whose entire purpose is
serving private networks. What contains it instead: only `http` and `https`,
only the two configured ports, at most `max_redirects` hops, a shared timeout,
an off switch, and the fetched body never being echoed into a client-visible
error. →
[HTTP-01](../challenges/http_01.md#redirects-are-an-ssrf-surface)

**`RS256` and RSA from 2048 bits** — *V11.2.3, V11.3.1.* RFC 8555 §6.2 names
`RS256` as an algorithm an ACME server must accept, and `RS256` is
RSASSA-PKCS1-v1_5. Refusing it would refuse conforming clients. Two things
soften it: this is a *signature* scheme, not the encryption padding V11.3.1
targets, and the key in question is a client's own account key, whose
compromise costs that client its account rather than costing the CA anything.
Raising the accepted floor to 3072 bits is a protocol-compatibility decision,
not a code change.

**PBKDF2-HMAC-SHA256 rather than Argon2id** — *V11.4.2.* Argon2id is the
stronger primitive. Adopting it would add four crates to a certificate
authority's dependency graph — all audited on every `cargo deny check`, which
runs with `all-features = true` — for a subsystem that is disabled by default
and whose password is the *bootstrap* credential in a design that ends in a
second factor. 600 000 iterations is OWASP's current recommendation for the
non-Argon2 case, and the stored form is self-describing so the trade can be
revisited without a migration. The argument is in the module doc of
`src/admin/password.rs`.

**`admin.require_mfa` defaults to `false`** — *V6.3.3.* Defaulting it on would
brick a panel whose first operator has not enrolled yet, with no way in to fix
it. The hardening checklist tells operators to turn it on, and the panel
supports a bootstrap flow where enrolment is the only thing a session can do.
An L2 claim for the web admin depends on the operator setting it. →
[Hardening](hardening.md#the-web-admin)

**No hardware-based authentication factor** — *V6.3.3 at L3.* WebAuthn was
investigated and deferred, and both blocking checks were actually run:
`webauthn-rs` 0.5.5 is MPL-2.0, which `deny.toml`'s allow list does not carry,
and `webauthn-rs-core` hard-depends on `openssl`, which this tree has avoided
at every turn. Nothing in the design precludes it — another factor kind is
another `MfaStep` variant, not a change to the state machine. It stays open in
`TODO.md`.

**The `relay` backend multiplexes one upstream account** — *V8.3.3.* One
upstream ACME account, and one centrally held RFC 2136 TSIG key, standing in
for every local client. That is the whole point of the backend: not
distributing a scarce credential is what it exists to do. Every authorization
decision is made locally, before the upstream is ever asked. →
[Relay](../signers/relay.md)

**Two listeners, usually two ports on one host** — *V3.5.4.* They are separate
sockets with separate TLS, separate authentication and separate defaults, and
the admin one binds loopback unless TLS is on. They are not separate
*hostnames*, and cookies are not port-scoped — which is exactly why the panel
does not rely on `SameSite` for CSRF and carries a per-session token plus an
`Origin` check instead. →
[Web Admin](../operations/webadmin.md#csrf)

**The audit trail is a record, not a control** — *V8.2.4.* Nothing in the
server compares a live request against the trail. Pinning an identity to an
address breaks CGNAT and mobile clients, and that is a deliberate
non-feature. It is stated as such in the
[Security Model](index.md#the-audit-trail-is-the-record-and-it-is-not-a-control).

## Gaps

Open shortfalls against the L1/L2 bar, worst first. Each is also an entry in
`TODO.md`.

**No SBOM** — *V15.1.2 (L2).* `Cargo.lock` pins everything and `cargo deny
check` gates advisories, licences and registries on every CI run — the
*substance* of the requirement is met. What is missing is the artifact: no
CycloneDX or SPDX document is generated or attached to a release, so a consumer
cannot answer "is this affected" without the tree.

**No documented secret rotation schedule** — *V13.1.4 (L3), reaching V11.1.1 at
L2.* Every secret is named and classified by what its compromise buys, and each
one *can* be rotated — EAB credentials without a restart, the CA key by
re-issuing an intermediate. What no page states is how often any of them
should be.

**Password change is host-only, and takes no current password** — *V6.2.2,
V6.2.3 (L1).* There is no self-service change in the panel, so an operator
without a shell cannot rotate their own password. `admin user passwd` answers
to a process that can already rewrite the database, so requiring the old
password there would add no authority — but any panel path that is added must
require it, and must go behind `check_step_up` like the second-factor routes.

**The container image runs as root** — *V13.2.2 (L2).* The repository
`Containerfile` sets no `USER`, so a container built from it runs the server as
uid 0 inside the namespace. The systemd path documented in
[Deployment](../getting_started/deployment.md) does the right thing — a
dedicated `acme-proxy` user — and the file's own header says it exists for the
e2e lab, but [Deployment](../getting_started/deployment.md) points container
users at it all the same. A `USER` directive and an ownership pass over the
data directory would close it.

**No notification on authentication events** — *V6.3.5, V6.3.7 (L3).* Every
attempt and every credential change is logged; nothing reaches the operator.
`src/notify/` exists but addresses certificate lifecycle, and an operator has
no contact address recorded anywhere.

**No last-resort panic handler** — *V16.5.4 (L3).* A panic in a handler drops
the connection without a response. The process survives and the panic is
logged, but the client sees a transport error rather than a problem document.

**Lower-priority L3 items**, recorded without a `TODO.md` entry: no CSP
violation-report endpoint (V3.4.7), no `Cross-Origin-Opener-Policy` (V3.4.8),
no documented behaviour for browsers lacking security features (V3.1.1,
V3.7.5), no OCSP stapling as a TLS server (V12.1.4), no Encrypted Client Hello
(V12.1.5), no post-quantum migration plan (V11.1.4), no multi-user approval for
issuance (V2.3.5), and `admin user passwd` letting the resetter learn the
password (V6.4.6).

## Re-running this

The requirement text is vendored at `rfc/asvs-5.0/`, so this page can be
re-derived against a later ASVS release by diffing the chapter files and
revisiting only the rows whose requirement text moved. The per-chapter tables
enumerate **every** in-scope requirement rather than only the failures for
exactly that reason: a list of gaps alone cannot be compared against anything.
