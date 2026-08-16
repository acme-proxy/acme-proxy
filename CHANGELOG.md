# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Compatibility

**Before 1.0.0, the database schema is the only compatibility guarantee.**
`migrations/` is append-only: a schema change is a new migration file, never an
edit to a committed one. Upgrading is therefore just starting the new binary
against the existing database — there is no dump/restore step, and no upgrade
procedure beyond replacing the binary.

Everything else may change in any release: configuration keys, profile names and
the ACME URLs derived from them, the admin JSON API, log event names, and the
CLI. That is deliberate — it is what lets the design keep improving instead of
carrying a compatibility layer for every shape it has ever had. In exchange:

- **Every such change is listed here**, under the release's `### Breaking`
  heading, with the old spelling and the new one.
- **A removed or renamed configuration key is refused by name at startup**
  wherever practical, so an unmigrated configuration stops the server instead of
  coming up looking configured. That refusal is a one-line error message, not a
  compatibility layer — there are no aliases, no dual syntax and no legacy
  lowering, and the refusals themselves go away at 1.0.0.

Read this section before an upgrade, and `acme-proxy filter show` builds a
`[filter]` policy exactly as startup does, so it is the cheapest way to check a
migrated configuration before restarting.

## [Unreleased]

### Breaking

- **`[filter]` is now a policy of named checks and boolean rules, and every key
  of the old shape is gone.** The flat all-must-pass chain could not express
  "this address is in the management network **or** the inventory confirms it
  owns the name": everything was AND, there was one instance per type, and the
  two-valued verdict could not tell "policy says no" from "I could not decide",
  so an `or` over an IPAM check would either refuse every request during an
  outage or quietly admit every request during one.

  Each filter is now a `[filter.check.<name>]` with a `type`, each rule a
  `[filter.rule.<name>]` whose `when` is a boolean expression over check names,
  and `filter.rules` lists the rules to evaluate in order. Two checks of one
  type are ordinary; `custom` is a type like any other.

  Migration, key by key:

  | Removed | Replacement |
  | --- | --- |
  | `filter.enabled` | a check per filter, a rule naming them, listed in `filter.rules` |
  | `filter.exempt_paths` | a `type = "path"` check plus a rule |
  | `filter.custom_enabled` | nothing — `filter.rules` already orders them |
  | `[filter.allowed_ip]`, `[filter.reverse_dns]`, `[filter.identifiers]`, `[filter.custom.<name>]` | the type's keys move onto its `[filter.check.<name>]` |

  Every one of them is **refused by name at startup**, from a file or the
  environment, so an unmigrated configuration stops the server rather than
  coming up looking configured and filtering nothing. `acme-proxy filter show`
  builds the policy exactly as startup does, so it is the cheapest way to check
  a migration before restarting.

  `allow`/`deny` on the name-matching checks now take **globs** (`*` is one
  label); the anchored regexes moved to `allow_regex`/`deny_regex` and union
  with them. Regex was the biggest footgun in this section and is no longer the
  only spelling.

  There is no compatibility path, which is the standing pre-1.0 rule rather
  than a judgement about this section: a removed key is deleted and refused by
  name, never aliased. No legacy lowering, no dual syntax, nothing to keep
  tested for ever.

- **The `netbox` filter is now the `ipam` check, and `[filter.netbox]` is now
  `[ipam]`.** Asking an inventory "which names does this address own?" is one
  question, and welding it to one vendor's REST API meant a second inventory
  could only ever arrive as a second filter with its own copy of the policy.
  The question now lives in its own subsystem with two backends, `netbox` and
  `phpipam`, and the filter is the thin consumer that turns an answer into a
  verdict. To migrate:

  - a `[filter.check.<name>]` with `type = "netbox"` becomes `type = "ipam"`.
  - `[filter.netbox]` becomes `[ipam.netbox]`, and the backend is selected with
    `ipam.backend = "netbox"`.
  - `filter.netbox.timeout_ms` becomes `ipam.timeout_ms` — the budget covers a
    whole lookup however many requests a backend makes of it.
  - `ACME_PROXY_FILTER__NETBOX__*` becomes `ACME_PROXY_IPAM__NETBOX__*`.

  `type = "netbox"` is refused at startup with an error naming all three moves.
  The section moved as well as the name, so a silent alias would have left
  `[filter.netbox]` read by nothing while the server came up looking configured.

- **`request_blocked` is now `filter_request_blocked`**, the one event in the
  subsystem that lacked its prefix. `filter_denied` and `filter_failed` keep
  their names and gain a `check` field carrying the *instance* name, so three
  `custom` scripts are finally distinguishable from one another.

- **The structured-logging vocabulary is normalized, and every record now
  carries an `outcome` field.** Log records are an operator contract — the
  monitoring page tells you to alert on `event`, and ~450 names had drifted far
  enough that the advice no longer worked. Two call sites *computed* `event`
  instead of writing a literal, so neither spelling could be grepped back to
  its source; ~24 names carried no subsystem prefix; nine concepts were spelled
  two ways, three of them inside a single file (`authorization_*` beside
  `authz_*` eleven lines apart); and `payload_length` meant base64 characters at
  one call site and decoded bytes eight lines below, which made any threshold
  set on it meaningless.

  Nothing here fails at startup — a log line has nothing to refuse — so **this
  is the one breaking change in this release that is silent**. Alerting rules,
  saved searches and log-pipeline field mappings need updating by hand.

  **New: `outcome`.** Every record carries `outcome = "success"`, `"failure"`,
  `"progress"` or `"advisory"` directly after `event`. This is what
  `audit_log.outcome` already does for the audit trail, for the same reason:
  failure is spelled a dozen ways across the event names (`_failed`, but also
  `_invalid`, `_mismatch`, `_missing`, `_unauthorized`, `_rejected`), so
  `event LIKE '%_failed'` silently missed most of it. **`outcome = "failure"`
  is now the one query that catches everything that broke.** `progress` marks a
  `_started`/`_requested` line whose result is not yet known; `advisory` marks a
  `warn` where nothing failed (`tls_disabled`,
  `challenge_validation_bypassed`), so it stays separable from real breakage.

  **Every event emitted from the storage layer is now `db_`-prefixed** — 93
  names, mechanically (`account_deleted` → `db_account_deleted`,
  `admin_user_created` → `db_admin_user_created`, and so on for everything
  under `src/sqlite/`). The prefix marks the layer; the level is unchanged, so
  what was `info` is still `info`.

  **The remaining 68 renames**, which are the ones worth reading:

  | `account_lookup_during_kid_verification` | `jws_kid_account_lookup_failed` |
  | `ari_cert_id_underivable` | `upstream_renewal_info_cert_id_underivable` |
  | `attempt_to_modify_deactivated_account` | `account_deactivated_modify_refused` |
  | `authorization_already_deactivated` | `authz_already_deactivated` |
  | `authorization_deactivated` | `authz_deactivated` |
  | `authorization_expired` | `authz_expired` |
  | `authorization_lookup_requested` | `authz_lookup_requested` |
  | `cert_revoked` | `certificate_revoked` |
  | `certificate_revoked` | `local_ca_certificate_revoked` |
  | `deactivated_account_request` | `account_deactivated_request_refused` |
  | `directory_endpoint_requested` | `directory_requested` |
  | `dns01_cleanup_failed` | `signer_relay_dns_01_cleanup_failed` |
  | `dns_update_truncated_retrying_tcp` | `signer_relay_dns_01_update_truncated` |
  | `filters_disabled` | `filter_disabled` |
  | `filters_enabled` | `filter_enabled` |
  | `finalize_chain_unparsable` | `order_finalize_chain_unparsable` |
  | `finalize_leaf_unparsable` | `order_finalize_leaf_unparsable` |
  | `finalize_order_not_ready` | `order_finalize_not_ready` |
  | `health_check_requested` | `server_health_requested` |
  | `http01_responder_mounted` | `http_01_responder_mounted` |
  | `http01_responder_served` | `http_01_responder_served` |
  | `http01_responder_unknown_token` | `http_01_responder_unknown_token` |
  | `index_link_header_invalid` | `request_index_link_header_invalid` |
  | `jwk_and_kid_both_present` | `jws_jwk_and_kid_both_present` |
  | `leaf_issued` | `local_ca_leaf_issued` |
  | `leaf_signing_failed` | `local_ca_leaf_signing_failed` |
  | `leaf_signing_panicked` | `local_ca_leaf_signing_panicked` |
  | `malformed_identifier` | `order_identifier_malformed` |
  | `missing_jwk_and_kid` | `jws_jwk_and_kid_missing` |
  | `new_account_request` | `account_creation_requested` |
  | `new_nonce_get_requested` | `nonce_new_get_requested` |
  | `new_nonce_head_requested` | `nonce_new_head_requested` |
  | `new_nonce_post_requested` | `nonce_new_post_requested` |
  | `only_return_existing_lookup_failed` | `account_only_return_existing_lookup_failed` |
  | `only_return_existing_miss` | `account_only_return_existing_miss` |
  | `post_as_get_payload_not_empty` | `jws_post_as_get_payload_not_empty` |
  | `profiles_init_failed` | `profile_init_failed` |
  | `requested_validity_discarded` | `local_ca_requested_validity_discarded` |
  | `reverse_dns_accepted` | `filter_reverse_dns_accepted` |
  | `reverse_dns_candidate_refused` | `filter_reverse_dns_candidate_refused` |
  | `revoke_cert_account_lookup_failed` | `certificate_revoke_account_lookup_failed` |
  | `revoke_cert_already_revoked` | `certificate_revoke_already_revoked` |
  | `revoke_cert_bad_reason` | `certificate_revoke_bad_reason` |
  | `revoke_cert_base64_invalid` | `certificate_revoke_base64_invalid` |
  | `revoke_cert_lookup_failed` | `certificate_revoke_lookup_failed` |
  | `revoke_cert_parse_failed` | `certificate_revoke_parse_failed` |
  | `revoke_cert_persist_failed` | `certificate_revoke_persist_failed` |
  | `revoke_cert_requested` | `certificate_revoke_requested` |
  | `revoke_cert_signer_failed` | `certificate_revoke_signer_failed` |
  | `revoke_cert_unauthorized` | `certificate_revoke_unauthorized` |
  | `revoke_cert_unknown_certificate` | `certificate_revoke_unknown_certificate` |
  | `serial_generation_failed` | `local_ca_serial_generation_failed` |
  | `signature_algorithm_unsupported` | `jws_signature_algorithm_unsupported` |
  | `signature_encoding_error` | `jws_signature_encoding_failed` |
  | `signature_verification_failed` | `jws_signature_verification_failed` |
  | `signature_verification_malformed` | `jws_signature_malformed` |
  | `signer_relay_http01_selected` | `signer_relay_http_01_selected` |
  | `socket_bind_failed` | `server_socket_bind_failed` |
  | `startup_admin_session_cleanup_failed` | `admin_session_cleanup_failed` |
  | `startup_nonce_cleanup_failed` | `nonce_cleanup_failed` |
  | `terms_of_service_not_agreed` | `account_terms_not_agreed` |
  | `thumbprint_failed` | `authz_thumbprint_failed` |
  | `unsupported_identifier_type` | `order_identifier_type_unsupported` |
  | `upstream_relays_batch_capped` | `upstream_relay_batch_capped` |
  | `upstream_relays_resuming` | `upstream_relay_resume_started` |
  | `verifying_jwk_signature` | `jws_jwk_verification_started` |
  | `verifying_kid_signature` | `jws_kid_verification_started` |
  | `wildcard_identifier_rejected` | `order_identifier_wildcard_rejected` |

  Two further changes that are not renames:

  - `startup_nonce_cleanup_completed` is **removed**. It duplicated
    `db_nonce_cleanup_completed`, which is emitted from the sweep itself.
  - Three events that shared one name now carry a discriminator rather than
    colliding: `db_admin_sessions_revoked` gains
    `scope = "user" | "user_except_current" | "all"` (replacing a magic
    `user_id = "*"`), and the seven admin actions reachable from both the JSON
    API and the HTML panel gain `surface = "api" | "ui"`.

  **Field renames**, for the same "one name, one meaning" reason:

  | Old | New | Why |
  | --- | --- | --- |
  | `payload_length`, `protected_length` | `*_bytes` / `*_b64_chars` | one name meant both the encoded and the decoded size |
  | `body_length`, `signature_size`, `certificate_length` | `*_bytes` / `*_b64_chars` | a size field says which unit it is in |
  | `removed`, `deleted` | `rows_removed` | one spelling for a delete count |
  | `pubkey_hash` | `pubkey_fp` | `*_fp` for every fingerprint |
  | `session` | `session_fp` | as above |
  | `nonce` | `nonce_fp` | as above |
  | `id` (admin user) | `user_id` | the name the other 21 sites already used |
  | `serial` | `cert_serial` | as above; `cert_id` stays RFC 9773's ARI certID |
  | `url` (database, upstream, IPAM, challenge probe) | `database_url`, `upstream_url`, `backend_url`, `probe_url` | `url` is now the JWS `url` header alone |
  | `path` (filesystem) | `file_path` | `path` is the HTTP request path alone |

  `server_startup` is deliberately **not** renamed: `tests/e2e/common.rs` gates
  container readiness on it, so a change there fails as a start timeout rather
  than an assertion, and it already followed the convention.

  All nine rules are now enforced by `tests/logging_convention.rs`, which walks
  `src/` and fails CI on a stray call site — including one check that reaches
  outside the crate, asserting that every event
  `doc/src/operations/monitoring.md` names is still emitted. That check found a
  pre-existing bug on its first run: the page documented
  `admin_login_rate_limited`, which nothing has ever emitted.

- **The `acme_proxy` signer backend is now `relay`.** It shared its name with
  the program that hosts it — the binary, the crate, the `ACME_PROXY_*`
  environment prefix and the default log filter are all `acme-proxy` — which
  made `ACME_PROXY_SIGNER__ACME_PROXY__DNS01__RFC2136__TSIG_KEY_SECRET` spell
  the application's name twice for two different things, and left the
  documentation glossing the page title as "ACME Proxy (Relay)" to say which
  one it meant. `relay` is what the code and the prose already called it. To
  migrate:

  - `signer.backend = "acme_proxy"` becomes `signer.backend = "relay"`.
  - `[signer.acme_proxy]`, `[signer.acme_proxy.eab]`,
    `[signer.acme_proxy.dns01]` and `[signer.acme_proxy.dns01.rfc2136]` become
    `[signer.relay]`, `[signer.relay.eab]`, `[signer.relay.dns01]` and
    `[signer.relay.dns01.rfc2136]`.
  - `ACME_PROXY_SIGNER__ACME_PROXY__*` becomes `ACME_PROXY_SIGNER__RELAY__*`.

  Neither half fails silently. The old `backend` value is refused at startup
  with an error naming its replacement and both env-var prefixes; a
  configuration that renames `backend` but leaves the table behind is refused
  by the existing "directory_url is empty" check, because the stale table is no
  longer read. `acme-proxy upstream show|register` is unchanged — it acts on
  the upstream account, which keeps its own word.

  The two startup log events `signer_acme_proxy_eab_secret_in_config` and
  `signer_acme_proxy_http01_selected` are renamed to `signer_relay_*`, and the
  three tracing spans `acme_proxy_{issue,revoke,renewal_info}` to `relay_*` —
  relevant if you alert or grep on them. No database, ACME wire format or CLI
  surface changes; `upstream_orders` and `upstream_account.key` keep their
  names, which were already about the far side rather than the backend.



- **A `[proxy]` section: every outbound HTTP request can now go through a
  forward proxy.** Three keys — `http_url`, `https_url` and `no_proxy` — and
  they govern the upstream CA the `relay` signer talks to, the IPAM inventory,
  the Mattermost webhook, and both network-touching challenge validators. An
  `https://` target is reached by a `CONNECT` tunnel and an `http://` one is
  forwarded (absolute-form request line plus `Proxy-Authorization`);
  `tls-alpn-01`'s raw TLS probe is tunnelled too, since a `CONNECT` tunnel is
  transparent under TLS.

  Each key falls back to its conventional environment variable when left empty:
  `http_url` to `$http_proxy`, `https_url` to `$https_proxy` then
  `$HTTPS_PROXY`, `no_proxy` to `$no_proxy` then `$NO_PROXY`. Uppercase
  `HTTP_PROXY` is **deliberately not read** — under CGI a client-supplied
  `Proxy:` header arrives in the environment under exactly that name (httpoxy,
  CVE-2016-5385), and while this server is never a CGI process, Go's `net/http`
  dropped the variable for the same reason and matching it costs nothing.

  Loopback and `localhost` bypass unconditionally, before `no_proxy` is
  consulted: an inherited shell `http_proxy` must not route this server's own
  loopback traffic through a corporate proxy. A configured but unreachable proxy
  is an error every time — there is no fallback to a direct connection, since
  dialling around a controlled egress path exactly when the control fails is the
  opposite of what the setting is for.

  **Not everything outbound**: SMTP (`notify.email`, via `lettre`) and the
  RFC 2136 DNS updates `signer.relay.dns01` makes are not HTTP, dial directly,
  and are documented as doing so. An estate whose egress is proxy-only needs a
  separate route for those two. `filter` is untouched — `reverse_dns` is DNS,
  the `ipam` filter receives an already-built inventory client, and `custom`
  shells out.

- `doc/lint.py`, a style and link gate for the book, run by a new **docs** CI
  job that builds the book on pull requests — the deploy workflow only ran after
  merge, so a broken `SUMMARY.md` entry was previously found too late.

- **`SignerBackend::resume` is gone, replaced by `SignerBackend::jobs`.** The
  old hook took no arguments, returned nothing, and each asynchronous backend
  implemented it by re-spawning its own `tokio` tasks at startup. A backend now
  *registers job handlers* instead, and recovery is one case of a queue rather
  than a mechanism of its own — see `JobHandler::recover`, which is where that
  logic went. This is a Rust API change with no configuration surface; nothing
  an operator writes down mentions either name.

  `MAX_CONCURRENT_RELAYS`, a constant inside the `relay` backend that capped
  concurrent upstream polling at 8, is likewise gone. The number and its
  reasoning moved to `jobs.max_concurrent`, which has the same default and now
  governs every kind of background work rather than that one backend's.

- **The `mattermost` notify backend is replaced by a generic `webhook` one.**
  It was one provider's payload shape (`{"text", "channel", "username"}`)
  frozen into a copy of the outbound HTTP transport — and every other part of
  it, the TLS stack, the proxy, the resolver, the timeout and the
  retryable/permanent status split, had nothing to do with Mattermost. Slack,
  Microsoft Teams, Google Chat, Telegram and Matrix differ from it in a URL, a
  verb, a header and a JSON shape, so the way to support them is to make those
  four configurable, not to write four more backends.

  `[notify.webhook.<name>]` entries are **named**, selected and ordered by
  `notify.webhook_enabled`, exactly like `[notify.custom]` — so one profile can
  post to Slack and an on-call room at once, and each is retried independently.

  Migration, key by key:

  | Removed | Replacement |
  | --- | --- |
  | `notify.enabled = ["mattermost"]` | `notify.enabled = ["webhook"]` plus `notify.webhook_enabled = ["<name>"]` |
  | `notify.mattermost.webhook_url` | `notify.webhook.<name>.url` |
  | `notify.mattermost.channel`, `.username` | members of `notify.webhook.<name>.body` |
  | `notify.mattermost.events`, `.timeout_ms` | `notify.webhook.<name>.events`, `.timeout_ms` |
  | `mattermost/<event>.j2` template overrides | `webhook/<event>.j2` |

  `notify.enabled = ["mattermost"]` is **refused by name at startup**, naming
  `[notify.webhook]` and the default `body`, so an unmigrated configuration
  stops the server rather than coming up looking configured and notifying
  nobody. The default `body` is `{"text": {{ message | tojson }}}` — the
  payload Mattermost, Slack, Teams and Google Chat all accept — so the common
  case is a `url` and nothing else.

  Two things worth knowing beyond a rename. The embedded message templates that
  moved to `webhook/` lost their `:lock:`-style emoji shortcodes and Markdown
  emphasis: they now feed any provider, and those render as literal noise in
  Telegram, Matrix and Teams. And a `body` template needs `| tojson` around
  anything holding text — `.j2` auto-escaping is off, deliberately, so an error
  message carrying a quote would otherwise produce a payload the provider
  answers `400` to. Both are covered in
  [Webhook Notifications](doc/src/notifications/webhook.md).

  A `notify_deliver` job queued for `mattermost` before the upgrade needs no
  migration: an unknown backend id already retires the row rather than retrying
  it for ever.

### Added

- **A durable job queue, and with it retries for relayed issuance.** The
  `relay` signer backend used to finish its work in a bare `tokio::spawn` whose
  state lived on its `upstream_orders` row: a restart destroyed the task, and a
  startup sweep re-created it from scratch. That bought *recovery* but never
  *retry* — with nowhere to record that an attempt had failed and should happen
  again, every failure had to be terminal, so a five-second upstream blip
  marked the client's order `invalid` and left them to place a new one.

  Background work is now a row in a new `jobs` table, drained by one runner per
  process (`[jobs]`, `src/jobs/`). The practical differences:

  - **A transient upstream failure is retried** with exponential backoff — a
    TCP reset mid-poll, a nameserver hiccup, a 503, a rate limit, an attempt
    that ran out of time. The order stays `processing` throughout and only
    reaches `invalid` once the attempts or its own `expires` run out.
  - **A CA that states a reason is still believed on the first attempt.** A
    rejected challenge, a refused identifier or an unparsable chain fails
    immediately rather than spending a budget it could never use.
  - **A crashed process no longer needs a restart to recover.** Each claim
    takes a lease, and a lease that expires returns the row to the queue.
  - **A graceful shutdown releases its leases**, so a restart re-claims its own
    work immediately instead of waiting one out.

  The queue is generic: `jobs.retention_days`'s own sweep is the first
  non-signer handler, and it is a self-rescheduling job rather than a fourth
  reaper. Nothing about the ACME wire format changes, and `upstream_orders`
  keeps every column it had.

- **Issued leaves can now say where this CA's CRL and certificate live.** Two
  keys under `[signer.local_ca]`: `crl_distribution_points` writes
  `cRLDistributionPoints` (RFC 5280 §4.2.1.13) into every leaf, and
  `ca_issuer_urls` writes `authorityInfoAccess` with the `caIssuers` access
  method (§4.2.2.1). Both are empty by default, in which case neither extension
  is emitted and a certificate is byte-for-byte what this CA issued before —
  which is also the state every existing deployment stays in until it opts in.

  The URLs are the operator's to name, not derived from `server.base_url`. A
  derived value would be frozen into every certificate signed while it held,
  and would silently stop resolving the day a `base_url` or a profile name
  changed. It would also point at `{base_url}/profile/<name>/crl`, which is
  served *inside* the profile router and therefore behind that profile's filter
  policy — refused to exactly the relying parties the extension exists for.

  Several `crl_distribution_points` entries mean one CRL reachable in several
  places, not several CRLs. Credentials in a URL, a non-`http(s)` scheme, and
  anything the URL parser would normalize (a missing trailing `/`, or the
  leading space an environment list written `a, b` produces) are each a startup
  error naming the key and the value — these are signed into certificates that
  outlive the mistake by `leaf_validity_days`. No OCSP pointer is ever written:
  this server runs no responder.

- **An `eab` check binds names to a tenant.** An EAB credential is minted
  before any account exists and its label is chosen by the operator, so it is a
  handle configuration can name up front — unlike an account id, which is a
  UUID you could only discover after the fact. `kids` pins a credential by id;
  `require_active` makes `eab revoke` reach accounts already registered under
  it, which it does not by default. No schema change: `accounts.eab_kid` has
  recorded this since EAB was implemented.

- **A `path` check**, replacing `filter.exempt_paths` and composing with the
  rest of a policy. It can restrict a path to a network, and it globs, so
  `/renewalInfo/*` is expressible where the exact-match list it replaces could
  not. Worth knowing: `/crl` is served by the profile router, so an
  address-based policy without a path rule silently breaks revocation checking
  for every relying party outside the allowlist.

- **`acme-proxy filter show` and `acme-proxy filter explain`.** `show` prints
  the resolved policy with each condition re-parenthesized, so precedence is
  visible rather than inferred. `explain` evaluates it against a hypothetical
  request across all three stages and reports every check's verdict, the checks
  short-circuited past, and the HTTP answer. It really runs the policy, scripts
  and inventory lookups included, and names what reached outside the process.

- **`mode = "warn"` on a rule** logs `filter_rule_warned` and does not decide,
  so a tightened policy can be watched in production before it bites. Rules are
  a map rather than an array of tables precisely so a profile can dry-run one
  of them and inherit the rest.

### Changed

- **Notifications are durable, and a failed delivery is retried.** Delivery used
  to be a bare `tokio::spawn`: a refused SMTP connection, a 503 from a webhook or
  a script that exited non-zero was logged once and the notification was gone,
  and a restart lost everything in flight. The only mitigation was a best-effort
  five-second drain at shutdown, which still lost anything slower than the
  budget. Each delivery is now a `notify_deliver` row on the durable queue, so it
  survives the process that wrote it and comes back under `jobs.max_attempts` and
  the shared backoff. Three details are worth knowing:

  - **One row per backend per event**, not one per event, so retrying a flaky
    webhook never re-sends through an email backend that already delivered.
  - **A failure that could never have worked is not retried.** A template that
    does not render, a `webhook_url` that does not parse and any webhook 4xx
    other than 408/429 are refused on the first attempt; transport failures,
    5xx, 429 and 408 go back in the queue. A `custom` script's exit code carries
    no way to say "never retry", so its failures are always retryable.
  - **A lost notification now says so**, once, as `notify_delivery_abandoned` —
    the line to alert on. `notify_delivery_failed` gained a `retryable` field
    and, on its own, usually just means a bad minute.

  No configuration changed: the retry budget is `[jobs]`, which already existed.
  The shutdown drain is gone, along with its five-second bound — there is
  nothing left to drain.

- **The nonce, audit-retention and admin-session sweeps run on the job queue**,
  as `nonce_sweep`, `audit_sweep` and `admin_session_sweep`, joining the
  `job_retention_sweep` that already did. Each was its own `tokio::spawn` +
  `tokio::time::interval` loop and a near-copy of the other two. Three things
  follow: a sweep whose task died is now reclaimed by lease expiry rather than
  being silently gone until the next restart; the schedule survives a restart, so
  a server restarting more often than once a day no longer skips the daily sweeps
  for ever; and there is one answer in the process to "run this every N seconds"
  rather than two. The intervals, the log event names
  (`nonce_reaper_swept`, `audit_reaper_swept`, `admin_session_reaper_swept` and
  their `_failed` twins) and the conditions under which each is scheduled are all
  unchanged. What is new is a dependency: the sweeps stop if the job runner does,
  so `job_runner_started` is now worth watching for.

- The `relay` signer's upstream client and the Mattermost notifier now send an
  **origin-form** request line (`GET /path`) on a direct connection, where both
  previously sent absolute-form unconditionally. RFC 9112 §3.2.1 reserves
  absolute-form for requests *to a proxy*, so this is the conformant direction;
  both already set `Host` explicitly, so nothing routes differently. Absolute
  form is still used, and only used, when a proxy is forwarding the request.
- `Cargo.toml` declares `description`, `repository`, `documentation`, `homepage`,
  `readme`, `keywords` and `categories`, and a `docs.rs` block building with all
  features, so the PKCS#11 module is documented rather than absent.
- Crate-level and module-level rustdoc: the module map now covers the web admin,
  the audit trail and the CLI, and the six modules that had no `//!` at all —
  `handlers`, `extractors`, `sqlite`, `admin`, `middlewares`, `cli` — have one.
  The `notify` payload structs, a plugin-facing data contract, are documented.

### Fixed

- An `https://[2001:db8::1]/…` URL never connected. `Url::host_str` hands back
  the *bracketed* literal, which `IpAddr::from_str` rejects, so the connect path
  handed it to the resolver as if it were a name. The brackets are now stripped
  for the lookup and kept for the `Host` header and the request line, where they
  belong.
- Two French comments in `src/handlers/helpers.rs`, contrary to the project's
  stated English-only rule.
- The `### Reference` entries throughout the book depended on invisible trailing
  double-spaces for their line breaks, which an editor trimming on save would
  have silently broken — and had already broken in twelve places. They are now a
  single line that cannot break that way.
- Several run-on paragraphs in the troubleshooting guide, where
  `Symptoms`/`Cause`/`Fix` lines were rendering joined into one block.
- `mdbook.yml` pinned `mdbook-version: latest` and installed `mdbook-mermaid`
  from source; both tools are now version-pinned, and every action in that
  workflow is SHA-pinned like `ci.yml`'s.

### Documentation

- Four new chapters: **Protocol Support** (an RFC 8555 conformance summary and
  what is deliberately not implemented), **Security Model** and **Hardening
  Checklist**, and **Database Schema** — the eleven tables, their constraints,
  and why `audit_log` deliberately has no foreign keys.
- Fourteen diagrams where prose was carrying branching, positional or state
  facts: the JWS verification pipeline, the order and authorization state
  machines, the relay's two stacked ACME conversations, the filter hooks on the
  request path, the MFA sign-in states, deployment topology, and an ER diagram
  of the schema.
- `[challenge]`'s keys were documented both in the configuration reference and
  in the challenges chapter, and the two copies had drifted. The chapter now
  owns them, and the reference carries an index of **every** section — with the
  seven that a `[profiles.<name>]` block may override marked as such, a fact
  that had not been written down anywhere.
- One voice across the book: sentence-case headings, no numbered headings for
  unordered content, 80-column prose, and no marketing register.
- `config.toml.example` gained a section index and per-section markers for what
  is overridable per profile.
- `CONTRIBUTING.md` and `SECURITY.md`, issue and pull-request templates, README
  badges, a container install path and the MSRV stated numerically.

## [0.1.0] — 2026-08-09

First release.

### The compatibility promise

The schema freeze starts here: `migrations/` is append-only from this release
on. See [Compatibility](#compatibility) above for the standing rule and what it
does *not* cover.

### ACME (RFC 8555)

- The full flow: `newNonce`, `newAccount`, `newOrder`, authorizations,
  challenges, `finalize`, certificate retrieval, and `POST`-as-`GET` throughout.
- Certificate revocation (§7.6), authorized by either the order's account key or
  the certificate's own key pair.
- Account management: contact updates, deactivation, and find-or-create by public
  key.
- Authorization deactivation (§7.5.2).
- Problem documents (`application/problem+json`) for every refusal, with
  `subproblems` on multi-identifier rejections (§6.7.1).
- Directory `meta` members, including a terms-of-service requirement that
  `newAccount` then enforces (§7.3.3).

### Extensions

- **External Account Binding** (§7.3.4) — credentials minted out of band, stored
  in the database and revocable without a restart.
- **Key rollover** (§7.3.5).
- **Renewal Information / ARI** (RFC 9773) — renewal windows, `explanationURL`
  passthrough, and `replaces` on `newOrder`.

### Challenge validation

- `http-01`, `dns-01` and `tls-alpn-01`, selectable per profile, validated inline
  under a configurable timeout.
- Wildcard identifiers, accepted only where `dns-01` is enabled.
- Validation is **on by default**; `challenge.bypass` turns it off for testing.

### Signer backends

- `local_ca` — an embedded CA that generates itself on first run, issues leaves,
  and publishes an RFC 5280 CRL at `GET /crl`. The issuing key may live in a
  **PKCS#11 token** (`--features hsm`).
- `acme_proxy` — relays to a real upstream ACME CA, solving the upstream's
  challenges itself via RFC 2136 dns-01, an http-01 responder, or bypass. One
  upstream account multiplexed across every local client.
- `custom` — delegates issuance and revocation to an operator-supplied script.

### Access control

- Pluggable filters, off by default: `allowed_ip`, `reverse_dns`, `identifiers`,
  `netbox` (IPAM-backed) and `custom`.
- Client-address resolution through trusted proxies, with a configurable
  forwarded-for header.

### Profiles

- Several independent ACME endpoints in one process, over one listener and one
  database, each with its own signer, filters, challenge validators and EAB
  policy. Accounts and orders are isolated per profile.

### Traceability and audit

- Accounts and orders record the address and reverse name they were created
  from; accounts additionally record where their key was last seen.
- An append-only `audit_log`, one row per CA action **and per refusal**, carrying
  the actor, address, reverse name, identifiers, User-Agent and request id.
- Readable through `acme-proxy audit list|show`, `GET /api/audit` and `/ui/audit`;
  pruned only from the host or by `audit.retention_days`.

### Administration

- An admin CLI in the same binary: accounts, orders, the audit trail, nonces, EAB
  credentials, upstream registration, revocation, and web admin operators.
- An optional **web admin** on its own listener, serving HTML pages and a JSON
  API over the same operations — behind password authentication, a TOTP second
  factor with recovery codes, session cookies, CSRF and origin checks, and a
  login rate limiter. Off by default, loopback by default, and it refuses to bind
  elsewhere without TLS.

### Operations

- Optional TLS termination on either listener, from supplied PEM or a
  self-signed certificate generated on first run.
- Notifications on issuance, revocation, account and challenge events, over
  email, Mattermost/Slack webhooks or a custom script.
- Structured logging with stable `event` names, request correlation, and an
  access line; JSON output for log pipelines.
- Admission control, request timeouts and body limits on the ACME routes.
- Graceful shutdown on SIGTERM.

[Unreleased]: https://github.com/acme-proxy/acme-proxy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/acme-proxy/acme-proxy/releases/tag/v0.1.0
