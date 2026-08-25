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

- **`order show` prints what its own `--json` carries.** It printed six fields
  and the authorization tree — `id`, `profile`, `account_id`, `status`,
  `identifiers`, `expires` — while `order show --json`, `GET /api/orders/{id}`
  and the panel's order card each carried a different, larger set, and the book
  documented two of theirs as something `order show` surfaced. It now prints
  `created` beside those six, then `not_before`, `not_after`, `replaces`,
  `serial`, `cert_not_after`, `revoked`, `reason` and `error`, each omitted
  entirely when the column holds nothing — the shape `audit show` and `account
  show` already had. The layout changed with it: a padded label column, no
  colon, so `id: abc` is now `id             abc`. A script parsing this output
  needs `--json`, which is what it was for.

  One member stays `--json`'s alone and the book says so: `certificatePem`, the
  issued chain, several kilobytes of PEM in a command run to get one's
  bearings. The panel's `chain.pem` download is the other way to it. The three
  URL members (`authorizations`, `finalize`, and the ACME `certificate` URL,
  which a browser cannot follow) are likewise not printed — the indented
  authorization tree is the terminal's answer to the same question.

  `certSerial` joins the order JSON on **every** surface — `order list --json`,
  `order show --json`, `GET /api/orders`, `GET /api/orders/{id}` — and the order
  card gains a `Serial` row and a `Certificate expires` row. Until now the
  serial was printed by nothing at all, while `audit list --cert-serial` and
  `GET /api/audit?certSerial=` both filtered on it: an operator could search the
  audit trail by a value no order rendering would tell them. It is omitted, not
  nulled, on an order that never issued. Listings are otherwise unchanged —
  `order list`'s line and the panel's order table keep their columns, a listing
  being allowed to be a summary where two detail views were not allowed to
  disagree.

- **`account list` and `order list` are paged**, `--limit`/`--offset`
  defaulting to 50 rows, where both used to answer with the whole table.
  `orders` grows a row per issuance for the life of the deployment, which
  reaches a real CA within a year — the reason `audit list` has been paged since
  it existed. There is deliberately no "everything" spelling and `--limit 0` is
  not a way around it. Both now end with `N of M row(s).`, so a page is never
  mistaken for the whole table; `order list --expiring-in` says the third number
  out loud (`6 of 8 row(s), 2 superseded hidden.`) because supersession is
  decided per row and cannot become part of the query. A script that read the
  whole listing needs `--limit` with a number it chooses; the window is **not**
  clamped to `admin.page_size_max`, which is a ceiling on what an HTTP caller
  may ask the server for.

- **`account list` is now newest first**, where it was oldest first. It reads
  the same `Account::search` the panel and `GET /api/accounts` do — a listing
  paged one way and ordered the other is a page control waiting to skip a row.
  `order list` and `audit list` were already newest first.

- **Every paged `--json` listing answers an envelope**:
  `{items, total, limit, offset}`, member for member the one the admin JSON API
  returns. `audit list --json` moves onto it from `{total, entries}` — the
  members are the same information under `items` rather than `entries`, plus the
  window it was answered with. `eab list`, `admin user list` and `admin session
  list` still print a bare array: an operator mints those by hand, so there is
  no page and no total to report.

- **`GET /api/eab` returns the list envelope**, not a bare array, and accepts
  `?limit=&offset=` clamped to `admin.page_size_max` like every other list
  endpoint. It was the one that did not, over a table where revoking keeps the
  row; the book already documented the envelope as what lists return. Ordering
  is unchanged (oldest first), so `/ui/eab` and `eab list` still describe the
  same listing in the same order.

### Added

- **The resolved filter policy, from the panel and in JSON** — `/ui/profiles/{name}/filter`,
  `GET /api/profiles/{name}/filter` and `acme-proxy filter show --json`.
  `/ui/profiles` warned that an endpoint with `challenge.bypass` on has
  `[filter]` and nothing else between it and its clients, and then offered no
  way to read what that policy said; the answer was an SSH session, at the
  moment somebody was trying to move quickly. All three surfaces render **one**
  document, built in one place, so a page and a terminal cannot come to describe
  one policy differently — the default effect, every check with its type and
  stages, and every rule in evaluation order with its condition
  **re-parenthesized**, which is the part an operator came for.

  **This is `filter show`, and only `filter show`.** `filter explain` really
  runs the policy — it executes the operator's `custom` scripts and issues real
  IPAM and DNS requests against an address and names the *caller* chose — so
  behind a session it would be script execution plus SSRF from one stolen
  cookie. It remains host-only and there is no plan to change that. `show` reads
  an already-built policy through four accessors, runs no check and reaches
  nothing outside the process, which is the whole of why it is proposable where
  its sibling is not. Neither new surface has a mutating verb, so neither
  contributes an entry to the CSRF test table.

  One difference between the two front ends is deliberate. The panel serves the
  **live** policy — what the process is enforcing right now — where the CLI
  **rebuilds** one from configuration, which is what makes `filter show` the
  cheapest pre-restart check. `[filter]` reloads on `SIGHUP`, so between an edit
  and its reload the two legitimately disagree, and a configuration that would
  be *refused* is reported by the CLI while the panel goes on serving the last
  good policy. Comparing them is how an operator finds out which state they are
  in.

  Two shapes to know when parsing the JSON: an endpoint with no rules answers
  `"active": false` and a warning rather than a `404` — filtering nothing is a
  state, and the one an operator most needs to be told about — and its
  `defaultEffect` is `null`, because `filter.default` is consulted only where
  some rule was applicable and is therefore not a fact about such an endpoint at
  all.

- **An admin surface for the expiry list** — `GET /api/expiring`,
  `/ui/expiring` and `order list --expiring-in <days>`. `[notify.expiry]`
  answers "what lapses soon, and has anything replaced it?" once per interval,
  into a mailbox; these ask the same question on demand, from a browser or a
  terminal. All three go through **one** operation, so a page and a mail can
  never disagree about what is expiring or about what counts as already
  replaced — the supersession rule moved out of the digest's job type and into
  the shared admin layer to make that structural rather than a convention.

  The panel opens on every endpoint at once, like every other listing, filters
  by profile and by window, and offers a control the digest has no room for:
  hiding the certificates something has already renewed, leaving only the ones
  to act on. They are **shown** by default, because the rows an operator is
  scanning for are the ones with no annotation. The default window is
  `[notify.expiry] lead_days` wherever the digest is on, and 30 days where it
  is off.

  **All three surfaces are read-only, and there is no plan for them not to
  be**: renewal is the client's own ACME flow against a key this server does
  not hold, so there is nothing here for a button to do. On the CLI,
  `--status` and `--account-id` are refused *by name* beside `--expiring-in` —
  the expiry listing is issued, unrevoked certificates by definition and
  carries no account predicate, so either flag would silently mean something
  other than it does elsewhere.

  One shape to know when parsing `/api/expiring`: `total` counts the rows the
  *window* matches and `hidden` counts the ones a page dropped as already
  replaced. They are separate because supersession is computed per row rather
  than in SQL, so the count beside the page cannot follow that filter down.

- **Shell completions and a man page**, generated from the command tree rather
  than maintained beside it: `acme-proxy completions <bash|elvish|fish|
  powershell|zsh>` and `acme-proxy man` each print to stdout. Both read neither
  the configuration nor the database — they are answered before either is
  opened — so they work in a shell startup file and before a deployment exists.
  Because they are generated, they cannot fall behind a renamed subcommand;
  because the CLI is not frozen before 1.0.0, regenerate them on upgrade.
  Installation paths are in the book's Admin CLI chapter.

- **Expiry reminders** (`[notify.expiry]`, off by default) — a periodic digest
  of the certificates approaching their notAfter, as a seventh notify event
  (`certificates_expiring`). `lead_days` is the window and `0` means the sweep
  is never scheduled; `interval_days` (7) is how often a profile's digest is
  sent, and one with nothing to report is not sent at all, so the absence of a
  message is what "everything is renewed" looks like.

  **One message per profile, not one per certificate**, which is the whole
  design rather than a formatting choice: a renewal is a *new* order, so the
  certificate it replaced still reaches its own expiry on schedule, and a
  per-certificate reminder would fire for every certificate the CA has ever
  issued — most loudly in the deployments where the automation is working. Each
  entry instead carries whether something has already taken its place, drawn
  from the successor's `replaces` field (RFC 9773 §5) or from a later,
  unrevoked certificate of the same account covering all the same names, and
  saying which. Both rules are deliberately narrow: a certificate wrongly
  marked as renewed is one an operator skips past while it lapses, where one
  wrongly left unmarked is a line of noise.

  Two consequences worth knowing. `orders` gains a **`cert_not_after`** column
  (a new migration — `not_after` was already taken by the *requested* §7.4
  window, which is a different question with a confusingly similar name);
  orders finalized before it are backfilled by the sweep itself. And a backend
  with an explicit `events` list does not receive the digest until
  `certificates_expiring` is added to it — the default list gains it
  automatically, and sends nothing while `lead_days` is `0`.

- **A `custom` IPAM backend** (`ipam.backend = "custom"`,
  `[ipam.custom]`) — the inventory is an operator script, for an estate whose
  record of truth is a CMDB, a `hosts` file, an LDAP tree or a vendor API this
  server carries no client for. It runs under the same hardening as the
  `custom` filter, signer and notifier (cleared environment, minimal `PATH`,
  `kill_on_drop`): `ACME_IPAM_HOOK`/`ACME_IPAM_CLIENT_IP` plus the same address
  again as JSON on stdin, and one permitted name per line on stdout. Exit `0`
  is "these are its names" (empty stdout being "recorded, and entitled to
  nothing"), exit **`3`** is reserved for "no record of this address at all",
  and every other non-zero exit — like a missing script or a timeout — is a
  retryable `500` rather than a denial, the guarantee an unreachable NetBox
  already had. Two keys, `script_path` and `args`; there is deliberately no
  `sources` (the script is the source) and no `timeout_ms` of its own
  (`ipam.timeout_ms` is the budget, and is what kills the child).

  It exists as much to prove the `Ipam` seam as to be useful: NetBox and
  phpIPAM share a `sources` vocabulary, a transport and a wire status code, so
  between them they never showed whether the trait generalised. This backend
  has none of the three and needed no change to `Ipam`, `AddressNames` or
  `IpamRegistry`. `tests/filters.rs` now runs the same `ipam` assertions three
  times over three backends, and the e2e scenario needs no mock container at
  all.

- **`order.max_identifiers`** (100) and **`order.retention_days`** (30), both
  per-profile. The first is a ceiling on one `newOrder`; the second is how long
  an order is kept *after it expires* before a new daily `order_sweep` deletes
  it, cascading to its authorizations and challenges. See `### Changed` for what
  each of them changes about a running deployment.

### Changed

- **Two `newAccount` requests carrying the same account key no longer race into
  a `500`.** `find_or_create` read then inserted, so two renewals starting
  together — a first boot, or a client retrying a response it thought was slow —
  both found nothing, both inserted, and the loser tripped
  `UNIQUE (profile, pubkey)`. RFC 8555 §7.3 makes find-or-create the contract:
  the loser is now handed the account that won. The same recovery is applied to
  **`keyChange`**, whose lost race became a `500` where §7.3.5 specifies `409`
  plus the `Location` of the account holding the key — and the handler was
  already building exactly that response on the non-racing path.

- **A challenge is claimed before it is validated**, moving `pending` to
  `processing` in a single guarded `UPDATE` — `Order::claim_for_finalize`'s
  primitive, one table down. Two triggers for one challenge previously each ran
  a validation, and validation reaches out to an address the *client* named, so
  N simultaneous triggers were N probes of that host from this server, bounded
  only by `server.max_concurrent_requests`. **A challenge being validated now
  reports `"status": "processing"`** rather than `"pending"`, which is what
  §7.1.6 asks for, and §8.2's `Retry-After` accompanies it. A client that
  matches challenge status exactly, rather than waiting for a terminal one, will
  see the new value.

- **`newOrder` refuses more than `order.max_identifiers` names**, and an account
  more than 32 `contact` entries. The only bound before was
  `server.max_body_bytes`, which at roughly thirty bytes per identifier admitted
  some four thousand names in one request — each an authorization plus a
  challenge per offered type, inserted in a *single* transaction against
  SQLite's one writer. Refused as `malformed`, not `rateLimited`: the order is
  malformed for this server whenever it is sent.

- **Expired orders are deleted after `order.retention_days`.** Nothing pruned
  `orders` before, so it and the `authorizations` and `challenges` beneath it
  grew for the life of a deployment. **A `valid` order is never swept, whatever
  its age** — its row is how `revokeCert` and the CRL resolve a certificate by
  serial, and what RFC 9773 renewal information is derived from. Only orders
  that ended some other way are eligible, and only once their own `expires` is
  that many days behind. Set `order.retention_days = 0` to keep the previous
  behaviour of keeping everything.

- **`x-request-id` is capped at 128 characters and restricted to
  `[A-Za-z0-9._:-]`**; anything else is replaced by a generated id rather than
  truncated, since half of somebody's correlation id correlates with nothing.
  The header is unauthenticated input that reaches the `request` span (so every
  log line of the request), the response header and two database columns — the
  ceiling `User-Agent` already had, for a value that travels further. Under the
  non-JSON log format the restriction also stops a caller writing fields that
  were never emitted.

### Packaging

- Published to [crates.io](https://crates.io/crates/acme-proxy), so
  `cargo install acme-proxy` is now an install path alongside a source build
  and the container image. README and the Installation chapter lead with it,
  and the README carries crates.io and docs.rs badges.
- The published `.crate` no longer carries what only means something inside the
  repository — the book, the vendored RFC text, `tests/e2e/`, the Grafana
  dashboard, the client examples and the `CLAUDE.md` files — taking it from 393
  files to 289. `migrations/` is deliberately still shipped: `sqlx::migrate!()`
  embeds it at compile time, so excluding it would break every install.
- docs.rs now renders a feature badge on the `hsm`-gated API instead of
  presenting it as part of the default build (`--cfg docsrs` plus `doc_cfg`).

### Documentation

- **The `[filter]` examples in the configuration reference and the Profiles
  chapter still used the 0.1.x shape** that 0.2.0 removed, so copying either
  produced a server that refused to start (`filter.enabled is no longer a
  setting`). Both are rewritten in the check/rule shape and verified by
  building them with `acme-proxy filter show`.
- The startup-failure table in Troubleshooting described the pre-0.2.0 filter
  world in three rows, none of whose suggested fixes were possible any more. It
  now quotes the messages the server actually emits, and gains rows for the two
  refusals an operator upgrading from 0.1.x is most likely to meet.
- `[signer.local_ca.subject]`'s six keys and `signer.relay.eab`'s two were
  documented in `config.toml.example` but nowhere in the book — including no
  spelling of their environment variables. Both now have reference entries on
  the chapter that owns them.
- The README's feature list had not kept up with Prometheus metrics, `SIGHUP`
  reload, the job queue or the phpIPAM backend; nor had `src/lib.rs`'s, whose
  architecture map was also missing nine public modules. Both now match the
  book. The README's stated coverage floor (96%) was one point below what CI
  enforces.

## [0.2.0] — 2026-08-23

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

- **The local CA drops expired certificates from its CRL** (RFC 5280 §3.3). The
  revocation ledger grew for the life of the deployment: nothing recorded when a
  revoked certificate expired, so nothing could ever be removed, and every
  relying party downloaded the whole history on every check. A revocation now
  records the leaf's own `notAfter` alongside its serial, and expired entries are
  pruned at startup and then daily.

  Two rules keep it safe. An entry goes an hour *after* the certificate's
  `notAfter`, not at it — the same clock-skew allowance issuance grants, and
  exactly the window in which a relying party whose clock is behind would
  otherwise accept a certificate this CA revoked. And an entry with **no**
  recorded expiry is never dropped: that is any entry written by 0.1.0, and an
  unknown expiry is not an expired one.

  **The `ca.json` sidecar gained an envelope** to carry a durable `crlNumber`.
  The number used to be derived from the entry count, which pruning would have
  made go *backwards* — and RFC 5280 §5.2.3 says a client meeting a lower number
  than it has cached keeps the cached CRL, i.e. keeps trusting what has since
  been revoked. **No action is needed on upgrade**: the 0.1.0 bare-array form is
  read as-is and rewritten on the next change, resuming numbering above anything
  that format could have published. Keep backing the sidecar up beside the CRL —
  it now holds the number as well as the ledger.

- **`acme-proxy --version` names the build.** The bug report template has always
  asked reporters to run it, but the flag did not exist — clap generates one
  only when the command declares a version, and this one did not, so the first
  instruction on the form errored out. The binary now reports its own crate
  version, which is also what makes "which release is this?" answerable on a
  host where the checkout is long gone.

- **The admin CLI colours its human-readable output, under a new global
  `--color auto|always|never`.** A listing is scanned for the row that is not
  what it should be, and until now every column read the same: an `invalid`
  order, a `revoked` credential and a `certificate_issue_failed` audit row were
  the same grey as the timestamp beside them.

  The default is `auto` — colour when the stream is a terminal and `NO_COLOR` is
  unset or empty — so a piped or redirected run is plain without asking.
  `always` colours regardless of the stream **and of `NO_COLOR`**, which is what
  makes `| less -R` work and is a deliberate departure from `logging.ansi`,
  where neither switch can turn colour on against the other: a configuration key
  is ambient, and a flag was typed by the person reading the output. stdout and
  stderr are decided separately, since the two are redirected independently.

  Colour is **semantic, never decorative**: statuses, audit events naming a
  refusal, `filter explain`'s per-check verdicts and its allow/deny/undecided
  answer, and the standing warnings (`eab create`'s "shown only this once", a
  policy with no rules configured, a reissued set of recovery codes). Labels,
  timestamps and identifiers stay plain.

  **Nothing about `--json` changes, at any setting**, and neither does any
  human-readable line under `--color never` — both are the same bytes as before,
  verified against the previous build rather than argued. What made that
  guarantee structural is that the CLI-only text renderers moved out of
  `src/admin/render.rs` (shared with the web admin, and the JSON one wire format
  two front ends parse) into `src/cli/render.rs`, where the terminal is the only
  consumer. `acme_proxy::admin::render_*_line` / `render_*_text` and
  `print_rows` are therefore now `acme_proxy::cli::render::*` — a library path,
  not a CLI surface, so no command, flag or output shape is renamed.

- **The profile set, each profile's `[signer]`, `dns.resolver` and `[proxy]` all
  reload on `SIGHUP`, and `reload::FROZEN` is down to `database.url` alone.**
  Adding an ACME endpoint used to cost a restart, which dropped every in-flight
  order on the endpoints that were *already* running — for a change that had
  nothing to do with them.

  The freeze was never about the CA files. A local CA is generated only when the
  files are absent and a relay registers with its upstream only once, so
  rebuilding a backend repeats nothing destructive. It was about state with no
  durable home: a `LocalCa` rebuilds its whole CRL from an in-memory revocation
  ledger, so two of them over one `crl_path` would drop each other's entries,
  and a relay serving `http-01` publishes key authorizations into a store a
  rebuild would empty — while an upstream CA is midway through fetching one.

  `SignerBackend` now has a seam for handing that state on. A backend whose
  configuration did not move is **reused verbatim** rather than rebuilt (so an
  ordinary reload does not re-read a CA key, and under
  `signer.local_ca.key_source = "pkcs11"` does not log in to the token again),
  and a backend whose configuration *did* move is rebuilt sharing the **same**
  ledger and the **same** token store as the instance it replaces. Sharing
  rather than reloading from disk is what closes the window the durable sidecar
  cannot: a revocation landing while the reload is still building would
  otherwise be lost.

  Two things fall out of it. Mounting and unmounting an endpoint is now an
  ordinary reload — a `profile_mounted` fires for an endpoint that was not there
  before and for no other, and an unmounted one leaves its accounts and orders
  in the database to come back if it is mounted again. And `dns.resolver` and
  `[proxy]` unfreeze: they were refused only because the signer backends cached
  them at construction, which is now a reason to rebuild a backend rather than
  to refuse the edit.

  One caveat, and it is the only one: unmounting the last profile a `relay`
  backend serves takes its job handler with it, so an issuance still waiting on
  the upstream has nothing left to finish it. Drain such an endpoint before
  removing it.

  `database.url` stays frozen and should stay frozen for good — the pool is
  open, migrations would run mid-flight, and the accounts and orders do not
  follow a URL elsewhere. A different database is a different CA.

- **`[jobs]` reloads on `SIGHUP`.** All seven keys — the poll interval,
  concurrency, the attempt budget, both retry bounds, the lease and retention —
  where six of them used to be refused by name. These are the knobs an operator
  reaches for while something is already going wrong (an upstream CA
  rate-limiting you, a backlog draining too slowly), so charging a restart for
  them dropped exactly the in-flight orders the retuning was meant to save. They
  were never *physically* frozen the way `database.url` is; the runner had
  simply snapshotted them when it started.

  It no longer does. The loop re-derives its pacing from a `watch` cell on every
  pass and resizes its own concurrency pool, and the queue reads `max_attempts`
  from a shared atomic — so nothing in the section is read once, and the runner
  never restarts.

  Each key lands at its own grain, and nothing already in flight is disturbed:

  - `poll_interval_ms` takes effect at once, without waiting out the old
    interval first.
  - `max_concurrent` widens immediately when raised; lowered, it takes back the
    slots that are free and reaches the new figure as running jobs finish. No
    job is ever cancelled to get there sooner.
  - `lease_seconds` and both `retry_*` keys apply to the next job claimed — one
    already running keeps the budget and backoff it started under.
  - `max_attempts` stays frozen onto each row at enqueue, so it applies to work
    queued from then on. Raising it is **not** a way to rescue a backlog that is
    about to give up.
  - `retention_days` rebuilds the sweep, including registering it when it goes
    from `0` to a real value.

  New event `job_runner_retuned`, carrying all five pacing values. It is the
  line worth grepping for: `server_config_reloaded` says a generation was
  published, this says the runner is actually running under it. It is silent
  when a reload leaves `[jobs]` alone.

- **The listeners rebind on `SIGHUP`.** All seven keys that decide where a
  socket is, or whether there is one, now reload: `server.bind_address`,
  `server.tls.enabled`, `admin.enabled`, `admin.bind_address`,
  `admin.tls.enabled`, `metrics.enabled` and `metrics.bind_address`. Moving the
  ACME port, bootstrapping the web admin on a running CA, or turning the metrics
  endpoint on for a new Prometheus each cost a restart — and a restart of a CA
  drops every live connection and every in-flight order for a change that never
  touched issuance.

  `reload::FROZEN` lost every bind address here; the `[jobs]` entry above took
  the rest.

  What made it possible is that this server now owns its accept loop
  (`src/listener.rs`) rather than handing each socket to `axum::serve`, which
  consumes it. One `axum::serve` per listener lives for the process; underneath
  it the `TcpListener` is replaceable and the TLS mode is an
  `Option<TlsSettings>` read **per connection**, exactly as the certificate
  already was. Three consequences worth knowing:

  - **A bad address refuses the reload rather than dropping the live socket.**
    Every new socket is bound before anything is published, so a port already in
    use is a `server_config_reload_failed` with the running listener untouched.
  - **Turning TLS on or off does not move the socket at all**, which is the one
    case a bind-then-drain scheme could not serve — two listeners cannot hold
    one port. The next connection speaks the new protocol on the same port.
  - **Established connections are never disturbed by a rebind.** Only the socket
    new connections arrive on changes.

  `server_config_reloaded` gained `listeners_rebound`, naming any socket that
  moved, and `server_listener_stopped` is new for a listener switched off.
  Switching the panel off releases its socket and empties its router, but does
  not sign anybody out — sessions are in the database; use `acme-proxy admin
  session revoke --all` for that.

- **`[logging]` reloads on `SIGHUP`.** All six keys — the filter, the format,
  the destination, colour, span events and `flatten_event` — where the whole
  section used to be refused by name. Raising the log level or switching to JSON
  for a collector was the one thing an operator most wants mid-incident and the
  one thing that still cost a restart, taking every live connection and
  in-flight order with it.

  The subscriber is installed once per process and that has not changed; what
  changed is that the layer stack now sits behind a
  `tracing_subscriber::reload::Layer`, so a generation swaps it like everything
  else. It is the **first** thing a reload publishes, so the
  `server_config_reloaded` line confirming the reload is already written under
  the new settings. The cost, stated rather than buried: a `reload::Layer` puts
  an `RwLock` read on every event.

  `RUST_LOG` still outranks `logging.filter`, on a reload exactly as at startup
  — the two disagreeing about what the server is running would be worse than the
  override. But that makes an edited filter a silent no-op, so a reload that
  hits it now logs `server_logging_filter_overridden` instead of looking like it
  worked. `server_config_reloaded` also gained `logging_reloaded`, which is
  `false` when the process installed no subscriber of its own and there was
  therefore nothing to swap.

- **A Grafana dashboard**, at `dashboards/acme-proxy.json`. Twelve panels over
  the four metric families: issuance and its refusals by ACME problem type,
  request rate by route and status, the 5xx share, shed requests, unmatched
  paths, and the SQLite pool. Import it and adapt it — it is a starting point,
  not a fixed artifact. See `doc/src/operations/grafana.md`.

  Two properties an operator cannot infer from the exposition alone are encoded
  in it: `route` is a matched route *pattern*, so grouping by it is bounded,
  and the pool gauge carries no `profile` label, so the dashboard-wide profile
  filter must not be applied to it. `tests/grafana_dashboard.rs` fails the build
  if a queried metric stops being emitted, if an emitted family is missing from
  the dashboard, or if the pool panels ever grow that filter — with the metric
  names read from a rendered registry rather than a hand-maintained list.

- **A Prometheus `/metrics` endpoint, on a listener of its own.** Off by
  default, configured by the new `[metrics]` section (`enabled`,
  `bind_address`, defaulting to `127.0.0.1:3002`). Until now the only way to
  alert on issuance failure rates was to parse the log stream.

  A **third socket** rather than a route on either existing listener, and that
  is what settles the access question: a scrape carries no credential and none
  is checked, because reaching the port at all is the permission — so the
  control is a firewall rule rather than something this server verifies. On the
  ACME listener it would have been an unauthenticated route on a public socket;
  on the admin listener it would have needed an auth exemption on a listener
  whose rule is that every route but sign-in requires a session, and would have
  coupled metrics to the panel being enabled.

  Four families: `acme_proxy_requests_total{profile,route,status}`,
  `acme_proxy_certificates_issued_total{profile}`,
  `acme_proxy_certificate_issue_failures_total{profile,reason}` and the
  `acme_proxy_database_pool_connections{state}` gauge. `route` is the matched
  route *pattern* (`/order/{id}`), never the URI, and an unmatched path
  collapses to one `<unmatched>` series — a label taken from the request would
  be unbounded memory in the scraper. The certificate counters are driven off
  the same record the audit trail is written from, so the metric and
  `acme-proxy audit list` cannot disagree.

  Hand-rolled rather than taken from a crate: the exposition format is a
  `write!` per series, and every façade brings a global recorder, which this
  tree already refused for `rustls`'s `CryptoProvider::install_default`.

  Both keys are frozen against reload, for the reason every bind address is —
  `SIGHUP` refuses the reload by name rather than applying half of it. The
  counters themselves *survive* a reload: a rebuilt registry would zero them,
  which `rate()` reads as a process restart.

  `Auditor::from_config` takes the registry as a **parameter** rather than
  through a builder, because the builder was forgotten on the serving path the
  first time round: the certificate counters stayed at zero in production while
  the suite passed, since the test harness wired the registry itself and so
  proved its own wiring rather than the server's.

- **`GET /ca.pem` serves the profile's trust anchor**, beside `GET /crl` and
  routed the same way: per-profile, unauthenticated, and deliberately not
  advertised in the directory, since it is CA infrastructure rather than an
  ACME resource. Installing the root a `local_ca` profile generated was
  previously a matter of finding the file on the server's disk; it is now one
  `curl`, and the bytes served are exactly the ones already appended to every
  chain that profile issues.

  A backend with no anchor of its own answers `404` — that is both delegating
  backends, whose anchor belongs to the CA they defer to. Note the route sits
  inside the profile router and so is subject to that profile's filter policy,
  which is the trap `doc/src/filters/path.md` already describes for `/crl` and
  now covers for both.

- **The web admin shows the issued certificate, and offers it as a file.** The
  order card rendered `order.certificate`, which is the ACME *URL* — served by
  signed POST-as-GET, so a browser handed it gets nothing and the field was a
  dead string. It now renders the chain itself, from the column that already
  held it, with a `GET /ui/orders/{id}/chain.pem` download beside it. The order
  detail shape (`GET /api/orders/{id}` and `acme-proxy order show --json`)
  gained `certificatePem` to match; listings are unchanged, since a page of
  fifty orders should not carry fifty chains.

- **The access line names the client.** The server-wide `request` span gained a
  `client_ip` field, so an ordinary request finally says who connected —
  previously only audit rows and a few targeted lines did. It is seeded from
  the peer address and replaced, where `filter.trusted_proxies` says the peer
  is a reverse proxy, by the address resolved from `filter.forwarded_header`.
  Both are per-profile settings, so a request that never reaches a profile
  (`/health`, the http-01 responder, anything admission control sheds) shows
  the peer.

- **Configuration reload on `SIGHUP`, without moving either socket.** Until now
  every configuration change was a process restart, which dropped in-flight
  ACME orders and every live connection — for changes that never needed a new
  socket, like a `[filter]` rule, an `[ipam]` token, a `[notify]` webhook or a
  renewed certificate.

  A reload rebuilds both routers, every profile's filter chain and challenge
  registry, the notification backends, the job registry and both TLS acceptors
  from the file on disk, then publishes them together. Add
  `ExecReload=/bin/kill -HUP $MAINPID` to the systemd unit and `systemctl
  reload` works. See `doc/src/operations/reload.md`.

  Two properties are the whole design:

  - **It is all or nothing.** A key a running process cannot change is refused
    **by name** — naming the key, what the server is running and what the file
    now says — and the reload is abandoned whole. A configuration that applied
    the half it understood would leave a running server that no file on disk
    describes.
  - **Signer backends are carried across, never rebuilt.** Not because
    generating a CA or registering with an upstream would repeat — neither
    does — but because a signer owns in-memory state with no durable home: a
    local CA rebuilds its whole CRL from its own ledger, so two over one
    `crl_path` would drop each other's entries, and a relay's `http-01` token
    store would come back empty while an upstream CA was fetching from it.

  Frozen, and so refused by name: `database.url`, `server.bind_address`,
  `server.tls.enabled`, `admin.enabled`/`bind_address`/`tls.enabled`, `[dns]`
  and `[proxy]`, six of the seven `[jobs]` keys (`retention_days` reloads), each
  profile's `[signer]` section, and the set of enabled profiles. (`[logging]`
  was on this list too, and is not any more — see the entry above.) Everything
  else reloads, including TLS certificate paths
  and `admin.template_dir` — a template that does not compile now fails the
  *reload* rather than reaching a browser.

  Every success logs `server_config_reloaded` with a `generation` that counts
  from 1, which is the quickest way to tell a landed reload from an ignored
  one; a refusal is `server_config_reload_refused` and a build failure
  `server_config_reload_failed`.

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

- **An unknown order status filter is refused by name rather than matching
  nothing.** `acme-proxy order list --status typoo`, `GET /api/orders?status=`
  and `/ui/orders?status=` all passed the value straight to SQL, so a typo came
  back as an empty result — indistinguishable from "nothing is in that state",
  which is a perfectly ordinary answer. All three now refuse it and list the
  five valid values, the rule `audit list --event` already followed. The three
  order/authorization/challenge states are Rust enums now rather than string
  literals compared at thirty-odd sites; the stored strings are byte-identical,
  so no migration and no wire-format change.

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

### Security

- **Two concurrent `finalize` requests on one order could each be issued a
  certificate, and all but one of them were unrevocable.** `post_finalize` read
  the order, checked `status == "ready"`, signed, and wrote — three steps with
  nothing holding the order in between, so N requests carrying their own nonce
  and their own CSR all passed the check and all reached the signer. Only the
  last write survived. The others were valid, CA-signed certificates whose
  serial reached no row, so `POST /revokeCert` answered `malformed` ("unknown
  certificate"), `acme-proxy order revoke` could not see them, and the CRL never
  learned they existed — there was no interface in the product that could
  withdraw them.

  `Order::claim_for_finalize` now moves `ready` → `processing` in one guarded
  `UPDATE` and hands the caller `rows_affected`, the primitive nonce
  consumption and the TOTP replay guard already rest on. The loser gets RFC 8555
  §7.4's own answer, `403 orderNotReady`, and sees `processing` then `valid` on
  its next poll. The `relay` backend was never exposed (its
  `upstream_orders.order_id` primary key is exactly this guard); `local_ca` and
  `custom`, which answer inline, had no equivalent until now. No schema change:
  `processing` has always been in the `orders.status` `CHECK`.

- **A refused configuration reload printed the HSM PIN, the RFC 2136 TSIG key
  and the upstream EAB secret to the log.** The frozen-key check compares
  `[proxy]` and each profile's resolved `[signer]` by rendering the whole
  section through `Debug`, and the refusal embeds both the running and the
  proposed rendering in a message `SIGHUP` handling logs at `warn`. So editing
  any `[signer]` key and reloading wrote the TSIG key — write access to the very
  DNS zone this CA validates against — into journald and every log shipper
  downstream. Those two projections are now compared by SHA-256 digest: the
  comparison is unchanged, the refusal still names the key and the profile, and
  the value is `sha256:…`. Sections that cannot hold a credential
  (`dns.resolver`, `database.url`) still name the old and the new value.

- **Admin login latency enumerated the operator table, in the opposite direction
  from the one the code guarded against.** The unknown-username branch verified
  against a dummy hash that was *generated* on the spot, so it paid two
  600 000-round PBKDF2 derivations where a known username paid one — a
  single-request, pre-authentication oracle on `POST /api/session` and
  `POST /ui/login`, and double the CPU an unauthenticated caller could force on
  the request the login limiter exists to bound. The dummy is now a precomputed
  constant, so both branches cost exactly one verification.

- **The web admin's step-up password check had no rate limit.** Replacing or
  removing a live second factor takes the account password, but that check ran
  the KDF with no budget and no counter — so somebody holding a stolen session
  cookie could brute-force the operator's password at line rate, and a correct
  guess converts the cookie into a factor takeover (enrol their own
  authenticator, revoke every other session, void the recovery codes), which is
  the lockout the check exists to prevent. Any authenticated caller could also
  pin a core with PBKDF2. It now runs the same `LoginLimiter` sign-in does,
  before the KDF and against the **same** bucket, so guessing here cannot buy a
  second budget. `POST /api/mfa/totp`, `DELETE /api/mfa/totp` and
  `POST /api/mfa/recovery-codes` can now answer `429` with `Retry-After`; the
  `/ui` twins render it as the account card's own banner.

### Fixed

- **Two atomic file writes could rename their bytes over each other.**
  `write_atomic` derived its scratch name with `with_extension("tmp")`, so the
  local CA's `ca.crl` and `ca.json` — written back to back on every revocation —
  both mapped to `ca.tmp`. A CRL rebuild racing a ledger persist could therefore
  land CRL PEM inside the sidecar, which the next startup refuses to parse:
  every revocation the CA had ever recorded, unreadable, because two writes
  shared a scratch name. The suffix is now appended rather than substituted, and
  carries the pid — two processes truncating and filling one temp file in turn
  interleave, and then each renames the mixture into place, atomically wrong.

- **`newAccount` did not refuse a deactivated account key.** RFC 8555 §7.3.6
  requires a `401` + `unauthorized` for any request from a deactivated account,
  and every other path kept it — `signer_account` for the seven order-side
  endpoints and `keyChange`, `post_account` directly. `newAccount` checked on
  neither of its branches, so a deactivated key could confirm its account still
  existed and read its own `contact` list back, either by asking
  `onlyReturnExisting` or by simply re-registering. Read-only and limited to
  that key's own holder, but a hole in a boundary that is otherwise uniform.

- The e2e lab picked the wrong container runtime on any host with
  `podman-docker` installed. The probe tested whether the `docker` command
  *spawned*, not whether it succeeded, so a `docker` shim over rootless podman
  answered "docker" — skipping the `podman.socket` check and the `DOCKER_HOST`
  setup, and failing later with an opaque connection error instead of the
  message naming `systemctl --user start podman.socket`.
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

[Unreleased]: https://github.com/acme-proxy/acme-proxy/compare/0.2.0...HEAD
[0.2.0]: https://github.com/acme-proxy/acme-proxy/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/acme-proxy/acme-proxy/releases/tag/0.1.0
