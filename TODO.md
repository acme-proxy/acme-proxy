# TODO

Open work only. Finished items are dropped rather than ticked — `CLAUDE.md` and
the documentation are where "what exists" is recorded, and a checklist that
keeps its corpses stops being read.

## Server

- [ ] **PostgreSQL beside SQLite.** Every query goes through `src/sqlite/` as a
      runtime `sqlx::query`, so most of them port unchanged; what does not is
      `Database::connect`'s two pragmas, the `rows_affected == 1` single-use
      idiom the nonces and recovery codes rest on, and `migrations/` — frozen
      since 0.1.0 and written in SQLite's dialect. Postgres therefore needs its
      own migration set selected by the URL scheme, never edits to the files
      already there. The declared widths can be transcribed literally: every
      `VARCHAR(n)` in the set was re-read against what its column actually
      holds, and the one that had drifted — `nonces.value`, still declared
      `VARCHAR(36)` after the nonce became a 43-character CSPRNG token — was
      corrected along with `challenges.token`, which holds the same value and
      declared no width at all. That mattered only for this port: SQLite
      ignores a width (TEXT affinity, no length check) where Postgres enforces
      one, so a faithful copy of the old files would have rejected every nonce
      this mints. `declared_token_widths_match_random_token` is what keeps the
      two token columns honest as `TOKEN_BYTES` moves.

      Ids need no transcription at all: they are `uuid::Uuid` in Rust and a
      BLOB here, so the Postgres set declares them `uuid` and the same binds
      and `try_get`s work unchanged — `sqlx`'s `uuid` feature already covers
      both dialects. `every_id_column_is_declared_a_blob` (`src/sqlite/db.rs`)
      is the list of columns that move, and the two it names as deliberate
      exceptions are the two to leave as text there too. What *is*
      dialect-specific is `sqlite::id::parse`, which exists because a `&str`
      bound against a BLOB matches nothing where Postgres would refuse the
      parameter outright; the seam is already one function, and the eleven
      callers named in `src/CLAUDE.md` are the whole of what depends on it.

## Observability

- [ ] **Histograms — request latency, and issuance latency.** The one thing a
      metrics *library* would genuinely earn over the hand-rolled registry in
      `src/metrics.rs`, since buckets are where the format stops being a
      `write!` per series. Worth reconsidering the dependency at that point
      rather than hand-rolling bucket boundaries; until then `latency_ms` on
      the access line is what there is.

## Web admin

- [ ] **WebAuthn as a second factor kind** — *investigated and deferred; both
      blocking checks were actually run.* This is the one thing standing between
      the web admin and ASVS 5.0 **V6.3.3 at L3**, which wants a hardware factor
      that resists phishing and requires a deliberate user action.
      `webauthn-rs` 0.5.5 is MPL-2.0, which
      `deny.toml`'s allow list does not carry, and `webauthn-rs-core`
      hard-depends on `openssl`/`openssl-sys` (non-optional), which this tree
      has avoided at every turn. The 0.6.1-dev line drops OpenSSL for
      `crypto-glue` but is a `-dev` prerelease — the category already refused
      for htmx 4.x. Nothing in the design precludes it: another factor kind is
      another `MfaStep` variant and another branch in `verify_second_factor`,
      not a change to the state machine, and `admin.base_url` is already the
      resolved origin an RP id would come from. The open choice is that
      dependency versus hand-rolling COSE/CBOR on `ring` + `ciborium`
      (Apache-2.0, already allowed) with attestation `none`.
- [ ] **Live view of a pending order** — `hx-trigger="every 5s"` on the order
      fragment, so an operator watches a challenge resolve instead of
      reloading. The fragment route exists already (`HX-Request` picks it);
      what needs deciding is when polling **stops**, so a tab left open on a
      terminal order does not poll for ever.

## Both surfaces

- [ ] **An admin action trail.** `audit_log` answers one question — who asked
      the CA to sign or withdraw a certificate — and four event names are the
      whole vocabulary. An account deleted, an EAB credential minted or
      revoked, a contact rewritten, every session revoked: none of it leaves a
      row, so the log stream is the only record and it lasts as long as the log
      rotation does. Most of the wiring is already there — `actor_kind` carries
      `admin` and `cli` beside `acme` and `system`, and `AdminState` holds the
      *same* `Arc<Auditor>` the ACME listener does, so an operator revoking
      through the panel already writes into the one trail. The cost is entirely
      schema: `event` carries a `CHECK (event IN (…))`, SQLite cannot alter
      one, and so new names mean a **table rebuild in a new migration** — the
      `admin_users.totp_*` precedent run the other way round. What needs
      deciding first is whether a table whose stated question is about
      certificates should carry actions that touch none, or whether that is a
      second table. Either way it does not weaken the rule the surface rests
      on: still no route on that listener that deletes.

## Signers — local CA

- [ ] **An OCSP responder** — by far the largest item here: a signed response
      per query, a delegated responder certificate (or the CA key doing double
      duty), and a route that is emphatically not an ACME resource. Worth
      deciding whether it is wanted at all before building it: the ecosystem
      moved towards RFC 9773 renewal info plus a small CRL, and this server
      serves both already. The pointer half is already cheap if this ever
      lands: `id-ad-ocsp` is a second `AccessDescription` inside the
      `authorityInfoAccess` extension `local_ca/policy.rs` builds today, so it
      is one more caller of `access_description` and a key beside
      `ca_issuer_urls`, not a rewrite.

## IPAM

- [ ] **phpIPAM's user/password session-token auth.** `src/ipam/phpipam/`
      implements the static app-code scheme only ("SSL with App code"), which
      is the direct analogue of NetBox's token and rotates in the environment.
      The other scheme exchanges user credentials for a six-hour token, so it
      needs a refresh loop and somewhere to keep the token — worth having only
      if an estate's phpIPAM cannot be given an app code at all.

## Notifications

- [ ] **Address expiry reminders to the account's own `contact`**, not only to
      the operator. `[admin.notify]` and the `admin_sign_in` /
      `admin_credential_changed` events already solved the per-event-recipient
      half (`NotifyEvent::recipient`, `EmailNotifier` sending there instead of
      its configured `to`) — so what is left is the account-facing grouping: one
      mail **per account** listing that account's own names, and, because a
      `contact` is unverified text a client typed, an opt-in default and a
      domain allowlist as the price of turning it on.

- [ ] **Web-admin CLI credential changes do not notify.** `admin user passwd`
      and `admin user totp reset` on the host change an operator's
      authentication details without an `admin_credential_changed`
      notification — the web panel's routes do (V6.3.7), the CLI's do not,
      because the CLI has no job runner and building an `[admin.notify]`
      dispatcher there was judged disproportionate for a host-root operation.
      Closing it means giving `run_admin_command` a `JobQueue` and an `Egress`
      to build one from.
- [ ] **A "new location" that is genuinely a location, not an address.**
      `admin_users.known_login_ips` (last five distinct addresses) is what
      raises `admin_sign_in` `succeeded_from_new_address`. An address changes
      far more often than a location — a mobile operator on CGNAT trips it
      daily. A coarser signal (ASN, or a geo lookup done out of process) would
      be quieter, at the cost of a dependency or a script hook.
