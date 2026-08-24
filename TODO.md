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
      already there.

## Observability

- [ ] **Histograms — request latency, and issuance latency.** The one thing a
      metrics *library* would genuinely earn over the hand-rolled registry in
      `src/metrics.rs`, since buckets are where the format stops being a
      `write!` per series. Worth reconsidering the dependency at that point
      rather than hand-rolling bucket boundaries; until then `latency_ms` on
      the access line is what there is.

## Web admin

- [ ] **WebAuthn as a second factor kind** — *investigated and deferred; both
      blocking checks were actually run.* `webauthn-rs` 0.5.5 is MPL-2.0, which
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

- [ ] **An admin surface for the expiry list.** The digest
      (`[notify.expiry]`) answers "what lapses soon, and has anything replaced
      it?" once per interval, into a mailbox. The same question asked from the
      panel wants `GET /api/expiring`, `/ui/expiring` (list plus the
      `HX-Request` fragment, a nav entry in `layout.html`) and `order list
      --expiring-in <days>`. **Read-only**, so it belongs in neither
      `mutating_endpoints()` nor `mutating_page_endpoints()` — the audit
      surface's standing, and for its reason: there is no route to list.
      `Order::find_expiring` already is the query, ordering included, and
      `notify::expiry`'s `superseded_by` already is the annotation; what needs
      deciding is whether that annotation moves down to `admin::ops` so the
      digest and the page cannot drift, and whether superseded rows are shown
      by default or behind a filter — the digest wants them visible and
      annotated, where a page has room for a control the digest does not.
      `render_expiring_json` in `src/admin/render.rs`, the human renderings in
      `src/cli/render.rs`, the split that keeps a `Palette` structurally out of
      reach of a `--json` shape.
- [ ] **Address expiry reminders to the account's own `contact`**, not only to
      the operator. Every existing `NotifyEvent` goes wherever the backend is
      configured to send; this would be the first whose recipient comes out of
      the data, and `EmailNotifier` holds a fixed `to` with no per-event path.
      Two things come with it: a contact is unverified text a client typed, so
      an opt-in default and a domain allowlist are the price of turning it on;
      and the digest shape means one mail **per account** listing that
      account's own names, which is a different grouping from the
      whole-profile digest an operator gets — not the same message resent to
      everybody named in it.
