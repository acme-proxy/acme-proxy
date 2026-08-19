# TODO

Open work only. Finished items are dropped rather than ticked — `CLAUDE.md` and
the documentation are where "what exists" is recorded, and a checklist that
keeps its corpses stops being read.

## Server

- [ ] **Reload `[signer]` and the profile set — carry the state, not the
      config.** The one thing `SIGHUP` refuses that is worth unfreezing. It is
      not that construction repeats anything destructive: a CA is generated
      only when the files are absent, and a relay registers upstream once. It
      is that a backend owns in-memory state with no durable home — a `LocalCa`
      rebuilds the whole CRL from its own ledger, and a relay's `http-01` token
      store would come back empty under a live upstream fetch. So give
      `SignerBackend` a seam for adopting the previous generation's state (the
      ledger's `Arc<Mutex<_>>`, the `Arc<dyn Http01TokenStore>`, an open PKCS#11
      session). Two things fall out of it: **mounting a new profile without a
      restart**, since the registry and router swaps already handle the rest,
      and `dns.resolver`/`proxy.*` unfreezing for free — they are frozen only
      because the signers cache them at construction, while every other
      consumer is already rebuilt per generation.
- [ ] **Rebind the listeners on reload** — `server.bind_address`,
      `admin.bind_address`, `admin.enabled`, and both `tls.enabled` flips. A
      different mechanism from every other reloadable key: bind the new socket,
      start serving on it, then drain the old one gracefully. `axum::serve`
      consumes its listener and `try_join!` assumes exactly two futures for the
      process's life, so this needs a per-listener supervisor that can be
      replaced. Same ordering rule the reload path already establishes — bind
      first, so a bad address refuses the reload instead of having already
      dropped the live socket. `tls.enabled` is a structural branch on the
      listener type, so it is this work rather than a separate item.
- [ ] **Reload the `[jobs]` runner tuning.** The cheapest of the three:
      `RunnerConfig` is snapshotted in `spawn_runner_watching`, so make it a
      second `watch` cell read per pass beside the registry one.
      `max_concurrent` must resize through `Semaphore::add_permits` /
      `forget_permits` rather than being replaced, or in-flight permit
      accounting is lost. `jobs.max_attempts` stays frozen *onto each row* at
      enqueue — that is a property of the queue, not of this freeze.
- [ ] **Reload `[logging]`.** `tracing_subscriber::reload::Layer` exists for
      exactly this: `logging.filter` becomes reloadable cheaply, and the other
      five (which change the layer stack's shape) follow if the format layer is
      boxed behind the same handle. The cost is honest and belongs in the
      decision — a `reload::Layer` puts an `RwLock` read on every event.
      `database.url` is the one key that should stay frozen for good: the pool
      is held by the runner and every request path, migrations would run
      mid-flight, and the accounts and orders do not follow it. A different
      database is a different CA.
- [ ] **PostgreSQL beside SQLite.** Every query goes through `src/sqlite/` as a
      runtime `sqlx::query`, so most of them port unchanged; what does not is
      `Database::connect`'s two pragmas, the `rows_affected == 1` single-use
      idiom the nonces and recovery codes rest on, and `migrations/` — frozen
      since 0.1.0 and written in SQLite's dialect. Postgres therefore needs its
      own migration set selected by the URL scheme, never edits to these twelve
      files.
## Observability

- [ ] **Histograms — request latency, and issuance latency.** The one thing a
      metrics *library* would genuinely earn over the hand-rolled registry in
      `src/metrics.rs`, since buckets are where the format stops being a
      `write!` per series. Worth reconsidering the dependency at that point
      rather than hand-rolling bucket boundaries; until then `latency_ms` on
      the access line is what there is.

## Admin CLI

- [ ] **Colourise the human output.** One rule to settle first: `src/admin/`
      is shared with the web front end and its `--json` shapes must stay
      byte-identical, so colour belongs at the print site in `src/cli/`, gated
      on a TTY check plus `NO_COLOR` — never woven into `render_*`.

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

- [ ] **Drop expired certificates from the CRL.** The ledger behind
      `local_ca/crl.rs` grows for ever; RFC 5280 §3.3 permits removing an entry
      once the certificate itself has expired. The ledger stores serials only,
      so this needs the notAfter recorded alongside — a change to the JSON
      sidecar's shape, which must *load* the old one rather than discard it.
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
- [ ] **A third backend to test the `Ipam` trait properly.** NetBox and
      phpIPAM between them already forced `sources` to be per-backend, the
      transport to be shared, and a status to survive on the error type (a
      phpIPAM `404` is an answer). A third — NIPAP, Infoblox, or a plain
      HTTP/script hook mirroring `filter.custom` — is what would show whether
      the seam generalises or merely spans those two.

## Notifications

- [x] **A generic webhook backend** (`src/notify/webhook.rs`, beside `email`
      and `custom`): URL, method, headers and a body template, so Slack,
      Telegram, Matrix and Teams are configuration rather than four backends.
      It **replaced** `mattermost` rather than sitting beside it — that backend
      was this one with a single provider's payload frozen into it. Two things
      the design turned on: the body is rendered in two stages (a shared
      `webhook/<event>.j2` message, then the entry's own `body`), so restyling
      the text and restructuring one provider's payload are independent; and
      `minijinja`'s `json` feature is now on, because `| tojson` is what keeps
      a body valid JSON when auto-escaping is off.
- [ ] **Expiry reminders**, at most one message per certificate per week. One
      piece is missing: nothing stores the leaf's notAfter (`orders` holds the
      PEM, and a notAfter column is a **new** migration, never an edit to a
      frozen one). The sweep itself is now a `JobHandler` returning
      `Reschedule`, the shape `jobs::retention` already uses.
  - [ ] Address them to the account's own `contact`, not only to the operator.
        Every existing `NotifyEvent` goes wherever the backend is configured to
        send; this would be the first whose recipient comes out of the data.
