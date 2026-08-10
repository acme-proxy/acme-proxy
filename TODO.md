# TODO

Open work only. Finished items are dropped rather than ticked — `CLAUDE.md` and
the documentation are where "what exists" is recorded, and a checklist that
keeps its corpses stops being read.

## Server

- [ ] **Reload the configuration on `SIGHUP`.** `cli::serve_on_with` builds
      everything exactly once — profiles, deduplicated signer backends, filter
      chains, challenge registries, both routers — and `AppState` holds an
      `Arc<Config>`, so a reload is a rebuild-and-swap, not a mutation. What
      cannot be swapped under a live listener is the bind addresses and TLS (a
      new socket is a restart) and whatever a signer backend provisioned at
      startup (`relay`'s upstream account). Decide which keys are
      reloadable and **refuse the rest by name**, the way startup validation
      already refuses an unknown `logging.target` instead of falling back.
- [ ] **PostgreSQL beside SQLite.** Every query goes through `src/sqlite/` as a
      runtime `sqlx::query`, so most of them port unchanged; what does not is
      `Database::connect`'s two pragmas, the `rows_affected == 1` single-use
      idiom the nonces and recovery codes rest on, and `migrations/` — frozen
      since 0.1.0 and written in SQLite's dialect. Postgres therefore needs its
      own migration set selected by the URL scheme, never edits to these twelve
      files.
- [ ] **A durable job runner with retries.** The one long-running task today is
      `signer::relay::flow`: a `tokio::spawn` whose state lives on the
      `upstream_orders` row and which `SignerBackend::resume` picks back up at
      startup. That is the right shape, but it is hand-rolled for one backend
      and retries nothing between restarts. Everything else that wants a queue
      — expiry notifications, CRL regeneration, an OCSP responder's refresh —
      wants the same table plus a claim/backoff/attempt-count loop, in one
      place.

## Observability

- [ ] **Name the client on the access line.** The server-wide `request` span
      carries method, uri, request id and profile, but **not the address**, so
      an ordinary request never says who connected — only audit rows and a few
      targeted lines (`admin_login_*`) do. The `ClientIp` the filter middleware
      resolves is not reachable from `access.rs`: that layer is per-profile and
      sits *inside* the span. Read the peer address in `access.rs` itself (the
      honest fix, since `/health` and the http-01 responder sit outside every
      profile) and declare `client_ip` as `field::Empty` so the per-profile
      layer can overwrite it with the `ProxyPolicy`-resolved one — the
      deferred-record pattern `profile` already uses, and necessary here
      because `filter.trusted_proxies` is per-profile configuration.
- [ ] **A Prometheus `/metrics` endpoint**: `requests` (profile, route,
      status), `cert_delivery`, `cert_failure`,
      `database_pool_active_connections`. Mount it where `/health` is — the
      root router, outside admission control and every filter chain — or on the
      admin listener; inside a profile a scrape would need an allowlist entry.
      `doc/src/operations/monitoring.md` states the absence today and is the
      page to update.
- [ ] A Grafana dashboard over the above.

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
- [ ] **Show and offer the issued chain.** `orders/_card.html` renders
      `order.certificate`, which is the ACME *URL* — reachable only by signed
      POST-as-GET, so a browser following it gets nothing and the field is a
      dead string. The PEM is in the `orders.certificate` column already:
      render it, and add a download route (`/ui/orders/{id}/chain.pem`,
      `application/pem-certificate-chain` + `Content-Disposition`). A `GET`, so
      it stays out of `mutating_page_endpoints()`.
- [ ] **Live view of a pending order** — `hx-trigger="every 5s"` on the order
      fragment, so an operator watches a challenge resolve instead of
      reloading. The fragment route exists already (`HX-Request` picks it);
      what needs deciding is when polling **stops**, so a tab left open on a
      terminal order does not poll for ever.

## Signers — local CA

- [ ] **`cRLDistributionPoints` (and AIA) in issued leaves.** `LocalCa::issue`
      already overwrites every extension the CSR asked for, so this is one more
      line there — but it needs a public URL for the CRL, which today is served
      per-profile at `{base_url}/profile/<name>/crl` and advertised nowhere.
      Until then the CRL this CA maintains is unreachable by anything holding
      only the leaf.
- [ ] **Serve the CA material for client bootstrap** — `GET /ca.pem`, and the
      chain, beside `/crl`, so installing the trust anchor is one `curl`. Same
      routing answer as `/crl`: per-profile (each profile has its own signer),
      unauthenticated, and deliberately not advertised in the directory.
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
      serves both already.

## IPAM

- [ ] **Lift NetBox from a filter to an IPAM backend.** `src/filter/netbox/`
      answers exactly one question — "does this client's address own these
      names?" — behind a `NetboxApi` seam shaped around NetBox's own REST API.
      A second IPAM means hoisting that question into an `Ipam` trait with its
      own `[ipam]` section, leaving `filter.netbox` as one consumer of it.
- [ ] **VRRP addresses in the NetBox lookup**: a service address belongs to the
      pair, so a client connecting from its own member address is refused
      today.
- [ ] **phpIPAM** as the second backend, once the trait above exists — and as
      the thing that proves the trait is not just NetBox with extra steps.

## Notifications

- [ ] **A generic webhook backend** (`src/notify/`, beside `email`,
      `mattermost` and `custom`): URL, method, headers and a body template, so
      Slack, Telegram, Matrix and Teams are configuration rather than four
      backends. The templating half exists already —
      `notify::build_environment` and the `.j2` convention (auto-escaping off,
      deliberately, unlike the web admin's `.html`).
- [ ] **Expiry reminders**, at most one message per certificate per week. Two
      pieces are missing: nothing stores the leaf's notAfter (`orders` holds
      the PEM, and a notAfter column is a **new** migration, never an edit to a
      frozen one), and there is no periodic task to sweep on — see the job
      runner above.
  - [ ] Address them to the account's own `contact`, not only to the operator.
        Every existing `NotifyEvent` goes wherever the backend is configured to
        send; this would be the first whose recipient comes out of the data.
