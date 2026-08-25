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
- [ ] **A role on `admin_users`, so a session that reads is not a session that
      revokes.** There is one kind of operator, and every live session can
      delete an account and revoke a certificate as readily as it can read the
      audit trail. `20260808120000_add_admin_users.sql` already says what the
      column would look like — "a later nullable `ALTER TABLE`, the shape
      `20260728120000_add_cert_revocation.sql` already established" — so the
      schema half is one migration file, and the enforcement half is one branch
      in `AuthenticatedWrite`/`PageSessionWrite`/`EnrolWrite`, the three
      extractors every mutating route already passes through, rather than a
      check per handler. What needs deciding is what a role means to the
      **CLI**, which answers to a shell on the host and holds no session at
      all: either it is a panel-only concept and `admin user list` grows a
      column nothing enforces, or it is not, and a root shell is being asked to
      respect it.
- [ ] **Operators and sessions, in the panel.** `admin user
      list|disable|enable|totp reset` and `admin session list|revoke` are
      shell-only; the panel manages the *current* operator's own factor and
      offers "sign out everywhere", with nothing in between — so the answer to
      a colleague's laptop going missing is an SSH session, at the moment
      somebody is trying to move quickly. `render_admin_session_json` already
      exists with exactly one consumer, and the token-hash fingerprint it
      prints rather than the hash is what a page would show too. **Create and
      `passwd` deliberately stay on the host**: those mint a credential, which
      is where the "no sign-up page" rule already draws the line, and
      everything proposed here only ever *tightens*. Each route goes behind
      `check_step_up` (`src/webadmin/handlers/mfa.rs`) and into
      `mutating_endpoints()`/`mutating_page_endpoints()`. The open question is
      whether it should wait for the role above: without one, this is every
      operator able to disable every other.
- [ ] **The resolved filter policy, read-only.** `/ui/profiles` warns that an
      endpoint with `challenge.bypass` on has `[filter]` and nothing else
      between it and its clients, and then offers no way to read what that
      policy says. This is `filter show`, not `filter explain`, and the
      distinction is the whole of why it is proposable at all: the standing
      refusal of a web twin is about `explain` **executing** operator scripts
      and issuing IPAM and DNS requests against an address and names the caller
      chose, which behind a session is script execution plus SSRF from one
      stolen cookie. `show` builds the policy from configuration and reaches
      nothing outside the process. What needs deciding is the shape it renders
      in: `render_policy` (`src/filter/explain.rs`) is text and takes a
      `Palette`, and the re-parenthesized condition it prints is the part an
      operator came for — so either a JSON rendering lands beside it (the same
      one `filter show --json` wants) or the page grows its own.

## Admin CLI

- [ ] **Paged listings.** `account list` and `order list` pass `limit:
      i64::MAX` and print whatever comes back, where `audit list` has had
      `--limit`/`--offset` and the `N of M row(s)` line since it existed. The
      reason stated there — a table that grows a row per issuance for the life
      of the deployment — reaches orders within a year of a CA running, and the
      JSON API already pages all three and clamps to `admin.page_size_max`.
      `Account::search` and `Order::search` already return the unpaged total
      beside the page, so this is argument marshalling rather than a query.
      `GET /api/eab` belongs here from the other direction: it is the one list
      endpoint answering a **bare array** instead of `page_envelope`'s
      `{items, total, limit, offset}` — which the book documents as what lists
      return — over a table where revoking keeps the row.
- [ ] **Exit codes that distinguish.** `src/main.rs` exits `1` for a
      configuration error, a database that will not open, and every `CliError`
      alike, so a script cannot tell "no such order" from "the database is
      gone" — and only the second is worth retrying. `CliError` carries a
      message and nothing else, so this is a code on it plus one `match` in the
      single place that exits. What needs deciding is how many: the cheap split
      is "the operator asked for something that is not there" against "this
      server could not do it", and every code past those two is a surface that
      has to be documented and then kept, under the same pre-1.0 rule as the
      rest of the CLI.
- [ ] **The last few asymmetries**, one entry because each is a line of work and
      they share a shape — a thing one front end does that its twin cannot.
      `filter show --json`: `explain` has it, and a machine-readable policy is
      what a configuration check in CI would read. `admin user show`: the only
      listable object with no detail command. The issued chain on stdout:
      `GET /ui/orders/{id}/chain.pem` has no CLI twin, so a host holding the
      database goes through a browser for a PEM it already has. A nonce count:
      `GET /api/nonces` reports one, where the shell can only sweep. And
      `profile list`: `GET /api/profiles` names the endpoints actually mounted,
      and nothing on the host can ask.

## Both surfaces

- [ ] **An operator surface for the job queue, and for the relay's orders in
      flight.** Neither front end mentions `jobs` at all — the grep is empty
      outside `src/jobs/` — so "why is this order still `processing`?" ends at
      `sqlite3`, on the one subsystem whose whole purpose is surviving the
      failures an operator gets called about. `Job::find_by_id`, `find_live`,
      `count_live` and `cleanup` exist; what is missing is a `JobQuery` plus
      `Job::search` beside `Order::search` (kind, status, `dedup_key`, paged,
      with the unpaged total), and then `job list|show`, `GET /api/jobs` and
      `/ui/jobs`. `upstream_orders` is the same hole from the relay side and
      belongs in the same entry: its `error`, `request_id` and upstream URLs
      answer the other half of that question and are reachable from
      `src/signer/relay/` alone. Two mutations need deciding, and neither is
      obvious. **Run now** is a write to `run_at` and `status`, but `attempts`
      increments at *claim*, so a job that has spent its budget stays spent
      unless the button resets it — and resetting it is exactly what turns a
      permanently failing job into one that loops for ever. **Cancel** the
      schema is already waiting for: `20260815120000_add_jobs.sql` declares
      `status = 'cancelled'` as "retired by an operator. Nothing writes it
      yet", the `admin_sessions.state = 'pending_mfa'` treatment. `last_error`
      is text the far end wrote, so it lands under the panel's stored-XSS
      regression exactly as a `User-Agent` does.
- [ ] **Find the order from what the operator was handed.** Two questions
      neither surface answers: "which order covers `web.corp.example.com`", and
      "what is this serial out of an abuse report". `OrderQuery` filters
      profile, account and status. The identifier half is a predicate on
      `Order::search`'s existing `QueryBuilder` over the `orders.identifiers`
      JSON column — not a join to `authorizations`, which holds the same names
      one row at a time. The serial half is nearly free, and its absence is the
      odd part: `Order::find_by_cert_serial` already exists with no admin
      caller, while `audit list --cert-serial` and `GET /api/audit?certSerial=`
      both filter on exactly that value. What needs deciding on the identifier
      side is exact match against substring — `LIKE '%example.com%'` also
      matches `evil-example.com`, which is the wrong answer to give somebody
      hunting a misissuance — and whether it earns an index: SQLite has no
      expression index over `json_each`, so the honest options are a scan or a
      generated column in a new migration, and a scan is defensible for a long
      while.
- [ ] **The order renderings disagree about what an order is.**
      `orders.cert_serial` is printed by **nothing** — not `render_order_json`,
      not `render_order_detail_text`, not the panel's card — while two filters
      accept it, so an operator can search the audit trail by a serial the rest
      of the tooling will not tell them. And `render_order_detail_text` prints
      six fields and the authorization tree where its own `--json` carries
      `createdAt`, `certNotAfter`, `revokedAt`, `revocationReason` and the
      chain: `doc/src/operations/cli.md` already tells operators that `order
      show` surfaces `revokedAt` and `revocationReason`, which today only
      `--json` does. What needs deciding is whether the text rendering tracks
      the JSON field for field, or stays a summary with the difference stated
      in the book. The split that put the text renderers in `src/cli/render.rs`
      was about a `Palette` being structurally unable to reach a `--json`
      shape; it says nothing about the two carrying different *fields*, and
      that is being chosen here rather than inherited.
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
      the operator. Every existing `NotifyEvent` goes wherever the backend is
      configured to send; this would be the first whose recipient comes out of
      the data, and `EmailNotifier` holds a fixed `to` with no per-event path.
      Two things come with it: a contact is unverified text a client typed, so
      an opt-in default and a domain allowlist are the price of turning it on;
      and the digest shape means one mail **per account** listing that
      account's own names, which is a different grouping from the
      whole-profile digest an operator gets — not the same message resent to
      everybody named in it.
