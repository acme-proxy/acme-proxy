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

- [ ] **ACME replay nonces are a UUID v4** — 122 bits, from `Uuid::new_v4()` in
      `src/sqlite/nonce.rs`, where every other non-guessable value in the tree
      is 256 bits out of `ring::rand::SystemRandom`. ASVS **V11.5.1** names
      UUIDs explicitly as not meeting its bar, and the fix is
      `authz::generate_token`'s four lines applied here. Guessing a nonce is
      worthless without an account key to sign with it, so this is a
      consistency defect rather than an
      exploitable one — which is exactly why it should be cheap: `value` is a
      `String` column with no format constraint, so nothing migrates.

- [ ] **A last-resort handler for a panicking handler** — ASVS **V16.5.4**. A
      panic in a route aborts that connection's task with no response at all;
      the process survives (`panic = "abort"` is deliberately not set) and the
      panic is logged, but the client sees a transport error where every other
      refusal this server makes is an `application/problem+json` document.
      `tower_http`'s `CatchPanicLayer` is the shape, and the open question is
      the same one `build_router`'s two fallbacks already answered: the ACME
      listener needs a problem document and the admin listener needs its own
      error shape, so it is one layer per router and not one shared constructor.

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
- [ ] **A role on `admin_users`, so a session that reads is not a session that
      revokes.** ASVS **V7.5.3** and **V8.4.2** both land here: revocation and
      account deletion take a live session and nothing further. There is one
      kind of operator, and every live session can
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
- [ ] **Operators and sessions, in the panel** — also ASVS **V7.5.2**, which
      wants an operator able to *see* their own live sessions and not only end
      them all at once. `admin user
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

- [ ] **Passwords are checked for length and nothing else.** ASVS **V6.2.4**
      (L1) wants a check against the top 3000 common passwords, **V6.2.12**
      against a breach corpus, and **V6.1.2**/**V6.2.11** against a documented
      list of context-specific words — "acme", "proxy", the CA subject, the
      deployment's hostname. `check_password_policy` in `src/admin/password.rs`
      is the single place all of it goes, and it is already the one function
      both front ends call. This is the assessment's only **L1** gap.
      What needs deciding is the corpus: a compiled-in list costs binary size
      for every deployment including the ones with `admin.enabled = false`, and
      a k-anonymity lookup against an online range API costs an outbound
      dependency on a credential path — which is the sort of thing
      [the security model](doc/src/security/index.md) would then have to name.
      The context list is free either way and should not wait for the answer.

- [ ] **No password change in the panel** — ASVS **V6.2.2** (L1). `admin user
      passwd` on the host is the only path, so an operator with no shell cannot
      rotate their own password, and "create and `passwd` deliberately stay on
      the host" was a rule about *minting* a credential rather than about
      rotating one you already hold. Two things come with it, and neither is
      optional: the route goes behind `check_step_up` like the second-factor
      routes, and it must take the **current** password as well as the new one
      (**V6.2.3**) — the CLI does not, and does not need to, because it answers
      to a process that can already rewrite the row. `users::set_password`
      already revokes every session of that user, which is the half that is
      easy to forget.

## Admin CLI

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
      `admin user show`: the only listable object with no detail command. The
      issued chain on stdout: `GET /ui/orders/{id}/chain.pem` has no CLI twin,
      so a host holding the database goes through a browser for a PEM it
      already has. A nonce count:
      `GET /api/nonces` reports one, where the shell can only sweep. And
      `profile list`: `GET /api/profiles` names the endpoints actually mounted,
      and nothing on the host can ask. Paging the listings left two more of the
      same shape: `eab list`, `admin user list` and `admin session list` are the
      three CLI listings still answering a **bare array** with no window, and
      `/ui/eab` is unpaged where `GET /api/eab` now windows — `Eab::search`
      exists, so that page is a `PageParams` plus the `pager` the accounts and
      orders templates already use. Each is defensible alone (an operator mints
      those rows by hand, a few at a time) and indefensible as a set, which is
      the argument for doing them together or not at all.

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

## Packaging & supply chain

- [ ] **No SBOM ships with a release** — ASVS **V15.1.2**. The substance is
      already there: `Cargo.lock` pins every transitive dependency and the
      `Advisories, licenses & sources` CI job runs `cargo deny` over licences,
      advisories and registries with `all-features = true`. What is missing is
      the artifact, so a consumer asking "is this build affected by RUSTSEC-…"
      has to reconstruct the graph from the tree. `cargo cyclonedx` or
      `cargo sbom` in the release workflow, attached to the GitHub release
      beside the binary, is the whole job.

- [ ] **The `Containerfile` sets no `USER`** — ASVS **V13.2.2**. It says on its
      first line that it builds the image for the e2e lab, and for that purpose
      root is unremarkable; but
      [Deployment](doc/src/getting_started/deployment.md) points container
      deployments at the same file, and the systemd path right beside it goes to
      the trouble of a dedicated `acme-proxy` user. A `USER` directive plus
      ownership of the data directory closes it. The decision that comes first
      is whether the root `Containerfile` is a lab artifact that the docs should
      stop recommending, or a deployment artifact that should be hardened —
      not both.

- [ ] **No rotation schedule for any secret** — ASVS **V13.1.4**, and the reason
      **V11.1.1** is only half met. [The security
      model](doc/src/security/index.md) names every secret and what its
      compromise buys, and each one *can* be rotated — an EAB credential without
      a restart, the CA key by re-issuing an intermediate, a TSIG key in the
      environment. No page says how often any of them should be. This is
      documentation, not code, and it belongs beside the hardening checklist
      rather than inside it: a checklist item is something you do once before
      serving, and this is a cadence.

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

- [ ] **Nothing ever tells an *operator* anything** — ASVS **V6.3.5** and
      **V6.3.7**, both L3. Every sign-in, every failure, every second-factor
      change is logged with its address and outcome, and none of it reaches the
      person it happened to. The blocker is not the notifier, it is that
      `admin_users` records no contact address at all — so this is a column and
      a `MfaStep`-sized decision about what counts as suspicious, not a new
      subsystem. The `NotifyEvent` enum is where the events would go, and the
      per-account recipient problem is the same one the expiry-reminder item
      above already has to solve.
