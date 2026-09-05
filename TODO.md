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
- [ ] **`admin session revoke --session <id>`.** The panel's Operators and
      Account pages can now revoke one session individually
      (`AdminSession::find_by_user_and_fingerprint`); the CLI's `revoke` still
      only takes `--user` (every session of one operator) or `--all` (every
      session on the server), which is coarser than what the web surface can
      do. Cheap to add — the model method already exists — and worth doing
      only if an operator working from a shell turns out to want the same
      granularity a browser now has.

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
