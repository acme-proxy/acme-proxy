-- The PostgreSQL schema, as one file.
--
-- This is deliberately **not** a transcription of `../migrations/`. Those 22
-- files carry their own history: three table rebuilds that exist only because
-- SQLite cannot add a `CHECK`, a `UNIQUE` or a foreign key to an existing
-- table, and one that converted every id column from text to bytes. Replaying
-- that here would be archaeology, not a schema — PostgreSQL has had
-- `ALTER TABLE ... ADD CONSTRAINT` all along, and no deployment of this
-- backend has ever held a v4 text id to convert.
--
-- What *is* transcribed literally is every declared width. SQLite gives
-- `VARCHAR(n)` TEXT affinity and enforces no length, so a width that had
-- drifted from what the column holds stayed wrong and invisible there;
-- PostgreSQL enforces it and would reject the row. `nonces.value` was that
-- case, and `declared_token_widths_match_random_token` (`src/db.rs`) is what
-- keeps the two token columns honest as `TOKEN_BYTES` moves.
--
-- Type mapping, once, so the rest of the file reads as a schema:
--
--   SQLite                            PostgreSQL
--   BLOB (a row id)                   uuid        -- sqlx maps `Uuid` to both
--   BLOB (key material, DER)          bytea
--   INTEGER (always epoch seconds)    bigint
--   INTEGER PRIMARY KEY AUTOINCREMENT bigint GENERATED ALWAYS AS IDENTITY
--   VARCHAR with no width             text
--   VARCHAR(n)                        varchar(n)  -- widths kept, see above
--   BOOLEAN                           boolean
--
-- This file is frozen from its first release, on the same append-only rule as
-- the SQLite set: see ADR 0003.

-- Anti-replay tokens. 43 characters is `random_token()`'s length; the pin is
-- `declared_token_widths_match_random_token`.
CREATE TABLE nonces
(
    value      varchar(43) PRIMARY KEY NOT NULL,
    created_at bigint NOT NULL
);

CREATE INDEX idx_nonces_created_at ON nonces (created_at);

-- An ACME account, keyed by (profile, pubkey): one client key presenting
-- itself at two endpoints is two independent accounts. That is a security
-- property, not tidiness -- see `doc/src/core/profiles.md`.
CREATE TABLE accounts
(
    id                      uuid PRIMARY KEY NOT NULL,
    profile                 text NOT NULL,
    pubkey                  bytea NOT NULL,
    contact                 text NOT NULL,
    status                  text NOT NULL DEFAULT 'valid'
                              CHECK (status IN ('valid', 'deactivated', 'revoked')),
    created_at              bigint NOT NULL,
    created_ip              text,
    created_ptr             text,
    last_seen_at            bigint,
    last_seen_ip            text,
    last_seen_ptr           text,
    -- No foreign key to `eab_keys`, deliberately: an EAB credential is
    -- revocable and the account outlives it.
    eab_kid                 uuid,
    terms_of_service_agreed boolean,
    -- Named rather than left to PostgreSQL's default spelling, because
    -- `Account::is_pubkey_conflict` matches on this name.
    CONSTRAINT accounts_profile_pubkey_key UNIQUE (profile, pubkey)
);

CREATE INDEX idx_accounts_eab_kid ON accounts (eab_kid);

CREATE TABLE orders
(
    id                uuid PRIMARY KEY NOT NULL,
    profile           text NOT NULL,
    account_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    status            text NOT NULL
                        CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers       text NOT NULL,
    expires           bigint NOT NULL,
    not_before        bigint,
    -- The validity the *client asked for*; `cert_not_after` is what the issued
    -- leaf says. Neither is the order object's own `expires`.
    not_after         bigint,
    error             text,
    certificate       text,
    -- An RFC 9773 section 5 certID, not an id of ours: stays text.
    replaces          text,
    created_at        bigint NOT NULL,
    created_ip        text,
    created_ptr       text,
    cert_serial       text,
    cert_pubkey       bytea,
    revoked_at        bigint,
    revocation_reason bigint,
    -- Three meaningful states: an epoch second, NULL (issued before the column
    -- existed, backfilled by the sweep), or a negative sentinel (the sweep
    -- looked and the chain would not parse).
    cert_not_after    bigint
);

CREATE INDEX idx_orders_account_id ON orders (account_id);
CREATE INDEX idx_orders_profile ON orders (profile);
CREATE INDEX idx_orders_cert_serial ON orders (profile, cert_serial);
CREATE INDEX idx_orders_created_at ON orders (created_at);
CREATE INDEX idx_orders_status_created_at ON orders (status, created_at);

-- Not a lookup index: RFC 9773 section 5's "already replaced?" rule enforced in
-- SQL, which is what makes `409 alreadyReplaced` race-free and what lets an
-- order that fails release its claim. `is_replaces_conflict` matches this name.
CREATE UNIQUE INDEX idx_orders_replaces_claim
    ON orders (profile, replaces)
    WHERE replaces IS NOT NULL AND status != 'invalid';

-- The expiry digest's own predicate.
CREATE INDEX idx_orders_cert_not_after ON orders (profile, cert_not_after)
    WHERE certificate IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE authorizations
(
    id         uuid PRIMARY KEY NOT NULL,
    order_id   uuid NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    identifier text NOT NULL,
    status     text NOT NULL
                 CHECK (status IN ('pending', 'valid', 'invalid',
                                   'deactivated', 'expired', 'revoked')),
    expires    bigint NOT NULL,
    created_at bigint NOT NULL,
    UNIQUE (order_id, identifier)
);

CREATE INDEX idx_authorizations_order ON authorizations (order_id);

CREATE TABLE challenges
(
    id         uuid PRIMARY KEY NOT NULL,
    authz_id   uuid NOT NULL REFERENCES authorizations (id) ON DELETE CASCADE,
    type       text NOT NULL CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    -- Same value as `nonces.value`, so the same width and the same pin.
    token      varchar(43) NOT NULL,
    status     text NOT NULL
                 CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated  bigint,
    created_at bigint NOT NULL,
    error      text,
    UNIQUE (authz_id, type)
);

CREATE INDEX idx_challenges_authz ON challenges (authz_id);

CREATE TABLE upstream_orders
(
    -- Primary key and foreign key at once, which is what stops two finalize
    -- requests both opening an upstream order.
    order_id                 uuid PRIMARY KEY REFERENCES orders (id) ON DELETE CASCADE,
    upstream_order_url       text NOT NULL,
    upstream_finalize_url    text,
    upstream_certificate_url text,
    csr_der                  bytea NOT NULL,
    status                   text NOT NULL
                               CHECK (status IN ('processing', 'valid', 'invalid')),
    error                    text,
    created_at               bigint NOT NULL,
    updated_at               bigint NOT NULL,
    -- Parked request context, so the job that finishes the order can write an
    -- audit row that says where the request came from.
    client_ip                text,
    client_ptr               text,
    user_agent               text,
    request_id               text
);

CREATE INDEX idx_upstream_orders_status ON upstream_orders (status);

-- External account binding credentials. `secret` is raw and retrievable on
-- purpose: HMAC verification needs the same bytes back on every request.
-- A NULL `profile` means "valid at every endpoint", not "unknown".
CREATE TABLE eab_keys
(
    kid        uuid PRIMARY KEY NOT NULL,
    secret     bytea NOT NULL,
    label      text,
    profile    text,
    status     text NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'revoked')),
    created_at bigint NOT NULL
);

-- The admin island: an operator of this server, never joined to `accounts`,
-- which is a client key that asks it for certificates.
CREATE TABLE admin_users
(
    id                  uuid PRIMARY KEY NOT NULL,
    username            text NOT NULL UNIQUE,
    -- One-way KDF. No code path reads it back.
    password_hash       text NOT NULL,
    status              text NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'disabled')),
    -- Plaintext on purpose: verification recomputes the HMAC, so the server
    -- needs the same bytes every attempt. `eab_keys.secret`'s situation, not a
    -- password's.
    totp_secret         bytea,
    totp_pending_secret bytea,
    totp_last_step      bigint,
    created_at          bigint NOT NULL,
    updated_at          bigint NOT NULL,
    last_login_at       bigint,
    -- No CHECK: `crate::admin_user::AdminRole` is the authority, and NULL
    -- reads as admin.
    role                text,
    contact_email       text,
    -- The last five distinct sign-in addresses. The one forensic column that
    -- is ever compared, and only to decide whether to send a message.
    known_login_ips     text NOT NULL DEFAULT '[]'
);

CREATE TABLE admin_sessions
(
    -- hex(SHA-256(token)), no KDF: a 256-bit CSPRNG token has no dictionary to
    -- slow down. The hash exists so a database read yields nothing replayable.
    token_hash   text PRIMARY KEY NOT NULL,
    user_id      uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    csrf_token   text NOT NULL,
    state        text NOT NULL DEFAULT 'active'
                   CHECK (state IN ('pending_mfa', 'active')),
    mfa_attempts bigint NOT NULL DEFAULT 0,
    created_at   bigint NOT NULL,
    expires_at   bigint NOT NULL,
    last_seen_at bigint NOT NULL,
    created_ip   text,
    user_agent   text
);

CREATE INDEX idx_admin_sessions_user_id ON admin_sessions (user_id);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions (expires_at);

-- A table rather than a JSON column so that consuming one is
-- `UPDATE ... WHERE id = ? AND used_at IS NULL` with `rows_affected` deciding
-- a race. `used_at` is stamped rather than deleted, so "7 of 10 remaining" is
-- a count and a spent code leaves a trail.
CREATE TABLE admin_recovery_codes
(
    id         uuid PRIMARY KEY NOT NULL,
    user_id    uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    created_at bigint NOT NULL,
    used_at    bigint
);

CREATE INDEX idx_admin_recovery_codes_user_id ON admin_recovery_codes (user_id);

-- The job queue is generic and has no foreign key: `payload` names whatever
-- `kind` means, so a typed key would be wrong for every other kind.
CREATE TABLE jobs
(
    id           uuid PRIMARY KEY NOT NULL,
    -- No CHECK: a kind is registered in code by whichever subsystem owns it,
    -- and the runner claims only the kinds its registry holds, so an
    -- unrecognised one is left alone rather than mis-run.
    kind         text NOT NULL,
    dedup_key    text NOT NULL,
    payload      text NOT NULL DEFAULT '{}',
    status       text NOT NULL
                   CHECK (status IN ('ready', 'running', 'done', 'failed', 'cancelled')),
    run_at       bigint NOT NULL,
    -- Incremented when the row is claimed, not when it completes, so a job
    -- that reliably kills the process still exhausts its budget.
    attempts     bigint NOT NULL DEFAULT 0,
    max_attempts bigint NOT NULL,
    deadline     bigint,
    lease_until  bigint,
    lease_owner  text,
    last_error   text,
    created_at   bigint NOT NULL,
    updated_at   bigint NOT NULL
);

-- Partial on purpose: only a live job holds an identity. A plain UNIQUE would
-- let one finished job block its own key for ever.
CREATE UNIQUE INDEX idx_jobs_identity
    ON jobs (kind, dedup_key) WHERE status IN ('ready', 'running');
CREATE INDEX idx_jobs_claim ON jobs (status, run_at);
CREATE INDEX idx_jobs_lease ON jobs (status, lease_until);
CREATE INDEX idx_jobs_retention ON jobs (status, updated_at);

-- Evidence, so no foreign keys: an audit row has to survive the account or
-- order it describes being deleted. The identifiers are frozen into the row
-- for the same reason, rather than read back through a join that may no longer
-- resolve. Rows are only ever INSERTed; the retention sweep is the only
-- statement that removes anything.
CREATE TABLE audit_log
(
    -- An operator types this id. `GENERATED ALWAYS AS IDENTITY` is what stops
    -- the id of a purged row being handed out a second time -- the property
    -- AUTOINCREMENT buys on SQLite.
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  bigint NOT NULL,
    -- No CHECK: `crate::audit::AuditEvent` is the authority.
    event       text NOT NULL,
    -- Denormalized from `event` at insert, via `AuditEvent::outcome`, so "show
    -- me everything that was refused" is an index lookup.
    outcome     text NOT NULL CHECK (outcome IN ('success', 'failure')),
    -- The ACME endpoint, or '' for an action not scoped to one.
    profile     text NOT NULL,
    actor_kind  text NOT NULL
                  CHECK (actor_kind IN ('acme', 'admin', 'cli', 'system')),
    actor_id    text,
    -- Names a row that may already be gone, so text rather than uuid -- the
    -- two deliberate exceptions in `every_id_column_is_declared_a_blob`.
    account_id  varchar(36),
    order_id    varchar(36),
    cert_serial text,
    identifiers text NOT NULL DEFAULT '[]',
    client_ip   text,
    client_ptr  text,
    user_agent  text,
    request_id  text,
    -- On a certificate failure, the RFC 8555 problem type; on a revocation,
    -- the RFC 5280 reason code. On an administrative action, unused.
    reason      text,
    detail      text
);

CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_account_id ON audit_log (account_id);
CREATE INDEX idx_audit_log_cert_serial ON audit_log (cert_serial);

-- A local CA's revocation ledger. No foreign key to `orders`, for `audit_log`'s
-- reason: a revocation must outlive an order an operator deletes, or the serial
-- would drop off the CRL.
CREATE TABLE revocations
(
    issuer     varchar(64) NOT NULL,
    serial     text NOT NULL,
    -- The *first* revocation of a serial is the one kept: a repeat is an
    -- `INSERT ... ON CONFLICT DO NOTHING`, so neither its time nor its reason
    -- can be rewritten after the fact.
    revoked_at bigint NOT NULL,
    -- RFC 5280 section 5.3.1 CRLReason, NULL for none. Validated in Rust.
    reason     bigint,
    -- The revoked certificate's own notAfter. **NULL is never pruned**: an
    -- unknown expiry is not an expired one.
    not_after  bigint,
    PRIMARY KEY (issuer, serial)
);

CREATE INDEX idx_revocations_issuer_not_after ON revocations (issuer, not_after);

CREATE TABLE crls
(
    issuer      varchar(64) PRIMARY KEY NOT NULL,
    -- Moves only by compare-and-swap, which is what keeps it monotonic across
    -- processes.
    crl_number  bigint NOT NULL,
    der         bytea NOT NULL,
    this_update bigint NOT NULL,
    next_update bigint NOT NULL
);

-- The relay's parked http-01 responses. State every role process shares.
CREATE TABLE http01_tokens
(
    token             text PRIMARY KEY NOT NULL,
    -- `<token>.<this proxy's account thumbprint at the upstream>`, served
    -- verbatim.
    key_authorization text NOT NULL,
    created_at        bigint NOT NULL,
    -- A backstop, swept hourly. A lookup ignores a row at or past it.
    expires_at        bigint NOT NULL
);

CREATE INDEX idx_http01_tokens_expires_at ON http01_tokens (expires_at);
