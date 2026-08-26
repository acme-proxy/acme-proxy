-- Row ids stop being 36 characters of text and become the 16 bytes they are.
--
-- Every id this server mints is a UUID (`src/sqlite/id.rs`), and every column
-- holding one declared VARCHAR(36) and stored the hyphenated rendering. That is
-- 36 bytes where 16 carry the same value, in a primary key, in every foreign
-- key beside it, and in every index over either -- and a string comparison
-- where a memcmp would do. `sqlx`'s `uuid` feature encodes a `Uuid` as a BLOB
-- and decodes it with `Uuid::from_slice`, so the Rust side needs no conversion
-- and the same type maps to Postgres's native `uuid` when that backend lands.
--
-- Nothing an ACME client or an operator sees moves: an id is still rendered by
-- `Uuid::to_string`, so account URLs, `kid`s, order URLs and every admin API
-- member are byte-identical. What does move is an ad-hoc query -- `SELECT id
-- FROM accounts` now prints bytes, and wants `lower(hex(id))`.
--
-- This is written while no deployment exists to be careful of, which is the
-- only reason it is affordable at all: it rewrites ten tables, and the cost of
-- doing it later is the same work plus somebody's data.
--
-- Not converted, and each for its own reason:
--
--   * `audit_log.account_id` / `order_id` -- this table has no foreign keys on
--     purpose (a CASCADE would delete the evidence with its subject), so these
--     name a row that may be gone rather than pointing at one. Their
--     neighbours `actor_id` (an account id, an admin username, or absent) and
--     `request_id` (whatever a proxy sent) are free-form, all four are written
--     from one builder, and nothing joins on any of them. Typing two of the
--     four is the inconsistency, not the fix. That table is untouched here.
--   * `orders.replaces` -- an RFC 9773 §5 certID, not a UUID.
--   * `jobs.dedup_key` (composite strings that embed an id), `jobs.lease_owner`
--     (a per-process runner id), `upstream_orders.request_id`.
--   * `nonces.value`, `challenges.token`, `admin_sessions.token_hash` -- CSPRNG
--     tokens, whose widths 20260826120000 has just made honest.
--
-- THE HAZARD THIS FILE IS SHAPED AROUND.
--
-- `PRAGMA foreign_keys` is a no-op inside a transaction and sqlx wraps each
-- migration in one, so the pragma dance SQLite's own documentation gives for a
-- table rebuild is unavailable. Under `foreign_keys = ON` -- pinned by
-- `Database::connect` -- DROP TABLE performs an implicit DELETE FROM, which
-- fires ON DELETE CASCADE into every child. Dropping `accounts` therefore
-- deletes every order, silently and without an error.
--
-- 20260727120000_indexes_and_constraints.sql rebuilt these same tables parent
-- first and was safe only by accident: the constraints it was replacing had no
-- referential action yet. They all have one now, so that order cannot be
-- copied, and neither can child-first -- dropping `authorizations` would
-- cascade into a `challenges` already rebuilt.
--
-- So the data is parked first. `CREATE TABLE ... AS SELECT` produces a table
-- with no constraints, no foreign keys and no indexes, which is exactly what is
-- wanted: nothing can cascade into a staging copy. Then every original is
-- dropped, every table re-created with BLOB ids, and the rows put back parent
-- first so each foreign key resolves as it lands.
--
-- Two traps inherited from the rebuilds before this one. An INSERT ... SELECT
-- silently drops any column it does not name, so every column list below is
-- the table's *current* order, appended columns included (`challenges.error`
-- from 20260727180000, `accounts.eab_kid` from 20260727190000, the five
-- revocation and expiry columns on `orders`). And a DROP takes the table's
-- indexes with it: they are declared across five earlier migrations, none of
-- which will run again, so all seventeen are re-created at the end.
--
-- `unhex` (SQLite 3.41+; the bundled build is 3.51.3) returns NULL on anything
-- that is not hex, so an id that cannot be converted fails a NOT NULL primary
-- key rather than being quietly mangled. On the one nullable id column,
-- `accounts.eab_kid`, it would convert to NULL instead -- which is what
-- `the_blob_migration_preserves_every_row` (`src/sqlite/db.rs`) is for.

-- 1. Park every row somewhere no constraint reaches.
CREATE TABLE _mig_accounts             AS SELECT * FROM accounts;
CREATE TABLE _mig_orders               AS SELECT * FROM orders;
CREATE TABLE _mig_authorizations       AS SELECT * FROM authorizations;
CREATE TABLE _mig_challenges           AS SELECT * FROM challenges;
CREATE TABLE _mig_upstream_orders      AS SELECT * FROM upstream_orders;
CREATE TABLE _mig_eab_keys             AS SELECT * FROM eab_keys;
CREATE TABLE _mig_admin_users          AS SELECT * FROM admin_users;
CREATE TABLE _mig_admin_sessions       AS SELECT * FROM admin_sessions;
CREATE TABLE _mig_admin_recovery_codes AS SELECT * FROM admin_recovery_codes;
CREATE TABLE _mig_jobs                 AS SELECT * FROM jobs;

-- 2. Drop the originals. Order is immaterial now -- every cascade these fire
--    lands in a table that is itself about to go.
DROP TABLE challenges;
DROP TABLE authorizations;
DROP TABLE upstream_orders;
DROP TABLE orders;
DROP TABLE accounts;
DROP TABLE admin_recovery_codes;
DROP TABLE admin_sessions;
DROP TABLE admin_users;
DROP TABLE eab_keys;
DROP TABLE jobs;

-- 3. Re-create each, identical but for the id columns. Every CHECK, UNIQUE and
--    FOREIGN KEY below is carried over verbatim from the migration that last
--    defined it; see those files for why each exists.
CREATE TABLE accounts
(
    id         BLOB PRIMARY KEY NOT NULL,
    profile    VARCHAR NOT NULL,
    pubkey     BLOB NOT NULL,
    contact    TEXT NOT NULL,
    status     VARCHAR NOT NULL DEFAULT 'valid'
                   CHECK (status IN ('valid', 'deactivated', 'revoked')),
    created_at INTEGER NOT NULL,
    created_ip    TEXT,
    created_ptr   TEXT,
    last_seen_at  INTEGER,
    last_seen_ip  TEXT,
    last_seen_ptr TEXT,
    -- No foreign key to `eab_keys`, deliberately: see 20260727190000.
    eab_kid       BLOB,
    terms_of_service_agreed BOOLEAN,
    UNIQUE (profile, pubkey)
);

CREATE TABLE orders
(
    id          BLOB PRIMARY KEY NOT NULL,
    profile     VARCHAR NOT NULL,
    account_id  BLOB NOT NULL,
    status      VARCHAR NOT NULL
                    CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers TEXT NOT NULL,
    expires     INTEGER NOT NULL,
    not_before  INTEGER,
    not_after   INTEGER,
    error       TEXT,
    certificate TEXT,
    -- An RFC 9773 §5 certID, not an id of ours: stays TEXT.
    replaces    TEXT,
    created_at  INTEGER NOT NULL,
    created_ip  TEXT,
    created_ptr TEXT,
    cert_serial TEXT,
    cert_pubkey BLOB,
    revoked_at  INTEGER,
    revocation_reason INTEGER,
    cert_not_after    INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE authorizations
(
    id         BLOB PRIMARY KEY NOT NULL,
    order_id   BLOB NOT NULL,
    identifier TEXT NOT NULL,
    status     VARCHAR NOT NULL
                   CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked')),
    expires    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    UNIQUE (order_id, identifier)
);

CREATE TABLE challenges
(
    id         BLOB PRIMARY KEY NOT NULL,
    authz_id   BLOB NOT NULL,
    type       VARCHAR NOT NULL CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    token      VARCHAR(43) NOT NULL,
    status     VARCHAR NOT NULL
                   CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated  INTEGER,
    created_at INTEGER NOT NULL,
    error      TEXT,
    FOREIGN KEY (authz_id) REFERENCES authorizations(id) ON DELETE CASCADE,
    UNIQUE (authz_id, type)
);

CREATE TABLE upstream_orders
(
    -- Primary key and foreign key at once, which is what stops two finalize
    -- requests both opening an upstream order; see 20260730120000.
    order_id BLOB PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE,
    upstream_order_url TEXT NOT NULL,
    upstream_finalize_url TEXT,
    upstream_certificate_url TEXT,
    csr_der BLOB NOT NULL,
    status TEXT NOT NULL
                   CHECK (status IN ('processing', 'valid', 'invalid')),
    error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    client_ip TEXT,
    client_ptr TEXT,
    user_agent TEXT,
    request_id TEXT
);

CREATE TABLE eab_keys
(
    kid        BLOB PRIMARY KEY NOT NULL,
    secret     BLOB NOT NULL,
    label      TEXT,
    profile    VARCHAR,
    status     VARCHAR NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL
);

CREATE TABLE admin_users
(
    id            BLOB PRIMARY KEY NOT NULL,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status        VARCHAR NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'disabled')),
    totp_secret         BLOB,
    totp_pending_secret BLOB,
    totp_last_step      INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE admin_sessions
(
    -- The session's own key is a SHA-256 of the token and stays TEXT.
    token_hash    TEXT PRIMARY KEY NOT NULL,
    user_id       BLOB NOT NULL
                      REFERENCES admin_users (id) ON DELETE CASCADE,
    csrf_token    TEXT NOT NULL,
    state         VARCHAR NOT NULL DEFAULT 'active'
                      CHECK (state IN ('pending_mfa', 'active')),
    mfa_attempts  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    created_ip    TEXT,
    user_agent    TEXT
);

CREATE TABLE admin_recovery_codes
(
    id         BLOB PRIMARY KEY NOT NULL,
    user_id    BLOB NOT NULL
                   REFERENCES admin_users (id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE jobs
(
    id           BLOB PRIMARY KEY NOT NULL,
    kind         TEXT NOT NULL,
    dedup_key    TEXT NOT NULL,
    payload      TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL
                     CHECK (status IN ('ready', 'running', 'done', 'failed',
                                       'cancelled')),
    run_at       INTEGER NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    deadline     INTEGER,
    lease_until  INTEGER,
    lease_owner  TEXT,
    last_error   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

-- 4. Put the rows back, parents first, so every foreign key resolves as it
--    lands rather than at COMMIT.
INSERT INTO accounts
    SELECT unhex(replace(id, '-', '')), profile, pubkey, contact, status, created_at,
           created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr,
           unhex(replace(eab_kid, '-', '')), terms_of_service_agreed
    FROM _mig_accounts;

INSERT INTO orders
    SELECT unhex(replace(id, '-', '')), profile, unhex(replace(account_id, '-', '')),
           status, identifiers, expires, not_before, not_after, error, certificate,
           replaces, created_at, created_ip, created_ptr, cert_serial, cert_pubkey,
           revoked_at, revocation_reason, cert_not_after
    FROM _mig_orders;

INSERT INTO authorizations
    SELECT unhex(replace(id, '-', '')), unhex(replace(order_id, '-', '')),
           identifier, status, expires, created_at
    FROM _mig_authorizations;

INSERT INTO challenges
    SELECT unhex(replace(id, '-', '')), unhex(replace(authz_id, '-', '')),
           type, token, status, validated, created_at, error
    FROM _mig_challenges;

INSERT INTO upstream_orders
    SELECT unhex(replace(order_id, '-', '')), upstream_order_url,
           upstream_finalize_url, upstream_certificate_url, csr_der, status, error,
           created_at, updated_at, client_ip, client_ptr, user_agent, request_id
    FROM _mig_upstream_orders;

INSERT INTO eab_keys
    SELECT unhex(replace(kid, '-', '')), secret, label, profile, status, created_at
    FROM _mig_eab_keys;

INSERT INTO admin_users
    SELECT unhex(replace(id, '-', '')), username, password_hash, status,
           totp_secret, totp_pending_secret, totp_last_step,
           created_at, updated_at, last_login_at
    FROM _mig_admin_users;

INSERT INTO admin_sessions
    SELECT token_hash, unhex(replace(user_id, '-', '')), csrf_token, state,
           mfa_attempts, created_at, expires_at, last_seen_at, created_ip, user_agent
    FROM _mig_admin_sessions;

INSERT INTO admin_recovery_codes
    SELECT unhex(replace(id, '-', '')), unhex(replace(user_id, '-', '')),
           code_hash, created_at, used_at
    FROM _mig_admin_recovery_codes;

INSERT INTO jobs
    SELECT unhex(replace(id, '-', '')), kind, dedup_key, payload, status, run_at,
           attempts, max_attempts, deadline, lease_until, lease_owner, last_error,
           created_at, updated_at
    FROM _mig_jobs;

-- 5. Clear the staging away.
DROP TABLE _mig_accounts;
DROP TABLE _mig_orders;
DROP TABLE _mig_authorizations;
DROP TABLE _mig_challenges;
DROP TABLE _mig_upstream_orders;
DROP TABLE _mig_eab_keys;
DROP TABLE _mig_admin_users;
DROP TABLE _mig_admin_sessions;
DROP TABLE _mig_admin_recovery_codes;
DROP TABLE _mig_jobs;

-- 6. Every index the DROPs took, re-declared. `db.rs`'s
--    `migrations_create_the_expected_indexes` is what notices one left out.
CREATE INDEX idx_orders_account_id    ON orders (account_id);
CREATE INDEX idx_orders_profile       ON orders (profile);
CREATE INDEX idx_orders_cert_serial   ON orders (profile, cert_serial);
CREATE INDEX idx_orders_created_at    ON orders (created_at);
CREATE INDEX idx_orders_status_created_at ON orders (status, created_at);
CREATE UNIQUE INDEX idx_orders_replaces_claim
    ON orders (profile, replaces)
 WHERE replaces IS NOT NULL AND status != 'invalid';
CREATE INDEX idx_orders_cert_not_after ON orders (profile, cert_not_after)
    WHERE certificate IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX idx_authorizations_order ON authorizations (order_id);
CREATE INDEX idx_challenges_authz     ON challenges (authz_id);
CREATE INDEX idx_upstream_orders_status ON upstream_orders(status);
CREATE INDEX idx_admin_sessions_user_id    ON admin_sessions (user_id);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions (expires_at);
CREATE INDEX idx_admin_recovery_codes_user_id ON admin_recovery_codes (user_id);
CREATE UNIQUE INDEX idx_jobs_identity
    ON jobs (kind, dedup_key) WHERE status IN ('ready', 'running');
CREATE INDEX idx_jobs_claim     ON jobs (status, run_at);
CREATE INDEX idx_jobs_lease     ON jobs (status, lease_until);
CREATE INDEX idx_jobs_retention ON jobs (status, updated_at);
