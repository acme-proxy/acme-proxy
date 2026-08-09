-- Tightens the schema the four earlier migrations left loose:
--
--   * indexes on every foreign key (SQLite indexes only PRIMARY KEY and UNIQUE,
--     so each child lookup was a full table scan — including
--     `Authorization::find_by_order`, which runs on every order read and every
--     challenge trigger);
--   * `ON DELETE CASCADE`, so an account or order can actually be deleted; the
--     original constraints had no referential action, which blocked any
--     retention or cleanup work;
--   * `CHECK` constraints pinning the status columns to the state machines the
--     model docs describe. Transitions are written as raw string literals spread
--     across three modules, where a typo would otherwise produce a silently
--     unreachable state.
--
-- SQLite cannot add a constraint to an existing table, so the three tables with
-- foreign keys are rebuilt. `PRAGMA foreign_keys` is a no-op inside a
-- transaction, and sqlx wraps each migration in one; the rebuild is ordered
-- child-first / parent-last and re-inserts identical ids, so no reference is
-- ever dangling.

-- accounts: no foreign keys, so the status CHECK needs a rebuild of this table
-- alone.
CREATE TABLE accounts_new
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    profile    VARCHAR NOT NULL,
    pubkey     BLOB NOT NULL,
    contact    TEXT NOT NULL,
    status     VARCHAR NOT NULL DEFAULT 'valid'
                   CHECK (status IN ('valid', 'deactivated', 'revoked')),
    created_at INTEGER NOT NULL,
    -- Traceability; see 20260722210000_add_accounts.sql for why nothing ever
    -- compares against these and why the last three are throttled.
    created_ip    TEXT,
    created_ptr   TEXT,
    last_seen_at  INTEGER,
    last_seen_ip  TEXT,
    last_seen_ptr TEXT,
    -- One account per (endpoint, key); see 20260722210000_add_accounts.sql.
    UNIQUE (profile, pubkey)
);
INSERT INTO accounts_new
    SELECT id, profile, pubkey, contact, status, created_at,
           created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr
    FROM accounts;
DROP TABLE accounts;
ALTER TABLE accounts_new RENAME TO accounts;

CREATE TABLE orders_new
(
    id          VARCHAR(36) PRIMARY KEY NOT NULL,
    profile     VARCHAR NOT NULL,          -- the ACME endpoint this order was placed at
    account_id  VARCHAR(36) NOT NULL,
    status      VARCHAR NOT NULL           -- new orders start at 'pending'
                    CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers TEXT NOT NULL,             -- JSON array of {"type":"dns","value":"..."}
    expires     INTEGER NOT NULL,          -- epoch seconds
    not_before  INTEGER,                   -- epoch seconds, nullable
    not_after   INTEGER,                   -- epoch seconds, nullable
    error       TEXT,                      -- JSON problem doc, nullable
    certificate TEXT,                      -- PEM chain, nullable until issued
    replaces    TEXT,                      -- RFC 9773 §5 certID of the predecessor, nullable
    created_at  INTEGER NOT NULL,
    -- Traceability; see 20260725120000_add_orders.sql.
    created_ip  TEXT,
    created_ptr TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
INSERT INTO orders_new
    SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after,
           error, certificate, NULL, created_at, created_ip, created_ptr
    FROM orders;
DROP TABLE orders;
ALTER TABLE orders_new RENAME TO orders;

CREATE TABLE authorizations_new
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    order_id   VARCHAR(36) NOT NULL,
    identifier TEXT NOT NULL,             -- JSON {"type":"dns","value":"..."}
    status     VARCHAR NOT NULL           -- pending -> valid
                   CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked')),
    expires    INTEGER NOT NULL,          -- epoch seconds
    created_at INTEGER NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    -- One authorization per identifier per order. `newOrder` iterates the
    -- payload's identifiers verbatim, so a client repeating a name would
    -- otherwise create two rows for it — and the readiness check counts
    -- authorizations against identifiers.
    UNIQUE (order_id, identifier)
);
INSERT INTO authorizations_new
    SELECT id, order_id, identifier, status, expires, created_at FROM authorizations;
DROP TABLE authorizations;
ALTER TABLE authorizations_new RENAME TO authorizations;

CREATE TABLE challenges_new
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    authz_id   VARCHAR(36) NOT NULL,
    type       VARCHAR NOT NULL CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    token      VARCHAR NOT NULL,
    status     VARCHAR NOT NULL
                   CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated  INTEGER,                   -- epoch seconds, nullable (set on validation)
    created_at INTEGER NOT NULL,
    FOREIGN KEY (authz_id) REFERENCES authorizations(id) ON DELETE CASCADE,
    UNIQUE (authz_id, type)
);
INSERT INTO challenges_new
    SELECT id, authz_id, type, token, status, validated, created_at FROM challenges;
DROP TABLE challenges;
ALTER TABLE challenges_new RENAME TO challenges;

CREATE INDEX idx_orders_account_id    ON orders (account_id);
-- Scanned by `order list --profile` and by the restart sweep the `acme_proxy`
-- backend runs over its own profiles' in-flight orders.
CREATE INDEX idx_orders_profile       ON orders (profile);
-- Probed on every newOrder carrying a `replaces` (RFC 9773 §5), to answer
-- "has this predecessor already been replaced?" before accepting the order.
CREATE INDEX idx_orders_replaces      ON orders (profile, replaces);
CREATE INDEX idx_authorizations_order ON authorizations (order_id);
CREATE INDEX idx_challenges_authz     ON challenges (authz_id);
-- Probed by `Nonce::verify`'s freshness predicate on every signed request and
-- by `Nonce::cleanup`, against a table that gains a row per HTTP response.
CREATE INDEX idx_nonces_created_at    ON nonces (created_at);
