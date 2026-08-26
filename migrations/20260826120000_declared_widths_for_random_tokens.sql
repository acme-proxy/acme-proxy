-- The declared width of the two columns holding a `random_token()` value.
--
-- `nonces.value` and `challenges.token` hold the same thing: 32 bytes from the
-- system CSPRNG, base64url-encoded without padding, which is 43 characters
-- (`src/random.rs`). Neither column said so. `nonces.value` was declared
-- VARCHAR(36) -- accurate while the nonce was a UUID v4, false from the moment
-- it became a CSPRNG token -- and `challenges.token` was declared a bare
-- VARCHAR, which claims nothing at all.
--
-- SQLite gives both TEXT affinity and enforces no length, so nothing here
-- changes what the server stores or accepts. That is why the width was left
-- alone when the nonce changed, and it is the wrong way round: the declaration
-- is what an operator reads out of `.schema`, what a port to another dialect
-- transcribes (Postgres *does* enforce `varchar(n)`, and would have rejected
-- every nonce this mints), and it lives in the one set of files this project
-- freezes. A width that no longer matches the data is a defect whether or not
-- the engine checks it -- and "the width does not matter" is precisely the
-- reasoning that let VARCHAR(36) survive the switch away from UUIDs.
--
-- 43 is derived from TOKEN_BYTES in `src/random.rs`. Changing that constant
-- means a new migration here, and `declared_token_widths_match_random_token`
-- (`src/sqlite/db.rs`) fails first if one is not written.
--
-- SQLite cannot alter a column's declared type, so both are table rebuilds --
-- the 20260727120000_indexes_and_constraints.sql shape, with the two traps
-- that file also had to handle: a DROP takes the table's indexes with it, and
-- an INSERT ... SELECT silently drops any column it does not name.

-- Column order is load-bearing here: `Nonce::save` binds
-- `INSERT INTO nonces VALUES (?, ?)` positionally.
CREATE TABLE nonces_new
(
    value      VARCHAR(43) PRIMARY KEY NOT NULL,
    created_at INTEGER NOT NULL
);
INSERT INTO nonces_new SELECT value, created_at FROM nonces;
DROP TABLE nonces;
ALTER TABLE nonces_new RENAME TO nonces;
-- Re-created, not inherited: the index is declared in 20260727120000, which
-- will not run again, and the DROP above took it. Without it `Nonce::verify`'s
-- freshness predicate scans a table that gains a row per HTTP response.
CREATE INDEX idx_nonces_created_at ON nonces (created_at);

-- Eight columns, `error` last because 20260727180000_challenge_error.sql
-- appended it -- the order the SELECT below has to reproduce.
CREATE TABLE challenges_new
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    authz_id   VARCHAR(36) NOT NULL,
    type       VARCHAR NOT NULL CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    token      VARCHAR(43) NOT NULL,
    status     VARCHAR NOT NULL
                   CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated  INTEGER,                   -- epoch seconds, nullable (set on validation)
    created_at INTEGER NOT NULL,
    error      TEXT,                      -- RFC 8555 §8 problem document, nullable
    FOREIGN KEY (authz_id) REFERENCES authorizations(id) ON DELETE CASCADE,
    UNIQUE (authz_id, type)
);
INSERT INTO challenges_new
    SELECT id, authz_id, type, token, status, validated, created_at, error
    FROM challenges;
-- Safe under `foreign_keys = ON` (pinned by `Database::connect`): `challenges`
-- is a child and nothing references it, so the implicit delete a DROP performs
-- has no child rows of its own to orphan.
DROP TABLE challenges;
ALTER TABLE challenges_new RENAME TO challenges;
CREATE INDEX idx_challenges_authz ON challenges (authz_id);
