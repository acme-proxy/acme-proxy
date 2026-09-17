-- The key authorizations the `relay` signer backend publishes for its upstream
-- CA to fetch at `/.well-known/acme-challenge/{token}` (RFC 8555 §8.3).
--
-- They were held in memory by the backend that published them, which only
-- worked while the relay job publishing a token and the root router serving
-- it were the same process: a runner in one process and a listener in another,
-- or two instances behind one name, answered the upstream's fetch `404`. The
-- database is the store both already share.
--
-- **`expires_at` is the backstop, not the mechanism.** A token is retracted by
-- the attempt that published it as soon as the upstream has decided; a row
-- still here past `expires_at` belongs to an attempt that died before it could
-- retract, is never served, and is deleted by the sweep.
--
-- The token is the upstream's own random value and the secret §8.3 relies on,
-- which is why it is the key on its own and a lookup needs nothing else. No
-- foreign key: a row names an upstream's challenge, not anything of ours.
CREATE TABLE IF NOT EXISTS http01_tokens
(
    token             TEXT PRIMARY KEY NOT NULL,
    -- `<token>.<this proxy's account thumbprint at the upstream>`, served
    -- verbatim.
    key_authorization TEXT    NOT NULL,
    created_at        INTEGER NOT NULL,
    -- Epoch seconds. A lookup ignores a row at or past it.
    expires_at        INTEGER NOT NULL
);

-- The sweep: `expires_at <= ?`.
CREATE INDEX IF NOT EXISTS idx_http01_tokens_expires_at ON http01_tokens (expires_at);
