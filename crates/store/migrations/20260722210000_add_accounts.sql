-- `profile` names the ACME endpoint (`[profiles.<name>]`, served under
-- /profile/<name>) the account was registered at. Accounts are keyed
-- UNIQUE(profile, pubkey), not UNIQUE(pubkey): the same client key at two
-- profiles is two accounts, with independent status, contact and EAB
-- provenance. Without that, an account created at a permissive endpoint would
-- be usable at a stricter one -- bypassing its `eab.enabled`, and carrying its
-- orders across.
-- The five `*_ip` / `*_ptr` / `last_seen_at` columns are traceability, not
-- authorisation: nothing in the request path ever compares against them, for
-- the same reason `admin_sessions.created_ip` does not (pinning an identity to
-- an address breaks every CGNAT and mobile client). They answer "where was this
-- account registered from, and where was it last used from" -- the question an
-- operator asks about a key they did not expect to see.
--
-- `*_ptr` is the reverse-DNS name for the address at that moment, best-effort:
-- NULL means no PTR record, a resolver failure, a timeout, or
-- `audit.reverse_dns = false`. Frozen at write time rather than resolved at
-- read time, because the answer a month later is not the answer that mattered.
CREATE TABLE IF NOT EXISTS accounts
(
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    profile      VARCHAR NOT NULL,
    pubkey       BLOB NOT NULL,
    contact      TEXT NOT NULL,
    status       VARCHAR NOT NULL DEFAULT 'valid',
    created_at   INTEGER NOT NULL,
    created_ip   TEXT,
    created_ptr  TEXT,
    -- Advanced by `Account::touch` on any request this key authenticated, at
    -- most once per `ACCOUNT_TOUCH_INTERVAL` -- every ACME POST already writes
    -- a nonce row, and an unthrottled UPDATE here would double that on the
    -- polling traffic that dominates a real deployment. The throttle is skipped
    -- when the address changed, which is the one case the delay would hide.
    last_seen_at  INTEGER,
    last_seen_ip  TEXT,
    last_seen_ptr TEXT,
    UNIQUE (profile, pubkey)
);
