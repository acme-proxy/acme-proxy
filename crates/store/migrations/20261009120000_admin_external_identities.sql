-- Web-admin operators whose identity lives in an OpenID Connect provider or an
-- LDAP directory rather than in this table, and the short-lived state of an
-- OpenID Connect sign-in between the redirect out and the callback back.
--
-- `auth_provider` -- NULL is a local operator (a password, and optionally a
-- TOTP factor, held here). Otherwise `oidc:<name>` or `ldap:<name>`, naming the
-- `[admin.auth.oidc.<name>]` / `[admin.auth.ldap.<name>]` table that vouches
-- for them. No CHECK: the configured providers are the authority, and a row
-- naming one that is no longer configured is refused at sign-in rather than by
-- the schema (the `AdminRole` precedent).
--
-- `external_id` -- the provider's stable name for the person, which survives a
-- rename: an OpenID Connect `iss` and `sub`, or a directory's `objectGUID` /
-- `entryUUID`. Matched on, never displayed.
--
-- `password_hash` stays NOT NULL: an external operator holds a sentinel no
-- encoding produces, and `admin::users::authenticate` refuses them by
-- `auth_provider` before the hash is ever read. Dropping the NOT NULL would be
-- a table rebuild with two cascading children for a column nothing would read.
--
-- Two plain ADD COLUMNs and a partial unique index, so no rebuild: the shape
-- 20260908120000_add_admin_user_contact.sql and
-- 20260731120000_unique_replaces_claim.sql established. The index is what makes
-- "the same person signing in twice at once" provision one operator, not two.
ALTER TABLE admin_users ADD COLUMN auth_provider TEXT;
ALTER TABLE admin_users ADD COLUMN external_id   TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_external
    ON admin_users (auth_provider, external_id) WHERE auth_provider IS NOT NULL;

-- One OpenID Connect sign-in in flight. Written when the browser is sent to the
-- provider, consumed -- deleted -- by the callback that brings it back, so a
-- `state` value is good for exactly one callback.
--
-- In the database rather than in a signed cookie for ADR 0008's reason: the
-- admin process that sent the browser out need not be the one it returns to.
-- Every secret is stored hashed or is useless without the browser's cookie:
--
-- * `state_hash` -- hex(SHA-256(state)). `state` travels in the URL both ways,
--   so the key must not be replayable from a database read.
-- * `binding_hash` -- hex(SHA-256(the `__Host-acme_admin_oidc` cookie)). Ties
--   the callback to the browser that started the sign-in (login CSRF).
-- * `nonce` and `pkce_verifier` -- needed in clear at the callback, and worth
--   nothing without an authorization code only the browser holds.
--
-- `expires_at` bounds a sign-in abandoned at the provider; the session sweep
-- deletes rows past it, and the callback refuses one.
CREATE TABLE IF NOT EXISTS admin_oidc_logins
(
    state_hash    TEXT PRIMARY KEY NOT NULL,
    provider      TEXT    NOT NULL,
    binding_hash  TEXT    NOT NULL,
    nonce         TEXT    NOT NULL,
    pkce_verifier TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);

-- The sweep: `expires_at <= ?`.
CREATE INDEX IF NOT EXISTS idx_admin_oidc_logins_expires_at ON admin_oidc_logins (expires_at);
