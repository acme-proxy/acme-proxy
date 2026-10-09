-- Web-admin operators vouched for by an OpenID Connect provider or an LDAP
-- directory, and the state of an OpenID Connect sign-in in flight. The
-- reasoning is in the SQLite twin,
-- migrations/20261009120000_admin_external_identities.sql.

-- NULL is a local operator; otherwise `oidc:<name>` or `ldap:<name>`.
ALTER TABLE admin_users ADD COLUMN auth_provider text;
-- The provider's rename-proof name for the person.
ALTER TABLE admin_users ADD COLUMN external_id text;

CREATE UNIQUE INDEX idx_admin_users_external
    ON admin_users (auth_provider, external_id) WHERE auth_provider IS NOT NULL;

-- Consumed (deleted) by the callback, so a `state` is good once.
CREATE TABLE admin_oidc_logins
(
    state_hash    text PRIMARY KEY NOT NULL,
    provider      text   NOT NULL,
    binding_hash  text   NOT NULL,
    nonce         text   NOT NULL,
    pkce_verifier text   NOT NULL,
    created_at    bigint NOT NULL,
    expires_at    bigint NOT NULL
);

CREATE INDEX idx_admin_oidc_logins_expires_at ON admin_oidc_logins (expires_at);
