-- The re-authentication an OpenID Connect sign-in in flight asked its provider
-- for: NULL for an ordinary sign-in, seconds for a step-up. The reasoning is in
-- the SQLite twin, migrations/20261010120000_admin_oidc_login_max_age.sql.
ALTER TABLE admin_oidc_logins ADD COLUMN max_age bigint;
