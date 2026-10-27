-- The ACME profile (draft-ietf-acme-profiles) an order is issued under: the
-- one its client named in `newOrder`, the backend's default, or the one a relay
-- forces. NULL when the backend offers no profiles, which is every order
-- placed before this column existed.
--
-- No CHECK: a profile name is the backend's vocabulary (a `local_ca`'s
-- `[signer.local_ca.profiles.<name>]`, or whatever the upstream CA advertises
-- for a relay), checked against it at `newOrder`.
ALTER TABLE orders ADD COLUMN profile TEXT;
