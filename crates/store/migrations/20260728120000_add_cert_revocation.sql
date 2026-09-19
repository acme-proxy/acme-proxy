-- RFC 8555 §7.6 certificate revocation (`POST /revokeCert`). Revocation is
-- orthogonal to the order state machine -- RFC 8555 defines no "revoked"
-- order status, so a revoked order's own `status` stays `valid` -- these four
-- columns track it independently of `status`.
--
-- `cert_serial`/`cert_pubkey` are populated once, at finalize time (alongside
-- `certificate`), from the leaf certificate the signer just issued:
--   * `cert_serial` (hex, no separators) is what a revoke request is looked
--     up by -- indexed below, so that lookup is not a full table scan.
--   * `cert_pubkey` (DER SPKI, the same encoding `accounts.pubkey` uses) is
--     compared byte-for-byte against a revoke request's own JWS-verified
--     `pubkey` -- RFC 8555 §7.6's second authorization case: the certificate's
--     own key pair, proving possession of its private key, with no account
--     involved at all.
--
-- `revoked_at`/`revocation_reason` are set once, by the revoke handler.
-- `revocation_reason` is nullable independently of `revoked_at` being set --
-- RFC 8555's `reason` field is itself optional.
--
-- A plain ADD COLUMN x4: none of the four carries a CHECK/UNIQUE/FK, so (like
-- 20260727180000_challenge_error.sql and 20260727190000_add_eab.sql) nothing
-- needs rebuilding.
ALTER TABLE orders ADD COLUMN cert_serial TEXT;
ALTER TABLE orders ADD COLUMN cert_pubkey BLOB;
ALTER TABLE orders ADD COLUMN revoked_at INTEGER;
ALTER TABLE orders ADD COLUMN revocation_reason INTEGER;

-- Looked up by `POST /revokeCert` on every request; SQLite indexes only
-- PRIMARY KEY/UNIQUE columns, so without this every revocation is a full
-- table scan across every issued order -- the lesson idx_orders_account_id
-- and friends already paid for once (20260727120000_indexes_and_constraints.sql).
--
-- Keyed on (profile, cert_serial), matching the lookup: revocation and ARI
-- take no account, so the endpoint the request arrived at is the only thing
-- scoping them -- one profile must never answer for another's certificate.
CREATE INDEX idx_orders_cert_serial ON orders (profile, cert_serial);
