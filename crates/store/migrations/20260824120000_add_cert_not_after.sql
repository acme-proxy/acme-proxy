-- The issued leaf's own notAfter, for the expiry digest (`[notify.expiry]`).
--
-- `orders` already has a `not_after`, and this is deliberately **not** it:
-- that column is the validity the *client* asked for in `newOrder` (RFC 8555
-- §7.4), which is usually NULL and which `local_ca` may clamp to a narrower
-- window than it was given. Nothing recorded what the certificate actually
-- says, so "which certificates expire in the next fortnight" could only be
-- answered by parsing every stored PEM chain -- which SQLite cannot do, and
-- which is why this is a column rather than a query.
--
-- Populated at finalize time alongside `certificate`/`cert_serial`/
-- `cert_pubkey`, from the same leaf DER those two are already derived from,
-- and best-effort: a chain this server cannot parse must not turn a completed
-- issuance into a failure (the rule `LocalCa::revoke` already follows when it
-- records a revoked leaf's expiry).
--
-- Three values, all meaningful:
--   * an epoch second -- the leaf expires then;
--   * NULL           -- issued before this migration, and nobody has looked
--                       at its PEM yet. The sweep backfills these.
--   * a negative     -- the sweep looked and the chain would not parse. A
--                       sentinel rather than leaving it NULL, or every pass
--                       would re-parse the same unparsable row for ever.
--
-- A plain nullable ADD COLUMN: no CHECK, no UNIQUE, no foreign key, so
-- nothing needs rebuilding (the 20260728120000_add_cert_revocation.sql shape).
ALTER TABLE orders ADD COLUMN cert_not_after INTEGER;

-- The digest's whole query is this predicate, run once per profile per
-- interval. Partial, because a row with no certificate or a revoked one can
-- never appear in the answer, and leaving them out keeps the index roughly
-- the size of the live certificate set rather than of every order ever
-- placed. Keyed on (profile, cert_not_after) matching the lookup: the digest
-- is per profile, and one endpoint must never report another's certificates.
CREATE INDEX idx_orders_cert_not_after ON orders (profile, cert_not_after)
    WHERE certificate IS NOT NULL AND revoked_at IS NULL;
