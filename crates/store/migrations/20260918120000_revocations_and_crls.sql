-- The local CA's revocation state, moved out of the files beside its CRL.
--
-- Until this migration a `local_ca` kept what it had revoked in a JSON sidecar
-- (`ca.json`, beside `signer.local_ca.crl_path`) and served the CRL signed over
-- it from memory. Every process that built the CA held its own copy: an
-- `acme-proxy order revoke` run beside a running `serve` wrote the files, and
-- the server went on serving a CRL without that serial until its own next
-- write. The database is the one store every process already shares, so both
-- halves live here now, and `ca.json` is read once -- imported into
-- `revocations` the first time a CA meets this schema -- and never written
-- again. `crl_path` stays, as an export of `crls.der` that nothing reads back.
--
-- **`issuer` names the CA by its key**: lowercase hex SHA-256 of the CA
-- certificate's SubjectPublicKeyInfo DER, 64 characters. Not `crl_path`, which
-- is where a copy is written rather than which CA signed it, and not a profile,
-- since two profiles over one CA are one issuer with one CRL.
--
-- **There is deliberately no foreign key to `orders`**, the `audit_log`
-- precedent (20260809120000): an operator may delete a revoked certificate's
-- order, and the revocation must outlive it -- a serial dropping off the CRL
-- because its order row went is exactly the failure this table exists to end.
-- `serial` is the same hex rendering `orders.cert_serial` stores.
CREATE TABLE IF NOT EXISTS revocations
(
    issuer     VARCHAR(64) NOT NULL,
    serial     TEXT        NOT NULL,
    -- Epoch seconds. The *first* revocation of a serial is the one kept: a
    -- repeat is an `INSERT ... ON CONFLICT DO NOTHING`, so neither its time nor
    -- its reason can be rewritten after the fact.
    revoked_at INTEGER     NOT NULL,
    -- RFC 5280 §5.3.1 CRLReason code, NULL for none. Validated in Rust, the
    -- `orders.revocation_reason` precedent, so no CHECK.
    reason     INTEGER,
    -- The revoked certificate's own notAfter, epoch seconds. What lets the
    -- daily sweep drop the entry once RFC 5280 §3.3 permits it. **NULL is never
    -- pruned**: it is an entry imported from a v1 sidecar, or a certificate
    -- whose validity would not parse, and an unknown expiry is not an expired
    -- one.
    not_after  INTEGER,
    PRIMARY KEY (issuer, serial)
);

-- The prune: `issuer = ? AND not_after < ?`.
CREATE INDEX IF NOT EXISTS idx_revocations_issuer_not_after ON revocations (issuer, not_after);

-- The current signed CRL, one row per issuer, replaced in place.
--
-- `crl_number` is the RFC 5280 §5.2.3 counter, which must only ever increase: a
-- relying party meeting a lower number than it has cached keeps the cached CRL,
-- i.e. keeps trusting what was since revoked. Every replacement is therefore
-- guarded on the number it read (`UPDATE ... WHERE crl_number = ?`), and a
-- writer that lost that race re-reads and signs again rather than overwriting a
-- newer CRL with an older one.
CREATE TABLE IF NOT EXISTS crls
(
    issuer      VARCHAR(64) PRIMARY KEY NOT NULL,
    crl_number  INTEGER     NOT NULL,
    der         BLOB        NOT NULL,
    -- Epoch seconds, as signed into the CRL: what the daily sweep reads to
    -- decide the CRL is due a fresh signature before `next_update` lapses.
    this_update INTEGER     NOT NULL,
    next_update INTEGER     NOT NULL
);
