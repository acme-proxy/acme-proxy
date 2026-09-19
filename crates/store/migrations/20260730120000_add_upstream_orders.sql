-- Maps a local order to the order the `acme_proxy` signer backend opened for
-- it at the upstream CA.
--
-- One row per local order (hence `order_id` as the primary key, not a surrogate
-- id): the mapping is per-order state, unlike `local_ca`'s revocation ledger,
-- which lives in a JSON sidecar precisely because it is not.
--
-- The primary key doubles as the concurrency guard: two finalize requests
-- racing on the same order cannot both open an upstream order, because the
-- second INSERT conflicts.
CREATE TABLE upstream_orders (
    order_id TEXT PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE,
    upstream_order_url TEXT NOT NULL,
    upstream_finalize_url TEXT,
    upstream_certificate_url TEXT,
    -- The client's CSR, relayed byte-for-byte to the upstream's finalize. Kept
    -- because a relay interrupted by a restart has to be able to finish: an
    -- upstream order left at `ready` still needs this exact CSR, and it is not
    -- recoverable from anywhere else once the request that carried it is gone.
    -- Not a secret — a CSR is a public document carrying only a public key.
    csr_der BLOB NOT NULL,
    status TEXT NOT NULL
                   CHECK (status IN ('processing', 'valid', 'invalid')),
    error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- The finalize request's own context, carried here so the audit row written
    -- when the relay eventually settles can still say who asked.
    --
    -- This backend answers `processing` and signs minutes later, from a
    -- background task with no request in scope — so without these four the one
    -- `audit_log` row for an issuance this server relayed would have no address
    -- at all, which is the field the trail exists for. Written by
    -- `post_finalize` immediately after the backend answered, because the row
    -- itself is created inside `SignerBackend::issue` and does not exist any
    -- earlier.
    --
    -- Traceability, never compared, and NULL is a legitimate value: an order
    -- resumed after a restart that predates these columns settles without them.
    client_ip TEXT,
    client_ptr TEXT,
    user_agent TEXT,
    request_id TEXT
);

-- Serves the restart-recovery sweep: rows still `processing` after a restart
-- have lost their in-memory task and need one respawned.
CREATE INDEX idx_upstream_orders_status ON upstream_orders(status);
