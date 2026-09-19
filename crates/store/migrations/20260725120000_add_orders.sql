CREATE TABLE IF NOT EXISTS orders
(
    id          VARCHAR(36) PRIMARY KEY NOT NULL,
    profile     VARCHAR NOT NULL,          -- the ACME endpoint this order was placed at
    account_id  VARCHAR(36) NOT NULL,
    status      VARCHAR NOT NULL,          -- pending|ready|processing|valid|invalid (we start at 'ready')
    identifiers TEXT NOT NULL,             -- JSON array of {"type":"dns","value":"..."}
    expires     INTEGER NOT NULL,          -- epoch seconds
    not_before  INTEGER,                   -- epoch seconds, nullable
    not_after   INTEGER,                   -- epoch seconds, nullable
    error       TEXT,                      -- JSON problem doc, nullable
    certificate TEXT,                      -- PEM chain, nullable until issued
    created_at  INTEGER NOT NULL,
    -- Where this order was placed from, and the reverse-DNS name for that
    -- address at that moment. Same shape and same rules as `accounts`
    -- (20260722210000): traceability only, never compared, NULL when there was
    -- no PTR record or `audit.reverse_dns` is off. There is deliberately no
    -- update-side pair -- the moment that matters after creation is issuance,
    -- and that is an `audit_log` row with its own address.
    created_ip  TEXT,
    created_ptr TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
