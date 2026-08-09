CREATE TABLE IF NOT EXISTS authorizations
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    order_id   VARCHAR(36) NOT NULL,
    identifier TEXT NOT NULL,             -- JSON {"type":"dns","value":"..."}
    status     VARCHAR NOT NULL,          -- pending|valid|invalid (we use pending -> valid)
    expires    INTEGER NOT NULL,          -- epoch seconds
    created_at INTEGER NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS challenges
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    authz_id   VARCHAR(36) NOT NULL,
    type       VARCHAR NOT NULL,          -- http-01
    token      VARCHAR NOT NULL,
    status     VARCHAR NOT NULL,          -- pending|valid
    validated  INTEGER,                   -- epoch seconds, nullable (set on validation)
    created_at INTEGER NOT NULL,
    FOREIGN KEY (authz_id) REFERENCES authorizations(id)
);
