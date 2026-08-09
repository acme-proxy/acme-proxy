-- The CA's own audit trail: one row per action taken on a certificate, and one
-- per action refused.
--
-- This table is the reason the other tables' `ON DELETE CASCADE` stops here.
-- **There is deliberately no foreign key on `account_id` or `order_id`**, which
-- is the opposite of every other table in this schema (20260727120000 made
-- indexing and cascading every FK a rule). An audit row must survive
-- `acme-proxy account delete` and `order delete` -- an operator removing the
-- account is exactly the moment the trail becomes worth having, and a CASCADE
-- would delete the evidence along with the subject. The ids are therefore plain
-- columns naming a row that may no longer exist, and `identifiers` is frozen
-- into the row rather than joined back to `orders` for the same reason: after
-- the order is gone, "which names did this certificate cover" has to still be
-- answerable.
--
-- Rows are only ever INSERTed. Nothing in the crate updates or deletes one
-- except `audit cleanup` / `audit.retention_days`, which delete whole rows by
-- age and never rewrite a field.
--
-- `id` is an autoincrementing integer rather than this schema's usual UUID, on
-- both counts deliberately: an operator types it (`acme-proxy audit show 41812`),
-- and AUTOINCREMENT is what stops SQLite reusing the rowid of a purged row --
-- an id appearing twice across a purge, in the one table whose job is to be
-- referred back to, is worse than the extra sqlite_sequence write.
CREATE TABLE IF NOT EXISTS audit_log
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  INTEGER NOT NULL,
    -- Two events per action, one for each way it ends. A refusal is an audit
    -- record in its own right: "who tried to revoke this and was turned away"
    -- is the question the successes cannot answer.
    event       TEXT NOT NULL
                    CHECK (event IN ('certificate_issued',
                                     'certificate_issue_failed',
                                     'certificate_revoked',
                                     'certificate_revoke_failed')),
    -- Derivable from `event`, and stored anyway: "show me everything that was
    -- refused" is the commonest reading of this table, and deriving it in SQL
    -- means `event LIKE '%_failed'` in the CLI, the API and the page. Written
    -- from `AuditEvent::outcome()` at insert, so the two cannot disagree --
    -- there is one definition, not a column an INSERT could get wrong.
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    -- Which ACME endpoint. Never NULL: an issuance or a revocation always
    -- happens under one profile's signer, including the admin and CLI paths,
    -- which resolve the order's own profile before acting.
    profile     TEXT NOT NULL,
    -- Who acted. 'acme' is a client over the ACME API, 'admin' an operator
    -- through the web admin, 'cli' `acme-proxy order revoke` on the host, and
    -- 'system' the `acme_proxy` signer's background relay settling an issuance
    -- that was already answered `processing` -- the one actor with no request
    -- behind it, and therefore no address.
    actor_kind  TEXT NOT NULL
                    CHECK (actor_kind IN ('acme', 'admin', 'cli', 'system')),
    -- The acting identity within that kind: an account id, an admin username,
    -- an OS user. NULL where there genuinely is none -- RFC 8555 §7.6's
    -- accountless revocation, authorised by the certificate's own key pair,
    -- is an 'acme' actor with nothing to name.
    actor_id    TEXT,
    -- The subject. No FK, see the header comment.
    account_id  VARCHAR(36),
    order_id    VARCHAR(36),
    cert_serial TEXT,
    -- JSON array of identifier values, frozen at write time.
    identifiers TEXT NOT NULL DEFAULT '[]',
    -- The request's own context. All NULL for 'cli' and 'system', which is the
    -- honest answer rather than a placeholder: there was no client.
    client_ip   TEXT,
    client_ptr  TEXT,
    user_agent  TEXT,
    -- The `x-request-id` the access middleware echoed, so a row here joins to
    -- the tracing lines for the same request.
    request_id  TEXT,
    -- On a failure, the RFC 8555 problem type (`badCSR`, `unauthorized`, ...).
    -- On a revocation, the RFC 5280 reason code as a decimal string. Two
    -- meanings in one column because they are never both present.
    reason      TEXT,
    detail      TEXT
);

-- Newest-first listing, and the retention sweep's predicate.
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at);
-- "everything this account ever did", the question `account show` leads to.
CREATE INDEX IF NOT EXISTS idx_audit_log_account_id ON audit_log (account_id);
-- "the history of this one certificate", starting from a serial in a CRL.
CREATE INDEX IF NOT EXISTS idx_audit_log_cert_serial ON audit_log (cert_serial);
