-- Broadens `audit_log` from "what the CA did to a certificate" to that plus
-- "what an operator did to the CA".
--
-- `20260809120000_add_audit_log.sql` pinned `event` to four certificate values
-- with a `CHECK (event IN (...))`. Recording an account deletion, an EAB
-- credential minted or revoked, an operator created or disabled, a session
-- revoked, a job cancelled or the nonce/audit tables pruned needs ~20 more
-- names, and SQLite cannot alter a `CHECK`, so the table is rebuilt.
--
-- The `event` CHECK is **dropped rather than widened**. `crate::audit::AuditEvent`
-- is the authority on the vocabulary now: `AuditEntry::insert` binds
-- `event.as_str()` (a match on an enum, never a free string), the CLI validates
-- `--event` against `ALL_AUDIT_EVENTS`, and `AuditEntry::event` parses the
-- column back the same way. This is the `admin_users.role` precedent
-- (`20260905120000`) -- validated in Rust, no CHECK -- and it means a new audit
-- event never needs another table rebuild. The `outcome` and `actor_kind`
-- CHECKs stay: those two vocabularies really are closed
-- (`AuditEvent::outcome` is exhaustive, and there are exactly four actor kinds).
--
-- No foreign keys and no child tables, so this is the simplest rebuild shape:
-- one `_new` table, `INSERT ... SELECT`, `DROP`, `RENAME`, then the three
-- indexes the DROP took. `account_id`/`order_id` stay `VARCHAR(36)` -- they
-- carry no FK and name a row that may be gone, exactly as
-- `20260827120000_uuid_ids_as_blobs.sql` left them, and
-- `every_id_column_is_declared_a_blob` (`src/sqlite/db.rs`) asserts it.
--
-- `id` keeps `INTEGER PRIMARY KEY AUTOINCREMENT`. The surviving rows keep their
-- ids (the INSERT names `id` explicitly), so `acme-proxy audit show <id>` is
-- stable across the upgrade; SQLite re-derives the `sqlite_sequence` high-water
-- mark from `MAX(id)`, which is inherent to any rebuild and harmless here.

CREATE TABLE audit_log_new
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  INTEGER NOT NULL,
    -- No CHECK: `crate::audit::AuditEvent` is the authority (see the header).
    event       TEXT NOT NULL,
    -- Still derived from `event` at insert, via `AuditEvent::outcome`.
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    -- The ACME endpoint, or '' for an action not scoped to one (an operator, a
    -- session, the nonce table, the audit log itself). Still NOT NULL.
    profile     TEXT NOT NULL,
    actor_kind  TEXT NOT NULL
                    CHECK (actor_kind IN ('acme', 'admin', 'cli', 'system')),
    actor_id    TEXT,
    account_id  VARCHAR(36),
    order_id    VARCHAR(36),
    cert_serial TEXT,
    identifiers TEXT NOT NULL DEFAULT '[]',
    client_ip   TEXT,
    client_ptr  TEXT,
    user_agent  TEXT,
    request_id  TEXT,
    -- On a certificate failure, the RFC 8555 problem type; on a revocation, the
    -- RFC 5280 reason code. On an administrative action, unused -- `detail`
    -- carries the human description of what changed.
    reason      TEXT,
    detail      TEXT
);

INSERT INTO audit_log_new
    (id, created_at, event, outcome, profile, actor_kind, actor_id, account_id,
     order_id, cert_serial, identifiers, client_ip, client_ptr, user_agent,
     request_id, reason, detail)
    SELECT id, created_at, event, outcome, profile, actor_kind, actor_id,
           account_id, order_id, cert_serial, identifiers, client_ip,
           client_ptr, user_agent, request_id, reason, detail
    FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

-- Re-created, not inherited: the DROP above took them and 20260809120000 will
-- not run again.
CREATE INDEX idx_audit_log_created_at  ON audit_log (created_at);
CREATE INDEX idx_audit_log_account_id  ON audit_log (account_id);
CREATE INDEX idx_audit_log_cert_serial ON audit_log (cert_serial);
