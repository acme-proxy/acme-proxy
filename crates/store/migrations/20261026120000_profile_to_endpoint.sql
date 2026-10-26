-- A configured `[profiles.<name>]` is now an `[endpoints.<name>]`, and the
-- schema follows: every column, table and index that named one is renamed.
-- "Profile" is left free for the ACME concept (draft-ietf-acme-profiles), which
-- an order will carry in a column of its own.
--
-- `RENAME COLUMN` (SQLite 3.25+) rewrites every index, view and trigger that
-- names the column, so `idx_orders_replaces`, `idx_orders_cert_serial` and the
-- rest keep working unchanged. SQLite has no `ALTER INDEX ... RENAME`, so the
-- one index whose *name* says "profile" is recreated under its new name.
ALTER TABLE accounts  RENAME COLUMN profile TO endpoint;
ALTER TABLE orders    RENAME COLUMN profile TO endpoint;
ALTER TABLE eab_keys  RENAME COLUMN profile TO endpoint;
ALTER TABLE audit_log RENAME COLUMN profile TO endpoint;

ALTER TABLE profile_issuers RENAME TO endpoint_issuers;
ALTER TABLE endpoint_issuers RENAME COLUMN profile TO endpoint;

DROP INDEX IF EXISTS idx_orders_profile;
CREATE INDEX IF NOT EXISTS idx_orders_endpoint ON orders (endpoint);

-- Queued work written by the previous binary names the endpoint under the old
-- key, and the job handlers now read `endpoint`: rewrite the payloads rather
-- than teach every reader the old spelling. Three places hold it — the
-- top-level member (`notify_deliver`, `relay`, `signer_issue`), the event a
-- notification carries, and that event's `hook` when it is the renamed
-- `profile_mounted`. `json_valid` guards a payload no handler could have read
-- anyway, so it cannot fail the migration.
UPDATE jobs
SET payload = json_remove(json_set(payload, '$.endpoint', json_extract(payload, '$.profile')), '$.profile')
WHERE json_valid(payload) AND json_type(payload, '$.profile') IS NOT NULL;

UPDATE jobs
SET payload = json_remove(
        json_set(payload, '$.event.endpoint', json_extract(payload, '$.event.profile')),
        '$.event.profile')
WHERE json_valid(payload) AND json_type(payload, '$.event.profile') IS NOT NULL;

UPDATE jobs
SET payload = json_set(payload, '$.event.hook', 'endpoint_mounted')
WHERE json_valid(payload) AND json_extract(payload, '$.event.hook') = 'profile_mounted';

-- The one audit event whose name carried the old word. `audit --event` takes a
-- closed vocabulary, so a row left on the old name could never be selected by
-- it again.
UPDATE audit_log SET event = 'endpoint_issuer_accepted' WHERE event = 'profile_issuer_accepted';
