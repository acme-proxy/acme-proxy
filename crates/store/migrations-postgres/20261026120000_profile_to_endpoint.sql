-- `[profiles.<name>]` became `[endpoints.<name>]`, and the schema follows. The
-- reasoning is in the SQLite twin, migrations/20261026120000_profile_to_endpoint.sql.
ALTER TABLE accounts  RENAME COLUMN profile TO endpoint;
ALTER TABLE orders    RENAME COLUMN profile TO endpoint;
ALTER TABLE eab_keys  RENAME COLUMN profile TO endpoint;
ALTER TABLE audit_log RENAME COLUMN profile TO endpoint;

ALTER TABLE profile_issuers RENAME TO endpoint_issuers;
ALTER TABLE endpoint_issuers RENAME COLUMN profile TO endpoint;
ALTER INDEX profile_issuers_pkey RENAME TO endpoint_issuers_pkey;

ALTER INDEX idx_orders_profile RENAME TO idx_orders_endpoint;
-- Named in code: `account::create` maps a violation of it to "this key already
-- has an account here".
ALTER TABLE accounts RENAME CONSTRAINT accounts_profile_pubkey_key TO accounts_endpoint_pubkey_key;

-- `payload` is text holding JSON. Each row is parsed inside its own exception
-- block, so a payload no handler could have read is skipped rather than failing
-- the cast and with it the migration (`IS JSON` would say the same, but only
-- from PostgreSQL 16).
DO $$
DECLARE
    job     RECORD;
    doc     jsonb;
BEGIN
    FOR job IN SELECT id, jobs.payload AS raw FROM jobs WHERE jobs.payload LIKE '%profile%' LOOP
        BEGIN
            doc := job.raw::jsonb;
        EXCEPTION WHEN others THEN
            CONTINUE;
        END;
        IF jsonb_typeof(doc) <> 'object' THEN
            CONTINUE;
        END IF;
        IF doc ? 'profile' THEN
            doc := (doc - 'profile') || jsonb_build_object('endpoint', doc -> 'profile');
        END IF;
        IF jsonb_typeof(doc -> 'event') = 'object' THEN
            IF doc -> 'event' ? 'profile' THEN
                doc := jsonb_set(doc #- '{event,profile}', '{event,endpoint}',
                             doc #> '{event,profile}');
            END IF;
            IF doc #>> '{event,hook}' = 'profile_mounted' THEN
                doc := jsonb_set(doc, '{event,hook}', '"endpoint_mounted"');
            END IF;
        END IF;
        UPDATE jobs SET payload = doc::text WHERE id = job.id;
    END LOOP;
END
$$;

UPDATE audit_log SET event = 'endpoint_issuer_accepted' WHERE event = 'profile_issuer_accepted';
