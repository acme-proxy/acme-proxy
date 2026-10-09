-- The CA each `local_ca` profile issues from, by its issuer id. The reasoning
-- is in the SQLite twin, migrations/20261011130000_profile_issuers.sql.
CREATE TABLE profile_issuers
(
    profile     text PRIMARY KEY NOT NULL,
    issuer      varchar(64) NOT NULL,
    recorded_at bigint NOT NULL
);
