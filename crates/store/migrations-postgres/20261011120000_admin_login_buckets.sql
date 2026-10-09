-- The web admin's failed-login counter, one row per (scope, client bucket).
-- The reasoning is in the SQLite twin,
-- migrations/20261011120000_admin_login_buckets.sql.
CREATE TABLE admin_login_buckets
(
    scope          text   NOT NULL,
    bucket         text   NOT NULL,
    failures       bigint NOT NULL,
    in_flight      bigint NOT NULL,
    window_started bigint NOT NULL,
    PRIMARY KEY (scope, bucket)
);

CREATE INDEX idx_admin_login_buckets_window_started
    ON admin_login_buckets (window_started);
