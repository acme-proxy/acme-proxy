-- The web admin's failed-login counter, one row per (scope, client bucket).
--
-- It was a `HashMap` inside the admin process, which was correct only while
-- exactly one admin process existed: a second one behind the same load
-- balancer gave an attacker a second `admin.login_max_attempts`, and each
-- process restart a fresh one. ADR 0008 named it as the one piece of state
-- that stayed in memory; this table closes that exception.
--
-- **An attempt is counted when it starts.** `in_flight` holds the attempts
-- begun and not yet settled, and `begin` reserves a slot with one conditional
-- `UPDATE` that refuses once `failures + in_flight` reaches the limit. One
-- statement is what keeps a burst spread over several processes from buying
-- more guesses than the limit: both engines serialise the row.
--
-- `scope` is `password` or `oidc_start` (two budgets per address), an open
-- vocabulary owned by the Rust side with no `CHECK` (ADR 0005). `bucket` is the
-- client address as the limiter keys it: an IPv4 address, or an IPv6 /64.
-- No foreign key: a row names a network address, not anything of ours.
CREATE TABLE IF NOT EXISTS admin_login_buckets
(
    scope          TEXT    NOT NULL,
    bucket         TEXT    NOT NULL,
    failures       INTEGER NOT NULL,
    in_flight      INTEGER NOT NULL,
    -- Epoch seconds. A window that has run out resets both counters on the
    -- next `begin`, which is also what bounds a slot leaked by a process that
    -- died mid-attempt to one window.
    window_started INTEGER NOT NULL,
    PRIMARY KEY (scope, bucket)
);

-- The sweep: `window_started <= ?`.
CREATE INDEX IF NOT EXISTS idx_admin_login_buckets_window_started
    ON admin_login_buckets (window_started);
