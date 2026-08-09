-- The web admin's own identities and browser sessions.
--
-- Nothing here is an ACME concept: an `admin_users` row is an operator, an
-- `accounts` row is a client key. The two never join. An admin user is
-- process-wide rather than per-profile -- there is no `profile` column and no
-- role, because there is not yet a second kind of operator to distinguish (a
-- `role` column is a later nullable ALTER TABLE, the shape
-- 20260728120000_add_cert_revocation.sql already established).
--
-- Deliberately the OPPOSITE of 20260727190000_add_eab.sql. That migration
-- stores its secret as retrievable bytes because HMAC verification needs the
-- very same secret back on every newAccount request. A password is only ever
-- *compared*, so it is stored one-way and no code path can read it back --
-- losing one means `acme-proxy admin user passwd`, never a recovery.
CREATE TABLE IF NOT EXISTS admin_users
(
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    -- Lowercased by `admin::users::create_user` before it ever reaches here,
    -- so `Alice` and `alice` cannot become two logins that read as one in a
    -- log line. UNIQUE is therefore a real constraint and not a near-miss.
    username      TEXT NOT NULL UNIQUE,
    -- `<algo>$<params>$<salt-b64url>$<hash-b64url>` (see src/admin/password.rs).
    -- Self-describing on purpose: raising the cost parameters, or swapping the
    -- algorithm outright, then needs no migration -- only a new branch in
    -- `verify_password` and a rehash on the owner's next successful login.
    password_hash TEXT NOT NULL,
    status        VARCHAR NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'disabled')),
    -- Second-factor state (RFC 6238, src/admin/totp.rs).
    -- `totp_pending_secret` holds an enrolment the owner has not yet proven a
    -- code against; only `totp_secret` counts as enrolled, which is what lets
    -- the login path refuse a half-enrolled user rather than silently ignoring
    -- a factor the operator believes is on.
    --
    -- Both are the raw secret, in the clear -- and unlike `password_hash` two
    -- lines above, that is not a lapse. Verifying a TOTP code means recomputing
    -- the HMAC, so the server needs the very same bytes back on every attempt;
    -- this is `eab_keys.hmac_key`'s situation, not a password's. Wrapping them
    -- would need a key, and that key would live in the same directory as this
    -- database file.
    totp_secret         BLOB,
    totp_pending_secret BLOB,
    -- The last TOTP time step accepted for this user: a code observed in
    -- flight must not be replayable inside its own 30-second window
    -- (RFC 6238 §5.2).
    totp_last_step      INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_sessions
(
    -- SHA-256 of the cookie's bearer token, hex-encoded. The token itself is
    -- never stored: a database read -- a backup, a `.dump`, an injection --
    -- must not yield a usable session. SHA-256 rather than the password KDF
    -- because the token is 256 CSPRNG bits, so there is no dictionary to slow
    -- down and a slow hash would buy nothing but latency on every request.
    token_hash    TEXT PRIMARY KEY NOT NULL,
    user_id       VARCHAR(36) NOT NULL
                      REFERENCES admin_users (id) ON DELETE CASCADE,
    -- Per-session CSRF token, plaintext on purpose: it authorises nothing on
    -- its own, it only has to be unguessable and unreadable cross-origin.
    -- Rotated with the session it belongs to.
    csrf_token    TEXT NOT NULL,
    -- 'pending_mfa' is the half-authenticated state: password accepted, second
    -- factor outstanding, and the only routes such a session may reach are the
    -- ones that finish it (webadmin::session's `PendingMfa` extractor, which is
    -- the exact mirror image of `Authenticated`'s refusal).
    --
    -- Write-once at INSERT: promotion mints a *new* row and deletes this one
    -- rather than updating this column, so there is deliberately no setter. The
    -- pending token was minted before authentication completed and has since
    -- crossed the wire, so its privilege level changing means its value changes
    -- -- the same rule `sign_in`'s session-fixation delete follows.
    state         VARCHAR NOT NULL DEFAULT 'active'
                      CHECK (state IN ('pending_mfa', 'active')),
    -- Second-factor codes rejected against *this* session, and the only bound
    -- on guessing one that an attacker cannot shed.
    --
    -- `webadmin::session::LoginLimiter` keys on the peer address, and a
    -- `pending_mfa` cookie is deliberately valid from any address (see
    -- `created_ip` below -- pinning breaks CGNAT and mobile). So somebody
    -- holding a correct password could mint one pending session and then spend
    -- `admin.login_max_attempts` guesses per source address, which a single
    -- IPv6 /64 supplies 2^64 of. Six digits with a +-1 step window is 3 in
    -- 10^6 per guess; a few hundred thousand guesses inside `PENDING_MFA_TTL`
    -- is a coin flip.
    --
    -- Incremented by a single `UPDATE ... RETURNING`, which is also what makes
    -- it race-free: this listener carries no admission control by design, so a
    -- read-then-write would let K concurrent submissions all observe zero.
    mfa_attempts  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    -- Absolute deadline (admin.session_ttl_seconds). Never extended: past it
    -- the operator logs in again.
    expires_at    INTEGER NOT NULL,
    -- Idle deadline (admin.session_idle_timeout_seconds), advanced on use but
    -- at most once a minute -- a page polling with htmx must not be a page of
    -- WAL writes.
    last_seen_at  INTEGER NOT NULL,
    -- Forensics only, never compared against the current request. Pinning a
    -- session to an address breaks every mobile and CGNAT operator; pinning it
    -- to a User-Agent breaks on the next browser auto-update. They are here to
    -- answer "where was this session opened from", not to authorise anything.
    created_ip    TEXT,
    user_agent    TEXT
);

-- One recovery code: the way back in when the phone holding the TOTP secret is
-- gone. Hashed exactly as a password is (src/admin/password.rs) -- a recovery
-- code is only ever compared, never needed back, so this table is on the
-- `password_hash` side of the line the header comment draws and the `totp_*`
-- columns above sit on the other side of.
--
-- A table rather than a JSON column on `admin_users`, because single-use has to
-- be decided by the database: consumption is
-- `UPDATE ... WHERE id = ? AND used_at IS NULL` and `rows_affected == 1` says
-- which of two concurrent submissions won -- the same primitive `nonces`
-- already uses. A column would be a read-modify-write with no constraint behind
-- it.
--
-- `used_at` is stamped rather than the row deleted: the panel says "7 of 10
-- remaining", and "this code was spent, at T" is the audit trail a
-- recovery-code use exists to leave.
CREATE TABLE IF NOT EXISTS admin_recovery_codes
(
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id    VARCHAR(36) NOT NULL
                   REFERENCES admin_users (id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);

-- Every read here is "this user's codes", and verification walks the unused
-- ones one PBKDF2 run at a time.
CREATE INDEX IF NOT EXISTS idx_admin_recovery_codes_user_id
    ON admin_recovery_codes (user_id);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id
    ON admin_sessions (user_id);
-- The reaper's sweep predicate, on a table that gains a row per login.
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at
    ON admin_sessions (expires_at);

-- Two indexes the admin API needs and the ACME path never did: it lists orders
-- newest-first across every account, and filters by status without naming a
-- profile. `idx_orders_profile` (20260727120000) already covers `?profile=`.
CREATE INDEX IF NOT EXISTS idx_orders_created_at
    ON orders (created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_created_at
    ON orders (status, created_at);
