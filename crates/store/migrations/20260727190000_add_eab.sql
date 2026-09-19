-- External Account Binding (RFC 8555 §7.3.4): pre-shared HMAC credentials an
-- operator issues out-of-band, so a client's newAccount request can prove it
-- was authorized to register before an account exists at all.
--
-- Keys are REUSABLE: the same kid may bind more than one account (e.g. an
-- operator issuing one credential to a team, or a client registering more
-- than one ACME account key) until it is explicitly revoked. There is
-- therefore no "used" state, only active/revoked -- unlike a nonce or a
-- challenge token.
--
-- The secret is stored as retrievable bytes, not a one-way hash: HMAC
-- verification needs the very same secret back on every newAccount request,
-- unlike a password, where only ever comparing works with a one-way hash.
CREATE TABLE IF NOT EXISTS eab_keys
(
    kid        VARCHAR(36) PRIMARY KEY NOT NULL,
    secret     BLOB NOT NULL,
    label      TEXT,
    -- Which ACME endpoint the credential is good for. NULL means every
    -- profile, which is what a credential minted before profiles existed --
    -- or by an operator who does not care to scope it -- is.
    profile    VARCHAR,
    status     VARCHAR NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL
);

-- Which EAB credential (if any) an account was created under -- an audit
-- trail only: revoking the credential later does not retroactively affect
-- accounts already created with it (see Account::set_eab_kid). Set once, at
-- creation, and never overwritten afterwards.
--
-- A plain nullable column, no FOREIGN KEY: the row it names is only ever
-- revoked, never deleted, so there is nothing to cascade, and (like
-- 20260727180000_challenge_error.sql) a column with no CHECK/UNIQUE/FK needs
-- no table rebuild to add.
ALTER TABLE accounts
    ADD COLUMN eab_kid VARCHAR(36);

-- Whether the account agreed to the terms of service at creation
-- (RFC 8555 §7.3.3), so §7.1.2's optional `termsOfServiceAgreed` member can be
-- reflected back honestly rather than inferred from whether a ToS happens to be
-- configured now -- an account created before one was configured never agreed
-- to anything.
--
-- Same shape as `eab_kid` above and for the same reasons: nullable, no
-- CHECK/UNIQUE/FK, so no table rebuild; set once at creation and never
-- overwritten. NULL means "never recorded" and renders as absent, which is what
-- §7.1.2 says an optional member does.
ALTER TABLE accounts
    ADD COLUMN terms_of_service_agreed BOOLEAN;
