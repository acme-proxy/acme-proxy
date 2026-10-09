-- The CA each `local_ca` profile issues from, by its issuer id.
--
-- A worker loads its CA from files on its own host (or a token attached to
-- it), and generates one when `ca.key` is missing. With one worker that was a
-- first-run convenience; with a second worker on another host over the same
-- database it is a silent fork — two CAs issuing for one profile, each
-- trusted by only half the clients, each revoking into its own CRL. This row
-- is what a worker compares its CA against before it signs anything, and why
-- one with no key files refuses rather than generating a CA of its own.
--
-- `issuer` is the hex SHA-256 of the CA certificate's SubjectPublicKeyInfo,
-- the same key `revocations` and `crls` use. A deliberate change of CA is
-- `acme-proxy profile issuer accept <name>`, which replaces the row.
-- No foreign key: a profile is configuration, not a row.
CREATE TABLE IF NOT EXISTS profile_issuers
(
    profile     TEXT PRIMARY KEY NOT NULL,
    issuer      VARCHAR(64) NOT NULL,
    recorded_at INTEGER     NOT NULL
);
