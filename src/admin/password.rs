//! Password hashing for the web admin's operators.
//!
//! PBKDF2-HMAC-SHA256 over `ring::pbkdf2`, which is already this crate's crypto
//! backend everywhere else. Deliberately *not* Argon2id, which is the stronger
//! primitive: it would add four crates (`argon2`, `password-hash`, `base64ct`,
//! `blake2`) to a certificate authority's dependency graph -- all of them
//! audited on every `cargo deny check`, since `deny.toml` runs with
//! `all-features = true` -- for a subsystem that is `enabled = false` by
//! default and whose password is the *bootstrap* credential in a design that
//! ends in a second factor. PBKDF2-HMAC-SHA256 at 600 000 iterations is
//! OWASP's current recommendation for the non-Argon2 case.
//!
//! The stored form is self-describing, so that trade can be revisited without
//! a migration: raising the iteration count, or swapping the algorithm
//! outright, needs a new branch in [`verify_password`] and nothing else --
//! [`needs_rehash`] then re-encodes each row on its owner's next successful
//! login.
//!
//! ```text
//! pbkdf2-sha256$600000$<salt-b64url>$<hash-b64url>
//! ```
//!
//! This module holds no database access and no I/O: it is shared by the CLI
//! (`admin user create`/`passwd`) and the web login path, which is why it lives
//! under `admin::` beside the other logic both front ends use rather than
//! inside `webadmin::`.

use std::num::NonZeroU32;
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};

/// The only algorithm this version writes. `verify_password` matches on it, so
/// adding a second is additive.
const ALGORITHM: &str = "pbkdf2-sha256";

/// OWASP's current recommendation for PBKDF2-HMAC-SHA256.
///
/// Measured at ~85 ms per verification in a release build on a 2020s desktop
/// core (and ~1.3 s in a debug build, which is why the tests below mostly do
/// not use it). That is the login latency, and it is a small denial-of-service
/// lever -- which is why `webadmin::session` rate-limits login *before* it
/// reaches here rather than after.
const ITERATIONS: u32 = 600_000;

/// 128 bits. Salts are per-row and public; their only job is to make one
/// precomputed table useless against every row at once.
const SALT_LEN: usize = 16;

/// 256 bits, matching the underlying PRF's output.
const HASH_LEN: usize = 32;

/// Shortest password accepted. Length is the only rule -- composition rules
/// ("one digit, one symbol") measurably push people towards weaker, more
/// guessable passwords, and this is an operator-facing surface with a handful
/// of accounts, not a consumer signup.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Longest password accepted. A DoS control, not a security one: without it a
/// login request could hand 600 000 iterations a multi-megabyte input.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// A stored hash that could not be read back.
///
/// Every variant means the `admin_users` row is corrupt, never that the
/// password was wrong -- callers must not fold this into "authentication
/// failed", or a mangled row would read as a bad password forever.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    /// Not the four `$`-separated fields the format defines.
    #[error("stored password hash is not in the expected format")]
    Malformed,
    /// A prefix this build does not implement.
    #[error("unknown password hash algorithm `{0}`")]
    UnknownAlgorithm(String),
    /// The iteration field was not a positive integer.
    #[error("stored password hash has an invalid iteration count")]
    BadIterations,
    /// Salt or hash was not valid unpadded base64url, or was the wrong length.
    #[error("stored password hash has an invalid salt or digest")]
    BadEncoding,
}

/// Rejects a password before it is ever hashed.
///
/// Returns the operator-facing message, so the CLI and the API report the same
/// words. Runs on `create`/`passwd`, never on login -- an existing password
/// that predates a rule change must still work.
pub fn check_password_policy(password: &str) -> Result<(), String> {
    // Characters, not bytes: a 12-character passphrase in a non-Latin script
    // would otherwise be measured as comfortably long by accident.
    let length = password.chars().count();
    if length < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters (got {length})"
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_LEN} bytes (got {})",
            password.len()
        ));
    }
    Ok(())
}

/// Hashes `password` under the current parameters, returning the encoded form
/// to store.
///
/// Does **not** check the policy: callers that accept a new password call
/// [`check_password_policy`] first, and the login path's rehash must be able to
/// re-encode a password that predates the current rules.
#[must_use]
pub fn hash_password(password: &str) -> String {
    hash_with_iterations(password, ITERATIONS)
}

/// Hashes a **high-entropy generated secret**, at a cost matched to the fact
/// that it is one.
///
/// [`ITERATIONS`] exists to slow a dictionary down. A recovery code
/// ([`crate::admin::recovery`]) has no dictionary: it is CSPRNG output from a
/// 32-symbol alphabet, so the cheapest attack on the stored form is a
/// brute-force over its own keyspace, which [`RECOVERY_ITERATIONS`] widens by
/// another ~13 bits on top.
///
/// The reason not to spend more is specific, and worth stating so it is not
/// "hardened" later by reflex: **the attacker this would defend against already
/// has a better route.** Recovery codes only matter to somebody holding the
/// database file, and that same file holds `admin_users.totp_secret` in the
/// clear -- it must, since verifying a code means recomputing the HMAC. Paying
/// 600 000 iterations ten times per enrolment buys nothing against a reader who
/// can simply take the factor itself.
///
/// The stored form is self-describing, so the two costs coexist with no
/// migration and no second format: [`verify_password`] reads the count back out
/// of the string. Do **not** run [`needs_rehash`] against one of these -- it
/// compares against [`ITERATIONS`] and would report every recovery code as
/// stale forever.
#[must_use]
pub fn hash_generated_secret(secret: &str) -> String {
    hash_with_iterations(secret, RECOVERY_ITERATIONS)
}

/// The cost [`hash_generated_secret`] uses. Named so the reasoning above has
/// something to point at.
pub const RECOVERY_ITERATIONS: u32 = 10_000;

/// [`hash_password`] with the cost as a parameter.
///
/// Exists so the tests can exercise this exact path -- the salt generation and
/// the encoding, which is where the bugs would be -- without paying 600 000
/// iterations a dozen times over. Private: nothing outside this module gets to
/// choose a cost, only to pick one of the two named above.
fn hash_with_iterations(password: &str, iterations: u32) -> String {
    let mut salt = [0u8; SALT_LEN];
    // Same trade-off as `sqlite::eab::generate_secret` and
    // `authz::generate_token`: an unavailable system RNG is unrecoverable, and
    // threading the error out would only move the panic.
    SystemRandom::new()
        .fill(&mut salt)
        .expect("system RNG unavailable");

    encode(&salt, &derive(password, &salt, iterations), iterations)
}

/// Verifies `password` against a stored hash, in constant time
/// (`ring::pbkdf2::verify` compares that way).
///
/// `Ok(false)` is a wrong password; `Err` is a corrupt row. Keeping them apart
/// is the point -- see [`PasswordError`].
pub fn verify_password(stored: &str, password: &str) -> Result<bool, PasswordError> {
    let (iterations, salt, expected) = decode(stored)?;
    Ok(pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &expected,
    )
    .is_ok())
}

/// Whether `stored` was written under parameters this build has since moved
/// past -- a different algorithm, or a lower iteration count.
///
/// A row that cannot be decoded reports `true`: it is already unusable, and
/// re-encoding it on the next successful login is the only way it ever gets
/// fixed. (`verify_password` will have returned `Err` for the same row, so
/// this is reached only where a caller chose to carry on regardless.)
#[must_use]
pub fn needs_rehash(stored: &str) -> bool {
    match decode(stored) {
        Ok((iterations, _, _)) => iterations.get() < ITERATIONS,
        Err(_) => true,
    }
}

/// A stored hash no password matches: given to the login path to verify against
/// when the username does not exist, so an unknown user costs the same one
/// derivation as a known one.
///
/// Without it, login latency enumerates the user table -- a fast rejection
/// means "no such user", a slow one means "wrong password".
///
/// **Encoded, never derived, and that is the whole point.** Calling
/// [`hash_password`] here costs a full [`ITERATIONS`]-round `pbkdf2::derive`
/// that the caller's [`verify_password`] then pays *again*, making the unknown
/// branch twice the known one -- the enumeration oracle inverted rather than
/// closed, and pointing the expensive direction at the branch an unauthenticated
/// caller picks. The digest is never matched against anything, so it only has to
/// be well-formed and carry the current cost; the bytes being zero is not a
/// weakness, since the value is in the binary either way and `pbkdf2::verify`
/// costs the same for any salt. [`encode`] is this module's own writer, so the
/// shape cannot drift from what [`decode`] expects, and reading [`ITERATIONS`]
/// here means the cost tracks a change to it rather than needing a second
/// spelling.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| encode(&[0u8; SALT_LEN], &[0u8; HASH_LEN], ITERATIONS));

#[must_use]
pub fn dummy_hash() -> &'static str {
    &DUMMY_HASH
}

fn derive(password: &str, salt: &[u8], iterations: u32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        nonzero(iterations),
        salt,
        password.as_bytes(),
        &mut out,
    );
    out
}

/// `iterations` is a compile-time constant everywhere it matters, and `decode`
/// has already refused a zero, so this cannot fail in practice -- but a
/// silently-clamped iteration count would be a real weakening, so clamp
/// upwards rather than downwards.
fn nonzero(iterations: u32) -> NonZeroU32 {
    NonZeroU32::new(iterations).unwrap_or(NonZeroU32::MIN)
}

fn encode(salt: &[u8], hash: &[u8], iterations: u32) -> String {
    format!(
        "{ALGORITHM}${iterations}${}${}",
        BASE64_URL_SAFE_NO_PAD.encode(salt),
        BASE64_URL_SAFE_NO_PAD.encode(hash),
    )
}

fn decode(stored: &str) -> Result<(NonZeroU32, Vec<u8>, Vec<u8>), PasswordError> {
    let mut fields = stored.split('$');
    let (Some(algorithm), Some(iterations), Some(salt), Some(hash), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(PasswordError::Malformed);
    };

    if algorithm != ALGORITHM {
        return Err(PasswordError::UnknownAlgorithm(algorithm.to_string()));
    }

    let iterations = iterations
        .parse::<u32>()
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(PasswordError::BadIterations)?;

    let salt = BASE64_URL_SAFE_NO_PAD
        .decode(salt)
        .map_err(|_| PasswordError::BadEncoding)?;
    let hash = BASE64_URL_SAFE_NO_PAD
        .decode(hash)
        .map_err(|_| PasswordError::BadEncoding)?;

    // A truncated digest would otherwise verify against a truncated
    // derivation, which is a weaker hash accepted silently.
    if salt.len() != SALT_LEN || hash.len() != HASH_LEN {
        return Err(PasswordError::BadEncoding);
    }

    Ok((iterations, salt, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real cost parameters run ~250 ms in release and ~1.6 s in a debug
    /// build, which is the point in production and far too slow for a suite
    /// that wants a dozen of them. Only the two tests that assert on the real
    /// constants pay it; everything else goes through here, which is the same
    /// code path at a cost the tests can afford.
    const TEST_ITERATIONS: u32 = 1_000;

    fn cheap_hash(password: &str) -> String {
        hash_with_iterations(password, TEST_ITERATIONS)
    }

    /// An encoded hash at an arbitrary cost, with a digest that was never
    /// derived. For [`needs_rehash`], which only ever decodes -- deriving one
    /// at `ITERATIONS` purely to read its header back would be the slowest
    /// possible way to parse a string.
    fn stored_at(iterations: u32) -> String {
        encode(&[7u8; SALT_LEN], &[0u8; HASH_LEN], iterations)
    }

    #[test]
    fn hash_then_verify_round_trips() {
        let stored = cheap_hash("correct horse battery");
        assert_eq!(verify_password(&stored, "correct horse battery"), Ok(true));
    }

    #[test]
    fn a_wrong_password_is_false_and_not_an_error() {
        let stored = cheap_hash("correct horse battery");
        assert_eq!(verify_password(&stored, "wrong"), Ok(false));
        assert_eq!(verify_password(&stored, ""), Ok(false));
    }

    #[test]
    fn two_hashes_of_one_password_differ_by_salt() {
        let first = cheap_hash("a-long-enough-password");
        let second = cheap_hash("a-long-enough-password");
        assert_ne!(first, second, "each hash must carry its own random salt");
        // Specifically the salt field, not just the string as a whole -- a
        // constant salt with a differing digest would be a much stranger bug
        // and this pins which one is being ruled out.
        assert_ne!(
            first.split('$').nth(2).unwrap(),
            second.split('$').nth(2).unwrap()
        );
        assert_eq!(verify_password(&first, "a-long-enough-password"), Ok(true));
        assert_eq!(verify_password(&second, "a-long-enough-password"), Ok(true));
    }

    #[test]
    fn the_encoded_form_is_self_describing() {
        let stored = hash_password("a-long-enough-password");
        let fields: Vec<&str> = stored.split('$').collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "pbkdf2-sha256");
        assert_eq!(fields[1], ITERATIONS.to_string());
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.decode(fields[2]).unwrap().len(),
            SALT_LEN
        );
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.decode(fields[3]).unwrap().len(),
            HASH_LEN
        );
        // No padding and no `+`/`/`: the value travels in JSON and, later, in
        // a template.
        assert!(!stored.contains('='));
        assert!(!stored.contains('+'));
    }

    #[test]
    fn every_decode_failure_is_its_own_variant() {
        let good = cheap_hash("pw");
        let salt = good.split('$').nth(2).unwrap().to_string();
        let hash = good.split('$').nth(3).unwrap().to_string();

        let cases: Vec<(&str, String, PasswordError)> = vec![
            ("empty", String::new(), PasswordError::Malformed),
            (
                "too few fields",
                format!("pbkdf2-sha256$1000${salt}"),
                PasswordError::Malformed,
            ),
            (
                "too many fields",
                format!("pbkdf2-sha256$1000${salt}${hash}$extra"),
                PasswordError::Malformed,
            ),
            (
                "unknown algorithm",
                format!("argon2id$1000${salt}${hash}"),
                PasswordError::UnknownAlgorithm("argon2id".to_string()),
            ),
            (
                "non-numeric iterations",
                format!("pbkdf2-sha256$many${salt}${hash}"),
                PasswordError::BadIterations,
            ),
            (
                "zero iterations",
                format!("pbkdf2-sha256$0${salt}${hash}"),
                PasswordError::BadIterations,
            ),
            (
                "salt is not base64url",
                format!("pbkdf2-sha256$1000$not base64${hash}"),
                PasswordError::BadEncoding,
            ),
            (
                "digest is not base64url",
                format!("pbkdf2-sha256$1000${salt}$not base64"),
                PasswordError::BadEncoding,
            ),
            (
                "short salt",
                format!(
                    "pbkdf2-sha256$1000${}${hash}",
                    BASE64_URL_SAFE_NO_PAD.encode([1u8; 4])
                ),
                PasswordError::BadEncoding,
            ),
            (
                "truncated digest",
                format!(
                    "pbkdf2-sha256$1000${salt}${}",
                    BASE64_URL_SAFE_NO_PAD.encode([1u8; 8])
                ),
                PasswordError::BadEncoding,
            ),
        ];

        for (name, stored, expected) in cases {
            assert_eq!(
                verify_password(&stored, "pw"),
                Err(expected),
                "case `{name}` decoded differently than expected"
            );
        }
    }

    #[test]
    fn every_error_renders() {
        let rendered: Vec<String> = [
            PasswordError::Malformed,
            PasswordError::UnknownAlgorithm("scrypt".to_string()),
            PasswordError::BadIterations,
            PasswordError::BadEncoding,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        assert!(rendered.iter().all(|line| !line.is_empty()));
        assert!(rendered[1].contains("scrypt"));
    }

    /// The two costs have to coexist in one format, since recovery codes and
    /// passwords both live in `<algo>$<iters>$…` columns and one `verify` reads
    /// both.
    #[test]
    fn a_generated_secret_hashes_cheaper_and_still_verifies() {
        let stored = hash_generated_secret("K7QF23BXTM");
        assert_eq!(stored.split('$').nth(1), Some("10000"));
        assert_eq!(verify_password(&stored, "K7QF23BXTM"), Ok(true));
        assert_eq!(verify_password(&stored, "K7QF23BXTN"), Ok(false));

        // The trap this documents: `needs_rehash` compares against the
        // *password* cost, so it reports true for every recovery code. Nothing
        // may call it on one.
        assert!(needs_rehash(&stored));
    }

    #[test]
    fn needs_rehash_tracks_the_current_parameters() {
        assert!(!needs_rehash(&stored_at(ITERATIONS)));
        assert!(needs_rehash(&stored_at(ITERATIONS - 1)));
        assert!(needs_rehash(&stored_at(TEST_ITERATIONS)));
        // Already stronger than this build asks for: leave it alone rather
        // than re-encoding it weaker.
        assert!(!needs_rehash(&stored_at(ITERATIONS + 1)));
        // A row that cannot be read is due a rewrite by definition.
        assert!(needs_rehash("nonsense"));
        assert!(needs_rehash(""));
        assert!(needs_rehash("argon2id$1$c2FsdA$aGFzaA"));
    }

    #[test]
    fn the_policy_enforces_length_and_nothing_else() {
        assert!(check_password_policy("a-long-enough-password").is_ok());
        // Exactly at the boundary, both ends.
        assert!(check_password_policy(&"x".repeat(MIN_PASSWORD_LEN)).is_ok());
        assert!(check_password_policy(&"x".repeat(MAX_PASSWORD_LEN)).is_ok());

        let too_short = check_password_policy(&"x".repeat(MIN_PASSWORD_LEN - 1)).unwrap_err();
        assert!(too_short.contains("at least 12"), "got: {too_short}");
        let too_long = check_password_policy(&"x".repeat(MAX_PASSWORD_LEN + 1)).unwrap_err();
        assert!(too_long.contains("at most 1024"), "got: {too_long}");

        // No composition rules: a long run of one character is accepted, and
        // a short but "complex" one is not.
        assert!(check_password_policy("aaaaaaaaaaaaaaaa").is_ok());
        assert!(check_password_policy("Aa1!Aa1!").is_err());
    }

    #[test]
    fn the_policy_counts_characters_not_bytes() {
        // 12 characters, 36 bytes in UTF-8. Measured as bytes this passes for
        // the wrong reason; measured as characters it passes for the right one.
        let passphrase = "日本語日本語日本語日本語";
        assert_eq!(passphrase.chars().count(), 12);
        assert!(passphrase.len() > MIN_PASSWORD_LEN);
        assert!(check_password_policy(passphrase).is_ok());

        // 11 characters is short whatever its byte length.
        assert!(check_password_policy("日本語日本語日本語日本").is_err());
    }

    /// The dummy must cost the login path exactly **one** derivation -- the same
    /// as a known username -- and carry the current cost while doing it.
    ///
    /// No longer one of the tests that pays the real cost: the assertions below
    /// are string comparisons, because `dummy_hash` no longer derives anything.
    #[test]
    fn the_dummy_hash_is_precomputed_and_matches_no_password() {
        // The one that catches a `hash_password`-based dummy: that spelling
        // salts randomly, so it returns a different string every call *and*
        // makes the unknown-username branch pay a derivation the caller's
        // `verify_password` then pays again -- twice a known username, i.e. the
        // enumeration oracle inverted rather than closed.
        assert_eq!(
            dummy_hash(),
            dummy_hash(),
            "a dummy computed per call costs the unknown-username branch an \
             extra derivation, which is the enumeration oracle it exists to close"
        );

        // Exact equality, not `!needs_rehash`: that only checks `<`, so it would
        // accept a dummy at twice the real cost -- the very shape of the bug.
        let (iterations, _, _) = decode(dummy_hash()).expect("the dummy is well-formed");
        assert_eq!(iterations.get(), ITERATIONS);

        assert!(!needs_rehash(dummy_hash()));
        assert_eq!(verify_password(dummy_hash(), "hunter2"), Ok(false));
    }
}
