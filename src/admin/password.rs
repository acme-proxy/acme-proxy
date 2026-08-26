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
//! The other half of this module is [`check_password_policy`], which is the
//! single place every rule about an *acceptable* password lives. Three of them:
//! length, a list of words naming this deployment ([`PasswordContext`]), and a
//! corpus of common passwords compiled in from `corpus/common-passwords.txt`.
//! The last two are ASVS 5.0 V6.2.11 and V6.2.4/V6.2.12, and both rest on the
//! same observation -- **the length rule has already refused everything short**,
//! so a corpus filtered at [`MIN_PASSWORD_LEN`] is 195 KB where the list it was
//! derived from is 8.5 MB. `corpus/README.md` has the provenance and the
//! budget.
//!
//! This module holds no database access and no I/O: it is shared by the CLI
//! (`admin user create`/`passwd`) and the web login path, which is why it lives
//! under `admin::` beside the other logic both front ends use rather than
//! inside `webadmin::`.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use url::Url;

use crate::config::{Config, LocalCaSubjectConfig};

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

/// Shortest context word that can bar a password.
///
/// Three characters is noise: a subject holding `CA`, or a host label `io`,
/// would refuse a large share of every password anyone typed and buy nothing.
/// Four is the shortest word this list actually needs -- `acme`.
const MIN_CONTEXT_WORD_LEN: usize = 4;

/// The words every deployment bars, whatever it happens to be called.
const UNIVERSAL_CONTEXT_WORDS: [&str; 2] = ["acme", "proxy"];

/// Common passwords: one per line, lowercase, sorted, and every one of them at
/// least [`MIN_PASSWORD_LEN`] characters.
///
/// **The length filter is what makes a compiled-in corpus affordable.**
/// `password`, `qwerty` and `123456` never reach this check -- the length rule
/// above has already refused them -- so carrying them would add bytes to every
/// deployment, including the ones with `admin.enabled = false`, in exchange for
/// nothing. Filtering the upstream million at twelve characters is what turns
/// 8.5 MB into 195 KB.
///
/// Provenance, the rank cut, the budget it was derived from and the refresh
/// command are in `src/admin/corpus/README.md`. The invariants this module
/// relies on are asserted by the tests below rather than trusted.
const COMMON_PASSWORDS: &str = include_str!("corpus/common-passwords.txt");

/// The words that name *this* deployment, barred from an operator's password.
///
/// ASVS 5.0 **V6.1.2** asks for such a list to be documented and **V6.2.11**
/// for it to be enforced; the operator-facing copy is
/// `doc/src/operations/webadmin_users.md`. It is *derived* rather than
/// hardcoded because the name of the thing being protected is the first
/// password anybody reaches for, and that name differs per deployment.
///
/// Two limits are deliberate and worth knowing before trusting it:
///
/// * **A CA already on disk is not described here.**
///   `[signer.local_ca.subject]` is read only when this server *generates* a
///   CA, so an adopted `ca.pem` carries a subject configuration never sees.
///   Reading it back would mean parsing every mounted profile's certificate on
///   a CLI path that has not otherwise opened one. When `common_name` is unset
///   the built-in default is `acme-proxy local CA`, whose only words worth
///   barring are already in [`UNIVERSAL_CONTEXT_WORDS`].
/// * **`country` is excluded**, being two characters and so below
///   [`MIN_CONTEXT_WORD_LEN`] whatever it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordContext {
    /// Lowercase, deduplicated, sorted, each at least
    /// [`MIN_CONTEXT_WORD_LEN`] characters.
    words: Vec<String>,
}

impl PasswordContext {
    /// No words: every password passes the context rule.
    ///
    /// What a caller with no configuration in hand uses. It is a *weaker*
    /// check, never a wrong one -- the length and corpus rules still run.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Derives the list from the deployment's own configuration and the
    /// operator's own name.
    ///
    /// **Cannot fail.** A `[profiles]` table that will not resolve contributes
    /// nothing and the global `[signer]` still does: refusing a password change
    /// because an unrelated profile is misconfigured would be a lockout caused
    /// by the control that exists to prevent one.
    #[must_use]
    pub fn from_config(config: &Config, username: &str) -> Self {
        let mut words = BTreeSet::new();

        for word in UNIVERSAL_CONTEXT_WORDS {
            words.insert(word.to_string());
        }
        push_tokens(&mut words, username);
        push_host(&mut words, &config.server.base_url);
        push_host(&mut words, &config.admin.base_url);
        push_subject(&mut words, &config.signer.local_ca.subject);

        // The profile name is in every `kid` and order URL this endpoint ever
        // issued, which makes it public and memorable -- exactly the shape of
        // word this list is for.
        for profile in config.resolve_profiles().unwrap_or_default() {
            push_tokens(&mut words, &profile.name);
            push_subject(&mut words, &profile.sections.signer.local_ca.subject);
        }

        Self {
            words: words.into_iter().collect(),
        }
    }

    /// The first barred word `folded` contains, if any.
    ///
    /// Substring, not equality: `acmeproxy2026!` is the guess this rule exists
    /// to refuse, and it contains no barred word as a whole password.
    fn first_match(&self, folded: &str) -> Option<&str> {
        self.words
            .iter()
            .find(|word| folded.contains(word.as_str()))
            .map(String::as_str)
    }

    /// The derived words, for the tests that assert what each source
    /// contributed.
    #[cfg(test)]
    fn words(&self) -> &[String] {
        &self.words
    }
}

/// Splits `value` on everything that is not a letter or a digit, keeping the
/// tokens long enough to be worth barring.
///
/// A CommonName is a phrase ("Example Corp Issuing CA"), a host is dotted and a
/// username may be hyphenated: one splitter serves all three, and it is what
/// turns `ca.example.com` into `example` rather than into a string no password
/// would ever contain whole.
fn push_tokens(words: &mut BTreeSet<String>, value: &str) {
    for token in value.split(|c: char| !c.is_alphanumeric()) {
        if token.chars().count() >= MIN_CONTEXT_WORD_LEN {
            words.insert(token.to_lowercase());
        }
    }
}

/// The host of a configured base URL, tokenized.
///
/// Parsed rather than split by hand: [`push_tokens`] over the whole URL would
/// bar `http`, which is not this deployment's name. A value that will not parse
/// contributes nothing -- `webadmin::check_config` refuses one at startup, so
/// this is reached only by a CLI run against a configuration the server would
/// not have accepted.
fn push_host(words: &mut BTreeSet<String>, base_url: &str) {
    if let Some(host) = Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
    {
        push_tokens(words, &host);
    }
}

/// Every subject attribute except `country` -- see [`PasswordContext`].
fn push_subject(words: &mut BTreeSet<String>, subject: &LocalCaSubjectConfig) {
    for value in [
        &subject.common_name,
        &subject.organization,
        &subject.organizational_unit,
        &subject.state,
        &subject.locality,
    ]
    .into_iter()
    .flatten()
    {
        push_tokens(words, value);
    }
}

/// Whether `folded` is one of the [`COMMON_PASSWORDS`] entries.
///
/// A linear scan over `include_str!`, deliberately: no `LazyLock`, no heap, no
/// perfect-hash dependency -- the `metrics.rs` and `cli/style.rs` call, made
/// here for a concrete reason. This runs **once per password set and never on
/// login**, and `str`'s `PartialEq` compares lengths before bytes, so 14 000
/// comparisons cost microseconds beside the 600 000-iteration derivation the
/// caller is about to pay.
///
/// Whole-password equality, **never a substring**: `a-long-enough-password`
/// contains `password`, and refusing it would be refusing a good password for
/// the sins of a bad one.
fn is_common(folded: &str) -> bool {
    COMMON_PASSWORDS.lines().any(|entry| entry == folded)
}

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
/// Three rules, in this order, each of which ends the check:
///
/// 1. **Length** -- [`MIN_PASSWORD_LEN`] characters to [`MAX_PASSWORD_LEN`]
///    bytes. Still the only rule about a password's *shape*; composition rules
///    remain deliberately absent.
/// 2. **Context** -- it must not contain a word naming this deployment
///    ([`PasswordContext`], ASVS V6.2.11).
/// 3. **Corpus** -- it must not be a known common password ([`is_common`],
///    ASVS V6.2.4/V6.2.12).
///
/// The order is cheapest-first, and each rule returning immediately is the
/// point: a password refused for being eight characters must not also be told
/// it is common, which would be a second sentence about a string that was
/// never going to be accepted.
///
/// Returns the operator-facing message, so the CLI and the API report the same
/// words. **No message ever echoes the password** -- the context one names the
/// offending *word*, which the operator configured and can see anyway.
///
/// Runs on `create`/`passwd`, never on login: an existing password that
/// predates a rule change must still work, and a corpus refresh must never
/// lock an operator out of a panel they can no longer sign in to fix.
pub fn check_password_policy(password: &str, context: &PasswordContext) -> Result<(), String> {
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

    // One fold, shared by both remaining rules. Neither is case-sensitive:
    // `Passwordpassword` is the same guess as `passwordpassword`, and a
    // deployment's name is no less its name in capitals.
    let folded = password.to_lowercase();

    if let Some(word) = context.first_match(&folded) {
        return Err(format!(
            "password must not contain `{word}`, which names this deployment"
        ));
    }
    if is_common(&folded) {
        return Err("password appears in a list of commonly used passwords".to_string());
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

    /// Exactly [`MIN_PASSWORD_LEN`] characters and **not a corpus entry**.
    ///
    /// The obvious spelling, `"x".repeat(MIN_PASSWORD_LEN)`, is no longer
    /// available: `xxxxxxxxxxxx` is in the corpus, which is the whole point of
    /// having one. Anything at the top end is safe by construction -- the
    /// longest corpus entry is 29 characters.
    const SHORTEST_ACCEPTABLE: &str = "Zq7-Kx2-Mp9v";

    #[test]
    fn the_policy_enforces_length_at_both_ends() {
        let none = PasswordContext::empty();
        assert_eq!(SHORTEST_ACCEPTABLE.chars().count(), MIN_PASSWORD_LEN);
        assert!(check_password_policy(SHORTEST_ACCEPTABLE, &none).is_ok());
        assert!(check_password_policy(&"a".repeat(MAX_PASSWORD_LEN), &none).is_ok());

        let too_short =
            check_password_policy(&"x".repeat(MIN_PASSWORD_LEN - 1), &none).unwrap_err();
        assert!(too_short.contains("at least 12"), "got: {too_short}");
        let too_long = check_password_policy(&"a".repeat(MAX_PASSWORD_LEN + 1), &none).unwrap_err();
        assert!(too_long.contains("at most 1024"), "got: {too_long}");
    }

    /// Composition rules stay deliberately absent. What changed is only that
    /// the run has to be one the corpus has not heard of: sixteen `a`s used to
    /// stand here and is a corpus entry, twenty-four is not.
    #[test]
    fn the_policy_still_has_no_composition_rules() {
        let none = PasswordContext::empty();
        assert!(check_password_policy(&"a".repeat(24), &none).is_ok());
        assert!(check_password_policy("Aa1!Aa1!", &none).is_err());
    }

    #[test]
    fn the_policy_counts_characters_not_bytes() {
        let none = PasswordContext::empty();
        // 12 characters, 36 bytes in UTF-8. Measured as bytes this passes for
        // the wrong reason; measured as characters it passes for the right one.
        let passphrase = "日本語日本語日本語日本語";
        assert_eq!(passphrase.chars().count(), 12);
        assert!(passphrase.len() > MIN_PASSWORD_LEN);
        assert!(check_password_policy(passphrase, &none).is_ok());

        // 11 characters is short whatever its byte length.
        assert!(check_password_policy("日本語日本語日本語日本", &none).is_err());
    }

    // ---- the corpus (ASVS V6.2.4 / V6.2.12) ------------------------------

    /// Every invariant the lookup and the size budget rest on.
    ///
    /// A refresh that drops `awk`, `tr` or `LC_ALL=C` from the pipeline in
    /// `corpus/README.md` reintroduces exactly what the filter exists to
    /// remove, and nothing else in the tree would notice.
    #[test]
    fn the_corpus_holds_its_shape() {
        let mut previous = "";
        let mut entries = 0usize;
        for entry in COMMON_PASSWORDS.lines() {
            assert!(
                entry.is_ascii(),
                "non-ASCII entry `{entry}`: the >= 12 filter counts bytes, which \
                 equals characters only for ASCII"
            );
            assert_eq!(
                entry,
                entry.to_lowercase(),
                "entry `{entry}` is not folded, so the folded lookup can never match it"
            );
            assert!(
                entry.chars().count() >= MIN_PASSWORD_LEN,
                "entry `{entry}` is shorter than the length rule already refuses, \
                 so it is bytes spent on an unreachable comparison"
            );
            assert!(
                previous < entry,
                "`{previous}` then `{entry}`: the corpus must be `LC_ALL=C sort -u`ed"
            );
            previous = entry;
            entries += 1;
        }

        // A floor against a truncated or half-written file, not a claim about
        // V6.2.4 -- that requirement is met by construction, every top-3000
        // password being either below the length floor or in here.
        assert!(
            entries > 10_000,
            "only {entries} entries: the file looks truncated"
        );
        assert!(
            COMMON_PASSWORDS.len() < 200 * 1024,
            "corpus is {} bytes, past the 200 KiB budget the rank cut was derived from",
            COMMON_PASSWORDS.len()
        );
    }

    /// The fixture roughly fifty integration tests sign in with.
    ///
    /// If a corpus refresh ever swallows it they all fail at once, and not one
    /// of them says why. This one does.
    #[test]
    fn the_test_fixture_passwords_are_not_in_the_corpus() {
        for fixture in [
            "a-long-enough-password",
            "correct horse battery",
            SHORTEST_ACCEPTABLE,
        ] {
            assert!(
                !is_common(&fixture.to_lowercase()),
                "`{fixture}` is now a corpus entry, and every test that uses it is \
                 about to fail somewhere else"
            );
        }
    }

    #[test]
    fn a_common_password_is_refused_however_it_is_capitalized() {
        let none = PasswordContext::empty();
        for spelling in ["passwordpassword", "PasswordPassword", "PASSWORDPASSWORD"] {
            let error = check_password_policy(spelling, &none).unwrap_err();
            assert!(error.contains("commonly used"), "got: {error}");
            assert!(
                !error.contains(spelling),
                "the message must never echo the password: {error}"
            );
        }
    }

    /// Whole-password equality, never a substring -- otherwise
    /// `a-long-enough-password` would be refused for containing `password`,
    /// which is a good password refused for the sins of a bad one.
    #[test]
    fn the_corpus_rule_does_not_match_a_substring() {
        assert!(is_common("passwordpassword"));
        assert!(!is_common("a-long-enough-password"));
        assert!(!is_common("xx-passwordpassword-xx"));
    }

    // ---- the context list (ASVS V6.1.2 / V6.2.11) ------------------------

    /// Loads a `Config` the way the server does, so `resolve_profiles` has the
    /// raw sources per-key inheritance needs -- the `cli::filter` helper
    /// verbatim, and for the same reason: a `Config` deserialized directly
    /// carries no raw layer and resolves no profiles at all.
    fn load(body: &str) -> Config {
        let _lock = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = crate::testutil::TempDir::new("password-context");
        std::fs::write(dir.join("config.toml"), body).unwrap();
        // SAFETY: single-threaded test holding ENV_LOCK; removed before return.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    #[test]
    fn the_context_list_is_derived_from_the_deployment() {
        let mut config = Config::default();
        config.server.base_url = "https://ca.example.com:3000".to_string();
        config.admin.base_url = "https://panel.internal.test".to_string();
        config.signer.local_ca.subject.common_name = Some("Example Corp Issuing CA".to_string());
        config.signer.local_ca.subject.organizational_unit = Some("Platform".to_string());
        config.signer.local_ca.subject.state = Some("Noord-Holland".to_string());
        config.signer.local_ca.subject.locality = Some("Amsterdam".to_string());
        // Two characters, so below the floor whatever it holds -- which is
        // why `push_subject` does not read it at all.
        config.signer.local_ca.subject.country = Some("NL".to_string());

        let context = PasswordContext::from_config(&config, "operator");
        let words = context.words();

        for expected in [
            "acme",
            "proxy",
            "operator",
            "example",
            "panel",
            "internal",
            "test",
            "issuing",
            "platform",
            "noord",
            "holland",
            "amsterdam",
        ] {
            assert!(
                words.iter().any(|word| word == expected),
                "expected `{expected}` among {words:?}"
            );
        }

        // The scheme is not this deployment's name, and parsing the URL rather
        // than splitting it is what keeps it out.
        for absent in ["http", "https"] {
            assert!(
                !words.iter().any(|word| word == absent),
                "`{absent}` came from a URL scheme: {words:?}"
            );
        }
        // Under MIN_CONTEXT_WORD_LEN: `com` from the host, `ca` from both the
        // host and the CommonName, `nl` from the country.
        for absent in ["com", "ca", "nl"] {
            assert!(
                !words.iter().any(|word| word == absent),
                "`{absent}` is under the floor and must bar nothing: {words:?}"
            );
        }

        let mut expected = words.to_vec();
        expected.sort();
        expected.dedup();
        assert_eq!(
            words,
            expected.as_slice(),
            "words must be sorted and unique"
        );
    }

    #[test]
    fn a_context_word_is_refused_as_a_substring_and_named_in_the_message() {
        let mut config = Config::default();
        config.server.base_url = "https://ca.example.com".to_string();
        let context = PasswordContext::from_config(&config, "operator");

        let error = check_password_policy("acmeproxy2026!!", &context).unwrap_err();
        assert!(
            error.contains("acme"),
            "the message must name the word: {error}"
        );
        assert!(error.contains("names this deployment"), "got: {error}");
        assert!(
            !error.contains("acmeproxy2026!!"),
            "the message must name the word, never the password: {error}"
        );

        // Folded on both sides.
        assert!(check_password_policy("XXXX-ExAmPlE-XXXX", &context).is_err());
        // And a password naming nothing is accepted.
        assert!(check_password_policy("a-long-enough-password", &context).is_ok());
    }

    /// The empty context is a *weaker* check, never a wrong one.
    #[test]
    fn an_empty_context_bars_nothing_and_keeps_the_other_rules() {
        let none = PasswordContext::empty();
        assert!(none.words().is_empty());
        assert!(check_password_policy("acmeproxy2026!!", &none).is_ok());
        assert!(check_password_policy("passwordpassword", &none).is_err());
        assert!(check_password_policy("short", &none).is_err());
    }

    /// Cheapest first, and each rule ends the check: one refusal names one
    /// reason, about a string that was never going to be accepted anyway.
    #[test]
    fn each_rule_ends_the_check() {
        let mut config = Config::default();
        config.server.base_url = "https://ca.example.com".to_string();
        let context = PasswordContext::from_config(&config, "operator");

        // Length before context: `acme` is barred and also four characters.
        let error = check_password_policy("acme", &context).unwrap_err();
        assert!(error.contains("at least 12"), "got: {error}");

        // Context before the corpus: `passwordpassword` is a corpus entry, and
        // a list barring `word` reaches it first.
        let barring_word = PasswordContext {
            words: vec!["word".to_string()],
        };
        assert!(is_common("passwordpassword"));
        let error = check_password_policy("passwordpassword", &barring_word).unwrap_err();
        assert!(error.contains("names this deployment"), "got: {error}");
    }

    /// A profile contributes its name -- which is in every `kid` and order URL
    /// that endpoint ever issued -- and its own resolved CA subject, not just
    /// the global one.
    #[test]
    fn profiles_contribute_their_names_and_their_own_ca_subjects() {
        let config = load(
            r#"
            [profiles.staging]
            [profiles.staging.signer.local_ca.subject]
            common_name = "Contoso Staging Root"
        "#,
        );

        let context = PasswordContext::from_config(&config, "op");
        let words = context.words();
        for expected in ["staging", "contoso", "root"] {
            assert!(
                words.iter().any(|word| word == expected),
                "expected `{expected}` among {words:?}"
            );
        }
        // Two characters: a short username contributes nothing.
        assert!(!words.iter().any(|word| word == "op"));
    }

    /// **A configuration resolving no profiles must still yield a word list**,
    /// and this is the common case rather than a corner one: a bare
    /// `Config::default()` resolves none, and the CLI legitimately runs
    /// `admin user create` against a configuration the server would refuse to
    /// start on. Refusing a password change because an unrelated section is
    /// missing would be a lockout caused by the control meant to prevent one.
    #[test]
    fn a_configuration_with_no_resolvable_profiles_still_yields_words() {
        let config = Config::default();
        assert!(
            config.resolve_profiles().is_err(),
            "a default configuration resolves no profiles -- if that ever changes, \
             this test stops proving the fallback works"
        );

        let context = PasswordContext::from_config(&config, "operator");
        let words = context.words();
        for expected in ["acme", "proxy", "operator", "localhost"] {
            assert!(
                words.iter().any(|word| word == expected),
                "expected `{expected}` among {words:?}"
            );
        }
    }

    /// A `base_url` that will not parse contributes nothing, rather than
    /// contributing its scheme or a fragment of itself.
    #[test]
    fn an_unparseable_base_url_contributes_nothing() {
        let mut config = Config::default();
        config.server.base_url = "not a url".to_string();
        config.admin.base_url = String::new();

        let context = PasswordContext::from_config(&config, "operator");
        assert_eq!(context.words(), ["acme", "operator", "proxy"]);
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
