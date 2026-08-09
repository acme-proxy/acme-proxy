//! Recovery codes: the way back in when the phone holding the TOTP secret is
//! gone.
//!
//! Ten single-use codes, minted when a factor is confirmed and shown exactly
//! once -- the treatment `eab create` already gives its HMAC secret. Stored
//! one-way through [`crate::admin::password`], because a recovery code is a
//! *password* in every respect that matters: it is only ever compared, never
//! needed back, so the database holds nothing replayable. That is the opposite
//! of `admin_users.totp_secret`, which verification needs in the clear on every
//! attempt.
//!
//! This module is generation and normalisation only. Consumption is a single
//! `UPDATE … WHERE id = ? AND used_at IS NULL` in
//! [`crate::sqlite::admin_recovery_code`], because "single-use" has to be
//! decided by the database rather than by a read followed by a write.

use ring::rand::{SecureRandom, SystemRandom};

use crate::admin::totp::BASE32_ALPHABET;

/// Codes minted per set. Enough to cover a lost phone and a few false starts
/// without becoming a list nobody stores anywhere safe.
pub const CODE_COUNT: usize = 10;

/// Characters per code, from a 32-symbol alphabet: 50 bits, which is far past
/// what the login limiter and a `pending_mfa` session's five-minute life leave
/// guessable.
pub const CODE_LEN: usize = 10;

/// Where the separator goes when a code is rendered for a human.
const GROUP_LEN: usize = 5;

/// Mints a fresh set. The caller hashes them, stores the hashes, and shows
/// these strings once.
#[must_use]
pub fn generate_codes() -> Vec<String> {
    (0..CODE_COUNT).map(|_| generate_code()).collect()
}

/// One code, formatted for someone reading it off a screen and typing it back:
/// `K7QF2-3BXTM`.
#[must_use]
fn generate_code() -> String {
    let mut bytes = [0u8; CODE_LEN];
    // Same trade-off as `totp::generate_secret`: an unavailable system RNG is
    // unrecoverable, and threading the error out would only move the panic.
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG unavailable");

    let mut code = String::with_capacity(CODE_LEN + 1);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % GROUP_LEN == 0 {
            code.push('-');
        }
        // Modulo bias over a 32-symbol alphabet from a 256-value byte is
        // exactly zero: 256 is a multiple of 32.
        code.push(BASE32_ALPHABET[usize::from(*byte) % BASE32_ALPHABET.len()] as char);
    }
    code
}

/// Canonicalises a submitted code so the grouping and the case an operator
/// typed cannot make a correct code fail.
///
/// Deliberately **no** confusable-character fixup (`O`→`0`, `l`→`1`): the
/// alphabet is RFC 4648 base32, which already excludes `0`, `1`, `8` and `9`,
/// so there is nothing to confuse them *with*. A fixup would only widen what
/// counts as a match.
#[must_use]
pub fn normalize(raw: &str) -> String {
    raw.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

/// Whether `candidate` could be a recovery code at all.
///
/// Lets the second-factor path skip up to ten PBKDF2 runs on something that is
/// plainly a mistyped TOTP code -- the same "refuse the wrong shape before any
/// crypto" rule [`crate::admin::totp::verify`] follows.
#[must_use]
pub fn is_well_formed(candidate: &str) -> bool {
    candidate.len() == CODE_LEN
        && candidate
            .bytes()
            .all(|byte| BASE32_ALPHABET.contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_set_is_ten_distinct_codes_from_the_base32_alphabet() {
        let codes = generate_codes();
        assert_eq!(codes.len(), CODE_COUNT);

        let distinct: HashSet<&String> = codes.iter().collect();
        assert_eq!(
            distinct.len(),
            CODE_COUNT,
            "codes must not repeat: {codes:?}"
        );

        for code in &codes {
            // `K7QF2-3BXTM`: two groups of five with one separator.
            assert_eq!(code.len(), CODE_LEN + 1, "{code}");
            assert_eq!(code.chars().nth(GROUP_LEN), Some('-'), "{code}");

            let normalized = normalize(code);
            assert!(
                is_well_formed(&normalized),
                "a freshly minted code must pass the shape check: {code}"
            );
        }
    }

    #[test]
    fn normalize_absorbs_the_ways_a_human_retypes_a_code() {
        let canonical = "K7QF23BXTM";
        for typed in [
            "K7QF2-3BXTM",
            "k7qf2-3bxtm",
            " K7QF2 3BXTM ",
            "K7QF2\t3BXTM\n",
            "K7QF23BXTM",
            "K7-QF2-3B-XTM",
        ] {
            assert_eq!(normalize(typed), canonical, "input {typed:?}");
        }

        // Idempotent, since the login path normalises once and the tests
        // normalise again.
        assert_eq!(normalize(canonical), canonical);
        assert_eq!(normalize(&normalize("k7qf2-3bxtm")), canonical);
    }

    #[test]
    fn the_shape_check_refuses_what_is_plainly_not_a_recovery_code() {
        assert!(is_well_formed("K7QF23BXTM"));

        let cases = [
            ("empty", ""),
            ("a totp code", "123456"),
            ("too short", "K7QF23BXT"),
            ("too long", "K7QF23BXTMM"),
            // The four characters the alphabet leaves out, which is what makes
            // the confusable fixup unnecessary.
            ("contains 0", "K7QF23BXT0"),
            ("contains 1", "K7QF23BXT1"),
            ("contains 8", "K7QF23BXT8"),
            ("contains 9", "K7QF23BXT9"),
            ("still grouped", "K7QF2-3BXT"),
            ("lowercase", "k7qf23bxtm"),
        ];
        for (name, candidate) in cases {
            assert!(!is_well_formed(candidate), "case `{name}`");
        }
    }
}
