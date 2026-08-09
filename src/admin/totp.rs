//! RFC 6238 time-based one-time passwords, over RFC 4226's HOTP.
//!
//! Hand-rolled on `ring::hmac`, which is already this crate's crypto backend
//! everywhere else, rather than pulling a TOTP crate in: the whole primitive is
//! an HMAC, an eight-byte counter and RFC 4226 §5.4's dynamic truncation, and
//! both RFCs publish test vectors, so the hand-rolled version is checkable
//! against the same authority a dependency would be. Same bar
//! [`crate::admin::password`]'s module doc sets when it rejects Argon2id.
//!
//! This module holds no database access and no I/O -- the split
//! [`crate::eab`] (pure verification) and `sqlite::eab` (persistence) already
//! make. The replay guard RFC 6238 §5.2 asks for needs a row, so it lives in
//! `AdminUser::claim_totp_step`; [`verify`] deliberately knows nothing about
//! it.
//!
//! ## Why HMAC-**SHA-1**
//!
//! `src/eab.rs` uses HMAC-SHA256, so SHA-256 looks like the house style here.
//! It is the wrong choice: **Google Authenticator ignores the `algorithm=`
//! parameter of an `otpauth://` URI and always computes SHA-1**, so an operator
//! enrolling with the most widely deployed authenticator would get an entry
//! producing wrong codes forever, with no diagnosis available from either side.
//! A second factor nobody can enrol is not a second factor.
//!
//! SHA-1's collision attacks do not weaken HMAC-SHA1 -- HMAC's security rests
//! on the compression function being a PRF, not on collision resistance, which
//! is why RFC 6238 §1.2 and NIST SP 800-107 both still specify it here. The
//! `ring` constant is named `HMAC_SHA1_FOR_LEGACY_USE_ONLY`, so **this comment
//! is the reason not to "fix" it.**
//!
//! The stored secret carries no algorithm tag, so changing this later means
//! re-enrolment -- one `acme-proxy admin user totp reset` per operator, which
//! is exactly why that command exists.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use url::Url;

/// RFC 4648 §6's alphabet. Shared with [`crate::admin::recovery`], so there is
/// one table and one test: it already excludes `0`, `1`, `8` and `9`, which is
/// what lets a recovery code be read off a screen without a confusable fixup.
pub(crate) const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 160 bits: RFC 4226 §4 R6's floor, what every authenticator expects, and
/// exactly 32 base32 characters -- so the encoder never has to pad and the
/// operator never has to type a `=`.
pub const SECRET_LEN: usize = 20;

/// RFC 6238 §4's default time step, and universally assumed by clients.
pub const PERIOD_SECONDS: i64 = 30;

/// Code length. Six is what every authenticator renders.
pub const DIGITS: u32 = 6;

/// RFC 6238 §5.2 permits one step of clock skew either way. More widens the
/// guessing window for no usability gain.
pub const SKEW_STEPS: i64 = 1;

/// The issuer this server names itself as in an `otpauth://` URI. It is what an
/// authenticator app shows above the code.
pub const ISSUER: &str = "acme-proxy";

/// A generated enrolment: the bytes to store, and the two things the operator
/// must see exactly once.
#[derive(Debug, Clone)]
pub struct Enrolment {
    /// The raw secret, for `admin_users.totp_pending_secret`.
    pub secret: Vec<u8>,
    /// The same secret as the operator types it into an app.
    pub secret_base32: String,
    /// The `otpauth://` URI, for a QR code or a click-through.
    pub uri: String,
}

/// Mints a secret and the two representations of it the enrolment page shows.
///
/// `account` is what distinguishes two entries in one authenticator, so it
/// carries the operator's name and the host they administer -- see
/// [`account_label`].
#[must_use]
pub fn begin_enrolment(issuer: &str, account: &str) -> Enrolment {
    let secret = generate_secret();
    let secret_base32 = base32_encode(&secret);
    let uri = provisioning_uri(&secret_base32, issuer, account);
    Enrolment {
        secret,
        secret_base32,
        uri,
    }
}

/// [`SECRET_LEN`] bytes from the system CSPRNG.
#[must_use]
pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_LEN];
    // Same trade-off as `password::hash_with_iterations` and
    // `sqlite::eab::generate_secret`: an unavailable system RNG is
    // unrecoverable, and threading the error out would only move the panic.
    SystemRandom::new()
        .fill(&mut secret)
        .expect("system RNG unavailable");
    secret
}

/// The account half of an `otpauth://` label: `alice@admin.example.com`.
///
/// The host disambiguates two acme-proxy instances in one authenticator, which
/// is why `admin.base_url` is load-bearing here as well as in the CSRF origin
/// check and the generated certificate's name. A `base_url` that does not parse
/// or has no host cannot reach this -- `webadmin::check_config` refuses to start
/// on one -- but fall back to the bare username rather than panicking on a
/// caller that skipped it.
#[must_use]
pub fn account_label(username: &str, base_url: &str) -> String {
    match Url::parse(base_url).ok().and_then(|url| {
        url.host_str()
            .filter(|host| !host.is_empty())
            .map(str::to_string)
    }) {
        Some(host) => format!("{username}@{host}"),
        None => username.to_string(),
    }
}

/// Builds the `otpauth://totp/<issuer>:<account>?…` URI.
///
/// Built through `url` rather than `format!` on purpose: `account` carries an
/// operator-supplied username, which is only lowercased and trimmed and may
/// therefore hold `/`, `?`, `#` or a space. `PathSegmentsMut::push`
/// percent-encodes the whole label as one segment, including a `/` that would
/// otherwise silently become a second path component.
#[must_use]
pub fn provisioning_uri(secret_base32: &str, issuer: &str, account: &str) -> String {
    let mut url = Url::parse("otpauth://totp").expect("a constant, valid URL");
    url.path_segments_mut()
        .expect("otpauth://totp has an authority, so it can be a base")
        .push(&format!("{issuer}:{account}"));

    url.query_pairs_mut()
        .append_pair("secret", secret_base32)
        .append_pair("issuer", issuer)
        // Emitted although the apps that matter ignore it -- see the module
        // doc. The ones that do read it must not guess.
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", &DIGITS.to_string())
        .append_pair("period", &PERIOD_SECONDS.to_string());

    url.to_string()
}

/// RFC 4648 §6 base32: uppercase, **unpadded**.
///
/// Only an encoder exists, and deliberately so: enrolment generates a secret,
/// stores the raw bytes and shows the base32 for the operator to type into an
/// app. Nothing in this server ever reads base32 back, so a decoder would be
/// untested surface.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(5) * 8);

    for chunk in bytes.chunks(5) {
        // Up to 40 bits, big-endian and left-aligned inside the low 40 bits:
        // the first input byte occupies bits 39..32.
        let mut buffer: u64 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            buffer |= u64::from(*byte) << (32 - 8 * index);
        }

        // How many whole 5-bit groups this many input bits actually fill.
        // Anything beyond is the padding RFC 4648 defines and this does not
        // emit.
        let groups = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for group in 0..groups {
            let value = ((buffer >> (35 - 5 * group)) & 0x1f) as usize;
            encoded.push(BASE32_ALPHABET[value] as char);
        }
    }

    encoded
}

/// RFC 6238 §4's `T`: the number of whole [`PERIOD_SECONDS`] windows since the
/// epoch.
///
/// `div_euclid`, not `/`: truncating division rounds a pre-epoch instant
/// towards zero, which would make two adjacent negative seconds share a step
/// boundary they should not.
#[must_use]
pub fn step_at(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(PERIOD_SECONDS)
}

/// RFC 4226 §5.3's HOTP, truncated to `digits` decimal digits.
///
/// `digits` is a parameter although production only ever passes [`DIGITS`]:
/// RFC 6238's published vectors are 8-digit, and a core that cannot produce
/// them cannot be checked against them.
#[must_use]
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let digest = tag.as_ref();

    // RFC 4226 §5.4's dynamic truncation: the low nibble of the last byte picks
    // where to read four bytes from, and the top bit is masked so the result is
    // a positive 31-bit integer on every platform's notion of signedness.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    // 10^10 overflows a u32, and a zero-digit code is not a code.
    let digits = digits.clamp(1, 9);
    let width = digits as usize;
    format!("{:0width$}", binary % 10u32.pow(digits))
}

/// The code for one time step.
#[must_use]
pub fn totp_at(secret: &[u8], step: i64, digits: u32) -> String {
    // RFC 6238 §4.2 defines the counter as the time step itself. A negative
    // step is pre-epoch and unreachable from a real clock; wrapping it is
    // deterministic, which is all the tests need.
    hotp(secret, step as u64, digits)
}

/// Verifies `code` against `secret` around `now_unix`, returning the time step
/// it matched.
///
/// Every candidate in the ±[`SKEW_STEPS`] window is compared with
/// `subtle::ConstantTimeEq` and the loop **does not short-circuit**, so neither
/// the timing nor the number of comparisons says which step matched. A code of
/// the wrong shape is refused before any HMAC runs.
///
/// Deliberately does **not** consult the replay guard: that needs the database.
/// `admin::mfa::verify_second_factor` calls this, then
/// `AdminUser::claim_totp_step` with the step returned here.
#[must_use]
pub fn verify(secret: &[u8], code: &str, now_unix: i64) -> Option<i64> {
    let width = DIGITS as usize;
    if code.len() != width || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let current = step_at(now_unix);
    let mut matched: Option<i64> = None;
    for step in (current - SKEW_STEPS)..=(current + SKEW_STEPS) {
        let candidate = totp_at(secret, step, DIGITS);
        if bool::from(candidate.as_bytes().ct_eq(code.as_bytes())) {
            matched = Some(step);
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed both RFCs publish their vectors against: the ASCII string
    /// `"12345678901234567890"`.
    const RFC_SEED: &[u8] = b"12345678901234567890";

    /// RFC 4226 Appendix D, the 6-digit column -- the production shape. This is
    /// what pins the dynamic truncation: an off-by-one in the offset or a
    /// missing `& 0x7f` moves every one of these.
    #[test]
    fn rfc_4226_appendix_d_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                &hotp(RFC_SEED, counter as u64, DIGITS),
                want,
                "HOTP counter {counter}"
            );
        }
    }

    /// RFC 6238 Appendix B, the SHA-1 rows. 8 digits, which is why [`hotp`]
    /// takes `digits` at all.
    #[test]
    fn rfc_6238_appendix_b_sha1_vectors() {
        let cases = [
            (59_i64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (time, want) in cases {
            assert_eq!(
                totp_at(RFC_SEED, step_at(time), 8),
                want,
                "RFC 6238 vector at T = {time}"
            );
        }
    }

    /// RFC 4648 §10, with the padding stripped: every residue class of the
    /// 5-bit chunker, which is the only place this encoder can go wrong.
    #[test]
    fn rfc_4648_base32_vectors_unpadded() {
        let cases = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];
        for (input, want) in cases {
            assert_eq!(base32_encode(input.as_bytes()), want, "base32({input:?})");
        }
    }

    #[test]
    fn a_generated_secret_is_exactly_thirty_two_unpadded_characters() {
        let secret = generate_secret();
        assert_eq!(secret.len(), SECRET_LEN);

        let encoded = base32_encode(&secret);
        assert_eq!(
            encoded.len(),
            32,
            "160 bits is chosen so the operator never has to type a `=`"
        );
        assert!(!encoded.contains('='));
        assert!(
            encoded.bytes().all(|byte| BASE32_ALPHABET.contains(&byte)),
            "every character must come from the RFC 4648 alphabet"
        );

        // Two secrets in a row must differ, or the RNG is not wired up.
        assert_ne!(secret, generate_secret());
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_no_further() {
        let secret = generate_secret();
        let now = 1_700_000_000_i64;
        let current = step_at(now);

        for offset in [-1_i64, 0, 1] {
            let code = totp_at(&secret, current + offset, DIGITS);
            assert_eq!(
                verify(&secret, &code, now),
                Some(current + offset),
                "a code {offset} steps away must be accepted, and report its own step"
            );
        }

        for offset in [-2_i64, 2, 10] {
            let code = totp_at(&secret, current + offset, DIGITS);
            assert_eq!(
                verify(&secret, &code, now),
                None,
                "a code {offset} steps away is outside the window"
            );
        }
    }

    #[test]
    fn a_wrong_shaped_code_is_refused_before_any_hmac() {
        let secret = generate_secret();
        let now = 1_700_000_000_i64;

        let cases = [
            ("empty", ""),
            ("too short", "12345"),
            ("too long", "1234567"),
            ("not all digits", "12a456"),
            ("leading space", " 12345"),
            ("trailing space", "12345 "),
            // Six characters, but not six bytes -- `code.len()` is bytes, so
            // this must be refused by the length check rather than reaching the
            // comparison.
            ("non-ascii", "１２３４５６"),
        ];
        for (name, code) in cases {
            assert_eq!(verify(&secret, code, now), None, "case `{name}`");
        }
    }

    #[test]
    fn step_at_does_not_straddle_the_epoch() {
        assert_eq!(step_at(0), 0);
        assert_eq!(step_at(29), 0);
        assert_eq!(step_at(30), 1);
        assert_eq!(step_at(59), 1);
        // Truncating division would give 0 for both of these, merging two
        // distinct windows into one.
        assert_eq!(step_at(-1), -1);
        assert_eq!(step_at(-30), -1);
        assert_eq!(step_at(-31), -2);
    }

    #[test]
    fn the_provisioning_uri_carries_every_parameter_an_app_reads() {
        let uri = provisioning_uri("ABCDEFGH", ISSUER, "alice@admin.example.com");
        assert_eq!(
            uri,
            "otpauth://totp/acme-proxy:alice@admin.example.com\
             ?secret=ABCDEFGH&issuer=acme-proxy&algorithm=SHA1&digits=6&period=30"
        );
    }

    /// A username is only trimmed and lowercased, never restricted to a
    /// charset, so the label must survive one that would otherwise rewrite the
    /// URI's own structure.
    #[test]
    fn a_hostile_username_is_percent_encoded_into_one_path_segment() {
        let uri = provisioning_uri("ABCDEFGH", ISSUER, "a/b?c#d e");
        let parsed = Url::parse(&uri).expect("the built URI must parse back");

        let segments: Vec<&str> = parsed
            .path_segments()
            .expect("otpauth:// can be a base")
            .collect();
        assert_eq!(
            segments.len(),
            1,
            "a `/` in the username must not become a second path segment: {uri}"
        );

        // The `?` and `#` must not have terminated the path either -- the query
        // is exactly the five parameters this builds.
        let names: Vec<String> = parsed
            .query_pairs()
            .map(|(name, _)| name.into_owned())
            .collect();
        assert_eq!(names, ["secret", "issuer", "algorithm", "digits", "period"]);
    }

    #[test]
    fn begin_enrolment_agrees_with_itself() {
        let enrolment = begin_enrolment(ISSUER, "alice@admin.example.com");
        assert_eq!(enrolment.secret_base32, base32_encode(&enrolment.secret));
        assert!(
            enrolment
                .uri
                .contains(&format!("secret={}", enrolment.secret_base32)),
            "the URI must carry the same secret the page shows: {}",
            enrolment.uri
        );

        // And the whole thing round-trips: a code built from the raw secret
        // verifies, which is the only assertion that proves the three
        // representations are one secret.
        let now = 1_700_000_000_i64;
        let code = totp_at(&enrolment.secret, step_at(now), DIGITS);
        assert!(verify(&enrolment.secret, &code, now).is_some());
    }

    #[test]
    fn account_label_prefers_the_configured_host() {
        assert_eq!(
            account_label("alice", "https://admin.example.com:3001"),
            "alice@admin.example.com"
        );
        assert_eq!(
            account_label("alice", "http://localhost:3001"),
            "alice@localhost"
        );
        // `check_config` refuses to start on either of these, so this is the
        // belt to that braces -- a label, not a panic.
        assert_eq!(account_label("alice", "not a url"), "alice");
        assert_eq!(account_label("alice", ""), "alice");
    }
}
