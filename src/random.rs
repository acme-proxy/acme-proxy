//! Random values from the system CSPRNG.
//!
//! One definition of an idiom that had been written out at every call site
//! that needed it: fill a buffer from `ring::rand::SystemRandom` and panic if
//! the OS cannot supply the bytes. The comments at those sites cross-referenced
//! each other by name ("the same trade-off `authz::generate_token` makes"),
//! which is the shape a hoist is owed.
//!
//! Two sites deliberately stay outside this module, both because their failure
//! handling differs rather than their randomness:
//! [`crate::signer::local_ca`]'s serial generator returns a `Result`, and the
//! job runner's retry jitter falls back to an unjittered delay rather than
//! panicking.

use base64::prelude::*;
use ring::rand::{SecureRandom, SystemRandom};

/// Bytes, in a [`random_token`], before encoding: 256 bits, the size every
/// non-guessable value in this tree is minted at.
const TOKEN_BYTES: usize = 32;

/// `N` bytes from the system CSPRNG.
///
/// An unavailable system RNG is unrecoverable and threading the error out
/// would only move the panic, so this panics.
#[must_use]
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG unavailable");
    bytes
}

/// A fresh high-entropy token: [`TOKEN_BYTES`] random bytes, base64url-encoded
/// without padding, which is 43 characters.
///
/// That encoding is not cosmetic. It is what RFC 8555 §8.1 requires of a
/// challenge token and §6.5.1 of a `Replay-Nonce`, and it is header-safe and
/// URL-safe everywhere else the value is carried.
#[must_use]
pub(crate) fn random_token() -> String {
    BASE64_URL_SAFE_NO_PAD.encode(random_bytes::<TOKEN_BYTES>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_fills_the_whole_buffer() {
        // Two draws of the same width differing is the only thing that can
        // tell a filled buffer from a zeroed one that was never touched.
        assert_ne!(random_bytes::<32>(), [0u8; 32]);
        assert_ne!(random_bytes::<32>(), random_bytes::<32>());
        assert_eq!(random_bytes::<16>().len(), 16);
    }

    #[test]
    fn random_token_is_43_base64url_characters_over_32_bytes() {
        let token = random_token();

        assert_eq!(token.len(), 43, "43 characters encode 32 bytes unpadded");
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "the base64url alphabet only: {token}"
        );
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.decode(&token).unwrap().len(),
            TOKEN_BYTES
        );
    }

    #[test]
    fn random_token_does_not_repeat() {
        assert_ne!(random_token(), random_token());
    }
}
