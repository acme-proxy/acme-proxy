//! External Account Binding (RFC 8555 §7.3.4), **outbound**: the inner HMAC
//! JWS this server attaches to its own `newAccount` request when the upstream
//! CA requires a pre-shared credential.
//!
//! The exact mirror of [`crate::eab`], which does the same thing in the other
//! direction — verifying the EAB a *client* of this server presents. Same
//! envelope, same `HS256`, same `ring::hmac`; only the direction differs, so
//! the types are reused rather than redefined and the round-trip is testable
//! against the existing verifier.
//!
//! ## The secret never lives on this server
//!
//! An EAB credential authorizes exactly one thing — a single `newAccount`
//! call — and is useless afterwards. So it is not configuration: it is passed
//! once to `acme-proxy upstream register` (see [`crate::cli::upstream`]),
//! used, and dropped. Only the resulting account `kid` is persisted, and a
//! `kid` is not a secret. That is why [`build`] borrows the secret rather than
//! storing it anywhere, and why nothing on the `serve` path calls this module.

use base64::prelude::*;
use ring::hmac;
use serde_json::Value;

use crate::eab::EabJws;

/// Only supported MAC algorithm, matching what [`crate::eab`] accepts on the
/// way in and what RFC 8555 §7.3.4 recommends.
const ALG: &str = "HS256";

/// Builds the inner EAB JWS to embed as the `externalAccountBinding` member of
/// a `newAccount` payload.
///
/// - `kid` / `hmac_secret`: the credential the upstream's operator issued.
/// - `account_jwk`: the public key of the account being registered. RFC 8555
///   requires the inner payload to be exactly this, which is what binds the
///   credential to *this* key and no other.
/// - `new_account_url`: must equal the outer JWS's own `url`, so the binding
///   cannot be lifted onto a different request.
pub(crate) fn build(
    kid: &str,
    hmac_secret: &[u8],
    account_jwk: &Value,
    new_account_url: &str,
) -> EabJws {
    let protected = serde_json::json!({ "alg": ALG, "kid": kid, "url": new_account_url });
    // Both `to_vec` calls are on values this function just built from strings,
    // so serialization cannot fail.
    let protected_b64 =
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap_or_default());
    let payload_b64 =
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(account_jwk).unwrap_or_default());

    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_secret);
    let signature = hmac::sign(&key, format!("{protected_b64}.{payload_b64}").as_bytes());

    EabJws {
        protected: protected_b64,
        payload: payload_b64,
        signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
    }
}

/// Decodes an EAB HMAC secret, accepting every base64 flavor an operator is
/// likely to hand this server: base64url first (what this project's own
/// `eab create` prints), unpadded or padded, then falls back to standard
/// base64 so a credential from another CA's console pastes in unchanged.
///
/// A value that decodes as none of them is `None` rather than being silently
/// used as raw bytes — that would build a binding the upstream rejects for no
/// visible reason. Shared between `cli::upstream`'s `--eab-hmac-key-file`/
/// stdin path and `signer.relay.eab.hmac_key` in configuration, so both
/// entry points accept exactly the same secrets.
pub(crate) fn decode_secret(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    BASE64_URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| BASE64_URL_SAFE.decode(value))
        .or_else(|_| BASE64_STANDARD.decode(value))
        .ok()
        .filter(|decoded| !decoded.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eab::{EabError, parse_header, verify_payload_and_signature};
    use crate::extractors::acme::Jwk;

    const SECRET: &[u8] = b"01234567890123456789012345678901";
    const URL: &str = "https://upstream.example/newAccount";

    fn jwk_value() -> Value {
        serde_json::json!({ "crv": "P-256", "kty": "EC", "x": "x-value", "y": "y-value" })
    }

    fn jwk_typed() -> Jwk {
        Jwk::EC {
            crv: "P-256".to_string(),
            x: "x-value".to_string(),
            y: "y-value".to_string(),
        }
    }

    /// The whole point: what this module builds must be exactly what the
    /// inbound verifier accepts. Checking it against `crate::eab` rather than
    /// against a hand-written expectation is what stops the two halves
    /// drifting apart — a mismatch here is a credential a real upstream would
    /// reject, which is otherwise only discoverable against a live CA.
    #[test]
    fn a_built_eab_verifies_with_this_crates_own_verifier() {
        let eab = build("kid-1", SECRET, &jwk_value(), URL);

        let header = parse_header(&eab, URL).expect("the header must be well formed");
        assert_eq!(header.kid, "kid-1");
        assert_eq!(header.alg, "HS256");

        verify_payload_and_signature(&eab, SECRET, &jwk_typed())
            .expect("the signature must verify against the same secret");
    }

    #[test]
    fn the_url_is_bound_into_the_signature() {
        let eab = build("kid-1", SECRET, &jwk_value(), URL);
        // Presented at any other endpoint, the binding must not be accepted.
        assert!(matches!(
            parse_header(&eab, "https://upstream.example/other"),
            Err(EabError::Malformed(_))
        ));
    }

    #[test]
    fn a_different_secret_does_not_verify() {
        let eab = build("kid-1", SECRET, &jwk_value(), URL);
        assert!(matches!(
            verify_payload_and_signature(&eab, b"a completely different secret!!", &jwk_typed()),
            Err(EabError::BadSignature)
        ));
    }

    /// The binding names one account key; presenting it for another must fail.
    #[test]
    fn the_account_key_is_bound_into_the_payload() {
        let eab = build("kid-1", SECRET, &jwk_value(), URL);
        let other = Jwk::EC {
            crv: "P-256".to_string(),
            x: "different".to_string(),
            y: "different".to_string(),
        };
        assert!(matches!(
            verify_payload_and_signature(&eab, SECRET, &other),
            Err(EabError::Malformed(_))
        ));
    }

    /// A real account key, rather than a hand-written JWK, must also round
    /// trip — this is the shape `upstream register` actually passes.
    #[test]
    fn a_real_account_keys_jwk_round_trips() {
        let pkcs8 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_der();
        let account = super::super::client::AccountKey::from_pkcs8(&pkcs8).unwrap();

        let eab = build("kid-1", SECRET, &account.jwk(), URL);
        parse_header(&eab, URL).unwrap();

        // The typed `Jwk` the verifier compares against is derived from the
        // account's stored SPKI, so this also pins the two representations of
        // the same key to each other.
        let spki_jwk: Jwk = serde_json::from_value(account.jwk()).unwrap();
        verify_payload_and_signature(&eab, SECRET, &spki_jwk).unwrap();
    }

    #[test]
    fn a_base64url_secret_decodes() {
        let secret = b"01234567890123456789012345678901";
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(secret);
        assert_eq!(decode_secret(&encoded).as_deref(), Some(&secret[..]));
    }

    /// Another CA's console may hand out padded standard base64; it must
    /// paste in unchanged rather than being rejected.
    #[test]
    fn a_standard_base64_secret_decodes() {
        let secret = b"\xff\xfe\xfd\xfc some bytes";
        let encoded = BASE64_STANDARD.encode(secret);
        assert_eq!(decode_secret(&encoded).as_deref(), Some(&secret[..]));
    }

    #[test]
    fn a_non_base64_secret_is_refused() {
        // Not "silently used as raw bytes": that would build a binding the
        // upstream rejects with no clue why.
        assert!(decode_secret("not base64!!!").is_none());
        assert!(decode_secret("").is_none());
    }
}
