//! External Account Binding (RFC 8555 §7.3.4): verification of the inner HMAC
//! JWS a `newAccount` payload may carry, proving the client holds a
//! pre-shared credential an operator issued out-of-band.
//!
//! Pure verification logic only -- no database access. [`crate::sqlite::eab`]
//! is the persistence layer for the credentials themselves (create/find/list/
//! revoke); this module only checks an already-looked-up secret against an
//! already-parsed request. The same split [`crate::dns`] and
//! [`crate::pemfile`] draw between "how" and "where from".
//!
//! ## Shape
//!
//! The inner object is itself a flattened JWS (RFC 7515), reusing
//! [`crate::extractors::acme::AcmeJwsRequest`]'s `{protected, payload,
//! signature}` shape as [`EabJws`] -- the same three-field envelope,
//! HMAC-signed rather than public-key-signed.
//!
//! Its protected header ([`EabHeader`]) is deliberately its own type rather
//! than a reuse of [`crate::extractors::acme::ProtectedHeader`]: `kid` is
//! required here (a distinct namespace from the account `kid`), there is no
//! `jwk` member, and there is no `nonce` -- this is a credential bound into a
//! request the outer JWS already authenticates and replay-protects, not a
//! second signed request in its own right. A client that sends a `nonce`
//! anyway has it silently ignored, like any other unknown field the payload
//! types in this codebase accept.
//!
//! Its payload is the account's public key, as a plain JWK JSON object -- the
//! same [`Jwk`] shape the outer JWS embeds -- and verification requires the
//! two to be structurally equal (`Jwk` derives `PartialEq`), which is what
//! binds the credential to *this* account key rather than any other.

use base64::prelude::*;
use ring::hmac;
use serde::Deserialize;

use crate::error::Problem;
use crate::extractors::acme::Jwk;

/// The inner EAB JWS: the same flattened `{protected, payload, signature}`
/// shape as the outer request JWS.
pub(crate) type EabJws = crate::extractors::acme::AcmeJwsRequest;

/// The inner EAB JWS's protected header. See the [module docs](self) for why
/// this is its own type rather than a reuse of `ProtectedHeader`.
#[derive(Debug, Deserialize)]
pub(crate) struct EabHeader {
    pub alg: String,
    pub kid: String,
    pub url: String,
}

/// Why EAB verification failed, in the two buckets [`eab_problem`] renders as
/// HTTP status: a shape problem the client can fix by resending correctly
/// formed EAB (`Malformed`, 400), or a signature that plainly does not verify
/// against the looked-up secret (`BadSignature`, 401). An unknown or revoked
/// `kid` is not represented here at all: that decision needs the database, so
/// the caller (`verify_eab` in `lib.rs`) makes it directly.
#[derive(Debug)]
pub(crate) enum EabError {
    Malformed(&'static str),
    BadSignature,
}

/// Only supported inner MAC algorithm, per RFC 8555's own recommendation. Not
/// configurable: a knob with exactly one safe value is not a knob.
const SUPPORTED_ALG: &str = "HS256";

/// Decodes and validates the inner EAB JWS's protected header: `alg` must be
/// `HS256`, and `url` must equal `expected_url` -- the same URL the outer
/// JWS's own `header.url` was already checked against (RFC 8555 §6.4), i.e.
/// this exact `newAccount` request.
///
/// Returns the header so the caller can look up `kid`'s HMAC secret (a DB
/// operation this module does not perform) before finishing verification with
/// [`verify_payload_and_signature`].
pub(crate) fn parse_header(eab: &EabJws, expected_url: &str) -> Result<EabHeader, EabError> {
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&eab.protected)
        .map_err(|_| EabError::Malformed("EAB protected base64 invalid"))?;

    let header: EabHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|_| EabError::Malformed("EAB protected JSON invalid"))?;

    if header.alg != SUPPORTED_ALG {
        return Err(EabError::Malformed("EAB alg must be HS256"));
    }
    if header.url != expected_url {
        return Err(EabError::Malformed("EAB url does not match the request"));
    }

    Ok(header)
}

/// Completes EAB verification once `kid`'s HMAC secret has been looked up:
/// the inner payload must decode to a [`Jwk`] structurally equal to the
/// account's own embedded JWK (`outer_jwk`), and the HS256 signature over
/// `protected_b64.payload_b64` must verify against `hmac_secret`.
pub(crate) fn verify_payload_and_signature(
    eab: &EabJws,
    hmac_secret: &[u8],
    outer_jwk: &Jwk,
) -> Result<(), EabError> {
    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&eab.payload)
        .map_err(|_| EabError::Malformed("EAB payload base64 invalid"))?;
    let inner_jwk: Jwk = serde_json::from_slice(&payload_bytes)
        .map_err(|_| EabError::Malformed("EAB payload is not a JWK"))?;
    if &inner_jwk != outer_jwk {
        return Err(EabError::Malformed(
            "EAB payload JWK does not match the account key",
        ));
    }

    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&eab.signature)
        .map_err(|_| EabError::Malformed("EAB signature base64 invalid"))?;

    let signing_input = format!("{}.{}", eab.protected, eab.payload);
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_secret);
    hmac::verify(&key, signing_input.as_bytes(), &sig_bytes).map_err(|_| EabError::BadSignature)
}

/// Maps an [`EabError`] to the `Problem` the caller rejects with. Structural
/// failures -- malformed base64/JSON, an unsupported `alg`, a `url` mismatch,
/// or a payload JWK that does not match the account's own -- are `malformed`
/// (400), mirroring how the outer JWS's own `SignatureError` splits shape
/// problems from signature-validity ones. A signature that simply does not
/// verify is `unauthorized` (401), the same as a bad outer JWS signature.
pub(crate) fn eab_problem(error: EabError) -> Problem {
    match error {
        EabError::Malformed(detail) => Problem::malformed(detail),
        EabError::BadSignature => {
            Problem::unauthorized("External Account Binding signature invalid")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwk_a() -> Jwk {
        Jwk::EC {
            crv: "P-256".to_string(),
            x: "x-a".to_string(),
            y: "y-a".to_string(),
        }
    }

    fn jwk_b() -> Jwk {
        Jwk::EC {
            crv: "P-256".to_string(),
            x: "x-b".to_string(),
            y: "y-b".to_string(),
        }
    }

    fn b64_json(value: &serde_json::Value) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    fn jwk_json(jwk: &Jwk) -> serde_json::Value {
        match jwk {
            Jwk::EC { crv, x, y } => json!({ "kty": "EC", "crv": crv, "x": x, "y": y }),
            Jwk::RSA { n, e } => json!({ "kty": "RSA", "n": n, "e": e }),
        }
    }

    /// Builds a well-formed EAB JWS signed with `secret`, embedding `jwk` as
    /// its payload.
    fn build(secret: &[u8], alg: &str, kid: &str, url: &str, jwk: &Jwk) -> EabJws {
        let protected = json!({ "alg": alg, "kid": kid, "url": url });
        let protected_b64 = b64_json(&protected);
        let payload_b64 = b64_json(&jwk_json(jwk));
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let signature = hmac::sign(&key, signing_input.as_bytes());
        EabJws {
            protected: protected_b64,
            payload: payload_b64,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
        }
    }

    const SECRET: &[u8] = b"01234567890123456789012345678901";
    const URL: &str = "http://localhost:3000/newAccount";

    #[test]
    fn parse_header_accepts_hs256_and_matching_url() {
        let eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        let header = parse_header(&eab, URL).unwrap();
        assert_eq!(header.kid, "kid-1");
    }

    #[test]
    fn parse_header_rejects_unsupported_alg() {
        let eab = build(SECRET, "HS384", "kid-1", URL, &jwk_a());
        assert!(matches!(
            parse_header(&eab, URL),
            Err(EabError::Malformed(_))
        ));
    }

    #[test]
    fn parse_header_rejects_url_mismatch() {
        let eab = build(
            SECRET,
            "HS256",
            "kid-1",
            "http://localhost:3000/other",
            &jwk_a(),
        );
        assert!(matches!(
            parse_header(&eab, URL),
            Err(EabError::Malformed(_))
        ));
    }

    #[test]
    fn parse_header_rejects_malformed_base64_and_json() {
        let mut eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        eab.protected = "!!!not-base64!!!".to_string();
        assert!(matches!(
            parse_header(&eab, URL),
            Err(EabError::Malformed(_))
        ));

        let mut eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        eab.protected = BASE64_URL_SAFE_NO_PAD.encode(b"not json");
        assert!(matches!(
            parse_header(&eab, URL),
            Err(EabError::Malformed(_))
        ));
    }

    /// A client-sent `nonce` in the inner header is silently ignored, since
    /// `EabHeader` has no such field.
    #[test]
    fn parse_header_ignores_an_extra_nonce_field() {
        let protected = json!({ "alg": "HS256", "kid": "kid-1", "url": URL, "nonce": "n" });
        let protected_b64 = b64_json(&protected);
        let eab = EabJws {
            protected: protected_b64,
            payload: String::new(),
            signature: String::new(),
        };
        assert!(parse_header(&eab, URL).is_ok());
    }

    #[test]
    fn verify_payload_and_signature_accepts_correct_hmac() {
        let eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        assert!(verify_payload_and_signature(&eab, SECRET, &jwk_a()).is_ok());
    }

    #[test]
    fn verify_payload_and_signature_rejects_wrong_secret() {
        let eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        assert!(matches!(
            verify_payload_and_signature(&eab, b"a-completely-different-secret!!", &jwk_a()),
            Err(EabError::BadSignature)
        ));
    }

    #[test]
    fn verify_payload_and_signature_rejects_a_tampered_signature() {
        let mut eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        eab.signature = BASE64_URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(matches!(
            verify_payload_and_signature(&eab, SECRET, &jwk_a()),
            Err(EabError::BadSignature)
        ));
    }

    #[test]
    fn verify_payload_and_signature_rejects_a_jwk_payload_mismatch() {
        // Signed correctly, but the account key it names differs from the
        // outer JWS's own key -- must be rejected as `Malformed`, checked
        // *before* HMAC verification would even matter.
        let eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        assert!(matches!(
            verify_payload_and_signature(&eab, SECRET, &jwk_b()),
            Err(EabError::Malformed(_))
        ));
    }

    #[test]
    fn verify_payload_and_signature_rejects_malformed_payload_json() {
        let mut eab = build(SECRET, "HS256", "kid-1", URL, &jwk_a());
        eab.payload = BASE64_URL_SAFE_NO_PAD.encode(b"not a jwk");
        assert!(matches!(
            verify_payload_and_signature(&eab, SECRET, &jwk_a()),
            Err(EabError::Malformed(_))
        ));
    }
}
