//! Account Key Rollover (RFC 8555 §7.3.5): verification of the nested inner
//! JWS a `keyChange` request's payload carries, proving simultaneous
//! possession of both the old and new account keys.
//!
//! Pure verification logic only -- no database access. This mirrors the
//! split [`crate::eab`] draws for the same reason: this module only checks
//! an already-parsed request against values the caller (`post_key_change` in
//! `lib.rs`) already looked up.
//!
//! ## Shape
//!
//! RFC 8555 §7.3.5's inner object is itself a flattened JWS (RFC 7515),
//! reusing [`crate::extractors::acme::AcmeJwsRequest`]'s `{protected,
//! payload, signature}` shape as [`KeyChangeJws`] -- the same convention
//! [`crate::eab::EabJws`] uses.
//!
//! Its protected header ([`InnerHeader`]) is its own type rather than a reuse
//! of [`crate::extractors::acme::ProtectedHeader`], for the same reason
//! EAB's is: RFC 8555 §7.3.5 requires the inner JWS to **omit `nonce`**
//! entirely (verified against the RFC text directly) -- this is a request
//! the outer JWS already replay-protects, not a second signed request in its
//! own right -- and it must carry `jwk`, never `kid`, since the whole point
//! is proving possession of a *new*, not-yet-registered key.
//!
//! Its payload ([`InnerPayload`]) names the account being rolled (`account`,
//! checked against the outer JWS's own `kid`) and restates the *old* key as
//! a JWK (`oldKey`, checked against the account's stored key). Accounts are
//! keyed by DER SPKI rather than by JWK (see
//! [`crate::extractors::acme::jwk_thumbprint`]'s doc comment), so the
//! caller reconstructs a [`Jwk`] from storage via
//! [`crate::extractors::acme::spki_to_jwk`] and this module compares the two
//! structurally (`Jwk` derives `PartialEq`) -- mirroring exactly how
//! [`crate::eab::verify_payload_and_signature`] compares its own embedded
//! JWK against the account's. Both checks exist so a captured inner JWS
//! cannot be replayed onto a different account or a different old key than
//! the one that produced it.

use base64::prelude::*;
use serde::Deserialize;
use tracing::warn;

use crate::error::Problem;
use crate::extractors::acme::{Jwk, SignatureError, verify_jwk_signature_and_get_der};

/// The inner keyChange JWS: the same flattened `{protected, payload,
/// signature}` shape as the outer request JWS.
pub(crate) type KeyChangeJws = crate::extractors::acme::AcmeJwsRequest;

/// The inner keyChange JWS's protected header. See the [module docs](self)
/// for why this is its own type rather than a reuse of `ProtectedHeader`.
#[derive(Debug, Deserialize)]
pub(crate) struct InnerHeader {
    pub alg: String,
    pub jwk: Jwk,
    pub url: String,
}

/// The inner keyChange JWS's payload -- RFC 8555 §7.3.5's `keyChange` object.
#[derive(Debug, Deserialize)]
pub(crate) struct InnerPayload {
    pub account: String,
    #[serde(rename = "oldKey")]
    pub old_key: Jwk,
}

/// Why keyChange verification failed, in the three buckets [`key_change_problem`]
/// renders as HTTP status: a shape problem the client can fix by resending
/// correctly formed inner JWS (`Malformed`, 400), a signature that plainly
/// does not verify against its own embedded key (`BadSignature`, 401), or a
/// stored account key this server itself cannot decode (`Internal`, 500 --
/// our bug, not the client's).
#[derive(Debug)]
pub(crate) enum KeyChangeError {
    Malformed(&'static str),
    BadSignature,
    Internal(&'static str),
}

impl From<SignatureError> for KeyChangeError {
    fn from(error: SignatureError) -> Self {
        match error {
            SignatureError::Malformed(detail) => KeyChangeError::Malformed(detail),
            // An unsupported `alg` on the *inner* JWS stays `malformed` rather
            // than becoming `badSignatureAlgorithm`: RFC 8555 §6.2 is about the
            // request's own signature, and the inner JWS is payload here — a
            // client renegotiating on the strength of that error would change
            // the wrong thing.
            SignatureError::BadAlgorithm(detail) => KeyChangeError::Malformed(detail),
            SignatureError::BadSignature(_) => KeyChangeError::BadSignature,
            SignatureError::Encoding(detail) => KeyChangeError::Internal(detail),
        }
    }
}

/// Decodes and validates the inner JWS's protected header (RFC 8555 §7.3.5
/// checks #3/#6): `jwk` must be present (guaranteed by `InnerHeader`'s shape
/// once it deserializes at all), and `url` must equal `expected_url` -- the
/// *outer* JWS's own already-verified `header.url` (RFC 8555 §6.4), i.e.
/// this exact `keyChange` request. No `nonce` check is made: RFC 8555
/// §7.3.5 requires the inner JWS to omit it entirely, and an extra field a
/// client sends anyway is silently ignored, like any unknown field the
/// payload types in this codebase accept.
pub(crate) fn parse_header(
    inner: &KeyChangeJws,
    expected_url: &str,
) -> Result<InnerHeader, KeyChangeError> {
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&inner.protected)
        .map_err(|_| KeyChangeError::Malformed("inner protected base64 invalid"))?;

    let header: InnerHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|_| KeyChangeError::Malformed("inner protected JSON invalid"))?;

    if header.url != expected_url {
        return Err(KeyChangeError::Malformed(
            "inner url does not match the request",
        ));
    }

    Ok(header)
}

/// Verifies the inner JWS's self-signature (RFC 8555 §7.3.5 check #4 -- the
/// new key signs its own request) and returns that key as DER SPKI, the form
/// accounts are keyed by.
pub(crate) fn verify_signature(
    inner: &KeyChangeJws,
    header: &InnerHeader,
) -> Result<Vec<u8>, KeyChangeError> {
    let signing_input = format!("{}.{}", inner.protected, inner.payload);
    Ok(verify_jwk_signature_and_get_der(
        &header.alg,
        &header.jwk,
        &signing_input,
        &inner.signature,
    )?)
}

/// Decodes and validates the inner JWS's payload (RFC 8555 §7.3.5 checks
/// #5/#7/#8): well-formed `keyChange` object, `account` naming the account
/// that signed the outer JWS, and `oldKey` structurally equal to that
/// account's current key. Both comparisons are checked here, not left to the
/// caller, mirroring [`crate::eab::verify_payload_and_signature`]'s own
/// embedded-JWK check -- a mismatch is `Malformed`, not `BadSignature`: it is
/// a claim about identity, not a cryptographic failure.
pub(crate) fn verify_payload(
    inner: &KeyChangeJws,
    expected_account_url: &str,
    expected_old_key: &Jwk,
) -> Result<InnerPayload, KeyChangeError> {
    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&inner.payload)
        .map_err(|_| KeyChangeError::Malformed("inner payload base64 invalid"))?;

    let payload: InnerPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| KeyChangeError::Malformed("inner payload is not a keyChange object"))?;

    if payload.account != expected_account_url {
        return Err(KeyChangeError::Malformed(
            "inner account does not match the signer",
        ));
    }
    if &payload.old_key != expected_old_key {
        return Err(KeyChangeError::Malformed(
            "inner oldKey does not match the account key",
        ));
    }

    Ok(payload)
}

/// Maps a [`KeyChangeError`] to the `Problem` the caller rejects with.
///
/// Also the one place a rejection here is logged. Every `Err` in this module
/// funnels through it, so one event covers all eight of them — and until it
/// existed, a forged inner JWS on `POST /keyChange` (a bid to take over
/// somebody else's account) left no trace at all: the handler sees only the
/// `Problem`, never which check refused it.
pub(crate) fn key_change_problem(error: KeyChangeError) -> Problem {
    let (reason, detail) = match &error {
        KeyChangeError::Malformed(detail) => ("malformed", *detail),
        KeyChangeError::BadSignature => ("bad_signature", "inner JWS signature invalid"),
        KeyChangeError::Internal(detail) => ("internal", *detail),
    };
    warn!(
        event = "key_change_rejected",
        outcome = "failure",
        reason,
        detail
    );

    match error {
        KeyChangeError::Malformed(detail) => Problem::malformed(detail),
        KeyChangeError::BadSignature => Problem::unauthorized("Inner JWS signature invalid"),
        KeyChangeError::Internal(detail) => Problem::server_internal(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair};
    use serde_json::json;

    const URL: &str = "http://localhost:3000/keyChange";

    fn b64(data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    fn b64_json(value: &serde_json::Value) -> String {
        b64(&serde_json::to_vec(value).unwrap())
    }

    fn generate_ec_key() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .unwrap()
    }

    fn ec_jwk(key_pair: &EcdsaKeyPair) -> Jwk {
        let point = key_pair.public_key().as_ref();
        Jwk::EC {
            crv: "P-256".to_string(),
            x: b64(&point[1..33]),
            y: b64(&point[33..65]),
        }
    }

    /// Builds a well-formed inner keyChange JWS, self-signed by `new_key`,
    /// embedding `new_key`'s own JWK.
    fn build(new_key: &EcdsaKeyPair, url: &str, payload: &serde_json::Value) -> KeyChangeJws {
        let protected = json!({ "alg": "ES256", "jwk": ec_jwk_value(new_key), "url": url });
        let protected_b64 = b64_json(&protected);
        let payload_b64 = b64_json(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let rng = SystemRandom::new();
        let sig = new_key.sign(&rng, signing_input.as_bytes()).unwrap();
        KeyChangeJws {
            protected: protected_b64,
            payload: payload_b64,
            signature: b64(sig.as_ref()),
        }
    }

    fn ec_jwk_value(key_pair: &EcdsaKeyPair) -> serde_json::Value {
        let point = key_pair.public_key().as_ref();
        json!({ "kty": "EC", "crv": "P-256", "x": b64(&point[1..33]), "y": b64(&point[33..65]) })
    }

    fn account_url() -> &'static str {
        "http://localhost:3000/acct/1"
    }

    fn payload_for(old_key: &Jwk) -> serde_json::Value {
        let old_key_json = match old_key {
            Jwk::EC { crv, x, y } => json!({ "kty": "EC", "crv": crv, "x": x, "y": y }),
            Jwk::RSA { n, e } => json!({ "kty": "RSA", "n": n, "e": e }),
        };
        json!({ "account": account_url(), "oldKey": old_key_json })
    }

    #[test]
    fn parse_header_accepts_well_formed_and_matching_url() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let inner = build(&new_key, URL, &payload_for(&old_key));

        let header = parse_header(&inner, URL).unwrap();
        assert_eq!(header.alg, "ES256");
    }

    #[test]
    fn parse_header_rejects_url_mismatch() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let inner = build(
            &new_key,
            "http://localhost:3000/other",
            &payload_for(&old_key),
        );

        assert!(matches!(
            parse_header(&inner, URL),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn parse_header_rejects_malformed_base64_and_json() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());

        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        inner.protected = "!!!not-base64!!!".to_string();
        assert!(matches!(
            parse_header(&inner, URL),
            Err(KeyChangeError::Malformed(_))
        ));

        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        inner.protected = b64(b"not json");
        assert!(matches!(
            parse_header(&inner, URL),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn parse_header_rejects_missing_jwk() {
        let protected_b64 = b64_json(&json!({ "alg": "ES256", "url": URL }));
        let inner = KeyChangeJws {
            protected: protected_b64,
            payload: String::new(),
            signature: String::new(),
        };
        assert!(matches!(
            parse_header(&inner, URL),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn verify_signature_accepts_a_correctly_self_signed_inner_jws() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let inner = build(&new_key, URL, &payload_for(&old_key));
        let header = parse_header(&inner, URL).unwrap();

        let der = verify_signature(&inner, &header).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn verify_signature_rejects_a_tampered_signature() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        let header = parse_header(&inner, URL).unwrap();
        inner.signature = b64(&[0u8; 64]);

        assert!(matches!(
            verify_signature(&inner, &header),
            Err(KeyChangeError::BadSignature)
        ));
    }

    #[test]
    fn verify_signature_rejects_a_tampered_payload() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        let header = parse_header(&inner, URL).unwrap();
        // A different, still well-formed payload -- the signature no longer
        // covers this content.
        inner.payload = b64_json(&payload_for(&ec_jwk(&generate_ec_key())));

        assert!(matches!(
            verify_signature(&inner, &header),
            Err(KeyChangeError::BadSignature)
        ));
    }

    #[test]
    fn verify_payload_accepts_correct_account_and_old_key() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let inner = build(&new_key, URL, &payload_for(&old_key));

        let payload = verify_payload(&inner, account_url(), &old_key).unwrap();
        assert_eq!(payload.account, account_url());
    }

    #[test]
    fn verify_payload_rejects_account_mismatch() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let inner = build(&new_key, URL, &payload_for(&old_key));

        assert!(matches!(
            verify_payload(&inner, "http://localhost:3000/acct/999", &old_key),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn verify_payload_rejects_old_key_mismatch() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let unrelated_key = ec_jwk(&generate_ec_key());
        let inner = build(&new_key, URL, &payload_for(&old_key));

        assert!(matches!(
            verify_payload(&inner, account_url(), &unrelated_key),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn verify_payload_rejects_malformed_payload_json() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        inner.payload = b64(b"not a keyChange object");

        assert!(matches!(
            verify_payload(&inner, account_url(), &old_key),
            Err(KeyChangeError::Malformed(_))
        ));
    }

    #[test]
    fn verify_payload_rejects_malformed_payload_base64() {
        let new_key = generate_ec_key();
        let old_key = ec_jwk(&generate_ec_key());
        let mut inner = build(&new_key, URL, &payload_for(&old_key));
        inner.payload = "!!!not-base64!!!".to_string();

        assert!(matches!(
            verify_payload(&inner, account_url(), &old_key),
            Err(KeyChangeError::Malformed(_))
        ));
    }
}
