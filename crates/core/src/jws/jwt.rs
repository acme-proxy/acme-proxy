//! OpenID Connect ID tokens: a compact JWS whose payload is a set of claims,
//! verified against the provider's published key set (OpenID Connect Core 1.0
//! §3.1.3.7).
//!
//! Built on [`signature`](super::signature) rather than on a JOSE library, so
//! the same two algorithms and the same ring code that verify every ACME
//! request verify a token too (ADR 0015,
//! `doc/src/dev/adr/0015-external-identity-providers.md`). What that buys and costs:
//!
//! - **`RS256` and `ES256` only.** Every mainstream provider signs ID tokens
//!   with `RS256` by default; anything else is [`JwtError::Malformed`] with the
//!   algorithm named. `none` and the `HS*` family are never accepted -- an
//!   HMAC "signature" keyed with the client secret is a shared-secret MAC the
//!   provider's key set cannot vouch for.
//! - **The key picks the algorithm, never the token alone.** A token is
//!   checked only against keys whose type matches its `alg` (an `RS256` token
//!   is never tried against an EC key) -- `verify_jwk_signature_and_get_der`
//!   refuses the mismatch, which is the algorithm-confusion attack closed in
//!   one place for both callers.
//! - **An unknown `kid` is its own error**, [`JwtError::UnknownKey`], because
//!   it is the one failure a caller should answer by refetching the key set:
//!   providers rotate keys, and a cache a rotation old knows none of the new
//!   tokens.
//!
//! The claim checks run only after the signature verified, so nothing below
//! reads a claim an attacker could have written.

use base64::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::Jwk;
use super::signature::{SignatureError, verify_jwk_signature_and_get_der};

/// Why an ID token was refused. Every variant is a refusal; the split is for
/// the log line and for [`JwtError::UnknownKey`]'s refetch.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Not three base64url segments of JSON, or a header this module will not
    /// verify (an unsupported `alg`, a `crit` it cannot honour).
    #[error("malformed token: {0}")]
    Malformed(String),
    /// No key in the set matches the token's `kid` (or, with no `kid`, no
    /// single key could be chosen). Refetch the key set and try once more.
    #[error("no key in the provider's key set matches the token")]
    UnknownKey,
    /// The signature did not verify against the chosen key.
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
    /// The signature verified and a claim is wrong: the token was issued, but
    /// not to us, not by whom we expect, not for this sign-in, or not now.
    #[error("claim `{claim}`: {reason}")]
    Claim {
        claim: &'static str,
        reason: &'static str,
    },
}

/// One key of a provider's key set (RFC 7517 §5), with the members that
/// decide whether it may verify a given token.
#[derive(Debug)]
pub struct JwkSetKey {
    pub kid: Option<String>,
    /// `use`: a key published for `enc` must not verify a signature.
    pub key_use: Option<String>,
    /// `alg`: when present, the only algorithm this key verifies.
    pub alg: Option<String>,
    pub jwk: Jwk,
}

/// A provider's key set, as fetched from its `jwks_uri`.
#[derive(Debug, Default)]
pub struct JwkSet {
    pub keys: Vec<JwkSetKey>,
}

impl JwkSet {
    /// Parses a JWK Set document.
    ///
    /// A key this server cannot use -- an `OKP` key, an RSA key missing `n`, a
    /// curve other than P-256 -- is **skipped**, not an error: providers
    /// publish keys for every algorithm they support, and one Ed25519 key in
    /// the set must not make every RS256 token unverifiable.
    pub fn parse(document: &[u8]) -> Result<Self, JwtError> {
        #[derive(Deserialize)]
        struct Document {
            keys: Vec<Value>,
        }
        let document: Document = serde_json::from_slice(document)
            .map_err(|_| JwtError::Malformed("the key set is not a JWK Set".to_string()))?;
        let keys = document
            .keys
            .into_iter()
            .filter_map(|key| {
                let member = |name: &str| key.get(name).and_then(Value::as_str).map(str::to_string);
                let (kid, key_use, alg) = (member("kid"), member("use"), member("alg"));
                let jwk = Jwk::deserialize(key).ok()?;
                Some(JwkSetKey {
                    kid,
                    key_use,
                    alg,
                    jwk,
                })
            })
            .collect();
        Ok(Self { keys })
    }

    /// The keys that may verify a token signed `alg` with `kid`.
    fn candidates<'a>(&'a self, alg: &'a str, kid: Option<&'a str>) -> Vec<&'a JwkSetKey> {
        self.keys
            .iter()
            .filter(|key| {
                key.key_use
                    .as_deref()
                    .is_none_or(|key_use| key_use == "sig")
            })
            .filter(|key| key.alg.as_deref().is_none_or(|key_alg| key_alg == alg))
            .filter(|key| {
                matches!(
                    (&key.jwk, alg),
                    (Jwk::RSA { .. }, "RS256") | (Jwk::EC { .. }, "ES256")
                )
            })
            .filter(|key| kid.is_none_or(|kid| key.kid.as_deref() == Some(kid)))
            .collect()
    }
}

/// What a token must say to be accepted for this sign-in.
#[derive(Debug, Clone, Copy)]
pub struct IdTokenExpectations<'a> {
    /// The provider's issuer identifier, compared byte for byte (§3.1.3.7 2).
    pub issuer: &'a str,
    /// Our `client_id`: must be an audience, and the authorized party when
    /// there are several (§3.1.3.7 3–5).
    pub client_id: &'a str,
    /// The `nonce` this sign-in sent (§3.1.3.7 11).
    pub nonce: &'a str,
    /// Epoch seconds.
    pub now: i64,
    /// Clock skew tolerated on `exp`, `iat` and `nbf`, in seconds.
    pub leeway_seconds: i64,
}

/// Verifies `token` against `keys` and `expected`, answering its claims.
pub fn verify_id_token(
    token: &str,
    keys: &JwkSet,
    expected: &IdTokenExpectations<'_>,
) -> Result<Map<String, Value>, JwtError> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        kid: Option<String>,
        crit: Option<Vec<String>>,
    }

    let mut segments = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwtError::Malformed(
            "not three dot-separated segments".to_string(),
        ));
    };

    let header: Header = decode_json(header_b64, "header")?;
    if header.crit.is_some() {
        // RFC 7515 §4.1.11: an extension the sender marked critical is one we
        // must understand, and we understand none.
        return Err(JwtError::Malformed("a `crit` header".to_string()));
    }
    if header.alg != "RS256" && header.alg != "ES256" {
        return Err(JwtError::Malformed(format!(
            "algorithm `{}` (accepted: RS256, ES256)",
            header.alg
        )));
    }

    let candidates = keys.candidates(&header.alg, header.kid.as_deref());
    // With a `kid`, the set should hold exactly one such key; without one, a
    // single candidate is unambiguous and several are not worth guessing at.
    let [key] = candidates.as_slice() else {
        return Err(JwtError::UnknownKey);
    };

    let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
    verify_jwk_signature_and_get_der(&header.alg, &key.jwk, signing_input, signature_b64)?;

    let claims: Map<String, Value> = decode_json(payload_b64, "payload")?;
    check_claims(&claims, expected)?;
    Ok(claims)
}

/// OpenID Connect Core §3.1.3.7, steps 2–5, 9–11, after the signature.
fn check_claims(
    claims: &Map<String, Value>,
    expected: &IdTokenExpectations<'_>,
) -> Result<(), JwtError> {
    let refuse = |claim: &'static str, reason: &'static str| Err(JwtError::Claim { claim, reason });

    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return refuse("iss", "not the configured issuer");
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return refuse("sub", "missing");
    }

    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => return refuse("aud", "missing"),
    };
    if !audiences.contains(&expected.client_id) {
        return refuse("aud", "does not name this client");
    }
    match claims.get("azp").and_then(Value::as_str) {
        Some(azp) if azp != expected.client_id => {
            return refuse("azp", "another client is the authorized party");
        }
        None if audiences.len() > 1 => {
            return refuse("azp", "missing while there are several audiences");
        }
        _ => {}
    }

    let time = |claim: &str| claims.get(claim).and_then(Value::as_i64);
    match time("exp") {
        Some(exp) if exp + expected.leeway_seconds > expected.now => {}
        Some(_) => return refuse("exp", "expired"),
        None => return refuse("exp", "missing"),
    }
    match time("iat") {
        Some(iat) if iat - expected.leeway_seconds <= expected.now => {}
        Some(_) => return refuse("iat", "issued in the future"),
        None => return refuse("iat", "missing"),
    }
    if time("nbf").is_some_and(|nbf| nbf - expected.leeway_seconds > expected.now) {
        return refuse("nbf", "not yet valid");
    }

    // Not secret -- it travelled through the browser -- so a plain comparison.
    if claims.get("nonce").and_then(Value::as_str) != Some(expected.nonce) {
        return refuse("nonce", "not this sign-in's");
    }
    Ok(())
}

fn decode_json<T: serde::de::DeserializeOwned>(
    segment: &str,
    what: &'static str,
) -> Result<T, JwtError> {
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JwtError::Malformed(format!("the {what} is not base64url")))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| JwtError::Malformed(format!("the {what} is not a JSON object")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
    use serde_json::json;
    use simple_asn1::ASN1Block;

    const ISSUER: &str = "https://idp.example";
    const CLIENT: &str = "acme-proxy";
    const NOW: i64 = 1_800_000_000;

    fn b64(data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    fn ec_key() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
        EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap()
    }

    fn ec_public(key: &EcdsaKeyPair, kid: &str) -> Value {
        let sec1 = key.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
               "x": b64(&sec1[1..33]), "y": b64(&sec1[33..65])})
    }

    fn rsa_key() -> RsaKeyPair {
        RsaKeyPair::from_pkcs8(include_bytes!(
            "../../../../tests/fixtures/rsa_test_key.pk8"
        ))
        .unwrap()
    }

    fn rsa_public(key: &RsaKeyPair, kid: &str) -> Value {
        let blocks = simple_asn1::from_der(key.public_key().as_ref()).unwrap();
        let ASN1Block::Sequence(_, items) = &blocks[0] else {
            panic!("RSAPublicKey is a SEQUENCE")
        };
        let int = |block: &ASN1Block| match block {
            ASN1Block::Integer(_, value) => b64(&value.to_bytes_be().1),
            _ => panic!("expected an INTEGER"),
        };
        json!({"kty": "RSA", "kid": kid, "alg": "RS256", "n": int(&items[0]), "e": int(&items[1])})
    }

    enum Signer<'a> {
        Ec(&'a EcdsaKeyPair),
        Rsa(&'a RsaKeyPair),
    }

    fn token(header: &Value, claims: &Value, signer: Signer<'_>) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let rng = SystemRandom::new();
        let signature = match signer {
            Signer::Ec(key) => key.sign(&rng, input.as_bytes()).unwrap().as_ref().to_vec(),
            Signer::Rsa(key) => {
                let mut out = vec![0; key.public().modulus_len()];
                key.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &rng,
                    input.as_bytes(),
                    &mut out,
                )
                .unwrap();
                out
            }
        };
        format!("{input}.{}", b64(&signature))
    }

    fn claims() -> Value {
        json!({"iss": ISSUER, "sub": "user-1", "aud": CLIENT, "exp": NOW + 300,
               "iat": NOW - 5, "nonce": "n-0", "groups": ["admins"]})
    }

    fn expected() -> IdTokenExpectations<'static> {
        IdTokenExpectations {
            issuer: ISSUER,
            client_id: CLIENT,
            nonce: "n-0",
            now: NOW,
            leeway_seconds: 60,
        }
    }

    fn set(keys: &[Value]) -> JwkSet {
        JwkSet::parse(json!({ "keys": keys }).to_string().as_bytes()).unwrap()
    }

    fn es256(key: &EcdsaKeyPair, claims: &Value) -> String {
        token(
            &json!({"alg": "ES256", "kid": "ec"}),
            claims,
            Signer::Ec(key),
        )
    }

    fn claim_error(result: Result<Map<String, Value>, JwtError>) -> &'static str {
        match result {
            Err(JwtError::Claim { claim, .. }) => claim,
            other => panic!("expected a claim refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_es256_token_verifies_and_answers_its_claims() {
        let key = ec_key();
        let keys = set(&[ec_public(&key, "ec")]);
        let verified = verify_id_token(&es256(&key, &claims()), &keys, &expected()).unwrap();
        assert_eq!(verified["sub"], "user-1");
        assert_eq!(verified["groups"], json!(["admins"]));
    }

    #[test]
    fn an_rs256_token_verifies() {
        let key = rsa_key();
        let keys = set(&[rsa_public(&key, "rsa")]);
        let signed = token(
            &json!({"alg": "RS256", "kid": "rsa"}),
            &claims(),
            Signer::Rsa(&key),
        );
        assert!(verify_id_token(&signed, &keys, &expected()).is_ok());
    }

    /// A key the server cannot use is skipped rather than failing the set.
    #[test]
    fn unusable_keys_are_skipped_not_fatal() {
        let key = ec_key();
        let keys = set(&[
            json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": "AAAA"}),
            json!({"kty": "RSA", "kid": "broken"}),
            ec_public(&key, "ec"),
        ]);
        assert_eq!(keys.keys.len(), 1);
        assert!(verify_id_token(&es256(&key, &claims()), &keys, &expected()).is_ok());
        assert!(matches!(
            JwkSet::parse(b"{\"nokeys\": []}"),
            Err(JwtError::Malformed(_))
        ));
    }

    /// `none` and HMAC are refused before any key is looked at.
    #[test]
    fn none_and_hmac_are_refused() {
        let key = ec_key();
        let keys = set(&[ec_public(&key, "ec")]);
        for alg in ["none", "HS256", "PS256"] {
            let forged = format!(
                "{}.{}.",
                b64(json!({"alg": alg, "kid": "ec"}).to_string().as_bytes()),
                b64(claims().to_string().as_bytes())
            );
            assert!(
                matches!(
                    verify_id_token(&forged, &keys, &expected()),
                    Err(JwtError::Malformed(_))
                ),
                "{alg} must be refused"
            );
        }
    }

    /// An RSA-signed token presented as ES256 finds no EC key to confuse.
    #[test]
    fn a_token_is_never_tried_against_a_key_of_another_type() {
        let rsa = rsa_key();
        let keys = set(&[rsa_public(&rsa, "k")]);
        let signed = token(
            &json!({"alg": "ES256", "kid": "k"}),
            &claims(),
            Signer::Rsa(&rsa),
        );
        assert!(matches!(
            verify_id_token(&signed, &keys, &expected()),
            Err(JwtError::UnknownKey)
        ));
    }

    #[test]
    fn an_unknown_kid_or_an_ambiguous_set_is_unknown_key() {
        let key = ec_key();
        let one = set(&[ec_public(&key, "ec")]);
        let other_kid = token(
            &json!({"alg": "ES256", "kid": "rotated"}),
            &claims(),
            Signer::Ec(&key),
        );
        assert!(matches!(
            verify_id_token(&other_kid, &one, &expected()),
            Err(JwtError::UnknownKey)
        ));

        // No `kid`: one candidate is used, two are not guessed between.
        let no_kid = token(&json!({"alg": "ES256"}), &claims(), Signer::Ec(&key));
        assert!(verify_id_token(&no_kid, &one, &expected()).is_ok());
        let two = set(&[ec_public(&key, "a"), ec_public(&ec_key(), "b")]);
        assert!(matches!(
            verify_id_token(&no_kid, &two, &expected()),
            Err(JwtError::UnknownKey)
        ));
    }

    /// A key published for encryption, or pinned to another algorithm, does
    /// not verify a signature.
    #[test]
    fn a_key_for_encryption_or_another_alg_is_not_a_candidate() {
        let key = ec_key();
        let mut enc = ec_public(&key, "ec");
        enc["use"] = json!("enc");
        let mut pinned = ec_public(&key, "ec");
        pinned["alg"] = json!("ES384");
        for published in [enc, pinned] {
            assert!(matches!(
                verify_id_token(&es256(&key, &claims()), &set(&[published]), &expected()),
                Err(JwtError::UnknownKey)
            ));
        }
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        let key = ec_key();
        let keys = set(&[ec_public(&key, "ec")]);
        let signed = es256(&key, &claims());
        let mut parts: Vec<&str> = signed.split('.').collect();
        let mut forged = claims();
        forged["groups"] = json!(["everyone-is-admin"]);
        let forged_b64 = b64(forged.to_string().as_bytes());
        parts[1] = &forged_b64;
        assert!(matches!(
            verify_id_token(&parts.join("."), &keys, &expected()),
            Err(JwtError::Signature(_))
        ));
    }

    #[test]
    fn malformed_shapes_are_refused() {
        let keys = JwkSet::default();
        for bad in ["", "a.b", "a.b.c.d", "!!!.e30.sig", "e30.e30.sig"] {
            assert!(
                matches!(
                    verify_id_token(bad, &keys, &expected()),
                    Err(JwtError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
        let critical = format!(
            "{}.e30.sig",
            b64(json!({"alg": "ES256", "crit": ["exp"]})
                .to_string()
                .as_bytes())
        );
        assert!(matches!(
            verify_id_token(&critical, &keys, &expected()),
            Err(JwtError::Malformed(_))
        ));
        // A payload that is base64 but not an object fails after the signature.
        let key = ec_key();
        let signed = token(&json!({"alg": "ES256"}), &json!([1, 2]), Signer::Ec(&key));
        assert!(matches!(
            verify_id_token(&signed, &set(&[ec_public(&key, "ec")]), &expected()),
            Err(JwtError::Malformed(_))
        ));
    }

    #[test]
    fn each_claim_is_checked() {
        let key = ec_key();
        let keys = set(&[ec_public(&key, "ec")]);
        let check = |edit: &dyn Fn(&mut Value)| {
            let mut edited = claims();
            edit(&mut edited);
            claim_error(verify_id_token(&es256(&key, &edited), &keys, &expected()))
        };

        assert_eq!(check(&|c| c["iss"] = json!("https://evil.example")), "iss");
        assert_eq!(check(&|c| c["sub"] = json!("")), "sub");
        assert_eq!(check(&|c| c["aud"] = json!("someone-else")), "aud");
        assert_eq!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("aud");
            }),
            "aud"
        );
        assert_eq!(check(&|c| c["aud"] = json!([CLIENT, "other"])), "azp");
        assert_eq!(check(&|c| c["azp"] = json!("other")), "azp");
        assert_eq!(check(&|c| c["exp"] = json!(NOW - 61)), "exp");
        assert_eq!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
            "exp"
        );
        assert_eq!(check(&|c| c["iat"] = json!(NOW + 61)), "iat");
        assert_eq!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            "iat"
        );
        assert_eq!(check(&|c| c["nbf"] = json!(NOW + 61)), "nbf");
        assert_eq!(check(&|c| c["nonce"] = json!("n-1")), "nonce");
        assert_eq!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            "nonce"
        );
    }

    /// Several audiences are fine when we are the authorized party, and the
    /// leeway forgives a clock a little behind.
    #[test]
    fn several_audiences_with_our_azp_and_a_skewed_clock_pass() {
        let key = ec_key();
        let keys = set(&[ec_public(&key, "ec")]);
        let mut edited = claims();
        edited["aud"] = json!([CLIENT, "other"]);
        edited["azp"] = json!(CLIENT);
        edited["exp"] = json!(NOW - 30);
        edited["iat"] = json!(NOW + 30);
        assert!(verify_id_token(&es256(&key, &edited), &keys, &expected()).is_ok());
    }
}
