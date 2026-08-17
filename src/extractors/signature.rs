use base64::prelude::*;
use ring::{digest, signature};
use simple_asn1::{ASN1Block, BigInt, BigUint};

use crate::extractors::jws::{Jwk, ProtectedHeader};

/// The three ASN.1 object identifiers this module compares against, each in one
/// place.
///
/// They were written out six times across the two verification paths. An OID is
/// a bare sequence of numbers with no compiler check on it, and a typo in one
/// of six copies would not fail to build — it would make one path stop
/// recognising a key type while the other still did, which on this module's
/// paths means a silent authentication bug.
///
/// `fn` rather than `const`: `simple_asn1`'s `oid!` builds an owned `OID`, so
/// there is nothing to make a constant out of.
mod oids {
    use simple_asn1::{OID, oid};

    /// `id-ecPublicKey` (RFC 5480 §2.1.1).
    pub(super) fn ec_public_key() -> OID {
        oid!(1, 2, 840, 10045, 2, 1)
    }

    /// `secp256r1`, the curve `ES256` is defined over (RFC 5480 §2.1.1.1).
    pub(super) fn p256() -> OID {
        oid!(1, 2, 840, 10045, 3, 1, 7)
    }

    /// `rsaEncryption` (RFC 8017 appendix C).
    pub(super) fn rsa_encryption() -> OID {
        oid!(1, 2, 840, 113549, 1, 1, 1)
    }
}

/// Why a JWS signature check failed, so callers can pick the right HTTP status.
#[derive(Debug)]
pub enum SignatureError {
    /// Invalid base64 in the signature or key params, or a key whose shape does
    /// not match its declared type.
    Malformed(&'static str),
    /// The `alg` (or the `crv` under it) names an algorithm this server does not
    /// implement.
    ///
    /// Split from [`SignatureError::Malformed`] because RFC 8555 §6.2 gives it
    /// its own error type — `badSignatureAlgorithm`, carrying the list of
    /// algorithms the server *does* support — so a client can retry with one
    /// instead of being told only that its request was bad.
    BadAlgorithm(&'static str),
    /// The signature did not verify against the public key.
    BadSignature(&'static str),
    /// Re-encoding the verified public key to DER SPKI failed.
    Encoding(&'static str),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::Malformed(msg) => write!(f, "Malformed signature: {msg}"),
            SignatureError::BadAlgorithm(msg) => write!(f, "Unsupported algorithm: {msg}"),
            SignatureError::BadSignature(msg) => write!(f, "Bad signature: {msg}"),
            SignatureError::Encoding(msg) => write!(f, "Encoding error: {msg}"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Length in octets of a single P-256 coordinate (RFC 7518 §6.2.1.2).
const P256_COORDINATE_LEN: usize = 32;

/// Verifies a JWS signature and returns the public key in DER SPKI format.
pub fn verify_signature_and_get_der(
    header: &ProtectedHeader,
    signing_input: &str,
    sig_b64: &str,
) -> Result<Vec<u8>, SignatureError> {
    let jwk = header
        .jwk
        .as_ref()
        .ok_or(SignatureError::Malformed("jwk missing"))?;

    verify_jwk_signature_and_get_der(&header.alg, jwk, signing_input, sig_b64)
}

/// The `(alg, jwk)`-parameterized core of [`verify_signature_and_get_der`].
pub(crate) fn verify_jwk_signature_and_get_der(
    alg: &str,
    jwk: &Jwk,
    signing_input: &str,
    sig_b64: &str,
) -> Result<Vec<u8>, SignatureError> {
    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| SignatureError::Malformed("Signature base64 invalid"))?;

    match jwk {
        Jwk::EC { crv, x, y } => {
            if alg != "ES256" || crv != "P-256" {
                return Err(SignatureError::BadAlgorithm(
                    "EC algorithm incorrect. Expected: ES256 on P-256 curve.",
                ));
            }

            let x_b = BASE64_URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| SignatureError::Malformed("X coordinate base64 invalid"))?;
            let y_b = BASE64_URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|_| SignatureError::Malformed("Y coordinate base64 invalid"))?;

            if x_b.len() != P256_COORDINATE_LEN || y_b.len() != P256_COORDINATE_LEN {
                return Err(SignatureError::Malformed(
                    "EC coordinates must be 32 octets each",
                ));
            }

            let mut sec1_pk = Vec::with_capacity(1 + 32 + 32);
            sec1_pk.push(0x04);
            sec1_pk.extend_from_slice(&x_b);
            sec1_pk.extend_from_slice(&y_b);

            let ring_algo = &signature::ECDSA_P256_SHA256_FIXED;
            let peer_public_key = signature::UnparsedPublicKey::new(ring_algo, &sec1_pk);
            peer_public_key
                .verify(signing_input.as_bytes(), &sig_bytes)
                .map_err(|_| SignatureError::BadSignature("ES256 signature validation failed"))?;

            let ec_pubkey_oid = oids::ec_public_key();
            let p256_curve_oid = oids::p256();

            let algorithm_identifier = ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, ec_pubkey_oid),
                    ASN1Block::ObjectIdentifier(0, p256_curve_oid),
                ],
            );

            let spki_sequence = ASN1Block::Sequence(
                0,
                vec![
                    algorithm_identifier,
                    ASN1Block::BitString(0, sec1_pk.len() * 8, sec1_pk),
                ],
            );

            let der_bytes = simple_asn1::to_der(&spki_sequence)
                .map_err(|_| SignatureError::Encoding("EC key DER encoding error"))?;

            Ok(der_bytes)
        }

        Jwk::RSA { n, e } => {
            if alg != "RS256" {
                return Err(SignatureError::BadAlgorithm(
                    "RSA algorithm incorrect. Expected: RS256.",
                ));
            }

            let n_b = BASE64_URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|_| SignatureError::Malformed("N parameter base64 invalid"))?;
            let e_b = BASE64_URL_SAFE_NO_PAD
                .decode(e)
                .map_err(|_| SignatureError::Malformed("E parameter base64 invalid"))?;

            let n_bi = BigInt::from(BigUint::from_bytes_be(&n_b));
            let e_bi = BigInt::from(BigUint::from_bytes_be(&e_b));
            let rsa_public_key_seq = ASN1Block::Sequence(
                0,
                vec![ASN1Block::Integer(0, n_bi), ASN1Block::Integer(0, e_bi)],
            );

            let raw_rsa_public_key_der = simple_asn1::to_der(&rsa_public_key_seq)
                .map_err(|_| SignatureError::Encoding("RSA ASN.1 structure compilation error"))?;

            let ring_algo = &signature::RSA_PKCS1_2048_8192_SHA256;
            let peer_public_key =
                signature::UnparsedPublicKey::new(ring_algo, &raw_rsa_public_key_der);
            peer_public_key
                .verify(signing_input.as_bytes(), &sig_bytes)
                .map_err(|_| SignatureError::BadSignature("RS256 signature validation failed"))?;

            let rsa_encryption_oid = oids::rsa_encryption();

            let algorithm_identifier = ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, rsa_encryption_oid),
                    ASN1Block::Null(0),
                ],
            );

            let spki_sequence = ASN1Block::Sequence(
                0,
                vec![
                    algorithm_identifier,
                    ASN1Block::BitString(
                        0,
                        raw_rsa_public_key_der.len() * 8,
                        raw_rsa_public_key_der,
                    ),
                ],
            );

            let der_bytes = simple_asn1::to_der(&spki_sequence)
                .map_err(|_| SignatureError::Encoding("RSA key DER encoding error"))?;

            Ok(der_bytes)
        }
    }
}

/// A DER SPKI decomposed into the three things this module needs from it.
#[derive(Debug)]
pub(crate) struct SpkiParts {
    /// The `AlgorithmIdentifier`'s own OID: `id-ecPublicKey` or `rsaEncryption`.
    pub algorithm: simple_asn1::OID,
    /// The `AlgorithmIdentifier`'s `parameters`, when it carries an OID — for an
    /// EC key that is the named curve, and it is *not* decoration: the algorithm
    /// OID alone says "some elliptic curve key", not which curve.
    pub parameters: Option<simple_asn1::OID>,
    /// The raw `subjectPublicKey` bits.
    pub key: Vec<u8>,
}

/// Decomposes a DER SPKI into its `AlgorithmIdentifier` and raw `subjectPublicKey` bits.
pub(crate) fn spki_parts(spki_der: &[u8]) -> Result<SpkiParts, SignatureError> {
    let blocks = simple_asn1::from_der(spki_der)
        .map_err(|_| SignatureError::Encoding("Stored SPKI could not be parsed"))?;

    match blocks.first() {
        Some(ASN1Block::Sequence(_, items)) => {
            let (algorithm, parameters) = match items.first() {
                Some(ASN1Block::Sequence(_, algorithm)) => match algorithm.first() {
                    Some(ASN1Block::ObjectIdentifier(_, oid)) => {
                        let parameters = match algorithm.get(1) {
                            Some(ASN1Block::ObjectIdentifier(_, curve)) => Some(curve.clone()),
                            _ => None,
                        };
                        (oid.clone(), parameters)
                    }
                    _ => {
                        return Err(SignatureError::Encoding("Stored SPKI has no algorithm OID"));
                    }
                },
                _ => {
                    return Err(SignatureError::Encoding(
                        "Stored SPKI has no AlgorithmIdentifier",
                    ));
                }
            };
            match items.get(1) {
                Some(ASN1Block::BitString(_, _, bytes)) => Ok(SpkiParts {
                    algorithm,
                    parameters,
                    key: bytes.clone(),
                }),
                _ => Err(SignatureError::Encoding(
                    "Stored SPKI has no subjectPublicKey",
                )),
            }
        }
        _ => Err(SignatureError::Encoding("Stored SPKI is not a SEQUENCE")),
    }
}

/// Reconstructs a [`Jwk`] from a stored DER SPKI key.
pub fn spki_to_jwk(spki_der: &[u8]) -> Result<Jwk, SignatureError> {
    let SpkiParts {
        algorithm: key_oid,
        key: raw_key,
        ..
    } = spki_parts(spki_der)?;

    if key_oid == oids::ec_public_key() {
        if raw_key.len() != 1 + 2 * P256_COORDINATE_LEN || raw_key[0] != 0x04 {
            return Err(SignatureError::Encoding(
                "Stored EC key is not an uncompressed P-256 point",
            ));
        }
        Ok(Jwk::EC {
            crv: "P-256".to_string(),
            x: BASE64_URL_SAFE_NO_PAD.encode(&raw_key[1..=P256_COORDINATE_LEN]),
            y: BASE64_URL_SAFE_NO_PAD.encode(&raw_key[1 + P256_COORDINATE_LEN..]),
        })
    } else if key_oid == oids::rsa_encryption() {
        let blocks = simple_asn1::from_der(&raw_key)
            .map_err(|_| SignatureError::Encoding("Stored RSA key could not be parsed"))?;
        let (n, e) = match blocks.first() {
            Some(ASN1Block::Sequence(_, items)) => match (items.first(), items.get(1)) {
                (Some(ASN1Block::Integer(_, n)), Some(ASN1Block::Integer(_, e))) => (n, e),
                _ => {
                    return Err(SignatureError::Encoding(
                        "Stored RSA key is not SEQUENCE { n, e }",
                    ));
                }
            },
            _ => {
                return Err(SignatureError::Encoding("Stored RSA key is not a SEQUENCE"));
            }
        };
        Ok(Jwk::RSA {
            n: BASE64_URL_SAFE_NO_PAD.encode(n.to_bytes_be().1),
            e: BASE64_URL_SAFE_NO_PAD.encode(e.to_bytes_be().1),
        })
    } else {
        Err(SignatureError::Malformed(
            "Unsupported key type for a JWK thumbprint",
        ))
    }
}

/// The RFC 7638 JWK thumbprint of an account key stored as DER SPKI.
pub fn jwk_thumbprint(spki_der: &[u8]) -> Result<String, SignatureError> {
    let json = match spki_to_jwk(spki_der)? {
        Jwk::EC { crv, x, y } => format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#),
        Jwk::RSA { n, e } => format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#),
    };

    Ok(BASE64_URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, json.as_bytes()).as_ref()))
}

/// Verifies a JWS signature against a public key already stored as DER SPKI.
pub fn verify_signature_with_spki(
    alg: &str,
    spki_der: &[u8],
    signing_input: &str,
    sig_b64: &str,
) -> Result<(), SignatureError> {
    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| SignatureError::Malformed("Signature base64 invalid"))?;

    let SpkiParts {
        algorithm: key_oid,
        parameters,
        key: raw_key,
    } = spki_parts(spki_der)?;

    // `expected_curve` is what stops `alg` from being the only thing choosing
    // the verification algorithm. `id-ecPublicKey` says "an elliptic curve key"
    // and nothing more: a P-384 SPKI carries the same algorithm OID as a P-256
    // one, so matching that alone would hand a P-384 key to
    // `ECDSA_P256_SHA256_FIXED`. Nothing writes such a key today —
    // `verify_jwk_signature_and_get_der` only ever emits P-256 — but
    // `accounts.pubkey` is a database column, and the whole point of verifying
    // against the *stored* key is that a corrupted or substituted row must
    // refuse the request rather than authenticate somebody else.
    let (ring_algo, expected_oid, expected_curve): (
        &'static dyn signature::VerificationAlgorithm,
        _,
        _,
    ) = match alg {
        "ES256" => (
            &signature::ECDSA_P256_SHA256_FIXED,
            oids::ec_public_key(),
            // prime256v1 / secp256r1
            Some(oids::p256()),
        ),
        "RS256" => (
            &signature::RSA_PKCS1_2048_8192_SHA256,
            oids::rsa_encryption(),
            // rsaEncryption's parameters are NULL, not an OID.
            None,
        ),
        _ => {
            return Err(SignatureError::BadAlgorithm(
                "Unsupported algorithm. Expected: ES256 or RS256.",
            ));
        }
    };

    if key_oid != expected_oid {
        return Err(SignatureError::Malformed(
            "alg does not match the account key type",
        ));
    }

    if let Some(curve) = expected_curve
        && parameters.as_ref() != Some(&curve)
    {
        return Err(SignatureError::Malformed(
            "alg does not match the account key's named curve",
        ));
    }

    signature::UnparsedPublicKey::new(ring_algo, raw_key)
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| SignatureError::BadSignature("Signature validation failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};
    use simple_asn1::oid;

    fn b64(data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    fn generate_ec_key() -> EcdsaKeyPair {
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

    fn ec_jwk(key_pair: &EcdsaKeyPair) -> Jwk {
        let sec1 = key_pair.public_key().as_ref();
        assert_eq!(sec1[0], 0x04, "expected uncompressed SEC1 point");
        Jwk::EC {
            crv: "P-256".to_string(),
            x: b64(&sec1[1..33]),
            y: b64(&sec1[33..65]),
        }
    }

    fn rsa_test_key() -> RsaKeyPair {
        let pkcs8 = include_bytes!("../../tests/fixtures/rsa_test_key.pk8");
        RsaKeyPair::from_pkcs8(pkcs8).unwrap()
    }

    fn rsa_jwk(key_pair: &RsaKeyPair) -> Jwk {
        let blocks = simple_asn1::from_der(key_pair.public_key().as_ref()).unwrap();
        let (n, e) = match &blocks[0] {
            ASN1Block::Sequence(_, items) => {
                let int = |block: &ASN1Block| match block {
                    ASN1Block::Integer(_, v) => v.to_bytes_be().1,
                    _ => panic!("expected INTEGER in RSA public key"),
                };
                (int(&items[0]), int(&items[1]))
            }
            _ => panic!("unexpected RSA public key DER structure"),
        };
        Jwk::RSA {
            n: b64(&n),
            e: b64(&e),
        }
    }

    fn rsa_sign(key_pair: &RsaKeyPair, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; 256];
        key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .unwrap();
        sig
    }

    #[test]
    fn ec_valid_signature_verifies_and_returns_spki_der() {
        let key_pair = generate_ec_key();
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(ec_jwk(&key_pair)),
            kid: None,
            nonce: "test-nonce".to_string(),
            url: "http://localhost:3000/newAccount".to_string(),
            crit: None,
        };

        let signing_input = "protected.payload";
        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();

        let der = verify_signature_and_get_der(&header, signing_input, &b64(sig.as_ref()))
            .expect("a valid ES256 signature should verify");

        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn ec_rejects_wrong_alg() {
        let key_pair = generate_ec_key();
        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(ec_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        let signing_input = "protected.payload";
        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();

        assert!(matches!(
            verify_signature_and_get_der(&header, signing_input, &b64(sig.as_ref())),
            Err(SignatureError::BadAlgorithm(_))
        ));
    }

    #[test]
    fn ec_rejects_tampered_signing_input() {
        let key_pair = generate_ec_key();
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(ec_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, b"protected.payload").unwrap();

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.TAMPERED", &b64(sig.as_ref())),
            Err(SignatureError::BadSignature(_))
        ));
    }

    #[test]
    fn rsa_valid_signature_verifies_and_returns_spki_der() {
        let key_pair = rsa_test_key();
        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(rsa_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        let signing_input = "protected.payload";
        let sig = rsa_sign(&key_pair, signing_input.as_bytes());

        let der = verify_signature_and_get_der(&header, signing_input, &b64(&sig))
            .expect("a valid RS256 signature should verify");

        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn rsa_rejects_wrong_alg() {
        let key_pair = rsa_test_key();
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(rsa_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        let sig = rsa_sign(&key_pair, b"protected.payload");

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.payload", &b64(&sig)),
            Err(SignatureError::BadAlgorithm(_))
        ));
    }

    #[test]
    fn rsa_rejects_tampered_signing_input() {
        let key_pair = rsa_test_key();
        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(rsa_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        let sig = rsa_sign(&key_pair, b"protected.payload");

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.TAMPERED", &b64(&sig)),
            Err(SignatureError::BadSignature(_))
        ));
    }

    fn dummy_sig() -> String {
        b64(&[0u8; 64])
    }

    #[test]
    fn ec_rejects_invalid_base64_signature() {
        let key_pair = generate_ec_key();
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(ec_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.payload", "!!!not-base64!!!"),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn ec_rejects_invalid_base64_coordinates() {
        let header_x = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(Jwk::EC {
                crv: "P-256".to_string(),
                x: "!!!not-base64!!!".to_string(),
                y: b64(&[0u8; 32]),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        assert!(matches!(
            verify_signature_and_get_der(&header_x, "protected.payload", &dummy_sig()),
            Err(SignatureError::Malformed(_))
        ));

        let header_y = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(Jwk::EC {
                crv: "P-256".to_string(),
                x: b64(&[0u8; 32]),
                y: "!!!not-base64!!!".to_string(),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        assert!(matches!(
            verify_signature_and_get_der(&header_y, "protected.payload", &dummy_sig()),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn ec_rejects_wrong_curve() {
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(Jwk::EC {
                crv: "P-384".to_string(),
                x: b64(&[0u8; 32]),
                y: b64(&[0u8; 32]),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.payload", &dummy_sig()),
            Err(SignatureError::BadAlgorithm(_))
        ));
    }

    #[test]
    fn rsa_rejects_invalid_base64_signature() {
        let key_pair = rsa_test_key();
        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(rsa_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };

        assert!(matches!(
            verify_signature_and_get_der(&header, "protected.payload", "!!!not-base64!!!"),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn rsa_rejects_invalid_base64_params() {
        let header_n = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(Jwk::RSA {
                n: "!!!not-base64!!!".to_string(),
                e: b64(&[1, 0, 1]),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        assert!(matches!(
            verify_signature_and_get_der(&header_n, "protected.payload", &dummy_sig()),
            Err(SignatureError::Malformed(_))
        ));

        let header_e = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(Jwk::RSA {
                n: b64(&[0u8; 256]),
                e: "!!!not-base64!!!".to_string(),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        assert!(matches!(
            verify_signature_and_get_der(&header_e, "protected.payload", &dummy_sig()),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn spki_verify_ec_round_trip() {
        let key_pair = generate_ec_key();
        let signing_input = "protected.payload";
        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();

        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(ec_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        let der = verify_signature_and_get_der(&header, signing_input, &b64(sig.as_ref())).unwrap();

        assert!(
            verify_signature_with_spki("ES256", &der, signing_input, &b64(sig.as_ref())).is_ok()
        );

        assert!(matches!(
            verify_signature_with_spki("ES256", &der, "protected.TAMPERED", &b64(sig.as_ref())),
            Err(SignatureError::BadSignature(_))
        ));

        // An `alg` this server does not implement is its own error, so RFC 8555
        // §6.2's `badSignatureAlgorithm` can carry the supported list back.
        assert!(matches!(
            verify_signature_with_spki("EdDSA", &der, signing_input, &b64(sig.as_ref())),
            Err(SignatureError::BadAlgorithm(_))
        ));

        assert!(matches!(
            verify_signature_with_spki("ES256", &der, signing_input, "!!!not-base64!!!"),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn spki_verify_rsa_round_trip() {
        let key_pair = rsa_test_key();
        let signing_input = "protected.payload";
        let sig = rsa_sign(&key_pair, signing_input.as_bytes());

        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(rsa_jwk(&key_pair)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        let der = verify_signature_and_get_der(&header, signing_input, &b64(&sig)).unwrap();

        assert!(verify_signature_with_spki("RS256", &der, signing_input, &b64(&sig)).is_ok());
        assert!(matches!(
            verify_signature_with_spki("RS256", &der, "protected.TAMPERED", &b64(&sig)),
            Err(SignatureError::BadSignature(_))
        ));
    }

    #[test]
    fn spki_rejects_garbage_key() {
        assert!(matches!(
            verify_signature_with_spki("ES256", &[0xde, 0xad, 0xbe, 0xef], "a.b", &dummy_sig()),
            Err(SignatureError::Encoding(_))
        ));
    }

    fn spki_of(jwk: Jwk, alg: &str, signing_input: &str, sig: &[u8]) -> Vec<u8> {
        let header = ProtectedHeader {
            alg: alg.to_string(),
            jwk: Some(jwk),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        verify_signature_and_get_der(&header, signing_input, &b64(sig)).unwrap()
    }

    #[test]
    fn jwk_thumbprint_matches_the_rfc_7638_worked_example() {
        const RFC_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV\
             T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n\
             9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7\
             d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcR\
             wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let der = {
            let n = BASE64_URL_SAFE_NO_PAD.decode(RFC_N).unwrap();
            let e = BASE64_URL_SAFE_NO_PAD.decode("AQAB").unwrap();
            let pkcs1 = simple_asn1::to_der(&ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::Integer(0, BigInt::from(BigUint::from_bytes_be(&n))),
                    ASN1Block::Integer(0, BigInt::from(BigUint::from_bytes_be(&e))),
                ],
            ))
            .unwrap();
            simple_asn1::to_der(&ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::Sequence(
                        0,
                        vec![
                            ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 113549, 1, 1, 1)),
                            ASN1Block::Null(0),
                        ],
                    ),
                    ASN1Block::BitString(0, pkcs1.len() * 8, pkcs1),
                ],
            ))
            .unwrap()
        };

        assert_eq!(
            jwk_thumbprint(&der).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn jwk_thumbprint_of_an_ec_key_matches_an_independent_computation() {
        let key_pair = generate_ec_key();
        let rng = SystemRandom::new();
        let signing_input = "protected.payload";
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();

        let sec1 = key_pair.public_key().as_ref();
        let (x, y) = (b64(&sec1[1..33]), b64(&sec1[33..65]));
        let der = spki_of(ec_jwk(&key_pair), "ES256", signing_input, sig.as_ref());

        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let expected = b64(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref());

        assert_eq!(jwk_thumbprint(&der).unwrap(), expected);
    }

    #[test]
    fn jwk_thumbprint_of_an_rsa_key_is_stable() {
        let key_pair = rsa_test_key();
        let signing_input = "protected.payload";
        let sig = rsa_sign(&key_pair, signing_input.as_bytes());
        let der = spki_of(rsa_jwk(&key_pair), "RS256", signing_input, &sig);

        let first = jwk_thumbprint(&der).unwrap();
        assert_eq!(first, jwk_thumbprint(&der).unwrap());
        assert_eq!(first.len(), 43);
        let ec = generate_ec_key();
        let rng = SystemRandom::new();
        let ec_sig = ec.sign(&rng, signing_input.as_bytes()).unwrap();
        let ec_der = spki_of(ec_jwk(&ec), "ES256", signing_input, ec_sig.as_ref());
        assert_ne!(first, jwk_thumbprint(&ec_der).unwrap());
    }

    #[test]
    fn jwk_thumbprint_rejects_keys_it_cannot_describe() {
        assert!(matches!(
            jwk_thumbprint(&[0xde, 0xad, 0xbe, 0xef]),
            Err(SignatureError::Encoding(_))
        ));

        let ed25519 = simple_asn1::to_der(&ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Sequence(
                    0,
                    vec![ASN1Block::ObjectIdentifier(0, oid!(1, 3, 101, 112))],
                ),
                ASN1Block::BitString(0, 8, vec![0x00]),
            ],
        ))
        .unwrap();
        assert!(matches!(
            jwk_thumbprint(&ed25519),
            Err(SignatureError::Malformed(_))
        ));

        let short_point = simple_asn1::to_der(&ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Sequence(
                    0,
                    vec![
                        ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1)),
                        ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 10045, 3, 1, 7)),
                    ],
                ),
                ASN1Block::BitString(0, 24, vec![0x04, 0x01, 0x02]),
            ],
        ))
        .unwrap();
        assert!(matches!(
            jwk_thumbprint(&short_point),
            Err(SignatureError::Encoding(_))
        ));
    }

    #[test]
    fn spki_to_jwk_round_trips_an_ec_key() {
        let key_pair = generate_ec_key();
        let rng = SystemRandom::new();
        let signing_input = "protected.payload";
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();

        let original = ec_jwk(&key_pair);
        let der = spki_of(ec_jwk(&key_pair), "ES256", signing_input, sig.as_ref());

        assert_eq!(spki_to_jwk(&der).unwrap(), original);
    }

    #[test]
    fn spki_to_jwk_round_trips_an_rsa_key() {
        let key_pair = rsa_test_key();
        let signing_input = "protected.payload";
        let sig = rsa_sign(&key_pair, signing_input.as_bytes());

        let original = rsa_jwk(&key_pair);
        let der = spki_of(rsa_jwk(&key_pair), "RS256", signing_input, &sig);

        assert_eq!(spki_to_jwk(&der).unwrap(), original);
    }

    #[test]
    fn spki_to_jwk_rejects_garbage_key() {
        assert!(matches!(
            spki_to_jwk(&[0xde, 0xad, 0xbe, 0xef]),
            Err(SignatureError::Encoding(_))
        ));
    }

    #[test]
    fn spki_refuses_an_alg_that_does_not_match_the_stored_key() {
        let ec = generate_ec_key();
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(ec_jwk(&ec)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        let signing_input = "protected.payload";
        let sig = ec
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .unwrap();
        let ec_der =
            verify_signature_and_get_der(&header, signing_input, &b64(sig.as_ref())).unwrap();

        assert!(
            matches!(
                verify_signature_with_spki("RS256", &ec_der, signing_input, &b64(sig.as_ref())),
                Err(SignatureError::Malformed(_))
            ),
            "RS256 over an EC key must be malformed, not merely a bad signature"
        );

        let rsa = rsa_test_key();
        let rsa_sig = rsa_sign(&rsa, signing_input.as_bytes());
        let header = ProtectedHeader {
            alg: "RS256".to_string(),
            jwk: Some(rsa_jwk(&rsa)),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        let rsa_der = verify_signature_and_get_der(&header, signing_input, &b64(&rsa_sig)).unwrap();

        assert!(matches!(
            verify_signature_with_spki("ES256", &rsa_der, signing_input, &b64(&rsa_sig)),
            Err(SignatureError::Malformed(_))
        ));
    }

    /// `id-ecPublicKey` says "an elliptic curve key", not *which* curve, so the
    /// named-curve parameter has to be checked too. Otherwise a P-384 SPKI in
    /// `accounts.pubkey` — which only a corrupted or substituted row could put
    /// there, but that is exactly the case verifying against the stored key is
    /// meant to survive — would be handed to `ECDSA_P256_SHA256_FIXED`.
    #[test]
    fn an_ec_key_on_another_curve_is_refused_for_es256() {
        use simple_asn1::{ASN1Block, to_der};

        // A well-formed SPKI naming secp384r1 rather than prime256v1.
        let spki = to_der(&ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Sequence(
                    0,
                    vec![
                        ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1)),
                        ASN1Block::ObjectIdentifier(0, oid!(1, 3, 132, 0, 34)),
                    ],
                ),
                ASN1Block::BitString(0, 8 * 97, vec![0x04; 97]),
            ],
        ))
        .unwrap();

        match verify_signature_with_spki("ES256", &spki, "a.b", &dummy_sig()) {
            Err(SignatureError::Malformed(message)) => {
                assert!(message.contains("named curve"), "got {message:?}");
            }
            other => panic!("expected a Malformed error, got {other:?}"),
        }
    }

    /// The parameters of a real P-256 account key are read, not ignored — so the
    /// check above cannot be satisfied by simply never looking.
    #[test]
    fn a_p256_key_carries_the_prime256v1_parameter() {
        let key_pair = generate_ec_key();
        let sec1 = key_pair.public_key().as_ref();
        let signing_input = "protected.payload";
        let header = ProtectedHeader {
            alg: "ES256".to_string(),
            jwk: Some(Jwk::EC {
                crv: "P-256".to_string(),
                x: b64(&sec1[1..33]),
                y: b64(&sec1[33..65]),
            }),
            kid: None,
            nonce: "n".to_string(),
            url: "u".to_string(),
            crit: None,
        };
        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
        let sig = sig.as_ref();
        let der = verify_signature_and_get_der(&header, signing_input, &b64(sig)).unwrap();

        let parts = spki_parts(&der).unwrap();
        assert_eq!(parts.parameters, Some(oid!(1, 2, 840, 10045, 3, 1, 7)));
        assert!(verify_signature_with_spki("ES256", &der, signing_input, &b64(sig)).is_ok());
    }

    #[test]
    fn ec_coordinates_must_be_exactly_32_octets() {
        let key_pair = generate_ec_key();
        let sec1 = key_pair.public_key().as_ref();

        for (x, y, case) in [
            (b64(&sec1[2..33]), b64(&sec1[33..65]), "short x"),
            (
                b64(&sec1[1..33]),
                b64(&[&[0u8][..], &sec1[33..65]].concat()),
                "long y",
            ),
            (String::new(), b64(&sec1[33..65]), "empty x"),
        ] {
            let header = ProtectedHeader {
                alg: "ES256".to_string(),
                jwk: Some(Jwk::EC {
                    crv: "P-256".to_string(),
                    x,
                    y,
                }),
                kid: None,
                nonce: "n".to_string(),
                url: "u".to_string(),
                crit: None,
            };
            assert!(
                matches!(
                    verify_signature_and_get_der(&header, "a.b", &dummy_sig()),
                    Err(SignatureError::Malformed(_))
                ),
                "{case} should be rejected"
            );
        }
    }

    /// Each variant renders with its own prefix. These strings reach an
    /// operator's log when a signed request is refused, so a variant added
    /// without a message would read as an empty failure.
    #[test]
    fn every_signature_error_renders_its_kind() {
        for (error, expected) in [
            (SignatureError::Malformed("m"), "Malformed signature: m"),
            (
                SignatureError::BadAlgorithm("a"),
                "Unsupported algorithm: a",
            ),
            (SignatureError::BadSignature("s"), "Bad signature: s"),
            (SignatureError::Encoding("e"), "Encoding error: e"),
        ] {
            assert_eq!(error.to_string(), expected);
        }
    }

    /// `spki_parts` reads keys straight out of the database, so every shape it
    /// cannot make sense of has to be an error rather than a panic or a wrong
    /// key: a corrupted `accounts.pubkey` row must refuse the request, not
    /// authenticate somebody else.
    #[test]
    fn a_malformed_stored_spki_is_an_encoding_error() {
        use simple_asn1::{ASN1Block, to_der};

        let cases: Vec<(Vec<u8>, &str)> = vec![
            (b"not DER at all".to_vec(), "could not be parsed"),
            // A top-level INTEGER where a SEQUENCE belongs.
            (
                to_der(&ASN1Block::Integer(0, 42.into())).unwrap(),
                "is not a SEQUENCE",
            ),
            // SEQUENCE whose first element is not the AlgorithmIdentifier.
            (
                to_der(&ASN1Block::Sequence(
                    0,
                    vec![ASN1Block::Integer(0, 1.into())],
                ))
                .unwrap(),
                "has no AlgorithmIdentifier",
            ),
            // AlgorithmIdentifier present, but holding no OID.
            (
                to_der(&ASN1Block::Sequence(
                    0,
                    vec![ASN1Block::Sequence(
                        0,
                        vec![ASN1Block::Integer(0, 1.into())],
                    )],
                ))
                .unwrap(),
                "has no algorithm OID",
            ),
            // Well-formed AlgorithmIdentifier, but no subjectPublicKey after it.
            (
                to_der(&ASN1Block::Sequence(
                    0,
                    vec![ASN1Block::Sequence(
                        0,
                        vec![ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1))],
                    )],
                ))
                .unwrap(),
                "has no subjectPublicKey",
            ),
        ];

        for (der, expected) in cases {
            match spki_parts(&der) {
                Err(SignatureError::Encoding(message)) => assert!(
                    message.contains(expected),
                    "expected {expected:?}, got {message:?}"
                ),
                other => panic!("expected an Encoding error for {expected:?}, got {other:?}"),
            }
        }
    }

    /// The same for the RSA branch of `spki_to_jwk`, which parses a second
    /// layer of DER out of the bit string.
    #[test]
    fn a_malformed_stored_rsa_key_is_an_encoding_error() {
        use simple_asn1::{ASN1Block, to_der};

        /// Wraps `inner` as the `subjectPublicKey` of an RSA SPKI.
        fn rsa_spki(inner: Vec<u8>) -> Vec<u8> {
            let bits = inner.len() * 8;
            to_der(&ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::Sequence(
                        0,
                        vec![ASN1Block::ObjectIdentifier(
                            0,
                            oid!(1, 2, 840, 113549, 1, 1, 1),
                        )],
                    ),
                    ASN1Block::BitString(0, bits, inner),
                ],
            ))
            .unwrap()
        }

        // Not DER inside the bit string at all.
        match spki_to_jwk(&rsa_spki(b"not DER".to_vec())) {
            Err(SignatureError::Encoding(message)) => {
                assert!(message.contains("could not be parsed"), "{message}")
            }
            other => panic!("expected an Encoding error, got {other:?}"),
        }

        // A SEQUENCE, but not `{ n, e }`.
        let wrong_shape =
            to_der(&ASN1Block::Sequence(0, vec![ASN1Block::Boolean(0, true)])).unwrap();
        match spki_to_jwk(&rsa_spki(wrong_shape)) {
            Err(SignatureError::Encoding(message)) => {
                assert!(message.contains("SEQUENCE { n, e }"), "{message}")
            }
            other => panic!("expected an Encoding error, got {other:?}"),
        }

        // Not a SEQUENCE at the top of the key itself.
        let not_a_sequence = to_der(&ASN1Block::Integer(0, 7.into())).unwrap();
        match spki_to_jwk(&rsa_spki(not_a_sequence)) {
            Err(SignatureError::Encoding(message)) => {
                assert!(message.contains("is not a SEQUENCE"), "{message}")
            }
            other => panic!("expected an Encoding error, got {other:?}"),
        }
    }
}
