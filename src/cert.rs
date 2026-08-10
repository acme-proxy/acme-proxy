//! Small X.509 helpers shared by the certificate revocation paths: the ACME
//! `POST /revokeCert` handler ([`crate::handlers::post_revoke_cert`]) and the `order
//! revoke` admin CLI command ([`crate::admin::revoke_order`]). Both need to
//! pull a certificate's serial/public key out of raw DER, and pull the leaf
//! back out of a stored `leaf + CA` PEM chain, so the parsing lives here once
//! rather than twice.

use base64::prelude::*;
use x509_parser::nom;
use x509_parser::pem::Pem;

/// RFC 5280 §5.3.1 `CRLReason` codes RFC 8555 §7.6 permits in a revocation
/// request's `reason` — every value except the reserved `7`. Shared with
/// `rcgen::RevocationReason`'s own numbering (see
/// [`crate::signer::local_ca`]).
pub const ALLOWED_REVOCATION_REASONS: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10];

/// Whether `reason` is one of the `CRLReason` codes RFC 8555 §7.6 permits.
#[must_use]
pub fn is_valid_revocation_reason(reason: u32) -> bool {
    ALLOWED_REVOCATION_REASONS.contains(&reason)
}

/// Extracts a single certificate's serial (hex-encoded, no separators) and
/// the DER encoding of its `SubjectPublicKeyInfo` from raw X.509 DER bytes.
///
/// The SPKI returned is the certificate's own `SEQUENCE { AlgorithmIdentifier,
/// BIT STRING }` — the same canonical DER-SPKI shape
/// `verify_signature_and_get_der` builds for `Account.pubkey`, so it can be
/// compared byte-for-byte against a JWS-verified `pubkey` with no conversion.
pub fn cert_serial_and_spki(
    der: &[u8],
) -> Result<(String, Vec<u8>), nom::Err<x509_parser::error::X509Error>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)?;
    Ok((
        hex::encode(cert.tbs_certificate.raw_serial()),
        cert.tbs_certificate.subject_pki.raw.to_vec(),
    ))
}

/// Extracts the leaf certificate's DER bytes from a `leaf + CA` PEM chain
/// (the shape `SignerBackend::issue` returns and `orders.certificate`
/// stores) — the first `CERTIFICATE` block, mirroring
/// [`crate::pemfile::read_certificates`]'s label-agnostic PEM iterator.
pub fn leaf_der_from_chain(chain_pem: &str) -> anyhow::Result<Vec<u8>> {
    match Pem::iter_from_buffer(chain_pem.as_bytes()).next() {
        Some(result) => Ok(result?.contents),
        None => anyhow::bail!("no CERTIFICATE block found in chain"),
    }
}

/// The ACME Renewal Information certificate identifier (RFC 9773 §4.1) for a
/// DER-encoded certificate: `base64url(AKI keyIdentifier) || "." ||
/// base64url(serial)`, both unpadded.
///
/// Used in both directions: to ask an upstream CA about a certificate
/// ([`crate::signer::relay`]) and to check an inbound certID against the
/// certificate it claims to name ([`crate::handlers::get_renewal_info`]).
///
/// Fails when the certificate carries no Authority Key Identifier extension,
/// or one with no `keyIdentifier` field — without it there is no certID to
/// build, and guessing would produce one no one recognizes. Certificates this
/// server issued before its local CA emitted an AKI are exactly that case, so
/// the inbound side treats the failure as "cannot check" rather than "reject".
pub fn ari_cert_id(der: &[u8]) -> anyhow::Result<String> {
    let (aki, serial) = ari_cert_id_parts(der)?;
    Ok(format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(aki),
        BASE64_URL_SAFE_NO_PAD.encode(serial),
    ))
}

/// The raw `(AKI keyIdentifier, serial)` bytes behind [`ari_cert_id`], for
/// callers that want to compare the halves rather than the rendered string.
pub fn ari_cert_id_parts(der: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;

    let (_, cert) = x509_parser::parse_x509_certificate(der)?;
    let extension = cert
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)?
        .ok_or_else(|| anyhow::anyhow!("certificate has no Authority Key Identifier extension"))?;

    let ParsedExtension::AuthorityKeyIdentifier(aki) = extension.parsed_extension() else {
        anyhow::bail!("Authority Key Identifier extension could not be parsed");
    };
    let key_identifier = aki
        .key_identifier
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Authority Key Identifier carries no keyIdentifier"))?;

    Ok((
        key_identifier.0.to_vec(),
        cert.tbs_certificate.raw_serial().to_vec(),
    ))
}

/// The two halves of an ACME Renewal Information certID (RFC 9773 §4.1),
/// decoded: `base64url(AKI keyIdentifier) "." base64url(serial)`.
///
/// Parsed in one place because both RFC 9773 surfaces consume the same string:
/// `GET /renewalInfo/{certID}` (§4.1) and a newOrder's `replaces` field (§5),
/// which "is constructed in the same way as the path component for GET
/// requests described in Section 4.1".
#[derive(Debug, PartialEq, Eq)]
pub struct AriCertId {
    /// The issuer's Authority Key Identifier `keyIdentifier`, raw bytes.
    pub aki: Vec<u8>,
    /// The certificate serial, raw DER integer content bytes (no tag/length).
    pub serial: Vec<u8>,
}

impl AriCertId {
    /// The serial as this codebase stores it: lowercase hex, no separators —
    /// what `orders.cert_serial` holds and `Order::find_by_cert_serial` takes.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        hex::encode(&self.serial)
    }
}

/// Parses an inbound certID (RFC 9773 §4.1).
///
/// Strict on both halves, which is the point of doing it here rather than
/// splitting inline: exactly one `.`, and both sides unpadded base64url —
/// `NO_PAD` *rejects* `=` rather than tolerating it, which is the right reading
/// of "All trailing `=` characters MUST be stripped from both parts". An empty
/// half is refused too, since neither an empty AKI nor an empty serial can
/// identify anything.
pub fn parse_ari_cert_id(cert_id: &str) -> anyhow::Result<AriCertId> {
    let (aki_b64, serial_b64) = cert_id
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("certID must be two base64url parts separated by '.'"))?;

    if serial_b64.contains('.') {
        anyhow::bail!("certID must contain exactly one '.'");
    }
    if aki_b64.is_empty() || serial_b64.is_empty() {
        anyhow::bail!("both halves of a certID must be non-empty");
    }

    Ok(AriCertId {
        aki: BASE64_URL_SAFE_NO_PAD
            .decode(aki_b64)
            .map_err(|_| anyhow::anyhow!("invalid key identifier encoding in certID"))?,
        serial: BASE64_URL_SAFE_NO_PAD
            .decode(serial_b64)
            .map_err(|_| anyhow::anyhow!("invalid serial number encoding in certID"))?,
    })
}

/// Extracts the validity period (notBefore, notAfter) from a DER-encoded certificate
/// as UNIX timestamps (seconds since epoch).
pub fn cert_validity(der: &[u8]) -> Result<(i64, i64), nom::Err<x509_parser::error::X509Error>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)?;
    Ok((
        cert.tbs_certificate.validity.not_before.timestamp(),
        cert.tbs_certificate.validity.not_after.timestamp(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(name: &str) -> rcgen::Certificate {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params.self_signed(&key_pair).unwrap()
    }

    fn make_cert_der(name: &str) -> Vec<u8> {
        make_cert(name).der().to_vec()
    }

    #[test]
    fn is_valid_revocation_reason_accepts_every_defined_code_but_the_reserved_one() {
        for code in 0..=10u32 {
            assert_eq!(is_valid_revocation_reason(code), code != 7, "code {code}");
        }
        assert!(!is_valid_revocation_reason(999));
    }

    #[test]
    fn cert_serial_and_spki_round_trips_a_real_certificate() {
        let der = make_cert_der("example.com");
        let (serial_hex, spki) = cert_serial_and_spki(&der).unwrap();
        assert!(!serial_hex.is_empty());
        assert!(hex::decode(&serial_hex).is_ok());
        assert!(!spki.is_empty());

        // The SPKI must be the certificate's actual public key, re-derivable
        // via x509-parser's own accessor.
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(spki, parsed.tbs_certificate.subject_pki.raw);
    }

    #[test]
    fn cert_serial_and_spki_rejects_garbage() {
        assert!(cert_serial_and_spki(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    #[test]
    fn leaf_der_from_chain_takes_the_first_block() {
        let leaf_cert = make_cert("leaf.example.com");
        let ca_cert = make_cert("ca.example.com");
        let chain = format!("{}{}", leaf_cert.pem(), ca_cert.pem());

        let leaf = leaf_der_from_chain(&chain).unwrap();
        assert_eq!(leaf, leaf_cert.der().to_vec());
    }

    #[test]
    fn leaf_der_from_chain_rejects_a_chain_with_no_certificate_block() {
        assert!(leaf_der_from_chain("not a pem file at all").is_err());
    }

    /// A CA-signed leaf carrying an Authority Key Identifier — the shape ARI
    /// applies to, whether an upstream or this server's own `LocalCa` issued it.
    ///
    /// Built with `rcgen` directly rather than through `LocalCa` only to keep
    /// this module's tests free of the signer: `LocalCa` does set
    /// `use_authority_key_identifier_extension`, and
    /// `local_ca::tests::an_issued_leaf_carries_the_cas_key_identifier` is what
    /// pins that.
    fn ca_signed_leaf_with_aki() -> Vec<u8> {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["ca.example".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn ari_cert_id_joins_the_aki_and_the_serial() {
        let leaf = ca_signed_leaf_with_aki();

        let cert_id = ari_cert_id(&leaf).unwrap();
        let (aki_b64, serial_b64) = cert_id.split_once('.').expect("certID is two parts");

        // The serial half must round-trip to the same serial the revocation
        // path reads, since both describe the same certificate.
        let (serial_hex, _) = cert_serial_and_spki(&leaf).unwrap();
        assert_eq!(
            hex::encode(BASE64_URL_SAFE_NO_PAD.decode(serial_b64).unwrap()),
            serial_hex
        );

        // And the AKI half must be the issuer's key identifier, not empty.
        let aki = BASE64_URL_SAFE_NO_PAD.decode(aki_b64).unwrap();
        assert!(!aki.is_empty());
        // Base64url, so neither half may carry padding a URL path would escape.
        assert!(!cert_id.contains('=') && !cert_id.contains('+') && !cert_id.contains('/'));
    }

    /// A certificate with no AKI has no derivable certID; saying so beats
    /// inventing one the upstream would not recognize. This is also the case
    /// a `local_ca`-issued leaf falls into today — see
    /// [`ca_signed_leaf_with_aki`].
    #[test]
    fn ari_cert_id_refuses_a_certificate_without_an_aki() {
        let der = make_cert_der("example.com");
        let error = ari_cert_id(&der).unwrap_err().to_string();
        assert!(error.contains("Authority Key Identifier"), "{error}");
    }

    #[test]
    fn ari_cert_id_rejects_garbage() {
        assert!(ari_cert_id(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    #[test]
    fn cert_validity_extracts_correct_timestamps() {
        let cert = make_cert("example.com");
        let der = cert.der().to_vec();

        let (not_before, not_after) = cert_validity(&der).unwrap();

        // rcgen generates certificates with default validity starting now or recently
        // and ending some days in the future (rcgen defaults to 365 days)
        // Just verify they are reasonable unix timestamps
        assert!(not_before > 0);
        assert!(not_after > not_before);
    }
}
