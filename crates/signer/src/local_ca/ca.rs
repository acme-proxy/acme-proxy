//! Generating this CA's own certificate, and the serial numbers it issues
//! under.
//!
//! The `pkcs11` key source never reaches any of this: it *loads* a CA and
//! refuses to create one, deliberately, so that nothing can leave a private key
//! on disk while the operator believes it is in hardware.
//!
//! [`ca_subject_round_trips`] is the exception: it vets an *imported* CA on
//! every key source, before any of it is used to sign.

use time::{Duration, OffsetDateTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};

use acme_proxy_core::config::LocalCaSubjectConfig;

use super::{CA_VALIDITY_DAYS, CLOCK_SKEW_ALLOWANCE};

/// hardcoded value this backend has always used.
pub(super) const DEFAULT_CA_COMMON_NAME: &str = "acme-proxy local CA";

/// Builds the CA's own Subject from `subject`, falling back to
/// [`DEFAULT_CA_COMMON_NAME`] for the CommonName when it — or any other
/// field — is unset or empty (`None | Some("")`, matching
/// `dns::resolver_addr`'s env-var-ambiguity convention: `config`'s
/// environment source can't tell an explicitly empty string from an absent
/// one). The other five attributes are simply omitted when unset; there is
/// no sensible default for them.
pub(super) fn build_ca_distinguished_name(
    subject: &LocalCaSubjectConfig,
) -> rcgen::DistinguishedName {
    fn present(value: &Option<String>) -> Option<&str> {
        match value.as_deref() {
            None | Some("") => None,
            Some(s) => Some(s),
        }
    }

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        present(&subject.common_name).unwrap_or(DEFAULT_CA_COMMON_NAME),
    );
    if let Some(v) = present(&subject.organization) {
        dn.push(DnType::OrganizationName, v);
    }
    if let Some(v) = present(&subject.organizational_unit) {
        dn.push(DnType::OrganizationalUnitName, v);
    }
    if let Some(v) = present(&subject.country) {
        dn.push(DnType::CountryName, v);
    }
    if let Some(v) = present(&subject.state) {
        dn.push(DnType::StateOrProvinceName, v);
    }
    if let Some(v) = present(&subject.locality) {
        dn.push(DnType::LocalityName, v);
    }
    dn
}

/// Generates a fresh self-signed CA of `key_type`, returning its key pair and
/// certificate PEM. Shared by the on-disk and in-memory constructors.
pub(super) fn generate_ca(
    key_type: &str,
    subject: &LocalCaSubjectConfig,
) -> anyhow::Result<(KeyPair, String)> {
    let key_pair = match key_type {
        // rcgen's default algorithm is ECDSA P-256.
        "ecdsa-p256" => KeyPair::generate()?,
        other => anyhow::bail!("unsupported local_ca key_type: {other}"),
    };

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    // `Constrained(0)` means this CA may issue leaves but no further CAs. Even
    // if a sub-CA certificate escaped, a conforming verifier would refuse the
    // chain below it.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.distinguished_name = build_ca_distinguished_name(subject);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // rcgen leaves these at its own defaults otherwise; pin an explicit window.
    let now = OffsetDateTime::now_utc();
    params.not_before = now - CLOCK_SKEW_ALLOWANCE;
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
    params.serial_number = Some(random_serial()?);

    let ca_cert = params.self_signed(&key_pair)?;
    Ok((key_pair, ca_cert.pem()))
}

/// Refuses a CA certificate whose subject rcgen would not write back unchanged.
///
/// rcgen does not keep the CA's subject as bytes: `Issuer::from_ca_cert_der`
/// rebuilds it into a `DistinguishedName`, which holds one value per attribute
/// type and one attribute per RDN, and writes that copy as the issuer of every
/// certificate and CRL. A subject that repeats a type (`DC=com, DC=example`)
/// silently loses all but the last value, so everything this CA signs names an
/// issuer that does not exist and fails path validation (issue #36). A
/// multi-valued RDN (`OU=PKI+CN=…`) is refused by rcgen with an opaque parse
/// error.
///
/// Rather than guess which shapes break, this proves the round trip: it builds
/// an `Issuer` from the certificate exactly as the constructors do, over a
/// throwaway software key (a token is never touched), signs a throwaway leaf,
/// and compares that leaf's issuer with the CA's subject byte for byte. rcgen
/// writes a CRL's issuer with the same function, so the CRL is covered too.
///
/// Delete this when rcgen supports repeated attributes (rustls/rcgen#81, fixed
/// by #394 for 0.15) and the fixtures in `testdata/` round-trip.
pub(super) fn ca_subject_round_trips(ca_der: &[u8]) -> anyhow::Result<()> {
    let (_, parsed) = x509_parser::parse_x509_certificate(ca_der)
        .map_err(|error| anyhow::anyhow!("the CA certificate does not parse: {error}"))?;
    let subject = &parsed.tbs_certificate.subject;

    // The CA's own key is not needed to see what rcgen writes: an `Issuer`
    // over a throwaway key names the CA exactly as the real one does.
    let throwaway = KeyPair::generate()?;
    let issuer = Issuer::from_ca_cert_der(&ca_der.into(), &throwaway).map_err(|error| {
        anyhow::anyhow!(
            "the CA subject `{subject}` cannot be used to sign ({error}): a multi-valued \
             RDN (such as `OU=PKI+CN=Issuing CA`) or an unusual string type in the subject \
             is not supported. Re-issue the CA certificate with one attribute per RDN"
        )
    })?;
    let probe = CertificateParams::default().signed_by(&throwaway, &issuer)?;
    let (_, probe) = x509_parser::parse_x509_certificate(probe.der()).map_err(|error| {
        anyhow::anyhow!("rcgen wrote a certificate that does not parse: {error}")
    })?;
    let written = &probe.tbs_certificate.issuer;

    anyhow::ensure!(
        written.as_raw() == subject.as_raw(),
        "the CA subject `{subject}` would be written as `{written}` in every certificate \
         and CRL this CA signs, so none of them would chain to it. A subject that repeats \
         an attribute type (such as `DC=com, DC=example`) is not supported yet \
         (rustls/rcgen#81). Re-issue the CA certificate without the repeated attribute"
    );
    Ok(())
}

/// A fresh 16-byte (127-bit) certificate serial number.
///
/// Without this rcgen derives the serial as `SHA256(subjectPublicKey)[0..20]`,
/// which is *deterministic per key*: renewing an order with the same key pair —
/// the normal case — would mint a second certificate carrying the same serial
/// from the same issuer, violating RFC 5280 §4.1.2.2 and breaking any revocation
/// scheme built on top.
pub(super) fn random_serial() -> anyhow::Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
    // Clear the top bit so the DER INTEGER stays positive and fits in 16 bytes.
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first certificate of a PEM file, as DER.
    fn der(pem: &str) -> Vec<u8> {
        acme_proxy_core::cert::leaf_der_from_chain(pem).unwrap()
    }

    #[test]
    fn a_repeated_attribute_type_is_refused() {
        let error = ca_subject_round_trips(&der(include_str!("testdata/repeated_dc_ca.pem")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("DC=com, DC=example"), "{error}");
        assert!(error.contains("rcgen#81"), "{error}");
    }

    #[test]
    fn a_multi_valued_rdn_is_refused() {
        let error = ca_subject_round_trips(&der(include_str!("testdata/multi_valued_rdn_ca.pem")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("multi-valued RDN"), "{error}");
    }

    /// The guard must not refuse an ordinary imported CA: openssl mixes
    /// `PrintableString` and `UTF8String`, and both must survive.
    #[test]
    fn an_openssl_made_ca_round_trips() {
        ca_subject_round_trips(&der(include_str!("testdata/openssl_ca.pem"))).unwrap();
    }

    #[test]
    fn every_generated_subject_round_trips() {
        let subject = LocalCaSubjectConfig {
            common_name: Some("Issuing CA".to_string()),
            organization: Some("Example Corp".to_string()),
            organizational_unit: Some("PKI".to_string()),
            country: Some("FR".to_string()),
            state: Some("Île-de-France".to_string()),
            locality: Some("Paris".to_string()),
        };
        for subject in [LocalCaSubjectConfig::default(), subject] {
            let (_, ca_pem) = generate_ca("ecdsa-p256", &subject).unwrap();
            ca_subject_round_trips(&der(&ca_pem)).unwrap();
        }
    }
}
