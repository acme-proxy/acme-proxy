//! Generating this CA's own certificate, and the serial numbers it issues
//! under.
//!
//! The `pkcs11` key source never reaches any of this: it *loads* a CA and
//! refuses to create one, deliberately, so that nothing can leave a private key
//! on disk while the operator believes it is in hardware.

use time::{Duration, OffsetDateTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::LocalCaSubjectConfig;

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
