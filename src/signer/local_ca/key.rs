//! Where the local CA's issuing private key lives.
//!
//! [`CaSigningKey`] is the seam between [`LocalCa`](super::LocalCa) and the key
//! that signs its leaves and its CRL. It exists because **rcgen already defines
//! the abstraction we need**: `rcgen::SigningKey` is a public trait, and every
//! signing entry point this backend uses — `CertificateSigningRequestParams::
//! signed_by`, `CertificateRevocationListParams::signed_by`,
//! `CertificateParams::self_signed`, and `Issuer<'_, S>` itself — is generic
//! over it. So `LocalCa` holds an `Issuer<'static, CaSigningKey>` and nothing
//! in `issue`/`revoke`/`crl_der` has any idea whether the private key is a few
//! bytes in this process's heap or a token on the other end of a USB cable.
//!
//! An enum rather than `Arc<dyn SigningKey>`: rcgen implements its traits for
//! `&S` but not for `Arc<dyn _>`, the variant set is closed and small, and the
//! default (software) path keeps a direct call with no dynamic dispatch.
//!
//! The [`Pkcs11`](CaSigningKey::Pkcs11) variant only exists in a build with
//! `--features hsm`; see [`super::pkcs11`].

use std::path::Path;

use rcgen::{KeyPair, PublicKeyData, SignatureAlgorithm, SigningKey};

use crate::config::LocalCaConfig;

/// The key that signs this CA's leaves and CRLs.
pub enum CaSigningKey {
    /// A key pair held in this process's memory, read from `key_path` (or
    /// generated and written there on first run).
    Software(KeyPair),
    /// A key that never leaves a PKCS#11 token. `sign` is a `C_Sign` call.
    #[cfg(feature = "hsm")]
    Pkcs11(super::pkcs11::Pkcs11SigningKey),
}

impl PublicKeyData for CaSigningKey {
    fn der_bytes(&self) -> &[u8] {
        match self {
            Self::Software(key) => key.der_bytes(),
            #[cfg(feature = "hsm")]
            Self::Pkcs11(key) => key.der_bytes(),
        }
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        match self {
            Self::Software(key) => key.algorithm(),
            #[cfg(feature = "hsm")]
            Self::Pkcs11(key) => key.algorithm(),
        }
    }
}

impl SigningKey for CaSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            Self::Software(key) => key.sign(msg),
            #[cfg(feature = "hsm")]
            Self::Pkcs11(key) => key.sign(msg),
        }
    }
}

impl std::fmt::Debug for CaSigningKey {
    /// Never renders key material — mirroring rcgen's own `Issuer`/`KeyPair`
    /// `Debug` impls, which elide it deliberately.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software(_) => f.write_str("CaSigningKey::Software([elided])"),
            #[cfg(feature = "hsm")]
            Self::Pkcs11(key) => write!(f, "CaSigningKey::Pkcs11({key:?})"),
        }
    }
}

/// Where the issuing private key comes from — the `signer.local_ca.key_source`
/// values, parsed once at startup so a typo cannot reach the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A PEM file at `key_path`, loaded or generated. The default, and the only
    /// behaviour that existed before this module.
    File,
    /// A PKCS#11 token described by `[signer.local_ca.pkcs11]`.
    Pkcs11,
}

impl KeySource {
    /// Parses `signer.local_ca.key_source`.
    ///
    /// An unknown value is a startup error rather than a silent fallback to
    /// `File`: falling back would mean an operator who meant to protect the CA
    /// key in hardware gets a software key and no indication of it.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "pkcs11" => Ok(Self::Pkcs11),
            other => anyhow::bail!(
                "unsupported local_ca key_source: `{other}` (expected \"file\" or \"pkcs11\")"
            ),
        }
    }
}

/// Reads the PKCS#11 user PIN from `pin_file` if set, else from `pin`.
///
/// `pin_file` wins so a deployment can keep the PIN out of both the config file
/// and the process environment. Neither set is a startup error: this is only
/// ever called for `key_source = "pkcs11"`, where a login is not optional.
///
/// The file's contents are trimmed of trailing whitespace. This is not
/// cosmetic — `printf 'x' > pin` and `echo x > pin` differ by a newline, and
/// `C_Login` does not ignore it: the PIN simply comes back **wrong**, which on
/// a YubiKey PIV applet burns one of the three attempts standing between the
/// operator and a PUK-blocked slot.
#[cfg_attr(not(feature = "hsm"), allow(dead_code))]
pub fn read_pin(cfg: &LocalCaConfig) -> anyhow::Result<String> {
    let pkcs11 = &cfg.pkcs11;

    if !pkcs11.pin_file.is_empty() {
        let path = Path::new(&pkcs11.pin_file);
        // The PIN unlocks the CA's signing key; a world-readable file holding
        // it is worth the same nag `ca.key` gets.
        crate::pemfile::warn_if_key_is_readable("local_ca_pkcs11_pin_permissive", path);
        let raw = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!(
                "local_ca pkcs11 pin_file `{}` could not be read: {error}",
                pkcs11.pin_file
            )
        })?;
        let pin = raw.trim_end().to_string();
        if pin.is_empty() {
            anyhow::bail!("local_ca pkcs11 pin_file `{}` is empty", pkcs11.pin_file);
        }
        return Ok(pin);
    }

    if !pkcs11.pin.is_empty() {
        return Ok(pkcs11.pin.clone());
    }

    anyhow::bail!(
        "local_ca key_source = \"pkcs11\" needs a user PIN: set \
         signer.local_ca.pkcs11.pin_file, or the \
         ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__PIN environment variable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Pkcs11Config;
    use crate::testutil::TempDir;
    use rcgen::{CertificateParams, Issuer};

    fn config_with(pkcs11: Pkcs11Config) -> LocalCaConfig {
        LocalCaConfig {
            pkcs11,
            ..LocalCaConfig::default()
        }
    }

    #[test]
    fn key_source_parses_the_two_known_values() {
        assert_eq!(KeySource::parse("file").unwrap(), KeySource::File);
        assert_eq!(KeySource::parse("pkcs11").unwrap(), KeySource::Pkcs11);
    }

    /// A typo must stop the server rather than quietly leave the CA key in a
    /// file when the operator asked for hardware.
    #[test]
    fn an_unknown_key_source_is_an_error_naming_it() {
        let error = KeySource::parse("hsm").unwrap_err().to_string();
        assert!(error.contains("hsm"), "{error}");
        assert!(error.contains("pkcs11"), "{error}");
    }

    /// The regression test for the `Issuer<'static, KeyPair>` →
    /// `Issuer<'static, CaSigningKey>` swap: wrapping a key pair in the enum
    /// must produce byte-identical behaviour, not merely a certificate that
    /// happens to parse.
    #[test]
    fn the_software_variant_signs_exactly_as_the_bare_key_pair_does() {
        let key_pair = KeyPair::generate().unwrap();
        // The same key, reached through the enum — `KeyPair` is not `Clone`, so
        // it round-trips through PEM.
        let wrapped = CaSigningKey::Software(KeyPair::from_pem(&key_pair.serialize_pem()).unwrap());

        // The public halves must agree, or the CA certificate and the issued
        // leaves would name different keys.
        assert_eq!(wrapped.der_bytes(), key_pair.der_bytes());
        assert_eq!(
            wrapped.subject_public_key_info(),
            key_pair.subject_public_key_info()
        );
        assert_eq!(wrapped.algorithm(), key_pair.algorithm());

        // ECDSA is randomised, so two signatures over one message differ by
        // construction. What must hold is that both verify — build a real CA
        // through each and check the issued leaf against it.
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_cert = ca_params.self_signed(&wrapped).unwrap();

        let issuer = Issuer::new(ca_params, wrapped);
        let leaf_key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(vec!["example.com".to_string()])
            .unwrap()
            .serialize_request(&leaf_key)
            .unwrap();
        let parsed =
            rcgen::CertificateSigningRequestParams::from_der(&csr.der().to_vec().into()).unwrap();
        let leaf = parsed.signed_by(&issuer).unwrap();

        // `webpki` is the strictest parser in the tree; if the signature the
        // enum produced were malformed, this is where it would show.
        let (_, parsed_leaf) = x509_parser::parse_x509_certificate(leaf.der()).unwrap();
        let (_, parsed_ca) = x509_parser::parse_x509_certificate(ca_cert.der()).unwrap();
        assert!(
            parsed_leaf
                .verify_signature(Some(parsed_ca.public_key()))
                .is_ok()
        );
    }

    #[test]
    fn debug_never_renders_key_material() {
        let key = CaSigningKey::Software(KeyPair::generate().unwrap());
        let rendered = format!("{key:?}");
        assert!(rendered.contains("elided"), "{rendered}");
    }

    #[test]
    fn a_pin_file_wins_over_the_pin_field() {
        let dir = TempDir::new("pin");
        let path = dir.write("hsm.pin", "from-file\n");
        let cfg = config_with(Pkcs11Config {
            pin: "from-config".to_string(),
            pin_file: path.to_string_lossy().into_owned(),
            ..Pkcs11Config::default()
        });
        assert_eq!(read_pin(&cfg).unwrap(), "from-file");
    }

    /// The newline `echo` leaves behind is not part of the PIN. Getting this
    /// wrong costs one of three attempts before a PIV slot blocks.
    #[test]
    fn a_trailing_newline_is_not_part_of_the_pin() {
        let dir = TempDir::new("pin");
        for written in ["1234\n", "1234\r\n", "1234"] {
            let path = dir.write("hsm.pin", written);
            let cfg = config_with(Pkcs11Config {
                pin_file: path.to_string_lossy().into_owned(),
                ..Pkcs11Config::default()
            });
            assert_eq!(read_pin(&cfg).unwrap(), "1234", "for {written:?}");
        }
    }

    #[test]
    fn the_pin_field_is_used_when_no_file_is_configured() {
        let cfg = config_with(Pkcs11Config {
            pin: "1234".to_string(),
            ..Pkcs11Config::default()
        });
        assert_eq!(read_pin(&cfg).unwrap(), "1234");
    }

    #[test]
    fn no_pin_at_all_is_an_error_naming_both_ways_to_set_one() {
        let error = read_pin(&config_with(Pkcs11Config::default()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("pin_file"), "{error}");
        assert!(
            error.contains("ACME_PROXY_SIGNER__LOCAL_CA__PKCS11__PIN"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_pin_file_is_an_error_naming_the_path() {
        let cfg = config_with(Pkcs11Config {
            pin_file: "/nonexistent/acme-proxy/hsm.pin".to_string(),
            ..Pkcs11Config::default()
        });
        let error = read_pin(&cfg).unwrap_err().to_string();
        assert!(error.contains("/nonexistent/acme-proxy/hsm.pin"), "{error}");
    }

    /// An empty file is a configuration mistake, not an empty PIN — catching it
    /// here turns it into a startup error instead of a `CKR_PIN_INCORRECT` that
    /// eats a login attempt.
    #[test]
    fn an_empty_pin_file_is_an_error() {
        let dir = TempDir::new("pin");
        let path = dir.write("hsm.pin", "\n");
        let cfg = config_with(Pkcs11Config {
            pin_file: path.to_string_lossy().into_owned(),
            ..Pkcs11Config::default()
        });
        assert!(read_pin(&cfg).is_err());
    }
}
