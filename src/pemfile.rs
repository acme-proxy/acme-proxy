//! PEM material on disk: reading a certificate chain or a private key, and
//! writing a key that is never briefly world-readable.
//!
//! Two subsystems provision key material at startup — [`crate::signer::local_ca`]
//! generates and reloads the CA, [`crate::tls`] does the same for the HTTPS
//! listener's certificate — so the file hygiene lives here rather than in either
//! of them, the way [`crate::dns`] holds the resolver that both `filter` and
//! `challenge` need.
//!
//! Reading goes through `x509-parser`'s label-agnostic PEM iterator, already in
//! the tree via `rcgen`. That is why `rustls-pemfile` is not a dependency: what
//! it would buy is the label match below.

use std::fs;
use std::path::Path;

use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tracing::warn;
use x509_parser::pem::Pem;

/// PEM label of an X.509 certificate.
const CERTIFICATE: &str = "CERTIFICATE";

/// Reads every `CERTIFICATE` block of `path`, in file order — which for a chain
/// means leaf first, as `rustls` expects.
///
/// Blocks with any other label are skipped, so a file holding both the chain and
/// its key is read correctly.
pub(crate) fn read_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = read_file(path)?;

    let mut chain = Vec::new();
    for block in Pem::iter_from_buffer(&bytes) {
        let block = block.map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
        if block.label == CERTIFICATE {
            chain.push(CertificateDer::from(block.contents));
        }
    }

    if chain.is_empty() {
        anyhow::bail!("{}: no CERTIFICATE block found", path.display());
    }
    Ok(chain)
}

/// Reads the first private key of `path`, whichever of the three encodings it is
/// written in.
///
/// The PEM label is what says how the DER is encoded, and `rustls` needs to be
/// told: `PRIVATE KEY` is PKCS#8, `EC PRIVATE KEY` is SEC1, `RSA PRIVATE KEY` is
/// PKCS#1. An unknown label is reported *by name* — "expected a private key,
/// found CERTIFICATE" is the whole diagnosis of a swapped `cert_path`/`key_path`.
pub(crate) fn read_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes = read_file(path)?;

    let mut skipped: Vec<String> = Vec::new();
    for block in Pem::iter_from_buffer(&bytes) {
        let block = block.map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
        let key = match block.label.as_str() {
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(block.contents)),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(block.contents)),
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(block.contents)),
            // Not a key: keep looking, but remember what it was.
            other => {
                skipped.push(other.to_string());
                continue;
            }
        };
        return Ok(key);
    }

    if skipped.is_empty() {
        anyhow::bail!("{}: no private key block found", path.display());
    }
    anyhow::bail!(
        "{}: no private key block found, only {}",
        path.display(),
        skipped.join(", ")
    );
}

/// Writes a private key PEM, owner-readable from the moment it exists.
///
/// `fs::write` would create the file with the process umask (commonly `0644`)
/// and only tighten it afterwards, leaving a window in which any local user can
/// read the key. Passing the mode to `open` closes that race. `create_new`
/// additionally refuses to follow a pre-planted symlink.
pub(crate) fn write_private_key(path: &Path, pem: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Writes `bytes` to `path` atomically, at `mode`.
///
/// Two properties `fs::write` does not have. **Atomic**: the content lands via a
/// temporary file and a rename, so a crash part-way through leaves the previous
/// version intact rather than a truncated one. That matters for the local CA's
/// revocation ledger, which is the authoritative input to CRL generation — a
/// half-written ledger read at the next startup is a set of revocations
/// silently forgotten. **Owner-controlled**: the mode is passed to `open`
/// rather than applied afterwards, the same reasoning as
/// [`write_private_key`], so the file is never briefly world-readable.
///
/// The temporary file sits beside the target, since `rename` is only atomic
/// within a filesystem.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;

    let temp = path.with_extension("tmp");
    // Not `create_new`: a leftover temporary from a previous crash must not
    // wedge every subsequent write. It is in a directory the server owns and
    // its name is derived, not attacker-chosen.
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    // Before the rename, or the rename can be durable while the content is not.
    file.sync_all()?;
    drop(file);

    fs::rename(&temp, path)?;
    Ok(())
}

/// Warns when an operator-supplied private key is group- or world-readable.
///
/// Loading it anyway is deliberate — refusing to start over file permissions
/// would be a poor trade — but it should never pass unremarked. `event` names the
/// subsystem, so a log line says *which* key is exposed.
pub(crate) fn warn_if_key_is_readable(event: &'static str, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o077;
            if mode != 0 {
                warn!(event,
                      path = ?path,
                      mode = format!("{:o}", metadata.permissions().mode() & 0o777),
                      "private key is readable beyond its owner");
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (event, path);
}

/// Reads a file, naming it in the error. `fs::read`'s own message does not.
fn read_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    fs::read(path).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// A self-signed certificate PEM plus its key PEM.
    fn certificate() -> (String, rcgen::KeyPair) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair)
    }

    /// A chain is read whole, in file order: `rustls` wants the leaf first, and
    /// the CA that signed it after.
    #[test]
    fn every_certificate_block_is_read_in_order() {
        let dir = TempDir::new("pemfile");
        let (leaf, _) = certificate();
        let (ca, _) = certificate();
        let path = dir.write("chain.pem", &format!("{leaf}{ca}"));

        let chain = read_certificates(&path).unwrap();
        assert_eq!(chain.len(), 2);
        // The first block really is the first certificate, not the other one.
        let expected = read_certificates(&dir.write("leaf.pem", &leaf)).unwrap();
        assert_eq!(chain[0], expected[0]);
        assert_ne!(chain[0], chain[1]);
    }

    /// A key sitting in the same file is not mistaken for a certificate.
    #[test]
    fn a_key_block_is_skipped_when_reading_certificates() {
        let dir = TempDir::new("pemfile");
        let (pem, key_pair) = certificate();
        let path = dir.write(
            "both.pem",
            &format!("{}{pem}", key_pair.serialize_pem()).to_string(),
        );

        assert_eq!(read_certificates(&path).unwrap().len(), 1);
    }

    #[test]
    fn a_file_without_a_certificate_is_an_error() {
        let dir = TempDir::new("pemfile");
        let path = dir.write("empty.pem", "not pem at all\n");

        let error = read_certificates(&path).unwrap_err().to_string();
        assert!(error.contains("no CERTIFICATE block"), "{error}");
        assert!(error.contains("empty.pem"), "{error}");
    }

    #[test]
    fn a_missing_file_names_itself() {
        let dir = TempDir::new("pemfile");
        let path = dir.join("absent.pem");

        let error = read_certificates(&path).unwrap_err().to_string();
        assert!(error.contains("absent.pem"), "{error}");
    }

    /// rcgen writes PKCS#8; the other two labels are what an operator's own
    /// tooling produces.
    #[test]
    fn each_private_key_label_maps_to_its_encoding() {
        let dir = TempDir::new("pemfile");
        let (_, key_pair) = certificate();
        let der = key_pair.serialize_der();
        let body = base64_pem(&der);

        for (label, expected) in [
            ("PRIVATE KEY", "Pkcs8"),
            ("EC PRIVATE KEY", "Sec1"),
            ("RSA PRIVATE KEY", "Pkcs1"),
        ] {
            let path = dir.write(
                "key.pem",
                &format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n"),
            );
            let key = read_private_key(&path).unwrap();
            let variant = match key {
                PrivateKeyDer::Pkcs8(_) => "Pkcs8",
                PrivateKeyDer::Sec1(_) => "Sec1",
                PrivateKeyDer::Pkcs1(_) => "Pkcs1",
                _ => "unknown",
            };
            assert_eq!(variant, expected, "label {label}");
            fs::remove_file(&path).unwrap();
        }
    }

    /// The commonest misconfiguration: `key_path` pointed at the certificate.
    /// The error has to say so.
    #[test]
    fn a_certificate_where_a_key_is_expected_names_the_label() {
        let dir = TempDir::new("pemfile");
        let (pem, _) = certificate();
        let path = dir.write("swapped.pem", &pem);

        let error = read_private_key(&path).unwrap_err().to_string();
        assert!(error.contains("no private key block"), "{error}");
        assert!(error.contains("CERTIFICATE"), "{error}");
    }

    #[test]
    fn a_file_without_any_block_is_an_error() {
        let dir = TempDir::new("pemfile");
        let path = dir.write("garbage.key", "-- nothing here --\n");

        let error = read_private_key(&path).unwrap_err().to_string();
        assert!(error.contains("no private key block"), "{error}");
    }

    /// The key is never readable by anyone else, not even briefly.
    #[test]
    #[cfg(unix)]
    fn a_written_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("pemfile");
        let path = dir.join("written.key");
        write_private_key(&path, "-----BEGIN PRIVATE KEY-----\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
        // `create_new`: an existing file is never silently overwritten.
        assert!(write_private_key(&path, "x").is_err());
    }

    /// PEM body of `der`, wrapped at 64 characters.
    fn base64_pem(der: &[u8]) -> String {
        use base64::prelude::*;

        let encoded = BASE64_STANDARD.encode(der);
        let mut out = String::new();
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out
    }

    #[test]
    fn write_atomic_replaces_the_target_and_leaves_no_temporary() {
        let dir = TempDir::new("pemfile");
        let path = dir.join("ledger.json");

        write_atomic(&path, b"first", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        // Overwriting an existing file must work — this is the case a
        // `create_new` would have refused, and it is the normal one here.
        write_atomic(&path, b"second", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        assert!(
            !path.with_extension("tmp").exists(),
            "the temporary must be renamed away, not left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_honours_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("pemfile");

        let private = dir.join("ledger.json");
        write_atomic(&private, b"{}", 0o600).unwrap();
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o600,
            "the revocation ledger decides what the CRL says; it is not public"
        );

        let public = dir.join("ca.crl");
        write_atomic(&public, b"der", 0o644).unwrap();
        assert_eq!(
            fs::metadata(&public).unwrap().permissions().mode() & 0o777,
            0o644,
            "the CRL is published material and is served to anyone"
        );
    }

    /// A leftover temporary from a previous crash must not wedge every later
    /// write — which is why this deliberately does not use `create_new`.
    #[test]
    fn write_atomic_overwrites_a_stale_temporary() {
        let dir = TempDir::new("pemfile");
        let path = dir.join("ledger.json");
        fs::write(path.with_extension("tmp"), b"leftover from a crash").unwrap();

        write_atomic(&path, b"fresh", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
    }
}
