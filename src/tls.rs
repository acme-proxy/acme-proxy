//! HTTPS termination for the server's own listener.
//!
//! RFC 8555 §6.1 expects ACME to be spoken over HTTPS. This module is the
//! alternative to putting a reverse proxy in front: with `server.tls.enabled`,
//! `server.bind_address` speaks TLS **instead of** cleartext HTTP — one listener,
//! not two. It is off by default, so an existing deployment is untouched.
//!
//! **Provisioning only.** Accepting connections — and handing one of these
//! acceptors to each handshake — belongs to [`crate::listener`], which owns a
//! socket that can be replaced and a TLS mode that can be switched off. The line
//! between the two is the one this module already drew for itself: resolving
//! configuration at startup on this side, the accept loop on the other.
//!
//! Shaped like the other subsystems ([`crate::signer`], [`crate::filter`],
//! [`crate::challenge`]): [`from_config`] resolves everything at startup — files
//! read or generated, certificate and key parsed, rustls configuration built — so
//! a broken setup stops the server instead of failing every connection later.
//! Its `Option` is the "disabled" case, which touches no disk at all.
//!
//! ## Certificate provisioning
//!
//! `cert_path`/`key_path` are loaded when **both** exist; otherwise a self-signed
//! certificate for the host of `server.base_url` is generated and written, the
//! way [`crate::signer::local_ca`] provisions the CA and `sqlite.db` provisions
//! itself. The key is created `0600` (see [`crate::pemfile`]).
//!
//! ## Two rustls constraints
//!
//! 1. The crypto provider is passed **explicitly**, never installed as a process
//!    default — the same rule as [`crate::challenge::tls_alpn_01`], and for the
//!    same reason: `CryptoProvider::install_default` panics on a second call.
//! 2. `with_single_cert` parses the chain with `rustls-webpki`, which refuses an
//!    unrecognised *critical* extension. An ordinary server certificate is fine;
//!    a `tls-alpn-01` *responder* certificate is exactly what cannot be served
//!    this way (see `AcceptAnyServerCert` in [`crate::challenge::tls_alpn_01`]).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use url::{Host, Url};

use crate::config::{ServerConfig, TlsConfig};
use crate::pemfile;

/// Validity of a generated self-signed certificate, in days (~10 years).
///
/// Long on purpose: nothing regenerates the file once it exists, so a short-lived
/// certificate would expire in silence years after anyone remembers where it came
/// from. An operator who wants a real lifecycle supplies their own files.
const SELF_SIGNED_VALIDITY_DAYS: i64 = 3653;

/// Backdating applied to `not_before`, to tolerate modest clock skew between
/// this server and a client — as in [`crate::signer::local_ca`].
const CLOCK_SKEW_ALLOWANCE: time::Duration = time::Duration::hours(1);

/// Builds the TLS acceptor for the ACME listener, or `None` when HTTPS is
/// disabled. Called once at startup, so it may fail fast (the caller exits).
///
/// Takes the whole [`ServerConfig`] rather than its `tls` table alone: the two
/// warnings below are ACME-specific and need `base_url` to spot. Everything
/// after them is [`acceptor_from`], which the admin listener shares.
pub fn from_config(cfg: &ServerConfig) -> anyhow::Result<Option<TlsAcceptor>> {
    if !cfg.tls.enabled {
        warn!(
            event = "tls_disabled",
            outcome = "advisory",
            "serving ACME in cleartext: RFC 8555 §6.1 expects HTTPS, so either \
             enable server.tls or terminate TLS in front of this server"
        );
        return Ok(None);
    }

    // The JWS `url` check (RFC 8555 §6.4) is a string equality against
    // `base_url + path`, so a base URL still naming `http://` breaks every signed
    // request the moment this listener speaks TLS. The converse — `https://` with
    // TLS off — is the legitimate reverse-proxy setup, and says nothing.
    if cfg.base_url.starts_with("http://") {
        warn!(event = "tls_base_url_mismatch", outcome = "advisory", base_url = ?cfg.base_url,
              "server.base_url names http:// while TLS is enabled: signed requests \
               will be refused until it names https://");
    }

    Ok(Some(acceptor_from(
        &cfg.tls,
        &cfg.base_url,
        &cfg.bind_address,
        "acme",
    )?))
}

/// Builds the TLS acceptor for the web admin listener, or `None` when it is
/// disabled — or when the panel itself is off, which touches no disk.
///
/// The counterpart to [`from_config`], with the ACME-specific warnings replaced
/// by the one that matters here. Nothing warns about cleartext: for this
/// listener that combination is already refused outright at startup unless the
/// bind is loopback (see [`crate::webadmin::check_config`]), and on loopback it
/// is the documented default rather than something to complain about on every
/// boot.
pub fn admin_from_config(cfg: &crate::config::AdminConfig) -> anyhow::Result<Option<TlsAcceptor>> {
    if !cfg.enabled || !cfg.tls.enabled {
        return Ok(None);
    }

    // `AdminTlsConfig` is a distinct type from `TlsConfig` (its defaults
    // differ), but the fields are the same four, so the shared builder takes
    // the parts rather than either struct.
    let tls = TlsConfig {
        enabled: cfg.tls.enabled,
        cert_path: cfg.tls.cert_path.clone(),
        key_path: cfg.tls.key_path.clone(),
        handshake_timeout_ms: cfg.tls.handshake_timeout_ms,
    };
    Ok(Some(acceptor_from(
        &tls,
        &cfg.base_url,
        &cfg.bind_address,
        "admin",
    )?))
}

/// Loads or generates `cfg.cert_path`/`cfg.key_path` and builds the rustls
/// acceptor.
///
/// Knows nothing about ACME. `listener` (`"acme"` / `"admin"`) only labels the
/// log lines, so one socket's certificate churn is distinguishable from the
/// other's; the event *names* stay the same, because "a TLS certificate was
/// loaded" means the same thing on both — and `tls_enabled` is among the names
/// `tests/e2e/` watches for.
fn acceptor_from(
    cfg: &TlsConfig,
    host_url: &str,
    bind_address: &str,
    listener: &'static str,
) -> anyhow::Result<TlsAcceptor> {
    let cert_path = Path::new(&cfg.cert_path);
    let key_path = Path::new(&cfg.key_path);

    if cert_path.exists() && key_path.exists() {
        pemfile::warn_if_key_is_readable("tls_key_permissive", key_path);
        info!(event = "tls_cert_loaded", outcome = "success", listener = listener, cert_path = ?cfg.cert_path);
    } else {
        let (cert_pem, key_pem) = generate_self_signed(host_url)?;
        std::fs::write(cert_path, &cert_pem)
            .map_err(|error| anyhow::anyhow!("{}: {error}", cert_path.display()))?;
        pemfile::write_private_key(key_path, &key_pem)?;
        info!(event = "tls_cert_generated", outcome = "success", listener = listener, cert_path = ?cfg.cert_path, key_path = ?cfg.key_path);
    }

    // Read back what was just written rather than keeping the DER in hand: what
    // is served is then exactly what is on disk, on the first run as on every
    // later one.
    let chain = pemfile::read_certificates(cert_path)?;
    let key = pemfile::read_private_key(key_path)?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("building the TLS server configuration: {error}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| {
            anyhow::anyhow!(
                "{} and {} are not a usable certificate/key pair: {error}",
                cert_path.display(),
                key_path.display()
            )
        })?;
    // `axum` is taken with its default features, which do not include `http2`:
    // advertising `h2` would promise a protocol this server does not speak.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    info!(event = "tls_enabled", outcome = "success", listener = listener, bind_address = ?bind_address, cert_path = ?cfg.cert_path);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generates a self-signed certificate for the host of `base_url`, returning the
/// certificate and key PEMs.
///
/// The host is the only name a client will ever ask for, which is why it is
/// derived rather than configured: a certificate for anything else would not be
/// accepted anyway, and an operator needing more names supplies their own files.
fn generate_self_signed(base_url: &str) -> anyhow::Result<(String, String)> {
    let url = Url::parse(base_url)
        .map_err(|error| anyhow::anyhow!("server.base_url is not a URL: {error}"))?;
    let host = match url
        .host()
        .ok_or_else(|| anyhow::anyhow!("server.base_url has no host: {base_url}"))?
    {
        Host::Domain(name) => name.to_string(),
        // `Host`'s own `Display` brackets an IPv6 address; `CertificateParams`
        // parses each name itself and would take `[::1]` for a DNS name.
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };

    let key_pair = KeyPair::generate()?;
    // `new` turns anything that parses as an IP into an `IpAddress` SAN and
    // everything else into a `DnsName` one, which is exactly the split we want.
    let mut params = CertificateParams::new(vec![host.clone()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - CLOCK_SKEW_ALLOWANCE;
    params.not_after = now + time::Duration::days(SELF_SIGNED_VALIDITY_DAYS);
    // rcgen's default serial — `SHA256(subjectPublicKey)[0..20]` — is unique
    // enough here: the key is freshly generated and signs one certificate. The
    // local CA needs a random one because it signs many, from the same key.

    let certificate = params.self_signed(&key_pair)?;
    Ok((certificate.pem(), key_pair.serialize_pem()))
}

/// Everything one handshake needs, as a single swappable value.
///
/// The pair travels together because both halves come from the same `[tls]`
/// section and both are read at the same moment — the top of a handshake. Making
/// this the unit [`crate::listener`]'s accept loop reads is what lets a renewed
/// certificate and a changed `handshake_timeout_ms` land without rebinding the
/// socket: a configuration reload publishes a new `TlsSettings` and the next
/// connection uses it, while connections already established are untouched.
///
/// That cell is an `Option`, and the absence is `tls.enabled = false` — which is
/// why turning TLS on or off is not a different listener type either.
#[derive(Clone)]
pub struct TlsSettings {
    pub acceptor: TlsAcceptor,
    pub handshake_timeout: Duration,
}

impl TlsSettings {
    #[must_use]
    pub fn new(acceptor: TlsAcceptor, handshake_timeout: Duration) -> Self {
        Self {
            acceptor,
            handshake_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsConfig;
    use crate::testutil::TempDir;
    use std::fs;

    /// A scratch directory that removes itself, so a failing assertion cannot
    /// leave key material behind.
    /// A `ServerConfig` with TLS enabled, its material inside `dir`.
    fn tls_config(dir: &TempDir, base_url: &str) -> ServerConfig {
        ServerConfig {
            bind_address: "127.0.0.1:0".to_string(),
            base_url: base_url.to_string(),
            tls: TlsConfig {
                enabled: true,
                cert_path: dir.join("server.pem").display().to_string(),
                key_path: dir.join("server.key").display().to_string(),
                handshake_timeout_ms: 5_000,
            },
            ..ServerConfig::default()
        }
    }

    /// `TlsAcceptor` is not `Debug`, so `unwrap_err` is unavailable.
    fn startup_error(result: anyhow::Result<Option<TlsAcceptor>>) -> String {
        match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("this configuration must not build"),
        }
    }

    /// An `AdminConfig` with the panel *and* its TLS on, material inside `dir`.
    fn admin_config(dir: &TempDir, base_url: &str) -> crate::config::AdminConfig {
        crate::config::AdminConfig {
            enabled: true,
            bind_address: "127.0.0.1:0".to_string(),
            base_url: base_url.to_string(),
            tls: crate::config::AdminTlsConfig {
                enabled: true,
                cert_path: dir.join("admin.pem").display().to_string(),
                key_path: dir.join("admin.key").display().to_string(),
                handshake_timeout_ms: 5_000,
            },
            ..crate::config::AdminConfig::default()
        }
    }

    /// Two ways for the admin listener to want no acceptor, and neither may
    /// touch the disk: the panel off entirely, or the panel on in cleartext.
    #[test]
    fn the_admin_acceptor_is_absent_when_the_panel_or_its_tls_is_off() {
        for (panel, tls) in [(false, true), (true, false), (false, false)] {
            let dir = TempDir::new("tls-admin");
            let mut cfg = admin_config(&dir, "https://localhost:3001");
            cfg.enabled = panel;
            cfg.tls.enabled = tls;

            assert!(
                admin_from_config(&cfg).unwrap().is_none(),
                "enabled={panel} tls={tls} must build no acceptor"
            );
            assert!(!Path::new(&cfg.tls.cert_path).exists());
            assert!(!Path::new(&cfg.tls.key_path).exists());
        }
    }

    /// The admin listener provisions and reloads exactly as the ACME one does,
    /// and takes its name from `admin.base_url` rather than `server.base_url`.
    #[test]
    fn the_admin_certificate_is_generated_reloaded_and_names_its_own_host() {
        use x509_parser::prelude::*;

        let dir = TempDir::new("tls-admin");
        let cfg = admin_config(&dir, "https://panel.example.test:3001");

        assert!(admin_from_config(&cfg).unwrap().is_some());
        let generated = fs::read(&cfg.tls.cert_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&cfg.tls.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the generated key was {mode:o}");
        }

        // Reload rather than mint a second identity.
        assert!(admin_from_config(&cfg).unwrap().is_some());
        assert_eq!(fs::read(&cfg.tls.cert_path).unwrap(), generated);

        let chain = pemfile::read_certificates(Path::new(&cfg.tls.cert_path)).unwrap();
        let (_, certificate) = X509Certificate::from_der(&chain[0]).unwrap();
        let names: Vec<_> = certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .map(|name| format!("{name:?}"))
            .collect();
        assert!(names[0].contains("panel.example.test"), "{names:?}");
    }

    /// A mismatched pair fails at startup here too, naming both files.
    #[test]
    fn a_mismatched_admin_pair_is_a_startup_error() {
        let acme_dir = TempDir::new("tls-acme");
        let admin_dir = TempDir::new("tls-admin");

        // Generate two independent identities, then cross them.
        let acme = tls_config(&acme_dir, "https://localhost:3000");
        from_config(&acme).unwrap();
        let cfg = admin_config(&admin_dir, "https://localhost:3001");
        admin_from_config(&cfg).unwrap();

        let crossed = crate::config::AdminConfig {
            tls: crate::config::AdminTlsConfig {
                key_path: acme.tls.key_path.clone(),
                ..cfg.tls.clone()
            },
            ..cfg
        };
        let error = startup_error(admin_from_config(&crossed));
        assert!(
            error.contains("not a usable certificate/key pair"),
            "got: {error}"
        );
    }

    /// The two listeners keep separate certificates: provisioning one must not
    /// write, read or overwrite the other's files.
    #[test]
    fn the_two_listeners_provision_independent_certificates() {
        let dir = TempDir::new("tls-both");
        let acme = ServerConfig {
            bind_address: "127.0.0.1:0".to_string(),
            base_url: "https://acme.example.test".to_string(),
            tls: TlsConfig {
                enabled: true,
                cert_path: dir.join("server.pem").display().to_string(),
                key_path: dir.join("server.key").display().to_string(),
                handshake_timeout_ms: 5_000,
            },
            ..ServerConfig::default()
        };
        let admin = admin_config(&dir, "https://panel.example.test");

        from_config(&acme).unwrap();
        admin_from_config(&admin).unwrap();

        assert_ne!(
            fs::read(&acme.tls.cert_path).unwrap(),
            fs::read(&admin.tls.cert_path).unwrap(),
            "the two listeners answer to different names and must not share a certificate"
        );
    }

    /// The default is off, and off must mean *nothing happens*: no file read, no
    /// certificate generated where one was not asked for.
    #[test]
    fn disabled_builds_nothing_and_touches_no_disk() {
        let dir = TempDir::new("tls");
        let mut cfg = tls_config(&dir, "http://localhost:3000");
        cfg.tls.enabled = false;

        assert!(from_config(&cfg).unwrap().is_none());
        assert!(!Path::new(&cfg.tls.cert_path).exists());
        assert!(!Path::new(&cfg.tls.key_path).exists());
    }

    /// First run provisions both files; the second reuses them rather than
    /// minting a new identity on every restart.
    #[test]
    fn a_missing_certificate_is_generated_then_reloaded() {
        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "https://localhost:3000");

        assert!(from_config(&cfg).unwrap().is_some());
        let generated = fs::read(&cfg.tls.cert_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&cfg.tls.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the generated key was {mode:o}");
        }

        assert!(from_config(&cfg).unwrap().is_some());
        assert_eq!(fs::read(&cfg.tls.cert_path).unwrap(), generated);
    }

    /// The generated certificate is for the host of `base_url` — the only name a
    /// client will present in SNI.
    #[test]
    fn the_generated_certificate_names_the_base_url_host() {
        use x509_parser::prelude::*;

        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "https://acme.example.test:8443");
        from_config(&cfg).unwrap();

        let chain = pemfile::read_certificates(Path::new(&cfg.tls.cert_path)).unwrap();
        let (_, certificate) = X509Certificate::from_der(&chain[0]).unwrap();
        let names: Vec<_> = certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .map(|name| format!("{name:?}"))
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].contains("acme.example.test"), "{names:?}");
        // The port is not part of the name.
        assert!(!names[0].contains("8443"), "{names:?}");
    }

    /// A base URL on an IP address must yield an `iPAddress` SAN: no client
    /// honours an IP written into a `dNSName`.
    #[test]
    fn an_ip_base_url_yields_an_ip_san() {
        use x509_parser::prelude::*;

        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "https://127.0.0.1:3000");
        from_config(&cfg).unwrap();

        let chain = pemfile::read_certificates(Path::new(&cfg.tls.cert_path)).unwrap();
        let (_, certificate) = X509Certificate::from_der(&chain[0]).unwrap();
        let general_names = certificate.subject_alternative_name().unwrap().unwrap();
        assert!(
            general_names
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::IPAddress(_))),
            "{:?}",
            general_names.value.general_names
        );
    }

    #[test]
    fn a_base_url_without_a_host_is_a_startup_error() {
        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "not-a-url");

        let error = startup_error(from_config(&cfg));
        assert!(error.contains("server.base_url"), "{error}");
    }

    /// A certificate and a key that do not go together are caught at startup,
    /// not on the first handshake.
    #[test]
    fn a_mismatched_pair_is_a_startup_error() {
        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "https://localhost:3000");

        let (cert_pem, _) = generate_self_signed("https://localhost").unwrap();
        let (_, key_pem) = generate_self_signed("https://localhost").unwrap();
        fs::write(&cfg.tls.cert_path, cert_pem).unwrap();
        fs::write(&cfg.tls.key_path, key_pem).unwrap();

        let error = startup_error(from_config(&cfg));
        assert!(
            error.contains("not a usable certificate/key pair"),
            "{error}"
        );
    }

    #[test]
    fn a_certificate_file_without_a_certificate_is_a_startup_error() {
        let dir = TempDir::new("tls");
        let cfg = tls_config(&dir, "https://localhost:3000");

        let (_, key_pem) = generate_self_signed("https://localhost").unwrap();
        fs::write(&cfg.tls.cert_path, "nothing useful here\n").unwrap();
        fs::write(&cfg.tls.key_path, key_pem).unwrap();

        let error = startup_error(from_config(&cfg));
        assert!(error.contains("no CERTIFICATE block"), "{error}");
    }
}
