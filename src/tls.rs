//! HTTPS termination for the server's own listener.
//!
//! RFC 8555 §6.1 expects ACME to be spoken over HTTPS. This module is the
//! alternative to putting a reverse proxy in front: with `server.tls.enabled`,
//! `server.bind_address` speaks TLS **instead of** cleartext HTTP — one listener,
//! not two. It is off by default, so an existing deployment is untouched.
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

use std::future::pending;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::{Listener, ListenerExt, TapIo};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};
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

/// How many connections may sit between the TCP accept and `axum` — handshakes
/// in flight plus finished streams not yet picked up.
///
/// This is the accept loop's backpressure: it reserves a slot *before* accepting,
/// so a flood of half-open TLS connections cannot spawn tasks without bound.
const MAX_PENDING_CONNECTIONS: usize = 256;

/// Pause after a failed `accept()`, so a listener that is refusing connections
/// (out of file descriptors, say) does not spin a core. Mirrors what
/// `axum::serve` does for the same case.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// The listener type [`TlsListener::spawn`] hands to `axum::serve`.
///
/// The `tap_io` wrapper is **functional, not decorative**.
/// `into_make_service_with_connect_info::<SocketAddr>()` requires
/// `SocketAddr: Connected<IncomingStream<'_, L>>`, and axum implements that for
/// exactly two listeners: the concrete `TcpListener`, and — blanket — any
/// `TapIo<L, F>` whose `L::Addr` is `Clone + Sync + 'static`. We cannot write the
/// missing impl ourselves: foreign trait, foreign `Self` type, coherence refuses
/// it. So the wrapper is what makes the peer address reach the request
/// extensions, and without it `add_filter_middleware` sees no client address and
/// the IP filters fail closed. Returning the wrapped type from `spawn` is what
/// keeps a caller from forgetting.
pub type HttpsListener = TapIo<TlsListener, fn(&mut TlsStream<TcpStream>)>;

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
        warn!(event = "tls_base_url_mismatch", base_url = ?cfg.base_url,
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
        info!(event = "tls_cert_loaded", listener = listener, cert_path = ?cfg.cert_path);
    } else {
        let (cert_pem, key_pem) = generate_self_signed(host_url)?;
        std::fs::write(cert_path, &cert_pem)
            .map_err(|error| anyhow::anyhow!("{}: {error}", cert_path.display()))?;
        pemfile::write_private_key(key_path, &key_pem)?;
        info!(event = "tls_cert_generated", listener = listener, cert_path = ?cfg.cert_path, key_path = ?cfg.key_path);
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

    info!(event = "tls_enabled", listener = listener, bind_address = ?bind_address, cert_path = ?cfg.cert_path);
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

/// A listener yielding connections whose TLS handshake has already completed.
///
/// Implements `axum::serve::Listener`, so the server keeps being run by
/// `axum::serve` — including `into_make_service_with_connect_info`, which is what
/// the IP filters depend on (see [`HttpsListener`]).
///
/// **Handshakes happen off the accept path.** A background task accepts TCP
/// connections and spawns each handshake, so one slow client cannot hold up
/// every other connection for the length of the timeout; `accept()` only picks
/// up the results. A handshake that fails or runs out of budget is logged and
/// dropped — the trait's `accept()` returns no `Result`, which suits this
/// exactly: a bad connection simply never becomes one.
pub struct TlsListener {
    /// Connections whose handshake completed, oldest first.
    incoming: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    /// The address the underlying socket is bound to.
    local_addr: SocketAddr,
}

impl TlsListener {
    /// Starts accepting on `tcp`, handshaking with `acceptor` under
    /// `handshake_timeout`.
    ///
    /// The returned listener is the one to hand to `axum::serve` — see
    /// [`HttpsListener`] for why it is wrapped.
    pub fn spawn(
        tcp: TcpListener,
        acceptor: TlsAcceptor,
        handshake_timeout: Duration,
    ) -> std::io::Result<HttpsListener> {
        let local_addr = tcp.local_addr()?;
        let (sender, incoming) = mpsc::channel(MAX_PENDING_CONNECTIONS);

        tokio::spawn(async move {
            loop {
                // Reserving before accepting is the backpressure: at most
                // `MAX_PENDING_CONNECTIONS` connections are in flight, and a
                // dropped listener closes the channel, which ends this task.
                let Ok(permit) = sender.clone().reserve_owned().await else {
                    debug!(event = "tls_accept_loop_ended");
                    return;
                };

                let (stream, peer) = match tcp.accept().await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!(event = "tls_accept_failed", error = %error);
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            permit.send((tls, peer));
                        }
                        // Neither is the server's problem: a port scan, a
                        // cleartext client, a stalled handshake. Never fatal.
                        Ok(Err(error)) => {
                            debug!(event = "tls_handshake_failed", peer = %peer, error = %error);
                        }
                        Err(_) => debug!(event = "tls_handshake_timeout", peer = %peer),
                    }
                });
            }
        });

        Ok(Self {
            incoming,
            local_addr,
        }
        // See `HttpsListener`: this is what carries the peer address into the
        // request extensions. The closure itself has nothing to do.
        .tap_io(noop_tap as fn(&mut TlsStream<TcpStream>)))
    }
}

/// The `tap_io` callback. Named rather than a closure so [`HttpsListener`] can
/// spell its type out.
fn noop_tap(_stream: &mut TlsStream<TcpStream>) {}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(connection) => connection,
            // The accept task only ends when this listener is dropped, so the
            // channel closing means it died. There is no error to return in this
            // signature, and returning a connection is impossible; parking is
            // what is left.
            None => {
                error!(
                    event = "tls_acceptor_stopped",
                    "the TLS accept task ended: no further connection will be served"
                );
                pending().await
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
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

    /// The whole listener, over a real socket: `axum::serve` on top of
    /// [`TlsListener`], driven by a real TLS client.
    mod loopback {
        use super::*;
        use axum::extract::ConnectInfo;
        use axum::routing::get;
        use axum::{Router, serve};
        use rustls::pki_types::ServerName;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;

        /// Serves `/peer`, which answers with the peer address axum saw — the
        /// value the IP filters run on.
        async fn https_server(handshake_timeout: Duration) -> u16 {
            let dir = TempDir::new("tls");
            let acceptor = from_config(&tls_config(&dir, "https://localhost"))
                .unwrap()
                .unwrap();

            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            let listener = TlsListener::spawn(tcp, acceptor, handshake_timeout).unwrap();

            let app = Router::new().route(
                "/peer",
                get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
            );

            tokio::spawn(async move {
                serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });

            // The directory must outlive the server: the acceptor holds the
            // parsed material, so the files may go, but not before `from_config`
            // has read them.
            drop(dir);
            port
        }

        /// One `GET /peer` over TLS, returning the raw response and the address
        /// the client used.
        async fn get_peer(port: u16) -> (String, SocketAddr) {
            let config =
                crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let client_addr = stream.local_addr().unwrap();

            let mut tls = TlsConnector::from(config)
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            tls.write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            (response, client_addr)
        }

        /// The end-to-end proof: a real handshake, a real request, and — the
        /// point of the test — `ConnectInfo` surviving the TLS wrapper. Without
        /// it every IP filter would fail closed.
        #[tokio::test]
        async fn a_request_is_served_with_the_peer_address_intact() {
            let port = https_server(Duration::from_secs(5)).await;
            let (response, client_addr) = get_peer(port).await;

            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(
                response.ends_with(&client_addr.to_string()),
                "expected the body to be {client_addr}, got {response}"
            );
        }

        /// A cleartext client (or a port scan) fails the handshake without
        /// taking the listener down with it.
        #[tokio::test]
        async fn a_failed_handshake_does_not_stop_the_listener() {
            let port = https_server(Duration::from_secs(5)).await;

            let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            plain.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            // The server answers a TLS alert, not HTTP.
            let mut ignored = Vec::new();
            let _ = plain.read_to_end(&mut ignored).await;

            let (response, _) = get_peer(port).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        }

        /// A client that connects and then says nothing is dropped when its
        /// budget runs out — and, crucially, does not hold up anyone else while
        /// it stalls. That is the whole reason handshakes are spawned rather
        /// than run inside `accept()`.
        #[tokio::test]
        async fn a_stalled_handshake_times_out_without_blocking_others() {
            let port = https_server(Duration::from_millis(300)).await;

            let mut stalled = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

            // Served while the first connection is still stuck mid-handshake.
            let (response, _) = tokio::time::timeout(Duration::from_secs(5), get_peer(port))
                .await
                .expect("a stalled handshake must not block the accept loop");
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

            // And the stalled one is eventually dropped, not held forever.
            let mut buffer = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buffer))
                .await
                .expect("the handshake timeout must close the connection");
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "expected EOF after the handshake timeout, got {read:?}"
            );
        }
    }
}
