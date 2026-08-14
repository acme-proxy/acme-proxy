//! The `tls-alpn-01` challenge (RFC 8737): a TLS handshake to port 443 with SNI
//! set to the identifier and ALPN `acme-tls/1`, answered with a certificate
//! carrying the proof in a critical `id-pe-acmeIdentifier` extension.
//!
//! Useful where port 80 is closed and the client cannot publish DNS records, and
//! the only challenge that needs no separate listener — the responder is the TLS
//! server that is already there.
//!
//! ## The responder's certificate is not trusted, and does not need to be
//!
//! RFC 8737 §3 says outright that the certificate presented is not validated as
//! a certificate: it is a carrier. The whole proof is the extension's content,
//! `SHA-256` of a key authorization derived from a per-challenge token only the
//! account holder knows. Replaying another responder's certificate would mean
//! having intercepted a `tls-alpn-01` handshake for that exact challenge — which
//! already requires controlling the path to the name being validated.
//!
//! That is why [`AcceptAnyServerCert`] accepts everything, and why the handshake
//! signature checks assert rather than verify. Doing otherwise is not merely
//! redundant, it does not work: see [`AcceptAnyServerCert`].

use std::sync::Arc;

use async_trait::async_trait;
use ring::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use subtle::ConstantTimeEq;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};
use x509_parser::prelude::*;

use super::{ChallengeError, ChallengeValidator, TLS_ALPN_01, ValidationContext};
use crate::config::TlsAlpnConfig;
use crate::dns::{self, Resolver};

/// The ALPN protocol identifier RFC 8737 §3 reserves for this challenge. A
/// server that does not negotiate it is not answering the challenge.
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// `id-pe-acmeIdentifier`, the extension carrying the proof (RFC 8737 §3).
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// A TLS handshake that returns the peer's leaf certificate.
///
/// Abstracted so the decision logic can be driven from certificates built in
/// memory, without a listener.
#[async_trait]
pub trait TlsAlpnProbe: Send + Sync {
    /// Handshakes with `identifier:port` using SNI `identifier` and ALPN
    /// `acme-tls/1`, returning the peer's leaf certificate in DER.
    async fn peer_certificate(&self, identifier: &str, port: u16) -> Result<Vec<u8>, ProbeError>;
}

/// Why a probe did not produce a certificate.
#[derive(Debug)]
pub enum ProbeError {
    /// Nothing answered: DNS, TCP connect, the socket dying mid-handshake.
    Connect(String),
    /// Something answered but the TLS exchange did not complete as required —
    /// an alert, no ALPN, no certificate.
    Tls(String),
}

/// A certificate verifier that accepts anything.
///
/// **Both signature checks assert rather than verify**, and that is not
/// laziness. `rustls-webpki` refuses to parse a certificate carrying an
/// unrecognised *critical* extension (`UnsupportedCriticalExtension`), and RFC
/// 8737 §3 requires `id-pe-acmeIdentifier` to be critical — so delegating to
/// `rustls::crypto::verify_tls13_signature`, which parses the certificate with
/// webpki internally, would fail against every conforming responder. (Go's
/// `crypto/x509` merely records unhandled critical extensions, which is why
/// Boulder never meets this.)
///
/// Asserting costs nothing here because the verifier above it already accepts
/// any certificate: the TLS layer establishes no identity at all, by design, and
/// the proof lives entirely in [`verify_acme_identifier`].
#[derive(Debug)]
struct AcceptAnyServerCert {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Must be non-empty or rustls refuses to build a `ClientHello`.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A TLS client configuration that trusts nothing and accepts everything,
/// optionally advertising `alpn`.
///
/// Shared with [`http_01`](super::http_01) for the https hop of a redirect,
/// where RFC 8555 §8.3 likewise says the certificate is not validated.
///
/// The crypto provider is passed **explicitly** rather than installed as a
/// process default: `CryptoProvider::install_default` panics on a second call,
/// which under `cargo test` is a matter of which tests happen to run together,
/// and a library has no business claiming a process-global anyway.
pub(crate) fn accept_any_client_config(alpn: &[&[u8]]) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = rustls::crypto::ring::default_provider();
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("building the TLS client configuration: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { schemes }))
        .with_no_client_auth();

    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// The production probe: a real TLS handshake over TCP.
pub struct RustlsProbe {
    config: Arc<ClientConfig>,
    resolver: Arc<dyn Resolver>,
}

impl RustlsProbe {
    /// Resolves its connect target through `resolver` — the same one
    /// `challenge::from_config` selected for `dns-01` (`dns.resolver` if set,
    /// else the system configuration).
    pub fn new(resolver: Arc<dyn Resolver>) -> anyhow::Result<Self> {
        Ok(Self {
            config: accept_any_client_config(&[ACME_TLS_ALPN])?,
            resolver,
        })
    }
}

#[async_trait]
impl TlsAlpnProbe for RustlsProbe {
    async fn peer_certificate(&self, identifier: &str, port: u16) -> Result<Vec<u8>, ProbeError> {
        let server_name = ServerName::try_from(identifier.to_string()).map_err(|error| {
            ProbeError::Connect(format!("{identifier} is not a valid SNI name: {error}"))
        })?;

        // Trying every resolved address in turn, the way `TcpStream::connect`
        // used to via the OS resolver — see `crate::dns::connect`.
        let stream = dns::connect(self.resolver.as_ref(), identifier, port)
            .await
            .map_err(|error| {
                ProbeError::Connect(format!("connecting to {identifier}:{port}: {error}"))
            })?;

        let stream = TlsConnector::from(self.config.clone())
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                ProbeError::Tls(format!("TLS handshake with {identifier}:{port}: {error}"))
            })?;

        let (_, connection) = stream.get_ref();

        // RFC 8737 §3: a server that did not negotiate `acme-tls/1` is serving
        // its ordinary certificate, not a challenge response. Accepting it would
        // mean comparing an extension against a certificate never meant as proof.
        match connection.alpn_protocol() {
            Some(ACME_TLS_ALPN) => {}
            Some(other) => {
                return Err(ProbeError::Tls(format!(
                    "{identifier}:{port} negotiated ALPN {:?} instead of acme-tls/1",
                    String::from_utf8_lossy(other)
                )));
            }
            None => {
                return Err(ProbeError::Tls(format!(
                    "{identifier}:{port} did not negotiate the acme-tls/1 ALPN protocol"
                )));
            }
        }

        let leaf = connection
            .peer_certificates()
            .and_then(<[CertificateDer<'_>]>::first)
            .ok_or_else(|| {
                ProbeError::Tls(format!("{identifier}:{port} presented no certificate"))
            })?;

        Ok(leaf.as_ref().to_vec())
    }
}

/// Probes a TLS responder and checks the certificate it presents.
pub struct TlsAlpn01Validator {
    probe: Arc<dyn TlsAlpnProbe>,
    port: u16,
}

impl std::fmt::Debug for TlsAlpn01Validator {
    /// `dyn TlsAlpnProbe` is not `Debug`; the port is the policy.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsAlpn01Validator")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl TlsAlpn01Validator {
    /// Builds the validator with a real TLS probe.
    pub fn from_config(cfg: &TlsAlpnConfig, resolver: Arc<dyn Resolver>) -> anyhow::Result<Self> {
        let probe = Arc::new(
            RustlsProbe::new(resolver)
                .map_err(|error| anyhow::anyhow!("challenge.tls_alpn_01: {error}"))?,
        );
        info!(
            event = "challenge_tls_alpn_01_loaded",
            outcome = "success",
            port = cfg.port
        );
        Ok(Self::with_probe(cfg, probe))
    }

    /// Same, against a caller-supplied probe. Used by tests.
    pub fn with_probe(cfg: &TlsAlpnConfig, probe: Arc<dyn TlsAlpnProbe>) -> Self {
        Self {
            probe,
            port: cfg.port,
        }
    }
}

#[async_trait]
impl ChallengeValidator for TlsAlpn01Validator {
    fn typ(&self) -> &'static str {
        TLS_ALPN_01
    }

    async fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        let leaf = self
            .probe
            .peer_certificate(ctx.identifier, self.port)
            .await
            .map_err(|error| match error {
                ProbeError::Connect(detail) => ChallengeError::Connection(detail),
                ProbeError::Tls(detail) => ChallengeError::Tls(detail),
            })?;

        verify_acme_identifier(&leaf, ctx.identifier, ctx.key_authorization).inspect(|()| {
            debug!(
                event = "challenge_tls_alpn_01_matched",
                outcome = "success",
                identifier = ctx.identifier,
                challenge_id = ctx.challenge_id,
            );
        })
    }
}

/// Checks a responder's certificate against RFC 8737 §3.
///
/// The certificate must carry exactly one subject alternative name — the
/// `dNSName` being validated — and a **critical** `id-pe-acmeIdentifier`
/// extension whose value is `OCTET STRING(SHA256(keyAuthorization))`.
///
/// Requiring a single SAN is the RFC's own rule and it matters: a responder
/// presenting `example.com` plus `victim.example` alongside a valid digest would
/// otherwise let one proof stand in for a name it was never derived from.
pub(crate) fn verify_acme_identifier(
    leaf_der: &[u8],
    identifier: &str,
    key_authorization: &str,
) -> Result<(), ChallengeError> {
    let (_, certificate) = X509Certificate::from_der(leaf_der).map_err(|error| {
        ChallengeError::Tls(format!(
            "responder certificate could not be parsed: {error}"
        ))
    })?;

    let sans = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| extension.value.general_names.as_slice())
        .unwrap_or_default();

    match sans {
        [GeneralName::DNSName(name)] if name.eq_ignore_ascii_case(identifier) => {}
        [] => {
            return Err(ChallengeError::IncorrectResponse(
                "responder certificate has no subject alternative name".to_string(),
            ));
        }
        [GeneralName::DNSName(name)] => {
            return Err(ChallengeError::IncorrectResponse(format!(
                "responder certificate is for {name}, not {identifier}"
            )));
        }
        other => {
            return Err(ChallengeError::IncorrectResponse(format!(
                "responder certificate must carry exactly one dNSName, found {}",
                other.len()
            )));
        }
    }

    let oid = der_parser::oid::Oid::from(ACME_IDENTIFIER_OID)
        .map_err(|error| ChallengeError::Internal(format!("acmeIdentifier OID: {error:?}")))?;
    let extension = certificate
        .get_extension_unique(&oid)
        .map_err(|error| {
            ChallengeError::IncorrectResponse(format!(
                "responder certificate has a malformed acmeIdentifier extension: {error}"
            ))
        })?
        .ok_or_else(|| {
            ChallengeError::IncorrectResponse(
                "responder certificate has no acmeIdentifier extension".to_string(),
            )
        })?;

    // RFC 8737 §3 requires the extension to be critical, so that a TLS stack
    // which does not understand it refuses to serve the certificate ordinarily.
    if !extension.critical {
        return Err(ChallengeError::IncorrectResponse(
            "the acmeIdentifier extension must be critical".to_string(),
        ));
    }

    // The extension value is a DER OCTET STRING wrapping the 32-byte digest:
    // tag 0x04, length 0x20, then the digest.
    let payload = match extension.value {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        _ => {
            return Err(ChallengeError::IncorrectResponse(
                "the acmeIdentifier extension is not a 32-octet OCTET STRING".to_string(),
            ));
        }
    };

    let expected = digest::digest(&digest::SHA256, key_authorization.as_bytes());
    if payload.ct_eq(expected.as_ref()).into() {
        Ok(())
    } else {
        Err(ChallengeError::IncorrectResponse(
            "the acmeIdentifier extension does not match the key authorization".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};

    const KEY_AUTH: &str = "token-value.thumbprint-value";

    /// Builds a responder certificate the way a conforming ACME client would.
    ///
    /// `digest_of` lets a test sign the digest of *something else*, and
    /// `critical` lets it drop the criticality RFC 8737 requires.
    fn responder_cert(sans: Vec<SanType>, digest_of: &str, critical: bool) -> Vec<u8> {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;

        let hash = digest::digest(&digest::SHA256, digest_of.as_bytes());
        // DER OCTET STRING: tag, length, contents.
        let mut value = vec![0x04, 0x20];
        value.extend_from_slice(hash.as_ref());

        let mut extension = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, value);
        extension.set_criticality(critical);
        params.custom_extensions = vec![extension];

        params
            .self_signed(&key_pair)
            .unwrap()
            .der()
            .as_ref()
            .to_vec()
    }

    fn dns_san(name: &str) -> SanType {
        SanType::DnsName(name.to_string().try_into().unwrap())
    }

    fn valid_cert() -> Vec<u8> {
        responder_cert(vec![dns_san("example.com")], KEY_AUTH, true)
    }

    /// A probe answering from a canned outcome.
    struct StubProbe {
        outcome: Result<Vec<u8>, &'static str>,
        tls_error: bool,
    }

    impl StubProbe {
        fn serving(der: Vec<u8>) -> Self {
            Self {
                outcome: Ok(der),
                tls_error: false,
            }
        }
    }

    #[async_trait]
    impl TlsAlpnProbe for StubProbe {
        async fn peer_certificate(
            &self,
            _identifier: &str,
            _port: u16,
        ) -> Result<Vec<u8>, ProbeError> {
            match &self.outcome {
                Ok(der) => Ok(der.clone()),
                Err(detail) if self.tls_error => Err(ProbeError::Tls(detail.to_string())),
                Err(detail) => Err(ProbeError::Connect(detail.to_string())),
            }
        }
    }

    fn validator(probe: StubProbe) -> TlsAlpn01Validator {
        TlsAlpn01Validator::with_probe(&TlsAlpnConfig::default(), Arc::new(probe))
    }

    fn context(identifier: &str) -> ValidationContext<'_> {
        ValidationContext {
            identifier,
            wildcard: false,
            token: "token-value",
            key_authorization: KEY_AUTH,
            challenge_id: "chall-1",
        }
    }

    #[tokio::test]
    async fn a_conforming_responder_certificate_passes() {
        assert!(
            validator(StubProbe::serving(valid_cert()))
                .validate(&context("example.com"))
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_digest_must_be_of_this_challenge_s_key_authorization() {
        let der = responder_cert(vec![dns_san("example.com")], "some.other-key-auth", true);
        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail))
                if detail.contains("does not match the key authorization")
        ));
    }

    /// Criticality is not decoration: it is what stops the certificate being
    /// served as an ordinary one by a stack that ignores the extension.
    #[test]
    fn a_non_critical_extension_is_refused() {
        let der = responder_cert(vec![dns_san("example.com")], KEY_AUTH, false);
        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail)) if detail.contains("must be critical")
        ));
    }

    #[test]
    fn a_certificate_without_the_extension_is_refused() {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![dns_san("example.com")];
        let der = params
            .self_signed(&key_pair)
            .unwrap()
            .der()
            .as_ref()
            .to_vec();

        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail))
                if detail.contains("no acmeIdentifier extension")
        ));
    }

    #[test]
    fn the_certificate_must_name_the_identifier_being_validated() {
        let der = responder_cert(vec![dns_san("other.example")], KEY_AUTH, true);
        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail))
                if detail.contains("other.example") && detail.contains("example.com")
        ));
    }

    /// A DNS name is case-insensitive; a responder spelling it differently is
    /// still the same host.
    #[test]
    fn the_dns_name_comparison_ignores_case() {
        let der = responder_cert(vec![dns_san("EXAMPLE.com")], KEY_AUTH, true);
        assert!(verify_acme_identifier(&der, "example.com", KEY_AUTH).is_ok());
    }

    /// RFC 8737 §3 allows exactly one SAN. A second name would ride along on a
    /// proof derived for the first.
    #[test]
    fn extra_subject_alternative_names_are_refused() {
        let der = responder_cert(
            vec![dns_san("example.com"), dns_san("victim.example")],
            KEY_AUTH,
            true,
        );
        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail)) if detail.contains("exactly one dNSName")
        ));

        let with_ip = responder_cert(
            vec![
                dns_san("example.com"),
                SanType::IpAddress("10.0.0.1".parse().unwrap()),
            ],
            KEY_AUTH,
            true,
        );
        assert!(matches!(
            verify_acme_identifier(&with_ip, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(_))
        ));
    }

    #[test]
    fn a_certificate_with_no_subject_alternative_name_is_refused() {
        let key_pair = KeyPair::generate().unwrap();
        let der = CertificateParams::default()
            .self_signed(&key_pair)
            .unwrap()
            .der()
            .as_ref()
            .to_vec();
        assert!(matches!(
            verify_acme_identifier(&der, "example.com", KEY_AUTH),
            Err(ChallengeError::IncorrectResponse(detail))
                if detail.contains("no subject alternative name")
        ));
    }

    #[test]
    fn an_unparsable_certificate_is_a_tls_error() {
        assert!(matches!(
            verify_acme_identifier(&[0xde, 0xad, 0xbe, 0xef], "example.com", KEY_AUTH),
            Err(ChallengeError::Tls(_))
        ));
    }

    #[tokio::test]
    async fn probe_failures_keep_their_kind() {
        let refused = validator(StubProbe {
            outcome: Err("connection refused"),
            tls_error: false,
        });
        assert!(matches!(
            refused.validate(&context("example.com")).await,
            Err(ChallengeError::Connection(_))
        ));

        let alerted = validator(StubProbe {
            outcome: Err("handshake failure"),
            tls_error: true,
        });
        assert!(matches!(
            alerted.validate(&context("example.com")).await,
            Err(ChallengeError::Tls(_))
        ));
    }

    #[test]
    fn reports_its_challenge_type() {
        assert_eq!(
            validator(StubProbe::serving(valid_cert())).typ(),
            "tls-alpn-01"
        );
    }

    /// The TLS client configuration must build with the `ring` provider and
    /// advertise the ALPN it is given, without installing anything globally.
    #[test]
    fn the_client_config_advertises_alpn_without_a_global_provider() {
        let config = accept_any_client_config(&[ACME_TLS_ALPN]).unwrap();
        assert_eq!(config.alpn_protocols, vec![ACME_TLS_ALPN.to_vec()]);
        // Building twice must work: nothing is claimed process-wide.
        let plain = accept_any_client_config(&[]).unwrap();
        assert!(plain.alpn_protocols.is_empty());
    }

    /// The real probe, against a loopback TLS listener.
    ///
    /// This is the test that settles whether `AcceptAnyServerCert` can delegate
    /// its signature checks to `rustls::crypto::verify_tls13_signature`: that
    /// path parses the peer certificate with `rustls-webpki`, which refuses an
    /// unrecognised **critical** extension — and RFC 8737 requires
    /// `id-pe-acmeIdentifier` to be exactly that. A stub certificate never
    /// exercises the handshake, so only a real one can tell us.
    mod loopback {
        use super::*;
        use rustls::ServerConfig;
        use rustls::pki_types::PrivateKeyDer;
        use rustls::server::{ClientHello, ResolvesServerCert};
        use rustls::sign::CertifiedKey;
        use std::net::SocketAddr;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        /// Every test here targets `127.0.0.1` literally, so `resolve_first`
        /// short-circuits before ever asking a resolver anything.
        struct UnreachableResolver;

        #[async_trait]
        impl Resolver for UnreachableResolver {
            async fn reverse(&self, _ip: std::net::IpAddr) -> Result<Vec<String>, String> {
                unreachable!()
            }
            async fn forward(&self, _name: &str) -> Result<Vec<std::net::IpAddr>, String> {
                unreachable!("a literal 127.0.0.1 must short-circuit before this is called")
            }
            async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
                unreachable!()
            }
        }

        fn probe() -> RustlsProbe {
            RustlsProbe::new(Arc::new(UnreachableResolver)).unwrap()
        }

        /// Hands back a fixed certificate without letting rustls vet it.
        ///
        /// `ServerConfig::with_single_cert` runs the chain through
        /// `rustls-webpki`, which refuses the critical `id-pe-acmeIdentifier`
        /// extension outright — a real `tls-alpn-01` responder built on rustls
        /// has to resolve its certificate this way too. That is a constraint on
        /// *responders*, not on this validator, and the point of the test is the
        /// client side.
        #[derive(Debug)]
        struct FixedCert(Arc<CertifiedKey>);

        impl ResolvesServerCert for FixedCert {
            fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(self.0.clone())
            }
        }

        /// Serves one handshake with `der`, advertising `alpn`.
        async fn serve_once(
            der: Vec<u8>,
            key: PrivateKeyDer<'static>,
            alpn: &[&[u8]],
        ) -> SocketAddr {
            let provider = rustls::crypto::ring::default_provider();
            // `CertifiedKey::from_der` re-parses the certificate to check the
            // key matches, and trips on the critical extension exactly as
            // `with_single_cert` does. `new` takes an already-loaded key and
            // asks no questions.
            let signing_key = provider.key_provider.load_private_key(key).unwrap();
            let certified = CertifiedKey::new(vec![CertificateDer::from(der)], signing_key);

            let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified))));
            config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));

            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                // The client reads the certificate and drops the connection, so
                // a handshake error here is expected and uninteresting.
                let _ = acceptor.accept(stream).await;
            });

            address
        }

        /// A responder certificate plus its private key, the way a real client
        /// would present them.
        fn responder(identifier: &str, key_auth: &str) -> (Vec<u8>, PrivateKeyDer<'static>) {
            let key_pair = KeyPair::generate().unwrap();
            let key = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

            let mut params = CertificateParams::default();
            params.subject_alt_names = vec![dns_san(identifier)];
            let hash = digest::digest(&digest::SHA256, key_auth.as_bytes());
            let mut value = vec![0x04, 0x20];
            value.extend_from_slice(hash.as_ref());
            let mut extension = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, value);
            extension.set_criticality(true);
            params.custom_extensions = vec![extension];

            let der = params
                .self_signed(&key_pair)
                .unwrap()
                .der()
                .as_ref()
                .to_vec();
            (der, key)
        }

        /// A full handshake against a conforming responder, end to end. If this
        /// ever fails with `UnsupportedCriticalExtension`, the verifier has been
        /// changed to delegate to webpki — put the assertions back.
        #[tokio::test]
        async fn a_conforming_responder_is_probed_end_to_end() {
            let (der, key) = responder("example.com", KEY_AUTH);
            let address = serve_once(der.clone(), key, &[ACME_TLS_ALPN]).await;

            let leaf = probe()
                .peer_certificate("127.0.0.1", address.port())
                .await
                .expect("the critical acmeIdentifier extension must not break the handshake");

            assert_eq!(leaf, der);
            // And the certificate the handshake returned really is the proof.
            assert!(verify_acme_identifier(&leaf, "example.com", KEY_AUTH).is_ok());
        }

        /// A server serving its ordinary certificate does not negotiate
        /// `acme-tls/1`, and must not be mistaken for a challenge response.
        #[tokio::test]
        async fn a_server_without_the_alpn_protocol_is_a_tls_error() {
            let (der, key) = responder("example.com", KEY_AUTH);
            let address = serve_once(der, key, &[]).await;

            let error = probe()
                .peer_certificate("127.0.0.1", address.port())
                .await
                .unwrap_err();
            assert!(matches!(error, ProbeError::Tls(_)), "{error:?}");
        }

        #[tokio::test]
        async fn a_closed_port_is_a_connect_error() {
            // Bind then drop, so the port is almost certainly free.
            let port = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap().port()
            };
            let error = probe()
                .peer_certificate("127.0.0.1", port)
                .await
                .unwrap_err();
            assert!(matches!(error, ProbeError::Connect(_)), "{error:?}");
        }

        /// SNI is a hostname or an IP literal; an identifier that is neither
        /// is refused before a socket is opened, so a malformed one can never
        /// become a connection attempt somewhere unexpected.
        #[tokio::test]
        async fn an_identifier_that_is_not_a_valid_sni_name_is_refused() {
            let error = probe()
                .peer_certificate("not a hostname", 443)
                .await
                .unwrap_err();
            match error {
                ProbeError::Connect(detail) => {
                    assert!(detail.contains("not a valid SNI name"), "{detail}")
                }
                other => panic!("expected a Connect error, got {other:?}"),
            }
        }

        /// A server that negotiates `acme-tls/1` but presents nothing cannot
        /// be checked. rustls will not complete such a handshake, so this pins
        /// the guard rather than reaching it — see the note on `FixedCert`.
        #[tokio::test]
        async fn from_config_builds_a_real_probe() {
            let validator = TlsAlpn01Validator::from_config(
                &TlsAlpnConfig { port: 8443 },
                Arc::new(UnreachableResolver),
            )
            .expect("the real probe must build");

            // The `Debug` impl is what a startup log shows for this validator.
            let rendered = format!("{validator:?}");
            assert!(rendered.contains("TlsAlpn01Validator"), "{rendered}");
            assert!(rendered.contains("8443"), "{rendered}");
        }
    }

    /// The extension has to wrap exactly a 32-octet digest. A responder that
    /// serves a different length is not answering this challenge, and reading
    /// past it would be comparing arbitrary bytes to a SHA-256 digest.
    #[test]
    fn an_extension_that_is_not_a_32_octet_octet_string_is_refused() {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![dns_san("example.com")];

        // A well-formed OCTET STRING, but only 16 octets long.
        let mut value = vec![0x04, 0x10];
        value.extend_from_slice(&[0xab; 16]);
        let mut extension = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, value);
        extension.set_criticality(true);
        params.custom_extensions = vec![extension];

        let der = params
            .self_signed(&key_pair)
            .unwrap()
            .der()
            .as_ref()
            .to_vec();

        match verify_acme_identifier(&der, "example.com", KEY_AUTH) {
            Err(ChallengeError::IncorrectResponse(detail)) => {
                assert!(detail.contains("32-octet OCTET STRING"), "{detail}")
            }
            other => panic!("expected an IncorrectResponse, got {other:?}"),
        }
    }
}
