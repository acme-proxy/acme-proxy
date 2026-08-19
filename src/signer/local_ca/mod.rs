//! A persistent local certificate authority (backed by `rcgen`).
//!
//! On first run [`LocalCa::load_or_generate`] generates a self-signed CA and
//! writes it to disk (`cert_path`/`key_path`); on later runs it loads those
//! files — mirroring how `sqlite.db` auto-provisions. Operators may also drop in
//! their own PEM files. [`LocalCa::generate_in_memory`] is the disk-free variant
//! used by tests.
//!
//! [`LocalCa::issue`] parses each finalize CSR, checks its DNS SANs match the
//! order, signs a real leaf embedding the CSR's public key, and returns the
//! `leaf + CA` PEM chain.
//!
//! [`LocalCa::revoke`] records a revocation and regenerates a real, CA-signed
//! certificate revocation list (RFC 5280) via `rcgen`'s CRL support; the
//! durable source of truth is a small JSON ledger sidecar next to `crl_path`
//! (`crl_path` with its extension replaced by `.json`), not the CRL's own DER
//! round-tripped back — simpler, and avoids ASN.1 reconstruction edge cases.
//! The CRL file itself is a derived artifact, rebuilt fresh from the ledger on
//! every revocation and on every startup. [`LocalCa::crl_der`] serves the
//! current one; an initial, empty, validly-signed CRL is generated eagerly (at
//! construction, before any revocation ever happens) so it is always fetchable.

mod ca;
mod crl;
pub mod key;
mod policy;

use ca::{generate_ca, random_serial};
use crl::{CrlPaths, RevokedEntry, RevokedLedger, build_crl, init_ledger};
use policy::LeafPolicy;
#[cfg(feature = "hsm")]
pub mod pkcs11;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::CertificateSigningRequestDer;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::cert::cert_serial_and_spki;
use crate::config::{LocalCaConfig, LocalCaSubjectConfig};
use crate::pemfile::{warn_if_key_is_readable, write_private_key};
use crate::signer::{IssueOutcome, RequestedValidity, SignerBackend, SignerError};
use crate::sqlite::order::Identifier;

pub use key::{CaSigningKey, KeySource};

/// A local CA that signs leaf certificates. Holds the issuing key + metadata
/// (as an rcgen [`Issuer`]) and the CA certificate PEM, which is appended to
/// every issued chain.
pub struct LocalCa {
    /// The issuer (owns the signing [`CaSigningKey`]).
    ///
    /// Behind an [`Arc`] so `issue` can hand it to `spawn_blocking`: the
    /// signature itself may be a round trip to a PKCS#11 token — tens to
    /// hundreds of milliseconds — and `rcgen::SigningKey::sign` is a
    /// synchronous call made deep inside `signed_by`, with no way to await
    /// through it. Left on a runtime worker it would stall every other
    /// connection that worker is polling.
    issuer: Arc<Issuer<'static, CaSigningKey>>,
    /// The CA certificate PEM, appended after the leaf to form the chain.
    ca_pem: String,
    /// Issued-leaf validity, in days (backend policy — see the module doc).
    leaf_validity_days: u64,
    /// What an issued leaf says about this CA's own services: where its CRL
    /// and its certificate can be fetched. Validated and DER-encoded once, at
    /// construction — see [`policy`].
    leaf_policy: LeafPolicy,
    /// Revoked-certificate ledger + the current signed CRL derived from it.
    revoked: Mutex<RevokedLedger>,
    /// Where the ledger/CRL are persisted. `None` for [`LocalCa::generate_in_memory`]
    /// (disk-free, tests): the ledger and CRL still work, just in-memory only.
    paths: Option<CrlPaths>,
}

/// Validity of a generated CA certificate, in days (~10 years). rcgen's default
/// is 1975-01-01 → 4096-01-01, a two-millennium root nobody wants.
const CA_VALIDITY_DAYS: i64 = 3653;

/// Backdating applied to every certificate's `not_before`, to tolerate modest
/// clock skew between this server and a verifier.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::hours(1);

/// The leaf validity window to sign, given this CA's policy and what the order
/// asked for (RFC 8555 §7.4's `notBefore`/`notAfter`).
///
/// The request narrows, never widens. §7.4 lets the server decide, and this CA
/// advertises `leaf_validity_days`: honouring an unbounded `notAfter` would let
/// any client holding one authorization mint a certificate outliving the policy
/// its operator configured. So:
///
/// - `notBefore` may only move the start *later* than the default (which is
///   backdated by [`CLOCK_SKEW_ALLOWANCE`]) — a client asking to start earlier
///   is asking to be trusted further back than the CA intends.
/// - `notAfter` may only move the end *earlier*. A shorter certificate is
///   always the client's to choose.
/// - A request that would leave the window empty or inverted is discarded
///   whole, falling back to the policy default rather than signing something
///   no verifier would accept.
fn clamp_leaf_validity(
    now: OffsetDateTime,
    leaf_validity_days: u64,
    requested: RequestedValidity,
) -> (OffsetDateTime, OffsetDateTime) {
    let default_start = now - CLOCK_SKEW_ALLOWANCE;
    let default_end = now + Duration::days(leaf_validity_days as i64);

    if requested.is_empty() {
        return (default_start, default_end);
    }

    let to_time = |seconds: i64| OffsetDateTime::from_unix_timestamp(seconds).ok();

    let start = requested
        .not_before
        .and_then(to_time)
        .filter(|wanted| *wanted > default_start)
        .unwrap_or(default_start);
    let end = requested
        .not_after
        .and_then(to_time)
        .filter(|wanted| *wanted < default_end)
        .unwrap_or(default_end);

    if start >= end {
        warn!(
            event = "local_ca_requested_validity_discarded",
            outcome = "advisory",
            not_before = ?requested.not_before,
            not_after = ?requested.not_after,
            "requested window is empty once clamped to this CA's policy",
        );
        return (default_start, default_end);
    }

    (start, end)
}

impl LocalCa {
    /// Builds the CA described by `cfg`, dispatching on `key_source`.
    ///
    /// The two sources differ in more than where the bytes come from:
    /// `"file"` loads *or generates* the CA, while `"pkcs11"` only ever loads
    /// one — see [`load_pkcs11`](Self::load_pkcs11).
    pub fn load_or_generate(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        match KeySource::parse(&cfg.key_source)? {
            KeySource::File => Self::load_or_generate_from_file(cfg),
            KeySource::Pkcs11 => Self::load_pkcs11(cfg),
        }
    }

    /// Loads the CA from `cert_path`/`key_path` if both exist, otherwise
    /// generates a new one, **persists both files**, and uses it. Also loads
    /// (or, on first run, eagerly creates) the revocation ledger/CRL at
    /// `crl_path`.
    fn load_or_generate_from_file(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        let cert_path = Path::new(&cfg.cert_path);
        let key_path = Path::new(&cfg.key_path);
        let paths = CrlPaths {
            crl_path: PathBuf::from(&cfg.crl_path),
            revoked_path: Path::new(&cfg.crl_path).with_extension("json"),
        };
        // Before either branch touches disk: a URL this CA could not honour is
        // a startup error, not a CA generated and then refused.
        let leaf_policy = LeafPolicy::from_config(cfg)?;

        if cert_path.exists() && key_path.exists() {
            let ca_pem = fs::read_to_string(cert_path)?;
            let key_pem = fs::read_to_string(key_path)?;
            warn_if_key_is_readable("local_ca_key_permissive", key_path);
            let key_pair = KeyPair::from_pem(&key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, CaSigningKey::Software(key_pair))?;
            info!(event = "local_ca_loaded", outcome = "success", cert_path = ?cfg.cert_path);
            return Self::assemble(
                issuer,
                ca_pem,
                cfg.leaf_validity_days,
                leaf_policy,
                Some(paths),
            );
        }

        let (key_pair, ca_pem) = generate_ca(&cfg.key_type, &cfg.subject)?;
        fs::write(cert_path, &ca_pem)?;
        write_private_key(key_path, &key_pair.serialize_pem())?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, CaSigningKey::Software(key_pair))?;
        info!(event = "local_ca_generated", outcome = "success", cert_path = ?cfg.cert_path, key_path = ?cfg.key_path);
        Self::assemble(
            issuer,
            ca_pem,
            cfg.leaf_validity_days,
            leaf_policy,
            Some(paths),
        )
    }

    /// Loads a CA whose issuing key lives on a PKCS#11 token.
    ///
    /// Unlike the file path this **never generates**: the private key is
    /// created out of band (`pkcs11-tool --keypairgen`, `yubico-piv-tool -a
    /// generate`), and this server has no way to produce one that a token
    /// would then hold. So `cert_path` must already exist, and `key_path` is
    /// neither read nor written.
    ///
    /// Before returning, the token key's SubjectPublicKeyInfo is checked
    /// against the CA certificate's. Without that check a typo in `key_label`
    /// resolves to some *other* key on the token, the server starts happily,
    /// and every certificate it issues fails path validation at the client —
    /// a failure that surfaces days later and nowhere near its cause.
    #[cfg(feature = "hsm")]
    fn load_pkcs11(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        let cert_path = Path::new(&cfg.cert_path);
        let paths = CrlPaths {
            crl_path: PathBuf::from(&cfg.crl_path),
            revoked_path: Path::new(&cfg.crl_path).with_extension("json"),
        };
        let leaf_policy = LeafPolicy::from_config(cfg)?;

        if !cert_path.exists() {
            anyhow::bail!(
                "local_ca key_source = \"pkcs11\" requires an existing CA certificate at \
                 `{}`, and does not generate one: the private key lives on the token, so \
                 create the key and its certificate out of band (see the Hardware Keys \
                 page in the documentation) and point cert_path at the result",
                cfg.cert_path
            );
        }

        // `key_type` selects the algorithm of a *generated* key. Nothing is
        // generated here — the algorithm is read off the token — so a value
        // set alongside pkcs11 is doing nothing and should not look like it is.
        if cfg.key_type != LocalCaConfig::default().key_type {
            warn!(
                event = "local_ca_key_type_ignored",
                outcome = "advisory",
                key_type = %cfg.key_type,
                "key_type applies only to a generated key; with key_source = \"pkcs11\" the \
                 algorithm comes from the token",
            );
        }

        let ca_pem = fs::read_to_string(cert_path)?;
        let signing_key = pkcs11::Pkcs11SigningKey::open(cfg)?;

        // The cross-check described above. Both sides are a full DER
        // SubjectPublicKeyInfo, so this compares the algorithm identifier as
        // well as the key itself.
        let ca_der = crate::cert::leaf_der_from_chain(&ca_pem)
            .map_err(|error| anyhow::anyhow!("cert_path `{}`: {error}", cfg.cert_path))?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&ca_der)
            .map_err(|error| anyhow::anyhow!("cert_path `{}`: {error}", cfg.cert_path))?;
        let cert_spki = parsed.tbs_certificate.subject_pki.raw;
        let token_spki = rcgen::PublicKeyData::subject_public_key_info(&signing_key);
        if cert_spki != token_spki.as_slice() {
            anyhow::bail!(
                "the PKCS#11 key `{}` is not the key certified by `{}`: the certificate's \
                 SubjectPublicKeyInfo ({} bytes) does not match the token key's ({} bytes). \
                 Check key_label/key_id, or point cert_path at the certificate belonging to \
                 this key — signing with a mismatched pair would produce certificates that \
                 verify nowhere",
                cfg.pkcs11.key_label,
                cfg.cert_path,
                cert_spki.len(),
                token_spki.len(),
            );
        }

        let issuer = Issuer::from_ca_cert_pem(&ca_pem, CaSigningKey::Pkcs11(signing_key))?;
        info!(
            event = "local_ca_pkcs11_loaded",
            outcome = "success",
            cert_path = ?cfg.cert_path,
            key_label = %cfg.pkcs11.key_label,
        );
        Self::assemble(
            issuer,
            ca_pem,
            cfg.leaf_validity_days,
            leaf_policy,
            Some(paths),
        )
    }

    /// The same entry point in a build without `--features hsm`.
    ///
    /// A startup error naming the feature, never a silent fallback to the file
    /// key: an operator who configured a token and got a software key would
    /// have no indication their CA key is sitting in `ca.key`.
    #[cfg(not(feature = "hsm"))]
    fn load_pkcs11(_cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        anyhow::bail!(
            "local_ca key_source = \"pkcs11\" needs PKCS#11 support, which this binary was \
             built without; rebuild with `cargo build --release --features hsm`"
        )
    }

    /// Generates a CA held only in memory (never written to disk). Used by tests
    /// so the suite stays disk-free — the revocation ledger/CRL work the same
    /// way, just never persisted (`paths: None`).
    pub fn generate_in_memory(key_type: &str, leaf_validity_days: u64) -> anyhow::Result<Self> {
        let (key_pair, ca_pem) = generate_ca(key_type, &LocalCaSubjectConfig::default())?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, CaSigningKey::Software(key_pair))?;
        Self::assemble(
            issuer,
            ca_pem,
            leaf_validity_days,
            LeafPolicy::default(),
            None,
        )
    }

    /// The tail every constructor shares: load or create the revocation
    /// ledger, then wrap everything up. Extracted because it is now reached
    /// from four places, and the `Arc` around the issuer has to be created
    /// after `init_ledger` has borrowed it.
    fn assemble(
        issuer: Issuer<'static, CaSigningKey>,
        ca_pem: String,
        leaf_validity_days: u64,
        leaf_policy: LeafPolicy,
        paths: Option<CrlPaths>,
    ) -> anyhow::Result<Self> {
        let revoked = init_ledger(paths.as_ref(), &issuer)?;
        Ok(Self {
            issuer: Arc::new(issuer),
            ca_pem,
            leaf_validity_days,
            leaf_policy,
            revoked: Mutex::new(revoked),
            paths,
        })
    }
}

/// Refuses a CSR that does not ask for exactly the order's DNS identifiers.
///
/// Defence in depth. `post_finalize` makes the same check before any backend is
/// reached, which is what makes the guarantee hold for the backends that cannot
/// make it themselves (`custom`, `relay`). This one stays because
/// `admin::ops` and `cli::order` call `issue` directly, so a backend has to be
/// safe on its own — and because it is the check that decides what this CA
/// actually signs.
fn check_csr_matches_order(
    csr: &CertificateSigningRequestParams,
    identifiers: &[Identifier],
) -> Result<(), SignerError> {
    // Every SAN must be a DNS name. Without this, the set comparison below
    // only sees `DnsName` entries and an `IpAddress`, `Rfc822Name` or `URI`
    // SAN rides along unexamined into the signed leaf — an order for
    // `example.com` would issue a certificate also valid for, say,
    // `10.0.0.1`. This CA only ever attests DNS identifiers.
    if let Some(other) = csr
        .params
        .subject_alt_names
        .iter()
        .find(|san| !matches!(san, SanType::DnsName(_)))
    {
        warn!(event = "local_ca_csr_non_dns_san", outcome = "failure", san = ?other);
        return Err(SignerError::BadCsr);
    }

    // A wildcard SAN is permitted here *only* because the set comparison
    // below pins it to an order identifier, and `post_new_order` already
    // validated that identifier's shape and refused it unless `dns-01` is
    // enabled — proving control of a whole zone is what `dns-01` is for.
    // Nothing in this backend re-derives that: it signs exactly the names
    // the order authorized, whatever they look like.

    // The CSR must request exactly the order's DNS identifiers.
    let csr_dns: BTreeSet<&str> = csr
        .params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::DnsName(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let want_dns: BTreeSet<&str> = identifiers
        .iter()
        .filter(|id| id.typ == "dns")
        .map(|id| id.value.as_str())
        .collect();
    if csr_dns != want_dns {
        warn!(event = "local_ca_csr_identifier_mismatch", outcome = "failure", csr = ?csr_dns, order = ?want_dns);
        return Err(SignerError::BadCsr);
    }

    Ok(())
}

/// Replaces everything the CSR *asked* to have asserted with this backend's own
/// policy, leaving only the public key and the names checked above.
///
/// Extracted from `issue` because it is the security-critical part of it and it
/// was buried two thirds of the way down a 116-line function, behind the very
/// comment explaining why it matters.
fn sanitize_csr_params(
    params: &mut CertificateParams,
    leaf_policy: &LeafPolicy,
) -> Result<(), SignerError> {
    // Everything the certificate asserts beyond its public key and its names
    // is decided *here*, never by the CSR.
    //
    // `CertificateSigningRequestParams::from_der` copies the CSR's requested
    // extensions verbatim — `basicConstraints` into `params.is_ca` and
    // `keyUsage` into `params.key_usages` — and `signed_by` writes them into
    // the leaf. Left alone, a client holding an authorization for one name
    // could submit a CSR carrying `CA:TRUE` + `keyCertSign` and receive a
    // working intermediate CA chaining to this one, then mint certificates
    // for any name at all. Overwrite the lot with this backend's policy.
    // `NoCa` omits `basicConstraints` altogether, rather than `ExplicitNoCa`
    // which writes `cA: FALSE`. Both deny CA status — RFC 5280 §6.1.4(k)
    // requires the extension to be *present* with `cA: TRUE` before a
    // certificate may sign others, so an absent extension is a refusal — but
    // `cA: FALSE` is the ASN.1 DEFAULT, and DER requires defaults be omitted.
    // rcgen emits it anyway, and strict parsers reject the result: certbot's
    // `cryptography` fails the whole chain with
    // `ParseError { kind: EncodedDefault, location: ["BasicConstraints::ca"] }`.
    // The distinguished name follows the same path as the extensions below:
    // `from_der` copies the one from the CSR into `params` and `signed_by`
    // writes it into the leaf. Without this reset, a CSR bearing
    // `CN=victim.example` next to a perfectly legitimate SAN gets a
    // certificate signed by this CA that *asserts* this name. Verifiers
    // ignore the CN since the replacement of RFC 2818, but a CA must
    // not rely on that. `post_finalize` already refuses a CN foreign to
    // the order; here we only keep the empty subject that goes with names
    // carried by the SAN, where RFC 5280 §4.2.1.6 wants them to be.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.serial_number = Some(random_serial().map_err(|error| {
        error!(event = "local_ca_serial_generation_failed", outcome = "failure", error = %error);
        SignerError::Internal(error.to_string())
    })?);

    // RFC 5280 §4.2.1.1 wants every certificate signed by a CA to name the
    // key that signed it, and RFC 9773 §4.1 *builds on* that: an ARI certID
    // is `base64url(AKI keyIdentifier) "." base64url(serial)`, so without
    // this extension a client cannot construct an identifier for its own
    // certificate at all. rcgen leaves it off by default.
    //
    // The value is not chosen here: `Issuer::from_ca_cert_pem` reads the
    // CA's own SubjectKeyIdentifier off the certificate
    // (`KeyIdMethod::from_x509`), so the AKI written here always equals it —
    // including for a CA generated by an older version of this code.
    params.use_authority_key_identifier_extension = true;

    // Where this CA's CRL and its own certificate can be fetched — both
    // operator-configured, both empty by default, in which case rcgen writes
    // neither extension and the leaf is what it always was.
    //
    // Assignment, not `extend`, for the same reason as everything above it: the
    // contract of this function is that nothing the CSR asked for survives.
    // That is defence in depth rather than a live fix — rcgen's CSR parser
    // already refuses a request carrying either extension outright
    // (`Error::UnsupportedExtension`), so these are provably empty on entry —
    // but the day it learns to parse one, this line is what keeps a client
    // from choosing where relying parties look for revocation data.
    //
    // One trap worth knowing about, three lines up: rcgen decides whether to
    // write the extensions block at all from a disjunction
    // (`CertificateParams::write`) that does **not** mention
    // `crl_distribution_points`. `use_authority_key_identifier_extension = true`
    // above is what keeps that block present today. Remove it and the CRL
    // pointer silently disappears from every leaf — one that still parses and
    // still verifies, so nothing fails except revocation checking, weeks later,
    // at a relying party.
    params.crl_distribution_points = leaf_policy.crl_distribution_points();
    params.custom_extensions = leaf_policy.custom_extensions();

    Ok(())
}

#[async_trait]
impl SignerBackend for LocalCa {
    /// Awaits only the blocking pool: the signature itself is either
    /// microseconds of CPU (a software key) or a round trip to a PKCS#11 token
    /// (tens to hundreds of milliseconds), and the latter must not sit on a
    /// runtime worker. The trait is async for the backends that delegate over
    /// the network.
    #[tracing::instrument(name = "local_ca_issue", skip_all)]
    async fn issue(
        &self,
        _order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        // Parse the PKCS#10 CSR (also verifies its self-signature).
        let der = CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut csr = CertificateSigningRequestParams::from_der(&der).map_err(|error| {
            warn!(event = "local_ca_csr_parse_failed", outcome = "failure", error = %error);
            SignerError::BadCsr
        })?;

        check_csr_matches_order(&csr, identifiers)?;
        sanitize_csr_params(&mut csr.params, &self.leaf_policy)?;

        // The leaf's validity: this backend's policy, narrowed by whatever the
        // order asked for.
        let now = OffsetDateTime::now_utc();
        let (not_before, not_after) = clamp_leaf_validity(now, self.leaf_validity_days, validity);
        csr.params.not_before = not_before;
        csr.params.not_after = not_after;

        // Sign the leaf (preserving the CSR's public key) and return leaf + CA.
        //
        // On the blocking pool unconditionally, rather than only for a token
        // key. `rcgen::SigningKey::sign` is synchronous and called from deep
        // inside `signed_by`, so there is nothing to await through; a branch on
        // the key kind here would be one more thing to get wrong, and a
        // `spawn_blocking` dispatch is microseconds against a finalize request
        // that already does a database transaction and a TLS handshake.
        let issuer = self.issuer.clone();
        let leaf = tokio::task::spawn_blocking(move || csr.signed_by(&issuer))
            .await
            .map_err(|error| {
                error!(event = "local_ca_leaf_signing_panicked", outcome = "failure", error = %error);
                SignerError::Internal(format!("leaf signing panicked: {error}"))
            })?
            .map_err(|error| {
                error!(event = "local_ca_leaf_signing_failed", outcome = "failure", error = %error);
                SignerError::Internal(error.to_string())
            })?;
        info!(event = "local_ca_leaf_issued", outcome = "success", dns = ?identifiers.iter().map(|i| i.value.as_str()).collect::<Vec<_>>());
        Ok(IssueOutcome::Issued(format!(
            "{}{}",
            leaf.pem(),
            self.ca_pem
        )))
    }

    /// Records `cert_der`'s serial as revoked and regenerates the CRL.
    /// Idempotent: revoking an already-revoked serial is a no-op, since a
    /// caller (the ACME handler, or the admin CLI after a partial-failure
    /// retry) may call this twice for the same certificate.
    #[tracing::instrument(name = "local_ca_revoke", skip_all)]
    async fn revoke(&self, cert_der: &[u8], reason: Option<u32>) -> Result<(), SignerError> {
        let (serial_hex, _) = cert_serial_and_spki(cert_der)
            .map_err(|error| SignerError::Internal(format!("unparsable certificate: {error}")))?;

        // A `tokio::sync::Mutex`, so the whole read-modify-write-persist
        // sequence is one critical section even though it now awaits in the
        // middle. With a `std::sync::Mutex` the guard could not be held across
        // the `spawn_blocking` below at all, and two concurrent revocations
        // could interleave: both read the ledger, both append their own serial,
        // and the second write drops the first.
        let mut ledger = self.revoked.lock().await;
        if ledger.entries.iter().any(|e| e.serial_hex == serial_hex) {
            return Ok(());
        }
        ledger.entries.push(RevokedEntry {
            serial_hex: serial_hex.clone(),
            revoked_at: OffsetDateTime::now_utc().unix_timestamp(),
            reason,
        });

        let ledger_json = serde_json::to_string(&ledger.entries)
            .map_err(|error| SignerError::Internal(error.to_string()))?;
        // Cloned rather than borrowed: the closure below outlives this scope as
        // far as the compiler is concerned, and a ledger is a handful of short
        // strings — nothing next to signing a CRL.
        let entries = ledger.entries.clone();
        let issuer = self.issuer.clone();
        let paths = self.paths.clone();

        // Signing the CRL and the two file writes, all off the runtime worker.
        //
        // The writes were already here; `build_crl` was not, and it is the part
        // that signs — with a PKCS#11 key that is a token round trip, which has
        // no business happening on a thread expected to poll every other
        // connection meanwhile. The file writes are short, but they are still
        // blocking syscalls.
        let crl_der = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let crl = build_crl(&entries, &issuer)?;
            let crl_der = crl.der().to_vec();

            if let Some(paths) = &paths {
                let crl_pem = crl.pem()?;
                // The ledger before the CRL: the ledger is the authoritative
                // record and the CRL is derived from it at every startup, so a
                // crash between the two loses nothing.
                //
                // `0600` on the ledger — it decides what the CRL says, and it
                // is not public material the way the CRL itself is.
                crate::pemfile::write_atomic(&paths.revoked_path, ledger_json.as_bytes(), 0o600)?;
                crate::pemfile::write_atomic(&paths.crl_path, crl_pem.as_bytes(), 0o644)?;
            }
            Ok(crl_der)
        })
        .await
        .map_err(|error| SignerError::Internal(format!("revocation persist panicked: {error}")))?
        .map_err(|error| SignerError::Internal(error.to_string()))?;

        // Only after the write succeeded: a revocation this process believes in
        // but never persisted would vanish at the next restart, and `revoke`
        // reporting an error while having already updated the served CRL is the
        // more confusing half of that.
        ledger.crl_der = crl_der;

        info!(event = "local_ca_certificate_revoked", outcome = "success", cert_serial = ?serial_hex);
        Ok(())
    }

    async fn crl_der(&self) -> Option<Vec<u8>> {
        Some(self.revoked.lock().await.crl_der.clone())
    }

    /// This CA's own certificate — the anchor, and the whole chain, since a
    /// `LocalCa` is a single self-signed root with `pathLenConstraint: 0` and
    /// there is nothing between it and a leaf.
    ///
    /// The same string `issue` appends to every leaf it signs, so what a client
    /// installs from `/ca.pem` is byte-identical to what it already received in
    /// its certificate chain.
    async fn ca_chain_pem(&self) -> Option<String> {
        Some(self.ca_pem.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::ca::DEFAULT_CA_COMMON_NAME;
    use super::crl::reason_from_u32;
    use super::*;
    use base64::prelude::Engine as _;
    use rcgen::BasicConstraints;

    /// [`LocalCa::issue`] with the PEM chain unwrapped out of its
    /// [`IssueOutcome`]. This backend is synchronous by construction — it never
    /// returns `Processing` — so every test below wants the chain, not the
    /// enum, and none of them care about the `order_id` `LocalCa` ignores.
    async fn issue_chain(
        ca: &LocalCa,
        csr_der: &[u8],
        identifiers: &[Identifier],
    ) -> Result<String, SignerError> {
        issue_chain_with(ca, csr_der, identifiers, RequestedValidity::default()).await
    }

    /// [`issue_chain`] with an explicit requested validity window, for the tests
    /// that care what `LocalCa` does with one.
    async fn issue_chain_with(
        ca: &LocalCa,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<String, SignerError> {
        match ca.issue("ord-test", csr_der, identifiers, validity).await? {
            IssueOutcome::Issued(chain) => Ok(chain),
            IssueOutcome::Processing => panic!("local_ca must always issue synchronously"),
        }
    }

    /// Decodes a single PEM certificate block to DER.
    fn pem_to_der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .skip_while(|line| !line.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|line| !line.starts_with("-----END CERTIFICATE-----"))
            .collect();
        base64::prelude::BASE64_STANDARD
            .decode(body)
            .expect("PEM body must be base64")
    }

    /// The leaf out of a `leaf + CA` chain, as DER.
    fn first_certificate(chain: &str) -> Vec<u8> {
        pem_to_der(chain)
    }

    /// Builds a real CSR for `name` and returns its DER bytes.
    fn make_csr_der(name: &str) -> Vec<u8> {
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        csr.der().to_vec()
    }

    #[test]
    fn the_default_ca_subject_is_common_name_only() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let ca_der = crate::cert::leaf_der_from_chain(&ca.ca_pem).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        let subject = ca_cert.subject();
        let cn = subject
            .iter_common_name()
            .next()
            .expect("CA must carry a CommonName")
            .as_str()
            .unwrap();
        assert_eq!(cn, DEFAULT_CA_COMMON_NAME);

        assert!(subject.iter_organization().next().is_none());
        assert!(subject.iter_organizational_unit().next().is_none());
        assert!(subject.iter_country().next().is_none());
        assert!(subject.iter_state_or_province().next().is_none());
        assert!(subject.iter_locality().next().is_none());
    }

    #[test]
    fn a_fully_custom_subject_is_carried_onto_the_generated_ca() {
        let subject = LocalCaSubjectConfig {
            common_name: Some("Custom Root CA".to_string()),
            organization: Some("Example Corp".to_string()),
            organizational_unit: Some("IT".to_string()),
            country: Some("US".to_string()),
            state: Some("California".to_string()),
            locality: Some("San Francisco".to_string()),
        };
        let (_key_pair, ca_pem) = generate_ca("ecdsa-p256", &subject).unwrap();
        let ca_der = crate::cert::leaf_der_from_chain(&ca_pem).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        let s = ca_cert.subject();
        assert_eq!(
            s.iter_common_name().next().unwrap().as_str().unwrap(),
            "Custom Root CA"
        );
        assert_eq!(
            s.iter_organization().next().unwrap().as_str().unwrap(),
            "Example Corp"
        );
        assert_eq!(
            s.iter_organizational_unit()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "IT"
        );
        assert_eq!(s.iter_country().next().unwrap().as_str().unwrap(), "US");
        assert_eq!(
            s.iter_state_or_province().next().unwrap().as_str().unwrap(),
            "California"
        );
        assert_eq!(
            s.iter_locality().next().unwrap().as_str().unwrap(),
            "San Francisco"
        );
    }

    /// `config`'s env-var source can't distinguish an explicitly empty
    /// string from an absent value, so an empty `common_name` must fall back
    /// to the default exactly as an unset one does.
    #[test]
    fn an_empty_string_common_name_falls_back_to_the_default() {
        let subject = LocalCaSubjectConfig {
            common_name: Some(String::new()),
            ..Default::default()
        };
        let (_key_pair, ca_pem) = generate_ca("ecdsa-p256", &subject).unwrap();
        let ca_der = crate::cert::leaf_der_from_chain(&ca_pem).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        let cn = ca_cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, DEFAULT_CA_COMMON_NAME);
    }

    /// Proves the config actually reaches the *persisted* CA, not just the
    /// `generate_ca` helper in isolation — the real entrypoint operators use.
    #[test]
    fn load_or_generate_applies_a_configured_subject() {
        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            subject: LocalCaSubjectConfig {
                organization: Some("Example Corp".to_string()),
                ..Default::default()
            },
            ..LocalCaConfig::default()
        };

        let ca = LocalCa::load_or_generate(&cfg).unwrap();
        let ca_der = crate::cert::leaf_der_from_chain(&ca.ca_pem).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        let org = ca_cert
            .subject()
            .iter_organization()
            .next()
            .expect("the configured organization must be on the persisted CA")
            .as_str()
            .unwrap();
        assert_eq!(org, "Example Corp");
    }

    #[tokio::test]
    async fn issue_produces_a_two_cert_chain() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();

        // The chain is leaf + CA: two PEM certificate blocks.
        let count = chain.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(count, 2, "expected leaf + CA in the chain");
        assert!(chain.ends_with(ca.ca_pem.as_str()) || chain.contains(ca.ca_pem.as_str()));
    }

    /// RFC 5280 §4.2.1.1 wants the extension; RFC 9773 §4.1 makes it
    /// load-bearing, since an ARI certID *is* the AKI plus the serial. It must
    /// equal the CA's own SubjectKeyIdentifier, or the identifier a client
    /// builds names an issuer nobody recognizes.
    #[tokio::test]
    async fn an_issued_leaf_carries_the_cas_key_identifier() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;

        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();

        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (aki, _serial) = crate::cert::ari_cert_id_parts(&leaf_der)
            .expect("an issued leaf must carry an Authority Key Identifier");

        // The CA's own Subject Key Identifier, read off its certificate.
        let ca_der = crate::cert::leaf_der_from_chain(&ca.ca_pem).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        let ski_ext = ca_cert
            .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .unwrap()
            .expect("the CA carries a Subject Key Identifier");
        let ParsedExtension::SubjectKeyIdentifier(ski) = ski_ext.parsed_extension() else {
            panic!("SubjectKeyIdentifier could not be parsed");
        };

        assert_eq!(
            aki,
            ski.0.to_vec(),
            "the leaf's AKI must name the key that signed it"
        );

        // …and the whole certID round-trips, which is what a client actually
        // builds and this server then has to recognize.
        assert!(crate::cert::ari_cert_id(&leaf_der).is_ok());
    }

    /// Goes through `load_or_generate` rather than handing a policy to a
    /// constructor: the point is that `LocalCaConfig` → `LeafPolicy` →
    /// `assemble` → `issue` is genuinely wired, which a policy passed in
    /// directly would not prove.
    #[tokio::test]
    async fn configured_urls_reach_every_issued_leaf() {
        use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
        use x509_parser::oid_registry::{
            OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_PKIX_AUTHORITY_INFO_ACCESS,
            OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
        };

        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            crl_distribution_points: vec![
                "http://ca.example/ca.crl".to_string(),
                "http://mirror.example/ca.crl".to_string(),
            ],
            ca_issuer_urls: vec!["http://ca.example/ca.crt".to_string()],
            ..LocalCaConfig::default()
        };

        let ca = LocalCa::load_or_generate(&cfg).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();

        let cdp = leaf
            .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            .unwrap()
            .expect("the leaf must name where the CRL lives");
        let ParsedExtension::CRLDistributionPoints(points) = cdp.parsed_extension() else {
            panic!("cRLDistributionPoints could not be parsed");
        };
        assert_eq!(
            points.points.len(),
            1,
            "both URLs serve the same CRL, so they belong to one distribution point"
        );
        let Some(DistributionPointName::FullName(names)) = &points.points[0].distribution_point
        else {
            panic!("expected a full name");
        };
        let uris: Vec<&str> = names
            .iter()
            .map(|name| match name {
                GeneralName::URI(uri) => *uri,
                other => panic!("expected a URI, got {other:?}"),
            })
            .collect();
        assert_eq!(
            uris,
            vec!["http://ca.example/ca.crl", "http://mirror.example/ca.crl"]
        );

        let aia = leaf
            .get_extension_unique(&OID_PKIX_AUTHORITY_INFO_ACCESS)
            .unwrap()
            .expect("the leaf must name where this CA's own certificate lives");
        assert!(
            !aia.critical,
            "RFC 5280 §4.2.2.1 requires authorityInfoAccess to be non-critical"
        );
        let ParsedExtension::AuthorityInfoAccess(access) = aia.parsed_extension() else {
            panic!("authorityInfoAccess could not be parsed");
        };
        assert_eq!(access.accessdescs.len(), 1);
        assert_eq!(
            access.accessdescs[0].access_method, OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS,
            "only caIssuers is ever written — this server runs no OCSP responder"
        );
        assert!(matches!(
            access.accessdescs[0].access_location,
            GeneralName::URI("http://ca.example/ca.crt")
        ));
    }

    /// The regression that keeps the default harmless: with neither key
    /// configured, a leaf is exactly what this CA issued before they existed.
    #[tokio::test]
    async fn an_unconfigured_ca_writes_neither_pointer_extension() {
        use x509_parser::oid_registry::{
            OID_PKIX_AUTHORITY_INFO_ACCESS, OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
        };

        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();

        assert!(
            leaf.get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
                .unwrap()
                .is_none()
        );
        assert!(
            leaf.get_extension_unique(&OID_PKIX_AUTHORITY_INFO_ACCESS)
                .unwrap()
                .is_none(),
            "an empty ca_issuer_urls must emit no extension, not an empty SEQUENCE"
        );
    }

    /// RFC 8555 §7.4's `notBefore`/`notAfter` narrow this CA's own window and
    /// never widen it: the order object echoes them back, so dropping them
    /// entirely (as this backend used to) made that echo a fiction — but
    /// honouring an unbounded `notAfter` would let any client outlive the
    /// `leaf_validity_days` its operator configured.
    #[test]
    fn a_requested_validity_narrows_but_never_widens_the_window() {
        let now = OffsetDateTime::now_utc();
        let default_start = now - CLOCK_SKEW_ALLOWANCE;
        let default_end = now + Duration::days(90);

        // Nothing requested: the policy window, unchanged.
        let (start, end) = clamp_leaf_validity(now, 90, RequestedValidity::default());
        assert_eq!((start, end), (default_start, default_end));

        // A shorter certificate is the client's to choose.
        let wanted_end = now + Duration::days(30);
        let (start, end) = clamp_leaf_validity(
            now,
            90,
            RequestedValidity {
                not_before: None,
                not_after: Some(wanted_end.unix_timestamp()),
            },
        );
        assert_eq!(start, default_start);
        assert_eq!(end.unix_timestamp(), wanted_end.unix_timestamp());

        // A longer one is not.
        let (_, end) = clamp_leaf_validity(
            now,
            90,
            RequestedValidity {
                not_before: None,
                not_after: Some((now + Duration::days(3650)).unix_timestamp()),
            },
        );
        assert_eq!(end, default_end, "a client must not outlive the policy");

        // Starting later is fine; starting earlier than the CA intends is not.
        let wanted_start = now + Duration::days(1);
        let (start, _) = clamp_leaf_validity(
            now,
            90,
            RequestedValidity {
                not_before: Some(wanted_start.unix_timestamp()),
                not_after: None,
            },
        );
        assert_eq!(start.unix_timestamp(), wanted_start.unix_timestamp());

        let (start, _) = clamp_leaf_validity(
            now,
            90,
            RequestedValidity {
                not_before: Some((now - Duration::days(365)).unix_timestamp()),
                not_after: None,
            },
        );
        assert_eq!(
            start, default_start,
            "backdating further than CLOCK_SKEW_ALLOWANCE is the CA's call, not the client's"
        );

        // An inverted request is discarded whole rather than signed.
        let (start, end) = clamp_leaf_validity(
            now,
            90,
            RequestedValidity {
                not_before: Some((now + Duration::days(60)).unix_timestamp()),
                not_after: Some((now + Duration::days(30)).unix_timestamp()),
            },
        );
        assert_eq!((start, end), (default_start, default_end));
    }

    /// The end-to-end half of the above: the window actually reaches the signed
    /// certificate, which is the property that was missing.
    #[tokio::test]
    async fn a_requested_not_after_shortens_the_issued_certificate() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let wanted_end = OffsetDateTime::now_utc() + Duration::days(7);

        let chain = issue_chain_with(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
            RequestedValidity {
                not_before: None,
                not_after: Some(wanted_end.unix_timestamp()),
            },
        )
        .await
        .unwrap();

        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (_, not_after) = crate::cert::cert_validity(&leaf_der).unwrap();

        // X.509 stores seconds, so compare at that resolution.
        assert_eq!(not_after, wanted_end.unix_timestamp());
    }

    #[tokio::test]
    async fn issue_rejects_identifier_mismatch() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        // CSR is for a.example but the order says b.example.
        let result = issue_chain(
            &ca,
            &make_csr_der("a.example"),
            &[Identifier::dns("b.example")],
        )
        .await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    /// A CSR whose DNS SANs match the order exactly, but which smuggles an IP
    /// address alongside them, must not be signed: the set comparison ignores
    /// non-DNS SANs, so only the explicit type check stops the leaf being valid
    /// for an address nobody authorized.
    #[tokio::test]
    async fn issue_rejects_a_non_dns_san() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(SanType::IpAddress("10.0.0.1".parse().unwrap()));
        let csr = params.serialize_request(&key_pair).unwrap();

        let result = issue_chain(&ca, csr.der(), &[Identifier::dns("example.com")]).await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    #[tokio::test]
    async fn issue_rejects_an_email_san() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.subject_alt_names.push(SanType::Rfc822Name(
            "someone@example.com".try_into().unwrap(),
        ));
        let csr = params.serialize_request(&key_pair).unwrap();

        let result = issue_chain(&ca, csr.der(), &[Identifier::dns("example.com")]).await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    /// The escalation this backend exists to prevent.
    ///
    /// rcgen's CSR parser copies the requested `basicConstraints` and `keyUsage`
    /// extensions into `params`, and `signed_by` writes whatever is there into
    /// the leaf. A client authorized for one name could therefore ask to be a
    /// CA and receive a working intermediate chaining to this one — enough to
    /// mint certificates for every other name. `issue` must overwrite both.
    #[tokio::test]
    async fn issue_refuses_to_grant_ca_powers_a_csr_asks_for() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let csr = params.serialize_request(&key_pair).unwrap();

        // The request itself is well-formed and its name matches the order, so
        // it is signed — but on the CA's terms, not the client's.
        let chain = issue_chain(&ca, csr.der(), &[Identifier::dns("example.com")])
            .await
            .expect("a CSR with a matching name is still signed");

        let leaf = first_certificate(&chain);
        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();

        // The leaf must not claim CA status. `issue` denies it by omitting
        // `basicConstraints` entirely (see the comment there for why not
        // `cA: FALSE`), and RFC 5280 §6.1.4(k) makes an absent extension a
        // refusal: a path validator requires it present with `cA: TRUE`. Accept
        // either shape here, so the test pins the *property* rather than the
        // encoding choice.
        match parsed.basic_constraints().unwrap() {
            None => {}
            Some(bc) => assert!(
                !bc.value.ca,
                "leaf must not be a CA even though the CSR asked to be one"
            ),
        }

        let key_usage = parsed
            .key_usage()
            .unwrap()
            .expect("leaf must carry keyUsage");
        assert!(
            !key_usage.value.key_cert_sign(),
            "leaf must not be allowed to sign certificates"
        );
        assert!(
            !key_usage.value.crl_sign(),
            "leaf must not be allowed to sign CRLs"
        );
        assert!(key_usage.value.digital_signature());
    }

    /// Every certificate in the chain must be **strictly DER**, not merely
    /// BER-parseable.
    ///
    /// This is not pedantry: certbot's `cryptography` refuses a chain whose
    /// `basicConstraints` encodes the `cA` DEFAULT explicitly, failing with
    /// `ParseError { kind: EncodedDefault }`. rcgen's `IsCa::ExplicitNoCa` emits
    /// exactly that, so choosing it here — the obvious way to say "not a CA" —
    /// broke real clients while every unit test still passed. `x509-parser`'s
    /// `parse_x509_certificate` is lenient, hence the explicit re-encoding check.
    #[tokio::test]
    async fn the_issued_chain_is_strictly_der_encoded() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();

        for (which, der) in [
            ("leaf", first_certificate(&chain)),
            ("ca", pem_to_der(&ca.ca_pem)),
        ] {
            let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();

            // A `cA: FALSE` that is present at all is the DEFAULT written out,
            // which DER forbids. Either omit the extension or set `cA: TRUE`.
            if let Some(bc) = parsed.basic_constraints().unwrap() {
                assert!(
                    bc.value.ca,
                    "{which}: basicConstraints encodes the cA DEFAULT (cA: FALSE); \
                     omit the extension instead — strict parsers reject this"
                );
            }
        }
    }

    /// The CA is `pathLenConstraint: 0`, so even a leaked sub-CA cannot issue
    /// beneath it.
    #[tokio::test]
    async fn the_ca_cannot_have_intermediates_below_it() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let ca_der = pem_to_der(&ca.ca_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        let basic_constraints = parsed.basic_constraints().unwrap().unwrap();
        assert!(basic_constraints.value.ca);
        assert_eq!(basic_constraints.value.path_len_constraint, Some(0));
    }

    /// Two certificates for the same name *and the same key* — the ordinary
    /// renewal — must not share a serial. rcgen's fallback derives the serial
    /// from the public key alone, so without an explicit one these would
    /// collide, which RFC 5280 §4.1.2.2 forbids and which would make any future
    /// revocation ambiguous.
    #[tokio::test]
    async fn renewing_with_the_same_key_produces_a_different_serial() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();

        // One key pair, two separate issuances.
        let key_pair = KeyPair::generate().unwrap();
        let mut serials = Vec::new();
        for _ in 0..2 {
            let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
            let csr = params.serialize_request(&key_pair).unwrap();
            let chain = issue_chain(&ca, csr.der(), &[Identifier::dns("example.com")])
                .await
                .unwrap();
            let leaf = first_certificate(&chain);
            let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
            serials.push(parsed.raw_serial().to_vec());
        }

        assert_ne!(
            serials[0], serials[1],
            "two issuances must not share a serial number"
        );
    }

    /// A wildcard the order actually authorized is signed. Whether the order
    /// should ever have carried it is decided upstream, in `post_new_order`,
    /// which requires `dns-01` to be enabled.
    #[tokio::test]
    async fn issue_accepts_a_wildcard_san_matching_the_order() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("*.example.com"),
            &[Identifier::dns("*.example.com")],
        )
        .await
        .expect("a wildcard the order authorized must be signed");
        assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);

        let leaf = pem_to_der(&chain);
        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        let sans = parsed
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .clone();
        assert_eq!(sans.len(), 1);
        assert!(
            matches!(&sans[0], x509_parser::extensions::GeneralName::DNSName(name)
                if *name == "*.example.com"),
            "{sans:?}"
        );
    }

    /// The dangerous direction: an order for one host must not yield a
    /// certificate covering its whole zone. The set comparison is what stops it.
    #[tokio::test]
    async fn issue_rejects_a_wildcard_csr_for_a_non_wildcard_order() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let result = issue_chain(
            &ca,
            &make_csr_der("*.example.com"),
            &[Identifier::dns("example.com")],
        )
        .await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    /// And the reverse: a wildcard order does not licence some other name.
    #[tokio::test]
    async fn issue_rejects_a_wildcard_san_not_in_the_order() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let result = issue_chain(
            &ca,
            &make_csr_der("*.other.example"),
            &[Identifier::dns("*.example.com")],
        )
        .await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    /// The generated CA must not inherit rcgen's 1975 → 4096 default window.
    #[test]
    fn the_generated_ca_has_a_sane_validity_window() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let ca_der = pem_to_der(&ca.ca_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        let now = OffsetDateTime::now_utc();
        let not_after = parsed.validity().not_after.to_datetime();
        let not_before = parsed.validity().not_before.to_datetime();

        assert!(not_before < now, "CA should already be valid");
        assert!(now < not_after, "CA should not have expired");
        // Comfortably inside rcgen's default, which would run to the year 4096.
        assert!(
            not_after < now + Duration::days(CA_VALIDITY_DAYS + 1),
            "CA validity should be the configured window, not rcgen's default"
        );
    }

    #[tokio::test]
    async fn issue_rejects_garbage_csr() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let result = issue_chain(
            &ca,
            &[0xde, 0xad, 0xbe, 0xef],
            &[Identifier::dns("example.com")],
        )
        .await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    #[test]
    fn unsupported_key_type_errors() {
        assert!(LocalCa::generate_in_memory("rsa-4096", 90).is_err());
    }

    #[tokio::test]
    async fn load_or_generate_persists_then_reloads() {
        // A unique temp dir so the generate-then-load branches both run.
        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            ..LocalCaConfig::default()
        };

        // First call generates and writes both files.
        let first = LocalCa::load_or_generate(&cfg).unwrap();
        assert!(Path::new(&cfg.cert_path).exists());
        assert!(Path::new(&cfg.key_path).exists());

        // The private key must be owner-only (0600), never world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&cfg.key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "CA key must be 0600");
        }

        // Second call loads the *same* CA (identical certificate PEM).
        let second = LocalCa::load_or_generate(&cfg).unwrap();
        assert_eq!(first.ca_pem, second.ca_pem);

        // The reloaded CA can still issue.
        let chain = issue_chain(
            &second,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }

    /// Parses `der` as a CRL and returns the hex-encoded serials it lists as
    /// revoked.
    fn revoked_serials(der: &[u8]) -> Vec<String> {
        use x509_parser::prelude::FromDer;
        use x509_parser::revocation_list::CertificateRevocationList;

        let (_, crl) = CertificateRevocationList::from_der(der).unwrap();
        crl.iter_revoked_certificates()
            .map(|r| r.raw_serial_as_string().replace(':', ""))
            .collect()
    }

    #[tokio::test]
    async fn an_empty_crl_is_served_before_any_revocation() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let der = ca.crl_der().await.expect("LocalCa always has a CRL");
        assert!(revoked_serials(&der).is_empty());
    }

    #[tokio::test]
    async fn revoke_marks_serial_and_appears_in_the_crl() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf = first_certificate(&chain);
        let (serial_hex, _) = crate::cert::cert_serial_and_spki(&leaf).unwrap();

        ca.revoke(&leaf, Some(1)).await.unwrap();

        let der = ca.crl_der().await.unwrap();
        let serials = revoked_serials(&der);
        assert!(
            serials.iter().any(|s| s.eq_ignore_ascii_case(&serial_hex)),
            "expected {serial_hex} in {serials:?}"
        );
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf = first_certificate(&chain);

        ca.revoke(&leaf, Some(1)).await.unwrap();
        ca.revoke(&leaf, Some(1)).await.unwrap();

        let der = ca.crl_der().await.unwrap();
        assert_eq!(revoked_serials(&der).len(), 1);
    }

    #[tokio::test]
    async fn revoke_of_unparsable_der_is_internal_error() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let result = ca.revoke(&[0xde, 0xad, 0xbe, 0xef], None).await;
        assert!(matches!(result, Err(SignerError::Internal(_))));
    }

    #[tokio::test]
    async fn revoking_a_certificate_does_not_block_reissuing_the_same_name() {
        let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf = first_certificate(&chain);
        ca.revoke(&leaf, None).await.unwrap();

        // Issuance and revocation are orthogonal: a revoked name can still be
        // reissued (that's a policy call for something else to make, not this
        // backend's job).
        let reissued = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await;
        assert!(reissued.is_ok());
    }

    #[tokio::test]
    async fn load_or_generate_persists_revocations_across_reload() {
        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            ..LocalCaConfig::default()
        };

        let first = LocalCa::load_or_generate(&cfg).unwrap();
        let chain = issue_chain(
            &first,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        let leaf = first_certificate(&chain);
        let (serial_hex, _) = crate::cert::cert_serial_and_spki(&leaf).unwrap();
        first.revoke(&leaf, Some(1)).await.unwrap();

        // A fresh `LocalCa` built from the same paths must still know about
        // the revocation — proving the ledger sidecar file, not just the
        // in-memory ledger, is what makes this durable.
        let reloaded = LocalCa::load_or_generate(&cfg).unwrap();
        let der = reloaded.crl_der().await.unwrap();
        let serials = revoked_serials(&der);
        assert!(
            serials.iter().any(|s| s.eq_ignore_ascii_case(&serial_hex)),
            "expected {serial_hex} in {serials:?}"
        );
    }

    /// A corrupted ledger sidecar is a startup *error* naming the file, not a
    /// panic.
    ///
    /// `build_crl` used to `expect` that every stored serial was hex. The
    /// sidecar is an ordinary JSON file an operator can edit or a crash can
    /// truncate, and `revoke` calls `build_crl` too — so this was not merely a
    /// boot panic but a panic in a request task, which would poison the ledger
    /// mutex and turn every later `GET /crl` into a panic of its own.
    #[tokio::test]
    async fn a_corrupted_ledger_is_reported_rather_than_panicking() {
        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            ..LocalCaConfig::default()
        };

        // Build once so the CA material exists, then hand-edit the ledger the
        // way a bad merge or a half-written file would.
        LocalCa::load_or_generate(&cfg).unwrap();
        fs::write(
            dir.join("ca.json"),
            r#"[{"serial_hex":"not hex at all","revoked_at":0,"reason":null}]"#,
        )
        .unwrap();

        let error = match LocalCa::load_or_generate(&cfg) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a non-hex serial must not start the server"),
        };
        assert!(error.contains("not hex"), "{error}");
        assert!(
            error.contains("entry 0"),
            "the message must name the offending entry: {error}"
        );
    }

    /// The revocation ledger is owner-only: it decides what the CRL says, so a
    /// local user able to rewrite it could un-revoke a certificate at the next
    /// restart. The CRL beside it is published material and stays readable.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_ledger_is_owner_only_and_the_crl_is_not() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::testutil::TempDir::new("ca");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            key_type: "ecdsa-p256".to_string(),
            leaf_validity_days: 90,
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            ..LocalCaConfig::default()
        };

        let ca = LocalCa::load_or_generate(&cfg).unwrap();
        let chain = issue_chain(
            &ca,
            &make_csr_der("example.com"),
            &[Identifier::dns("example.com")],
        )
        .await
        .unwrap();
        ca.revoke(&first_certificate(&chain), Some(1))
            .await
            .unwrap();

        let ledger_mode = fs::metadata(dir.join("ca.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(ledger_mode, 0o600, "the ledger must be owner-only");

        let crl_mode = fs::metadata(dir.join("ca.crl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(crl_mode, 0o644, "the CRL is served to anyone");
    }

    /// Every `CRLReason` this server accepts maps to an rcgen reason, and the
    /// two RFC 5280 gaps (7 and 11) plus anything out of range map to `None` —
    /// "revoke, but record no reason", never a refusal to revoke.
    #[test]
    fn every_accepted_reason_code_maps_to_a_crl_reason() {
        use rcgen::RevocationReason as R;

        let expected = [
            (0, Some(R::Unspecified)),
            (1, Some(R::KeyCompromise)),
            (2, Some(R::CaCompromise)),
            (3, Some(R::AffiliationChanged)),
            (4, Some(R::Superseded)),
            (5, Some(R::CessationOfOperation)),
            (6, Some(R::CertificateHold)),
            (8, Some(R::RemoveFromCrl)),
            (9, Some(R::PrivilegeWithdrawn)),
            (10, Some(R::AaCompromise)),
        ];
        for (code, wanted) in expected {
            assert_eq!(reason_from_u32(code), wanted, "code {code}");
            assert!(
                crate::cert::is_valid_revocation_reason(code),
                "code {code} must also be accepted at the ACME edge"
            );
        }

        // 7 and 11 are unassigned in RFC 5280 §5.3.1; 99 is simply out of range.
        for code in [7, 11, 99] {
            assert_eq!(reason_from_u32(code), None, "code {code}");
        }
    }
}
