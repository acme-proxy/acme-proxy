//! A local-CA issuing key held on a PKCS#11 token.
//!
//! Compiled only with `--features hsm`. [`Pkcs11SigningKey`] implements
//! `rcgen::SigningKey`, so [`LocalCa`](super::LocalCa) signs leaves and CRLs
//! through it without knowing the private key is on the other end of a USB
//! cable or a network HSM — see [`super::key`] for why that seam is rcgen's
//! own trait rather than one invented here.
//!
//! PKCS#11 rather than a vendor PIV library: a YubiKey via `libykcs11` and a
//! Thales/Entrust/SoftHSM token are then the same code path.
//!
//! ## Four things that are easy to get wrong here
//!
//! 1. **Signature encoding.** rcgen's `PKCS_ECDSA_P256_SHA256` is ring's
//!    `ECDSA_P256_SHA256_ASN1_SIGNING`, so `sign` must return a DER
//!    `SEQUENCE { r INTEGER, s INTEGER }`. PKCS#11 returns raw fixed-width
//!    `r ‖ s`. Handing the raw form back produces certificates that parse
//!    perfectly and verify nowhere. See [`raw_ecdsa_to_der`].
//! 2. **`CKM_ECDSA` does not hash.** rcgen passes the full TBS bytes.
//!    `CKM_ECDSA_SHA256` hashes then signs; `CKM_ECDSA` signs a digest it is
//!    given. `libykcs11` offers only the latter, so the "hash it ourselves"
//!    path is the YubiKey path, not a corner case.
//! 3. **`CKA_EC_POINT` is DER-wrapped.** rcgen wants the bare uncompressed
//!    point `0x04 ‖ X ‖ Y`; PKCS#11 v2.40+ wraps it in an `OCTET STRING`.
//!    Some tokens do not. See [`unwrap_ec_point`].
//! 4. **`C_Initialize` runs once per module per process.** Two profiles using
//!    two different keys on one module must share one context, or the second
//!    gets `CKR_CRYPTOKI_ALREADY_INITIALIZED`. See [`context_for`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};
use ring::digest;
use simple_asn1::{ASN1Block, BigInt, BigUint};
use tracing::{error, info, warn};

use crate::config::LocalCaConfig;

/// The DER encoding of the `secp256r1` (P-256) curve OID, `1.2.840.10045.3.1.7`,
/// as it appears in `CKA_EC_PARAMS`.
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// The DER encoding of the `secp384r1` (P-384) curve OID, `1.3.132.0.34`.
const OID_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

/// One `Pkcs11` context per module path, for the whole process.
///
/// `Pkcs11::new` + `initialize` is `C_Initialize`, which a PKCS#11 module
/// accepts exactly once per process; a second call returns
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED`. Two profiles pointing at two different
/// keys on the same module are a legitimate configuration that
/// `signer::build_backends` will not deduplicate (their signer configs differ),
/// so without this registry the second one would fail to start.
static CONTEXTS: OnceLock<Mutex<HashMap<PathBuf, Arc<Pkcs11>>>> = OnceLock::new();

/// The shared context for `module_path`, initialising it on first use.
fn context_for(module_path: &str) -> anyhow::Result<Arc<Pkcs11>> {
    // Canonicalised so `/usr/lib/softhsm/libsofthsm2.so` and a symlink to it
    // are one entry rather than two contexts over one module.
    let key = std::fs::canonicalize(module_path).unwrap_or_else(|_| PathBuf::from(module_path));

    let mut contexts = CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("the PKCS#11 context registry mutex is poisoned"))?;

    if let Some(context) = contexts.get(&key) {
        return Ok(context.clone());
    }

    let context = Pkcs11::new(&key).map_err(|error| {
        anyhow::anyhow!(
            "PKCS#11 module `{}` could not be loaded: {error}",
            module_path
        )
    })?;
    // `OS_LOCKING_OK`: this process is multi-threaded (tokio) and signing runs
    // on the blocking pool, so the module must guard its own state with OS
    // locking primitives rather than assuming a single-threaded caller.
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|error| {
            anyhow::anyhow!(
                "PKCS#11 module `{}` failed C_Initialize: {error}",
                module_path
            )
        })?;

    let context = Arc::new(context);
    contexts.insert(key, context.clone());
    Ok(context)
}

/// Logs `session` in as the user, treating "already logged in" as success.
///
/// PKCS#11 login state belongs to the **token within an application**, not to
/// the session: once any session on a slot has logged in, every other session
/// on that slot is logged in too, and `C_Login` answers
/// `CKR_USER_ALREADY_LOGGED_IN`. That is not a failure, and it is not exotic —
/// it is what two profiles sharing one token, or a reconnect racing a sibling,
/// both hit. Treating it as an error made the second `Pkcs11SigningKey` on a
/// token refuse to start.
fn login_as_user(session: &Session, pin: &AuthPin) -> Result<(), CryptokiError> {
    match session.login(UserType::User, Some(pin)) {
        Ok(()) => Ok(()),
        Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Everything needed to rebuild a session after the token drops the old one.
struct Reconnect {
    context: Arc<Pkcs11>,
    slot: Slot,
    pin: AuthPin,
    key_label: String,
    key_id: Option<Vec<u8>>,
}

/// A CA issuing key that never leaves its PKCS#11 token.
pub struct Pkcs11SigningKey {
    /// Serialised, because cryptoki's `Session` is `Send` but **not** `Sync`
    /// (`unsafe impl Send for Session {}` and no `Sync` impl), while this type
    /// has to be both to live inside an `Arc<dyn SignerBackend>`.
    ///
    /// A `std::sync::Mutex` rather than tokio's: `SigningKey::sign` is
    /// synchronous and never awaits, and the whole call already runs under
    /// `spawn_blocking` (see `LocalCa::issue`).
    session: Mutex<Session>,
    key_handle: Mutex<ObjectHandle>,
    /// The bare uncompressed EC point, cached because `PublicKeyData::
    /// der_bytes` returns a borrow and a token round trip per call is not an
    /// option.
    public_key_der: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
    /// The mechanism chosen once at startup, and whether we must hash first.
    mechanism: MechanismChoice,
    reconnect: Reconnect,
    /// For log lines and `Debug`; never the PIN.
    description: String,
}

/// Which `CKM_*` the token will be asked for, decided once at startup.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MechanismChoice {
    /// `CKM_ECDSA_SHA256` / `CKM_ECDSA_SHA384`: the token hashes and signs.
    Hashing(MechanismType),
    /// `CKM_ECDSA`: the token signs a digest we compute. The `libykcs11` path.
    RawWithDigest(&'static digest::Algorithm),
}

impl std::fmt::Debug for MechanismChoice {
    /// Renders the `CKM_*` name an operator would recognise. `MechanismType`'s
    /// own `Debug` prints `MechanismType { val: 4164 }`, which is the right
    /// number in the wrong base and no help at all in a startup log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hashing(MechanismType::ECDSA_SHA384) => f.write_str("CKM_ECDSA_SHA384"),
            Self::Hashing(_) => f.write_str("CKM_ECDSA_SHA256"),
            Self::RawWithDigest(algorithm) if std::ptr::eq(*algorithm, &digest::SHA384) => {
                f.write_str("CKM_ECDSA+SHA384")
            }
            Self::RawWithDigest(_) => f.write_str("CKM_ECDSA+SHA256"),
        }
    }
}

impl Pkcs11SigningKey {
    /// Opens the token described by `cfg`, logs in, and resolves the issuing
    /// key. Called once at startup, so every failure here is fatal and says
    /// what to fix.
    pub fn open(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        let pkcs11 = &cfg.pkcs11;
        if pkcs11.module_path.is_empty() {
            anyhow::bail!(
                "local_ca key_source = \"pkcs11\" needs signer.local_ca.pkcs11.module_path \
                 (e.g. \"/usr/lib/softhsm/libsofthsm2.so\" or \"/usr/lib/libykcs11.so\")"
            );
        }
        if pkcs11.key_label.is_empty() {
            anyhow::bail!(
                "local_ca key_source = \"pkcs11\" needs signer.local_ca.pkcs11.key_label; \
                 list what the token holds with \
                 `pkcs11-tool --module {} --list-objects --login`",
                pkcs11.module_path
            );
        }

        let key_id = parse_key_id(&pkcs11.key_id)?;
        let pin = AuthPin::from(super::key::read_pin(cfg)?);
        let context = context_for(&pkcs11.module_path)?;
        let slot = resolve_slot(&context, pkcs11.token_label.as_str(), pkcs11.slot_id)?;

        let session = context.open_ro_session(slot).map_err(|error| {
            anyhow::anyhow!("could not open a PKCS#11 session on slot {slot}: {error}")
        })?;
        login_as_user(&session, &pin).map_err(|error| {
            anyhow::anyhow!(
                "PKCS#11 login failed on slot {slot}: {error} \
                 (check the PIN in signer.local_ca.pkcs11.pin_file — note that a token \
                 typically blocks the PIN after a few wrong attempts)"
            )
        })?;

        let key_handle = find_private_key(&session, &pkcs11.key_label, key_id.as_deref())?;
        let (public_key_der, algorithm) =
            read_public_key(&session, &pkcs11.key_label, key_id.as_deref(), key_handle)?;
        let mechanism = choose_mechanism(&context, slot, algorithm)?;

        let description = format!(
            "module={} slot={} key_label={}",
            pkcs11.module_path, slot, pkcs11.key_label
        );
        info!(
            event = "local_ca_pkcs11_opened",
            outcome = "success",
            module = %pkcs11.module_path,
            slot = %slot,
            key_label = %pkcs11.key_label,
            algorithm = ?algorithm,
            mechanism = ?mechanism,
            "the local CA's issuing key is on a PKCS#11 token",
        );

        Ok(Self {
            session: Mutex::new(session),
            key_handle: Mutex::new(key_handle),
            public_key_der,
            algorithm,
            mechanism,
            reconnect: Reconnect {
                context,
                slot,
                pin,
                key_label: pkcs11.key_label.clone(),
                key_id,
            },
            description,
        })
    }

    /// One `C_Sign`, converting the token's raw `r ‖ s` into the DER signature
    /// rcgen's `SignatureAlgorithm` promises.
    fn sign_once(&self, msg: &[u8]) -> Result<Vec<u8>, CryptokiError> {
        let (mechanism, payload);
        match self.mechanism {
            MechanismChoice::Hashing(kind) => {
                mechanism = mechanism_from_type(kind);
                payload = msg.to_vec();
            }
            MechanismChoice::RawWithDigest(algorithm) => {
                mechanism = Mechanism::Ecdsa;
                payload = digest::digest(algorithm, msg).as_ref().to_vec();
            }
        }

        let session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let handle = *self
            .key_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        session.sign(&mechanism, handle, &payload)
    }

    /// Reopens the session, logs back in and re-resolves the key handle.
    ///
    /// A YubiKey gets unplugged; a network HSM times a session out. Without
    /// this the CA would be permanently broken by an event it can recover from.
    fn reconnect(&self) -> anyhow::Result<()> {
        let session = self
            .reconnect
            .context
            .open_ro_session(self.reconnect.slot)?;
        login_as_user(&session, &self.reconnect.pin)?;
        let handle = find_private_key(
            &session,
            &self.reconnect.key_label,
            self.reconnect.key_id.as_deref(),
        )?;

        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = session;
        *self
            .key_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handle;
        Ok(())
    }
}

impl PublicKeyData for Pkcs11SigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_der
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let raw = match self.sign_once(msg) {
            Ok(raw) => raw,
            Err(error) if is_recoverable(&error) => {
                // Exactly one retry, never a loop: a login failure is also
                // reachable here, and retrying that against a PIV applet burns
                // the three attempts standing between the operator and a
                // PUK-blocked slot.
                warn!(
                    event = "local_ca_pkcs11_session_lost",
                    outcome = "advisory",
                    error = %error,
                    token = %self.description,
                    "reopening the PKCS#11 session and retrying the signature once",
                );
                self.reconnect().map_err(|error| {
                    error!(
                        event = "local_ca_pkcs11_reconnect_failed",
                        outcome = "failure",
                        error = %error,
                        token = %self.description,
                    );
                    rcgen::Error::RemoteKeyError
                })?;
                self.sign_once(msg).map_err(|error| {
                    // `rcgen::Error::RemoteKeyError` carries no payload, so the
                    // real cause has to be logged here or it is lost — the
                    // operator would otherwise see only "Remote key error".
                    // Distinct from `local_ca_pkcs11_sign_failed` below: this
                    // one failed *after* a session was successfully reopened,
                    // which rules the session out as the cause.
                    error!(
                        event = "local_ca_pkcs11_sign_retry_failed",
                        outcome = "failure",
                        error = %error,
                        token = %self.description,
                    );
                    rcgen::Error::RemoteKeyError
                })?
            }
            Err(error) => {
                error!(
                    event = "local_ca_pkcs11_sign_failed",
                    outcome = "failure",
                    error = %error,
                    token = %self.description,
                );
                return Err(rcgen::Error::RemoteKeyError);
            }
        };

        raw_ecdsa_to_der(&raw).map_err(|error| {
            error!(
                event = "local_ca_pkcs11_signature_malformed",
                outcome = "failure",
                error = %error,
                len = raw.len(),
                token = %self.description,
            );
            rcgen::Error::RemoteKeyError
        })
    }
}

impl std::fmt::Debug for Pkcs11SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11SigningKey")
            .field("token", &self.description)
            .field("mechanism", &self.mechanism)
            .finish_non_exhaustive()
    }
}

/// Whether a failed `C_Sign` is worth reopening the session for.
///
/// Deliberately a small set. Anything else — a wrong mechanism, a key that
/// cannot sign — would fail identically on a fresh session, and retrying would
/// only double the log noise.
fn is_recoverable(error: &CryptokiError) -> bool {
    matches!(
        error,
        CryptokiError::Pkcs11(
            RvError::SessionHandleInvalid
                | RvError::SessionClosed
                | RvError::DeviceError
                | RvError::DeviceRemoved
                | RvError::UserNotLoggedIn
                | RvError::ObjectHandleInvalid,
            _
        )
    )
}

/// Turns the token's raw fixed-width `r ‖ s` into the DER
/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` that X.509 — and so
/// rcgen's `*_ASN1_SIGNING` algorithms — require.
///
/// Both halves are unsigned big-endian integers of the same length, so they go
/// through `BigUint` before `BigInt`: taking the bytes as a signed integer
/// would make any value with the high bit set encode as negative, and the
/// signature would verify nowhere.
fn raw_ecdsa_to_der(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        anyhow::bail!(
            "a raw ECDSA signature must be an even, non-zero number of bytes, got {}",
            raw.len()
        );
    }
    let (r, s) = raw.split_at(raw.len() / 2);

    let sequence = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from(BigUint::from_bytes_be(r))),
            ASN1Block::Integer(0, BigInt::from(BigUint::from_bytes_be(s))),
        ],
    );
    simple_asn1::to_der(&sequence)
        .map_err(|error| anyhow::anyhow!("could not DER-encode the ECDSA signature: {error}"))
}

/// Extracts the bare uncompressed EC point `0x04 ‖ X ‖ Y` from `CKA_EC_POINT`.
///
/// PKCS#11 v2.40 onwards defines the attribute as the point wrapped in a DER
/// `OCTET STRING`; older and embedded tokens hand back the point itself. Both
/// start with a `0x04` byte — as the OCTET STRING tag in one case and the
/// "uncompressed point" marker in the other — so the shapes are told apart by
/// checking whether the declared length actually accounts for the remainder.
fn unwrap_ec_point(attribute: &[u8]) -> anyhow::Result<Vec<u8>> {
    if attribute.len() < 2 {
        anyhow::bail!(
            "CKA_EC_POINT is too short to be a public key ({} bytes)",
            attribute.len()
        );
    }

    if attribute[0] == 0x04 {
        // Try the DER OCTET STRING reading first.
        let (header, length) = match attribute[1] {
            len @ 0x00..=0x7f => (2usize, len as usize),
            0x81 if attribute.len() >= 3 => (3usize, attribute[2] as usize),
            0x82 if attribute.len() >= 4 => (
                4usize,
                u16::from_be_bytes([attribute[2], attribute[3]]) as usize,
            ),
            _ => (0, 0),
        };
        if header != 0 && header + length == attribute.len() {
            let point = &attribute[header..];
            if point.first() == Some(&0x04) {
                return Ok(point.to_vec());
            }
        }
        // Not a wrapper, or the wrapper's length disagrees: take the attribute
        // as the point itself.
        return Ok(attribute.to_vec());
    }

    anyhow::bail!(
        "CKA_EC_POINT does not hold an uncompressed EC point (first byte 0x{:02x}); \
         compressed points are not supported",
        attribute[0]
    )
}

/// Parses the optional hex `CKA_ID`.
fn parse_key_id(key_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
    if key_id.is_empty() {
        return Ok(None);
    }
    let cleaned: String = key_id
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let bytes = hex::decode(&cleaned).map_err(|error| {
        anyhow::anyhow!("signer.local_ca.pkcs11.key_id `{key_id}` is not hexadecimal: {error}")
    })?;
    Ok(Some(bytes))
}

/// Finds the slot to use, by token label if one is configured, else by id.
fn resolve_slot(context: &Pkcs11, token_label: &str, slot_id: Option<u64>) -> anyhow::Result<Slot> {
    let slots = context
        .get_slots_with_token()
        .map_err(|error| anyhow::anyhow!("could not list PKCS#11 slots: {error}"))?;

    if !token_label.is_empty() {
        let mut seen = Vec::new();
        for slot in &slots {
            match context.get_token_info(*slot) {
                Ok(info) => {
                    let label = info.label().trim().to_string();
                    if label == token_label {
                        return Ok(*slot);
                    }
                    seen.push(label);
                }
                Err(error) => {
                    warn!(
                        event = "local_ca_pkcs11_token_info_failed",
                        outcome = "failure",
                        slot = %slot,
                        error = %error,
                    );
                }
            }
        }
        anyhow::bail!("no PKCS#11 token labelled `{token_label}`; tokens present: {seen:?}");
    }

    if let Some(id) = slot_id {
        let wanted = Slot::try_from(id)
            .map_err(|error| anyhow::anyhow!("slot_id {id} is not a valid slot: {error}"))?;
        if slots.contains(&wanted) {
            return Ok(wanted);
        }
        anyhow::bail!("no PKCS#11 token in slot {id}; slots with a token: {slots:?}");
    }

    anyhow::bail!(
        "local_ca key_source = \"pkcs11\" needs signer.local_ca.pkcs11.token_label \
         (preferred) or slot_id; tokens present: {slots:?}"
    )
}

/// Resolves the private key handle by label, narrowed by `CKA_ID` if given.
fn find_private_key(
    session: &Session,
    key_label: &str,
    key_id: Option<&[u8]>,
) -> anyhow::Result<ObjectHandle> {
    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(key_label.as_bytes().to_vec()),
    ];
    if let Some(id) = key_id {
        template.push(Attribute::Id(id.to_vec()));
    }

    let handles = session
        .find_objects(&template)
        .map_err(|error| anyhow::anyhow!("searching for the private key failed: {error}"))?;

    match handles.len() {
        0 => anyhow::bail!(
            "no PKCS#11 private key labelled `{key_label}`{}; list what the token holds with \
             `pkcs11-tool --module <module> --list-objects --login`",
            match key_id {
                Some(id) => format!(" with id {}", hex::encode(id)),
                None => String::new(),
            }
        ),
        1 => Ok(handles[0]),
        // Signing with an arbitrary one of several keys would produce
        // certificates that verify against whichever the CA certificate
        // happens to name — a coin flip nobody should ship.
        n => anyhow::bail!(
            "{n} PKCS#11 private keys are labelled `{key_label}`; set \
             signer.local_ca.pkcs11.key_id to pick one"
        ),
    }
}

/// Reads the public half and derives the rcgen algorithm from the curve.
///
/// The public key object is preferred — that is where `CKA_EC_POINT` is
/// defined to live — but many tokens also expose it on the private key, which
/// is the fallback for the ones that publish no `CKO_PUBLIC_KEY` at all.
fn read_public_key(
    session: &Session,
    key_label: &str,
    key_id: Option<&[u8]>,
    private_key: ObjectHandle,
) -> anyhow::Result<(Vec<u8>, &'static SignatureAlgorithm)> {
    let mut template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Label(key_label.as_bytes().to_vec()),
    ];
    if let Some(id) = key_id {
        template.push(Attribute::Id(id.to_vec()));
    }
    let public = session.find_objects(&template).unwrap_or_default();
    let handle = public.first().copied().unwrap_or(private_key);

    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint, AttributeType::EcParams])
        .map_err(|error| {
            anyhow::anyhow!(
                "could not read the public key of `{key_label}` from the token: {error} \
                 (the CA certificate's key must be readable to confirm it matches)"
            )
        })?;

    let mut point = None;
    let mut params = None;
    for attribute in attributes {
        match attribute {
            Attribute::EcPoint(value) => point = Some(value),
            Attribute::EcParams(value) => params = Some(value),
            _ => {}
        }
    }

    let point = point.ok_or_else(|| {
        anyhow::anyhow!(
            "the PKCS#11 key `{key_label}` exposes no CKA_EC_POINT; only ECDSA keys are \
             supported by this backend"
        )
    })?;
    let params = params
        .ok_or_else(|| anyhow::anyhow!("the PKCS#11 key `{key_label}` exposes no CKA_EC_PARAMS"))?;

    let algorithm = algorithm_for_curve(&params)?;
    Ok((unwrap_ec_point(&point)?, algorithm))
}

/// Maps a `CKA_EC_PARAMS` curve OID to the rcgen algorithm that goes with it.
fn algorithm_for_curve(params: &[u8]) -> anyhow::Result<&'static SignatureAlgorithm> {
    match params {
        OID_P256 => Ok(&rcgen::PKCS_ECDSA_P256_SHA256),
        OID_P384 => Ok(&rcgen::PKCS_ECDSA_P384_SHA384),
        other => anyhow::bail!(
            "unsupported PKCS#11 curve (CKA_EC_PARAMS {}); this backend supports \
             P-256 (secp256r1) and P-384 (secp384r1)",
            hex::encode(other)
        ),
    }
}

/// Picks the signing mechanism once, preferring the one where the token hashes.
///
/// `libykcs11` publishes only `CKM_ECDSA`, so the digest-it-ourselves branch is
/// the ordinary YubiKey path rather than a fallback for odd hardware.
fn choose_mechanism(
    context: &Pkcs11,
    slot: Slot,
    algorithm: &'static SignatureAlgorithm,
) -> anyhow::Result<MechanismChoice> {
    let (hashing, digest_algorithm) = if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
        (MechanismType::ECDSA_SHA256, &digest::SHA256)
    } else {
        (MechanismType::ECDSA_SHA384, &digest::SHA384)
    };

    let available = context.get_mechanism_list(slot).unwrap_or_else(|error| {
        // Not fatal: a module that will not enumerate can still sign, and
        // `CKM_ECDSA` is the safer assumption.
        warn!(
            event = "local_ca_pkcs11_mechanism_list_failed",
            outcome = "failure",
            slot = %slot,
            error = %error,
        );
        Vec::new()
    });

    if available.contains(&hashing) {
        return Ok(MechanismChoice::Hashing(hashing));
    }
    if available.is_empty() || available.contains(&MechanismType::ECDSA) {
        return Ok(MechanismChoice::RawWithDigest(digest_algorithm));
    }

    anyhow::bail!(
        "the token in slot {slot} supports neither {hashing} nor CKM_ECDSA, so this backend \
         cannot sign with it"
    )
}

/// `MechanismType` → the owned `Mechanism` `C_Sign` takes.
fn mechanism_from_type(kind: MechanismType) -> Mechanism<'static> {
    match kind {
        MechanismType::ECDSA_SHA384 => Mechanism::EcdsaSha384,
        _ => Mechanism::EcdsaSha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion that decides whether issued certificates verify at all.
    #[test]
    fn a_raw_signature_becomes_a_der_sequence_of_two_integers() {
        let raw: Vec<u8> = (1u8..=64).collect();
        let der = raw_ecdsa_to_der(&raw).unwrap();

        let blocks = simple_asn1::from_der(&der).unwrap();
        let ASN1Block::Sequence(_, items) = &blocks[0] else {
            panic!("expected a SEQUENCE, got {blocks:?}");
        };
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], ASN1Block::Integer(..)));
        assert!(matches!(items[1], ASN1Block::Integer(..)));
    }

    /// A half whose top bit is set must stay **positive**. Read as a signed
    /// integer it would encode as negative, and the signature would verify
    /// nowhere — the exact bug this helper exists to prevent.
    #[test]
    fn a_high_bit_half_stays_positive() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0xff; // r's top bit is set
        raw[32] = 0x7f; // s's is not
        raw[63] = 0x01;

        let der = raw_ecdsa_to_der(&raw).unwrap();
        let blocks = simple_asn1::from_der(&der).unwrap();
        let ASN1Block::Sequence(_, items) = &blocks[0] else {
            panic!("expected a SEQUENCE");
        };

        let zero = BigInt::from(0u8);
        for item in items {
            let ASN1Block::Integer(_, value) = item else {
                panic!("expected INTEGER, got {item:?}");
            };
            assert!(
                *value > zero,
                "both halves are unsigned; a negative INTEGER means the bytes were read \
                 as signed, and the signature would verify nowhere",
            );
        }

        // The encoding side of the same property: r needs an explicit 0x00 pad
        // so its leading 0xff is not read as a sign bit.
        assert_eq!(&der[..4], &[0x30, 0x45, 0x02, 0x21], "{der:02x?}");
        assert_eq!(der[4], 0x00, "r must be zero-padded: {der:02x?}");
    }

    /// Leading zeros are not significant in the fixed-width form and must not
    /// survive into the DER INTEGER.
    #[test]
    fn leading_zeros_are_dropped() {
        let mut raw = vec![0u8; 64];
        raw[31] = 0x09; // r = 9
        raw[63] = 0x0a; // s = 10
        let der = raw_ecdsa_to_der(&raw).unwrap();

        // SEQUENCE { INTEGER 9, INTEGER 10 } is six bytes: 30 06 02 01 09 02 01 0a
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x09, 0x02, 0x01, 0x0a]);
    }

    #[test]
    fn a_malformed_raw_signature_is_an_error_not_a_bad_certificate() {
        assert!(raw_ecdsa_to_der(&[]).is_err());
        assert!(raw_ecdsa_to_der(&[0x01, 0x02, 0x03]).is_err(), "odd length");
    }

    /// The DER-wrapped shape PKCS#11 v2.40+ specifies.
    #[test]
    fn a_der_wrapped_ec_point_is_unwrapped() {
        let mut point = vec![0x04];
        point.extend(std::iter::repeat_n(0xab, 64));

        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&point);

        assert_eq!(unwrap_ec_point(&wrapped).unwrap(), point);
    }

    /// …and the bare shape some tokens hand back instead.
    #[test]
    fn a_bare_ec_point_is_taken_as_is() {
        let mut point = vec![0x04];
        point.extend(std::iter::repeat_n(0xcd, 64));
        assert_eq!(unwrap_ec_point(&point).unwrap(), point);
    }

    /// A P-384 point, whose 97 bytes need the 0x81 long-form length.
    #[test]
    fn a_long_form_der_wrapped_ec_point_is_unwrapped() {
        let mut point = vec![0x04];
        point.extend(std::iter::repeat_n(0xef, 96));

        let mut wrapped = vec![0x04, 0x81, 0x61];
        wrapped.extend_from_slice(&point);

        assert_eq!(unwrap_ec_point(&wrapped).unwrap(), point);
    }

    #[test]
    fn a_compressed_or_empty_ec_point_is_refused() {
        assert!(unwrap_ec_point(&[]).is_err());
        assert!(unwrap_ec_point(&[0x04]).is_err(), "too short");
        // 0x02/0x03 mark a compressed point, which rcgen cannot consume.
        assert!(unwrap_ec_point(&[0x02, 0x20, 0xaa]).is_err());
    }

    #[test]
    fn the_two_supported_curves_map_to_rcgen_algorithms() {
        assert_eq!(
            algorithm_for_curve(OID_P256).unwrap(),
            &rcgen::PKCS_ECDSA_P256_SHA256
        );
        assert_eq!(
            algorithm_for_curve(OID_P384).unwrap(),
            &rcgen::PKCS_ECDSA_P384_SHA384
        );
    }

    /// An unsupported curve must name itself, so the operator can see which
    /// key they pointed at.
    #[test]
    fn an_unsupported_curve_is_an_error_naming_it() {
        // secp521r1: 1.3.132.0.35
        let p521 = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
        let error = algorithm_for_curve(p521).unwrap_err().to_string();
        assert!(error.contains("P-256"), "{error}");
        assert!(error.contains(&hex::encode(p521)), "{error}");
    }

    #[test]
    fn key_ids_are_parsed_as_hex_and_tolerate_separators() {
        assert_eq!(parse_key_id("").unwrap(), None);
        assert_eq!(parse_key_id("01ff").unwrap(), Some(vec![0x01, 0xff]));
        assert_eq!(parse_key_id("01:ff").unwrap(), Some(vec![0x01, 0xff]));
        assert!(parse_key_id("nothex").is_err());
    }
}

/// End-to-end tests against a real SoftHSM2 token.
///
/// The key is generated through `cryptoki` itself rather than shelling out to
/// `pkcs11-tool`, so the only prerequisite is the SoftHSM2 module `.so`. When
/// that is absent every test here **skips** rather than failing, keeping
/// `cargo nextest run --features hsm` green on a machine without it.
///
/// These need `cargo nextest`, not `cargo test` — doubly so. `SOFTHSM2_CONF`
/// is process-global and read at `C_Initialize`, and [`CONTEXTS`] caches one
/// context per module for the process; nextest's process-per-test isolation is
/// what keeps those from leaking between tests.
#[cfg(test)]
mod softhsm {
    use super::*;
    use crate::config::{LocalCaConfig, Pkcs11Config};
    use crate::signer::local_ca::LocalCa;
    // `issue`/`revoke`/`crl_der` are trait methods, so the trait has to be in
    // scope even though the concrete type is what the tests hold.
    use crate::signer::SignerBackend;
    use crate::testutil::TempDir;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
    use std::path::Path;
    use std::sync::OnceLock;

    /// Where SoftHSM2's module lives on the distributions this is likely to be
    /// run on. Debian/Ubuntu put it under a multiarch path, Arch and Fedora do
    /// not.
    const MODULE_CANDIDATES: &[&str] = &[
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ];

    const SO_PIN: &str = "3737";
    const USER_PIN: &str = "1234";
    const TOKEN_LABEL: &str = "acme-proxy-test";
    const KEY_LABEL: &str = "ca-key";

    fn module_path() -> Option<&'static str> {
        MODULE_CANDIDATES
            .iter()
            .copied()
            .find(|path| Path::new(path).exists())
    }

    /// A SoftHSM2 token with one P-256 key and a matching CA certificate.
    ///
    /// Built once per process: `SOFTHSM2_CONF` and the PKCS#11 context are both
    /// process-global, so a second token in the same process would not be seen
    /// anyway.
    struct Lab {
        _dir: TempDir,
        module_path: &'static str,
        ca_pem_path: std::path::PathBuf,
        crl_path: std::path::PathBuf,
        pin_path: std::path::PathBuf,
    }

    impl Lab {
        fn config(&self) -> LocalCaConfig {
            LocalCaConfig {
                cert_path: self.ca_pem_path.to_string_lossy().into_owned(),
                crl_path: self.crl_path.to_string_lossy().into_owned(),
                key_source: "pkcs11".to_string(),
                pkcs11: Pkcs11Config {
                    module_path: self.module_path.to_string(),
                    token_label: TOKEN_LABEL.to_string(),
                    key_label: KEY_LABEL.to_string(),
                    pin_file: self.pin_path.to_string_lossy().into_owned(),
                    ..Pkcs11Config::default()
                },
                ..LocalCaConfig::default()
            }
        }
    }

    fn lab() -> Option<&'static Lab> {
        static LAB: OnceLock<Option<Lab>> = OnceLock::new();
        LAB.get_or_init(|| {
            let module_path = module_path()?;
            Some(build_lab(module_path).expect("SoftHSM2 is present, so the lab must build"))
        })
        .as_ref()
    }

    /// Skips the calling test when SoftHSM2 is not installed.
    macro_rules! lab_or_skip {
        () => {
            match lab() {
                Some(lab) => lab,
                None => {
                    eprintln!(
                        "skipping: no SoftHSM2 module found (looked in {MODULE_CANDIDATES:?}); \
                         install softhsm2 to run the PKCS#11 tests"
                    );
                    return;
                }
            }
        };
    }

    fn build_lab(module_path: &'static str) -> anyhow::Result<Lab> {
        let dir = TempDir::new("softhsm");
        let tokens = dir.path().join("tokens");
        std::fs::create_dir_all(&tokens)?;
        let conf = dir.write(
            "softhsm2.conf",
            &format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        );

        // Must be set before `C_Initialize`, which `context_for` performs on
        // first use — and this is the first use in the process.
        //
        // SAFETY: `OnceLock` makes this run once, before any other thread in
        // this test binary has reason to read the environment.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };

        let context = context_for(module_path)?;

        // SoftHSM presents one uninitialised slot; initialising the token moves
        // it, so everything afterwards resolves by label rather than by id.
        let slot = *context
            .get_all_slots()?
            .first()
            .ok_or_else(|| anyhow::anyhow!("SoftHSM2 exposes no slots"))?;
        let so_pin = AuthPin::from(SO_PIN.to_string());
        let user_pin = AuthPin::from(USER_PIN.to_string());
        context.init_token(slot, &so_pin, TOKEN_LABEL)?;

        let slot = resolve_slot(&context, TOKEN_LABEL, None)?;
        {
            let session = context.open_rw_session(slot)?;
            session.login(UserType::So, Some(&so_pin))?;
            session.init_pin(&user_pin)?;
        }

        // Generate the CA key on the token. `Sensitive` + `Extractable(false)`
        // is the posture a CA key should have: it exists only inside the token.
        let session = context.open_rw_session(slot)?;
        session.login(UserType::User, Some(&user_pin))?;
        session.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
                Attribute::EcParams(OID_P256.to_vec()),
                Attribute::Verify(true),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
                Attribute::Sign(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ],
        )?;
        drop(session);

        let pin_path = dir.write("hsm.pin", &format!("{USER_PIN}\n"));
        let ca_pem_path = dir.join("ca.pem");
        let crl_path = dir.join("ca.crl");

        // Self-sign the CA certificate *through the token*. This is both the
        // fixture and the sharpest test of `sign`: if the raw-to-DER conversion
        // were wrong, the certificate below would not verify against its own
        // public key.
        let cfg = LocalCaConfig {
            cert_path: ca_pem_path.to_string_lossy().into_owned(),
            key_source: "pkcs11".to_string(),
            pkcs11: Pkcs11Config {
                module_path: module_path.to_string(),
                token_label: TOKEN_LABEL.to_string(),
                key_label: KEY_LABEL.to_string(),
                pin_file: pin_path.to_string_lossy().into_owned(),
                ..Pkcs11Config::default()
            },
            ..LocalCaConfig::default()
        };
        let signing_key = Pkcs11SigningKey::open(&cfg)?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "acme-proxy softhsm test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = params.self_signed(&signing_key)?;
        std::fs::write(&ca_pem_path, ca_cert.pem())?;

        Ok(Lab {
            _dir: dir,
            module_path,
            ca_pem_path,
            crl_path,
            pin_path,
        })
    }

    fn make_csr_der(name: &str) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.serialize_request(&key_pair).unwrap().der().to_vec()
    }

    /// The whole point: a CA whose key is on a token issues a leaf that
    /// verifies against it. Every one of this module's four gotchas — the DER
    /// signature encoding, the mechanism choice, the `CKA_EC_POINT` unwrapping
    /// and the shared context — has to be right for this to pass.
    #[tokio::test]
    async fn a_token_backed_ca_issues_a_verifiable_leaf() {
        let lab = lab_or_skip!();
        let ca = LocalCa::load_or_generate(&lab.config(), &crate::signer::CarriedState::new())
            .expect("the token-backed CA must load");

        let outcome = ca
            .issue(
                "ord-hsm",
                &make_csr_der("example.com"),
                &[crate::sqlite::order::Identifier::dns("example.com")],
                crate::signer::RequestedValidity::default(),
            )
            .await
            .expect("issuance through the token must succeed");
        let chain = match outcome {
            crate::signer::IssueOutcome::Issued(chain) => chain,
            crate::signer::IssueOutcome::Processing => panic!("local_ca issues synchronously"),
        };
        assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);

        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let ca_der =
            crate::cert::leaf_der_from_chain(&std::fs::read_to_string(&lab.ca_pem_path).unwrap())
                .unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca_der).unwrap();

        leaf.verify_signature(Some(ca_cert.public_key()))
            .expect("the leaf must verify against the CA that signed it");
    }

    /// The CRL signs through the same key, and is the path `GET /crl` serves.
    #[tokio::test]
    async fn a_token_backed_ca_signs_a_verifiable_crl() {
        let lab = lab_or_skip!();
        let ca =
            LocalCa::load_or_generate(&lab.config(), &crate::signer::CarriedState::new()).unwrap();

        let outcome = ca
            .issue(
                "ord-hsm",
                &make_csr_der("revoke.example"),
                &[crate::sqlite::order::Identifier::dns("revoke.example")],
                crate::signer::RequestedValidity::default(),
            )
            .await
            .unwrap();
        let crate::signer::IssueOutcome::Issued(chain) = outcome else {
            panic!("local_ca issues synchronously");
        };
        let leaf_der = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (serial_hex, _) = crate::cert::cert_serial_and_spki(&leaf_der).unwrap();

        ca.revoke(&leaf_der, Some(1)).await.unwrap();

        let crl_der = ca.crl_der().await.expect("a CRL is always present");
        use x509_parser::prelude::FromDer;
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&crl_der).unwrap();
        let serials: Vec<String> = crl
            .iter_revoked_certificates()
            .map(|r| r.raw_serial_as_string().replace(':', ""))
            .collect();
        assert!(
            serials.iter().any(|s| s.eq_ignore_ascii_case(&serial_hex)),
            "expected {serial_hex} in {serials:?}",
        );
    }

    /// The cross-check that turns a typo into a startup error instead of a
    /// fleet of certificates that verify nowhere.
    #[test]
    fn a_key_label_that_matches_nothing_is_a_startup_error() {
        let lab = lab_or_skip!();
        let mut cfg = lab.config();
        cfg.pkcs11.key_label = "not-the-ca-key".to_string();

        let error = match LocalCa::load_or_generate(&cfg, &crate::signer::CarriedState::new()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a key label matching nothing must not start the server"),
        };
        assert!(error.contains("not-the-ca-key"), "{error}");
    }

    /// HSM mode never generates: a missing certificate is an error naming the
    /// path, and nothing is written in its place.
    #[test]
    fn a_missing_certificate_is_an_error_and_no_ca_is_generated() {
        let lab = lab_or_skip!();
        let dir = TempDir::new("softhsm-nocert");
        let mut cfg = lab.config();
        cfg.cert_path = dir.join("absent.pem").to_string_lossy().into_owned();
        cfg.key_path = dir.join("absent.key").to_string_lossy().into_owned();

        let error = match LocalCa::load_or_generate(&cfg, &crate::signer::CarriedState::new()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("pkcs11 mode must not generate a CA"),
        };
        assert!(error.contains("absent.pem"), "{error}");
        assert!(error.contains("does not generate"), "{error}");

        assert!(!dir.join("absent.pem").exists(), "no CA may be written");
        assert!(!dir.join("absent.key").exists(), "no key may be written");
    }

    /// A wrong PIN fails at startup, before anything is signed — and the
    /// message points at where the PIN comes from.
    #[test]
    fn a_wrong_pin_fails_at_startup() {
        let lab = lab_or_skip!();
        let dir = TempDir::new("softhsm-badpin");
        let mut cfg = lab.config();
        cfg.pkcs11.pin_file = dir
            .write("hsm.pin", "9999\n")
            .to_string_lossy()
            .into_owned();

        let error = match LocalCa::load_or_generate(&cfg, &crate::signer::CarriedState::new()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a wrong PIN must not start the server"),
        };
        assert!(error.contains("login failed"), "{error}");
    }

    /// The backwards-compatibility guarantee, asserted rather than assumed: the
    /// software path still works in a binary built with `--features hsm`.
    #[tokio::test]
    async fn the_file_key_source_still_works_with_the_feature_on() {
        let dir = TempDir::new("softhsm-file");
        let cfg = LocalCaConfig {
            cert_path: dir.join("ca.pem").to_string_lossy().into_owned(),
            key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            crl_path: dir.join("ca.crl").to_string_lossy().into_owned(),
            ..LocalCaConfig::default()
        };
        assert_eq!(cfg.key_source, "file", "the default must not have moved");

        let ca = LocalCa::load_or_generate(&cfg, &crate::signer::CarriedState::new()).unwrap();
        let outcome = ca
            .issue(
                "ord-file",
                &make_csr_der("example.com"),
                &[crate::sqlite::order::Identifier::dns("example.com")],
                crate::signer::RequestedValidity::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            crate::signer::IssueOutcome::Issued(chain) if chain.matches("BEGIN CERTIFICATE").count() == 2
        ));
    }

    /// Two `LocalCa`s over one module must not fight over `C_Initialize` —
    /// the shared-context registry is what makes a second one possible at all.
    #[test]
    fn a_second_backend_over_the_same_module_opens_fine() {
        let lab = lab_or_skip!();
        let first =
            LocalCa::load_or_generate(&lab.config(), &crate::signer::CarriedState::new()).unwrap();
        let second =
            LocalCa::load_or_generate(&lab.config(), &crate::signer::CarriedState::new()).unwrap();
        drop((first, second));
    }
}
