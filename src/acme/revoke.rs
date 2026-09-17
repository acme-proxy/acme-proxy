//! Certificate revocation (RFC 8555 §7.6), whoever asks.
//!
//! Two front doors and one tail. A client asks by presenting the certificate
//! and signing with a key that may revoke it; an operator asks by naming the
//! order, and is trusted to. From "is it already revoked?" onwards the two are
//! the same operation — the signer first, then the order row, then the trail
//! and the notification — and that tail is written once, here.
//!
//! Deliberately not an [`OrderService`](super::OrderService) method: that
//! bundle carries a mounted [`Profile`](crate::server::Profile), and the host
//! CLI revokes with no profile mounted. What revocation needs is narrower —
//! whatever withdraws trust, and whom to tell — so that is what
//! [`Revocations`] holds.

use std::sync::Arc;

use tracing::{error, info, warn};

use crate::audit::{Actor, AuditEvent, AuditRecord, Auditor, ClientContext, RequestContext};
use crate::error::Problem;
use crate::jobs::JobQueue;
use crate::notify::{CertificateRevokedData, NotifyDispatcher, NotifyEvent};
use crate::signer::{SignerBackend, SignerError};
use crate::sqlite::{account::Account, db::Database, order::Order};

/// What withdraws trust in a certificate.
pub enum Revoker<'a> {
    /// The backend that issued it, called inline.
    Backend(&'a dyn SignerBackend),
    /// A local CA's revocation state, written directly — no key, no signer.
    ///
    /// The `revocations` row and the order's stamp land in **one**
    /// transaction, and `local_ca_crl_regenerate` asks whichever process holds
    /// the key to sign the CRL. What the host CLI uses: a revocation is
    /// recorded, and visible on the order, the moment the command returns,
    /// where the CRL follows once a server's job runner gets to it.
    Ledger {
        /// The CA's issuer id ([`crate::signer::local_ca::issuer_id_of`]).
        issuer: &'a str,
        jobs: &'a JobQueue,
    },
}

/// Where the address and reverse name an audit row stores come from.
pub enum Client<'a> {
    /// A request still to be resolved — resolved only once the operation is
    /// sure to write a row, since a PTR lookup for a request about to be
    /// turned away as unparsable buys nothing.
    Request(&'a RequestContext),
    /// Already resolved by the caller, or deliberately empty: the host CLI has
    /// no request, and its rows say so.
    Resolved(ClientContext),
}

impl Client<'_> {
    async fn resolve(self, audit: &Auditor) -> ClientContext {
        match self {
            Client::Request(request) => audit.client(request).await,
            Client::Resolved(client) => client,
        }
    }
}

/// Why a revocation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    /// A refusal only the ACME path makes — an unknown certificate, a request
    /// signed by a key that may not revoke it — already audited and logged.
    #[error("{}", .0.to_value()["detail"].as_str().unwrap_or_default())]
    Refused(Problem),
    /// No order has that id.
    #[error("no such order")]
    NotFound,
    /// The order never reached issuance.
    #[error("order has no issued certificate")]
    NotIssued,
    #[error("certificate already revoked")]
    AlreadyRevoked,
    #[error("unsupported revocation reason code {0}")]
    BadReason(u32),
    /// The backend refused or failed. Nothing was recorded on the order, so a
    /// retry is expected.
    #[error("signer error: {}", signer_detail(.0))]
    Signer(SignerError),
    /// The trust was withdrawn but the order row could not say so.
    #[error("database error: {0}")]
    Database(sqlx::Error),
    /// The stored certificate cannot be read back.
    #[error("internal error: {0}")]
    Internal(String),
}

/// How a [`SignerError`] reads inside a [`RevokeError`].
///
/// `BadCsr` is not a thing `revoke` can legitimately answer — the hook takes a
/// certificate, not a CSR — so it is reported as the contract violation it is
/// rather than passed through as if it meant something here.
pub(crate) fn signer_detail(error: &SignerError) -> String {
    match error {
        SignerError::Internal(detail) => detail.clone(),
        SignerError::BadCsr => "unexpected badCsr from revoke".to_string(),
    }
}

impl From<sqlx::Error> for RevokeError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// The answer an ACME client reads for each refusal.
impl From<RevokeError> for Problem {
    fn from(error: RevokeError) -> Self {
        match error {
            RevokeError::Refused(problem) => problem,
            RevokeError::NotFound | RevokeError::NotIssued => {
                Problem::malformed("Unknown certificate")
            }
            RevokeError::AlreadyRevoked => Problem::already_revoked("Certificate already revoked"),
            RevokeError::BadReason(reason) => Problem::bad_revocation_reason(format!(
                "Unsupported revocation reason code {reason}"
            )),
            RevokeError::Signer(_) | RevokeError::Database(_) | RevokeError::Internal(_) => {
                Problem::server_internal("Revocation failed")
            }
        }
    }
}

/// Everything a revocation reaches.
pub struct Revocations<'a> {
    pub database: &'a Arc<Database>,
    pub audit: &'a Auditor,
    /// The certificate's profile's dispatcher, when this process has one — a
    /// `certificate_revoked` notification is about the certificate, so it goes
    /// out however the revocation was asked for.
    pub notify: Option<&'a NotifyDispatcher>,
    pub revoker: Revoker<'a>,
}

/// Which refusals become audit rows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusals {
    /// A remote party turned away: every refusal is recorded, because a stream
    /// of them is somebody probing.
    Audited,
    /// An operator told the state of things: nothing to record.
    Silent,
}

impl Revocations<'_> {
    /// `POST /revokeCert`: revokes the certificate `cert_der` issued at
    /// `profile`, for a request signed by `pubkey`.
    ///
    /// Authorized by either the order's own account (RFC 8555 §7.6's `kid`
    /// case, `account` being the one the JWS named) or the certificate's key
    /// pair (the accountless `jwk` case). Every refusal past the point where a
    /// serial is known is an audit row.
    pub async fn revoke_certificate(
        &self,
        profile: &str,
        cert_der: &[u8],
        reason: Option<u32>,
        pubkey: &[u8],
        account: Option<Account>,
        request: &RequestContext,
    ) -> Result<Order, RevokeError> {
        let database = self.database;
        let (serial_hex, _) = crate::cert::cert_serial_and_spki(cert_der).map_err(|error| {
            warn!(event = "certificate_revoke_parse_failed", outcome = "failure", error = %error);
            RevokeError::Refused(Problem::malformed("certificate is unparsable"))
        })?;

        let order = Order::find_by_cert_serial(profile, &serial_hex, database)
            .await
            .map_err(|error| {
                error!(event = "certificate_revoke_lookup_failed", outcome = "failure", cert_serial = %serial_hex, error = %error);
                RevokeError::Refused(Problem::server_internal("Certificate lookup failed"))
            })?
            .filter(|order| {
                order
                    .certificate
                    .as_deref()
                    .and_then(|chain| crate::cert::leaf_der_from_chain(chain).ok())
                    .is_some_and(|leaf| leaf == cert_der)
            })
            .ok_or(());

        // Who is asking, as far as the JWS could tell. An embedded `jwk` names no
        // account (RFC 8555 §7.6's accountless case), and that is recorded as an
        // `acme` actor with no id rather than guessed at — the `cert_serial` on the
        // row already says which key it must have been. Resolved here so the
        // refusal rows below can name a signer this server has not authorized.
        let actor = match &account {
            Some(cached) => Actor::acme(cached.id.to_string()),
            None => Actor::acme_certificate_key(),
        };
        // One reverse lookup for whichever arm answers.
        let client = Client::Request(request).resolve(self.audit).await;
        let revoke_failed = |reason: &'static str, detail: &str| {
            refusal(
                profile,
                actor.clone(),
                &serial_hex,
                client.clone(),
                reason,
                detail,
            )
        };

        let order = match order {
            Ok(order) => order,
            Err(()) => {
                // Either no order carries this serial, or one does and its stored
                // leaf is not byte-for-byte what was submitted. The two are not
                // told apart on purpose: distinguishing them would confirm a serial
                // exists to a caller who has not proven anything yet. The audit row
                // does not distinguish them either, for the same reason — and it
                // exists because a stream of these is somebody enumerating.
                warn!(event = "certificate_revoke_unknown_certificate", outcome = "failure", cert_serial = %serial_hex);
                self.audit
                    .record(revoke_failed(
                        "malformed",
                        "no certificate issued here matches",
                    ))
                    .await;
                return Err(RevokeError::Refused(Problem::malformed(
                    "Unknown certificate",
                )));
            }
        };

        // Deliberately not gated on account status. RFC 8555 §7.6 gives two ways
        // to authorize a revocation and only one of them involves an account at
        // all — the certificate's own key pair is the accountless case.
        //
        // §7.3.6 says a server SHOULD NOT allow further requests by a deactivated
        // account key, and this path knowingly does. Revocation only ever removes
        // trust; refusing it would mean an operator who deactivated an account can
        // no longer withdraw the certificates it holds, which is the worse failure
        // in both directions. Pinned by
        // `tests/revoke_cert.rs::deactivated_account_can_still_revoke_its_own_certificate`.
        //
        // **Never compare a key re-derived from the submitted DER**: the DER match
        // above already proves it equals the stored leaf, so re-deriving would let
        // anyone who merely observed the certificate revoke it with an unrelated
        // key. The stored `cert_pubkey` is what is compared.
        let cert_key_matches = order.cert_pubkey.as_deref() == Some(pubkey);
        let authorized = if cert_key_matches {
            true
        } else {
            match account {
                Some(cached) => cached.id == order.account_id,
                None => Account::find_by_pubkey(profile, pubkey, database)
                    .await
                    .map_err(|error| {
                        error!(event = "certificate_revoke_account_lookup_failed", outcome = "failure", error = %error);
                        RevokeError::Refused(Problem::server_internal("Account lookup failed"))
                    })?
                    .is_some_and(|found| found.id == order.account_id),
            }
        };
        if !authorized {
            warn!(event = "certificate_revoke_unauthorized", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex);
            // The one refusal here that is somebody else's certificate being
            // attacked rather than a client's own mistake, and the reason failures
            // are audited at all.
            self.audit
                .record(
                    revoke_failed(
                        "unauthorized",
                        "signed by neither the order's account nor the certificate's own key",
                    )
                    .with_order(&order),
                )
                .await;
            return Err(RevokeError::Refused(Problem::unauthorized(
                "Neither the order's account nor the certificate's own key signed this request",
            )));
        }

        self.revoke(
            order,
            cert_der,
            serial_hex,
            reason,
            actor,
            client,
            Refusals::Audited,
        )
        .await
    }

    /// An operator's revocation of order `id`'s certificate.
    ///
    /// `actor`/`client` name the operator and where they asked from — **not**
    /// the certificate's owner, since an administrative revocation attributed to
    /// the client would say the opposite of what happened. The refusals
    /// (`NotFound`, `NotIssued`, `AlreadyRevoked`, a bad reason) write no row:
    /// the operator is being told the state of things, unlike `revokeCert`'s
    /// refusals, which are a remote party being turned away.
    pub async fn revoke_order(
        &self,
        id: &str,
        reason: Option<u32>,
        actor: Actor,
        client: ClientContext,
    ) -> Result<Order, RevokeError> {
        let Some(order) = Order::find_by_id(id, self.database).await? else {
            return Err(RevokeError::NotFound);
        };
        let Some(chain) = order.certificate.as_deref() else {
            return Err(RevokeError::NotIssued);
        };
        let cert_der = crate::cert::leaf_der_from_chain(chain).map_err(|error| {
            RevokeError::Internal(format!("stored certificate chain is unparsable: {error}"))
        })?;
        // The stored serial where there is one, since that is the column the
        // trail is searched by; re-read from the leaf otherwise.
        let serial = match order.cert_serial.clone() {
            Some(serial) => serial,
            None => crate::cert::cert_serial_and_spki(&cert_der)
                .map(|(serial, _)| serial)
                .map_err(|error| {
                    RevokeError::Internal(format!("stored certificate is unparsable: {error}"))
                })?,
        };
        self.revoke(
            order,
            &cert_der,
            serial,
            reason,
            actor,
            client,
            Refusals::Silent,
        )
        .await
    }

    /// The tail both doors share: already revoked → bad reason → the signer →
    /// the order row → the trail → the notification.
    #[allow(clippy::too_many_arguments)]
    async fn revoke(
        &self,
        mut order: Order,
        cert_der: &[u8],
        serial_hex: String,
        reason: Option<u32>,
        actor: Actor,
        client: ClientContext,
        refusals: Refusals,
    ) -> Result<Order, RevokeError> {
        let refused = |order: &Order, reason: &'static str, detail: &str| {
            refusal(
                &order.profile,
                actor.clone(),
                &serial_hex,
                client.clone(),
                reason,
                detail,
            )
            .with_order(order)
        };
        let audited = refusals == Refusals::Audited;

        // *After* authorization, so an unauthorized caller cannot probe
        // revocation state.
        if order.revoked_at.is_some() {
            if audited {
                warn!(event = "certificate_revoke_already_revoked", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex);
                self.audit
                    .record(refused(&order, "alreadyRevoked", "already revoked"))
                    .await;
            }
            return Err(RevokeError::AlreadyRevoked);
        }

        if let Some(code) = reason
            && !crate::cert::is_valid_revocation_reason(code)
        {
            if audited {
                warn!(
                    event = "certificate_revoke_bad_reason",
                    outcome = "failure",
                    reason = code
                );
                self.audit
                    .record(refused(
                        &order,
                        "badRevocationReason",
                        &format!("reason code {code}"),
                    ))
                    .await;
            }
            return Err(RevokeError::BadReason(code));
        }

        match self.revoker {
            // The signer first, then the order: the CA-side action is
            // authoritative, so a failure there must leave the order un-revoked
            // for a retry — and is audited as the attempt it was, whoever asked.
            Revoker::Backend(signer) => {
                if let Err(error) = signer.revoke(cert_der, reason).await {
                    error!(event = "certificate_revoke_signer_failed", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex, error = %error);
                    self.audit
                        .record(refused(&order, "serverInternal", &error.to_string()))
                        .await;
                    return Err(RevokeError::Signer(error));
                }
                if let Err(error) = order.revoke(reason.map(i64::from), self.database).await {
                    error!(event = "certificate_revoke_persist_failed", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex, error = %error);
                    // The signer already withdrew trust, so the CA-side action
                    // stands; what failed is this server's record of it. Audited
                    // as a failure because that is what a later reader needs to
                    // know — the order still reads un-revoked and a retry is
                    // expected.
                    self.audit
                        .record(refused(&order, "serverInternal", &error.to_string()))
                        .await;
                    return Err(RevokeError::Database(error));
                }
            }
            // The row and the order together, then the CRL asked for.
            Revoker::Ledger { issuer, jobs } => {
                if let Err(error) = self
                    .record_in_ledger(&mut order, issuer, cert_der, &serial_hex, reason)
                    .await
                {
                    self.audit
                        .record(refused(&order, "serverInternal", &error.to_string()))
                        .await;
                    return Err(error);
                }
                // The revocation stands whether or not this lands: the daily
                // refresh signs any recorded revocation its CRL does not list.
                jobs.enqueue_or_log(crate::signer::local_ca::sweep::regenerate_spec(issuer))
                    .await;
            }
        }

        info!(event = "certificate_revoked", outcome = "success", order_id = %order.id, cert_serial = %serial_hex);
        let revoked = AuditRecord::new(AuditEvent::CertificateRevoked, &order.profile, actor)
            .with_order(&order)
            .with_serial(&serial_hex)
            .with_client(client.clone());
        // The RFC 5280 reason code, decimal, and left **absent** when none was
        // given — which RFC 8555 §7.6 allows and which is not the same as
        // `unspecified` (0). A `with_reason("")` here would make the two
        // indistinguishable in the column that exists to tell them apart.
        self.audit
            .record(match reason {
                Some(code) => revoked.with_reason(code.to_string()),
                None => revoked,
            })
            .await;
        if let Some(dispatcher) = self.notify {
            dispatcher
                .dispatch(NotifyEvent::CertificateRevoked(CertificateRevokedData {
                    profile: order.profile.clone(),
                    order_id: order.id.to_string(),
                    account_id: order.account_id.to_string(),
                    cert_serial: serial_hex,
                    reason,
                    client_ip: client.ip,
                }))
                .await;
        }
        Ok(order)
    }
}

impl Revocations<'_> {
    /// The ledger half of [`Revoker::Ledger`]: the `revocations` row and the
    /// order's stamp in one transaction, `order` synced after the commit.
    ///
    /// Refused while the CA has no stored CRL. A CA meets the database through
    /// its first process holding the key, which imports any pre-database
    /// `ca.json` ledger in the same transaction as that first CRL — and a
    /// revocation landing before that import would be written under a row the
    /// import then believes it owns. Any server that has run with this CA has
    /// stored one.
    async fn record_in_ledger(
        &self,
        order: &mut Order,
        issuer: &str,
        cert_der: &[u8],
        serial_hex: &str,
        reason: Option<u32>,
    ) -> Result<(), RevokeError> {
        let revoked_at = crate::sqlite::nonce::now_secs();
        let row = crate::sqlite::revocation::Revocation {
            issuer: issuer.to_string(),
            serial: serial_hex.to_string(),
            revoked_at,
            reason,
            // Best-effort, as on the signer's own path: an expiry this server
            // cannot read only means the entry is never pruned.
            not_after: crate::cert::cert_validity(cert_der)
                .ok()
                .map(|(_, not_after)| not_after),
        };
        let written = async {
            let mut tx = self.database.transaction().await?;
            if crate::sqlite::crl::StoredCrl::find(issuer, &mut *tx)
                .await?
                .is_none()
            {
                return Ok(false);
            }
            row.insert_if_absent(&mut *tx).await?;
            Order::set_revoked(order.id, reason.map(i64::from), revoked_at, &mut *tx).await?;
            tx.commit().await?;
            Ok::<bool, sqlx::Error>(true)
        }
        .await;
        let recorded = written.map_err(|error| {
            error!(event = "certificate_revoke_persist_failed", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex, error = %error);
            RevokeError::Database(error)
        })?;
        if !recorded {
            warn!(event = "certificate_revoke_ca_uninitialized", outcome = "failure", order_id = %order.id, issuer = %issuer);
            return Err(RevokeError::Internal(format!(
                "the CA {issuer} has no stored CRL yet — start `acme-proxy serve` with this \
                 configuration once, so it can import its revocation ledger, then retry"
            )));
        }
        order.revoked_at = Some(revoked_at);
        order.revocation_reason = reason.map(i64::from);
        Ok(())
    }
}

/// One `certificate_revoke_failed` row.
fn refusal(
    profile: &str,
    actor: Actor,
    serial: &str,
    client: ClientContext,
    reason: &'static str,
    detail: &str,
) -> AuditRecord {
    AuditRecord::new(AuditEvent::CertificateRevokeFailed, profile, actor)
        .with_serial(serial)
        .with_client(client)
        .with_reason(reason)
        .with_detail(detail)
}
