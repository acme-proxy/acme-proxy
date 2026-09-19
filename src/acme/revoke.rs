//! Certificate revocation (RFC 8555 §7.6), whoever asks.
//!
//! Two front doors and one tail. A client asks by presenting the certificate
//! and signing with a key that may revoke it; an operator asks by naming the
//! order, and is trusted to. From "is it already revoked?" onwards the two are
//! the same operation — the signer first, then the order row, then the trail
//! and the notification — and that tail is written once, here.
//!
//! **No request reaches a backend.** Withdrawing trust needs what only the
//! `worker` role holds — a CA key, a token login, an upstream account — so a
//! request records a local CA's revocation in its ledger ([`Revoker::Ledger`],
//! the worker signing the CRL after) or queues it for the worker
//! ([`Revoker::Queued`], waiting on the job for the answer). The backend itself
//! ([`Revoker::Backend`]) is reached only from [`SignerRevokeJob`], in the
//! process that built it. [`Revoker::for_route`] is the choice every front end
//! makes, from the profile's [`RevocationRoute`].
//!
//! Deliberately not an [`OrderService`](super::OrderService) method: that
//! bundle carries a mounted [`Profile`](crate::profile::Profile), and the host
//! CLI revokes with no profile mounted. What revocation needs is narrower —
//! whatever withdraws trust, and whom to tell — so that is what
//! [`Revocations`] holds.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auditor::Auditor;
use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::notify::{CertificateRevokedData, NotifyDispatcher, NotifyEvent};
use crate::signer::{RevocationRoute, SignerBackend, SignerError};
use acme_proxy_core::audit::Actor;
use acme_proxy_core::audit::AuditEvent;
use acme_proxy_core::audit::AuditRecord;
use acme_proxy_core::audit::ClientContext;
use acme_proxy_core::audit::RequestContext;
use acme_proxy_core::error::Problem;
use acme_proxy_store::account::Account;
use acme_proxy_store::db::Database;
use acme_proxy_store::job::Job;
use acme_proxy_store::order::Order;

/// What withdraws trust in a certificate.
pub enum Revoker<'a> {
    /// The backend that issued it, called inline — only ever from
    /// [`SignerRevokeJob`], in the process that holds the backend.
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
    /// A backend only the `worker` role holds — an upstream CA or an operator
    /// script: the revocation is a `signer_revoke` job, and this waits up to
    /// `wait` for its answer. The job writes the success row and the
    /// notification; a caller that stops waiting gets [`RevokeError::Pending`],
    /// and the revocation carries on without it.
    Queued { jobs: &'a JobQueue, wait: Duration },
}

impl<'a> Revoker<'a> {
    /// What a front end with no backend uses for a profile whose read side
    /// answered `route`: a local CA's ledger, or the queue.
    #[must_use]
    pub fn for_route(route: &'a RevocationRoute, jobs: &'a JobQueue, wait: Duration) -> Self {
        match route {
            RevocationRoute::Ledger { issuer } => Revoker::Ledger { issuer, jobs },
            RevocationRoute::Delegated => Revoker::Queued { jobs, wait },
        }
    }
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
    /// Queued for the worker, and not answered within the wait. The revocation
    /// carries on: asking again waits on the same job.
    #[error("the revocation is queued as job {job} and has not completed yet")]
    Pending { job: Uuid },
    /// The queued revocation was retired without revoking — its backend kept
    /// failing, or an operator cancelled it.
    #[error("the revocation failed (job {job}): {reason}")]
    Abandoned { job: Uuid, reason: String },
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
            RevokeError::Pending { .. } => {
                Problem::service_unavailable("The revocation is queued; retry to confirm it")
            }
            RevokeError::Signer(_)
            | RevokeError::Database(_)
            | RevokeError::Internal(_)
            | RevokeError::Abandoned { .. } => Problem::server_internal("Revocation failed"),
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
        let (serial_hex, _) = acme_proxy_core::cert::cert_serial_and_spki(cert_der).map_err(|error| {
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
                    .and_then(|chain| acme_proxy_core::cert::leaf_der_from_chain(chain).ok())
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
                    .with_order(order.id, order.account_id, &order.identifiers),
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
        let cert_der = acme_proxy_core::cert::leaf_der_from_chain(chain).map_err(|error| {
            RevokeError::Internal(format!("stored certificate chain is unparsable: {error}"))
        })?;
        // The stored serial where there is one, since that is the column the
        // trail is searched by; re-read from the leaf otherwise.
        let serial = match order.cert_serial.clone() {
            Some(serial) => serial,
            None => acme_proxy_core::cert::cert_serial_and_spki(&cert_der)
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
            .with_order(order.id, order.account_id, &order.identifiers)
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
            && !acme_proxy_core::cert::is_valid_revocation_reason(code)
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

        if let Revoker::Queued { jobs, wait } = self.revoker {
            // Everything past this point is the job's: its tail writes the
            // `certificate_revoked` row and the notification, from the process
            // that holds the backend.
            return self
                .revoke_through_the_queue(&order, reason, &actor, &client, jobs, wait)
                .await;
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
            Revoker::Queued { .. } => unreachable!("answered above"),
        }

        info!(event = "certificate_revoked", outcome = "success", order_id = %order.id, cert_serial = %serial_hex);
        let revoked = AuditRecord::new(AuditEvent::CertificateRevoked, &order.profile, actor)
            .with_order(order.id, order.account_id, &order.identifiers)
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
    /// The queued half of [`Revoker::Queued`]: one `signer_revoke` row for the
    /// worker, then the wait for its answer.
    ///
    /// A row already live for this order is waited on rather than duplicated —
    /// the identity index refuses a second one — so a client retrying after
    /// [`RevokeError::Pending`] follows the revocation it already started.
    async fn revoke_through_the_queue(
        &self,
        order: &Order,
        reason: Option<u32>,
        actor: &Actor,
        client: &ClientContext,
        jobs: &JobQueue,
        wait: Duration,
    ) -> Result<Order, RevokeError> {
        let id = order.id.to_string();
        jobs.enqueue(signer_revoke_spec(&id, reason, actor, client))
            .await
            .inspect_err(|error| {
                error!(event = "certificate_revoke_queue_failed", outcome = "failure", order_id = %id, error = %error);
            })?;
        let job = acme_proxy_store::job::Job::find_latest_by_dedup(
            SIGNER_REVOKE_KIND,
            &id,
            self.database,
        )
        .await?
        .ok_or_else(|| {
            RevokeError::Internal(format!("the revocation of order {id} was not queued"))
        })?;
        info!(event = "certificate_revoke_queued", outcome = "progress", order_id = %id, job_id = %job.id);

        match await_job(self.database, job.id, wait).await? {
            JobSettled::Done => Order::find_by_id(&id, self.database)
                .await?
                .ok_or(RevokeError::NotFound),
            JobSettled::Failed(reason) => Err(RevokeError::Abandoned {
                job: job.id,
                reason,
            }),
            JobSettled::Cancelled => Err(RevokeError::Abandoned {
                job: job.id,
                reason: "cancelled by an operator".to_string(),
            }),
            JobSettled::Pending => Err(RevokeError::Pending { job: job.id }),
        }
    }

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
        let revoked_at = acme_proxy_store::nonce::now_secs();
        let row = acme_proxy_store::revocation::Revocation {
            issuer: issuer.to_string(),
            serial: serial_hex.to_string(),
            revoked_at,
            reason,
            // Best-effort, as on the signer's own path: an expiry this server
            // cannot read only means the entry is never pruned.
            not_after: acme_proxy_core::cert::cert_validity(cert_der)
                .ok()
                .map(|(_, not_after)| not_after),
        };
        let written = async {
            // Immediate: this reads the CA's stored CRL and then writes on the
            // strength of it, while the worker — another process, in a split
            // deployment — may be storing a CRL for the same issuer. Deferred,
            // the upgrade would fail with `SQLITE_BUSY_SNAPSHOT` instead of
            // waiting its turn.
            let mut tx = self.database.write_transaction().await?;
            if acme_proxy_store::crl::StoredCrl::find(issuer, &mut *tx)
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

/// The `jobs.kind` of a revocation a delegating backend must perform.
pub const SIGNER_REVOKE_KIND: &str = "signer_revoke";

/// The row asking a running server to revoke order `order_id`'s certificate
/// at its backend, on behalf of `actor`.
///
/// Keyed on the order, so asking twice while the first is still queued is one
/// revocation. The payload names who asked and from where, never the
/// certificate: the row is read back when it runs, so a retry sees the order as
/// it is then, and the `certificate_revoked` row the worker writes still names
/// the client or operator whose request queued it.
#[must_use]
pub fn signer_revoke_spec(
    order_id: &str,
    reason: Option<u32>,
    actor: &Actor,
    client: &ClientContext,
) -> JobSpec {
    JobSpec::now(SIGNER_REVOKE_KIND, order_id).with_payload(serde_json::json!({
        "order_id": order_id,
        "reason": reason,
        "actor_kind": actor.kind.as_str(),
        "actor_id": actor.id,
        "client": client.to_json(),
    }))
}

/// How long a request waits for a revocation it queued: its own deadline,
/// `server.request_timeout_ms`, less a second to answer in — so a slow worker
/// is told as [`RevokeError::Pending`] rather than cut off as a timeout that
/// says nothing about the job still running.
#[must_use]
pub fn request_wait(request_timeout_ms: u64) -> Duration {
    Duration::from_millis(request_timeout_ms).saturating_sub(Duration::from_secs(1))
}

/// How a job a caller is waiting on ended, or that it has not yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobSettled {
    Done,
    /// Retired for good, with the reason its last attempt gave.
    Failed(String),
    Cancelled,
    /// Still `ready` or `running` when the wait ran out.
    Pending,
}

/// How often [`await_job`] reads the row. A worker in another process picks a
/// row up within `jobs.poll_interval_ms`, so reading faster than this would
/// only cost queries.
const AWAIT_PACE: Duration = Duration::from_millis(100);

/// Waits up to `wait` for job `id` to settle.
///
/// Shared by every front end that queues work and answers with its outcome —
/// `order revoke` from the host, the panel's revoke button, and `revokeCert`
/// for a backend only the worker holds. A job that vanished is `Failed`:
/// nothing deletes a live row, so it went with its order.
pub async fn await_job(
    database: &Database,
    id: Uuid,
    wait: Duration,
) -> Result<JobSettled, sqlx::Error> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let Some(job) = acme_proxy_store::job::Job::find_by_id(id, database).await? else {
            return Ok(JobSettled::Failed(format!("job {id} disappeared")));
        };
        match job.status.as_str() {
            "done" => return Ok(JobSettled::Done),
            "failed" => {
                return Ok(JobSettled::Failed(
                    job.last_error
                        .unwrap_or_else(|| "no reason recorded".to_string()),
                ));
            }
            "cancelled" => return Ok(JobSettled::Cancelled),
            _ if tokio::time::Instant::now() >= deadline => return Ok(JobSettled::Pending),
            _ => tokio::time::sleep(AWAIT_PACE).await,
        }
    }
}

/// Revokes, at the backend that issued it, a certificate somebody asked to
/// revoke from a process holding no backend — `revokeCert` in the `acme` role,
/// the panel in the `admin` role, the host CLI — for a `relay` or `custom`
/// profile, whose revocation is a call to an upstream CA or a script.
///
/// **One handler over every profile**, the `RelayJob` shape: a row names its
/// order, the order names its profile, and the profile names the backend.
pub struct SignerRevokeJob {
    database: Arc<Database>,
    audit: Arc<Auditor>,
    signers: Vec<(String, Arc<dyn SignerBackend>)>,
    notifiers: crate::notify::Notifiers,
}

impl SignerRevokeJob {
    /// `signers` is this generation's backend per profile name.
    #[must_use]
    pub fn new(
        database: Arc<Database>,
        audit: Arc<Auditor>,
        signers: Vec<(String, Arc<dyn SignerBackend>)>,
        notifiers: crate::notify::Notifiers,
    ) -> Self {
        Self {
            database,
            audit,
            signers,
            notifiers,
        }
    }
}

/// The actor a queued revocation names, read back out of its payload.
fn payload_actor(payload: &serde_json::Value) -> Actor {
    let id = payload["actor_id"].as_str().map(str::to_string);
    let kind = match payload["actor_kind"].as_str() {
        Some("admin") => acme_proxy_core::audit::ActorKind::Admin,
        Some("acme") => acme_proxy_core::audit::ActorKind::Acme,
        Some("system") => acme_proxy_core::audit::ActorKind::System,
        _ => acme_proxy_core::audit::ActorKind::Cli,
    };
    Actor { kind, id }
}

#[async_trait::async_trait]
impl JobHandler for SignerRevokeJob {
    fn kind(&self) -> &'static str {
        SIGNER_REVOKE_KIND
    }

    /// What is worth asking again (`Retry`): a backend that failed, a database
    /// that did, a profile this process does not mount — another process, or
    /// the next generation of this one, may. What is not (`Failed`): an order
    /// that is gone, never issued, or a reason code no backend accepts. An
    /// order already revoked is `Done`: the operator's intent holds.
    async fn run(&self, job: &Job) -> JobOutcome {
        let payload = &job.payload;
        let Some(order_id) = payload["order_id"].as_str() else {
            return JobOutcome::Failed("the payload names no order".to_string());
        };
        let reason = payload["reason"]
            .as_u64()
            .and_then(|code| u32::try_from(code).ok());

        let order = match Order::find_by_id(order_id, &self.database).await {
            Ok(Some(order)) => order,
            Ok(None) => return JobOutcome::Failed("the order no longer exists".to_string()),
            Err(error) => return JobOutcome::Retry(format!("reading the order failed: {error}")),
        };
        let Some((_, signer)) = self
            .signers
            .iter()
            .find(|(profile, _)| *profile == order.profile)
        else {
            return JobOutcome::Retry(format!(
                "profile `{}` is not mounted by this process",
                order.profile
            ));
        };
        let dispatcher = self.notifiers.get(&order.profile);
        let revocations = Revocations {
            database: &self.database,
            audit: &self.audit,
            notify: dispatcher.as_deref(),
            revoker: Revoker::Backend(signer.as_ref()),
        };
        match revocations
            .revoke_order(
                order_id,
                reason,
                payload_actor(payload),
                ClientContext::from_json(&payload["client"]),
            )
            .await
        {
            Ok(_) | Err(RevokeError::AlreadyRevoked) => JobOutcome::Done,
            Err(error @ (RevokeError::Signer(_) | RevokeError::Database(_))) => {
                JobOutcome::Retry(error.to_string())
            }
            Err(error) => JobOutcome::Failed(error.to_string()),
        }
    }

    async fn abandon(&self, job: &Job, reason: &str) {
        error!(
            event = "certificate_revoke_abandoned",
            outcome = "failure",
            order_id = %job.dedup_key,
            reason = %reason,
            "a queued revocation was given up; the certificate is still trusted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::JobHandler;
    use crate::signer::{IssueOutcome, RequestedValidity};
    use acme_proxy_core::identifier::Identifier;

    /// A backend whose `revoke` always fails.
    struct Failing;

    #[async_trait::async_trait]
    impl SignerBackend for Failing {
        async fn issue(
            &self,
            _order_id: &str,
            _csr_der: &[u8],
            _identifiers: &[Identifier],
            _validity: RequestedValidity,
        ) -> Result<IssueOutcome, SignerError> {
            Err(SignerError::Internal("not here".into()))
        }
        async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
            Err(SignerError::Internal("upstream unreachable".into()))
        }
    }

    fn handler(database: &Arc<Database>) -> SignerRevokeJob {
        SignerRevokeJob::new(
            database.clone(),
            Arc::new(Auditor::offline(database.clone())),
            vec![("default".to_string(), Arc::new(Failing))],
            std::collections::HashMap::new().into(),
        )
    }

    async fn queued(database: &Arc<Database>, order_id: &str) -> Job {
        let queue = crate::testutil::idle_job_queue(database.clone());
        queue
            .enqueue(signer_revoke_spec(
                order_id,
                None,
                &Actor::cli(),
                &ClientContext::default(),
            ))
            .await
            .unwrap();
        Job::find_live(SIGNER_REVOKE_KIND, order_id, database)
            .await
            .unwrap()
            .unwrap()
    }

    /// A backend that failed is asked again; the order stays un-revoked.
    #[tokio::test]
    async fn a_failing_backend_is_retried() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = acme_proxy_store::testutil::account_id(&database).await;
        let order = acme_proxy_store::testutil::issued_order(
            &database,
            "default",
            account,
            &["example.com"],
            30,
        )
        .await;
        let job = queued(&database, &order.id.to_string()).await;

        assert!(matches!(
            handler(&database).run(&job).await,
            JobOutcome::Retry(_)
        ));
        let stored = Order::find_by_id(&order.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.revoked_at.is_none());
    }

    /// A backend whose `revoke` always succeeds.
    struct Succeeding;

    #[async_trait::async_trait]
    impl SignerBackend for Succeeding {
        async fn issue(
            &self,
            _order_id: &str,
            _csr_der: &[u8],
            _identifiers: &[Identifier],
            _validity: RequestedValidity,
        ) -> Result<IssueOutcome, SignerError> {
            Err(SignerError::Internal("not here".into()))
        }
        async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
            Ok(())
        }
    }

    /// A queue drained by a worker running [`SignerRevokeJob`] over `backend`,
    /// with `max_attempts` of its own and no backoff. The shutdown sender comes
    /// back so the runner lives exactly as long as the test holds it.
    fn worker(
        database: &Arc<Database>,
        backend: Arc<dyn SignerBackend>,
        max_attempts: u32,
    ) -> (JobQueue, tokio::sync::watch::Sender<bool>) {
        let config = acme_proxy_core::config::JobsConfig {
            poll_interval_ms: 10,
            max_attempts,
            retry_base_seconds: 0,
            retry_max_seconds: 0,
            ..acme_proxy_core::config::JobsConfig::default()
        };
        let queue = JobQueue::new(database.clone(), &config);
        let mut registry = crate::jobs::JobRegistry::new();
        registry
            .register(Arc::new(SignerRevokeJob::new(
                database.clone(),
                Arc::new(Auditor::offline(database.clone())),
                vec![("default".to_string(), backend)],
                std::collections::HashMap::new().into(),
            )))
            .unwrap();
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        crate::jobs::spawn_runner(queue.clone(), Arc::new(registry), &config, receiver);
        (queue, shutdown)
    }

    async fn issued(database: &Arc<Database>) -> Order {
        let account = acme_proxy_store::testutil::account_id(database).await;
        acme_proxy_store::testutil::issued_order(database, "default", account, &["example.com"], 30)
            .await
    }

    fn operator_client() -> ClientContext {
        ClientContext {
            ip: Some("198.51.100.4".to_string()),
            ..ClientContext::default()
        }
    }

    /// A request in a process holding no backend queues the revocation and
    /// answers once the worker has performed it — and the one
    /// `certificate_revoked` row, written by the worker, still names who asked
    /// and from where.
    #[tokio::test]
    async fn a_queued_revocation_answers_once_the_worker_has_revoked() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = issued(&database).await;
        let (jobs, _worker) = worker(&database, Arc::new(Succeeding), 5);
        let audit = Auditor::offline(database.clone());
        let revocations = Revocations {
            database: &database,
            audit: &audit,
            notify: None,
            revoker: Revoker::Queued {
                jobs: &jobs,
                wait: Duration::from_secs(10),
            },
        };

        let revoked = revocations
            .revoke_order(
                &order.id.to_string(),
                Some(1),
                Actor::admin("root"),
                operator_client(),
            )
            .await
            .unwrap();
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoked.revocation_reason, Some(1));

        let query = acme_proxy_store::audit::AuditQuery {
            limit: 50,
            ..acme_proxy_store::audit::AuditQuery::default()
        };
        let (rows, _) = acme_proxy_store::audit::AuditEntry::search(&query, &database)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].event, "certificate_revoked");
        assert_eq!(rows[0].actor_kind, "admin");
        assert_eq!(rows[0].client_ip.as_deref(), Some("198.51.100.4"));
    }

    /// Nothing drains the queue within the wait: the caller is told the
    /// revocation is pending, not that it failed — and asking again waits on
    /// the same row rather than queueing a second.
    #[tokio::test]
    async fn an_unanswered_revocation_is_pending_and_asking_again_follows_it() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = issued(&database).await;
        let jobs = crate::testutil::idle_job_queue(database.clone());
        let audit = Auditor::offline(database.clone());
        let revocations = Revocations {
            database: &database,
            audit: &audit,
            notify: None,
            revoker: Revoker::Queued {
                jobs: &jobs,
                wait: Duration::ZERO,
            },
        };

        let mut seen = Vec::new();
        for _ in 0..2 {
            match revocations
                .revoke_order(
                    &order.id.to_string(),
                    None,
                    Actor::cli(),
                    ClientContext::default(),
                )
                .await
            {
                Err(RevokeError::Pending { job }) => seen.push(job),
                other => panic!("expected a pending revocation, got {other:?}"),
            }
        }
        assert_eq!(seen[0], seen[1], "the second ask follows the first job");
        assert_eq!(
            Job::count_live(SIGNER_REVOKE_KIND, &database)
                .await
                .unwrap(),
            1
        );
        let problem = Problem::from(RevokeError::Pending { job: seen[0] }).to_value();
        assert_eq!(problem["status"], 503);
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:serverInternal");
    }

    /// A revocation the worker gave up on is reported as the failure it was,
    /// with the job's own reason, and the order stays un-revoked.
    #[tokio::test]
    async fn a_revocation_the_worker_gave_up_on_is_abandoned() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = issued(&database).await;
        let (jobs, _worker) = worker(&database, Arc::new(Failing), 1);
        let audit = Auditor::offline(database.clone());
        let revocations = Revocations {
            database: &database,
            audit: &audit,
            notify: None,
            revoker: Revoker::Queued {
                jobs: &jobs,
                wait: Duration::from_secs(10),
            },
        };

        let error = revocations
            .revoke_order(
                &order.id.to_string(),
                None,
                Actor::cli(),
                ClientContext::default(),
            )
            .await
            .unwrap_err();
        let RevokeError::Abandoned { reason, .. } = &error else {
            panic!("expected an abandoned revocation, got {error:?}")
        };
        assert!(reason.contains("upstream unreachable"), "{reason}");
        assert_eq!(
            Problem::from(error).to_value()["detail"],
            "Revocation failed"
        );
        let stored = Order::find_by_id(&order.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.revoked_at.is_none());
    }

    /// An operator cancelling the queued row is an answer too, and a row that
    /// vanished is a failure — neither leaves the caller waiting out its time.
    #[tokio::test]
    async fn a_cancelled_or_vanished_job_settles_the_wait() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = issued(&database).await;
        let job = queued(&database, &order.id.to_string()).await;
        Job::cancel_row(
            job.id,
            acme_proxy_store::status::JobStatus::Ready,
            &database,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            await_job(&database, job.id, Duration::from_secs(10))
                .await
                .unwrap(),
            JobSettled::Cancelled
        );
        let JobSettled::Failed(reason) = await_job(
            &database,
            acme_proxy_store::id::mint(),
            Duration::from_secs(10),
        )
        .await
        .unwrap() else {
            panic!("a job that is not there has failed")
        };
        assert!(reason.contains("disappeared"), "{reason}");
    }

    /// Each route picks its revoker, and a request waits a second less than its
    /// own deadline so it can still answer.
    #[tokio::test]
    async fn the_route_picks_the_revoker_and_the_wait_fits_the_deadline() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let jobs = crate::testutil::idle_job_queue(database);
        let ledger = RevocationRoute::Ledger {
            issuer: "ab".to_string(),
        };
        assert!(matches!(
            Revoker::for_route(&ledger, &jobs, Duration::ZERO),
            Revoker::Ledger { issuer: "ab", .. }
        ));
        assert!(matches!(
            Revoker::for_route(&RevocationRoute::Delegated, &jobs, Duration::from_secs(3)),
            Revoker::Queued { wait, .. } if wait == Duration::from_secs(3)
        ));
        assert_eq!(request_wait(60_000), Duration::from_secs(59));
        assert_eq!(request_wait(500), Duration::ZERO);
    }

    /// An order that is gone will not come back: retrying is pointless.
    #[tokio::test]
    async fn a_vanished_order_fails_for_good() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let job = queued(&database, &acme_proxy_store::id::mint().to_string()).await;
        assert!(matches!(
            handler(&database).run(&job).await,
            JobOutcome::Failed(_)
        ));
    }
}
