//! Certificate issuance as queued work.
//!
//! `finalize` checks the CSR, claims the order (`ready → processing`) and queues
//! one of these rows **in the same transaction**; the job runner asks the
//! backend to sign. RFC 8555 §7.4 already has the state this needs — an order is
//! `processing` while "the certificate is being issued", and the client polls —
//! and the `relay` backend has always answered that way.
//!
//! The point is where the key lives, not latency. Signing needs `ca.key`, a
//! PKCS#11 login or a relay's upstream account, and only the `worker` role
//! builds a backend, so the process parsing untrusted JWS and CSRs never holds
//! one. This is the one place a backend is asked to issue.
//!
//! **One handler over every profile**, the [`SignerRevokeJob`] shape: a row names
//! its order, the order names its profile, and the profile names the backend.
//!
//! How each answer settles the row:
//!
//! | Backend answer | Order | Job |
//! |---|---|---|
//! | a chain | `valid`, `certificate_issued`, notified | `Done` |
//! | a chain this server cannot read | `invalid` via `abandon` | `Failed` |
//! | a chain it could not store | unchanged | `Retry` |
//! | `Processing` (relay) | unchanged — the relay job owns it | `Done` |
//! | `BadCsr` | `invalid` with `badCSR` — a verdict | `Done` |
//! | `Internal` | unchanged | `Retry`, then `invalid` via `abandon` |
//!
//! `BadCsr` makes the order `invalid` rather than `ready` again, although §7.4
//! says a rejected CSR SHOULD leave it finalizable: the client was already told
//! `processing`, and certbot, acme.sh and lego all poll for `valid` or
//! `invalid` — an order back at `ready` would have them poll until they time
//! out, with no error to show. `finalize` still runs the CSR/order match and the
//! filter itself, so almost every bad CSR is still refused synchronously, with
//! the order left `ready`.
//!
//! [`SignerRevokeJob`]: super::revoke::SignerRevokeJob

use std::net::IpAddr;
use std::sync::Arc;

use base64::prelude::*;
use tracing::{error, info, warn};

use acme_proxy_core::audit::Actor;
use acme_proxy_core::audit::AuditEvent;
use acme_proxy_core::audit::AuditRecord;
use acme_proxy_core::audit::ClientContext;
use acme_proxy_core::error::Problem;
use acme_proxy_jobs::auditor::Auditor;
use acme_proxy_jobs::jobs::JobHandler;
use acme_proxy_jobs::jobs::JobOutcome;
use acme_proxy_jobs::jobs::JobSpec;
use acme_proxy_signer::IssueOutcome;
use acme_proxy_signer::RequestedValidity;
use acme_proxy_signer::SignerBackend;
use acme_proxy_signer::SignerError;
use acme_proxy_signer::issuance::IssuanceError;
use acme_proxy_signer::issuance::announce_issuance;
use acme_proxy_signer::issuance::record_issuance;
use acme_proxy_signer::issuance::record_issue_failure;
use acme_proxy_store::db::Database;
use acme_proxy_store::job::Job;
use acme_proxy_store::order::Order;
use acme_proxy_store::status::OrderStatus;

/// The `jobs.kind` one issuance is queued under.
pub const SIGNER_ISSUE_KIND: &str = "signer_issue";

/// The row asking a worker to issue the certificate `order` was just claimed
/// for.
///
/// Keyed on the order, so the claim and the job identity are the same fact
/// twice: the partial unique index refuses a second live row exactly as the
/// `ready → processing` CAS refuses a second claim.
///
/// The CSR travels in the payload — it is public material, and the order row
/// has no column for it — beside the two views of the client that asked:
/// `client` is the audit row's context (address, reverse name, User-Agent,
/// request id), `client_ip` the notification's rendering of the address, the
/// same split `finalize` made when it answered inline. `deadline` is the
/// order's own `expires`: past it the order is refused on read, so a
/// certificate issued afterwards could never be collected.
#[must_use]
pub fn signer_issue_spec(
    order: &Order,
    csr_der: &[u8],
    client: &ClientContext,
    client_ip: Option<IpAddr>,
) -> JobSpec {
    JobSpec::now(SIGNER_ISSUE_KIND, order.id.to_string())
        .with_payload(serde_json::json!({
            "order_id": order.id.to_string(),
            "profile": order.profile,
            "csr": BASE64_URL_SAFE_NO_PAD.encode(csr_der),
            "client": client.to_json(),
            "client_ip": client_ip.map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
        }))
        .with_deadline(Some(order.expires))
}

/// Issues the certificate a finalize request queued, at the backend of the
/// order's profile.
pub struct SignerIssueJob {
    database: Arc<Database>,
    audit: Arc<Auditor>,
    signers: Vec<(String, Arc<dyn SignerBackend>)>,
    notifiers: acme_proxy_jobs::notify::Notifiers,
}

impl SignerIssueJob {
    /// `signers` is this generation's backend per profile name — empty in a
    /// process that runs no worker, which never claims a row.
    #[must_use]
    pub fn new(
        database: Arc<Database>,
        audit: Arc<Auditor>,
        signers: Vec<(String, Arc<dyn SignerBackend>)>,
        notifiers: acme_proxy_jobs::notify::Notifiers,
    ) -> Self {
        Self {
            database,
            audit,
            signers,
            notifiers,
        }
    }

    fn signer(&self, profile: &str) -> Option<&Arc<dyn SignerBackend>> {
        self.signers
            .iter()
            .find(|(mounted, _)| mounted == profile)
            .map(|(_, signer)| signer)
    }
}

/// The client a row names, read back out of its payload.
fn payload_client(job: &Job) -> ClientContext {
    ClientContext::from_json(&job.payload["client"])
}

#[async_trait::async_trait]
impl JobHandler for SignerIssueJob {
    fn kind(&self) -> &'static str {
        SIGNER_ISSUE_KIND
    }

    async fn run(&self, job: &Job) -> JobOutcome {
        let payload = &job.payload;
        let Some(order_id) = payload["order_id"].as_str() else {
            return JobOutcome::Failed("the payload names no order".to_string());
        };
        let Some(csr_der) = payload["csr"]
            .as_str()
            .and_then(|csr| BASE64_URL_SAFE_NO_PAD.decode(csr).ok())
        else {
            return JobOutcome::Failed("the payload carries no readable CSR".to_string());
        };
        let mut order = match Order::find_by_id(order_id, &self.database).await {
            Ok(Some(order)) => order,
            Ok(None) => return JobOutcome::Failed("the order no longer exists".to_string()),
            Err(error) => return JobOutcome::Retry(format!("reading the order failed: {error}")),
        };
        // Settled already — the row was redelivered after a lost lease — or
        // demoted by a §7.5.2 deactivation since it was claimed. Either way
        // there is nothing left for this row to issue.
        if order.status != OrderStatus::Processing {
            return JobOutcome::Done;
        }
        let Some(signer) = self.signer(&order.profile) else {
            return JobOutcome::Retry(format!(
                "profile `{}` is not mounted by this process",
                order.profile
            ));
        };

        let client = payload_client(job);
        // The order's own `notBefore`/`notAfter` (RFC 8555 §7.4), which the
        // order object has always echoed back. The backend clamps or ignores
        // them; see `RequestedValidity`.
        let validity = RequestedValidity {
            not_before: order.not_before,
            not_after: order.not_after,
        };
        let issued = signer
            .issue(order_id, &csr_der, &order.identifiers, validity)
            .await;

        match issued {
            Ok(IssueOutcome::Issued(chain)) => {
                match record_issuance(&mut order, chain, &self.database).await {
                    Ok(serial) => {
                        info!(event = "order_finalized", outcome = "success", order_id = %order_id, cert_serial = %serial);
                        let dispatcher = self.notifiers.get(&order.profile);
                        announce_issuance(
                            &order,
                            &serial,
                            job.created_at,
                            Actor::acme(order.account_id.to_string()),
                            client,
                            payload["client_ip"].as_str().map(str::to_string),
                            &self.audit,
                            dispatcher.as_deref(),
                        )
                        .await;
                        JobOutcome::Done
                    }
                    // A certificate this server cannot read is one it cannot
                    // revoke, and signing again produces another it cannot read:
                    // the issuance failed, whoever retries it.
                    Err(IssuanceError::Chain(error)) => {
                        error!(event = "order_finalize_chain_unparsable", outcome = "failure", order_id = %order_id, error = %error);
                        JobOutcome::Failed(format!("the issued chain is unparsable: {error}"))
                    }
                    Err(IssuanceError::Leaf(error)) => {
                        error!(event = "order_finalize_leaf_unparsable", outcome = "failure", order_id = %order_id, error = %error);
                        JobOutcome::Failed(format!("the issued certificate is unparsable: {error}"))
                    }
                    // A retry signs again, and the certificate this attempt
                    // produced sits in no row — as it always did when this write
                    // failed inline. The order is still `processing`, so the
                    // retry is the only way it ever gets one.
                    Err(IssuanceError::Persist(error)) => {
                        error!(
                            event = "order_finalize_persistence_failed",
                            outcome = "failure",
                            order_id = %order_id,
                            error = %error
                        );
                        JobOutcome::Retry(format!("recording the certificate failed: {error}"))
                    }
                }
            }
            // A delegating backend took the CSR and resolves it elsewhere: the
            // relay job owns the order from here, and writes the one audit row
            // for this issuance when the upstream answers. It runs with no
            // request in scope, so the client that asked is parked on the
            // mapping row for it — see `UpstreamOrder::set_client`.
            Ok(IssueOutcome::Processing) => {
                if let Err(error) = acme_proxy_store::upstream_order::UpstreamOrder::set_client(
                    order_id,
                    &client,
                    &self.database,
                )
                .await
                {
                    warn!(
                        event = "upstream_order_client_context_failed",
                        outcome = "failure",
                        order_id = %order_id,
                        error = %error
                    );
                }
                info!(event = "order_finalize_delegated", outcome = "success", order_id = %order_id);
                JobOutcome::Done
            }
            // The backend's verdict on the CSR: the order's answer, recorded
            // once. Marked before the row is written, so a retry after a failed
            // write does not audit the refusal twice.
            Err(SignerError::BadCsr) => {
                warn!(event = "order_finalize_bad_csr", outcome = "failure", order_id = %order_id);
                let problem = Problem::bad_csr("CSR invalid or does not match order");
                if let Err(error) = order.mark_invalid(problem.to_value(), &self.database).await {
                    error!(event = "order_mark_invalid_failed", outcome = "failure", order_id = %order_id, error = %error);
                    return JobOutcome::Retry(format!("recording the refusal failed: {error}"));
                }
                self.audit
                    .record(
                        AuditRecord::new(
                            AuditEvent::CertificateIssueFailed,
                            &order.profile,
                            Actor::acme(order.account_id),
                        )
                        .with_order(order.id, order.account_id, &order.identifiers)
                        .with_client(client)
                        .with_reason("badCSR")
                        .with_detail("the signer backend rejected the CSR"),
                    )
                    .await;
                JobOutcome::Done
            }
            // Nothing decided anything about this CSR — a token, a script or
            // an upstream that did not answer — so ask again, and let `abandon`
            // retire the order once the budget is spent.
            Err(SignerError::Internal(detail)) => {
                error!(
                    event = "order_finalize_issuance_failed",
                    outcome = "failure",
                    order_id = %order_id,
                    detail = %detail
                );
                JobOutcome::Retry(detail)
            }
        }
    }

    /// The attempts ran out, the order expired under it, or the row could never
    /// settle. An order left `processing` would be polled by its client until
    /// it expired, saying nothing: record the failure instead, exactly once.
    async fn abandon(&self, job: &Job, reason: &str) {
        let Some(order_id) = job.payload["order_id"].as_str() else {
            return;
        };
        warn!(
            event = "order_finalize_abandoned",
            outcome = "failure",
            order_id = %order_id,
            attempts = job.attempts,
            reason = %reason,
            "a queued issuance was given up; its order is marked invalid"
        );
        let mut order = match Order::find_by_id(order_id, &self.database).await {
            Ok(Some(order)) if order.status == OrderStatus::Processing => order,
            Ok(_) => return,
            Err(error) => {
                error!(event = "order_mark_invalid_failed", outcome = "failure", order_id = %order_id, error = %error);
                return;
            }
        };
        let account = order.account_id;
        if let Err(error) = record_issue_failure(
            &mut order,
            &Problem::server_internal("Certificate issuance failed"),
            reason,
            Actor::acme(account),
            payload_client(job),
            &self.audit,
            &self.database,
        )
        .await
        {
            error!(event = "order_mark_invalid_failed", outcome = "failure", order_id = %order_id, error = %error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::order::tests::{account, ready_order};
    use acme_proxy_core::identifier::Identifier;

    /// A signer answering `issue` with whatever the test set.
    enum Answer {
        BadCsr,
        Internal,
        Chain(&'static str),
        Deferred,
    }

    struct Scripted(Answer);

    #[async_trait::async_trait]
    impl SignerBackend for Scripted {
        async fn issue(
            &self,
            _order_id: &str,
            _csr_der: &[u8],
            _identifiers: &[Identifier],
            _validity: RequestedValidity,
        ) -> Result<IssueOutcome, SignerError> {
            match &self.0 {
                Answer::BadCsr => Err(SignerError::BadCsr),
                Answer::Internal => Err(SignerError::Internal("the token is gone".into())),
                Answer::Chain(chain) => Ok(IssueOutcome::Issued((*chain).to_string())),
                Answer::Deferred => Ok(IssueOutcome::Processing),
            }
        }

        async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
            Ok(())
        }
    }

    fn client() -> ClientContext {
        ClientContext {
            ip: Some("203.0.113.9".to_string()),
            ptr: Some("client.example.net".to_string()),
            user_agent: Some("certbot/9".to_string()),
            request_id: Some("req-1".to_string()),
        }
    }

    /// A `processing` order, as `finalize` leaves it, and the row it queued.
    async fn claimed(database: &Arc<Database>) -> (Order, Job) {
        let account = account(database).await;
        let (mut order, csr) = ready_order(database, &account).await;
        assert!(order.claim_for_finalize(database).await.unwrap());
        let spec = signer_issue_spec(
            &order,
            &BASE64_URL_SAFE_NO_PAD.decode(csr).unwrap(),
            &client(),
            Some("203.0.113.9".parse().unwrap()),
        );
        let job = Job {
            kind: SIGNER_ISSUE_KIND.to_string(),
            dedup_key: spec.key.clone(),
            payload: spec.payload.clone(),
            ..acme_proxy_store::testutil::job_fixture()
        };
        (order, job)
    }

    fn handler(database: &Arc<Database>, signer: Arc<dyn SignerBackend>) -> SignerIssueJob {
        let (_tx, notifiers) = acme_proxy_jobs::notify::notifiers_channel(
            acme_proxy_jobs::notify::DispatcherMap::new(),
        );
        SignerIssueJob::new(
            database.clone(),
            Arc::new(Auditor::offline(database.clone())),
            vec![("default".to_string(), signer)],
            notifiers,
        )
    }

    async fn reload(database: &Database, order: &Order) -> Order {
        Order::find_by_id(&order.id.to_string(), database)
            .await
            .unwrap()
            .unwrap()
    }

    async fn audit_rows(database: &Database) -> Vec<acme_proxy_store::audit::AuditEntry> {
        let query = acme_proxy_store::audit::AuditQuery {
            limit: 50,
            ..acme_proxy_store::audit::AuditQuery::default()
        };
        acme_proxy_store::audit::AuditEntry::search(&query, database)
            .await
            .unwrap()
            .0
    }

    /// The worker signs: the order becomes `valid` with its certificate, and
    /// the one `certificate_issued` row names the client that finalized — not
    /// the worker, which has no request of its own.
    #[tokio::test]
    async fn a_signed_certificate_settles_the_order_and_names_the_client() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (order, job) = claimed(&database).await;
        let ca = acme_proxy_signer::local_ca::LocalCa::generate_in_memory(
            "ecdsa-p256",
            90,
            database.clone(),
        )
        .unwrap();

        assert!(matches!(
            handler(&database, Arc::new(ca)).run(&job).await,
            JobOutcome::Done
        ));
        let stored = reload(&database, &order).await;
        assert_eq!(stored.status, OrderStatus::Valid);
        assert!(stored.certificate.is_some());

        let rows = audit_rows(&database).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].event, "certificate_issued");
        assert_eq!(rows[0].cert_serial, stored.cert_serial);
        assert_eq!(rows[0].client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(rows[0].client_ptr.as_deref(), Some("client.example.net"));
        assert_eq!(rows[0].request_id.as_deref(), Some("req-1"));
    }

    /// The backend's own CSR verdict is the order's answer: `invalid` with a
    /// `badCSR` document the polling client reads, one row, and no retry.
    #[tokio::test]
    async fn a_csr_the_backend_rejects_invalidates_the_order_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (order, job) = claimed(&database).await;

        assert!(matches!(
            handler(&database, Arc::new(Scripted(Answer::BadCsr)))
                .run(&job)
                .await,
            JobOutcome::Done
        ));
        let stored = reload(&database, &order).await;
        assert_eq!(stored.status, OrderStatus::Invalid);
        let error = stored.error.unwrap();
        assert_eq!(error["type"], "urn:ietf:params:acme:error:badCSR");
        assert_eq!(error["detail"], "CSR invalid or does not match order");

        let rows = audit_rows(&database).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "certificate_issue_failed");
        assert_eq!(rows[0].reason.as_deref(), Some("badCSR"));
        assert_eq!(rows[0].client_ip.as_deref(), Some("203.0.113.9"));
    }

    /// A backend that did not answer decided nothing: the job retries and the
    /// order stays `processing`. Only `abandon` — once the budget is spent —
    /// retires it, with one row carrying the backend's own reason.
    #[tokio::test]
    async fn a_backend_failure_retries_and_is_abandoned_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (order, job) = claimed(&database).await;
        let handler = handler(&database, Arc::new(Scripted(Answer::Internal)));

        let JobOutcome::Retry(reason) = handler.run(&job).await else {
            panic!("an internal failure is retried")
        };
        assert_eq!(reason, "the token is gone");
        assert_eq!(
            reload(&database, &order).await.status,
            OrderStatus::Processing
        );
        assert!(audit_rows(&database).await.is_empty());

        handler.abandon(&job, &reason).await;
        let stored = reload(&database, &order).await;
        assert_eq!(stored.status, OrderStatus::Invalid);
        assert_eq!(
            stored.error.unwrap()["detail"],
            "Certificate issuance failed"
        );
        let rows = audit_rows(&database).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("serverInternal"));
        assert_eq!(rows[0].detail.as_deref(), Some("the token is gone"));

        // A second retirement — a redelivered row — finds nothing to do.
        handler.abandon(&job, &reason).await;
        assert_eq!(audit_rows(&database).await.len(), 1);
    }

    /// A chain this server cannot read is a certificate it could never
    /// revoke, and signing again would produce another: the row fails for good.
    #[tokio::test]
    async fn an_unreadable_chain_fails_the_row() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (order, job) = claimed(&database).await;

        let outcome = handler(&database, Arc::new(Scripted(Answer::Chain("not a chain"))))
            .run(&job)
            .await;
        let JobOutcome::Failed(reason) = outcome else {
            panic!("an unreadable chain is permanent")
        };
        assert!(reason.contains("unparsable"), "{reason}");
        let stored = reload(&database, &order).await;
        assert!(stored.certificate.is_none());
    }

    /// A delegating backend owns the order from here: the row is done, the
    /// order still `processing` for the relay to settle.
    #[tokio::test]
    async fn a_deferred_issuance_leaves_the_order_to_its_backend() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (order, job) = claimed(&database).await;

        assert!(matches!(
            handler(&database, Arc::new(Scripted(Answer::Deferred)))
                .run(&job)
                .await,
            JobOutcome::Done
        ));
        assert_eq!(
            reload(&database, &order).await.status,
            OrderStatus::Processing
        );
        assert!(audit_rows(&database).await.is_empty());
    }

    /// A redelivered row whose order already settled, or was demoted by a
    /// deactivation since, signs nothing.
    #[tokio::test]
    async fn an_order_no_longer_processing_is_not_issued_again() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (mut order, job) = claimed(&database).await;
        order.mark_pending(&database).await.unwrap();

        assert!(matches!(
            handler(&database, Arc::new(Scripted(Answer::Internal)))
                .run(&job)
                .await,
            JobOutcome::Done
        ));
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Pending);
    }

    /// A profile this process does not mount is a question for another
    /// process — or the next generation of this one — so it is asked again;
    /// a row that cannot be read is not.
    #[tokio::test]
    async fn an_unmounted_profile_retries_and_a_broken_row_fails() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let (_, job) = claimed(&database).await;
        let (_tx, notifiers) = acme_proxy_jobs::notify::notifiers_channel(
            acme_proxy_jobs::notify::DispatcherMap::new(),
        );
        let elsewhere = SignerIssueJob::new(
            database.clone(),
            Arc::new(Auditor::offline(database.clone())),
            Vec::new(),
            notifiers,
        );
        assert!(matches!(elsewhere.run(&job).await, JobOutcome::Retry(_)));

        for payload in [
            serde_json::json!({}),
            serde_json::json!({ "order_id": job.payload["order_id"], "csr": "!!" }),
            serde_json::json!({ "order_id": uuid::Uuid::nil().to_string(), "csr": "MAA" }),
        ] {
            let broken = Job {
                payload,
                ..job.clone()
            };
            assert!(matches!(
                elsewhere.run(&broken).await,
                JobOutcome::Failed(_)
            ));
        }
        // `abandon` on a row naming no order has nothing to retire.
        elsewhere
            .abandon(
                &Job {
                    payload: serde_json::json!({}),
                    ..job
                },
                "gone",
            )
            .await;
    }
}
