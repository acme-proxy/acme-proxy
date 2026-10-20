//! What happens once a chain exists: storing it on its order, announcing it,
//! and recording a failure to get one.
//!
//! Shared by the `signer_issue` job (`acme::issue`) and the relay
//! ([`crate::relay`]), which receives its chain from the upstream long
//! after the request that asked has returned. Here, beside the backends, rather
//! than in the ACME services above them, since the relay is one of the two
//! callers and sits below those services.

use acme_proxy_core::error::Problem;
use acme_proxy_jobs::auditor::Auditor;
use acme_proxy_jobs::notify::NotifyEvent;
use acme_proxy_store::db::Database;
use acme_proxy_store::order::Order;

/// Why an issued chain could not be recorded on its order.
///
/// Three cases a caller answers differently: a chain or leaf this server cannot
/// read is a certificate it cannot revoke, where a failed write is a retry.
#[derive(Debug)]
pub enum IssuanceError {
    /// No certificate could be read out of the chain.
    Chain(String),
    /// The leaf did not yield a serial and a public key.
    Leaf(String),
    /// The order row could not be written.
    Persist(sqlx::Error),
}

/// Stores an issued `chain` on `order`, returning the leaf's serial.
///
/// Shared by `finalize` and by the relay, which receives its chain from the
/// upstream long after the request that asked has returned. Logs nothing: the
/// two callers name the same failure differently, and those names are what an
/// operator greps for.
pub async fn record_issuance(
    order: &mut Order,
    chain: String,
    database: &Database,
) -> Result<String, IssuanceError> {
    let leaf_der = acme_proxy_core::cert::leaf_der_from_chain(&chain)
        .map_err(|error| IssuanceError::Chain(error.to_string()))?;
    let (cert_serial, cert_pubkey) = acme_proxy_core::cert::cert_serial_and_spki(&leaf_der)
        .map_err(|error| IssuanceError::Leaf(error.to_string()))?;

    // Best-effort, unlike the two above: the serial and the public key are
    // what make this certificate revocable, so a chain they cannot be read
    // from is a failed issuance, while the expiry is housekeeping for the
    // expiry digest. A leaf whose validity will not parse is still an issued
    // certificate, and the digest's own sweep will try again later.
    let cert_not_after = acme_proxy_core::cert::not_after(&leaf_der);

    order
        .finalize(
            chain,
            cert_serial.clone(),
            cert_pubkey,
            cert_not_after,
            database,
        )
        .await
        .map_err(IssuanceError::Persist)?;
    Ok(cert_serial)
}

/// Writes the `certificate_issued` audit row for an order
/// [`record_issuance`] stored, then queues `certificate_issued`.
///
/// `actor`/`client` name who asked: the account and its request on the
/// synchronous path, whatever the relay parked on `upstream_orders` on the
/// deferred one. `client_ip` is the notification's own rendering of that
/// address, `None` where no request is in scope. `notify` is `None` when the
/// order's profile has no dispatcher in this process.
///
/// `requested_at` is when the finalize was accepted, in Unix seconds: the
/// `created_at` of the job the caller is running, which the finalize request
/// enqueued. It times `acme_proxy_certificate_issue_duration_seconds`.
#[allow(clippy::too_many_arguments)]
pub async fn announce_issuance(
    order: &Order,
    serial: &str,
    requested_at: i64,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    client_ip: Option<String>,
    audit: &Auditor,
    notify: Option<&acme_proxy_jobs::notify::NotifyDispatcher>,
) {
    audit
        .record(
            acme_proxy_core::audit::AuditRecord::new(
                acme_proxy_core::audit::AuditEvent::CertificateIssued,
                &order.profile,
                actor,
            )
            .with_order(order.id, order.account_id, &order.identifiers)
            .with_client(client)
            .with_serial(serial),
        )
        .await;
    let elapsed = acme_proxy_store::nonce::now_secs().saturating_sub(requested_at);
    audit.observe_issuance(
        &order.profile,
        std::time::Duration::from_secs(u64::try_from(elapsed).unwrap_or(0)),
    );
    if let Some(dispatcher) = notify {
        dispatcher
            .dispatch(NotifyEvent::CertificateIssued(
                acme_proxy_jobs::notify::CertificateIssuedData {
                    profile: order.profile.clone(),
                    order_id: order.id.to_string(),
                    account_id: order.account_id.to_string(),
                    cert_serial: serial.to_string(),
                    identifiers: order.identifiers.iter().map(|i| i.value.clone()).collect(),
                    client_ip,
                },
            ))
            .await;
    }
}

/// The `certificate_issue_failed` row for `order`: who asked, from where, the
/// RFC 8555 problem type it failed with (`reason`) and what the operator should
/// read (`detail`).
///
/// The one builder for that row. `finalize`'s refusals record it with no order
/// change behind it, and [`fail_order`] with one.
pub fn issue_failed_record(
    order: &Order,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    reason: &str,
    detail: &str,
) -> acme_proxy_core::audit::AuditRecord {
    acme_proxy_core::audit::AuditRecord::new(
        acme_proxy_core::audit::AuditEvent::CertificateIssueFailed,
        &order.profile,
        actor,
    )
    .with_order(order.id, order.account_id, &order.identifiers)
    .with_client(client)
    .with_reason(reason)
    .with_detail(detail)
}

/// Retires an order whose issuance failed: the order `invalid` with `problem`
/// as the document its client reads, then one `certificate_issue_failed` row
/// naming `reason` and `detail`. Answers whether the order took it.
///
/// The row only when the write happened. A guarded write that finds the order
/// already decided by someone else — a redelivered job whose first attempt got
/// there, an operator who cancelled it — leaves it be, and recording a failure
/// for it would put an issuance failure in the trail of an order that did not
/// fail here. Written before the row, so a retry after a failed write does not
/// record the failure twice.
///
/// The client's document and the trail's detail are separate on purpose: what
/// went wrong upstream or in a signer is for the operator, and the client is
/// told only what RFC 8555 says it may be.
#[allow(clippy::too_many_arguments)]
pub async fn fail_order(
    order: &mut Order,
    problem: &Problem,
    reason: &str,
    detail: &str,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    audit: &Auditor,
    database: &Database,
) -> Result<bool, sqlx::Error> {
    if !order.mark_invalid(problem.to_value(), database).await? {
        return Ok(false);
    }
    audit
        .record(issue_failed_record(order, actor, client, reason, detail))
        .await;
    Ok(true)
}

/// [`fail_order`] for an issuance that failed on the server's side — a signer
/// or an upstream that never answered — which the client sees as
/// `serverInternal`.
pub async fn record_issue_failure(
    order: &mut Order,
    problem: &Problem,
    detail: &str,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    audit: &Auditor,
    database: &Database,
) -> Result<(), sqlx::Error> {
    fail_order(
        order,
        problem,
        "serverInternal",
        detail,
        actor,
        client,
        audit,
        database,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::audit::{Actor, ClientContext};
    use acme_proxy_store::testutil;
    use std::sync::Arc;

    async fn audit_rows(database: &Database) -> i64 {
        acme_proxy_store::audit::AuditEntry::search(&Default::default(), database)
            .await
            .unwrap()
            .1
    }

    /// The trail records a failure only for the order it actually retired: a
    /// second retirement of the same order — a redelivered job — finds it
    /// decided and writes nothing.
    #[tokio::test]
    async fn an_order_already_decided_gets_no_second_failure_row() {
        let database = Arc::new(Database::connect_for_test().await.unwrap());
        let audit = Auditor::offline(database.clone());
        let account_id = testutil::account_id(&database).await;
        let mut order = Order::create(
            "default",
            account_id,
            testutil::dns_identifiers(&["example.com"]),
            4_102_444_800,
            None,
            None,
            &database,
        )
        .await
        .unwrap();
        let problem = Problem::server_internal("Certificate issuance failed");

        for _ in 0..2 {
            record_issue_failure(
                &mut order,
                &problem,
                "the signer refused",
                Actor::acme(account_id),
                ClientContext::default(),
                &audit,
                &database,
            )
            .await
            .unwrap();
        }

        assert_eq!(audit_rows(&database).await, 1);
    }
}
