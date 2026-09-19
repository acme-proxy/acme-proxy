//! What happens once a chain exists: storing it on its order, announcing it,
//! and recording a failure to get one.
//!
//! Shared by the `signer_issue` job ([`crate::acme::issue`]) and the relay
//! ([`crate::signer::relay`]), which receives its chain from the upstream long
//! after the request that asked has returned. Here, beside the backends, rather
//! than in the ACME services above them, since the relay is one of the two
//! callers and sits below those services.

use crate::auditor::Auditor;
use crate::notify::NotifyEvent;
use acme_proxy_core::error::Problem;
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
    let cert_not_after = acme_proxy_core::cert::cert_validity(&leaf_der)
        .ok()
        .map(|(_, not_after)| not_after);

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
pub async fn announce_issuance(
    order: &Order,
    serial: &str,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    client_ip: Option<String>,
    audit: &Auditor,
    notify: Option<&crate::notify::NotifyDispatcher>,
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
    if let Some(dispatcher) = notify {
        dispatcher
            .dispatch(NotifyEvent::CertificateIssued(
                crate::notify::CertificateIssuedData {
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

/// Retires an order whose issuance failed for good: one
/// `certificate_issue_failed` row naming `detail`, then the order `invalid`
/// with `problem` as the document its client reads.
///
/// The client's document and the trail's detail are separate on purpose: what
/// went wrong upstream or in a signer is for the operator, and the client is
/// told only that issuance failed.
pub async fn record_issue_failure(
    order: &mut Order,
    problem: &Problem,
    detail: &str,
    actor: acme_proxy_core::audit::Actor,
    client: acme_proxy_core::audit::ClientContext,
    audit: &Auditor,
    database: &Database,
) -> Result<(), sqlx::Error> {
    audit
        .record(
            acme_proxy_core::audit::AuditRecord::new(
                acme_proxy_core::audit::AuditEvent::CertificateIssueFailed,
                &order.profile,
                actor,
            )
            .with_order(order.id, order.account_id, &order.identifiers)
            .with_client(client)
            .with_reason("serverInternal")
            .with_detail(detail),
        )
        .await;
    order.mark_invalid(problem.to_value(), database).await
}
