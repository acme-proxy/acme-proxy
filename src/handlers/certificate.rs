use axum::{
    Extension,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use serde::Deserialize;
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;
use crate::error::Problem;
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest};
use crate::filter::ClientIp;
use crate::handlers::helpers::load_owned_order;
use crate::notify::{CertificateRevokedData, NotifyEvent};
use crate::sqlite::{account::Account, order::Order};

/// A revokeCert payload (RFC 8555 §7.6).
#[derive(Debug, Deserialize)]
pub struct RevokeCertPayload {
    pub certificate: String,
    pub reason: Option<u32>,
}

/// Returns the issued certificate chain via POST-as-GET (RFC 8555 §7.4.2).
#[instrument(name = "post_certificate", skip_all, fields(order_id = %id))]
pub async fn post_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AcmePostAsGet {
        pubkey, account, ..
    }: AcmePostAsGet,
) -> Result<Response, Problem> {
    info!(
        event = "certificate_request_processed",
        outcome = "success",
        order_id = %id
    );
    let AppState {
        database, profile, ..
    } = state;

    let account =
        crate::handlers::helpers::signer_account(account, &profile.name, &pubkey, &database)
            .await?;
    let order = load_owned_order(&id, &account, &database).await?;

    match order.certificate {
        Some(pem) => {
            info!(
                event = "certificate_served",
                outcome = "success",
                order_id = %id
            );
            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
                pem,
            )
                .into_response())
        }
        None => {
            debug!(event = "certificate_not_ready", outcome = "failure", order_id = %id, status = %order.status);
            Err(Problem::malformed("Certificate not ready"))
        }
    }
}

/// Handles ACME certificate revocation (RFC 8555 §7.6).
#[instrument(name = "post_revoke_cert", skip_all)]
pub async fn post_revoke_cert(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: crate::audit::RequestContext,
    AcmeRequest {
        payload,
        pubkey,
        account,
        ..
    }: AcmeRequest<RevokeCertPayload>,
) -> Result<Response, Problem> {
    info!(event = "certificate_revoke_requested", outcome = "progress",);
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let signer = &profile.signer;

    let cert_der = BASE64_URL_SAFE_NO_PAD
        .decode(&payload.certificate)
        .map_err(|_| {
            warn!(
                event = "certificate_revoke_base64_invalid",
                outcome = "failure",
                certificate_b64_chars = payload.certificate.len()
            );
            Problem::malformed("certificate base64 invalid")
        })?;
    let (serial_hex, _) = crate::cert::cert_serial_and_spki(&cert_der).map_err(|error| {
        warn!(event = "certificate_revoke_parse_failed", outcome = "failure", error = %error);
        Problem::malformed("certificate is unparsable")
    })?;

    let order = Order::find_by_cert_serial(&profile.name, &serial_hex, &database)
        .await
        .map_err(|error| {
            error!(event = "certificate_revoke_lookup_failed", outcome = "failure", cert_serial = %serial_hex, error = %error);
            Problem::server_internal("Certificate lookup failed")
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
        Some(cached) => crate::audit::Actor::acme(&cached.id),
        None => crate::audit::Actor::acme_certificate_key(),
    };
    // One reverse lookup for whichever arm answers.
    let client = audit.client(&request_context).await;
    let revoke_failed = |reason: &'static str, detail: &str| {
        crate::audit::AuditRecord::new(
            crate::audit::AuditEvent::CertificateRevokeFailed,
            &profile.name,
            actor.clone(),
        )
        .with_serial(&serial_hex)
        .with_client(client.clone())
        .with_reason(reason)
        .with_detail(detail)
    };

    let mut order = match order {
        Ok(order) => order,
        Err(()) => {
            // Either no order carries this serial, or one does and its stored
            // leaf is not byte-for-byte what was submitted. The two are not
            // told apart on purpose: distinguishing them would confirm a serial
            // exists to a caller who has not proven anything yet. The audit row
            // does not distinguish them either, for the same reason — and it
            // exists because a stream of these is somebody enumerating.
            warn!(event = "certificate_revoke_unknown_certificate", outcome = "failure", cert_serial = %serial_hex);
            audit
                .record(revoke_failed(
                    "malformed",
                    "no certificate issued here matches",
                ))
                .await;
            return Err(Problem::malformed("Unknown certificate"));
        }
    };

    // Deliberately *not* routed through `signer_account`, and deliberately not
    // gated on account status. RFC 8555 §7.6 gives two ways to authorize a
    // revocation and only one of them involves an account at all — the
    // certificate's own key pair is the accountless case — so authorization is
    // resolved here rather than by a helper that assumes an account exists.
    //
    // §7.3.6 says a server SHOULD NOT allow further requests by a deactivated
    // account key, and this path knowingly does. Revocation only ever removes
    // trust; refusing it would mean an operator who deactivated an account can
    // no longer withdraw the certificates it holds, which is the worse failure
    // in both directions. Pinned by
    // `tests/revoke_cert.rs::deactivated_account_can_still_revoke_its_own_certificate`.
    let cert_key_matches = order.cert_pubkey.as_deref() == Some(pubkey.as_slice());
    let authorized = if cert_key_matches {
        true
    } else {
        match account {
            Some(cached) => cached.id == order.account_id,
            None => Account::find_by_pubkey(&profile.name, &pubkey, &database)
                .await
                .map_err(|error| {
                    error!(event = "certificate_revoke_account_lookup_failed", outcome = "failure", error = %error);
                    Problem::server_internal("Account lookup failed")
                })?
                .is_some_and(|found| found.id == order.account_id),
        }
    };
    if !authorized {
        warn!(event = "certificate_revoke_unauthorized", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex);
        // The one refusal here that is somebody else's certificate being
        // attacked rather than a client's own mistake, and the reason failures
        // are audited at all.
        audit
            .record(
                revoke_failed(
                    "unauthorized",
                    "signed by neither the order's account nor the certificate's own key",
                )
                .with_order(&order),
            )
            .await;
        return Err(Problem::unauthorized(
            "Neither the order's account nor the certificate's own key signed this request",
        ));
    }

    if order.revoked_at.is_some() {
        warn!(event = "certificate_revoke_already_revoked", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex);
        audit
            .record(revoke_failed("alreadyRevoked", "already revoked").with_order(&order))
            .await;
        return Err(Problem::already_revoked("Certificate already revoked"));
    }

    if let Some(reason) = payload.reason
        && !crate::cert::is_valid_revocation_reason(reason)
    {
        warn!(
            event = "certificate_revoke_bad_reason",
            outcome = "failure",
            reason = reason
        );
        audit
            .record(
                revoke_failed("badRevocationReason", &format!("reason code {reason}"))
                    .with_order(&order),
            )
            .await;
        return Err(Problem::bad_revocation_reason(format!(
            "Unsupported revocation reason code {reason}"
        )));
    }

    if let Err(error) = signer.revoke(&cert_der, payload.reason).await {
        error!(event = "certificate_revoke_signer_failed", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex, error = %error);
        audit
            .record(revoke_failed("serverInternal", &error.to_string()).with_order(&order))
            .await;
        return Err(Problem::server_internal("Revocation failed"));
    }
    if let Err(error) = order.revoke(payload.reason.map(i64::from), &database).await {
        error!(event = "certificate_revoke_persist_failed", outcome = "failure", order_id = %order.id, cert_serial = %serial_hex, error = %error);
        // The signer already withdrew trust, so the CA-side action stands; what
        // failed is this server's record of it. Audited as a failure because
        // that is what a later reader needs to know — the order still reads
        // un-revoked and a retry is expected.
        audit
            .record(revoke_failed("serverInternal", &error.to_string()).with_order(&order))
            .await;
        return Err(Problem::server_internal("Revocation failed"));
    }

    info!(event = "certificate_revoked", outcome = "success", order_id = %order.id, cert_serial = %serial_hex);
    let revoked = crate::audit::AuditRecord::new(
        crate::audit::AuditEvent::CertificateRevoked,
        &profile.name,
        actor,
    )
    .with_order(&order)
    .with_serial(&serial_hex)
    .with_client(client);
    // The RFC 5280 reason code, decimal, and left **absent** when the client
    // sent none — which RFC 8555 §7.6 allows and which is not the same as
    // `unspecified` (0). A `with_reason("")` here would make the two
    // indistinguishable in the column that exists to tell them apart.
    audit
        .record(match payload.reason {
            Some(reason) => revoked.with_reason(reason.to_string()),
            None => revoked,
        })
        .await;
    profile
        .notify
        .dispatch(NotifyEvent::CertificateRevoked(CertificateRevokedData {
            profile: profile.name.clone(),
            order_id: order.id.clone(),
            account_id: order.account_id.clone(),
            cert_serial: serial_hex.clone(),
            reason: payload.reason,
            client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
        }));
    Ok(StatusCode::OK.into_response())
}

/// Serves the local CA's certificate revocation list (RFC 5280), DER encoded.
#[instrument(name = "get_crl", skip_all)]
pub async fn get_crl(State(state): State<AppState>) -> Response {
    match state.profile.signer.crl_der().await {
        Some(der) => ([(header::CONTENT_TYPE, "application/pkix-crl")], der).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
