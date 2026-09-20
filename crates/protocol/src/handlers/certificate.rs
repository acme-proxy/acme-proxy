use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use serde::Deserialize;
use tracing::{debug, info, instrument, warn};

use crate::acme::access::load_owned_order;
use crate::acme::revoke::{Revocations, Revoker};
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest};
use crate::router::AppState;
use acme_proxy_core::error::Problem;

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
    // "Progress", because nothing has been decided yet: the ownership walk and
    // the certificate lookup are still below, and either can refuse. The
    // outcome of the request is `certificate_served` or one of the refusals.
    info!(
        event = "certificate_request_received",
        outcome = "progress",
        order_id = %id
    );
    let AppState {
        database, profile, ..
    } = state;

    let account =
        crate::acme::access::signer_account(account, &profile.name, &pubkey, &database).await?;
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

/// How long a client is asked to wait before asking again about a revocation
/// still queued: a worker picks a row up within `jobs.poll_interval_ms`, so a
/// second is usually enough.
const REVOCATION_RETRY_AFTER: &str = "1";

/// Revokes a certificate (RFC 8555 §7.6), by the account that holds its order
/// or by the certificate's own key.
#[instrument(name = "post_revoke_cert", skip_all)]
pub async fn post_revoke_cert(
    State(state): State<AppState>,
    request_context: acme_proxy_core::audit::RequestContext,
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
        config,
        jobs,
        ..
    } = state;

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

    // Never the backend: only the `worker` role holds one. A local CA's
    // revocation is a ledger row the worker signs into the CRL; anything else
    // is queued, and this request waits on it within its own deadline.
    let route = profile.signer_info.revocation_route();
    let revocations = Revocations {
        database: &database,
        audit: &audit,
        notify: Some(&profile.notify),
        revoker: Revoker::for_route(
            &route,
            &jobs,
            crate::acme::revoke::request_wait(config.server.request_timeout_ms),
        ),
    };
    match revocations
        .revoke_certificate(
            &profile.name,
            &cert_der,
            payload.reason,
            &pubkey,
            account,
            &request_context,
        )
        .await
    {
        Ok(_) => Ok(StatusCode::OK.into_response()),
        // Still queued when the wait ran out: nothing failed, so the client
        // is told when to ask again — and asking again waits on the same job.
        Err(error @ crate::acme::revoke::RevokeError::Pending { .. }) => {
            let mut response = Problem::from(error).into_response();
            response.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from_static(REVOCATION_RETRY_AFTER),
            );
            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}

/// Serves the local CA's certificate revocation list (RFC 5280), DER encoded.
///
/// `404` when the backend keeps no CRL of its own, and `500` when it does but
/// the CRL could not be read: a relying party told "there is no CRL" might
/// stop checking, where a failure it retries later.
#[instrument(name = "get_crl", skip_all)]
pub async fn get_crl(State(state): State<AppState>) -> Response {
    match state.profile.signer_info.crl_der().await {
        Ok(Some(der)) => ([(header::CONTENT_TYPE, "application/pkix-crl")], der).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        // Logged where the backend built it.
        Err(_) => Problem::server_internal("CRL lookup failed").into_response(),
    }
}

/// Serves the certificates a client must trust to accept what this profile
/// issues, PEM encoded — the trust anchor, so installing it is one `curl`
/// rather than finding a file on the server's disk.
///
/// Unauthenticated and deliberately **not advertised in the directory**, the
/// same answer `GET /crl` already settled: this is CA infrastructure, not an
/// ACME resource, and RFC 8555 §7.1.1 defines no member to advertise it under.
///
/// `404` when the backend has no anchor of its own to hand out — a delegating
/// backend's anchor belongs to the CA it defers to, and inventing one here
/// would be worse than saying nothing.
#[instrument(name = "get_ca_chain", skip_all)]
pub async fn get_ca_chain(State(state): State<AppState>) -> Response {
    match state.profile.signer_info.ca_chain_pem().await {
        // `application/x-pem-file` rather than `application/pem-certificate-chain`
        // (RFC 8555 §7.4.2): that media type names an *end-entity* chain, leaf
        // first, which is the opposite of what this is.
        Some(pem) => ([(header::CONTENT_TYPE, "application/x-pem-file")], pem).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
