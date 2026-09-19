use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::acme::OrderService;
use crate::acme::access::{load_owned_order, order_authz_ids, signer_account};
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest};
use crate::router::AppState;
use crate::sqlite::{order::Order, status::OrderStatus};
use acme_proxy_core::client::ClientIp;
use acme_proxy_core::error::Problem;

pub use crate::acme::order::{FinalizePayload, NewOrderPayload};

/// Handles ACME newOrder requests (RFC 8555 §7.4).
#[instrument(name = "post_new_order", skip_all, fields(algorithm = %header.alg))]
pub async fn post_new_order(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: acme_proxy_core::audit::RequestContext,
    AcmeRequest {
        header,
        payload,
        pubkey,
        account,
    }: AcmeRequest<NewOrderPayload>,
) -> Result<Response, Problem> {
    info!(
        event = "order_creation_requested",
        outcome = "progress",
        algorithm = %header.alg
    );
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let base = &profile.base_url;
    let orders = OrderService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    let (order, authz_ids) = orders
        .new_order(payload, account, &pubkey, client_ip, &request_context)
        .await?;
    let location = format!("{base}/order/{}", order.id);

    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(order.to_json(base, &authz_ids)),
    )
        .into_response())
}

/// Returns an order object via POST-as-GET (RFC 8555 §7.1.3 / §6.3).
#[instrument(name = "post_order", skip_all, fields(order_id = %id))]
pub async fn post_order(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AcmePostAsGet {
        pubkey, account, ..
    }: AcmePostAsGet,
) -> Result<Response, Problem> {
    info!(
        event = "order_lookup_requested",
        outcome = "progress",
        order_id = %id
    );
    let AppState {
        database, profile, ..
    } = state;
    let base = &profile.base_url;

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    let order = load_owned_order(&id, &account, &database).await?;
    let authz_ids = order_authz_ids(order.id, &database).await?;
    Ok(order_response(&order, base, &authz_ids))
}

/// How long a client is asked to wait before polling a `processing` order
/// again (RFC 8555 §7.4). A fixed, deliberately small value: the upstream's
/// own pacing is invisible from here, and an over-long hint would stall a
/// relay that finished in a second.
const PROCESSING_RETRY_AFTER: &str = "5";

/// The order object, plus a `Retry-After` header while it is `processing`.
///
/// RFC 8555 §7.4 has the client poll a `processing` order rather than holding
/// the request open, and *SHOULD* send this header to pace it. Every other
/// status renders exactly as before.
fn order_response(order: &Order, base: &str, authz_ids: &[Uuid]) -> Response {
    let mut response = Json(order.to_json(base, authz_ids)).into_response();
    if order.status == OrderStatus::Processing {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(PROCESSING_RETRY_AFTER),
        );
    }
    response
}

/// Finalizes an order (RFC 8555 §7.4).
#[instrument(name = "post_finalize", skip_all, fields(order_id = %id))]
pub async fn post_finalize(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: acme_proxy_core::audit::RequestContext,
    AcmeRequest {
        payload,
        pubkey,
        account,
        ..
    }: AcmeRequest<FinalizePayload>,
) -> Result<Response, Problem> {
    info!(
        event = "order_finalize_requested",
        outcome = "progress",
        order_id = %id
    );
    let AppState {
        database,
        profile,
        audit,
        jobs,
        ..
    } = state;
    let base = &profile.base_url;
    let orders = OrderService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    let order = load_owned_order(&id, &account, &database).await?;
    let order = orders
        .finalize(
            &account,
            order,
            &payload.csr,
            client_ip,
            &request_context,
            &jobs,
        )
        .await?;
    let authz_ids = order_authz_ids(order.id, &database).await?;
    Ok(order_response(&order, base, &authz_ids))
}
