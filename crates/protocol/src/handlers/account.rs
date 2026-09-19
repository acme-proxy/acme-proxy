use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::acme::{AccountService, Error};
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest};
use crate::router::AppState;
use acme_proxy_core::client::ClientIp;
use acme_proxy_core::error::Problem;
use acme_proxy_core::key_change;

pub use crate::acme::account::{NewAccountPayload, UpdateAccountPayload, verify_eab};

/// Handles ACME newAccount requests for creating new certificate accounts.
#[instrument(name = "post_new_account", skip_all, fields(algorithm = %header.alg))]
pub async fn post_new_account(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: acme_proxy_core::audit::RequestContext,
    AcmeRequest {
        header,
        payload,
        pubkey,
        ..
    }: AcmeRequest<NewAccountPayload>,
) -> Result<Response, Problem> {
    info!(
        event = "account_creation_requested",
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
    let accounts = AccountService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    let (account, created) = match accounts
        .new_account(payload, &header, &pubkey, client_ip, &request_context)
        .await
    {
        Ok(found) => found,
        // Built by hand rather than returned as a `Problem`, for the same reason
        // `post_key_change`'s conflict is: the response needs a header, and §6.7
        // pairs `userActionRequired` with the link naming what to agree to.
        Err(error @ Error::TermsNotAgreed) => {
            return Ok((
                StatusCode::FORBIDDEN,
                [
                    (header::CONTENT_TYPE, "application/problem+json".to_string()),
                    (
                        header::LINK,
                        format!(
                            "<{}>;rel=\"terms-of-service\"",
                            profile.meta.terms_of_service
                        ),
                    ),
                ],
                Json(Problem::from(error).to_value()),
            )
                .into_response());
        }
        Err(error) => return Err(error.into()),
    };

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let location = format!("{base}/acct/{}", account.id);
    Ok((
        status,
        [(header::LOCATION, location)],
        Json(account.to_json(base)),
    )
        .into_response())
}

/// Handles ACME account update requests (RFC 8555 §7.3.2 / §7.3.6).
#[instrument(name = "post_account", skip_all, fields(account_id = %id))]
pub async fn post_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    AcmeRequest {
        header,
        payload,
        pubkey,
        ..
    }: AcmeRequest<UpdateAccountPayload>,
) -> Result<Json<Value>, Problem> {
    info!(
        event = "account_update_requested",
        outcome = "progress",
        account_id = %id,
        algorithm = %header.alg
    );
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let accounts = AccountService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    let account = accounts.update(&id, payload, &pubkey, client_ip).await?;
    Ok(Json(account.to_json(&profile.base_url)))
}

/// Handles ACME account key rollover (RFC 8555 §7.3.5).
#[instrument(name = "post_key_change", skip_all)]
pub async fn post_key_change(
    State(state): State<AppState>,
    AcmeRequest {
        header,
        payload: inner_jws,
        pubkey: old_pubkey,
        account,
        ..
    }: AcmeRequest<key_change::KeyChangeJws>,
) -> Result<Response, Problem> {
    info!(event = "key_change_requested", outcome = "progress",);
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let base = &profile.base_url;
    let accounts = AccountService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    match accounts
        .key_change(account, &old_pubkey, &header, &inner_jws)
        .await
    {
        Ok(account) => Ok(Json(account.to_json(base)).into_response()),
        Err(error @ Error::KeyChangeConflict { holder }) => {
            Ok(key_change_conflict(base, holder, Problem::from(error)))
        }
        Err(error) => Err(error.into()),
    }
}

/// RFC 8555 §7.3.5's refusal for a new key that already belongs to somebody:
/// `409`, the problem document, and the `Location` of the account that holds it.
///
/// One rendering for the two ways this is discovered — the lookup before the
/// write, and the unique violation when another rollover lands between the two.
/// Both must answer identically or a client's recovery would depend on which
/// side of a race it fell.
fn key_change_conflict(base: &str, holder: Uuid, problem: Problem) -> Response {
    (
        StatusCode::CONFLICT,
        [
            (header::CONTENT_TYPE, "application/problem+json".to_string()),
            (header::LOCATION, format!("{base}/acct/{holder}")),
        ],
        Json(problem.to_value()),
    )
        .into_response()
}

/// Returns an account's order-list URL object via POST-as-GET.
#[instrument(name = "post_account_orders", skip_all, fields(account_id = %id))]
pub async fn post_account_orders(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AcmePostAsGet {
        pubkey, account, ..
    }: AcmePostAsGet,
) -> Result<Json<Value>, Problem> {
    info!(
        event = "account_orders_requested",
        outcome = "progress",
        account_id = %id
    );
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let base = &profile.base_url;
    let accounts = AccountService {
        database: &database,
        audit: &audit,
        profile: &profile,
    };

    let orders = accounts.orders(account, &pubkey, &id).await?;
    let urls: Vec<Value> = orders
        .iter()
        .map(|o| Value::String(format!("{base}/order/{}", o.id)))
        .collect();
    Ok(Json(json!({ "orders": urls })))
}
