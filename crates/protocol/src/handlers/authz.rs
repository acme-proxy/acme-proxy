use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info, instrument, warn};

use crate::acme::access::{load_owned_authz, load_owned_challenge, signer_account};
use crate::acme::order::OrderService;
use crate::extractors::acme::{AcmeOptionalPayload, AcmeRequest};
use crate::router::AppState;
use acme_proxy_core::client::ClientIp;
use acme_proxy_core::error::Problem;
use acme_proxy_store::authz::Challenge;
use acme_proxy_store::authz::ValidationClaim;

/// The one payload RFC 8555 §7.5.2 defines for the authorization resource:
/// "sending POST requests with the static object `{"status": "deactivated"}`".
#[derive(Debug, Deserialize)]
pub struct AuthzUpdatePayload {
    pub status: Option<String>,
}

/// Reads an authorization via POST-as-GET (RFC 8555 §7.5), or deactivates it
/// (§7.5.2) — one URL, two operations, told apart by whether a payload arrived.
///
/// Both answer with the authorization object and its challenges, so the client
/// sees the state it just read or just caused.
#[instrument(name = "post_authz", skip_all, fields(authz_id = %id))]
pub async fn post_authz(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AcmeOptionalPayload {
        payload,
        pubkey,
        account,
        ..
    }: AcmeOptionalPayload<AuthzUpdatePayload>,
) -> Result<Response, Problem> {
    info!(
        event = "authz_lookup_requested",
        outcome = "progress",
        authz_id = %id,
        deactivating = payload.is_some(),
    );
    let AppState {
        database,
        profile,
        audit,
        ..
    } = state;
    let base = &profile.base_url;

    // `load_owned_authz` walks up to the order and checks `account_id`, which is
    // §7.5.2's "the server MUST verify that the request is signed by the account
    // key corresponding to the account that owns the authorization".
    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    let (mut authz, mut order) = load_owned_authz(&id, &account, &database).await?;

    if let Some(update) = payload {
        // §7.5.2 defines exactly one payload; anything else is a client sending
        // us something we would otherwise silently ignore.
        if update.status.as_deref() != Some("deactivated") {
            warn!(event = "authz_update_unsupported", outcome = "failure", authz_id = %id, status = ?update.status);
            return Err(Problem::malformed(
                "Only {\"status\": \"deactivated\"} is supported on an authorization",
            ));
        }
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        orders.deactivate_authz(&mut authz, &mut order).await?;
    }

    let challenges = Challenge::find_by_authz(authz.id, &database)
        .await
        .map_err(|error| {
            error!(
                event = "challenge_list_failed",
                outcome = "failure",
                authz_id = %id,
                error = %error
            );
            Problem::server_internal("Challenge lookup failed")
        })?;

    let mut response = Json(authz.to_json(base, &challenges)).into_response();
    add_pending_retry_after(&mut response, authz.status.as_str());
    Ok(response)
}

/// Adds `Retry-After` while a resource is still undecided.
///
/// RFC 8555 §7.5.1: "The server SHOULD provide information about its retry
/// state to the client via the `Retry-After` HTTP header field" — the same
/// pacing courtesy `order_response` extends to a `processing` order. Any other
/// status is decided, so there is nothing to come back for.
///
/// `processing` is here because §8.2 says so in as many words: "While the
/// server is still trying, the status of the challenge remains `processing`",
/// and the `Retry-After` on requests to the challenge resource is a `MUST` in
/// that paragraph. Only challenges ever carry it — an authorization has no such
/// state — so this stays one helper for both.
fn add_pending_retry_after(response: &mut Response, status: &str) {
    if status == "pending" || status == "processing" {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(super::POLL_RETRY_AFTER),
        );
    }
}

/// Triggers validation of a challenge (RFC 8555 §7.5.1).
#[instrument(name = "post_challenge", skip_all, fields(challenge_id = %id))]
pub async fn post_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    AcmeRequest {
        pubkey, account, ..
    }: AcmeRequest<Value>,
) -> Result<Response, Problem> {
    info!(
        event = "challenge_trigger_requested",
        outcome = "progress",
        challenge_id = %id
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
    let (mut challenge, authz, order) = load_owned_challenge(&id, &account, &database).await?;

    // Claimed, then queued — never awaited. The check reaches an address the
    // client named, so awaiting it here held an admission permit for the length
    // of `challenge.timeout_ms`. The challenge now answers `processing`, which
    // §7.1.6 defines for exactly this ("transitions to the `processing` state
    // when the client responds to the challenge") and §8.2 pairs with the
    // `Retry-After` below.
    let claim = orders
        .claim_challenge(&mut challenge, &authz, &order)
        .await?;
    if claim == ValidationClaim::Limited {
        // §6.6's answer, with the header §6.6 recommends: the limit is on work
        // in flight, so waiting is exactly what clears it. The challenge is
        // untouched and still `pending`, so the retry is a plain re-trigger.
        let mut response = Problem::rate_limited(
            "Too many validations are already running for this account; retry shortly",
        )
        .into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(super::POLL_RETRY_AFTER),
        );
        return Ok(response);
    }
    if claim == ValidationClaim::Claimed {
        let queued = jobs
            .enqueue(crate::acme::validate::challenge_validate_spec(
                &id,
                client_ip,
                authz.expires,
            ))
            .await;

        // The claim is on the row and the work is not queued, so nothing is
        // coming for it: give the claim back rather than leave the client
        // polling a `processing` challenge until its authorization expires.
        // `Ok(false)` needs no release — a live job already holds this
        // challenge's identity, which is the same fact the claim asserts.
        if let Err(error) = queued {
            error!(
                event = "challenge_validation_enqueue_failed",
                outcome = "failure",
                challenge_id = %id,
                error = %error
            );
            let _ = challenge.release_validation_claim(&database).await;
            return Err(Problem::server_internal(
                "Challenge validation could not be queued",
            ));
        }
    }

    info!(
        event = "challenge_answered",
        outcome = "success",
        challenge_id = %id,
        authz_id = %authz.id,
        order_id = %order.id,
        status = %challenge.status
    );
    let up_link = format!("<{base}/authz/{}>;rel=\"up\"", authz.id);
    let mut response = (
        StatusCode::OK,
        [(header::LINK, up_link)],
        Json(challenge.to_json(base)),
    )
        .into_response();
    add_pending_retry_after(&mut response, challenge.status.as_str());
    Ok(response)
}
