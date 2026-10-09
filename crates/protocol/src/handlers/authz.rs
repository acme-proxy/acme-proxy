//! Authorizations (RFC 8555 §7.5) and challenges (§7.5.1).
//!
//! A challenge URL, like an authorization's, serves two operations told apart
//! by whether a payload arrived. A POST-as-GET (§6.3) reads the challenge and
//! never claims it or queues work. A payload (the client's `{}`) does not
//! validate it either: it claims the challenge and queues the validation for
//! the worker (ADR 0006), answering `processing`. The client learns the verdict
//! by polling, which is why a `pending` or `processing` answer carries
//! `Retry-After` — but never a `pending` one no trigger could start any more.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use std::net::IpAddr;
use tracing::{error, info, instrument, warn};

use crate::acme::access::{load_owned_authz, load_owned_challenge, signer_account};
use crate::acme::order::{OrderService, challenge_can_be_triggered};
use crate::extractors::acme::AcmeOptionalPayload;
use crate::router::AppState;
use acme_proxy_core::client::ClientIp;
use acme_proxy_core::error::Problem;
use acme_proxy_jobs::jobs::JobQueue;
use acme_proxy_store::authz::Authorization;
use acme_proxy_store::authz::Challenge;
use acme_proxy_store::authz::ValidationClaim;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::order::Order;
use acme_proxy_store::status::ChallengeStatus;

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

/// Reads a challenge via POST-as-GET (RFC 8555 §6.3), or triggers its
/// validation (§7.5.1) — one URL, two operations, told apart by whether a
/// payload arrived, as on the authorization.
///
/// A zero-byte payload only reads the owned challenge; it never claims it or
/// queues work. Any nonempty payload (the client's `{}`) is the acknowledgement.
#[instrument(name = "post_challenge", skip_all, fields(challenge_id = %id))]
pub async fn post_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    AcmeOptionalPayload {
        payload,
        pubkey,
        account,
        ..
    }: AcmeOptionalPayload<Value>,
) -> Result<Response, Problem> {
    info!(
        event = "challenge_trigger_requested",
        outcome = "progress",
        challenge_id = %id,
        triggering = payload.is_some(),
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

    // An empty payload only reads the owned challenge; it never starts work.
    if payload.is_some()
        && let Some(early) = trigger_validation(
            &orders,
            &jobs,
            &mut challenge,
            &authz,
            &order,
            &id,
            client_ip,
        )
        .await?
    {
        return Ok(early);
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
    // A `pending` challenge no trigger could start any more — its authorization
    // expired, was deactivated or failed, or a sibling already decided it — is
    // read without a refusal, but must not invite the client to poll an object
    // that can never move. A `processing` one has a job that owes it a verdict.
    if challenge.status != ChallengeStatus::Pending
        || challenge_can_be_triggered(&authz, &order, now_secs())
    {
        add_pending_retry_after(&mut response, challenge.status.as_str());
    }
    Ok(response)
}

/// Claims `challenge` and queues its validation — the trigger half of
/// [`post_challenge`].
///
/// `Some` is an answer that replaces the challenge object (the §6.6 rate
/// limit); `None` means answer with the challenge as it now stands.
async fn trigger_validation(
    orders: &OrderService<'_>,
    jobs: &JobQueue,
    challenge: &mut Challenge,
    authz: &Authorization,
    order: &Order,
    id: &str,
    client_ip: Option<IpAddr>,
) -> Result<Option<Response>, Problem> {
    // Claimed, then queued — never awaited. The check reaches an address the
    // client named, so awaiting it here held an admission permit for the length
    // of `challenge.timeout_ms`. The challenge now answers `processing`, which
    // §7.1.6 defines for exactly this ("transitions to the `processing` state
    // when the client responds to the challenge") and §8.2 pairs with the
    // `Retry-After` below.
    let claim = orders.claim_challenge(challenge, authz, order).await?;
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
        return Ok(Some(response));
    }
    if claim == ValidationClaim::Claimed {
        let queued = jobs
            .enqueue(crate::acme::validate::challenge_validate_spec(
                id,
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
            let _ = challenge.release_validation_claim(orders.database).await;
            return Err(Problem::server_internal(
                "Challenge validation could not be queued",
            ));
        }
    }
    Ok(None)
}
