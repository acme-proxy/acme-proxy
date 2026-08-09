use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info, instrument, warn};

use crate::AppState;
use crate::challenge::ValidationContext;
use crate::error::Problem;
use crate::extractors::acme::{AcmeOptionalPayload, AcmeRequest, jwk_thumbprint};
use crate::filter::ClientIp;
use crate::handlers::helpers::{
    challenge_problem, load_owned_authz, load_owned_challenge, signer_account,
};
use crate::notify::{ChallengeFailedData, NotifyEvent};
use crate::sqlite::{
    authz::{Authorization, Challenge},
    db::Database,
    nonce::now_secs,
    order::Order,
};
use std::sync::Arc;

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
        event = "authorization_lookup_requested",
        authz_id = %id,
        deactivating = payload.is_some(),
    );
    let AppState {
        database, profile, ..
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
            warn!(event = "authz_update_unsupported", authz_id = %id, status = ?update.status);
            return Err(Problem::malformed(
                "Only {\"status\": \"deactivated\"} is supported on an authorization",
            ));
        }
        deactivate_authz(&mut authz, &mut order, &database).await?;
    }

    let challenges = Challenge::find_by_authz(&authz.id, &database)
        .await
        .map_err(|error| {
            error!(
                event = "challenge_list_failed",
                authz_id = %id,
                error = %error
            );
            Problem::server_internal("Challenge lookup failed")
        })?;

    let mut response = Json(authz.to_json(base, &challenges)).into_response();
    add_pending_retry_after(&mut response, &authz.status);
    Ok(response)
}

/// How long a client is asked to wait before polling a still-`pending`
/// authorization or challenge again (RFC 8555 §7.5.1).
///
/// Deliberately small, and for the same reason as `PROCESSING_RETRY_AFTER` on
/// orders: validation here is inline and bounded by `challenge.timeout_ms`, so
/// the answer is usually already decided by the time a client asks — a long
/// hint would stall a client that could have finished immediately.
const PENDING_RETRY_AFTER: &str = "5";

/// Adds `Retry-After` while a resource is still `pending`.
///
/// RFC 8555 §7.5.1: "The server SHOULD provide information about its retry
/// state to the client via the `Retry-After` HTTP header field" — the same
/// pacing courtesy `order_response` extends to a `processing` order. Any other
/// status is decided, so there is nothing to come back for.
fn add_pending_retry_after(response: &mut Response, status: &str) {
    if status == "pending" {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(PENDING_RETRY_AFTER),
        );
    }
}

/// Deactivates `authz` and re-derives its order's status (RFC 8555 §7.5.2).
///
/// Already-`deactivated` is a no-op rather than an error: §7.5.2 describes the
/// client sending the same static object to *each* authorization of an
/// identifier, and a retry after a partial failure must not start reporting
/// errors halfway through.
async fn deactivate_authz(
    authz: &mut Authorization,
    order: &mut Order,
    database: &Arc<Database>,
) -> Result<(), Problem> {
    if authz.status == "deactivated" {
        return Ok(());
    }

    // A certificate already exists for this order, so relinquishing the
    // authorization it was issued under would claim something untrue. §7.5.2 is
    // about giving up the *ability* to issue, not about undoing issuance —
    // that is what revocation (§7.6) is for.
    if order.status == "valid" {
        warn!(event = "authz_deactivate_refused_order_valid", authz_id = %authz.id, order_id = %order.id);
        return Err(Problem::malformed(
            "Cannot deactivate an authorization whose order has already been issued; revoke the certificate instead",
        ));
    }

    if authz.status != "pending" && authz.status != "valid" {
        warn!(event = "authz_deactivate_refused_terminal", authz_id = %authz.id, status = %authz.status);
        return Err(Problem::malformed(
            "Authorization is in a terminal state and cannot be deactivated",
        ));
    }

    // §7.5.2: "The server MUST NOT treat deactivated authorization objects as
    // sufficient for issuing certificates." For a `pending` order that falls
    // out of the readiness check on its own, but an order already promoted to
    // `ready` would still finalize — so demote it.
    //
    // Both in one transaction. Between them, an order sits `ready` with a
    // deactivated authorization under it: finalizable for a name the client has
    // just given up, which is exactly what §7.5.2 forbids.
    let demote = order.status == "ready";
    let outcome = async {
        let mut tx = database.pool.begin().await?;
        Authorization::set_deactivated(&authz.id, &mut *tx).await?;
        if demote {
            Order::set_pending(&order.id, &mut *tx).await?;
        }
        tx.commit().await
    }
    .await;

    outcome.map_err(|error| {
        error!(event = "authz_deactivate_failed", authz_id = %authz.id, error = %error);
        Problem::server_internal("Authorization deactivation failed")
    })?;

    // Only once the transaction has committed: a rollback must not leave these
    // objects claiming a status the database never took.
    authz.status = "deactivated".to_string();
    if demote {
        order.status = "pending".to_string();
    }

    info!(event = "authorization_deactivated", authz_id = %authz.id, order_id = %order.id);
    Ok(())
}

/// Records a successful validation as **one** transaction: the challenge becomes
/// `valid`, its authorization becomes `valid`, and the order is promoted to
/// `ready` if that was the last one outstanding.
///
/// Three separate statements — which is what this was — can stop between any
/// two. The gap that matters is the last one: an order left `pending` with every
/// authorization already `valid` can never be finalized and nothing re-derives
/// readiness, because the check only ever ran from here and the client has no
/// challenge left to answer to make it run again. The order is stuck until it
/// expires. `post_new_order` has always used one transaction for the same
/// reason.
///
/// It also fixes a second, quieter bug. The readiness check used to re-read the
/// authorizations *from the pool* after the write above had committed, so two
/// concurrent validations of two authorizations of one order could each read
/// before the other's write landed: neither would see a complete set, and
/// neither would promote. Reading inside the transaction that just wrote means
/// SQLite serializes the two writers, and whichever commits second is the one
/// that sees them all `valid`.
async fn commit_validation(
    challenge: &mut Challenge,
    authz: &mut Authorization,
    order: &mut Order,
    database: &Arc<Database>,
) -> Result<(), Problem> {
    let validated = now_secs();
    let outcome = async {
        let mut tx = database.pool.begin().await?;
        Challenge::set_valid(&challenge.id, validated, &mut *tx).await?;
        Authorization::set_valid(&authz.id, &mut *tx).await?;

        // `pool.begin()` issues a deferred BEGIN, but the two writes above have
        // already taken the RESERVED lock by the time this reads — so this sees
        // its own write and no other writer can interleave. Putting a read
        // first here would break that.
        let promote = order.status == "pending" && {
            let authzs = Authorization::find_by_order_with(&order.id, &mut *tx).await?;
            authzs.len() == order.identifiers.len()
                && authzs.iter().all(|authz| authz.status == "valid")
        };
        if promote {
            Order::set_ready(&order.id, &mut *tx).await?;
        }
        tx.commit().await?;
        Ok::<bool, sqlx::Error>(promote)
    }
    .await;

    match outcome {
        Ok(promoted) => {
            // In-memory sync only after the commit; see `Authorization::set_valid`.
            challenge.status = "valid".to_string();
            challenge.validated = Some(validated);
            authz.status = "valid".to_string();
            if promoted {
                order.status = "ready".to_string();
            }
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_validation_persist_failed",
                challenge_id = %challenge.id,
                authz_id = %authz.id,
                order_id = %order.id,
                error = %error
            );
            Err(Problem::server_internal("Challenge validation failed"))
        }
    }
}

/// The failure arm of [`commit_validation`], same shape: the challenge takes the
/// problem document explaining why, and its authorization and order both become
/// `invalid`, in one transaction.
async fn commit_validation_failure(
    challenge: &mut Challenge,
    authz: &mut Authorization,
    order: &mut Order,
    problem: &Value,
    database: &Arc<Database>,
) -> Result<(), Problem> {
    let outcome = async {
        let mut tx = database.pool.begin().await?;
        Challenge::set_invalid(&challenge.id, problem, &mut *tx).await?;
        Authorization::set_invalid(&authz.id, &mut *tx).await?;
        Order::set_invalid(&order.id, problem, &mut *tx).await?;
        tx.commit().await
    }
    .await;

    match outcome {
        Ok(()) => {
            challenge.status = "invalid".to_string();
            challenge.error = Some(problem.clone());
            authz.status = "invalid".to_string();
            order.status = "invalid".to_string();
            order.error = Some(problem.clone());
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_failure_persist_failed",
                challenge_id = %challenge.id,
                authz_id = %authz.id,
                order_id = %order.id,
                error = %error
            );
            Err(Problem::server_internal("Challenge validation failed"))
        }
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
        challenge_id = %id
    );
    let AppState {
        database, profile, ..
    } = state;
    let base = &profile.base_url;
    let challenges = &profile.challenges;

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    let (mut challenge, mut authz, mut order) =
        load_owned_challenge(&id, &account, &database).await?;

    if authz.status != "valid" && authz.expires <= now_secs() {
        warn!(event = "authorization_expired", authz_id = %authz.id, expires = authz.expires);
        return Err(Problem::malformed("Authorization has expired"));
    }

    // The client gave this authorization up (RFC 8555 §7.5.2). Validating a
    // challenge under it would walk it straight back to `valid` — which §7.5.2
    // forbids being sufficient for issuance — so refuse before doing any work.
    if authz.status == "deactivated" {
        warn!(event = "authorization_already_deactivated", authz_id = %authz.id);
        return Err(Problem::malformed("Authorization has been deactivated"));
    }

    let decided =
        challenge.status == "valid" || challenge.status == "invalid" || authz.status == "valid";

    if !decided {
        let thumbprint = jwk_thumbprint(&account.pubkey).map_err(|error| {
            error!(event = "thumbprint_failed", account_id = %account.id, error = %error);
            Problem::server_internal("Key authorization could not be computed")
        })?;
        let key_authorization = format!("{}.{}", challenge.token, thumbprint);

        let context = ValidationContext {
            identifier: authz.base_identifier(),
            wildcard: authz.is_wildcard(),
            token: &challenge.token,
            key_authorization: &key_authorization,
            challenge_id: &challenge.id,
        };

        match challenges.validate(&challenge.typ, &context).await {
            Ok(()) => {
                commit_validation(&mut challenge, &mut authz, &mut order, &database).await?;
            }
            Err(error) => {
                let problem = challenge_problem(&error).to_value();
                warn!(
                    event = "challenge_failed",
                    challenge_id = %id,
                    typ = %challenge.typ,
                    kind = error.kind()
                );

                commit_validation_failure(
                    &mut challenge,
                    &mut authz,
                    &mut order,
                    &problem,
                    &database,
                )
                .await?;

                // After the commit, not before. Dispatched first, a persistence
                // failure would have notified an operator about a failure that
                // was never recorded — and the client, which gets a 500, would
                // see the challenge still `pending`.
                profile
                    .notify
                    .dispatch(NotifyEvent::ChallengeFailed(ChallengeFailedData {
                        profile: profile.name.clone(),
                        order_id: order.id.clone(),
                        account_id: account.id.clone(),
                        authz_id: authz.id.clone(),
                        challenge_id: challenge.id.clone(),
                        challenge_type: challenge.typ.clone(),
                        identifier: authz.base_identifier().to_string(),
                        error: error.kind().to_string(),
                        client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
                    }));
            }
        }
    }

    info!(
        event = "challenge_answered",
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
    add_pending_retry_after(&mut response, &challenge.status);
    Ok(response)
}
