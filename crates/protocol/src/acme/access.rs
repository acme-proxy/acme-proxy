//! Who may touch what: the account a signature belongs to, and the ownership
//! walk from a challenge up to its order.
//!
//! Every signed route that names a resource comes through here, and the answer
//! is deliberately the same shape whatever went wrong: a resource of another
//! account is "not found", never "not yours". The two would let a client map
//! the server's contents by asking about ids it does not own.
//!
//! An account that has been deactivated (RFC 8555 §7.3.6) is refused here too,
//! once, so no handler has to remember to ask.

use std::sync::Arc;
use uuid::Uuid;

use tracing::{error, warn};

use acme_proxy_core::error::Problem;
use acme_proxy_store::account::Account;
use acme_proxy_store::authz::Authorization;
use acme_proxy_store::authz::Challenge;
use acme_proxy_store::db::Database;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::order::Order;
use acme_proxy_store::status::OrderStatus;

/// Resolves the account that signed the request, within the endpoint it
/// reached: an account registered at another profile is simply unknown here.
pub(crate) async fn signer_account(
    cached: Option<Account>,
    profile: &str,
    pubkey: &[u8],
    database: &Arc<Database>,
) -> Result<Account, Problem> {
    let account = match cached {
        Some(account) => account,
        None => Account::find_by_pubkey(profile, pubkey, database)
            .await
            .map_err(|error| {
                error!(event = "account_lookup_failed", outcome = "failure", error = %error);
                Problem::server_internal("Account lookup failed")
            })?
            .ok_or_else(|| Problem::account_does_not_exist("Unknown account"))?,
    };

    if account.is_deactivated() {
        warn!(event = "account_deactivated_request_refused", outcome = "failure", account_id = %account.id);
        return Err(Problem::unauthorized("Account is deactivated"));
    }
    Ok(account)
}

/// Loads order `id` and verifies it belongs to the account that signed the request.
pub(crate) async fn load_owned_order(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<Order, Problem> {
    let order = Order::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "order_lookup_failed", outcome = "failure", order_id = %id, error = %error);
            Problem::server_internal("Order lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown order"))?;

    // An order belongs to the endpoint it was placed at. Refusing it as
    // *unknown* rather than unauthorized is deliberate: the two answers differ,
    // so anything else would let one endpoint's client probe another's for
    // which order ids exist.
    if order.profile != account.profile {
        warn!(
            event = "order_profile_mismatch",
            outcome = "failure",
            order_id = %id,
            order_profile = %order.profile,
            request_profile = %account.profile
        );
        return Err(Problem::malformed("Unknown order"));
    }

    if order.account_id != account.id {
        warn!(event = "order_ownership_mismatch", outcome = "failure", order_id = %id, account_id = %account.id);
        return Err(Problem::unauthorized(
            "Order belongs to a different account",
        ));
    }

    if order.status != OrderStatus::Valid && order.expires <= now_secs() {
        warn!(event = "order_expired", outcome = "failure", order_id = %id, expires = order.expires);
        return Err(Problem::malformed("Order has expired"));
    }
    Ok(order)
}

/// Loads authorization `id` and the order it belongs to, verifying ownership.
pub(crate) async fn load_owned_authz(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<(Authorization, Order), Problem> {
    let authz = Authorization::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "authz_lookup_failed", outcome = "failure", authz_id = %id, error = %error);
            Problem::server_internal("Authorization lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown authorization"))?;

    let order = load_owned_order(authz.order_id.to_string().as_str(), account, database).await?;
    Ok((authz, order))
}

/// Loads challenge `id`, its authorization, and its order, verifying ownership.
pub(crate) async fn load_owned_challenge(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<(Challenge, Authorization, Order), Problem> {
    let challenge = Challenge::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "challenge_lookup_failed", outcome = "failure", challenge_id = %id, error = %error);
            Problem::server_internal("Challenge lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown challenge"))?;

    let (authz, order) =
        load_owned_authz(challenge.authz_id.to_string().as_str(), account, database).await?;
    Ok((challenge, authz, order))
}

/// Fetches an order's authorization ids.
pub(crate) async fn order_authz_ids(
    order_id: Uuid,
    database: &Arc<Database>,
) -> Result<Vec<Uuid>, Problem> {
    Ok(Authorization::find_by_order(order_id, database)
        .await
        .map_err(|error| {
            error!(event = "authz_list_failed", outcome = "failure", order_id = %order_id, error = %error);
            Problem::server_internal("Authorization lookup failed")
        })?
        .into_iter()
        .map(|authz| authz.id)
        .collect())
}
