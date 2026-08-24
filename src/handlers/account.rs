use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{error, info, instrument, warn};

use crate::AppState;
use crate::eab;
use crate::error::Problem;
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest, ProtectedHeader, spki_to_jwk};
use crate::filter::ClientIp;
use crate::handlers::helpers::{signer_account, validate_contacts};
use crate::key_change;
use crate::notify::{AccountCreatedData, AccountDeactivatedData, NotifyEvent};
use crate::sqlite::{
    account::{Account, pubkey_fingerprint},
    db::Database,
    eab::Eab,
    order::Order,
};

/// Every field is optional: real clients may omit `contact`, and the two flags
/// default to `false`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NewAccountPayload {
    pub contact: Vec<String>,
    #[serde(alias = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
    #[serde(alias = "onlyReturnExisting")]
    pub only_return_existing: bool,
    #[serde(alias = "externalAccountBinding")]
    pub external_account_binding: Option<eab::EabJws>,
}

/// Refuses a request signed by the key of a deactivated account.
///
/// RFC 8555 §7.3.6: "If a server receives a POST or POST-as-GET from a
/// deactivated account, it MUST return an error response with status code 401
/// (Unauthorized) and type `urn:ietf:params:acme:error:unauthorized`." Every
/// order-side endpoint and `keyChange` get this through `signer_account`, and
/// `post_account` checks it directly — `newAccount` was the one path that did
/// not, on either of its branches, so a deactivated key could still confirm its
/// account existed and read its own `contact` list back out of the `Location`
/// response.
///
/// The wording matches `signer_account`'s byte for byte, so a deactivated key
/// gets one answer wherever it knocks.
fn refuse_deactivated(account: &Account, only_return_existing: bool) -> Result<(), Problem> {
    if account.status != "deactivated" {
        return Ok(());
    }
    warn!(
        event = "account_deactivated_registration_refused",
        outcome = "failure",
        account_id = %account.id,
        only_return_existing = only_return_existing
    );
    Err(Problem::unauthorized("Account is deactivated"))
}

/// Handles ACME newAccount requests for creating new certificate accounts.
#[instrument(name = "post_new_account", skip_all, fields(algorithm = %header.alg))]
pub async fn post_new_account(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: crate::audit::RequestContext,
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

    if payload.only_return_existing {
        let account = Account::find_by_pubkey(&profile.name, &pubkey, &database)
            .await
            .map_err(|error| {
                // Distinct from `helpers.rs`'s `account_lookup_failed`: same
                // query, but this one is `newAccount`'s §7.3.1 lookup, not the
                // one that resolves the signer of an order-side request.
                error!(event = "account_only_return_existing_lookup_failed", outcome = "failure", error = %error);
                Problem::server_internal("Account lookup failed")
            })?
            .ok_or_else(|| {
                info!(event = "account_only_return_existing_miss", outcome = "failure");
                Problem::account_does_not_exist("No account for this key")
            })?;

        refuse_deactivated(&account, true)?;

        let location = format!("{base}/acct/{}", account.id);
        return Ok((
            StatusCode::OK,
            [(header::LOCATION, location)],
            Json(account.to_json(base)),
        )
            .into_response());
    }

    // Checked before the EAB, so a client with a typo'd address hears about the
    // typo rather than burning its one-shot EAB credential on a doomed request.
    validate_contacts(&payload.contact)?;

    // RFC 8555 §7.3.3: a client agrees to the terms by setting
    // `termsOfServiceAgreed`, and §6.7's `userActionRequired` is the refusal
    // when it has not. Enforced only when `meta.termsOfService` is configured —
    // §7.3.3 ties the requirement to the directory advertising a ToS, so an
    // endpoint with none must not demand agreement to something it never named.
    if !profile.meta.terms_of_service.is_empty() && !payload.terms_of_service_agreed {
        warn!(event = "account_terms_not_agreed", outcome = "failure");
        let problem = Problem::user_action_required(
            "Terms of service must be agreed to before an account can be created",
        );
        // Built by hand rather than returned as a `Problem`, for the same reason
        // `post_key_change`'s conflict is: the response needs a header, and §6.7
        // pairs `userActionRequired` with the link naming what to agree to.
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
            Json(problem.to_value()),
        )
            .into_response());
    }

    let eab_kid = if profile.eab.enabled {
        Some(
            verify_eab(
                payload.external_account_binding.as_ref(),
                &header,
                &profile.name,
                &database,
            )
            .await?,
        )
    } else {
        None
    };

    // Resolved before the write, and only on this path: `onlyReturnExisting`
    // returned above without ever creating anything, and `find_or_create`
    // stamps these columns on the creating branch alone — so a PTR lookup for a
    // request that turns out to find an existing account is wasted, but a
    // lookup after the INSERT would need a second UPDATE to record it.
    let client = audit.client(&request_context).await;
    let (mut account, created) =
        Account::find_or_create(&profile.name, &pubkey, payload.contact, &client, &database)
            .await
            .map_err(|error| {
                error!(event = "account_creation_failed", outcome = "failure", error = %error);
                Problem::server_internal("Account persistence failed")
            })?;

    // Only on the found branch: an account this request just created is never
    // deactivated, and asking would be reading a column we wrote a line ago.
    if !created {
        refuse_deactivated(&account, false)?;
    }

    if created {
        if let Some(kid) = &eab_kid
            && let Err(error) = account.set_eab_kid(kid, &database).await
        {
            error!(event = "account_eab_kid_persist_failed", outcome = "failure", account_id = %account.id, error = %error);
        }
        // Recorded only where the endpoint actually has terms to agree to — the
        // check above already refused a request that did not agree, so reaching
        // here with a ToS configured means the client set the flag.
        if !profile.meta.terms_of_service.is_empty()
            && let Err(error) = account.set_terms_agreed(&database).await
        {
            error!(event = "account_terms_agreed_persist_failed", outcome = "failure", account_id = %account.id, error = %error);
        }
        profile
            .notify
            .dispatch(NotifyEvent::AccountCreated(AccountCreatedData {
                profile: profile.name.clone(),
                account_id: account.id.clone(),
                contact: account.contact.clone(),
                client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
            }))
            .await;
    }

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let location = format!("{base}/acct/{}", account.id);

    info!(
        event = "account_created",
        outcome = "success",
        account_id = %account.id,
        created = created,
        status = %status
    );

    Ok((
        status,
        [(header::LOCATION, location)],
        Json(account.to_json(base)),
    )
        .into_response())
}

/// Verifies the RFC 8555 §7.3.4 External Account Binding.
#[instrument(name = "verify_eab", skip_all)]
pub async fn verify_eab(
    eab_jws: Option<&eab::EabJws>,
    header: &ProtectedHeader,
    profile: &str,
    database: &Arc<Database>,
) -> Result<String, Problem> {
    let eab_jws = eab_jws.ok_or_else(|| {
        warn!(event = "eab_required", outcome = "failure", profile);
        Problem::external_account_required("This server requires External Account Binding")
    })?;

    let outer_jwk = header.jwk.as_ref().ok_or_else(|| {
        warn!(event = "eab_missing_jwk", outcome = "failure", profile);
        Problem::malformed("newAccount requires an embedded jwk for External Account Binding")
    })?;

    let eab_header = eab::parse_header(eab_jws, &header.url).map_err(eab::eab_problem)?;

    let key = Eab::find_by_kid(&eab_header.kid, profile, database)
        .await
        .map_err(|error| {
            error!(event = "eab_lookup_failed", outcome = "failure", kid = %eab_header.kid, error = %error);
            Problem::server_internal("External Account Binding lookup failed")
        })?
        .filter(Eab::is_active)
        .ok_or_else(|| {
            warn!(event = "eab_unknown_or_revoked_kid", outcome = "failure", kid = %eab_header.kid);
            Problem::unauthorized("Unknown or revoked External Account Binding key")
        })?;

    eab::verify_payload_and_signature(eab_jws, &key.secret, outer_jwk).map_err(eab::eab_problem)?;

    info!(event = "eab_verified", outcome = "success", kid = %key.kid);
    Ok(key.kid)
}

/// Fields an account-update request may carry.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UpdateAccountPayload {
    pub contact: Option<Vec<String>>,
    pub status: Option<String>,
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
        database, profile, ..
    } = state;
    let base = &profile.base_url;

    let mut account = match Account::find_by_id(&profile.name, &id, &database).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            warn!(event = "account_not_found", outcome = "failure", account_id = %id);
            return Err(Problem::account_does_not_exist("Unknown account"));
        }
        Err(error) => {
            error!(
                event = "account_update_lookup_failed",
                outcome = "failure",
                account_id = %id,
                error = %error
            );
            return Err(Problem::server_internal("Account lookup failed"));
        }
    };

    if account.pubkey != pubkey {
        warn!(
            event = "account_key_mismatch",
            outcome = "failure",
            account_id = %id,
            expected_pubkey_fp = %pubkey_fingerprint(&account.pubkey),
            actual_pubkey_fp = %pubkey_fingerprint(&pubkey)
        );
        return Err(Problem::unauthorized("Signed by a different account key"));
    }

    if account.status == "deactivated" {
        warn!(
            event = "account_deactivated_modify_refused",
            outcome = "failure",
            account_id = %id
        );
        return Err(Problem::unauthorized("Account deactivated"));
    }

    if let Some(status) = payload.status {
        if status != "deactivated" {
            warn!(event = "account_update_bad_status", outcome = "failure", account_id = %id, status = %status);
            return Err(Problem::malformed("Only 'deactivated' status is accepted"));
        }
        account.deactivate(&database).await.map_err(|error| {
            error!(
                event = "account_deactivation_failed",
                outcome = "failure",
                account_id = %id,
                error = %error
            );
            Problem::server_internal("Account update failed")
        })?;
        info!(
            event = "account_deactivated",
            outcome = "success",
            account_id = %id
        );
        profile
            .notify
            .dispatch(NotifyEvent::AccountDeactivated(AccountDeactivatedData {
                profile: profile.name.clone(),
                account_id: id.clone(),
                client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
            }))
            .await;
    } else if let Some(contact) = payload.contact {
        validate_contacts(&contact)?;
        account
            .update_contact(contact, &database)
            .await
            .map_err(|error| {
                error!(
                    event = "account_contact_update_failed",
                    outcome = "failure",
                    account_id = %id,
                    error = %error
                );
                Problem::server_internal("Account update failed")
            })?;
        info!(
            event = "account_contact_updated",
            outcome = "success",
            account_id = %id
        );
    }

    info!(
        event = "account_updated",
        outcome = "success",
        account_id = %id
    );
    Ok(Json(account.to_json(base)))
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
        database, profile, ..
    } = state;
    let base = &profile.base_url;

    let mut old_account = signer_account(account, &profile.name, &old_pubkey, &database).await?;

    let inner_header = key_change::parse_header(&inner_jws, &header.url)
        .map_err(key_change::key_change_problem)?;
    let new_pubkey = key_change::verify_signature(&inner_jws, &inner_header)
        .map_err(key_change::key_change_problem)?;

    let account_url = format!("{base}/acct/{}", old_account.id);
    let old_key_jwk = spki_to_jwk(&old_account.pubkey).map_err(|error| {
        error!(event = "key_change_old_key_decode_failed", outcome = "failure", account_id = %old_account.id, error = %error);
        Problem::server_internal("Stored account key could not be decoded")
    })?;
    key_change::verify_payload(&inner_jws, &account_url, &old_key_jwk)
        .map_err(key_change::key_change_problem)?;

    let conflicting_account =
        Account::find_by_pubkey(&profile.name, &new_pubkey, &database)
        .await
        .map_err(|error| {
            error!(event = "key_change_conflict_lookup_failed", outcome = "failure", account_id = %old_account.id, error = %error);
            Problem::server_internal("Account lookup failed")
        })?;
    if let Some(existing) = conflicting_account {
        warn!(event = "key_change_conflict", outcome = "failure", account_id = %old_account.id, conflicting_account_id = %existing.id);
        return Ok(key_change_conflict(base, &existing.id));
    }

    if let Err(error) = old_account.update_pubkey(&new_pubkey, &database).await {
        // The check above and this write are two statements, and another
        // rollover onto the same key can land between them — at which point
        // `UNIQUE (profile, pubkey)` is what says so. §7.3.5 gives that case a
        // status and a `Location`, so answering `serverInternal` here would
        // report "something went wrong" for a condition the RFC describes
        // exactly, and deny the client the one field it needs to recover.
        //
        // Re-read rather than reuse `new_pubkey`'s earlier (empty) lookup: the
        // account that won is by definition committed now.
        if crate::sqlite::account::is_pubkey_conflict(&error)
            && let Ok(Some(winner)) =
                Account::find_by_pubkey(&profile.name, &new_pubkey, &database).await
        {
            warn!(event = "key_change_conflict", outcome = "failure", account_id = %old_account.id, conflicting_account_id = %winner.id);
            return Ok(key_change_conflict(base, &winner.id));
        }
        error!(event = "key_change_persist_failed", outcome = "failure", account_id = %old_account.id, error = %error);
        return Err(Problem::server_internal("Account key update failed"));
    }

    info!(event = "account_key_changed", outcome = "success", account_id = %old_account.id);
    Ok(Json(old_account.to_json(base)).into_response())
}

/// RFC 8555 §7.3.5's refusal for a new key that already belongs to somebody:
/// `409`, the problem document, and the `Location` of the account that holds it.
///
/// Shared by the two ways this is discovered — the lookup before the write, and
/// the unique violation when another rollover lands between the two. Both must
/// answer identically or a client's recovery would depend on which side of a
/// race it fell.
fn key_change_conflict(base: &str, holder_id: &str) -> Response {
    let problem =
        Problem::key_change_conflict("The new key is already associated with a different account");
    (
        StatusCode::CONFLICT,
        [
            (header::CONTENT_TYPE, "application/problem+json".to_string()),
            (header::LOCATION, format!("{base}/acct/{holder_id}")),
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
        database, profile, ..
    } = state;
    let base = &profile.base_url;

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    if account.id != id {
        warn!(
            event = "account_orders_ownership_mismatch",
            outcome = "failure",
            requested = %id,
            signer = %account.id
        );
        return Err(Problem::unauthorized("Not your account"));
    }

    // RFC 8555 §7.1.2.1's filtered view — expired and `invalid` orders are not
    // URLs worth handing back (see `find_active_by_account`).
    let orders = Order::find_active_by_account(&id, &database)
        .await
        .map_err(|error| {
            error!(
                event = "account_orders_lookup_failed",
                outcome = "failure",
                account_id = %id,
                error = %error
            );
            Problem::server_internal("Order list failed")
        })?;

    let urls: Vec<Value> = orders
        .iter()
        .map(|o| Value::String(format!("{base}/order/{}", o.id)))
        .collect();
    Ok(Json(json!({ "orders": urls })))
}
