use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use serde::Deserialize;
use tracing::{error, info, instrument, warn};

use crate::AppState;
use crate::error::Problem;
use crate::extractors::acme::{AcmePostAsGet, AcmeRequest};
use crate::filter::{ClientIp, IdentifierStage, Stage as FilterStage};
use crate::handlers::helpers::{
    check_csr_matches_order, check_identifiers, csr_identifiers, is_wildcard, load_owned_order,
    normalize_dns_name, order_authz_ids, parse_csr, parse_rfc3339, signer_account,
    well_formed_name,
};
use crate::signer::{IssueOutcome, RequestedValidity, SignerError};
use crate::sqlite::{
    authz::{Authorization, Challenge},
    db::Database,
    nonce::now_secs,
    order::{Identifier, Order},
};

/// A newOrder payload (RFC 8555 §7.4).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
    #[serde(rename = "notBefore")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
    /// RFC 9773 §5: "A string uniquely identifying a previously issued
    /// certificate that this order is intended to replace", in the certID form
    /// of §4.1.
    pub replaces: Option<String>,
}

/// A finalize payload (RFC 8555 §7.4).
#[derive(Debug, Deserialize)]
pub struct FinalizePayload {
    pub csr: String,
}

/// Collapses per-identifier rejections into the one problem the client sees
/// (RFC 8555 §6.7.1).
///
/// A single rejection is returned as itself: wrapping one problem in a
/// `compound` would bury the type a client actually switches on for no gain.
/// Several become a `compound` whose status is the most severe of the parts —
/// so a batch containing a policy refusal reads as 403 rather than being
/// downgraded to 400 by a malformed name sitting next to it.
fn compound_identifier_problem(mut rejections: Vec<Problem>) -> Problem {
    if rejections.len() == 1 {
        return rejections.remove(0);
    }

    let status = rejections
        .iter()
        .map(Problem::status)
        .max()
        .unwrap_or(StatusCode::BAD_REQUEST);

    Problem::compound(status, "Some of the identifiers requested were rejected")
        .with_subproblems(rejections)
}

/// Validates a newOrder's `replaces` field (RFC 9773 §5) and returns the certID
/// to store, so it can be reflected back on this and every later read.
///
/// §5 asks for three checks — "that the identified certificate and the newOrder
/// request correspond to the same ACME Account, that they share at least one
/// identifier, and that the identified certificate has not already been marked
/// as replaced by a different Order that is not `invalid`" — and leaves
/// anything stricter ("such as requiring exact identifier matching") to server
/// policy. This implements exactly the three, and no more: a renewal that drops
/// or adds a name is an ordinary, legitimate thing to do.
///
/// The statuses differ by design. Only the already-replaced case is pinned by
/// the RFC (409 + `alreadyReplaced`); the rest are 400 `malformed`, matching
/// what every other unknown-or-unowned resource in this codebase returns.
async fn check_replaces(
    cert_id: &str,
    profile: &str,
    account_id: &str,
    identifiers: &[Identifier],
    database: &Arc<Database>,
) -> Result<String, Problem> {
    // Parsed with the same helper `GET /renewalInfo/{certID}` uses: §5 defines
    // the field as "constructed in the same way as the path component for GET
    // requests described in Section 4.1", so the two must not drift.
    let parsed = crate::cert::parse_ari_cert_id(cert_id).map_err(|error| {
        warn!(event = "replaces_malformed", outcome = "failure", replaces = %cert_id, error = %error);
        Problem::malformed(format!("Invalid `replaces` certID: {error}"))
    })?;

    let predecessor = Order::find_by_cert_serial(profile, &parsed.serial_hex(), database)
        .await
        .map_err(|error| {
            error!(event = "replaces_lookup_failed", outcome = "failure", error = %error);
            Problem::server_internal("Predecessor lookup failed")
        })?
        .ok_or_else(|| {
            warn!(event = "replaces_unknown", outcome = "failure", replaces = %cert_id);
            Problem::malformed("`replaces` names no certificate issued here")
        })?;

    // Same check the ARI handler makes, for the same reason: a serial alone does
    // not identify a certificate, and the AKI half must not be decorative.
    // Certificates issued before the local CA emitted an AKI have none, so a
    // missing extension means "cannot check" rather than "reject".
    if let Some(certificate) = predecessor.certificate.as_ref()
        && let Ok(leaf_der) = crate::cert::leaf_der_from_chain(certificate)
        && let Ok((aki, _)) = crate::cert::ari_cert_id_parts(&leaf_der)
        && aki != parsed.aki
    {
        warn!(event = "replaces_aki_mismatch", outcome = "failure", replaces = %cert_id);
        return Err(Problem::malformed(
            "`replaces` key identifier does not match the certificate",
        ));
    }

    // "…correspond to the same ACME Account". Also what stops one account
    // probing another's certificates through this field.
    if predecessor.account_id != account_id {
        warn!(event = "replaces_wrong_account", outcome = "failure", replaces = %cert_id, order_id = %predecessor.id);
        return Err(Problem::malformed(
            "`replaces` names a certificate belonging to another account",
        ));
    }

    // "…that they share at least one identifier".
    let shares_identifier = identifiers.iter().any(|wanted| {
        predecessor
            .identifiers
            .iter()
            .any(|had| had.typ == wanted.typ && had.value == wanted.value)
    });
    if !shares_identifier {
        warn!(event = "replaces_no_shared_identifier", outcome = "failure", replaces = %cert_id);
        return Err(Problem::malformed(
            "`replaces` names a certificate sharing no identifier with this order",
        ));
    }

    // "…has not already been marked as replaced by a different Order that is
    // not `invalid`" — the one case §5 gives a status and a type for.
    if let Some(existing) = Order::find_by_replaces(profile, cert_id, database)
        .await
        .map_err(|error| {
            error!(event = "replaces_conflict_lookup_failed", outcome = "failure", error = %error);
            Problem::server_internal("Replacement lookup failed")
        })?
    {
        warn!(
            event = "replaces_already_claimed",
            outcome = "failure",
            replaces = %cert_id,
            existing_order_id = %existing.id,
        );
        return Err(Problem::already_replaced(
            "This certificate has already been marked as replaced by another order",
        ));
    }

    info!(event = "replaces_accepted", outcome = "success", replaces = %cert_id, predecessor_order_id = %predecessor.id);
    Ok(cert_id.to_string())
}

/// Whether a failed order INSERT was the `replaces` claim losing a race.
///
/// Matched on the offending *column* rather than on "any unique violation": the
/// same transaction also inserts authorizations and challenges, each under its
/// own `UNIQUE` constraint, and reporting one of those as `alreadyReplaced`
/// would send a client chasing something entirely unrelated.
///
/// The column and not the index name — SQLite reports a partial unique index
/// violation as `UNIQUE constraint failed: orders.profile, orders.replaces`,
/// naming the columns and never `idx_orders_replaces_claim`. Pinned by
/// `sqlite::db::tests::one_predecessor_can_only_be_claimed_by_one_live_order`,
/// which asserts on the message this reads.
fn is_replaces_conflict(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation()
        && db.message().contains("orders.replaces"))
}

/// Builds the `certificate_issue_failed` row shared by `post_finalize`'s five
/// refusal arms.
///
/// A free function taking `&Order` rather than a closure capturing it: the
/// arms below sit either side of `order.mark_processing`/`order.finalize`, so a
/// closure holding a shared borrow of `order` would keep it alive across those
/// `&mut` calls and fail to compile — for no benefit, since the order is the
/// one thing that differs between where the closure is built and where it runs.
fn issue_failed(
    profile: &str,
    account_id: &str,
    order: &Order,
    client: &crate::audit::ClientContext,
    reason: &'static str,
    detail: &str,
) -> crate::audit::AuditRecord {
    crate::audit::AuditRecord::new(
        crate::audit::AuditEvent::CertificateIssueFailed,
        profile,
        crate::audit::Actor::acme(account_id),
    )
    .with_order(order)
    .with_client(client.clone())
    .with_reason(reason)
    .with_detail(detail)
}

/// Handles ACME newOrder requests (RFC 8555 §7.4).
#[instrument(name = "post_new_order", skip_all, fields(algorithm = %header.alg))]
pub async fn post_new_order(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    request_context: crate::audit::RequestContext,
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
    let challenges = &profile.challenges;

    if payload.identifiers.is_empty() {
        warn!(event = "order_no_identifiers", outcome = "failure");
        return Err(Problem::malformed("No identifiers"));
    }
    if let Some(bad) = payload.identifiers.iter().find(|id| id.typ != "dns") {
        warn!(event = "order_identifier_type_unsupported", outcome = "failure", typ = %bad.typ);
        return Err(Problem::unsupported_identifier(
            "Only dns identifiers supported",
        ));
    }

    let mut identifiers = payload.identifiers;
    for identifier in &mut identifiers {
        identifier.value = normalize_dns_name(&identifier.value);
    }

    // Every offending name at once, each attributed to itself (RFC 8555 §6.7.1).
    // Reporting only the first would make a ten-name order a ten-round-trip
    // guessing game — §6.7.1's own rationale: a client "may choose to submit
    // another order containing only the eight identifiers not listed".
    let rejections: Vec<Problem> = identifiers
        .iter()
        .filter_map(|identifier| {
            if !well_formed_name(&identifier.value) {
                warn!(event = "order_identifier_malformed", outcome = "failure", value = %identifier.value);
                Some(
                    Problem::malformed(format!(
                        "Malformed identifier {}: `*` is only legal as a single leading `*.`",
                        identifier.value
                    ))
                    .with_identifier(identifier),
                )
            } else if challenges
                .types_for(is_wildcard(&identifier.value))
                .is_empty()
            {
                warn!(event = "order_identifier_wildcard_rejected", outcome = "failure", value = %identifier.value);
                Some(
                    Problem::rejected_identifier(format!(
                        "Wildcard identifier {} requires the dns-01 challenge, which is not enabled",
                        identifier.value
                    ))
                    .with_identifier(identifier),
                )
            } else {
                None
            }
        })
        .collect();

    if !rejections.is_empty() {
        return Err(compound_identifier_problem(rejections));
    }

    let not_before = match payload.not_before {
        Some(ref s) => Some(parse_rfc3339("notBefore", s)?),
        None => None,
    };
    let not_after = match payload.not_after {
        Some(ref s) => Some(parse_rfc3339("notAfter", s)?),
        None => None,
    };

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;

    check_identifiers(
        &profile.filter,
        client_ip,
        &account.id,
        &profile.name,
        IdentifierStage::NewOrder,
        &identifiers,
        &database,
    )
    .await?;

    // RFC 9773 §5, run after `signer_account` so the "same ACME Account" check
    // has an account to compare against.
    let replaces = match payload.replaces {
        Some(ref cert_id) => Some(
            check_replaces(cert_id, &profile.name, &account.id, &identifiers, &database).await?,
        ),
        None => None,
    };

    let expires = now_secs() + profile.order.validity_seconds as i64;

    // The reverse lookup runs here rather than at the top of the handler: every
    // refusal above (malformed name, wildcard without dns-01, `alreadyReplaced`)
    // returns without an order to stamp, and a PTR query for a request that is
    // about to be turned away buys nothing.
    let client = audit.client(&request_context).await;
    let mut order = Order::new(
        &profile.name,
        &account.id,
        identifiers,
        expires,
        not_before,
        not_after,
    )
    .with_client(&client);
    order.replaces = replaces;
    let mut authz_ids = Vec::with_capacity(order.identifiers.len());

    let persisted = async {
        let mut tx = database.pool.begin().await?;
        order.insert(&mut *tx).await?;

        for identifier in &order.identifiers {
            let authz = Authorization::new(&order.id, identifier.clone(), order.expires);
            authz.insert(&mut *tx).await?;
            for typ in challenges.types_for(is_wildcard(&identifier.value)) {
                Challenge::new(&authz.id, typ).insert(&mut *tx).await?;
            }
            authz_ids.push(authz.id);
        }

        tx.commit().await
    }
    .await;

    persisted.map_err(|error| {
        // The predecessor was claimed by another order between `check_replaces`
        // reading and this transaction committing. The partial unique index on
        // `(profile, replaces)` is what catches it; without that arm the loser
        // of the race would get a 500 for a condition RFC 9773 §5 gives a
        // status and a type for.
        if is_replaces_conflict(&error) {
            warn!(event = "replaces_claim_race_lost", outcome = "failure", account_id = %account.id);
            return Problem::already_replaced(
                "This certificate has already been marked as replaced by another order",
            );
        }
        error!(
            event = "order_creation_failed",
            outcome = "failure",
            error = %error,
            account_id = %account.id
        );
        Problem::server_internal("Order persistence failed")
    })?;

    let location = format!("{base}/order/{}", order.id);
    info!(
        event = "order_created",
        outcome = "success",
        order_id = %order.id,
        account_id = %account.id,
        identifiers_count = order.identifiers.len()
    );

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
    let authz_ids = order_authz_ids(&order.id, &database).await?;
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
fn order_response(order: &Order, base: &str, authz_ids: &[String]) -> Response {
    let mut response = Json(order.to_json(base, authz_ids)).into_response();
    if order.status == "processing" {
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
    request_context: crate::audit::RequestContext,
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
        ..
    } = state;
    let base = &profile.base_url;
    let (signer, filter) = (&profile.signer, &profile.filter);

    let account = signer_account(account, &profile.name, &pubkey, &database).await?;
    let mut order = load_owned_order(&id, &account, &database).await?;

    if order.status != "ready" {
        warn!(event = "order_finalize_not_ready", outcome = "failure", order_id = %id, status = %order.status);
        return Err(Problem::order_not_ready("Order is not ready"));
    }

    // From here down every refusal is a *CA* refusal — the CSR was rejected, or
    // a filter said no, or issuance failed — so each one is an `audit_log` row
    // rather than only a log line. Above this point the refusals are protocol
    // bookkeeping (unknown order, wrong owner, not ready) with no CA action
    // attempted, and recording them would bury the ones that matter.
    //
    // The reverse lookup runs once here and is reused by whichever arm answers.
    let client = audit.client(&request_context).await;
    let failed = |order: &Order, reason: &'static str, detail: &str| {
        issue_failed(&profile.name, &account.id, order, &client, reason, detail)
    };

    let csr_der = match BASE64_URL_SAFE_NO_PAD.decode(&payload.csr) {
        Ok(der) => der,
        Err(_) => {
            audit
                .record(failed(&order, "badCSR", "CSR base64 invalid"))
                .await;
            return Err(Problem::bad_csr("CSR base64 invalid"));
        }
    };
    let csr = match parse_csr(&csr_der) {
        Ok(csr) => csr,
        Err(problem) => {
            audit
                .record(failed(&order, "badCSR", "CSR is unparsable"))
                .await;
            return Err(problem);
        }
    };

    // Before the filter chain: this is the most fundamental and least
    // expensive check, and doing it first guarantees that a filter — or the script
    // of a `custom` backend — never sees anything but a CSR already in agreement with its
    // order.
    if let Err(problem) = check_csr_matches_order(&csr, &order.identifiers) {
        audit
            .record(failed(
                &order,
                "badCSR",
                "CSR identifiers do not match the order",
            ))
            .await;
        return Err(problem);
    }

    // Gated on the *identifier* stage specifically: a policy of nothing but
    // connection-stage rules would otherwise pay for a CSR projection nothing
    // reads.
    if filter.has_rules_at(FilterStage::Identifiers) {
        let requested = csr_identifiers(&csr);
        if let Err(problem) = check_identifiers(
            filter,
            client_ip,
            &order.account_id,
            &profile.name,
            IdentifierStage::Csr,
            &requested,
            &database,
        )
        .await
        {
            // A refusal and a policy the server could not evaluate are
            // different things, and the trail said "badCSR" for both until
            // three-valued verdicts made the second visible. `500` here means
            // nobody decided anything about this CSR.
            let (reason, detail) = if problem.status() == StatusCode::BAD_REQUEST {
                ("badCSR", "the filter policy refused the CSR identifiers")
            } else {
                (
                    "serverInternal",
                    "the filter policy could not be evaluated for the CSR identifiers",
                )
            };
            audit.record(failed(&order, reason, detail)).await;
            return Err(problem);
        }
    }

    // The order's own `notBefore`/`notAfter` (RFC 8555 §7.4), which the order
    // object has always echoed back — passing them on is what stops the echo
    // being a fiction. The backend clamps or ignores them; see
    // `RequestedValidity`.
    let validity = RequestedValidity {
        not_before: order.not_before,
        not_after: order.not_after,
    };
    let issued = signer
        .issue(&order.id, &csr_der, &order.identifiers, validity)
        .await;
    let chain = match issued {
        Ok(IssueOutcome::Issued(chain)) => chain,
        // A delegating backend took the CSR but resolves it elsewhere. It owns
        // the order from here — it will call `finalize`/`mark_invalid` itself —
        // so all this handler does is publish the `processing` status the
        // client polls on (RFC 8555 §7.4). No `CertificateIssued` dispatch
        // here: the certificate isn't issued yet. That notification fires
        // later from `signer::relay::settle`, once the backend's
        // background relay actually completes — not a gap, deliberate.
        Ok(IssueOutcome::Processing) => {
            order.mark_processing(&database).await.map_err(|error| {
                error!(
                    event = "order_mark_processing_failed",
                    outcome = "failure",
                    order_id = %id,
                    error = %error
                );
                Problem::server_internal("Order finalize failed")
            })?;
            // No audit row here — nothing has been signed yet. The one row for
            // this issuance is written by `signer::relay::flow::settle`
            // when the upstream actually answers, and this is what lets it
            // carry the address of the client that asked: the relay runs from a
            // background task with no request in scope. See
            // `UpstreamOrder::set_client` for why it is stored rather than
            // passed, and for the ordering.
            if let Err(error) =
                crate::sqlite::upstream_order::UpstreamOrder::set_client(&id, &client, &database)
                    .await
            {
                warn!(
                    event = "upstream_order_client_context_failed",
                    outcome = "failure",
                    order_id = %id,
                    error = %error
                );
            }
            let authz_ids = order_authz_ids(&order.id, &database).await?;
            info!(event = "order_finalize_delegated", outcome = "success", order_id = %id);
            return Ok(order_response(&order, base, &authz_ids));
        }
        Err(SignerError::BadCsr) => {
            warn!(
                event = "order_finalize_bad_csr",
                outcome = "failure",
                order_id = %id
            );
            audit
                .record(failed(
                    &order,
                    "badCSR",
                    "the signer backend rejected the CSR",
                ))
                .await;
            return Err(Problem::bad_csr("CSR invalid or does not match order"));
        }
        Err(SignerError::Internal(detail)) => {
            error!(
                event = "order_finalize_issuance_failed",
                outcome = "failure",
                order_id = %id,
                detail = %detail
            );
            audit
                .record(failed(&order, "serverInternal", &detail))
                .await;
            let problem = Problem::server_internal("Certificate issuance failed");
            if let Err(error) = order.mark_invalid(problem.to_value(), &database).await {
                error!(
                    event = "order_mark_invalid_failed",
                    outcome = "failure",
                    order_id = %id,
                    error = %error
                );
            }
            return Err(problem);
        }
    };

    let leaf_der = crate::cert::leaf_der_from_chain(&chain).map_err(|error| {
        error!(event = "order_finalize_chain_unparsable", outcome = "failure", order_id = %id, error = %error);
        Problem::server_internal("Issued certificate chain is unparsable")
    })?;
    let (cert_serial, cert_pubkey) =
        crate::cert::cert_serial_and_spki(&leaf_der).map_err(|error| {
            error!(event = "order_finalize_leaf_unparsable", outcome = "failure", order_id = %id, error = %error);
            Problem::server_internal("Issued certificate is unparsable")
        })?;

    order
        .finalize(chain, cert_serial.clone(), cert_pubkey, &database)
        .await
        .map_err(|error| {
            error!(
                event = "order_finalize_persistence_failed",
                outcome = "failure",
                order_id = %id,
                error = %error
            );
            Problem::server_internal("Order finalize failed")
        })?;

    let authz_ids = order_authz_ids(&order.id, &database).await?;
    info!(
        event = "order_finalized",
        outcome = "success",
        order_id = %id,
        cert_serial = %cert_serial
    );
    audit
        .record(
            crate::audit::AuditRecord::new(
                crate::audit::AuditEvent::CertificateIssued,
                &profile.name,
                crate::audit::Actor::acme(&account.id),
            )
            .with_order(&order)
            .with_client(client)
            .with_serial(cert_serial.clone()),
        )
        .await;
    profile
        .notify
        .dispatch(crate::notify::NotifyEvent::CertificateIssued(
            crate::notify::CertificateIssuedData {
                profile: profile.name.clone(),
                order_id: order.id.clone(),
                account_id: order.account_id.clone(),
                cert_serial: cert_serial.clone(),
                identifiers: order.identifiers.iter().map(|i| i.value.clone()).collect(),
                client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
            },
        ))
        .await;
    Ok(order_response(&order, base, &authz_ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::db::Database;

    /// The unique-violation arm in `post_new_order` only fires when two
    /// newOrder requests race — `check_replaces` and the partial index share a
    /// predicate, so nothing but real concurrency can make them disagree. This
    /// drives the matcher against errors the database actually produces, which
    /// is the part that can silently rot: SQLite names the offending *columns*,
    /// not the index, so a matcher written against the index name would fall
    /// through to a 500 and no test of the happy path would notice.
    #[tokio::test]
    async fn a_replaces_collision_is_told_apart_from_other_unique_violations() {
        let database = Database::connect_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES ('acct', 'default', X'00', '[]', 'valid', 0);",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        let order = |id: &'static str, replaces: &'static str| {
            let pool = database.pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, \
                     replaces, created_at) VALUES (?, 'default', 'acct', 'pending', '[]', 0, ?, 0);",
                )
                .bind(id)
                .bind(replaces)
                .execute(&pool)
                .await
            }
        };

        order("first", "predecessor-cert-id").await.unwrap();
        let collision = order("second", "predecessor-cert-id").await.unwrap_err();
        assert!(is_replaces_conflict(&collision), "got {collision}");

        // The same transaction inserts authorizations under their own
        // `UNIQUE(order_id, identifier)`. That must not be reported to a client
        // as `alreadyReplaced`.
        let authz = |id: &'static str| {
            let pool = database.pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO authorizations (id, order_id, identifier, status, expires, \
                     created_at) VALUES (?, 'first', '{\"type\":\"dns\",\"value\":\"a.example.com\"}', \
                     'pending', 0, 0);",
                )
                .bind(id)
                .execute(&pool)
                .await
            }
        };
        authz("authz-one").await.unwrap();
        let other = authz("authz-two").await.unwrap_err();
        assert!(
            !is_replaces_conflict(&other),
            "an authorization collision must not read as alreadyReplaced: {other}"
        );

        // And an unrelated failure is not swept in either.
        let missing = sqlx::query("INSERT INTO orders (id) VALUES ('x');")
            .execute(&database.pool)
            .await
            .unwrap_err();
        assert!(!is_replaces_conflict(&missing));
    }
}
