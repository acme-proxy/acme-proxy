//! The order state machine: authorizations, challenges, finalization and
//! revocation, as operations on stored rows rather than on HTTP requests.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use base64::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::access::signer_account;
use super::error::Error;
use super::policy::{challenge_problem, check_identifiers};
use super::rules::{
    check_csr_matches_order, csr_identifiers, is_wildcard, normalize_dns_name, parse_csr,
    parse_rfc3339, well_formed_name,
};
use crate::profile::Profile;
use acme_proxy_core::audit::RequestContext;
use acme_proxy_core::error::Problem;
use acme_proxy_core::identifier::Identifier;
use acme_proxy_core::jws::signature::jwk_thumbprint;
use acme_proxy_jobs::auditor::Auditor;
use acme_proxy_jobs::jobs::JobQueue;
use acme_proxy_jobs::notify::ChallengeFailedData;
use acme_proxy_jobs::notify::NotifyEvent;
use acme_proxy_net::challenge::ValidationContext;
use acme_proxy_policy::filter::IdentifierStage;
use acme_proxy_policy::filter::Stage as FilterStage;
use acme_proxy_store::account::Account;
use acme_proxy_store::authz::Authorization;
use acme_proxy_store::authz::Challenge;
use acme_proxy_store::db::Database;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::order::Order;
use acme_proxy_store::status::AuthzStatus;
use acme_proxy_store::status::ChallengeStatus;
use acme_proxy_store::status::OrderStatus;

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
    account_id: Uuid,
    identifiers: &[Identifier],
    database: &Arc<Database>,
) -> Result<String, Problem> {
    // Parsed with the same helper `GET /renewalInfo/{certID}` uses: §5 defines
    // the field as "constructed in the same way as the path component for GET
    // requests described in Section 4.1", so the two must not drift.
    let parsed = acme_proxy_core::cert::parse_ari_cert_id(cert_id).map_err(|error| {
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
        && let Ok(leaf_der) = acme_proxy_core::cert::leaf_der_from_chain(certificate)
        && let Ok((aki, _)) = acme_proxy_core::cert::ari_cert_id_parts(&leaf_der)
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
/// `acme_proxy_store::db::tests::one_predecessor_can_only_be_claimed_by_one_live_order`,
/// which asserts on the message this reads.
fn is_replaces_conflict(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation()
        && db.message().contains("orders.replaces"))
}

/// Builds the `certificate_issue_failed` row shared by `finalize`'s four
/// refusal arms.
///
/// A free function taking `&Order` rather than a closure capturing it, so the
/// order stays free to be claimed after the refusals are behind it.
fn issue_failed(
    profile: &str,
    account_id: Uuid,
    order: &Order,
    client: &acme_proxy_core::audit::ClientContext,
    reason: &'static str,
    detail: &str,
) -> acme_proxy_core::audit::AuditRecord {
    acme_proxy_core::audit::AuditRecord::new(
        acme_proxy_core::audit::AuditEvent::CertificateIssueFailed,
        profile,
        acme_proxy_core::audit::Actor::acme(account_id),
    )
    .with_order(order.id, order.account_id, &order.identifiers)
    .with_client(client.clone())
    .with_reason(reason)
    .with_detail(detail)
}

/// The order-side operations of one endpoint.
///
/// A borrowed bundle rather than an owned service: every caller already holds
/// these — the ACME handlers in `AppState`, the web admin in `AdminState`, a
/// background job in its own state — and building one is three references.
/// The profile is the endpoint's whole configuration (its signer, filter,
/// validators and notifier), which is what makes one operation mean the same
/// thing whichever front end reached it.
pub struct OrderService<'a> {
    pub database: &'a Arc<Database>,
    pub audit: &'a Auditor,
    pub profile: &'a Profile,
}

impl OrderService<'_> {
    /// Creates an order and its authorizations (RFC 8555 §7.4), for the account
    /// that signed the request.
    ///
    /// `cached` is the account the JWS `kid` already resolved, if any. It is
    /// resolved here, *after* the identifiers are checked, so a malformed order
    /// is refused as malformed whoever sent it. `request` is where the reverse
    /// lookup that stamps the order comes from — run late, since every refusal
    /// above it would have wasted one.
    pub async fn new_order(
        &self,
        payload: NewOrderPayload,
        cached: Option<Account>,
        pubkey: &[u8],
        client_ip: Option<IpAddr>,
        request: &RequestContext,
    ) -> Result<(Order, Vec<Uuid>), Error> {
        let (database, profile, audit) = (self.database, self.profile, self.audit);
        let challenges = &profile.challenges;

        if payload.identifiers.is_empty() {
            warn!(event = "order_no_identifiers", outcome = "failure");
            return Err(Problem::malformed("No identifiers").into());
        }
        // Before anything is normalized or looked at: the cost this refuses is the
        // work below, and every bit of it scales with the count.
        if payload.identifiers.len() > profile.order.max_identifiers {
            warn!(
                event = "order_too_many_identifiers",
                outcome = "failure",
                identifiers_count = payload.identifiers.len(),
                limit = profile.order.max_identifiers
            );
            return Err(Problem::malformed(format!(
                "An order may name at most {} identifiers; this one names {}",
                profile.order.max_identifiers,
                payload.identifiers.len()
            ))
            .into());
        }
        if let Some(bad) = payload.identifiers.iter().find(|id| id.typ != "dns") {
            warn!(event = "order_identifier_type_unsupported", outcome = "failure", typ = %bad.typ);
            return Err(Problem::unsupported_identifier("Only dns identifiers supported").into());
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
            return Err(compound_identifier_problem(rejections).into());
        }

        let not_before = match payload.not_before {
            Some(ref s) => Some(parse_rfc3339("notBefore", s)?),
            None => None,
        };
        let not_after = match payload.not_after {
            Some(ref s) => Some(parse_rfc3339("notAfter", s)?),
            None => None,
        };

        let account = signer_account(cached, &profile.name, pubkey, database).await?;

        check_identifiers(
            &profile.filter,
            client_ip,
            &account.id.to_string(),
            &profile.name,
            IdentifierStage::NewOrder,
            &identifiers,
            database,
        )
        .await?;

        // RFC 9773 §5, run after `signer_account` so the "same ACME Account" check
        // has an account to compare against.
        let replaces = match payload.replaces {
            Some(ref cert_id) => Some(
                check_replaces(cert_id, &profile.name, account.id, &identifiers, database).await?,
            ),
            None => None,
        };

        let expires = now_secs() + profile.order.validity_seconds as i64;

        // The reverse lookup runs here rather than at the top of the handler: every
        // refusal above (malformed name, wildcard without dns-01, `alreadyReplaced`)
        // returns without an order to stamp, and a PTR query for a request that is
        // about to be turned away buys nothing.
        let client = audit.client(request).await;
        let mut order = Order::new(
            &profile.name,
            account.id,
            identifiers,
            expires,
            not_before,
            not_after,
        )
        .with_client(&client);
        order.replaces = replaces;
        let mut authz_ids = Vec::with_capacity(order.identifiers.len());

        let persisted = async {
            let mut tx = database.transaction().await?;
            order.insert(&mut *tx).await?;

            for identifier in &order.identifiers {
                let authz = Authorization::new(order.id, identifier.clone(), order.expires);
                authz.insert(&mut *tx).await?;
                for typ in challenges.types_for(is_wildcard(&identifier.value)) {
                    Challenge::new(authz.id, typ).insert(&mut *tx).await?;
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

        info!(
            event = "order_created",
            outcome = "success",
            order_id = %order.id,
            account_id = %account.id,
            identifiers_count = order.identifiers.len()
        );

        Ok((order, authz_ids))
    }

    /// Deactivates `authz` and re-derives its order's status (RFC 8555 §7.5.2).
    ///
    /// Already-`deactivated` is a no-op rather than an error: §7.5.2 describes the
    /// client sending the same static object to *each* authorization of an
    /// identifier, and a retry after a partial failure must not start reporting
    /// errors halfway through.
    pub async fn deactivate_authz(
        &self,
        authz: &mut Authorization,
        order: &mut Order,
    ) -> Result<(), Error> {
        let database = self.database;
        if authz.status == AuthzStatus::Deactivated {
            return Ok(());
        }

        // A certificate already exists for this order, so relinquishing the
        // authorization it was issued under would claim something untrue. §7.5.2 is
        // about giving up the *ability* to issue, not about undoing issuance —
        // that is what revocation (§7.6) is for.
        if order.status == OrderStatus::Valid {
            warn!(event = "authz_deactivate_refused_order_valid", outcome = "failure", authz_id = %authz.id, order_id = %order.id);
            return Err(Problem::malformed(
                "Cannot deactivate an authorization whose order has already been issued; revoke the certificate instead",
            )
            .into());
        }

        if authz.status != AuthzStatus::Pending && authz.status != AuthzStatus::Valid {
            warn!(event = "authz_deactivate_refused_terminal", outcome = "failure", authz_id = %authz.id, status = %authz.status);
            return Err(Problem::malformed(
                "Authorization is in a terminal state and cannot be deactivated",
            )
            .into());
        }

        // §7.5.2: "The server MUST NOT treat deactivated authorization objects as
        // sufficient for issuing certificates." For a `pending` order that falls
        // out of the readiness check on its own, but an order already promoted to
        // `ready` would still finalize — so demote it.
        //
        // Both in one transaction. Between them, an order sits `ready` with a
        // deactivated authorization under it: finalizable for a name the client has
        // just given up, which is exactly what §7.5.2 forbids.
        let demote = order.status == OrderStatus::Ready;
        let outcome = async {
            let mut tx = database.transaction().await?;
            Authorization::set_deactivated(authz.id, &mut *tx).await?;
            if demote {
                Order::set_pending(order.id, &mut *tx).await?;
            }
            tx.commit().await
        }
        .await;

        outcome.map_err(|error| {
            error!(event = "authz_deactivate_failed", outcome = "failure", authz_id = %authz.id, error = %error);
            Problem::server_internal("Authorization deactivation failed")
        })?;

        // Only once the transaction has committed: a rollback must not leave these
        // objects claiming a status the database never took.
        authz.status = AuthzStatus::Deactivated;
        if demote {
            order.status = OrderStatus::Pending;
        }

        info!(event = "authz_deactivated", outcome = "success", authz_id = %authz.id, order_id = %order.id);
        Ok(())
    }

    /// Decides whether a challenge trigger (RFC 8555 §7.5.1) starts a
    /// validation, and if so claims the challenge for it.
    ///
    /// `Ok(false)` is not a refusal: the challenge is already decided — here or
    /// by a sibling — or another trigger holds the claim, and the caller answers
    /// with the challenge as it stands. `Ok(true)` obliges the caller to follow
    /// with [`run_validation`](Self::run_validation).
    pub async fn claim_challenge(
        &self,
        challenge: &mut Challenge,
        authz: &Authorization,
    ) -> Result<bool, Error> {
        if authz.status != AuthzStatus::Valid && authz.expires <= now_secs() {
            warn!(event = "authz_expired", outcome = "failure", authz_id = %authz.id, expires = authz.expires);
            return Err(Problem::malformed("Authorization has expired").into());
        }

        // The client gave this authorization up (RFC 8555 §7.5.2). Validating a
        // challenge under it would walk it straight back to `valid` — which §7.5.2
        // forbids being sufficient for issuance — so refuse before doing any work.
        if authz.status == AuthzStatus::Deactivated {
            warn!(event = "authz_already_deactivated", outcome = "failure", authz_id = %authz.id);
            return Err(Problem::malformed("Authorization has been deactivated").into());
        }

        // Already answered, here or by a sibling: §7.5.1's "client requests for
        // retries do not cause a state change".
        let decided = challenge.status == ChallengeStatus::Valid
            || challenge.status == ChallengeStatus::Invalid
            || authz.status == AuthzStatus::Valid;

        // The claim, and the reason it is a claim rather than the status check
        // above: `challenges.validate` reaches out to an address the *client*
        // named, so two triggers that both read this row as `pending` become two
        // probes of that host from this server — bounded only by
        // `server.max_concurrent_requests`, on a default configuration with no
        // filter to refuse them. Deciding it in the `UPDATE` makes "one validation
        // per challenge" a property of the row instead of one of scheduling.
        //
        // The loser answers with the challenge as it now stands, which reports
        // `processing` — §8.2's answer for a challenge the server is still
        // working on.
        let claimed = !decided
            && challenge
                .claim_for_validation(self.database)
                .await
                .map_err(|error| {
                    error!(event = "challenge_claim_failed", outcome = "failure", challenge_id = %challenge.id, error = %error);
                    Problem::server_internal("Challenge could not be claimed for validation")
                })?;
        Ok(claimed)
    }

    /// Validates a challenge [`claim_challenge`](Self::claim_challenge) claimed,
    /// and records the answer.
    ///
    /// Either outcome is recorded — a failed validation is the challenge's
    /// answer, not an error of this call — so `Err` means only that the answer
    /// could not be computed or stored. On failure the operator hears about it
    /// through `challenge_failed`, after the commit.
    ///
    /// `client_ip` is the address the notification names: the client that
    /// triggered the validation, when there was one.
    pub async fn run_validation(
        &self,
        account: &Account,
        challenge: &mut Challenge,
        authz: &mut Authorization,
        order: &mut Order,
        client_ip: Option<IpAddr>,
    ) -> Result<(), Error> {
        let (database, profile) = (self.database, self.profile);
        let thumbprint = jwk_thumbprint(&account.pubkey).map_err(|error| {
            error!(event = "authz_thumbprint_failed", outcome = "failure", account_id = %account.id, error = %error);
            Problem::server_internal("Key authorization could not be computed")
        })?;
        let key_authorization = format!("{}.{}", challenge.token, thumbprint);
        let challenge_id = challenge.id.to_string();

        let context = ValidationContext {
            identifier: authz.base_identifier(),
            wildcard: authz.is_wildcard(),
            token: &challenge.token,
            key_authorization: &key_authorization,
            challenge_id: &challenge_id,
        };

        match profile.challenges.validate(&challenge.typ, &context).await {
            Ok(()) => {
                commit_validation(challenge, authz, order, database).await?;
            }
            Err(error) => {
                let problem = challenge_problem(&error).to_value();
                warn!(
                    event = "challenge_failed",
                    outcome = "failure",
                    challenge_id = %challenge_id,
                    typ = %challenge.typ,
                    kind = error.kind()
                );

                commit_validation_failure(challenge, authz, order, &problem, database).await?;

                // After the commit, not before. Dispatched first, a persistence
                // failure would have notified an operator about a failure that
                // was never recorded — and the client, which gets a 500, would
                // see the challenge still `pending`.
                profile
                    .notify
                    .dispatch(NotifyEvent::ChallengeFailed(ChallengeFailedData {
                        profile: profile.name.clone(),
                        order_id: order.id.to_string(),
                        account_id: account.id.to_string(),
                        authz_id: authz.id.to_string(),
                        challenge_id: challenge.id.clone().to_string(),
                        challenge_type: challenge.typ.clone(),
                        identifier: authz.base_identifier().to_string(),
                        error: error.kind().to_string(),
                        client_ip: client_ip
                            .map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
                    }))
                    .await;
            }
        }
        Ok(())
    }

    /// Records a claimed validation the server has given up on.
    ///
    /// The queue retires a row when its attempts run out or its deadline passes,
    /// and a challenge left `processing` at that point would be polled by its
    /// client, saying nothing, until the authorization expired. This writes the
    /// same failure `run_validation` writes — challenge, authorization and order
    /// together in one transaction — so the client sees an `invalid` order and
    /// stops.
    ///
    /// Deliberately **no `challenge_failed` notification**: nothing was learned
    /// about the client's own setup, which is what that event reports. The
    /// `challenge_validation_abandoned` log line is about this server instead.
    pub async fn abandon_validation(
        &self,
        challenge: &mut Challenge,
        authz: &mut Authorization,
        order: &mut Order,
        reason: &str,
    ) -> Result<(), Error> {
        let problem =
            Problem::server_internal(format!("Challenge validation was not completed: {reason}"))
                .to_value();
        commit_validation_failure(challenge, authz, order, &problem, self.database).await?;
        Ok(())
    }

    /// Finalizes `order` with the base64url CSR a client sent (RFC 8555 §7.4):
    /// checks the CSR, then claims the order and queues its issuance, returning
    /// it `processing`. The certificate arrives when a worker has run the
    /// `signer_issue` job ([`super::issue`]); the client polls for it.
    ///
    /// `account` must already own `order` (`access::load_owned_order`).
    pub async fn finalize(
        &self,
        account: &Account,
        mut order: Order,
        csr: &str,
        client_ip: Option<IpAddr>,
        request: &RequestContext,
        jobs: &JobQueue,
    ) -> Result<Order, Error> {
        let (database, profile, audit) = (self.database, self.profile, self.audit);
        let filter = &profile.filter;

        let id = order.id.to_string();
        if order.status != OrderStatus::Ready {
            warn!(event = "order_finalize_not_ready", outcome = "failure", order_id = %id, status = %order.status);
            return Err(Problem::order_not_ready("Order is not ready").into());
        }

        // From here down every refusal is a *CA* refusal — the CSR was rejected, or
        // a filter said no, or issuance failed — so each one is an `audit_log` row
        // rather than only a log line. Above this point the refusals are protocol
        // bookkeeping (unknown order, wrong owner, not ready) with no CA action
        // attempted, and recording them would bury the ones that matter.
        //
        // The reverse lookup runs once here and is reused by whichever arm answers.
        let client = audit.client(request).await;
        let failed = |order: &Order, reason: &'static str, detail: &str| {
            issue_failed(&profile.name, account.id, order, &client, reason, detail)
        };

        let csr_der = match BASE64_URL_SAFE_NO_PAD.decode(csr) {
            Ok(der) => der,
            Err(_) => {
                audit
                    .record(failed(&order, "badCSR", "CSR base64 invalid"))
                    .await;
                return Err(Problem::bad_csr("CSR base64 invalid").into());
            }
        };
        let csr = match parse_csr(&csr_der) {
            Ok(csr) => csr,
            Err(problem) => {
                audit
                    .record(failed(&order, "badCSR", "CSR is unparsable"))
                    .await;
                return Err(problem.into());
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
            return Err(problem.into());
        }

        // Gated on the *identifier* stage specifically: a policy of nothing but
        // connection-stage rules would otherwise pay for a CSR projection nothing
        // reads.
        if filter.has_rules_at(FilterStage::Identifiers) {
            let requested = csr_identifiers(&csr);
            if let Err(problem) = check_identifiers(
                filter,
                client_ip,
                order.account_id.to_string().as_str(),
                &profile.name,
                IdentifierStage::Csr,
                &requested,
                database,
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
                return Err(problem.into());
            }
        }

        // Claimed here rather than at the `ready` check above, so no refusal
        // above owes a release — and claimed **with** the job that settles it,
        // in one transaction, so no crash can leave an order `processing` with
        // nothing coming for it.
        //
        // The loser gets §7.4's own answer — `403 orderNotReady`, on which the
        // client POST-as-GETs the order and sees `processing`, then `valid`. No
        // audit row: like the not-ready refusal above, this is protocol
        // bookkeeping with no CA action attempted.
        let spec = super::issue::signer_issue_spec(&order, &csr_der, &client, client_ip);
        let claimed = async {
            let mut tx = database.transaction().await?;
            if !order.claim_for_finalize_on(&mut *tx).await? {
                return Ok(false);
            }
            jobs.enqueue_in(&spec, &mut tx).await?;
            tx.commit().await?;
            Ok::<bool, sqlx::Error>(true)
        }
        .await;
        match claimed {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    event = "order_finalize_claim_refused",
                    outcome = "failure",
                    order_id = %id
                );
                return Err(Problem::order_not_ready("Order is already being finalized").into());
            }
            Err(error) => {
                error!(
                    event = "order_mark_processing_failed",
                    outcome = "failure",
                    order_id = %id,
                    error = %error
                );
                return Err(Problem::server_internal("Order finalize failed").into());
            }
        }
        jobs.wake();

        info!(event = "order_finalize_queued", outcome = "success", order_id = %id);
        Ok(order)
    }
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
        let mut tx = database.transaction().await?;
        Challenge::set_valid(challenge.id, validated, &mut *tx).await?;
        Authorization::set_valid(authz.id, &mut *tx).await?;

        // `transaction()` issues a deferred BEGIN, but the two writes above
        // have already taken the RESERVED lock by the time this reads — so this
        // sees its own write and no other writer can interleave. Putting a read
        // first here would break that.
        let promote = order.status == OrderStatus::Pending && {
            let authzs = Authorization::find_by_order_with(order.id, &mut *tx).await?;
            authzs.len() == order.identifiers.len()
                && authzs
                    .iter()
                    .all(|authz| authz.status == AuthzStatus::Valid)
        };
        if promote {
            Order::set_ready(order.id, &mut *tx).await?;
        }
        tx.commit().await?;
        Ok::<bool, sqlx::Error>(promote)
    }
    .await;

    match outcome {
        Ok(promoted) => {
            // In-memory sync only after the commit; see `Authorization::set_valid`.
            challenge.status = ChallengeStatus::Valid;
            challenge.validated = Some(validated);
            authz.status = AuthzStatus::Valid;
            if promoted {
                order.status = OrderStatus::Ready;
            }
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_validation_persist_failed",
                outcome = "failure",
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
        let mut tx = database.transaction().await?;
        Challenge::set_invalid(challenge.id, problem, &mut *tx).await?;
        Authorization::set_invalid(authz.id, &mut *tx).await?;
        Order::set_invalid(order.id, problem, &mut *tx).await?;
        tx.commit().await
    }
    .await;

    match outcome {
        Ok(()) => {
            challenge.status = ChallengeStatus::Invalid;
            challenge.error = Some(problem.clone());
            authz.status = AuthzStatus::Invalid;
            order.status = OrderStatus::Invalid;
            order.error = Some(problem.clone());
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_failure_persist_failed",
                outcome = "failure",
                challenge_id = %challenge.id,
                authz_id = %authz.id,
                order_id = %order.id,
                error = %error
            );
            Err(Problem::server_internal("Challenge validation failed"))
        }
    }
}

/// `pub(crate)` so the sibling job suite can reuse `profile` and `account`
/// rather than growing a second copy of each — the rule `crates/signer/src/testutil.rs`
/// exists for, applied to two fixtures too entangled with this module's
/// `OrderService` to live there.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::profile::ProfileParts;
    use acme_proxy_core::identifier::Identifier;
    use acme_proxy_jobs::notify::NotifyDispatcher;
    use acme_proxy_net::challenge::ChallengeError;
    use acme_proxy_net::challenge::ChallengeRegistry;
    use acme_proxy_net::challenge::ChallengeValidator;
    use std::time::Duration;

    /// A `default` profile over `database`: an in-memory CA, no filter, no
    /// notifier, and `challenges` as the validators.
    pub(crate) fn profile(database: &Arc<Database>, challenges: ChallengeRegistry) -> Profile {
        let ca = acme_proxy_signer::local_ca::LocalCa::generate_in_memory(
            "ecdsa-p256",
            90,
            database.clone(),
        )
        .unwrap();
        profile_with(database, challenges, Arc::new(ca))
    }

    /// [`profile`] over a signer of the caller's choosing.
    pub(crate) fn profile_with(
        database: &Arc<Database>,
        challenges: ChallengeRegistry,
        signer: Arc<dyn acme_proxy_signer::SignerBackend>,
    ) -> Profile {
        Profile::new(
            "default",
            "http://localhost:3000",
            ProfileParts {
                signer_info: signer.info(),
                filter: Arc::new(acme_proxy_policy::filter::FilterPolicy::default()),
                challenges: Arc::new(challenges),
                order: acme_proxy_core::config::OrderConfig::default(),
                eab: acme_proxy_core::config::EabConfig::default(),
                meta: acme_proxy_core::config::MetaConfig::default(),
                notify: Arc::new(NotifyDispatcher::disabled(
                    acme_proxy_jobs::testutil::idle_job_queue(database.clone()),
                )),
            },
        )
    }

    /// An account whose stored key is a real SPKI, so a key authorization can
    /// be computed from it.
    pub(crate) async fn account(database: &Arc<Database>) -> Account {
        use rcgen::PublicKeyData;
        let key = rcgen::KeyPair::generate().unwrap();
        Account::find_or_create(
            "default",
            &key.subject_public_key_info(),
            vec![],
            &acme_proxy_core::audit::ClientContext::default(),
            database,
        )
        .await
        .unwrap()
        .0
    }

    /// An order for `names`, one pending authorization and `http-01` challenge
    /// each.
    async fn pending_order(
        database: &Arc<Database>,
        account: &Account,
        names: &[&str],
    ) -> (Order, Vec<(Authorization, Challenge)>) {
        let order = Order::create(
            "default",
            account.id,
            acme_proxy_store::testutil::dns_identifiers(names),
            now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap();
        let mut authzs = Vec::new();
        for name in names {
            let authz =
                Authorization::create(order.id, Identifier::dns(*name), order.expires, database)
                    .await
                    .unwrap();
            let challenge = Challenge::create(authz.id, "http-01", database)
                .await
                .unwrap();
            authzs.push((authz, challenge));
        }
        (order, authzs)
    }

    async fn reload(database: &Database, order: &Order) -> Order {
        Order::find_by_id(&order.id.to_string(), database)
            .await
            .unwrap()
            .unwrap()
    }

    /// A validator refusing every attempt.
    struct Refusing;

    #[async_trait::async_trait]
    impl ChallengeValidator for Refusing {
        fn typ(&self) -> &'static str {
            "http-01"
        }
        async fn validate(&self, _ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
            Err(ChallengeError::IncorrectResponse("wrong body".into()))
        }
    }

    #[tokio::test]
    async fn deactivating_under_a_ready_order_demotes_it_in_the_same_write() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        orders
            .run_validation(&account, challenge, authz, &mut order, None)
            .await
            .unwrap();
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Ready);

        orders.deactivate_authz(authz, &mut order).await.unwrap();
        assert_eq!(authz.status, AuthzStatus::Deactivated);
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Pending);

        // A repeat is a no-op, not an error.
        orders.deactivate_authz(authz, &mut order).await.unwrap();

        // And the challenge under it can no longer be triggered.
        let refused = orders.claim_challenge(challenge, authz).await.unwrap_err();
        assert_eq!(
            Problem::from(refused).to_value()["detail"],
            "Authorization has been deactivated"
        );
    }

    #[tokio::test]
    async fn an_issued_order_refuses_deactivation() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        order.status = OrderStatus::Valid;

        let refused = orders
            .deactivate_authz(&mut authzs[0].0, &mut order)
            .await
            .unwrap_err();
        assert_eq!(Problem::from(refused).status(), 400);
        assert_eq!(authzs[0].0.status, AuthzStatus::Pending);
    }

    /// The claim is what makes "one validation per challenge" a property of the
    /// row: the second trigger answers without validating.
    #[tokio::test]
    async fn a_challenge_is_claimed_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (_, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];
        let mut twin = Challenge::find_by_id(&challenge.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        assert!(!orders.claim_challenge(&mut twin, authz).await.unwrap());
    }

    /// Two authorizations of one order validated at once: whichever commits
    /// second reads both as `valid` inside its own transaction and promotes.
    #[tokio::test]
    async fn concurrent_validations_of_one_order_promote_it() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, authzs) =
            pending_order(&database, &account, &["a.example.com", "b.example.com"]).await;
        let mut authzs = authzs.into_iter();
        let (mut authz_a, mut challenge_a) = authzs.next().unwrap();
        let (mut authz_b, mut challenge_b) = authzs.next().unwrap();
        let (mut order_a, mut order_b) = (
            reload(&database, &order).await,
            reload(&database, &order).await,
        );

        let a = async {
            assert!(
                orders
                    .claim_challenge(&mut challenge_a, &authz_a)
                    .await
                    .unwrap()
            );
            orders
                .run_validation(&account, &mut challenge_a, &mut authz_a, &mut order_a, None)
                .await
                .unwrap();
        };
        let b = async {
            assert!(
                orders
                    .claim_challenge(&mut challenge_b, &authz_b)
                    .await
                    .unwrap()
            );
            orders
                .run_validation(&account, &mut challenge_b, &mut authz_b, &mut order_b, None)
                .await
                .unwrap();
        };
        tokio::join!(a, b);

        assert_eq!(reload(&database, &order).await.status, OrderStatus::Ready);
    }

    #[tokio::test]
    async fn a_failed_validation_invalidates_challenge_authorization_and_order_together() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(
            &database,
            ChallengeRegistry::new(
                vec![Arc::new(Refusing)],
                vec!["http-01".to_string()],
                false,
                Duration::from_secs(5),
            ),
        );
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        orders
            .run_validation(&account, challenge, authz, &mut order, None)
            .await
            .expect("a refused validation is the challenge's answer, not an error");

        let stored = Challenge::find_by_id(&challenge.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, ChallengeStatus::Invalid);
        assert_eq!(
            stored.error.unwrap()["type"],
            "urn:ietf:params:acme:error:incorrectResponse"
        );
        let reloaded = reload(&database, &order).await;
        assert_eq!(reloaded.status, OrderStatus::Invalid);
        assert_eq!(authz.status, AuthzStatus::Invalid);
    }

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
        .execute(database.raw_pool())
        .await
        .unwrap();

        let order = |id: &'static str, replaces: &'static str| {
            let pool = database.raw_pool().clone();
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
            let pool = database.raw_pool().clone();
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
            .execute(database.raw_pool())
            .await
            .unwrap_err();
        assert!(!is_replaces_conflict(&missing));
    }

    /// A `ready` order for `a.example.com` plus a CSR matching it, base64url.
    pub(crate) async fn ready_order(
        database: &Arc<Database>,
        account: &Account,
    ) -> (Order, String) {
        let (order, _) = pending_order(database, account, &["a.example.com"]).await;
        Order::set_ready(order.id, database.raw_pool())
            .await
            .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(vec!["a.example.com".to_string()])
            .unwrap()
            .serialize_request(&key)
            .unwrap();
        (
            reload(database, &order).await,
            BASE64_URL_SAFE_NO_PAD.encode(csr.der()),
        )
    }

    /// Finalizes a fresh `ready` order, returning the database, the order as
    /// it was, and what `finalize` answered.
    async fn finalize_ready() -> (Arc<Database>, Order, Result<Order, Error>) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, csr) = ready_order(&database, &account).await;
        let before = reload(&database, &order).await;
        let jobs = acme_proxy_jobs::testutil::idle_job_queue(database.clone());
        let outcome = orders
            .finalize(
                &account,
                order,
                &csr,
                None,
                &RequestContext::default(),
                &jobs,
            )
            .await;
        (database, before, outcome)
    }

    /// Finalize signs nothing: it claims the order and queues its issuance in
    /// one write, answering `processing` — the process answering ACME holds no
    /// backend.
    #[tokio::test]
    async fn finalize_claims_the_order_and_queues_its_issuance() {
        let (database, order, outcome) = finalize_ready().await;
        let answered = outcome.unwrap();
        assert_eq!(answered.status, OrderStatus::Processing);
        let stored = reload(&database, &order).await;
        assert_eq!(stored.status, OrderStatus::Processing);
        assert!(stored.certificate.is_none(), "nothing was signed here");

        let job = acme_proxy_store::job::Job::find_live(
            super::super::issue::SIGNER_ISSUE_KIND,
            &order.id.to_string(),
            &database,
        )
        .await
        .unwrap()
        .expect("the issuance is queued");
        assert_eq!(job.payload["order_id"], order.id.to_string());
        assert_eq!(job.payload["profile"], "default");
        assert!(
            job.payload["csr"]
                .as_str()
                .is_some_and(|csr| !csr.is_empty())
        );
        assert_eq!(job.deadline, Some(order.expires));
    }

    /// Two finalizes racing on one order: the loser's claim fails, it is told
    /// §7.4's `orderNotReady`, and only one issuance is queued.
    #[tokio::test]
    async fn a_second_finalize_loses_the_claim() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, csr) = ready_order(&database, &account).await;
        let jobs = acme_proxy_jobs::testutil::idle_job_queue(database.clone());

        // Both requests read the order `ready`.
        let rival = reload(&database, &order).await;
        orders
            .finalize(
                &account,
                order,
                &csr,
                None,
                &RequestContext::default(),
                &jobs,
            )
            .await
            .unwrap();
        let error = orders
            .finalize(
                &account,
                rival,
                &csr,
                None,
                &RequestContext::default(),
                &jobs,
            )
            .await
            .unwrap_err();
        let problem = Problem::from(error).to_value();
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:orderNotReady");
        assert_eq!(problem["detail"], "Order is already being finalized");
    }

    /// The claim and the job are one write: if the job cannot be queued, the
    /// order is not claimed either, so it is never `processing` with nothing
    /// coming for it.
    #[tokio::test]
    async fn a_failed_enqueue_leaves_the_order_ready() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, csr) = ready_order(&database, &account).await;
        let jobs = acme_proxy_jobs::testutil::idle_job_queue(database.clone());
        sqlx::query("DROP TABLE jobs;")
            .execute(database.raw_pool())
            .await
            .unwrap();

        let before = reload(&database, &order).await;
        let error = orders
            .finalize(
                &account,
                order,
                &csr,
                None,
                &RequestContext::default(),
                &jobs,
            )
            .await
            .unwrap_err();
        assert_eq!(
            Problem::from(error).to_value()["detail"],
            "Order finalize failed"
        );
        assert_eq!(reload(&database, &before).await.status, OrderStatus::Ready);
    }
}
