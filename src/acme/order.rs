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
use crate::audit::{Auditor, RequestContext};
use crate::challenge::ValidationContext;
use crate::error::Problem;
use crate::extractors::acme::jwk_thumbprint;
use crate::filter::{IdentifierStage, Stage as FilterStage};
use crate::notify::{ChallengeFailedData, NotifyEvent};
use crate::server::Profile;
use crate::signer::{IssueOutcome, RequestedValidity, SignerError};
use crate::sqlite::{
    account::Account,
    authz::{Authorization, Challenge},
    db::Database,
    nonce::now_secs,
    order::{Identifier, Order},
    status::{AuthzStatus, ChallengeStatus, OrderStatus},
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
    account_id: Uuid,
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

/// Gives back the claim [`Order::claim_for_finalize`] took, on the three
/// `post_finalize` arms that must leave the order finalizable.
///
/// A failure here is logged and swallowed rather than replacing the refusal the
/// caller is already returning: the client is being told its CSR was rejected
/// (or that this server could not read what it signed), and answering something
/// else because the *release* also failed would describe the wrong problem. The
/// order is left `processing` in that case, which the order's own `expires`
/// eventually retires.
async fn release_claim(order: &mut Order, database: &Database, id: &str) {
    if let Err(error) = order.release_finalize_claim(database).await {
        error!(
            event = "order_finalize_claim_release_failed",
            outcome = "failure",
            order_id = %id,
            error = %error
        );
    }
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
    account_id: Uuid,
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
                        client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
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

    /// Finalizes `order` with the base64url CSR a client sent (RFC 8555 §7.4),
    /// returning the order as it now stands: `valid` with its certificate, or
    /// `processing` when the backend resolves issuance elsewhere.
    ///
    /// `account` must already own `order` (`access::load_owned_order`).
    pub async fn finalize(
        &self,
        account: &Account,
        mut order: Order,
        csr: &str,
        client_ip: Option<IpAddr>,
        request: &RequestContext,
    ) -> Result<Order, Error> {
        let (database, profile, audit) = (self.database, self.profile, self.audit);
        let (signer, filter) = (&profile.signer, &profile.filter);

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

        // The order's own `notBefore`/`notAfter` (RFC 8555 §7.4), which the order
        // object has always echoed back — passing them on is what stops the echo
        // being a fiction. The backend clamps or ignores them; see
        // `RequestedValidity`.
        let validity = RequestedValidity {
            not_before: order.not_before,
            not_after: order.not_after,
        };

        // Claimed here rather than at the `ready` check above, and the placement is
        // the design: this narrows the guarded window to the one call that can bring
        // a certificate into existence, so only the arms below owe a release, where
        // claiming at the check would have made every refusal above owe one too.
        //
        // The loser gets §7.4's own answer — `403 orderNotReady`, on which the
        // client POST-as-GETs the order and sees `processing`, then `valid`. No
        // audit row: like the not-ready refusal above, this is protocol bookkeeping
        // with no CA action attempted.
        match order.claim_for_finalize(database).await {
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

        let issued = signer
            .issue(
                &order.id.to_string(),
                &csr_der,
                &order.identifiers,
                validity,
            )
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
            // The claim above already wrote `processing`, which is exactly the
            // status this arm publishes — so there is nothing left to do to the
            // order here.
            Ok(IssueOutcome::Processing) => {
                // No audit row here — nothing has been signed yet. The one row for
                // this issuance is written by `signer::relay::flow::settle`
                // when the upstream actually answers, and this is what lets it
                // carry the address of the client that asked: the relay runs from a
                // background task with no request in scope. See
                // `UpstreamOrder::set_client` for why it is stored rather than
                // passed, and for the ordering.
                if let Err(error) =
                    crate::sqlite::upstream_order::UpstreamOrder::set_client(&id, &client, database)
                        .await
                {
                    warn!(
                        event = "upstream_order_client_context_failed",
                        outcome = "failure",
                        order_id = %id,
                        error = %error
                    );
                }
                info!(event = "order_finalize_delegated", outcome = "success", order_id = %id);
                return Ok(order);
            }
            Err(SignerError::BadCsr) => {
                warn!(
                    event = "order_finalize_bad_csr",
                    outcome = "failure",
                    order_id = %id
                );
                // §7.4: a rejected CSR "SHOULD leave the order in the 'ready'
                // state", so the client can correct it and try again. Without the
                // release the claim would wedge the order in `processing` for ever
                // — a retry would then hit the claim's own refusal.
                release_claim(&mut order, database, &id).await;
                audit
                    .record(failed(
                        &order,
                        "badCSR",
                        "the signer backend rejected the CSR",
                    ))
                    .await;
                return Err(Problem::bad_csr("CSR invalid or does not match order").into());
            }
            Err(SignerError::Internal(detail)) => {
                error!(
                    event = "order_finalize_issuance_failed",
                    outcome = "failure",
                    order_id = %id,
                    detail = %detail
                );
                let problem = Problem::server_internal("Certificate issuance failed");
                if let Err(error) = record_issue_failure(
                    &mut order,
                    &problem,
                    &detail,
                    crate::audit::Actor::acme(account.id),
                    client,
                    audit,
                    database,
                )
                .await
                {
                    error!(
                        event = "order_mark_invalid_failed",
                        outcome = "failure",
                        order_id = %id,
                        error = %error
                    );
                }
                return Err(problem.into());
            }
        };

        // The two parse failures are `match` arms rather than `map_err(…)?`
        // because the release has to be awaited and a closure cannot. Both leave
        // the order `ready`, which is what `tests/orders.rs` already pins: the CSR
        // was fine and the client can retry, the fault being this server's
        // inability to read what it just signed.
        let cert_serial = match record_issuance(&mut order, chain, database).await {
            Ok(serial) => serial,
            Err(IssuanceError::Chain(error)) => {
                error!(event = "order_finalize_chain_unparsable", outcome = "failure", order_id = %id, error = %error);
                release_claim(&mut order, database, &id).await;
                return Err(
                    Problem::server_internal("Issued certificate chain is unparsable").into(),
                );
            }
            Err(IssuanceError::Leaf(error)) => {
                error!(event = "order_finalize_leaf_unparsable", outcome = "failure", order_id = %id, error = %error);
                release_claim(&mut order, database, &id).await;
                return Err(Problem::server_internal("Issued certificate is unparsable").into());
            }
            Err(IssuanceError::Persist(error)) => {
                error!(
                    event = "order_finalize_persistence_failed",
                    outcome = "failure",
                    order_id = %id,
                    error = %error
                );
                return Err(Problem::server_internal("Order finalize failed").into());
            }
        };

        info!(
            event = "order_finalized",
            outcome = "success",
            order_id = %id,
            cert_serial = %cert_serial
        );
        announce_issuance(
            &order,
            &cert_serial,
            crate::audit::Actor::acme(account.id.to_string()),
            client,
            client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
            audit,
            Some(&profile.notify),
        )
        .await;
        Ok(order)
    }
}

/// Why an issued chain could not be recorded on its order.
///
/// Three cases a caller answers differently: a chain or leaf this server cannot
/// read is a certificate it cannot revoke, where a failed write is a retry.
#[derive(Debug)]
pub enum IssuanceError {
    /// No certificate could be read out of the chain.
    Chain(String),
    /// The leaf did not yield a serial and a public key.
    Leaf(String),
    /// The order row could not be written.
    Persist(sqlx::Error),
}

/// Stores an issued `chain` on `order`, returning the leaf's serial.
///
/// Shared by `finalize` and by the relay, which receives its chain from the
/// upstream long after the request that asked has returned. Logs nothing: the
/// two callers name the same failure differently, and those names are what an
/// operator greps for.
pub async fn record_issuance(
    order: &mut Order,
    chain: String,
    database: &Database,
) -> Result<String, IssuanceError> {
    let leaf_der = crate::cert::leaf_der_from_chain(&chain)
        .map_err(|error| IssuanceError::Chain(error.to_string()))?;
    let (cert_serial, cert_pubkey) = crate::cert::cert_serial_and_spki(&leaf_der)
        .map_err(|error| IssuanceError::Leaf(error.to_string()))?;

    // Best-effort, unlike the two above: the serial and the public key are
    // what make this certificate revocable, so a chain they cannot be read
    // from is a failed issuance, while the expiry is housekeeping for the
    // expiry digest. A leaf whose validity will not parse is still an issued
    // certificate, and the digest's own sweep will try again later.
    let cert_not_after = crate::cert::cert_validity(&leaf_der)
        .ok()
        .map(|(_, not_after)| not_after);

    order
        .finalize(
            chain,
            cert_serial.clone(),
            cert_pubkey,
            cert_not_after,
            database,
        )
        .await
        .map_err(IssuanceError::Persist)?;
    Ok(cert_serial)
}

/// Writes the `certificate_issued` audit row for an order
/// [`record_issuance`] stored, then queues `certificate_issued`.
///
/// `actor`/`client` name who asked: the account and its request on the
/// synchronous path, whatever the relay parked on `upstream_orders` on the
/// deferred one. `client_ip` is the notification's own rendering of that
/// address, `None` where no request is in scope. `notify` is `None` when the
/// order's profile has no dispatcher in this process.
pub async fn announce_issuance(
    order: &Order,
    serial: &str,
    actor: crate::audit::Actor,
    client: crate::audit::ClientContext,
    client_ip: Option<String>,
    audit: &Auditor,
    notify: Option<&crate::notify::NotifyDispatcher>,
) {
    audit
        .record(
            crate::audit::AuditRecord::new(
                crate::audit::AuditEvent::CertificateIssued,
                &order.profile,
                actor,
            )
            .with_order(order)
            .with_client(client)
            .with_serial(serial),
        )
        .await;
    if let Some(dispatcher) = notify {
        dispatcher
            .dispatch(NotifyEvent::CertificateIssued(
                crate::notify::CertificateIssuedData {
                    profile: order.profile.clone(),
                    order_id: order.id.to_string(),
                    account_id: order.account_id.to_string(),
                    cert_serial: serial.to_string(),
                    identifiers: order.identifiers.iter().map(|i| i.value.clone()).collect(),
                    client_ip,
                },
            ))
            .await;
    }
}

/// Retires an order whose issuance failed for good: one
/// `certificate_issue_failed` row naming `detail`, then the order `invalid`
/// with `problem` as the document its client reads.
///
/// The client's document and the trail's detail are separate on purpose: what
/// went wrong upstream or in a signer is for the operator, and the client is
/// told only that issuance failed.
pub async fn record_issue_failure(
    order: &mut Order,
    problem: &Problem,
    detail: &str,
    actor: crate::audit::Actor,
    client: crate::audit::ClientContext,
    audit: &Auditor,
    database: &Database,
) -> Result<(), sqlx::Error> {
    audit
        .record(
            crate::audit::AuditRecord::new(
                crate::audit::AuditEvent::CertificateIssueFailed,
                &order.profile,
                actor,
            )
            .with_order(order)
            .with_client(client)
            .with_reason("serverInternal")
            .with_detail(detail),
        )
        .await;
    order.mark_invalid(problem.to_value(), database).await
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
/// rather than growing a second copy of each — the rule `src/testutil.rs`
/// exists for, applied to two fixtures too entangled with this module's
/// `OrderService` to live there.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::challenge::{ChallengeError, ChallengeRegistry, ChallengeValidator};
    use crate::notify::NotifyDispatcher;
    use crate::server::ProfileParts;
    use crate::sqlite::order::Identifier;
    use std::time::Duration;

    /// A `default` profile over `database`: an in-memory CA, no filter, no
    /// notifier, and `challenges` as the validators.
    pub(crate) fn profile(database: &Arc<Database>, challenges: ChallengeRegistry) -> Profile {
        let ca = crate::signer::local_ca::LocalCa::generate_in_memory(
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
        signer: Arc<dyn crate::signer::SignerBackend>,
    ) -> Profile {
        Profile::new(
            "default",
            "http://localhost:3000",
            ProfileParts {
                signer,
                filter: Arc::new(crate::filter::FilterPolicy::default()),
                challenges: Arc::new(challenges),
                order: crate::config::OrderConfig::default(),
                eab: crate::config::EabConfig::default(),
                meta: crate::config::MetaConfig::default(),
                notify: Arc::new(NotifyDispatcher::disabled(crate::testutil::idle_job_queue(
                    database.clone(),
                ))),
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
            &crate::audit::ClientContext::default(),
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
            crate::testutil::dns_identifiers(names),
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

    /// A signer answering `issue` with whatever the test set.
    enum Answer {
        BadCsr,
        Internal,
        Chain(&'static str),
    }

    struct Scripted(Answer);

    #[async_trait::async_trait]
    impl crate::signer::SignerBackend for Scripted {
        async fn issue(
            &self,
            _order_id: &str,
            _csr_der: &[u8],
            _identifiers: &[Identifier],
            _validity: RequestedValidity,
        ) -> Result<IssueOutcome, SignerError> {
            match &self.0 {
                Answer::BadCsr => Err(SignerError::BadCsr),
                Answer::Internal => Err(SignerError::Internal("the token is gone".into())),
                Answer::Chain(chain) => Ok(IssueOutcome::Issued((*chain).to_string())),
            }
        }

        async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
            Ok(())
        }
    }

    /// A `ready` order for `a.example.com` plus a CSR matching it, base64url.
    async fn ready_order(database: &Arc<Database>, account: &Account) -> (Order, String) {
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

    async fn issue_failures(database: &Database) -> Vec<crate::sqlite::audit::AuditEntry> {
        let query = crate::sqlite::audit::AuditQuery {
            limit: 50,
            ..crate::sqlite::audit::AuditQuery::default()
        };
        crate::sqlite::audit::AuditEntry::search(&query, database)
            .await
            .unwrap()
            .0
            .into_iter()
            .filter(|row| row.event == "certificate_issue_failed")
            .collect()
    }

    async fn finalize_with(answer: Answer) -> (Arc<Database>, Order, Result<Order, Error>) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile_with(
            &database,
            ChallengeRegistry::default(),
            Arc::new(Scripted(answer)),
        );
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, csr) = ready_order(&database, &account).await;
        let stored = reload(&database, &order).await;
        let outcome = orders
            .finalize(&account, order, &csr, None, &RequestContext::default())
            .await;
        (database, stored, outcome)
    }

    /// §7.4: a rejected CSR leaves the order `ready`, so the claim taken before
    /// the signer ran must be given back.
    #[tokio::test]
    async fn a_csr_the_backend_rejects_releases_the_claim() {
        let (database, order, outcome) = finalize_with(Answer::BadCsr).await;
        let problem = Problem::from(outcome.unwrap_err()).to_value();
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:badCSR");
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Ready);
        let rows = issue_failures(&database).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("badCSR"));
    }

    #[tokio::test]
    async fn a_backend_failure_invalidates_the_order_and_records_why() {
        let (database, order, outcome) = finalize_with(Answer::Internal).await;
        let problem = Problem::from(outcome.unwrap_err()).to_value();
        assert_eq!(problem["detail"], "Certificate issuance failed");
        let reloaded = reload(&database, &order).await;
        assert_eq!(reloaded.status, OrderStatus::Invalid);
        assert_eq!(
            reloaded.error.unwrap()["detail"],
            "Certificate issuance failed"
        );
        let rows = issue_failures(&database).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("serverInternal"));
        assert_eq!(rows[0].detail.as_deref(), Some("the token is gone"));
    }

    /// A chain this server cannot read is a certificate it could never
    /// revoke: the order stays `ready` for a retry rather than `valid`.
    #[tokio::test]
    async fn an_unreadable_chain_releases_the_claim() {
        let (database, order, outcome) = finalize_with(Answer::Chain("not a chain")).await;
        let problem = Problem::from(outcome.unwrap_err()).to_value();
        assert_eq!(problem["detail"], "Issued certificate chain is unparsable");
        let reloaded = reload(&database, &order).await;
        assert_eq!(reloaded.status, OrderStatus::Ready);
        assert!(reloaded.certificate.is_none());
    }

    #[tokio::test]
    async fn a_finalized_order_carries_its_certificate_and_one_issued_row() {
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

        let issued = orders
            .finalize(&account, order, &csr, None, &RequestContext::default())
            .await
            .unwrap();
        assert_eq!(issued.status, OrderStatus::Valid);
        let stored = reload(&database, &issued).await;
        assert!(stored.certificate.is_some());
        assert!(stored.cert_serial.is_some());

        let query = crate::sqlite::audit::AuditQuery {
            limit: 50,
            ..crate::sqlite::audit::AuditQuery::default()
        };
        let (rows, _) = crate::sqlite::audit::AuditEntry::search(&query, &database)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "certificate_issued");
        assert_eq!(rows[0].cert_serial, stored.cert_serial);
    }
}
