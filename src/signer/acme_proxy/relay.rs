//! The background half of the backend: driving one upstream order to a
//! certificate, and settling the local order once it resolves.
//!
//! Everything here runs *after* `issue` has already answered the client with
//! `processing` (RFC 8555 §7.4), in a task that owns the local `Order` from
//! then on. That is why these functions take the backend's `Inner` — with its
//! database handle and notifier — rather than reaching through an `AppState`:
//! there is no request in scope any more, and nothing here can report a failure
//! by returning it to anyone.

use std::sync::Arc;
use std::time::Duration;

use base64::prelude::*;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::error::Problem;
use crate::notify::{CertificateIssuedData, NotifyEvent};
use crate::sqlite::order::Order;
use crate::sqlite::upstream_order::UpstreamOrder;

use super::client::Signer;
use super::wire::{UpstreamAuthzView, UpstreamOrderView};
use super::{ChallengeStrategy, Inner, dns01, http01};

/// Spawns the background task that carries one relay to its conclusion, under
/// the configured time budget, and writes the result back onto the order.
///
/// Shared by [`AcmeProxySigner::issue`] (a fresh relay) and
/// [`AcmeProxySigner::resume`] (one interrupted by a restart) — they differ
/// only in where the CSR and the order URL come from, so the task itself is
/// written once.
pub(super) fn spawn_relay(
    inner: Arc<Inner>,
    order_id: String,
    csr_der: Vec<u8>,
    order_url: String,
) {
    tokio::spawn(async move {
        // Acquired *before* the timeout below starts, so a relay queued behind
        // seven others does not spend its own budget waiting for a turn and
        // then report the upstream as having timed out.
        let _permit = match Arc::clone(&inner.relay_permits).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return, // semaphore closed: the server is going away
        };

        let outcome = tokio::time::timeout(
            inner.poll.timeout,
            relay(&inner, &order_id, &csr_der, &order_url),
        )
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "upstream issuance timed out after {}s",
                inner.poll.timeout.as_secs()
            ))
        });
        settle(&inner, &order_id, outcome).await;
    });
}

/// Drives one upstream order to a certificate. Returns the PEM chain, or a
/// human-readable reason it could not be obtained.
async fn relay(
    inner: &Inner,
    order_id: &str,
    csr_der: &[u8],
    order_url: &str,
) -> Result<String, String> {
    match &inner.strategy {
        ChallengeStrategy::Dns01(updater) => {
            let view = poll_until(inner, order_url, &["pending", "ready", "valid"]).await?;
            if view.status == "pending" {
                answer_dns01(inner, updater.as_ref(), &view.authorizations).await?;
            }
        }
        ChallengeStrategy::Http01(tokens) => {
            let view = poll_until(inner, order_url, &["pending", "ready", "valid"]).await?;
            if view.status == "pending" {
                answer_http01(inner, tokens.clone(), &view.authorizations).await?;
            }
        }
        ChallengeStrategy::Bypass => {
            let view = poll_until(inner, order_url, &["pending", "ready", "valid"]).await?;
            if view.status == "pending" {
                answer_bypass(inner, &view.authorizations).await?;
            }
        }
    }

    // Wait for the upstream to decide the order is ready to finalize. With a
    // non-validating upstream this is immediate; the loop exists because even
    // then the transition is not promised to be synchronous.
    let view = poll_until(inner, order_url, &["ready", "valid"]).await?;

    let view = if view.status == "ready" {
        let finalize = view
            .finalize
            .clone()
            .ok_or_else(|| "upstream order is ready but advertises no finalize URL".to_string())?;
        // The client's CSR is relayed byte-for-byte: the upstream must see
        // exactly what the real end client asked for, keys and all.
        let payload = json!({
            "csr": BASE64_URL_SAFE_NO_PAD.encode(csr_der),
        });
        inner
            .client
            .post(
                &inner.account,
                &Signer::Kid(&inner.kid),
                &finalize,
                Some(&payload),
            )
            .await
            .map_err(|error| error.to_string())?;
        poll_until(inner, order_url, &["valid"]).await?
    } else {
        view
    };

    let certificate_url = view
        .certificate
        .ok_or_else(|| "upstream order is valid but carries no certificate URL".to_string())?;

    let response = inner
        .client
        .get(&inner.account, &inner.kid, &certificate_url)
        .await
        .map_err(|error| error.to_string())?;

    let chain = response.text().map_err(|error| error.to_string())?;

    if let Err(error) =
        UpstreamOrder::mark_valid(order_id, Some(&certificate_url), &inner.database).await
    {
        warn!(event = "upstream_order_mark_valid_failed", error = %error);
    }

    Ok(chain)
}

/// Satisfies every pending `dns-01` authorization the upstream posed.
///
/// The key authorization is built from **this proxy's** thumbprint at the
/// upstream, never the end client's: they are different accounts on different
/// servers, and only the upstream's own view of who is asking makes the digest
/// come out right. Getting this wrong is the single most likely way for the
/// dns-01 strategy to fail against a real CA, which is why the thumbprint is
/// taken from `inner.account` and computed by the crate's existing
/// `jwk_thumbprint` rather than rebuilt here.
async fn answer_dns01(
    inner: &Inner,
    updater: &dyn dns01::DnsUpdater,
    authorizations: &[String],
) -> Result<(), String> {
    let thumbprint = crate::extractors::acme::jwk_thumbprint(inner.account.spki_der())
        .map_err(|error| format!("cannot derive the upstream account thumbprint: {error}"))?;

    for authz_url in authorizations {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, authz_url)
            .await
            .map_err(|error| error.to_string())?;
        let authz: UpstreamAuthzView = response.json().map_err(|error| error.to_string())?;

        // Already proved (a re-run after a restart, or a reused authorization).
        if authz.status != "pending" {
            continue;
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|challenge| challenge.typ == crate::challenge::DNS_01)
            .ok_or_else(|| {
                // Deliberately not falling back to http-01/tls-alpn-01: this
                // server has no way to answer those on the client's behalf, and
                // silently trying would fail later and more confusingly.
                format!(
                    "upstream authorization for {} offers no dns-01 challenge",
                    authz.identifier.value
                )
            })?;

        // Name and digest come from the inbound validator's own helpers, so the
        // two directions cannot disagree about the convention.
        let name = crate::challenge::dns_01::record_name(&authz.identifier.value);
        let key_authorization = format!("{}.{thumbprint}", challenge.token);
        let value = crate::challenge::dns_01::expected_value(&key_authorization);

        // RFC 2136 wants an absolute name.
        let fqdn = if name.ends_with('.') {
            name.clone()
        } else {
            format!("{name}.")
        };

        updater
            .upsert_txt(&fqdn, &value)
            .await
            .map_err(|error| format!("publishing {fqdn} failed: {error}"))?;

        let triggered = trigger_and_await(inner, &challenge.url, authz_url).await;

        // Cleanup is best-effort and happens whether or not validation passed:
        // a challenge record has no reason to outlive the attempt.
        if let Err(error) = updater.delete_txt(&fqdn, &value).await {
            warn!(event = "dns01_cleanup_failed", name = %fqdn, error = %error);
        }
        triggered?;
    }
    Ok(())
}

/// Satisfies every pending `http-01` authorization the upstream posed, by
/// publishing the key authorization into the store the root router's
/// `/.well-known/acme-challenge/{token}` route serves from.
///
/// Three differences from [`answer_dns01`] are worth stating, because each is a
/// place the two challenge types are easy to conflate:
///
/// - What is served is the key authorization **verbatim** (RFC 8555 §8.3), not
///   its SHA-256 digest (§8.4). Publishing the digest here would fail against
///   every real CA and read like a network problem.
/// - A wildcard is refused outright: §8.3 fetches from the identifier itself,
///   and nothing answers on the name `*.example.com`.
/// - Retraction is a `Drop` guard rather than an explicit call, because here it
///   *can* be — see [`http01::PublishedToken`] for the cancellation hole that
///   closes and why the dns-01 side cannot do the same.
///
/// The thumbprint is **this proxy's** at the upstream, for the reason
/// [`answer_dns01`] sets out at length: they are different accounts on
/// different servers.
async fn answer_http01(
    inner: &Inner,
    tokens: Arc<dyn http01::TokenStore>,
    authorizations: &[String],
) -> Result<(), String> {
    let thumbprint = crate::extractors::acme::jwk_thumbprint(inner.account.spki_der())
        .map_err(|error| format!("cannot derive the upstream account thumbprint: {error}"))?;

    for authz_url in authorizations {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, authz_url)
            .await
            .map_err(|error| error.to_string())?;
        let authz: UpstreamAuthzView = response.json().map_err(|error| error.to_string())?;

        // Already proved (a re-run after a restart, or a reused authorization).
        if authz.status != "pending" {
            continue;
        }

        // Checked on the value's leading `*.` because `UpstreamIdentifier`
        // carries no `type`, and checked *before* looking for a challenge so
        // the error names the real problem rather than "offers no http-01" —
        // a CA correctly offers dns-01 alone for a wildcard.
        if authz.identifier.value.starts_with("*.") {
            return Err(format!(
                "upstream authorization for {} is a wildcard, which http-01 cannot validate: use \
                 signer.acme_proxy.challenge_strategy = \"dns01\" for wildcard names",
                authz.identifier.value
            ));
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|challenge| challenge.typ == crate::challenge::HTTP_01)
            .ok_or_else(|| {
                // Deliberately not falling back to another type, for the same
                // reason `answer_dns01` does not: silently trying one this
                // server cannot answer fails later and more confusingly.
                format!(
                    "upstream authorization for {} offers no http-01 challenge",
                    authz.identifier.value
                )
            })?;

        // §8.3 serves the key authorization itself — no digest, unlike dns-01.
        let key_authorization = format!("{}.{thumbprint}", challenge.token);

        // Dropped at the end of this iteration, on any early return, and — the
        // case an explicit retract would miss — when `spawn_relay`'s timeout
        // drops this future mid-poll.
        let _published =
            http01::PublishedToken::publish(tokens.clone(), &challenge.token, &key_authorization);

        // Returns only once the upstream's authorization is terminal, so every
        // validation fetch — including a multi-perspective CA's several — has
        // already happened by the time `_published` drops.
        trigger_and_await(inner, &challenge.url, authz_url).await?;
    }
    Ok(())
}

/// Triggers any available challenge when the strategy is Bypass.
async fn answer_bypass(inner: &Inner, authorizations: &[String]) -> Result<(), String> {
    for authz_url in authorizations {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, authz_url)
            .await
            .map_err(|error| error.to_string())?;
        let authz: UpstreamAuthzView = response.json().map_err(|error| error.to_string())?;

        // Already proved
        if authz.status != "pending" {
            continue;
        }

        let challenge = authz.challenges.first().ok_or_else(|| {
            format!(
                "upstream authorization for {} offers no challenges to bypass",
                authz.identifier.value
            )
        })?;

        trigger_and_await(inner, &challenge.url, authz_url).await?;
    }
    Ok(())
}

/// POSTs the challenge to tell the upstream to validate, then waits for its
/// authorization to settle.
async fn trigger_and_await(
    inner: &Inner,
    challenge_url: &str,
    authz_url: &str,
) -> Result<(), String> {
    inner
        .client
        .post(
            &inner.account,
            &Signer::Kid(&inner.kid),
            challenge_url,
            Some(&json!({})),
        )
        .await
        .map_err(|error| format!("triggering the upstream challenge failed: {error}"))?;

    let deadline = tokio::time::Instant::now() + inner.poll.timeout;
    loop {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, authz_url)
            .await
            .map_err(|error| error.to_string())?;
        let authz: UpstreamAuthzView = response.json().map_err(|error| error.to_string())?;

        match authz.status.as_str() {
            "valid" => return Ok(()),
            "invalid" => {
                return Err(format!(
                    "upstream rejected the challenge for {}",
                    authz.identifier.value
                ));
            }
            _ if tokio::time::Instant::now() >= deadline => {
                return Err(format!(
                    "upstream authorization for {} did not settle in time",
                    authz.identifier.value
                ));
            }
            _ => tokio::time::sleep(inner.poll.interval).await,
        }
    }
}

/// Polls the upstream order until it reaches one of `wanted`, or fails.
async fn poll_until(
    inner: &Inner,
    order_url: &str,
    wanted: &[&str],
) -> Result<UpstreamOrderView, String> {
    loop {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, order_url)
            .await
            .map_err(|error| error.to_string())?;
        let view: UpstreamOrderView = response.json().map_err(|error| error.to_string())?;

        if wanted.contains(&view.status.as_str()) {
            return Ok(view);
        }
        if view.status == "invalid" {
            let detail = view
                .error
                .as_ref()
                .and_then(|error| error.get("detail"))
                .and_then(Value::as_str)
                .unwrap_or("no detail given")
                .to_string();
            return Err(format!("upstream order became invalid: {detail}"));
        }

        // `pending` or `processing`: honour the upstream's own pacing hint
        // when it gave one, else fall back to the configured interval.
        let wait = response
            .retry_after
            .map(Duration::from_secs)
            .unwrap_or(inner.poll.interval);
        tokio::time::sleep(wait).await;
    }
}

/// Writes the relay's outcome back onto the local order — the whole reason
/// this backend holds an `Arc<Database>`.
pub(super) async fn settle(inner: &Inner, order_id: &str, outcome: Result<String, String>) {
    let mut order = match Order::find_by_id(order_id, &inner.database).await {
        Ok(Some(order)) => order,
        Ok(None) => {
            warn!(event = "upstream_relay_order_vanished", order_id = %order_id);
            return;
        }
        Err(error) => {
            error!(event = "upstream_relay_order_lookup_failed", order_id = %order_id, error = %error);
            return;
        }
    };

    match outcome {
        Ok(chain) => {
            let leaf = match crate::cert::leaf_der_from_chain(&chain) {
                Ok(leaf) => leaf,
                Err(error) => {
                    fail(
                        inner,
                        &mut order,
                        &format!("upstream chain unparsable: {error}"),
                    )
                    .await;
                    return;
                }
            };
            let (serial, pubkey) = match crate::cert::cert_serial_and_spki(&leaf) {
                Ok(parts) => parts,
                Err(error) => {
                    fail(
                        inner,
                        &mut order,
                        &format!("upstream leaf unparsable: {error}"),
                    )
                    .await;
                    return;
                }
            };
            if let Err(error) = order
                .finalize(chain, serial.clone(), pubkey, &inner.database)
                .await
            {
                error!(event = "upstream_relay_finalize_failed", order_id = %order_id, error = %error);
                return;
            }
            info!(event = "upstream_relay_succeeded", order_id = %order_id, cert_serial = %serial);

            // The audit row for this issuance, written here and nowhere else:
            // `post_finalize` answered `processing` without signing anything,
            // so this is the moment a certificate came into existence. The
            // client context is the one that request stored on the mapping row
            // — the relay has no request of its own, and a row saying "issued,
            // from nowhere, by nobody" is the shape this trail exists to avoid.
            crate::audit::write(
                relay_record(crate::audit::AuditEvent::CertificateIssued, &order, inner)
                    .await
                    .with_serial(serial.clone()),
                &inner.database,
            )
            .await;

            // The synchronous signer backends (`local_ca`, `custom`) notify
            // from `post_finalize`'s own success tail, which has a `Profile`
            // in scope. This backend's completion happens here instead, long
            // after that handler returned — so it looks up the right
            // profile's dispatcher by `Order.profile` rather than being
            // handed one directly. `client_ip` is `None`: no request is in
            // scope on this path at all.
            if let Some(dispatcher) = inner.notifiers.get(&order.profile) {
                dispatcher.dispatch(NotifyEvent::CertificateIssued(CertificateIssuedData {
                    profile: order.profile.clone(),
                    order_id: order_id.to_string(),
                    account_id: order.account_id.clone(),
                    cert_serial: serial.clone(),
                    identifiers: order.identifiers.iter().map(|i| i.value.clone()).collect(),
                    client_ip: None,
                }));
            }
        }
        Err(reason) => fail(inner, &mut order, &reason).await,
    }
}

/// The audit row for a relayed issuance, carrying the finalize request's own
/// context back out of the `upstream_orders` row it was parked in.
///
/// The actor is the **account that asked**, not [`crate::audit::Actor::system`]:
/// somebody placed and finalized this order, and attributing it to the server
/// would lose the one identity the row is for. `system` is what is left when
/// the mapping row is gone or predates the context columns — a relay resumed
/// across a restart from an older database — and it means exactly "this server
/// completed work whose requester it can no longer name".
async fn relay_record(
    event: crate::audit::AuditEvent,
    order: &Order,
    inner: &Inner,
) -> crate::audit::AuditRecord {
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &inner.database)
        .await
        .unwrap_or_else(|error| {
            warn!(event = "upstream_order_client_context_lookup_failed", order_id = %order.id, error = %error);
            None
        });
    let (actor, client) = match &mapping {
        Some(mapping) => (
            crate::audit::Actor::acme(&order.account_id),
            mapping.client(),
        ),
        None => (
            crate::audit::Actor::system(),
            crate::audit::ClientContext::default(),
        ),
    };
    crate::audit::AuditRecord::new(event, &order.profile, actor)
        .with_order(order)
        .with_client(client)
}

/// Records a failed relay on both the local order (client-visible) and the
/// mapping row (operator-visible).
async fn fail(inner: &Inner, order: &mut Order, reason: &str) {
    warn!(event = "upstream_relay_failed", order_id = %order.id, reason = %reason);

    crate::audit::write(
        relay_record(
            crate::audit::AuditEvent::CertificateIssueFailed,
            order,
            inner,
        )
        .await
        .with_reason("serverInternal")
        .with_detail(reason),
        &inner.database,
    )
    .await;

    let problem = Problem::server_internal("Upstream certificate issuance failed");
    if let Err(error) = order
        .mark_invalid(problem.to_value(), &inner.database)
        .await
    {
        error!(event = "upstream_relay_mark_invalid_failed", order_id = %order.id, error = %error);
    }
    if let Err(error) = UpstreamOrder::mark_invalid(&order.id, reason, &inner.database).await {
        warn!(event = "upstream_order_mark_invalid_failed", error = %error);
    }
}
