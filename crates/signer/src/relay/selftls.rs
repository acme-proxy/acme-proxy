//! Obtaining a certificate for **this server's own** listener.
//!
//! `[server.tls]` otherwise serves a self-signed certificate, which every client
//! has to be told to trust — the exact chore the server exists to automate. With
//! `server.tls.acme_enabled` the server orders a real certificate for the host of
//! `server.base_url` from the upstream CA one of its profiles already relays to,
//! and proves control of that name the way the profile already proves control for
//! its clients: through `[signer.relay.dns01]`.
//!
//! ## Why this does not go through the ACME surface of the same process
//!
//! It could: an internal caller could open a local order and let a client-answer
//! path validate it. That is worse in three ways. The name would have to survive
//! the `[filter]` policy, which is written to constrain *clients*, not this
//! server. The local challenge would have to be one the server itself can answer,
//! coupling the listener certificate to `[challenge] enabled` — and a deployment
//! whose clients prove control with `http-01` would then have no way to obtain
//! its own certificate at all. And the JWS, nonce and account machinery would run
//! against a loopback copy of itself for no benefit.
//!
//! What it does instead is what a relay already does for a client, with this
//! process as the requester: one `newOrder`, one dns-01 authorization answered by
//! the profile's own updater, then the same
//! [`finalize_and_fetch`](super::flow::finalize_and_fetch) tail every relayed
//! issuance ends with. `http-01` is deliberately not an option here: this listener
//! is what the certificate is *for*, so answering an HTTP-01 challenge on it would
//! need the certificate before it had one.
//!
//! ## Why nothing here is recorded
//!
//! `upstream_orders` is keyed by the local order a client is waiting on, and this
//! order has none. There is nothing to settle, nobody to notify, and no client
//! holding a URL — the *result* is a file on disk, and the caller in
//! `server::selftls` decides what to do with it. Re-running the whole thing is
//! safe for the same reason [`super::flow`] says it is: every step re-reads the
//! upstream's own view.

use serde_json::json;
use tracing::info;

use super::client::Signer;
use super::flow::{RelayFailure, answer_dns01, classify, finalize_and_fetch, poll_until};
use super::{ChallengeStrategy, Inner};

/// Opens one upstream order for `domain`, answers its `dns-01` authorization with
/// this backend's own updater, and returns the PEM chain the upstream issued for
/// `csr_der`.
///
/// The failure keeps the relay job's own distinction — see [`RelayFailure`] —
/// because the caller has to make the same choice the job does: a CA that stated a
/// reason is not going to change its mind in thirty seconds, and a CA that was
/// unreachable is.
pub(super) async fn issue(
    inner: &Inner,
    domain: &str,
    csr_der: &[u8],
) -> Result<String, RelayFailure> {
    // Read before the order is opened rather than discovered inside it: a strategy
    // that cannot publish a TXT record would leave an order `invalid` at the
    // upstream, and a certificate from a public CA's weekly allowance spent to
    // find that out. The configuration that allows this in the first place is
    // checked at startup by `server::selftls::target`; this is the same rule
    // standing where a caller that skipped that check cannot talk itself round it.
    let ChallengeStrategy::Dns01(updater) = &inner.strategy else {
        return Err(RelayFailure::Permanent(
            "this server can only obtain its own certificate while \
             signer.relay.challenge_strategy = \"dns01\", because there is no way \
             to prove control of the listener's own name by any other means"
                .to_string(),
        ));
    };

    let payload = json!({
        "identifiers": [{ "type": "dns", "value": domain }],
    });
    let new_order = inner.client.directory().new_order.clone();
    let response = inner
        .client
        .post(
            &inner.account,
            &Signer::Kid(&inner.kid),
            &new_order,
            Some(&payload),
        )
        .await
        .map_err(|error| classify(&error))?;
    let order_url = response.location.clone().ok_or_else(|| {
        RelayFailure::Permanent("upstream newOrder returned no Location header".to_string())
    })?;

    // The body is deliberately not parsed: `finalize_and_fetch` reads the order
    // again, which is what a retry after a restart needs anyway.
    let view = poll_until(inner, &order_url, &["pending", "ready", "valid"]).await?;
    if view.status == "pending" {
        answer_dns01(inner, updater.as_ref(), &view.authorizations).await?;
    }

    let (chain, _) = finalize_and_fetch(inner, &order_url, csr_der).await?;
    info!(
        event = "signer_self_tls_issued",
        outcome = "success",
        domain = %domain,
        upstream = %new_order
    );
    Ok(chain)
}
