//! A signer backend that relays issuance to a real upstream ACME server.
//!
//! Where [`local_ca`](crate::signer::local_ca) *is* the CA, this backend makes
//! the server a **proxy**: clients keep speaking ordinary ACME to it and keep
//! proving domain control to it, but the certificate itself is obtained from an
//! upstream ACME server — another `acme-proxy`, a private enterprise CA, or a
//! public CA — of which this server becomes a client.
//!
//! ## Two independent proof cycles
//!
//! The local validation flow does not change: that is what justifies the proxy
//! existing at all. What changes is only what happens *after* the local order
//! reaches `ready`. The upstream has its own opinion about domain control, and
//! this server — not the original client — must satisfy it, because the
//! upstream account is this server's. See [`ChallengeStrategy`].
//!
//! ## Asynchronous by necessity
//!
//! An upstream validation cycle can take minutes. Holding the client's
//! `finalize` request open for that long would tie up a connection and a SQLite
//! handle, so [`AcmeProxySigner::issue`] returns
//! [`IssueOutcome::Processing`] and finishes in a background task. RFC 8555
//! §7.4 has the `processing` order status for exactly this, and the client
//! polls. The task owns the `Order` from then on: it calls `Order::finalize` on
//! success and `Order::mark_invalid` on failure, which is why this backend
//! needs an `Arc<Database>` where `local_ca` needs none.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::*;
use serde_json::json;
use tracing::{debug, error, info, warn};

use crate::config::AcmeProxyConfig;
use crate::notify::NotifyDispatcher;
use crate::signer::{IssueOutcome, RenewalWindow, RequestedValidity, SignerBackend, SignerError};
use crate::sqlite::db::Database;
use crate::sqlite::order::Identifier;
use crate::sqlite::upstream_order::UpstreamOrder;

pub mod account;
pub mod client;
pub mod dns01;
pub mod eab;
pub mod http01;
pub mod relay;
#[cfg(test)]
pub mod testsrv;
pub mod wire;

use client::{AccountKey, AcmeClient, Signer};

use account::provision;
pub use account::{register_upstream_account, stored_kid};
pub(crate) use eab::decode_secret;
use relay::spawn_relay;
use wire::{RenewalInfoView, UpstreamOrderView, parse_rfc3339, upstream_to_signer_error};

/// How this proxy satisfies the *upstream's* domain-control requirement.
pub enum ChallengeStrategy {
    /// The upstream validates nothing — a private CA that already trusts this
    /// server, or another `acme-proxy` running with `challenge.bypass`. The
    /// relay just follows the upstream order's status as it is.
    Bypass,
    /// The upstream runs a real `dns-01` challenge, which this server answers
    /// by publishing the TXT record itself. See [`dns01`] for why the original
    /// client cannot do it.
    Dns01(Arc<dyn dns01::DnsUpdater>),
    /// The upstream runs a real `http-01` challenge, which this server answers
    /// by serving the key authorization from its own root router. See
    /// [`http01`] for why that is a route rather than a second listener, and
    /// what the operator has to put in front of it.
    Http01(Arc<dyn http01::TokenStore>),
}

/// Timing knobs for the background relay.
struct PollConfig {
    interval: Duration,
    timeout: Duration,
}

/// The shared guts, behind one `Arc`.
///
/// `SignerBackend::issue` takes `&self`, but the background task it spawns must
/// be `'static` and so cannot borrow from it. One `Arc` cloned into the task is
/// the cheapest way to bridge that; cloning five fields individually would say
/// the same thing five times.
struct Inner {
    client: AcmeClient,
    account: AccountKey,
    /// The account URL the upstream assigned, used as the `kid` on every
    /// signed request after registration.
    kid: String,
    database: Arc<Database>,
    strategy: ChallengeStrategy,
    poll: PollConfig,
    /// The profiles this backend answers for — several endpoints may share one
    /// upstream configuration, and [`AcmeProxySigner::resume`] must pick up
    /// their in-flight orders and **only** theirs.
    profiles: Vec<String>,
    /// The whole `profile name -> dispatcher` map, not just the entries in
    /// `profiles` above: a cheap `Arc` clone either way, and it sidesteps
    /// keeping a second, filtered copy in sync. `settle()` looks up the right
    /// one by `Order.profile` once an issuance resolves — the only place this
    /// backend has no `AppState`/`Profile` to reach a notifier through at all.
    notifiers: Arc<HashMap<String, Arc<NotifyDispatcher>>>,
    /// Caps how many relays poll the upstream at once; see
    /// [`MAX_CONCURRENT_RELAYS`].
    relay_permits: Arc<tokio::sync::Semaphore>,
}

/// How many upstream relays may be in flight at once.
///
/// `resume` spawns one task per row left `processing` by a previous run, and
/// each polls the upstream in a loop for up to `poll_timeout_secs`. Uncapped,
/// a restart after an upstream outage that left a few thousand orders in flight
/// becomes a few thousand concurrent pollers against one CA — which is how a
/// recoverable backlog turns into a rate-limit ban and a mass failure. Eight is
/// well under any public CA's concurrency expectations and still drains a
/// backlog steadily.
const MAX_CONCURRENT_RELAYS: usize = 8;

pub struct AcmeProxySigner(Arc<Inner>);

/// The `Location` sidecar next to the account key: `foo.key` → `foo.kid`.
///
/// Same convention as `local_ca`'s ledger sidecar next to its CRL. Holding the
/// `kid` locally is what keeps startup from depending on the upstream after the
/// first successful registration.
impl AcmeProxySigner {
    /// Builds the backend, provisioning the upstream account if needed.
    ///
    /// Unlike `local_ca`, whose construction is pure disk I/O, this may make a
    /// network call — but only the *first* time, when no `kid` sidecar exists
    /// yet. Every later startup just reads the two local files, so a temporarily
    /// unreachable upstream does not stop the server from booting.
    pub fn from_config(
        cfg: &AcmeProxyConfig,
        profiles: Vec<String>,
        database: Arc<Database>,
        notifiers: Arc<HashMap<String, Arc<NotifyDispatcher>>>,
        resolver: Arc<dyn crate::dns::Resolver>,
    ) -> anyhow::Result<Self> {
        if cfg.directory_url.is_empty() {
            anyhow::bail!(
                "signer.acme_proxy.directory_url is empty: the acme_proxy backend has no upstream \
                 to relay to"
            );
        }

        let poll = PollConfig {
            interval: Duration::from_millis(cfg.poll_interval_ms),
            timeout: Duration::from_secs(cfg.poll_timeout_secs),
        };

        // Construction is synchronous (see `signer::from_config`) but the
        // provisioning below is inherently async, and the one caller that
        // matters — `cli::serve_on` — is *already* inside a runtime. Blocking on a
        // nested runtime from there panics ("Cannot start a runtime from within
        // a runtime"), and `block_in_place` is unavailable on a current-thread
        // runtime, so the only construction that works from both an async and a
        // sync caller is a scoped OS thread with a runtime of its own.
        // `thread::scope` joins before returning, which is what keeps this
        // function synchronous, and borrows `cfg` rather than cloning it. The
        // `strategy` match lives inside the spawned closure too, not just the
        // `provision` call: `Rfc2136Updater::from_config` can do a blocking DNS
        // resolution, and that must stay off the caller's tokio worker thread
        // for exactly the same reason the network provisioning below does.
        let (client, account, kid, strategy) = std::thread::scope(|scope| {
            scope
                .spawn(|| -> anyhow::Result<_> {
                    // Validated whether or not it is the selected strategy, for
                    // the reason `challenge::from_config` validates names
                    // before checking `bypass`: a typo must not sit unnoticed
                    // until someone switches strategies.
                    let strategy = match cfg.challenge_strategy.as_str() {
                        "bypass" => ChallengeStrategy::Bypass,
                        "dns01" => match cfg.dns01.provider.as_str() {
                            "rfc2136" => ChallengeStrategy::Dns01(Arc::new(
                                dns01::Rfc2136Updater::from_config(&cfg.dns01.rfc2136)?,
                            )),
                            other => anyhow::bail!(
                                "unknown signer.acme_proxy.dns01.provider: {other} (supported: rfc2136)"
                            ),
                        },
                        "http01" => {
                            // Nothing to validate: unlike `dns01`, this
                            // strategy has no credential and no remote
                            // endpoint — the responder is a route on this
                            // server's own root router. What it *does* need is
                            // out of this process's reach, so say so on every
                            // startup rather than at the first failed issuance.
                            info!(
                                event = "signer_acme_proxy_http01_selected",
                                path = crate::challenge::http_01::WELL_KNOWN_PREFIX,
                                "the upstream will fetch \
                                 http://<identifier>:80/.well-known/acme-challenge/<token>; a \
                                 reverse proxy must forward or redirect that path to this server \
                                 (RFC 8555 §8.3 permits a redirect, so it need not share the name)"
                            );
                            ChallengeStrategy::Http01(Arc::new(http01::MemoryTokenStore::new()))
                        }
                        other => anyhow::bail!(
                            "unknown signer.acme_proxy.challenge_strategy: {other} \
                             (supported: bypass, dns01, http01)"
                        ),
                    };

                    let (client, account, kid) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(provision(cfg, resolver, poll.timeout))?;
                    Ok((client, account, kid, strategy))
                })
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("upstream provisioning thread panicked")))
        })?;

        Ok(Self(Arc::new(Inner {
            client,
            account,
            kid,
            database,
            strategy,
            poll,
            profiles,
            notifiers,
            relay_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RELAYS)),
        })))
    }
}

/// Loads (or creates) the account key, then loads (or registers) the `kid`.
#[async_trait]
impl SignerBackend for AcmeProxySigner {
    /// Opens the upstream order, then hands the rest to a background task.
    ///
    /// The `newOrder` itself is deliberately **synchronous**: it costs one
    /// round-trip, but it means an upstream refusal (an identifier it will not
    /// issue for, a rate limit, a dead account) reaches the client as an
    /// accurate error on the finalize request itself, instead of the order
    /// quietly going `processing` and then `invalid` moments later.
    #[tracing::instrument(name = "acme_proxy_issue", skip_all, fields(order_id = %order_id))]
    async fn issue(
        &self,
        order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        // The upstream CA decides validity, and RFC 8555 §7.4 lets it: relaying
        // the request would be honest only if the upstream honoured it, which
        // this proxy cannot promise on its behalf.
        let _ = validity;
        let inner = self.0.clone();

        let payload = json!({
            "identifiers": identifiers.iter().map(|identifier| json!({
                "type": identifier.typ,
                "value": identifier.value,
            })).collect::<Vec<_>>(),
        });

        let response = inner
            .client
            .post(
                &inner.account,
                &Signer::Kid(&inner.kid),
                &inner.client.directory().new_order.clone(),
                Some(&payload),
            )
            .await
            .map_err(upstream_to_signer_error)?;

        let order_url = response.location.clone().ok_or_else(|| {
            SignerError::Internal("upstream newOrder returned no Location header".to_string())
        })?;
        let view: UpstreamOrderView = response.json().map_err(upstream_to_signer_error)?;

        // The primary key refuses a second relay for this order, which is what
        // stops two racing finalize requests opening two upstream orders.
        let created = UpstreamOrder::create(
            order_id,
            &order_url,
            view.finalize.as_deref(),
            csr_der,
            &inner.database,
        )
        .await
        .map_err(|error| SignerError::Internal(format!("recording upstream order: {error}")))?;

        if created.is_none() {
            warn!(event = "upstream_relay_already_in_flight", order_id = %order_id);
            return Ok(IssueOutcome::Processing);
        }

        info!(event = "upstream_order_opened", order_id = %order_id, upstream_url = %order_url);

        spawn_relay(inner, order_id.to_string(), csr_der.to_vec(), order_url);

        Ok(IssueOutcome::Processing)
    }

    /// Restarts relays this process lost when it last stopped.
    ///
    /// A relay lives in a `tokio` task, so a restart mid-flight leaves the
    /// local order `processing` and the upstream order untouched — the client
    /// would poll forever. Every row still `processing` therefore gets a task
    /// respawned, which POST-as-GETs the stored upstream order URL to find the
    /// real state and carries on from there. RFC 8555 lets an order be re-read
    /// at any time, so nothing has to start over: an upstream that already
    /// issued simply has its certificate collected.
    ///
    /// This is why the CSR is stored — an upstream order still at `ready`
    /// needs that exact CSR to finalize, and it is gone from memory.
    async fn resume(&self) {
        let inner = self.0.clone();
        let pending = match UpstreamOrder::list_processing(&inner.profiles, &inner.database).await {
            Ok(pending) => pending,
            Err(error) => {
                // Best-effort by contract: log and let the server start.
                error!(event = "upstream_resume_lookup_failed", error = %error);
                return;
            }
        };

        if pending.is_empty() {
            return;
        }
        info!(event = "upstream_relays_resuming", count = pending.len());
        if pending.len() >= crate::sqlite::upstream_order::MAX_PROCESSING_BATCH {
            warn!(
                event = "upstream_relays_batch_capped",
                count = pending.len(),
                "more orders are still processing than one resume picks up; the rest \
                 are taken by a later restart or by their own retry",
            );
        }

        for row in pending {
            spawn_relay(
                inner.clone(),
                row.order_id,
                row.csr_der,
                row.upstream_order_url,
            );
        }
    }

    #[tracing::instrument(name = "acme_proxy_revoke", skip_all)]
    async fn revoke(&self, cert_der: &[u8], reason: Option<u32>) -> Result<(), SignerError> {
        let inner = &self.0;
        let revoke_url = inner
            .client
            .directory()
            .revoke_cert
            .clone()
            .ok_or_else(|| {
                SignerError::Internal("upstream directory advertises no revokeCert".to_string())
            })?;

        let mut payload = json!({
            "certificate": BASE64_URL_SAFE_NO_PAD.encode(cert_der),
        });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }

        match inner
            .client
            .post(
                &inner.account,
                &Signer::Kid(&inner.kid),
                &revoke_url,
                Some(&payload),
            )
            .await
        {
            Ok(_) => Ok(()),
            // `SignerBackend::revoke` is contractually idempotent, so the
            // upstream telling us it is already revoked *is* the desired state.
            Err(error) if error.is_already_revoked() => {
                debug!(event = "upstream_already_revoked");
                Ok(())
            }
            Err(error) => Err(upstream_to_signer_error(error)),
        }
    }

    /// Asks the upstream when it would like this certificate renewed
    /// (RFC 9773). The upstream is the authority here: it knows its own rate
    /// limits and any planned mass-revocation, which no local computation can.
    ///
    /// `Ok(None)` whenever the upstream has nothing to say — it advertises no
    /// `renewalInfo`, or the certificate has no derivable certID — leaving the
    /// handler on its local estimate rather than failing the client's request.
    #[tracing::instrument(name = "acme_proxy_renewal_info", skip_all)]
    async fn renewal_info(&self, cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        let inner = &self.0;
        let Some(base) = inner.client.directory().renewal_info.clone() else {
            debug!(event = "upstream_has_no_renewal_info");
            return Ok(None);
        };

        // The certID is derived from the certificate itself, so nothing extra
        // has to be stored per order for this to work.
        let cert_id = match crate::cert::ari_cert_id(cert_der) {
            Ok(cert_id) => cert_id,
            Err(error) => {
                debug!(event = "ari_cert_id_underivable", error = %error);
                return Ok(None);
            }
        };

        let url = format!("{}/{cert_id}", base.trim_end_matches('/'));
        let response = inner
            .client
            .get_unsigned(&url)
            .await
            .map_err(upstream_to_signer_error)?;
        let info: RenewalInfoView = response.json().map_err(upstream_to_signer_error)?;

        let start = parse_rfc3339(&info.suggested_window.start)?;
        let end = parse_rfc3339(&info.suggested_window.end)?;
        info!(
            event = "upstream_renewal_info_used",
            start,
            end,
            explanation_url = ?info.explanation_url,
        );
        Ok(Some(RenewalWindow {
            start,
            end,
            // Passed straight through: it is the upstream CA's own explanation
            // of its window, and RFC 9773 §4.2 wants the client to show it to
            // an operator. Rewriting or dropping it would lose the one piece of
            // context this proxy cannot reconstruct.
            explanation_url: info.explanation_url,
        }))
    }

    /// Hands the responder route the store the `http01` strategy publishes
    /// into. `None` under every other strategy, so an upstream validated by
    /// DNS or not at all never exposes the well-known path.
    fn http01_tokens(&self) -> Option<Arc<dyn crate::signer::Http01TokenStore>> {
        match &self.0.strategy {
            ChallengeStrategy::Http01(tokens) => Some(tokens.clone()),
            ChallengeStrategy::Bypass | ChallengeStrategy::Dns01(_) => None,
        }
    }
}

#[cfg(test)]
mod tests;
