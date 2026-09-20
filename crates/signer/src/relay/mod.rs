//! A signer backend that relays issuance to a real upstream ACME server.
//!
//! Where [`local_ca`](crate::local_ca) *is* the CA, this backend makes
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
//! handle, so [`RelaySigner::issue`] returns [`IssueOutcome::Processing`] and
//! finishes later. RFC 8555 §7.4 has the `processing` order status for exactly
//! this, and the client polls. Whatever finishes it owns the `Order` from then
//! on: it calls `Order::finalize` on success and `Order::mark_invalid` on
//! failure, which is why this backend needs an `Arc<Database>` where `local_ca`
//! needs none.
//!
//! That "later" is a row in the [`acme_proxy_jobs::jobs`] queue, not a `tokio::spawn`.
//! `issue` enqueues a [`flow::RelayJob`] and the process-wide runner claims it —
//! which is what gives a relay an attempt count, a backoff and a lease it did
//! not have when this backend ran its own task and its own startup sweep. The
//! practical difference is that a transient upstream failure now retries instead
//! of invalidating the order, and a crashed process's work is reclaimed by
//! lease expiry rather than only by a restart.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::*;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    IssueOutcome, RenewalWindow, RequestedValidity, RevocationRoute, SignerBackend, SignerError,
    SignerInfo,
};
use acme_proxy_core::config::RelayConfig;
use acme_proxy_core::identifier::Identifier;
use acme_proxy_jobs::jobs::JobQueue;
use acme_proxy_store::db::Database;
use acme_proxy_store::upstream_order::UpstreamOrder;

pub mod account;
pub mod client;
pub mod dns01;
pub mod eab;
pub mod flow;
pub mod http01;
mod propagation;
#[cfg(any(test, feature = "test-util"))]
pub mod testsrv;
pub mod wire;

use client::{AccountKey, AcmeClient, Signer};

use account::provision;
pub use account::{register_upstream_account, stored_kid};
pub use eab::decode_secret;
use flow::{OrderContext, relay_spec};
pub use flow::{RELAY_JOB_KIND, abandon_relayed_order};
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
/// `SignerBackend::issue` takes `&self`, but the relay job that carries the
/// order the rest of the way runs with no borrow of it — in another process,
/// after a restart, or in the next generation of this one. One `Arc` is what
/// the job's state holds; cloning five fields individually would say the same
/// thing five times.
struct Inner {
    /// Shared with [`Inner::info`], so the read side answers from the directory
    /// this backend already discovered rather than fetching its own.
    client: Arc<AcmeClient>,
    account: AccountKey,
    /// The account URL the upstream assigned, used as the `kid` on every
    /// signed request after registration.
    kid: String,
    database: Arc<Database>,
    strategy: ChallengeStrategy,
    /// How long `dns01` waits between publishing a record and triggering the
    /// challenge; [`propagation::Propagation::None`] under every other strategy.
    /// A field beside the strategy rather than inside `ChallengeStrategy::Dns01`,
    /// so a test swapping the updater keeps whatever wait was configured.
    dns01_propagation: propagation::Propagation,
    poll: PollConfig,
    /// The whole `profile name -> dispatcher` map, not merely the profiles this
    /// backend relays for: a cheap clone either way, and it sidesteps keeping a
    /// second, filtered copy in sync. `settle()` looks up the right one by
    /// `Order.profile` once an issuance resolves — the only place this backend
    /// has no `AppState`/`Profile` to reach a notifier through at all.
    ///
    /// A [`Notifiers`] handle rather than the map itself, because this backend
    /// outlives a configuration generation: it is carried across a reload while
    /// the dispatchers are rebuilt, so a captured map would keep notifying
    /// through backends the operator has since removed.
    notifiers: acme_proxy_jobs::notify::Notifiers,
    /// Where this backend's settle-time audit rows go, counted into the
    /// process's Prometheus registry. Needed for the same reason `notifiers`
    /// is: an issuance is recorded by the relay job, long after the
    /// `signer_issue` job answered `Processing` and moved on, with no
    /// `Auditor` of its in scope. An offline one — no resolver, since the address
    /// was resolved during the finalize request and parked on
    /// `upstream_orders` — over the registry, which is *not* rebuilt per
    /// generation and so can be held directly.
    audit: Arc<acme_proxy_jobs::auditor::Auditor>,
    /// The read side over the same directory and token store — what
    /// [`SignerBackend::info`] hands out.
    info: Arc<RelayInfo>,
    /// Where an issuance is queued once the upstream order is open.
    ///
    /// The backend holds the *enqueue* side only; the runner that drains it is
    /// process-wide and knows nothing about signers. How many relays poll one
    /// upstream at once is therefore `jobs.max_concurrent` rather than a
    /// constant here — this backend used to cap it itself, and the reasoning
    /// moved with the number: uncapped, a restart after an outage that left a
    /// few thousand orders in flight becomes a few thousand concurrent pollers
    /// against one CA, which is how a recoverable backlog turns into a
    /// rate-limit ban.
    jobs: JobQueue,
}

pub struct RelaySigner(Arc<Inner>);

/// One relay backend, as the process-wide [`flow::RelayJob`] holds it.
///
/// Opaque on purpose: the handler lives in [`flow`] and reaches `Inner`
/// directly, so nothing outside this module needs a single accessor. It exists
/// only so [`crate::SignerBackend::relay_state`] has a type to name —
/// the `crl_refresher` shape, with a concrete type instead of a trait object
/// because the one consumer is this backend's own handler rather than a third
/// party that must be kept ignorant of what a [`RelaySigner`] is.
pub struct RelayState(Arc<Inner>);

impl RelaySigner {
    /// Queues the job that carries `order_id` the rest of the way, and answers
    /// `Processing`.
    ///
    /// Idempotent: [`relay_spec`] is keyed on the order, so asking twice while
    /// the first row is live is one job. That is what makes a `signer_issue`
    /// retry safe — the upstream order is opened once, and every attempt after
    /// it only makes sure the relay is queued.
    async fn requeue(&self, order_id: &str) -> Result<IssueOutcome, SignerError> {
        let context = OrderContext::read(order_id, &self.0).await;
        self.0
            .jobs
            .enqueue(relay_spec(order_id, &context))
            .await
            .map_err(|error| SignerError::Internal(format!("queueing the relay: {error}")))?;
        Ok(IssueOutcome::Processing)
    }

    /// Builds the backend, provisioning the upstream account if needed.
    ///
    /// Unlike `local_ca`, whose construction is pure disk I/O, this may make a
    /// network call — but only the *first* time, when no `kid` sidecar exists
    /// yet. Every later startup just reads the two local files, so a temporarily
    /// unreachable upstream does not stop the server from booting.
    pub fn from_config(cfg: &RelayConfig, parts: &crate::SignerParts) -> anyhow::Result<Self> {
        let outbound = parts.egress.outbound();
        if cfg.directory_url.is_empty() {
            anyhow::bail!(
                "signer.relay.directory_url is empty: the relay backend has no upstream \
                 to relay to"
            );
        }

        let poll = PollConfig {
            interval: Duration::from_millis(cfg.poll_interval_ms),
            timeout: Duration::from_secs(cfg.poll_timeout_secs),
        };

        // Before provisioning, which may reach the upstream: a wait that cannot
        // fit the attempt budget is a configuration error, and should say so
        // without a network round trip first.
        let dns01_propagation = if cfg.challenge_strategy == "dns01" {
            propagation::Propagation::from_config(&cfg.dns01.propagation, poll.timeout)?
        } else {
            propagation::Propagation::None
        };

        // Construction is synchronous (see `signer::from_config`) but the
        // provisioning below is inherently async, and the one caller that
        // matters — `server::serve_on` — is *already* inside a runtime.
        // Blocking on a nested runtime from there panics ("Cannot start a
        // runtime from within a runtime"), and `block_in_place` is unavailable
        // on a current-thread runtime, so the only construction that works from
        // both an async and a sync caller is a scoped OS thread with a runtime
        // of its own. `thread::scope` joins before returning, which is what
        // keeps this function synchronous, and borrows `cfg` rather than
        // cloning it. The `strategy` match lives inside the spawned closure
        // too, not just the `provision` call: `Rfc2136Updater::from_config` can
        // do a blocking DNS resolution, and that must stay off the caller's
        // tokio worker thread for exactly the same reason the network
        // provisioning below does.
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
                                "unknown signer.relay.dns01.provider: {other} (supported: rfc2136)"
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
                                event = "signer_relay_http_01_selected",
                                outcome = "advisory",
                                path = acme_proxy_net::challenge::http_01::WELL_KNOWN_PREFIX,
                                "the upstream will fetch \
                                 http://<identifier>:80/.well-known/acme-challenge/<token>; a \
                                 reverse proxy must forward or redirect that path to this server \
                                 (RFC 8555 §8.3 permits a redirect, so it need not share the name)"
                            );
                            // In the database, not in this backend: the relay
                            // job publishing a token and the route serving it
                            // need not be one process, and a backend rebuilt by
                            // a reload serves what the outgoing one published.
                            // An entry outlives the attempt that published it
                            // by a margin at most, that attempt's own budget
                            // being the longest any fetch can matter.
                            ChallengeStrategy::Http01(Arc::new(http01::DbTokenStore::new(
                                parts.database.clone(),
                                http01::token_ttl(poll.timeout),
                            )))
                        }
                        other => anyhow::bail!(
                            "unknown signer.relay.challenge_strategy: {other} \
                             (supported: bypass, dns01, http01)"
                        ),
                    };

                    let (client, account, kid) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(provision(cfg, outbound, poll.timeout))?;
                    Ok((client, account, kid, strategy))
                })
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("upstream provisioning thread panicked")))
        })?;

        let client = Arc::new(client);
        let info = Arc::new(RelayInfo {
            directory_url: cfg.directory_url.clone(),
            outbound: parts.egress.outbound(),
            timeout: poll.timeout,
            client: tokio::sync::OnceCell::new_with(Some(client.clone())),
            http01: match &strategy {
                ChallengeStrategy::Http01(tokens) => Some(tokens.clone()),
                ChallengeStrategy::Bypass | ChallengeStrategy::Dns01(_) => None,
            },
        });
        Ok(Self(Arc::new(Inner {
            client,
            info,
            account,
            kid,
            database: parts.database.clone(),
            strategy,
            dns01_propagation,
            poll,
            notifiers: parts.notifiers.clone(),
            audit: Arc::new(
                acme_proxy_jobs::auditor::Auditor::offline(parts.database.clone())
                    .with_metrics(parts.metrics.clone()),
            ),
            jobs: parts.jobs.clone(),
        })))
    }
}

/// Loads (or creates) the account key, then loads (or registers) the `kid`.
#[async_trait]
impl SignerBackend for RelaySigner {
    /// Opens the upstream order, then queues the rest as a durable job.
    ///
    /// The `newOrder` itself is deliberately **synchronous**: it costs one
    /// round-trip, but it means an upstream refusal (an identifier it will not
    /// issue for, a rate limit, a dead account) reaches the client as an
    /// accurate error on the finalize request itself, instead of the order
    /// quietly going `processing` and then `invalid` moments later.
    #[tracing::instrument(name = "relay_issue", skip_all, fields(order_id = %order_id))]
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

        // An order already relayed: the enqueue below is what may have failed
        // last time, and `signer_issue` is retrying. Opening a second upstream
        // order would leak one per retry and then answer `Processing` with
        // nothing queued — which only `RelayJob::recover`, at the next startup,
        // would ever pick up.
        if let Some(existing) = UpstreamOrder::find_by_order_id(order_id, &inner.database)
            .await
            .map_err(|error| {
                SignerError::Internal(format!("reading the upstream order: {error}"))
            })?
        {
            warn!(event = "upstream_relay_already_in_flight", outcome = "advisory", order_id = %order_id, upstream_url = %existing.upstream_order_url);
            return self.requeue(order_id).await;
        }

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
            // Two finalize requests raced and the other wrote first; its job
            // row is the one that matters, and `enqueue` is keyed on the order,
            // so asking again is the same row.
            warn!(event = "upstream_relay_already_in_flight", outcome = "advisory", order_id = %order_id);
            return self.requeue(order_id).await;
        }

        info!(event = "upstream_order_opened", outcome = "success", order_id = %order_id, upstream_url = %order_url);

        // The order's own `expires` bounds how long this may be retried: past
        // it the order is refused on read, so a certificate obtained upstream
        // could never be collected. Its `profile` comes back from the same read
        // and names the backend that owns the work, this one handling `issue`
        // but the shared handler having several to choose between. One extra
        // primary-key read on a path that has just made an HTTPS round trip, and
        // worth it because both then survive a restart rather than being
        // recomputed from nothing.
        self.requeue(order_id).await
    }

    /// This backend, as the shared [`flow::RelayJob`] sees it.
    ///
    /// State rather than a handler, for the reason `crl_refresher` is: the
    /// registry refuses two handlers for one `kind`, and two relay profiles
    /// pointed at different upstreams are two backends.
    fn relay_state(&self) -> Option<RelayState> {
        Some(RelayState(self.0.clone()))
    }

    #[tracing::instrument(name = "relay_revoke", skip_all)]
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
                debug!(event = "upstream_already_revoked", outcome = "success");
                Ok(())
            }
            Err(error) => Err(upstream_to_signer_error(error)),
        }
    }

    fn info(&self) -> Arc<dyn SignerInfo> {
        self.0.info.clone()
    }
}

/// What a request may ask of a relay without its upstream account: the
/// upstream's renewal opinion and the `http-01` tokens published for it.
///
/// Built from configuration by every role. It holds no account key — its one
/// upstream call, `renewalInfo`, is unauthenticated — and discovers the
/// upstream directory lazily, on the first request that needs it, so a process
/// that never serves ARI never dials the upstream at all. A failed discovery is
/// retried on the next request, and the handler answers the local estimate
/// meanwhile.
pub struct RelayInfo {
    directory_url: String,
    outbound: acme_proxy_net::http_client::Outbound,
    timeout: Duration,
    client: tokio::sync::OnceCell<Arc<AcmeClient>>,
    http01: Option<Arc<dyn http01::TokenStore>>,
}

impl RelayInfo {
    /// The read side of the relay `cfg` describes. Contacts nothing.
    ///
    /// The `http-01` store is built over the same table the relay job
    /// publishes into, which is what lets the route in one process answer a
    /// fetch for a token a worker in another published.
    pub fn from_config(cfg: &RelayConfig, parts: &crate::SignerParts) -> anyhow::Result<Self> {
        if cfg.directory_url.is_empty() {
            anyhow::bail!(
                "signer.relay.directory_url is empty: the relay backend has no upstream \
                 to relay to"
            );
        }
        let timeout = Duration::from_secs(cfg.poll_timeout_secs);
        let http01 = (cfg.challenge_strategy == "http01").then(|| {
            Arc::new(http01::DbTokenStore::new(
                parts.database.clone(),
                http01::token_ttl(timeout),
            )) as Arc<dyn http01::TokenStore>
        });
        Ok(Self {
            directory_url: cfg.directory_url.clone(),
            outbound: parts.egress.outbound(),
            timeout,
            client: tokio::sync::OnceCell::new(),
            http01,
        })
    }

    /// The upstream's directory, discovered on first use.
    async fn client(&self) -> Result<&Arc<AcmeClient>, SignerError> {
        self.client
            .get_or_try_init(|| async {
                AcmeClient::discover(&self.directory_url, self.outbound.clone(), self.timeout)
                    .await
                    .map(Arc::new)
            })
            .await
            .map_err(upstream_to_signer_error)
    }
}

#[async_trait]
impl SignerInfo for RelayInfo {
    /// Asks the upstream when it would like this certificate renewed
    /// (RFC 9773). The upstream is the authority here: it knows its own rate
    /// limits and any planned mass-revocation, which no local computation can.
    ///
    /// `Ok(None)` whenever the upstream has nothing to say — it advertises no
    /// `renewalInfo`, or the certificate has no derivable certID — leaving the
    /// handler on its local estimate rather than failing the client's request.
    #[tracing::instrument(name = "relay_renewal_info", skip_all)]
    async fn renewal_info(&self, cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        let client = self.client().await?;
        let Some(base) = client.directory().renewal_info.clone() else {
            debug!(event = "upstream_has_no_renewal_info", outcome = "success");
            return Ok(None);
        };

        // The certID is derived from the certificate itself, so nothing extra
        // has to be stored per order for this to work.
        let cert_id = match acme_proxy_core::cert::ari_cert_id(cert_der) {
            Ok(cert_id) => cert_id,
            Err(error) => {
                debug!(event = "upstream_renewal_info_cert_id_underivable", outcome = "failure", error = %error);
                return Ok(None);
            }
        };

        let url = format!("{}/{cert_id}", base.trim_end_matches('/'));
        let response = client
            .get_unsigned(&url)
            .await
            .map_err(upstream_to_signer_error)?;
        let info: RenewalInfoView = response.json().map_err(upstream_to_signer_error)?;

        let start = parse_rfc3339(&info.suggested_window.start)?;
        let end = parse_rfc3339(&info.suggested_window.end)?;
        info!(
            event = "upstream_renewal_info_used",
            outcome = "success",
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
    fn http01_tokens(&self) -> Option<Arc<dyn crate::Http01TokenStore>> {
        self.http01.clone()
    }

    /// An upstream CA revokes with this server's upstream account key, which
    /// only the process holding the backend has.
    fn revocation_route(&self) -> RevocationRoute {
        RevocationRoute::Delegated
    }
}

#[cfg(test)]
mod tests;
