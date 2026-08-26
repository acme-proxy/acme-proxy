//! The background half of the backend: driving one upstream order to a
//! certificate, and settling the local order once it resolves.
//!
//! Everything here runs *after* `issue` has already answered the client with
//! `processing` (RFC 8555 §7.4), in a job that owns the local `Order` from then
//! on. That is why these functions take the backend's `Inner` — with its
//! database handle and notifier — rather than reaching through an `AppState`:
//! there is no request in scope any more, and nothing here can report a failure
//! by returning it to anyone.
//!
//! ## Why this is safe to run again
//!
//! [`RelayJob`] is a [`crate::jobs::JobHandler`], so the runner may call it
//! repeatedly for one order: after a transient failure, and after a process
//! died mid-flight. Nothing here checkpoints its own progress, and it does not
//! need to — every step re-reads the upstream's own view and skips what is
//! already done ([`poll_until`] accepts a `pending`/`ready`/`valid` order and the
//! authorization loops `continue` past anything not `pending`). RFC 8555 lets an
//! order be re-read at any time, which is what makes "start from the top" and
//! "carry on" the same code.
//!
//! ## Retryable versus permanent
//!
//! [`RelayFailure`] is the distinction the old code could not make: it returned
//! `Result<String, String>`, so a TCP reset mid-poll invalidated the order as
//! surely as a CA refusing the name. The rule is *whose* answer it is — a
//! network, a proxy or an overloaded CA has not decided anything, so ask again;
//! a CA that stated a reason has, so believe it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::*;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::error::Problem;
use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::notify::{CertificateIssuedData, NotifyEvent};
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;
use crate::sqlite::order::Order;
use crate::sqlite::upstream_order::UpstreamOrder;

use super::client::{Signer, UpstreamError};
use super::wire::{UpstreamAuthzView, UpstreamChallengeView, UpstreamOrderView};
use super::{ChallengeStrategy, Inner, RelayState, dns01, http01};

/// The `jobs.kind` one relayed issuance is queued under.
pub const RELAY_JOB_KIND: &str = "signer_relay_issue";

/// Why one attempt at a relay did not produce a certificate.
///
/// The two variants map onto [`JobOutcome::Retry`] and [`JobOutcome::Failed`],
/// and choosing between them is the whole of this type's job. Getting it wrong
/// in one direction wastes the retry budget and delays the client's real answer;
/// in the other it throws away the retry, which is what the queue exists for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.reason())]
pub(super) enum RelayFailure {
    /// Nobody decided anything: the network, a proxy, a 5xx, a rate limit, a
    /// timeout. Ask again after the backoff.
    Retryable(String),
    /// The upstream stated a reason, or the answer can never parse. Asking again
    /// says the same thing.
    Permanent(String),
}

impl RelayFailure {
    fn reason(&self) -> &str {
        match self {
            RelayFailure::Retryable(reason) | RelayFailure::Permanent(reason) => reason,
        }
    }
}

/// Classifies an upstream failure.
///
/// Two of these are worth stating, because both are easy to get backwards:
///
/// - **`Protocol` is retryable.** It means "that was not the JSON I expected",
///   and the commonest way to see it is a CDN or load balancer returning an HTML
///   502 in front of a CA that is briefly down — transient, however
///   permanent-looking the parse failure is.
/// - **`Jws` is permanent.** The local account key produced a signature the
///   upstream rejected; nothing about waiting fixes a wrong key.
pub(super) fn classify(error: &UpstreamError) -> RelayFailure {
    let reason = error.to_string();
    match error {
        // The network, or something standing in it.
        UpstreamError::Transport(_) | UpstreamError::Url(_) => RelayFailure::Retryable(reason),
        // Not the JSON expected: most often an error page from something in
        // front of the CA.
        UpstreamError::Protocol(_) => RelayFailure::Retryable(reason),
        // The CA is busy or broken rather than refusing: 5xx, and 429, which is
        // a rate limit explicitly asking to be asked again later.
        UpstreamError::Problem { status, .. } if *status >= 500 || *status == 429 => {
            RelayFailure::Retryable(reason)
        }
        // The CA stated a reason. Believe it.
        UpstreamError::Problem { .. } => RelayFailure::Permanent(reason),
        // A local key problem; time does not fix it.
        UpstreamError::Jws(_) => RelayFailure::Permanent(reason),
    }
}

/// Every relayed issuance in the process, as one durable job handler.
///
/// **One handler over every relay profile, not one per backend**, and the
/// distinction is the whole reason this type has a map in it.
/// [`crate::jobs::JobRegistry::register`] refuses a second handler for one
/// `kind`, while [`crate::signer::build_backends`] deliberately does *not*
/// collapse two profiles whose `[signer.relay]` sections differ — a Let's
/// Encrypt endpoint beside a commercial CA is two backends. Returning a handler
/// from each would therefore make that supported configuration a startup error,
/// which is exactly what `SignerBackend::relay_state` handing over *state*
/// avoids, the way `crl_pruner` already does for two local CAs.
///
/// Which backend answers for a row is decided per row, from the profile the
/// payload names — the `notify_deliver` idiom. Everything else is still re-read
/// from the database each attempt, because a value captured on the first
/// attempt would be stale on the fourth.
pub struct RelayJob {
    /// Profile name to the backend relaying for it. Built from the *current*
    /// generation's profile list rather than from anything a backend
    /// remembers: a backend whose configuration did not move is reused verbatim
    /// across a reload, so a profile newly mounted onto it would be missing
    /// from any list the backend itself kept.
    targets: BTreeMap<String, Arc<Inner>>,
    /// The distinct backends, each with the profiles it serves — what
    /// [`RelayJob::recover`] fans out over. Grouped once here rather than per
    /// sweep, since `recover` runs once per process and the grouping is by
    /// `Arc` identity.
    upstreams: Vec<(Arc<Inner>, Vec<String>)>,
    /// The longest per-attempt budget among `targets`, used only for a row that
    /// names no profile (see [`RelayJob::target_for`]). Longer than one backend
    /// asked for is the safe direction: an attempt that would have been cut
    /// short runs to its own conclusion instead. `None` only with no targets at
    /// all, which falls back to `jobs.lease_seconds` like any other handler.
    longest_lease: Option<Duration>,
    /// The pool, which every backend shares, taken as an argument rather than
    /// from a target so the legacy-row fallback can read an order before it has
    /// an `Inner` — and so no target is a degenerate case rather than a panic.
    database: Arc<Database>,
}

impl RelayJob {
    /// One handler over every relay profile mounted in this generation.
    ///
    /// Registered by `cli::build_generation` only when `targets` is non-empty,
    /// the way `CrlSweepJob` is registered only when some backend keeps a
    /// ledger: a deployment with no relay profile has nothing to claim. An
    /// empty set is nonetheless a working handler that claims nothing, rather
    /// than a panic — that caller's guard is about not registering a kind
    /// nothing will ever queue, not about safety here.
    #[must_use]
    pub fn new(database: Arc<Database>, targets: Vec<(String, RelayState)>) -> Self {
        let mut upstreams: Vec<(Arc<Inner>, Vec<String>)> = Vec::new();
        for (profile, state) in &targets {
            match upstreams
                .iter_mut()
                .find(|(inner, _)| Arc::ptr_eq(inner, &state.0))
            {
                Some((_, served)) => served.push(profile.clone()),
                None => upstreams.push((state.0.clone(), vec![profile.clone()])),
            }
        }

        let longest_lease = targets.iter().map(|(_, state)| state.0.poll.timeout).max();

        Self {
            targets: targets
                .into_iter()
                .map(|(profile, state)| (profile, state.0))
                .collect(),
            upstreams,
            longest_lease,
            database,
        }
    }

    /// The backend this row belongs to, from the profile its payload names.
    ///
    /// `None` covers two different situations the callers tell apart: a payload
    /// with no `profile` at all — a row queued by a build before this field
    /// existed, still in flight across the upgrade — and a profile that is no
    /// longer mounted. [`RelayJob::resolve`] resolves the first from the order
    /// row and refuses the second; this synchronous form exists for
    /// [`JobHandler::lease`], which has no database and no `await`.
    fn target_for(&self, job: &Job) -> Option<&Arc<Inner>> {
        let profile = job.payload.get("profile").and_then(Value::as_str)?;
        self.targets.get(profile)
    }

    /// The backend this row belongs to, reading the order when the payload does
    /// not say.
    async fn resolve(&self, job: &Job, order_id: &str) -> Resolved<'_> {
        if let Some(profile) = job.payload.get("profile").and_then(Value::as_str) {
            return match self.targets.get(profile) {
                Some(inner) => Resolved::Backend(inner),
                None => Resolved::Unmounted(profile.to_string()),
            };
        }

        // No profile on the payload: a row queued before it was written. The
        // order itself still says which endpoint it was placed against, and
        // that is what the payload would have carried.
        match Order::find_by_id(order_id, &self.database).await {
            Ok(Some(order)) => match self.targets.get(&order.profile) {
                Some(inner) => Resolved::Backend(inner),
                None => Resolved::Unmounted(order.profile),
            },
            Ok(None) => Resolved::Gone,
            Err(error) => Resolved::Unreadable(error.to_string()),
        }
    }
}

/// What [`RelayJob::resolve`] found. Four answers rather than an `Option`
/// because each settles the job differently.
enum Resolved<'a> {
    /// The backend that relays for this row.
    Backend(&'a Arc<Inner>),
    /// The profile is named but not mounted here.
    Unmounted(String),
    /// The local order the row names has been deleted.
    Gone,
    /// The order could not be read at all.
    Unreadable(String),
}

#[async_trait]
impl JobHandler for RelayJob {
    fn kind(&self) -> &'static str {
        RELAY_JOB_KIND
    }

    /// The per-attempt budget is the **owning profile's**
    /// `signer.relay.poll_timeout_secs`, which is what the hand-rolled
    /// `tokio::time::timeout` around this used to be — so an attempt is bounded
    /// exactly as before, and the queue adds retries on top rather than changing
    /// how long one try may take.
    ///
    /// Per profile rather than one number for the handler because
    /// [`poll_until`] has no deadline of its own: this is the only thing
    /// bounding it, so a shared maximum would let an endpoint configured for a
    /// minute poll for five. A row naming no profile falls back to the longest
    /// configured budget, this being synchronous and having no order to read.
    fn lease(&self, job: &Job) -> Option<Duration> {
        self.target_for(job)
            .map(|inner| inner.poll.timeout)
            .or(self.longest_lease)
    }

    async fn run(&self, job: &Job) -> JobOutcome {
        let Some(order_id) = job.payload.get("order_id").and_then(Value::as_str) else {
            return JobOutcome::Failed("the job payload names no order".to_string());
        };

        let inner = match self.resolve(job, order_id).await {
            Resolved::Backend(inner) => inner,
            // **`Retry`, not `Failed`.** A profile can be absent for the length
            // of one reload, and `Failed` calls `abandon`, which tells the
            // client its order is `invalid` — a terminal answer to a
            // configuration window. The attempt budget and the job's own
            // deadline still retire it if the profile really is gone.
            Resolved::Unmounted(profile) => {
                return JobOutcome::Retry(format!(
                    "no relay backend is mounted for profile `{profile}`"
                ));
            }
            Resolved::Gone => {
                return JobOutcome::Failed(format!("local order {order_id} no longer exists"));
            }
            Resolved::Unreadable(error) => {
                return JobOutcome::Retry(format!("reading the local order failed: {error}"));
            }
        };

        // Re-read every attempt: `mark_valid` may have run since the last one,
        // and a value captured at enqueue would be stale.
        let mapping = match UpstreamOrder::find_by_order_id(order_id, &inner.database).await {
            Ok(Some(mapping)) => mapping,
            Ok(None) => {
                return JobOutcome::Failed(format!(
                    "no upstream order is recorded for local order {order_id}"
                ));
            }
            Err(error) => {
                return JobOutcome::Retry(format!("reading the upstream order failed: {error}"));
            }
        };

        match relay(
            inner,
            order_id,
            &mapping.csr_der,
            &mapping.upstream_order_url,
        )
        .await
        {
            Ok(chain) => settle(inner, order_id, chain).await,
            Err(RelayFailure::Retryable(reason)) => JobOutcome::Retry(reason),
            Err(RelayFailure::Permanent(reason)) => JobOutcome::Failed(reason),
        }
    }

    /// Records a relay that will not be tried again, on both the local order
    /// (client-visible) and the mapping row (operator-visible).
    ///
    /// Called once, by the runner, when the job is retired for good — never
    /// between retries. That is the whole client-facing gain of the queue: an
    /// order stays `processing` through a transient upstream failure instead of
    /// going terminally `invalid` on the first blip.
    async fn abandon(&self, job: &Job, reason: &str) {
        let Some(order_id) = job.payload.get("order_id").and_then(Value::as_str) else {
            return;
        };

        // Resolved again rather than carried from `run`: `abandon` is also
        // called for a job that exhausted its attempts or passed its deadline
        // without this process ever running one.
        let Resolved::Backend(inner) = self.resolve(job, order_id).await else {
            warn!(event = "upstream_relay_backend_unresolved", outcome = "failure", order_id = %order_id, reason = %reason);
            return;
        };

        warn!(event = "upstream_relay_failed", outcome = "failure", order_id = %order_id, reason = %reason);

        let mut order = match Order::find_by_id(order_id, &inner.database).await {
            Ok(Some(order)) => order,
            Ok(None) => {
                warn!(event = "upstream_relay_order_vanished", outcome = "failure", order_id = %order_id);
                return;
            }
            Err(error) => {
                error!(event = "upstream_relay_order_lookup_failed", outcome = "failure", order_id = %order_id, error = %error);
                return;
            }
        };

        // Counted from the same value that is about to be written, so the
        // metric and the audit row cannot disagree — the property
        // `Metrics::record_audit` exists for. Spelled out here rather than
        // folded into `write` because this path has no `Auditor`, which is the
        // very reason the free function exists.
        let record = relay_record(
            crate::audit::AuditEvent::CertificateIssueFailed,
            &order,
            inner,
        )
        .await
        .with_reason("serverInternal")
        .with_detail(reason);
        inner.metrics.record_audit(&record);
        crate::audit::write(record, &inner.database).await;

        // The client sees a generic problem document; the real reason is
        // operator-only, on the mapping row and in the log above.
        let problem = Problem::server_internal("Upstream certificate issuance failed");
        if let Err(error) = order
            .mark_invalid(problem.to_value(), &inner.database)
            .await
        {
            error!(event = "upstream_relay_mark_invalid_failed", outcome = "failure", order_id = %order_id, error = %error);
        }
        if let Err(error) = UpstreamOrder::mark_invalid(order_id, reason, &inner.database).await {
            warn!(event = "upstream_order_mark_invalid_failed", outcome = "failure", error = %error);
        }
    }

    /// Re-queues relays a previous process left in flight.
    ///
    /// What `SignerBackend::resume` used to spawn, as an enqueue. Two things
    /// follow from that change: the identity index makes it safe to run again
    /// (a row already queued is simply not queued twice), and a job that fails
    /// after recovery now retries like any other instead of needing yet another
    /// restart.
    ///
    /// This is why the CSR is stored — an upstream order still at `ready` needs
    /// that exact CSR to finalize, and it is long gone from memory.
    /// Fans out over every relay backend, since this handler serves them all
    /// and `runner::recover_new_kinds` calls it once per kind per process.
    ///
    /// Each backend is asked only for the orders of the profiles **this
    /// generation** says it serves — which is why the profile list lives on
    /// this map rather than on the backend. A backend reused across a reload
    /// remembers the profile set it was built for, so a profile mounted onto an
    /// unchanged `[signer]` section would have had its in-flight orders left on
    /// the floor until a restart.
    async fn recover(&self, queue: &JobQueue) {
        for (inner, profiles) in &self.upstreams {
            let pending = match UpstreamOrder::list_processing(profiles, &inner.database).await {
                Ok(pending) => pending,
                Err(error) => {
                    // Best-effort by contract: log and let the server start.
                    error!(event = "upstream_resume_lookup_failed", outcome = "failure", error = %error);
                    continue;
                }
            };

            if pending.is_empty() {
                continue;
            }
            info!(
                event = "upstream_relay_resume_started",
                outcome = "progress",
                count = pending.len()
            );
            if pending.len() >= crate::sqlite::upstream_order::MAX_PROCESSING_BATCH {
                warn!(
                    event = "upstream_relay_batch_capped",
                    outcome = "advisory",
                    count = pending.len(),
                    "more orders are still processing than one recovery pass picks up; the \
                     rest are taken by a later restart",
                );
            }

            for row in pending {
                let context = OrderContext::read(&row.order_id, inner).await;
                queue
                    .enqueue_or_log(relay_spec(&row.order_id, &context))
                    .await;
            }
        }
    }
}

/// The job one relayed issuance is queued as.
///
/// The payload is the order's *identity* and nothing else: every other field the
/// relay needs is on the `upstream_orders` row, and re-reading it each attempt
/// is what keeps a retry from working off a stale snapshot. The profile is part
/// of that identity — an order is placed against one endpoint and stays there —
/// and it is what tells [`RelayJob`] which upstream this row belongs to, the
/// same way a `notify_deliver` row names the profile it is delivering for.
pub(super) fn relay_spec(order_id: &str, context: &OrderContext) -> JobSpec {
    let mut payload = json!({ "order_id": order_id });
    if let Some(profile) = &context.profile {
        payload["profile"] = json!(profile);
    }
    JobSpec::now(RELAY_JOB_KIND, order_id)
        .with_payload(payload)
        .with_deadline(context.deadline)
}

/// What the queue needs from the local order a relay was asked for: how long it
/// may be retried, and which endpoint it was placed against.
///
/// Both come from one read, on a path that has just made an HTTPS round trip.
/// A lookup failure yields neither, which is deliberate on both counts: no
/// deadline is a worse bound than the right one but a better one than refusing
/// to queue the work at all, and a payload naming no profile still resolves —
/// [`RelayJob::resolve`] reads the order itself, which is the same fallback a
/// row queued before this field existed takes.
#[derive(Default)]
pub(super) struct OrderContext {
    /// `orders.expires`. Past that point the order is refused on read, so a
    /// certificate obtained upstream could never be collected by the client
    /// that asked for it: retrying beyond it is not merely wasteful, it cannot
    /// produce the outcome.
    pub(super) deadline: Option<i64>,
    /// `orders.profile`, which names the relay backend that owns this work.
    pub(super) profile: Option<String>,
}

impl OrderContext {
    pub(super) async fn read(order_id: &str, inner: &Inner) -> Self {
        match Order::find_by_id(order_id, &inner.database).await {
            Ok(Some(order)) => Self {
                deadline: Some(order.expires),
                profile: Some(order.profile),
            },
            Ok(None) => Self::default(),
            Err(error) => {
                warn!(event = "upstream_relay_order_context_lookup_failed", outcome = "failure", order_id = %order_id, error = %error);
                Self::default()
            }
        }
    }
}

/// Drives one upstream order to a certificate. Returns the PEM chain, or why it
/// could not be obtained and whether asking again might help.
async fn relay(
    inner: &Inner,
    order_id: &str,
    csr_der: &[u8],
    order_url: &str,
) -> Result<String, RelayFailure> {
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
        let finalize = view.finalize.clone().ok_or_else(|| {
            RelayFailure::Permanent(
                "upstream order is ready but advertises no finalize URL".to_string(),
            )
        })?;
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
            .map_err(|error| classify(&error))?;
        poll_until(inner, order_url, &["valid"]).await?
    } else {
        view
    };

    let certificate_url = view.certificate.ok_or_else(|| {
        RelayFailure::Permanent(
            "upstream order is valid but carries no certificate URL".to_string(),
        )
    })?;

    let response = inner
        .client
        .get(&inner.account, &inner.kid, &certificate_url)
        .await
        .map_err(|error| classify(&error))?;

    let chain = response.text().map_err(|error| classify(&error))?;

    if let Err(error) =
        UpstreamOrder::mark_valid(order_id, Some(&certificate_url), &inner.database).await
    {
        warn!(event = "upstream_order_mark_valid_failed", outcome = "failure", error = %error);
    }

    Ok(chain)
}

/// **This proxy's** account thumbprint at the upstream — never the end client's.
///
/// The two are different accounts on different servers: the client proved
/// control to this server with its own key, and this server proves it again
/// upstream with the key in `signer.relay.account_key_path`. Both challenge
/// strategies need it, and both had this block written out.
///
/// Permanent rather than retryable: a local account key that cannot produce a
/// thumbprint is a key problem, not a moment's bad luck, and asking again in
/// thirty seconds changes nothing.
fn upstream_thumbprint(inner: &Inner) -> Result<String, RelayFailure> {
    crate::extractors::acme::jwk_thumbprint(inner.account.spki_der()).map_err(|error| {
        RelayFailure::Permanent(format!(
            "cannot derive the upstream account thumbprint: {error}"
        ))
    })
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
) -> Result<(), RelayFailure> {
    let thumbprint = upstream_thumbprint(inner)?;

    for authz_url in authorizations {
        let authz = read_authz(inner, authz_url).await?;

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
                // Permanent: the CA's offer will not change on the next attempt.
                RelayFailure::Permanent(format!(
                    "upstream authorization for {} offers no dns-01 challenge",
                    authz.identifier.value
                ))
            })?;

        let token = require_token(challenge, &authz.identifier.value)?;

        // Name and digest come from the inbound validator's own helpers, so the
        // two directions cannot disagree about the convention.
        let name = crate::challenge::dns_01::record_name(&authz.identifier.value);
        let key_authorization = format!("{token}.{thumbprint}");
        let value = crate::challenge::dns_01::expected_value(&key_authorization);

        // RFC 2136 wants an absolute name.
        let fqdn = if name.ends_with('.') {
            name.clone()
        } else {
            format!("{name}.")
        };

        // Retryable: a nameserver that refused an update, or was unreachable,
        // is the commonest transient failure on this path.
        updater.upsert_txt(&fqdn, &value).await.map_err(|error| {
            RelayFailure::Retryable(format!("publishing {fqdn} failed: {error}"))
        })?;

        let triggered = trigger_and_await(inner, &challenge.url, authz_url).await;

        // Cleanup is best-effort and happens whether or not validation passed:
        // a challenge record has no reason to outlive the attempt.
        if let Err(error) = updater.delete_txt(&fqdn, &value).await {
            warn!(event = "signer_relay_dns_01_cleanup_failed", outcome = "failure", name = %fqdn, error = %error);
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
) -> Result<(), RelayFailure> {
    let thumbprint = upstream_thumbprint(inner)?;

    for authz_url in authorizations {
        let authz = read_authz(inner, authz_url).await?;

        // Already proved (a re-run after a restart, or a reused authorization).
        if authz.status != "pending" {
            continue;
        }

        // Checked on the value's leading `*.` because `UpstreamIdentifier`
        // carries no `type`, and checked *before* looking for a challenge so
        // the error names the real problem rather than "offers no http-01" —
        // a CA correctly offers dns-01 alone for a wildcard. Permanent: this is
        // a configuration mismatch, and no number of attempts resolves it.
        if authz.identifier.value.starts_with("*.") {
            return Err(RelayFailure::Permanent(format!(
                "upstream authorization for {} is a wildcard, which http-01 cannot validate: use \
                 signer.relay.challenge_strategy = \"dns01\" for wildcard names",
                authz.identifier.value
            )));
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|challenge| challenge.typ == crate::challenge::HTTP_01)
            .ok_or_else(|| {
                // Deliberately not falling back to another type, for the same
                // reason `answer_dns01` does not: silently trying one this
                // server cannot answer fails later and more confusingly.
                RelayFailure::Permanent(format!(
                    "upstream authorization for {} offers no http-01 challenge",
                    authz.identifier.value
                ))
            })?;

        let token = require_token(challenge, &authz.identifier.value)?;

        // §8.3 serves the key authorization itself — no digest, unlike dns-01.
        let key_authorization = format!("{token}.{thumbprint}");

        // Dropped at the end of this iteration, on any early return, and — the
        // case an explicit retract would miss — when the job runner's per-attempt
        // timeout drops this future mid-poll.
        let _published = http01::PublishedToken::publish(tokens.clone(), token, &key_authorization);

        // Returns only once the upstream's authorization is terminal, so every
        // validation fetch — including a multi-perspective CA's several — has
        // already happened by the time `_published` drops.
        trigger_and_await(inner, &challenge.url, authz_url).await?;
    }
    Ok(())
}

/// Triggers any available challenge when the strategy is Bypass.
async fn answer_bypass(inner: &Inner, authorizations: &[String]) -> Result<(), RelayFailure> {
    for authz_url in authorizations {
        let authz = read_authz(inner, authz_url).await?;

        // Already proved
        if authz.status != "pending" {
            continue;
        }

        // Prefer one of the token-based types: an upstream that bypasses
        // validation will accept whichever challenge is triggered, but a type
        // this server could never satisfy is the wrong one to pick when a
        // familiar one is sitting beside it. Falls back to the first challenge
        // so an upstream offering only unfamiliar types still gets triggered.
        let challenge = authz
            .challenges
            .iter()
            .find(|challenge| challenge.token.is_some())
            .or_else(|| authz.challenges.first())
            .ok_or_else(|| {
                RelayFailure::Permanent(format!(
                    "upstream authorization for {} offers no challenges to bypass",
                    authz.identifier.value
                ))
            })?;

        trigger_and_await(inner, &challenge.url, authz_url).await?;
    }
    Ok(())
}

/// The token a token-based challenge type must carry.
///
/// Permanent rather than retryable: a CA that offered `dns-01` or `http-01`
/// without a token is contradicting itself, and no number of attempts changes
/// what it says. Distinct from the challenge simply being absent from the
/// offer, which is what the `offers no …` refusals above report.
fn require_token<'a>(
    challenge: &'a UpstreamChallengeView,
    identifier: &str,
) -> Result<&'a str, RelayFailure> {
    challenge.token.as_deref().ok_or_else(|| {
        RelayFailure::Permanent(format!(
            "upstream {} challenge for {identifier} carries no token",
            challenge.typ
        ))
    })
}

/// Reads one upstream authorization.
///
/// One function rather than the same four lines in each `answer_*`, so the
/// classification of a failed read is decided once: a transport failure and an
/// unparsable body are both the upstream being unreachable in some way, never a
/// statement about this order.
async fn read_authz(inner: &Inner, authz_url: &str) -> Result<UpstreamAuthzView, RelayFailure> {
    let response = inner
        .client
        .get(&inner.account, &inner.kid, authz_url)
        .await
        .map_err(|error| classify(&error))?;
    response.json().map_err(|error| classify(&error))
}

/// POSTs the challenge to tell the upstream to validate, then waits for its
/// authorization to settle.
async fn trigger_and_await(
    inner: &Inner,
    challenge_url: &str,
    authz_url: &str,
) -> Result<(), RelayFailure> {
    inner
        .client
        .post(
            &inner.account,
            &Signer::Kid(&inner.kid),
            challenge_url,
            Some(&json!({})),
        )
        .await
        .map_err(|error| match classify(&error) {
            RelayFailure::Retryable(reason) => RelayFailure::Retryable(format!(
                "triggering the upstream challenge failed: {reason}"
            )),
            RelayFailure::Permanent(reason) => RelayFailure::Permanent(format!(
                "triggering the upstream challenge failed: {reason}"
            )),
        })?;

    let deadline = tokio::time::Instant::now() + inner.poll.timeout;
    loop {
        let authz = read_authz(inner, authz_url).await?;

        match authz.status.as_str() {
            "valid" => return Ok(()),
            "invalid" => {
                // The CA looked and said no. Permanent: the client's own record
                // or reachability is what would have to change, not the moment.
                return Err(RelayFailure::Permanent(format!(
                    "upstream rejected the challenge for {}",
                    authz.identifier.value
                )));
            }
            _ if tokio::time::Instant::now() >= deadline => {
                // Retryable, and the single biggest behavioural gain of the
                // queue: a slow CA used to invalidate the order outright.
                return Err(RelayFailure::Retryable(format!(
                    "upstream authorization for {} did not settle in time",
                    authz.identifier.value
                )));
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
) -> Result<UpstreamOrderView, RelayFailure> {
    loop {
        let response = inner
            .client
            .get(&inner.account, &inner.kid, order_url)
            .await
            .map_err(|error| classify(&error))?;
        let view: UpstreamOrderView = response.json().map_err(|error| classify(&error))?;

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
            // The CA's own verdict on this order. Permanent.
            return Err(RelayFailure::Permanent(format!(
                "upstream order became invalid: {detail}"
            )));
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

/// Writes a successful relay back onto the local order — the whole reason this
/// backend holds an `Arc<Database>`.
///
/// Returns the job's own outcome, so the two ways this can still fail after the
/// upstream has issued are distinguished rather than merged: a chain that will
/// never parse is permanent, while a database that would not take the write is a
/// retry. The second one matters — before the queue it was a log line and a
/// dropped certificate, leaving the client polling an order that would never
/// move.
pub(super) async fn settle(inner: &Inner, order_id: &str, chain: String) -> JobOutcome {
    let mut order = match Order::find_by_id(order_id, &inner.database).await {
        Ok(Some(order)) => order,
        Ok(None) => {
            warn!(event = "upstream_relay_order_vanished", outcome = "failure", order_id = %order_id);
            return JobOutcome::Failed("the local order no longer exists".to_string());
        }
        Err(error) => {
            error!(event = "upstream_relay_order_lookup_failed", outcome = "failure", order_id = %order_id, error = %error);
            return JobOutcome::Retry(format!("reading the local order failed: {error}"));
        }
    };

    let leaf = match crate::cert::leaf_der_from_chain(&chain) {
        Ok(leaf) => leaf,
        Err(error) => {
            return JobOutcome::Failed(format!("upstream chain unparsable: {error}"));
        }
    };
    let (serial, pubkey) = match crate::cert::cert_serial_and_spki(&leaf) {
        Ok(parts) => parts,
        Err(error) => {
            return JobOutcome::Failed(format!("upstream leaf unparsable: {error}"));
        }
    };

    // Best-effort, for the reason `handlers::order` states at its own call
    // site: an upstream leaf this server cannot read the validity of is still
    // a certificate the client is owed.
    let cert_not_after = crate::cert::cert_validity(&leaf)
        .ok()
        .map(|(_, not_after)| not_after);

    if let Err(error) = order
        .finalize(
            chain,
            serial.clone(),
            pubkey,
            cert_not_after,
            &inner.database,
        )
        .await
    {
        error!(event = "upstream_relay_finalize_failed", outcome = "failure", order_id = %order_id, error = %error);
        // Retryable: the certificate exists upstream and the whole relay is
        // re-entrant, so the next attempt collects it again and writes it.
        return JobOutcome::Retry(format!("recording the certificate failed: {error}"));
    }
    info!(event = "upstream_relay_succeeded", outcome = "success", order_id = %order_id, cert_serial = %serial);

    // The audit row for this issuance, written here and nowhere else:
    // `post_finalize` answered `processing` without signing anything, so this is
    // the moment a certificate came into existence. The client context is the
    // one that request stored on the mapping row — the relay has no request of
    // its own, and a row saying "issued, from nowhere, by nobody" is the shape
    // this trail exists to avoid.
    let record = relay_record(crate::audit::AuditEvent::CertificateIssued, &order, inner)
        .await
        .with_serial(serial.clone());
    // See the failure arm above: no `Auditor` reaches this task, so the counter
    // is bumped from the record itself rather than from a wrapper.
    inner.metrics.record_audit(&record);
    crate::audit::write(record, &inner.database).await;

    // The synchronous signer backends (`local_ca`, `custom`) notify from
    // `post_finalize`'s own success tail, which has a `Profile` in scope. This
    // backend's completion happens here instead, long after that handler
    // returned — so it looks up the right profile's dispatcher by
    // `Order.profile` rather than being handed one directly. `client_ip` is
    // `None`: no request is in scope on this path at all.
    if let Some(dispatcher) = inner.notifiers.get(&order.profile) {
        dispatcher
            .dispatch(NotifyEvent::CertificateIssued(CertificateIssuedData {
                profile: order.profile.clone(),
                order_id: order_id.to_string(),
                account_id: order.account_id.clone(),
                cert_serial: serial.clone(),
                identifiers: order.identifiers.iter().map(|i| i.value.clone()).collect(),
                client_ip: None,
            }))
            .await;
    }

    JobOutcome::Done
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
            warn!(event = "upstream_order_client_context_lookup_failed", outcome = "failure", order_id = %order.id, error = %error);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The classification table, one row per way the upstream can fail.
    ///
    /// Table-driven because the two mistakes it guards against are symmetric and
    /// both silent: a permanent failure classed retryable burns the whole budget
    /// before the client hears the real answer, and a transient one classed
    /// permanent throws away the retry this queue exists for.
    #[test]
    fn every_upstream_failure_is_classified_by_whose_answer_it_is() {
        let permanent = |error: UpstreamError| match classify(&error) {
            RelayFailure::Permanent(_) => (),
            other => panic!("{error} must be permanent, got {other:?}"),
        };
        let retryable = |error: UpstreamError| match classify(&error) {
            RelayFailure::Retryable(_) => (),
            other => panic!("{error} must be retryable, got {other:?}"),
        };

        // Nobody decided anything.
        retryable(UpstreamError::Transport("connection reset".to_string()));
        retryable(UpstreamError::Url("no host".to_string()));
        // A gateway's HTML error page in front of a CA that is briefly down
        // arrives as exactly this.
        retryable(UpstreamError::Protocol(
            "expected a JSON object".to_string(),
        ));
        retryable(UpstreamError::Problem {
            status: 500,
            typ: "urn:ietf:params:acme:error:serverInternal".to_string(),
            detail: "internal error".to_string(),
        });
        retryable(UpstreamError::Problem {
            status: 503,
            typ: "urn:ietf:params:acme:error:serverInternal".to_string(),
            detail: "try later".to_string(),
        });
        // A rate limit is the CA explicitly asking to be asked again later.
        retryable(UpstreamError::Problem {
            status: 429,
            typ: "urn:ietf:params:acme:error:rateLimited".to_string(),
            detail: "too many certificates".to_string(),
        });

        // The CA stated a reason.
        permanent(UpstreamError::Problem {
            status: 403,
            typ: "urn:ietf:params:acme:error:unauthorized".to_string(),
            detail: "not authorized".to_string(),
        });
        permanent(UpstreamError::Problem {
            status: 400,
            typ: "urn:ietf:params:acme:error:badCSR".to_string(),
            detail: "unacceptable key".to_string(),
        });
        permanent(UpstreamError::Problem {
            status: 400,
            typ: "urn:ietf:params:acme:error:rejectedIdentifier".to_string(),
            detail: "will not issue for that name".to_string(),
        });
        // A local key problem: time does not fix it.
        permanent(UpstreamError::Jws("signing failed".to_string()));
    }

    #[test]
    fn a_classified_failure_keeps_the_upstream_error_text() {
        let error = UpstreamError::Transport("connection reset".to_string());
        let failure = classify(&error);
        assert_eq!(failure.reason(), error.to_string());
        assert_eq!(failure.to_string(), error.to_string());
    }

    #[test]
    fn a_relay_job_spec_carries_the_order_id_as_both_identity_and_payload() {
        let spec = relay_spec(
            "ord-1",
            &OrderContext {
                deadline: Some(1_234),
                profile: Some("le".to_string()),
            },
        );
        assert_eq!(spec.kind, RELAY_JOB_KIND);
        // The key, so two finalize requests for one order queue one job.
        assert_eq!(spec.key, "ord-1");
        // The profile beside it is what tells the shared handler which upstream
        // this row belongs to.
        assert_eq!(spec.payload, json!({"order_id": "ord-1", "profile": "le"}));
        assert_eq!(spec.deadline, Some(1_234));
    }

    /// An order that could not be read names no endpoint, and the payload then
    /// carries no `profile` member at all rather than a null one — which is
    /// what `RelayJob::resolve` distinguishes to take the order-row fallback.
    #[test]
    fn a_spec_for_an_unreadable_order_names_neither_profile_nor_deadline() {
        let spec = relay_spec("ord-1", &OrderContext::default());
        assert_eq!(spec.payload, json!({"order_id": "ord-1"}));
        assert_eq!(spec.deadline, None);
    }
}
