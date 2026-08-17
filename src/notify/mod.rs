//! Operator notifications for ACME lifecycle events.
//!
//! The shape mirrors [`filter`](crate::filter)/[`signer`](crate::signer): a
//! trait, an error type, and a [`from_config`] selector building the
//! configured set at startup. Three backends exist today —
//! [`email`], [`webhook`] (any HTTP endpoint, with the URL, method, headers
//! and body all configured, which is what makes a chat provider configuration
//! rather than code), and [`custom`] (an external script, for a channel that
//! is not an HTTP request at all).
//!
//! ## Fire-and-forget, always — and now durable
//!
//! A notification can never affect the ACME response that triggered it.
//! [`NotifyDispatcher::dispatch`] returns `()` and cannot be `?`'d: it writes
//! the delivery to the [durable queue](crate::jobs) and returns. That is a
//! deliberate API shape, not a convention callers must remember — there is no
//! method on this type whose result a handler *could* propagate.
//!
//! What changed is what happens *after* it returns. Delivery used to be a bare
//! `tokio::spawn`, so a refused SMTP connection or a 503 from a webhook was
//! logged once and the notification was gone, and a restart lost everything in
//! flight — the operator never heard that a certificate had been issued, and
//! nothing recorded that they hadn't. Now each delivery is a `notify_deliver`
//! job row: a transport failure is retried under `jobs.max_attempts` and the
//! shared backoff, and a row outlives the process that queued it.
//!
//! Two consequences worth not rediscovering:
//!
//! - **One job per (occurrence × backend)**, never one per event. A retry must
//!   not re-send to a backend that already succeeded, or one flaky webhook
//!   produces a duplicate email on every attempt.
//! - **[`NotifyError`] carries whether it is worth retrying.** A template that
//!   does not render and a 400 from a webhook will fail identically for ever,
//!   so they are permanent and refused on the first attempt; a connection
//!   refused, a timeout and a 503 have decided nothing, so they are retried.
//!   That is [`crate::jobs`]'s `Retry`/`Failed` split, applied at the source.
//!
//! ## Per-backend event filtering
//!
//! Unlike [`FilterConfig::rules`](crate::config::FilterConfig), where every
//! filter must agree, notify backends are independent broadcast side-channels
//! — an operator plausibly wants email only for issuance/revocation and a chat
//! webhook for everything including failures. Each backend's own `events`
//! list (defaulting to all six kinds) decides what reaches it, and the list
//! lives on its [`BackendSlot`] so the check happens once, in
//! [`NotifyDispatcher::dispatch`], rather than in each backend's own delivery
//! code. Filtering *there* rather than in a wrapper around `send` is what stops
//! a job being queued for a delivery that would immediately do nothing.
//!
//! ## Per-profile, like every other subsystem
//!
//! [`build_registry`] builds one [`NotifyDispatcher`] per resolved profile
//! (not deduplicated by configuration identity like signer backends are —
//! dispatchers are stateless side-channels, so two profiles with identical
//! `[notify]` sections simply get two independent instances). The
//! asynchronous `relay` signer backend, whose completion happens outside
//! any HTTP handler, is handed the whole `profile name -> dispatcher` map so
//! it can notify the right profile once an order settles — see
//! `signer::relay::flow::settle`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use tracing::info;

use crate::config::{ALL_NOTIFY_EVENTS, NotifyConfig, ProfileConfig};
use crate::jobs::{JobQueue, JobSpec};

pub mod custom;
pub mod email;
pub mod job;
pub mod webhook;

pub use job::{NOTIFY_JOB_KIND, NotifyJob};

/// A pluggable notification channel.
#[async_trait]
pub trait NotifyBackend: Send + Sync {
    /// The configuration name this backend runs under, used in logs.
    fn name(&self) -> &'static str;

    /// Delivers `event`. Failure is always non-fatal to the *caller* — see the
    /// module docs — but it is no longer thrown away: [`NotifyJob`] retries it
    /// unless the [`NotifyError`] says the attempt could never have worked.
    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError>;
}

/// Why a notify backend failed to deliver, and whether asking again could help.
///
/// The `retryable` half is what [`NotifyJob`] turns into
/// [`JobOutcome::Retry`](crate::jobs::JobOutcome::Retry) or
/// [`JobOutcome::Failed`](crate::jobs::JobOutcome::Failed), so the distinction
/// has to be drawn where the failure happens rather than guessed from a string
/// afterwards. The default — [`NotifyError::new`] — is *retryable*, because
/// most of these are transport; a backend that knows better says so with
/// [`NotifyError::permanent`].
#[derive(Debug)]
pub struct NotifyError {
    detail: String,
    retryable: bool,
}

impl NotifyError {
    /// A failure that may not recur: a refused connection, a timeout, a 503.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            retryable: true,
        }
    }

    /// A failure that will repeat identically however many times it is tried:
    /// a template that does not render, a URL that does not parse, a webhook
    /// that answers 400.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            retryable: false,
        }
    }

    /// Whether another attempt could plausibly succeed.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryable
    }
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for NotifyError {}

/// Context common to every event: the profile it happened on and the client
/// address, when a request was in scope.
///
/// `client_ip` is `None` on the one firing site with no request in scope at
/// all — the `relay` signer backend's asynchronous completion, which
/// runs in a background task long after any handler returned. Templates must
/// treat it as optional.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProfileMountedData {
    pub profile: String,
}

/// Payload of [`NotifyEvent::AccountCreated`]: a client registered a new
/// account at this endpoint.
///
/// `contact` is what the client supplied, which may legitimately be empty —
/// RFC 8555 does not require one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountCreatedData {
    pub profile: String,
    pub account_id: String,
    pub contact: Vec<String>,
    pub client_ip: Option<String>,
}

/// Payload of [`NotifyEvent::AccountDeactivated`]: an account was deactivated,
/// either by the client (§7.3.6) or by `acme-proxy account deactivate`.
///
/// Deactivation is permanent, so this event has no counterpart.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountDeactivatedData {
    pub profile: String,
    pub account_id: String,
    pub client_ip: Option<String>,
}

/// Payload of [`NotifyEvent::CertificateIssued`]: a certificate was signed.
///
/// `cert_serial` is the hex serial, the same value `POST /revokeCert` and the
/// audit trail identify a certificate by. `identifiers` are the names the
/// certificate covers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateIssuedData {
    pub profile: String,
    pub order_id: String,
    pub account_id: String,
    pub cert_serial: String,
    pub identifiers: Vec<String>,
    pub client_ip: Option<String>,
}

/// Payload of [`NotifyEvent::CertificateRevoked`]: a certificate was withdrawn.
///
/// `reason` is the RFC 5280 §5.3.1 code the caller supplied, and is `None` when
/// none was given — which is not the same as `Some(0)`. It reaches a `custom`
/// script only in the JSON on stdin, since it has no environment variable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateRevokedData {
    pub profile: String,
    pub order_id: String,
    pub account_id: String,
    pub cert_serial: String,
    pub reason: Option<u32>,
    pub client_ip: Option<String>,
}

/// Payload of [`NotifyEvent::ChallengeFailed`]: a validation attempt did not
/// succeed.
///
/// This fires on the failure of one *challenge*, which is not necessarily the
/// failure of the order: a client may have another enabled type left to try.
/// `error` is the human-readable detail, the same text the challenge object's
/// `error` member carries back to the client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChallengeFailedData {
    pub profile: String,
    pub order_id: String,
    pub account_id: String,
    pub authz_id: String,
    pub challenge_id: String,
    pub challenge_type: String,
    pub identifier: String,
    pub error: String,
    pub client_ip: Option<String>,
}

/// One lifecycle event, carrying everything a template or `custom` script
/// needs to describe it.
///
/// **Internally tagged on `hook`**, which is load-bearing twice over. It is the
/// `custom` backend's stdin contract — a script reads `.hook` to tell one event
/// from another — and it is what lets a queued delivery survive a restart, since
/// a `notify_deliver` job payload is this enum and nothing else. The tag and the
/// variant renaming reproduce exactly what [`Self::payload`] used to assemble by
/// hand, so neither the script contract nor a row already in the queue changes
/// shape; `payload_is_tagged_with_its_own_hook` pins that.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "hook", rename_all = "snake_case")]
pub enum NotifyEvent {
    ProfileMounted(ProfileMountedData),
    AccountCreated(AccountCreatedData),
    AccountDeactivated(AccountDeactivatedData),
    CertificateIssued(CertificateIssuedData),
    CertificateRevoked(CertificateRevokedData),
    ChallengeFailed(ChallengeFailedData),
}

impl NotifyEvent {
    /// The event kind name — matches [`ALL_NOTIFY_EVENTS`] and the template
    /// file stem used to render it (e.g. `email/certificate_issued.body.j2`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ProfileMounted(_) => "profile_mounted",
            Self::AccountCreated(_) => "account_created",
            Self::AccountDeactivated(_) => "account_deactivated",
            Self::CertificateIssued(_) => "certificate_issued",
            Self::CertificateRevoked(_) => "certificate_revoked",
            Self::ChallengeFailed(_) => "challenge_failed",
        }
    }

    /// The profile this event happened on.
    pub fn profile(&self) -> &str {
        match self {
            Self::ProfileMounted(data) => &data.profile,
            Self::AccountCreated(data) => &data.profile,
            Self::AccountDeactivated(data) => &data.profile,
            Self::CertificateIssued(data) => &data.profile,
            Self::CertificateRevoked(data) => &data.profile,
            Self::ChallengeFailed(data) => &data.profile,
        }
    }

    /// The template rendering context: this event's own data, serialized.
    pub(crate) fn context(&self) -> minijinja::Value {
        match self {
            Self::ProfileMounted(data) => minijinja::Value::from_serialize(data),
            Self::AccountCreated(data) => minijinja::Value::from_serialize(data),
            Self::AccountDeactivated(data) => minijinja::Value::from_serialize(data),
            Self::CertificateIssued(data) => minijinja::Value::from_serialize(data),
            Self::CertificateRevoked(data) => minijinja::Value::from_serialize(data),
            Self::ChallengeFailed(data) => minijinja::Value::from_serialize(data),
        }
    }

    /// This event's own data as a JSON object, tagged with `"hook"` — the
    /// `custom` backend's stdin payload, and the body of a queued
    /// `notify_deliver` job. Not used by the templating backends, which render
    /// from [`Self::context`] instead.
    ///
    /// This is the enum's own `Serialize`: the internal tag *is* the `"hook"`
    /// member that used to be spliced in here after the fact.
    pub(crate) fn payload(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("notify event data always serializes to a JSON object")
    }

    /// This event's client address, when a request was in scope — `None` on
    /// the `relay` async-completion path. Used by the `custom` backend
    /// to fill `ACME_NOTIFY_CLIENT_IP`.
    fn client_ip(&self) -> Option<&str> {
        match self {
            Self::ProfileMounted(_) => None,
            Self::AccountCreated(data) => data.client_ip.as_deref(),
            Self::AccountDeactivated(data) => data.client_ip.as_deref(),
            Self::CertificateIssued(data) => data.client_ip.as_deref(),
            Self::CertificateRevoked(data) => data.client_ip.as_deref(),
            Self::ChallengeFailed(data) => data.client_ip.as_deref(),
        }
    }

    /// This event's account id, when it has one. Used by the `custom` backend
    /// to fill `ACME_NOTIFY_ACCOUNT_ID`.
    fn account_id(&self) -> Option<&str> {
        match self {
            Self::ProfileMounted(_) => None,
            Self::AccountCreated(data) => Some(&data.account_id),
            Self::AccountDeactivated(data) => Some(&data.account_id),
            Self::CertificateIssued(data) => Some(&data.account_id),
            Self::CertificateRevoked(data) => Some(&data.account_id),
            Self::ChallengeFailed(data) => Some(&data.account_id),
        }
    }

    /// This event's order id, when it has one. Used by the `custom` backend
    /// to fill `ACME_NOTIFY_ORDER_ID`.
    fn order_id(&self) -> Option<&str> {
        // Enumerated rather than `_ => None`, like every other accessor here:
        // a wildcard would let a seventh variant carrying an order id compile,
        // ship, and write an empty `ACME_NOTIFY_ORDER_ID` — the exact silent
        // failure the accessor tests exist to make impossible.
        match self {
            Self::ProfileMounted(_) => None,
            Self::AccountCreated(_) => None,
            Self::AccountDeactivated(_) => None,
            Self::CertificateIssued(data) => Some(&data.order_id),
            Self::CertificateRevoked(data) => Some(&data.order_id),
            Self::ChallengeFailed(data) => Some(&data.order_id),
        }
    }

    /// This event's certificate serial, when it has one. Used by the `custom`
    /// backend to fill `ACME_NOTIFY_CERT_SERIAL`.
    fn cert_serial(&self) -> Option<&str> {
        match self {
            Self::ProfileMounted(_) => None,
            Self::AccountCreated(_) => None,
            Self::AccountDeactivated(_) => None,
            Self::CertificateIssued(data) => Some(&data.cert_serial),
            Self::CertificateRevoked(data) => Some(&data.cert_serial),
            Self::ChallengeFailed(_) => None,
        }
    }

    /// This event's requested identifiers, comma-joined. Used by the `custom`
    /// backend to fill `ACME_NOTIFY_IDENTIFIERS`.
    fn identifiers_joined(&self) -> String {
        match self {
            Self::ProfileMounted(_) => String::new(),
            Self::AccountCreated(_) => String::new(),
            Self::AccountDeactivated(_) => String::new(),
            Self::CertificateIssued(data) => data.identifiers.join(","),
            Self::CertificateRevoked(_) => String::new(),
            Self::ChallengeFailed(_) => String::new(),
        }
    }
}

/// One configured backend, under the id a queued job addresses it by.
///
/// The id is **not** [`NotifyBackend::name`]: that is a `&'static str` a backend
/// type answers, so every `custom` entry reports `"custom"` and two of them
/// would be indistinguishable to a job row. It is built from the configuration
/// instead — `email`, `webhook:<entry>`, `custom:<entry>` — which makes it
/// stable across a restart, the property a durable payload needs. The same
/// reasoning gives `filter::custom` its `ACME_FILTER_CHECK_NAME`.
pub struct BackendSlot {
    id: String,
    /// The event kinds this backend's own `events` list admits. Filtering here
    /// rather than inside a wrapper around `send` is what stops a job being
    /// queued for a delivery that would immediately no-op.
    events: HashSet<String>,
    backend: Arc<dyn NotifyBackend>,
}

impl BackendSlot {
    /// The id a job payload names this backend by.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether this backend's `events` list admits `event`.
    #[must_use]
    pub fn wants(&self, event: &NotifyEvent) -> bool {
        self.events.contains(event.kind())
    }

    /// Builds a slot directly.
    ///
    /// [`from_config`] is how one is normally made — it derives the ids from the
    /// configuration, which is what keeps them stable across a restart. This is
    /// for a caller assembling a dispatcher over a backend of its own, which in
    /// practice means a test.
    #[must_use]
    pub fn new(id: impl Into<String>, backend: Arc<dyn NotifyBackend>, events: &[String]) -> Self {
        Self {
            id: id.into(),
            events: events.iter().cloned().collect(),
            backend,
        }
    }
}

/// The configured notify backends for one profile.
///
/// Cheap to clone behind the `Arc` it is always held in (`Profile::notify`,
/// and the `profile name -> dispatcher` map handed to the `relay` signer
/// backend and to [`NotifyJob`]).
pub struct NotifyDispatcher {
    profile: String,
    slots: Vec<BackendSlot>,
    jobs: JobQueue,
}

impl std::fmt::Debug for NotifyDispatcher {
    /// `dyn NotifyBackend` is not `Debug`, so show the slot ids — the only part
    /// worth reading anyway. Mirrors `FilterPolicy`'s own `Debug` impl.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotifyDispatcher")
            .field("profile", &self.profile)
            .field(
                "backends",
                &self.slots.iter().map(BackendSlot::id).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl NotifyDispatcher {
    /// Builds a dispatcher over already-constructed slots.
    #[must_use]
    pub fn new(profile: impl Into<String>, slots: Vec<BackendSlot>, jobs: JobQueue) -> Self {
        Self {
            profile: profile.into(),
            slots,
            jobs,
        }
    }

    /// A dispatcher with no backends — every `dispatch` is a no-op. The shape a
    /// profile with an empty `notify.enabled` gets, and what tests that do not
    /// care about notifications want.
    #[must_use]
    pub fn disabled(jobs: JobQueue) -> Self {
        Self::new("default", Vec::new(), jobs)
    }

    /// The profile whose `[notify]` section this dispatcher was built from.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The backend registered under `id`, if it is still configured. `None`
    /// after a configuration change removed a backend a queued job still names.
    #[must_use]
    pub fn slot(&self, id: &str) -> Option<&BackendSlot> {
        self.slots.iter().find(|slot| slot.id == id)
    }

    /// Queues one delivery per backend that wants this event, and returns.
    ///
    /// Not `?`-able and with nothing useful to return: a notification can never
    /// affect the ACME response that triggered it, which is why this goes
    /// through [`JobQueue::enqueue_or_log`] — a database failure here is logged
    /// and swallowed exactly like the delivery failure it stands in for.
    ///
    /// The `delivery_id` is minted per call, so the queue's identity index never
    /// refuses a genuine second occurrence of the same event: two dispatches
    /// mean two notifications, as they always did. It is shared across the
    /// backends of one call purely so an operator can correlate them in a log.
    pub async fn dispatch(&self, event: NotifyEvent) {
        if self.slots.is_empty() {
            return;
        }

        let kind = event.kind();
        let payload = event.payload();
        let delivery_id = uuid::Uuid::new_v4().to_string();
        for slot in &self.slots {
            if !slot.wants(&event) {
                continue;
            }
            let spec = JobSpec::now(NOTIFY_JOB_KIND, format!("{delivery_id}:{}", slot.id))
                .with_payload(serde_json::json!({
                    "profile": self.profile,
                    "backend": slot.id,
                    "event": payload,
                }));
            if self.jobs.enqueue_or_log(spec).await {
                info!(
                    event = "notify_delivery_queued",
                    outcome = "progress",
                    profile = %self.profile,
                    backend = %slot.id,
                    kind,
                    delivery_id = %delivery_id,
                );
            }
        }
    }

    /// Runs one delivery, now, against the backend registered under `id`.
    ///
    /// What [`NotifyJob`] calls for each claimed row, and what a test calls when
    /// it wants delivery without a runner in the way. `Ok(None)` means no such
    /// backend is configured any more — a decision for the caller, since a
    /// handler must retire that job rather than retry it for ever.
    pub(crate) async fn deliver(
        &self,
        id: &str,
        event: &NotifyEvent,
    ) -> Option<Result<(), NotifyError>> {
        let slot = self.slot(id)?;
        Some(slot.backend.send(event).await)
    }
}

/// An `events` list naming something outside [`ALL_NOTIFY_EVENTS`] is a
/// startup error, the same treatment `filter.enabled`/`challenge.enabled`
/// give an unknown name — a typo here should stop the server, not silently
/// mean "never fires".
fn validate_events(field: &str, events: &[String]) -> anyhow::Result<()> {
    for event in events {
        anyhow::ensure!(
            ALL_NOTIFY_EVENTS.contains(&event.as_str()),
            "{field}: unknown event `{event}` (expected one of {ALL_NOTIFY_EVENTS:?})"
        );
    }
    Ok(())
}

/// Builds the configured notify dispatcher. Called once per profile at
/// startup (via [`build_registry`]), so it may fail fast.
///
/// `jobs` is the enqueue side of the durable queue: every delivery is a row on
/// it, so a dispatcher cannot be built without one.
pub fn from_config(
    profile: &str,
    cfg: &NotifyConfig,
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
    jobs: &JobQueue,
) -> anyhow::Result<Arc<NotifyDispatcher>> {
    // Built once and shared: both templating backends render from the same
    // `template_dir` override, and `Environment` is cheap to clone (it holds
    // an `Arc`-like handle to its loader internally) but not to construct.
    let env = Arc::new(build_environment(&cfg.template_dir));

    let mut slots: Vec<BackendSlot> = Vec::with_capacity(cfg.enabled.len());
    for name in &cfg.enabled {
        let built: Vec<BackendSlot> = match name.as_str() {
            "email" => {
                validate_events("notify.email.events", &cfg.email.events)?;
                vec![BackendSlot::new(
                    "email",
                    Arc::new(email::EmailNotifier::from_config(&cfg.email, env.clone())?),
                    &cfg.email.events,
                )]
            }
            "webhook" => build_webhook_slots(cfg, &env, &resolver, &proxies)?,
            "custom" => build_custom_slots(cfg)?,
            // Refused by name, the `signer.backend = "acme_proxy"` -> `relay`
            // treatment: the `mattermost` backend was one provider's payload
            // shape frozen into a copy of the webhook transport, and every
            // other part of it now lives in `webhook`. An unmigrated
            // configuration stops the server rather than coming up looking
            // configured and notifying nobody.
            "mattermost" => anyhow::bail!(
                "notify.enabled: `mattermost` was replaced by `webhook`. Use \
                 notify.enabled = [\"webhook\"] with a [notify.webhook.<name>] entry \
                 whose `url` is the incoming webhook URL; the default `body` is \
                 already the payload Mattermost accepts. `channel` and `username` \
                 move into that `body`"
            ),
            other => anyhow::bail!("unknown notify backend: {other}"),
        };
        slots.extend(built);
    }

    if slots.is_empty() {
        info!(
            event = "notify_disabled",
            outcome = "success",
            "no notification backends configured"
        );
    } else {
        info!(event = "notify_enabled", outcome = "success", backends = ?cfg.enabled);
    }

    Ok(Arc::new(NotifyDispatcher::new(
        profile,
        slots,
        jobs.clone(),
    )))
}

/// One slot per `notify.custom` entry, addressed `custom:<entry>`.
///
/// The entry name is what makes two custom backends tell-apart-able: every
/// [`custom::CustomScriptNotifier`] answers `"custom"` to
/// [`NotifyBackend::name`], so a job payload naming that alone could not say
/// which script it meant. `resolve_named_entries` has already refused a name
/// that is not a valid environment-variable segment, so the id is safe to build
/// from it.
fn build_custom_slots(cfg: &NotifyConfig) -> anyhow::Result<Vec<BackendSlot>> {
    crate::config::resolve_named_entries(
        "notify.custom",
        "notify.custom_enabled",
        "custom",
        &cfg.custom,
        &cfg.custom_enabled,
    )?
    .into_iter()
    .map(|(name, script)| -> anyhow::Result<BackendSlot> {
        validate_events(&format!("notify.custom.{name}.events"), &script.events)?;
        let backend = custom::CustomScriptNotifier::from_config(script)?;
        Ok(BackendSlot::new(
            format!("custom:{name}"),
            Arc::new(backend),
            &script.events,
        ))
    })
    .collect()
}

/// One slot per selected `notify.webhook` entry, addressed `webhook:<entry>`.
///
/// Same shape and same reasoning as [`build_custom_slots`] — every
/// [`webhook::WebhookNotifier`] answers `"webhook"` to
/// [`NotifyBackend::name`], so the entry name is what tells two of them apart
/// in a durable job payload. The environment is passed by reference rather than
/// cloned in: each notifier compiles its own `body` into a clone of it, so a
/// template that does not parse is a startup error.
fn build_webhook_slots(
    cfg: &NotifyConfig,
    env: &minijinja::Environment<'static>,
    resolver: &Arc<dyn crate::dns::Resolver>,
    proxies: &Arc<crate::proxy::OutboundProxies>,
) -> anyhow::Result<Vec<BackendSlot>> {
    crate::config::resolve_named_entries(
        "notify.webhook",
        "notify.webhook_enabled",
        "webhook",
        &cfg.webhook,
        &cfg.webhook_enabled,
    )?
    .into_iter()
    .map(|(name, entry)| -> anyhow::Result<BackendSlot> {
        validate_events(&format!("notify.webhook.{name}.events"), &entry.events)?;
        let backend = webhook::WebhookNotifier::from_config(
            name,
            entry,
            env,
            resolver.clone(),
            proxies.clone(),
        )?;
        Ok(BackendSlot::new(
            format!("webhook:{name}"),
            Arc::new(backend),
            &entry.events,
        ))
    })
    .collect()
}

/// One generation's `profile name -> dispatcher` map.
///
/// Named because it appears in four signatures and clippy is right that the
/// spelled-out form is unreadable in all of them.
pub type DispatcherMap = HashMap<String, Arc<NotifyDispatcher>>;

/// The writing half of a [`Notifiers`] handle.
pub type NotifiersSender = tokio::sync::watch::Sender<Arc<DispatcherMap>>;

/// The `profile name -> dispatcher` map, as a handle that survives a
/// configuration reload.
///
/// The map itself is rebuilt whole on every generation, but two of its readers
/// outlive a generation: a signer backend captures it at construction (and
/// signer backends are carried across reloads rather than rebuilt), and
/// [`NotifyJob`] captures it at registration. Handing those two a plain `Arc`
/// pinned them to generation zero, which is worse than stale — a request served
/// by a *new* router writes a `notify_deliver` row naming a slot id from the
/// *new* configuration, and a `NotifyJob` still holding the old map would answer
/// [`JobOutcome::Failed`](crate::jobs::JobOutcome::Failed) for it. Permanently:
/// an unknown backend id is retired rather than retried, by design.
///
/// [`tokio::sync::watch::Receiver::borrow`] takes `&self` and does not mark the
/// value seen, so this stays `Clone + Send + Sync` and [`get`](Self::get) is
/// callable from any task. A generation is published with a single synchronous
/// [`tokio::sync::watch::Sender::send_replace`], so no reader can observe a
/// half-built map.
#[derive(Clone)]
pub struct Notifiers(tokio::sync::watch::Receiver<Arc<DispatcherMap>>);

impl Notifiers {
    /// The dispatcher for `profile` in the current generation, if it is mounted.
    #[must_use]
    pub fn get(&self, profile: &str) -> Option<Arc<NotifyDispatcher>> {
        // The `Ref` guard dies at the semicolon, so nothing holds the lock
        // across an await — which is the whole reason this returns an owned
        // `Arc` rather than lending one out.
        self.0.borrow().get(profile).cloned()
    }
}

/// A fixed map, for every caller that has no reload to serve — the tests, and
/// any construction that predates the first generation being published.
///
/// Dropping the sender leaves `borrow` working for ever (only `changed()` ever
/// errors on a closed channel), so this is a genuine constant, not a channel
/// that will go quiet. It is also what lets every existing call site pass an
/// `Arc<HashMap<..>>` unchanged.
impl From<Arc<DispatcherMap>> for Notifiers {
    fn from(map: Arc<DispatcherMap>) -> Self {
        Self(tokio::sync::watch::channel(map).1)
    }
}

impl From<DispatcherMap> for Notifiers {
    fn from(map: DispatcherMap) -> Self {
        Arc::new(map).into()
    }
}

/// One cell the reload path replaces, and every reader sees the new map at the
/// next `get`.
#[must_use]
pub fn notifiers_channel(initial: DispatcherMap) -> (NotifiersSender, Notifiers) {
    let (sender, receiver) = tokio::sync::watch::channel(Arc::new(initial));
    (sender, Notifiers(receiver))
}

/// Builds one [`NotifyDispatcher`] per resolved profile, keyed by profile
/// name — the map the `relay` signer backend needs to notify the right
/// profile from its background completion task, where there is no
/// `AppState`/`Profile` to reach through.
pub fn build_registry(
    profiles: &[ProfileConfig],
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
    jobs: &JobQueue,
) -> anyhow::Result<HashMap<String, Arc<NotifyDispatcher>>> {
    let mut registry = HashMap::with_capacity(profiles.len());
    for profile in profiles {
        let dispatcher = from_config(
            &profile.name,
            &profile.sections.notify,
            resolver.clone(),
            proxies.clone(),
            jobs,
        )
        .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
        registry.insert(profile.name.clone(), dispatcher);
    }
    Ok(registry)
}

/// Every default template, embedded so the server needs no external
/// `templates/` directory to run. Keyed the same way [`build_environment`]'s
/// loader looks them up: `"<backend>/<event>.<subject|body>.j2"` for email,
/// `"<backend>/<event>.j2"` for the webhook message.
static EMBEDDED_TEMPLATES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        (
            "email/profile_mounted.subject.j2",
            include_str!("templates/email/profile_mounted.subject.j2"),
        ),
        (
            "email/profile_mounted.body.j2",
            include_str!("templates/email/profile_mounted.body.j2"),
        ),
        (
            "email/account_created.subject.j2",
            include_str!("templates/email/account_created.subject.j2"),
        ),
        (
            "email/account_created.body.j2",
            include_str!("templates/email/account_created.body.j2"),
        ),
        (
            "email/account_deactivated.subject.j2",
            include_str!("templates/email/account_deactivated.subject.j2"),
        ),
        (
            "email/account_deactivated.body.j2",
            include_str!("templates/email/account_deactivated.body.j2"),
        ),
        (
            "email/certificate_issued.subject.j2",
            include_str!("templates/email/certificate_issued.subject.j2"),
        ),
        (
            "email/certificate_issued.body.j2",
            include_str!("templates/email/certificate_issued.body.j2"),
        ),
        (
            "email/certificate_revoked.subject.j2",
            include_str!("templates/email/certificate_revoked.subject.j2"),
        ),
        (
            "email/certificate_revoked.body.j2",
            include_str!("templates/email/certificate_revoked.body.j2"),
        ),
        (
            "email/challenge_failed.subject.j2",
            include_str!("templates/email/challenge_failed.subject.j2"),
        ),
        (
            "email/challenge_failed.body.j2",
            include_str!("templates/email/challenge_failed.body.j2"),
        ),
        (
            "webhook/profile_mounted.j2",
            include_str!("templates/webhook/profile_mounted.j2"),
        ),
        (
            "webhook/account_created.j2",
            include_str!("templates/webhook/account_created.j2"),
        ),
        (
            "webhook/account_deactivated.j2",
            include_str!("templates/webhook/account_deactivated.j2"),
        ),
        (
            "webhook/certificate_issued.j2",
            include_str!("templates/webhook/certificate_issued.j2"),
        ),
        (
            "webhook/certificate_revoked.j2",
            include_str!("templates/webhook/certificate_revoked.j2"),
        ),
        (
            "webhook/challenge_failed.j2",
            include_str!("templates/webhook/challenge_failed.j2"),
        ),
    ])
});

/// Builds a template environment: `template_dir` (if set) is checked for each
/// named template before falling back to the compiled-in default, so an
/// operator can override a single message and leave every other one at its
/// default.
pub(crate) fn build_environment(template_dir: &str) -> minijinja::Environment<'static> {
    let dir = (!template_dir.is_empty()).then(|| std::path::PathBuf::from(template_dir));
    let mut env = minijinja::Environment::new();
    env.set_loader(move |name| {
        if let Some(dir) = &dir
            && let Ok(contents) = std::fs::read_to_string(dir.join(name))
        {
            return Ok(Some(contents));
        }
        Ok(EMBEDDED_TEMPLATES.get(name).map(|body| (*body).to_string()))
    });
    env
}

/// Renders one named template against `event`'s own data.
///
/// Both failures are **permanent**: a template that is absent or does not
/// compile will be just as absent on the fifth attempt, so retrying only delays
/// the log line that tells the operator to fix it.
pub(crate) fn render(
    env: &minijinja::Environment<'static>,
    template_name: &str,
    event: &NotifyEvent,
) -> Result<String, NotifyError> {
    let template = env.get_template(template_name).map_err(|error| {
        NotifyError::permanent(format!("template `{template_name}` not found: {error}"))
    })?;
    template.render(event.context()).map_err(|error| {
        NotifyError::permanent(format!("template `{template_name}` failed: {error}"))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::CustomNotifyConfig;
    use crate::sqlite::db::Database;
    use crate::sqlite::job::Job;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// The shared resolver `Profile::build_all` supplies at startup.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    /// A queue over an in-memory database, for the assertions that read back
    /// the rows `dispatch` wrote.
    pub(crate) async fn test_queue() -> JobQueue {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        JobQueue::new(database, &crate::config::JobsConfig::default())
    }

    /// How a backend failed, when it is configured to.
    #[derive(Default, Clone, Copy)]
    enum Failure {
        #[default]
        None,
        Retryable,
        Permanent,
    }

    /// A backend recording every event it received, for asserting dispatch
    /// behavior without a real SMTP/HTTP/script target.
    #[derive(Default)]
    pub(crate) struct RecordingNotifyBackend {
        pub(crate) events: Mutex<Vec<NotifyEvent>>,
        fail: Failure,
    }

    impl RecordingNotifyBackend {
        /// Fails the way a refused connection does: worth another attempt.
        pub(crate) fn failing() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                fail: Failure::Retryable,
            }
        }

        /// Fails the way a missing template does: another attempt is pointless.
        pub(crate) fn failing_permanently() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                fail: Failure::Permanent,
            }
        }
    }

    #[async_trait]
    impl NotifyBackend for RecordingNotifyBackend {
        fn name(&self) -> &'static str {
            "recording"
        }

        async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
            self.events.lock().unwrap().push(event.clone());
            match self.fail {
                Failure::None => Ok(()),
                Failure::Retryable => Err(NotifyError::new("recording backend configured to fail")),
                Failure::Permanent => Err(NotifyError::permanent(
                    "recording backend configured to fail permanently",
                )),
            }
        }
    }

    fn profile_mounted(profile: &str) -> NotifyEvent {
        NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: profile.to_string(),
        })
    }

    /// One of every variant, all on the same profile — the input to the
    /// accessor sweep below, which is what the `custom` backend's environment
    /// and both templating backends' contexts are built from.
    fn every_event() -> Vec<NotifyEvent> {
        vec![
            profile_mounted("p"),
            NotifyEvent::AccountCreated(AccountCreatedData {
                profile: "p".to_string(),
                account_id: "acct-1".to_string(),
                contact: vec!["mailto:a@example.com".to_string()],
                client_ip: Some("203.0.113.5".to_string()),
            }),
            NotifyEvent::AccountDeactivated(AccountDeactivatedData {
                profile: "p".to_string(),
                account_id: "acct-1".to_string(),
                client_ip: Some("203.0.113.5".to_string()),
            }),
            NotifyEvent::CertificateIssued(CertificateIssuedData {
                profile: "p".to_string(),
                order_id: "ord-1".to_string(),
                account_id: "acct-1".to_string(),
                cert_serial: "0a0b".to_string(),
                identifiers: vec!["a.example.com".to_string(), "b.example.com".to_string()],
                client_ip: Some("203.0.113.5".to_string()),
            }),
            NotifyEvent::CertificateRevoked(CertificateRevokedData {
                profile: "p".to_string(),
                order_id: "ord-1".to_string(),
                account_id: "acct-1".to_string(),
                cert_serial: "0a0b".to_string(),
                reason: Some(1),
                client_ip: None,
            }),
            NotifyEvent::ChallengeFailed(ChallengeFailedData {
                profile: "p".to_string(),
                order_id: "ord-1".to_string(),
                account_id: "acct-1".to_string(),
                authz_id: "authz-1".to_string(),
                challenge_id: "chall-1".to_string(),
                challenge_type: "http-01".to_string(),
                identifier: "a.example.com".to_string(),
                error: "connection refused".to_string(),
                client_ip: Some("203.0.113.5".to_string()),
            }),
        ]
    }

    /// Every variant answers every accessor. These are wide `match`es over an
    /// enum that grows, so a new variant added to only some of them would
    /// otherwise surface as a silently empty template field.
    #[test]
    fn every_event_answers_every_accessor() {
        let events = every_event();
        assert_eq!(
            events.len(),
            ALL_NOTIFY_EVENTS.len(),
            "every declared event kind needs a sample here"
        );

        for event in &events {
            assert_eq!(event.profile(), "p");
            assert!(
                ALL_NOTIFY_EVENTS.contains(&event.kind()),
                "{}",
                event.kind()
            );

            // The rendering context and the `custom` backend's stdin payload
            // are built from the same data by two different routes.
            assert!(!event.context().is_undefined());
            let payload = event.payload();
            assert_eq!(
                payload.get("hook").and_then(|v| v.as_str()),
                Some(event.kind()),
                "the payload must name its own hook"
            );
            assert_eq!(payload.get("profile").and_then(|v| v.as_str()), Some("p"));
        }

        // `profile_mounted` is the one event with no account, order or client
        // behind it: it happens at startup, outside any request.
        let mounted = &events[0];
        assert_eq!(mounted.client_ip(), None);
        assert_eq!(mounted.account_id(), None);
        assert_eq!(mounted.order_id(), None);
        assert_eq!(mounted.cert_serial(), None);
        assert_eq!(mounted.identifiers_joined(), "");

        for event in &events[1..] {
            assert_eq!(event.account_id(), Some("acct-1"));
        }
        // A revocation reached through the admin CLI has no client address.
        assert_eq!(events[4].client_ip(), None);
        assert_eq!(events[1].client_ip(), Some("203.0.113.5"));

        // Order and serial only exist once there is a certificate to name.
        assert_eq!(events[1].order_id(), None);
        assert_eq!(events[2].cert_serial(), None);
        for event in &events[3..] {
            assert_eq!(event.order_id(), Some("ord-1"));
        }
        assert_eq!(events[3].cert_serial(), Some("0a0b"));
        assert_eq!(events[4].cert_serial(), Some("0a0b"));
        assert_eq!(events[5].cert_serial(), None);

        // Only issuance carries the names the certificate is for.
        assert_eq!(
            events[3].identifiers_joined(),
            "a.example.com,b.example.com"
        );
        assert_eq!(events[5].identifiers_joined(), "");
    }

    /// `dyn NotifyBackend` is not `Debug`, so the dispatcher renders the slot
    /// ids instead — the part a startup log is read for, and now also the part a
    /// queued job addresses.
    #[tokio::test]
    async fn the_dispatcher_debug_names_its_backends() {
        let queue = test_queue().await;
        let dispatcher = NotifyDispatcher::new(
            "le",
            vec![BackendSlot::new(
                "recording",
                Arc::new(RecordingNotifyBackend::default()),
                &every_kind(),
            )],
            queue.clone(),
        );
        let rendered = format!("{dispatcher:?}");
        assert!(rendered.contains("NotifyDispatcher"), "{rendered}");
        assert!(rendered.contains("recording"), "{rendered}");
        assert!(rendered.contains("le"), "{rendered}");

        assert!(format!("{:?}", NotifyDispatcher::disabled(queue)).contains("[]"));
    }

    /// The reload property: a reader that took its handle before the swap sees
    /// the map that came *after* it.
    ///
    /// This is what a signer backend and [`NotifyJob`] rely on — both are built
    /// once and outlive a configuration generation, so a captured `Arc` would
    /// pin them to whatever was configured when the process started.
    #[tokio::test]
    async fn a_handle_taken_before_a_swap_reads_the_map_after_it() {
        let queue = test_queue().await;
        let (sender, notifiers) = notifiers_channel(HashMap::new());
        assert!(notifiers.get("le").is_none());

        let mut next = HashMap::new();
        next.insert(
            "le".to_string(),
            Arc::new(NotifyDispatcher::disabled(queue.clone())),
        );
        sender.send_replace(Arc::new(next));

        assert!(notifiers.get("le").is_some());
        // A profile the new generation does not mount is absent, not stale.
        assert!(notifiers.get("staging").is_none());

        // And a swap back is seen too: this is a cell, not a latch.
        sender.send_replace(Arc::new(HashMap::new()));
        assert!(notifiers.get("le").is_none());
    }

    /// A fixed map keeps answering after its sender is gone.
    ///
    /// The `From` impl drops the sender on the spot, which is what lets every
    /// caller with no reload to serve — the tests, and anything built before the
    /// first generation is published — pass a plain map. If a closed channel
    /// made `borrow` fail, that conversion would be a trap rather than a
    /// convenience.
    #[tokio::test]
    async fn a_fixed_map_survives_its_sender_being_dropped() {
        let queue = test_queue().await;
        let mut map = HashMap::new();
        map.insert(
            "le".to_string(),
            Arc::new(NotifyDispatcher::disabled(queue)),
        );

        let notifiers: Notifiers = map.into();
        assert!(notifiers.get("le").is_some());
        // Cloned handles are the same cell, and equally durable.
        assert!(notifiers.clone().get("le").is_some());
    }

    /// Every event kind, as a backend's own `events` list would spell them.
    fn every_kind() -> Vec<String> {
        ALL_NOTIFY_EVENTS.iter().map(|k| (*k).to_string()).collect()
    }

    /// A dispatcher over one recording backend, plus the queue its rows land in.
    async fn recording_dispatcher(
        events: &[String],
    ) -> (Arc<NotifyDispatcher>, Arc<RecordingNotifyBackend>, JobQueue) {
        let queue = test_queue().await;
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let dispatcher = Arc::new(NotifyDispatcher::new(
            "le",
            vec![BackendSlot::new("recording", recorder.clone(), events)],
            queue.clone(),
        ));
        (dispatcher, recorder, queue)
    }

    /// The property the whole change turns on: `dispatch` delivers nothing
    /// itself, it writes a row. Nothing has reached the backend when it returns.
    #[tokio::test]
    async fn dispatch_queues_a_row_rather_than_delivering() {
        let (dispatcher, recorder, queue) = recording_dispatcher(&every_kind()).await;

        dispatcher.dispatch(profile_mounted("le")).await;

        assert!(
            recorder.events.lock().unwrap().is_empty(),
            "dispatch must not deliver inline"
        );
        let queued = Job::count_live(NOTIFY_JOB_KIND, queue.database())
            .await
            .unwrap();
        assert_eq!(queued, 1, "one backend, one row");
    }

    /// The `events` list is applied at *enqueue*, so a backend that does not
    /// want an event costs no row at all — not a row that runs and no-ops.
    #[tokio::test]
    async fn a_backend_that_does_not_want_the_event_gets_no_row() {
        let (dispatcher, _recorder, queue) =
            recording_dispatcher(&["certificate_issued".to_string()]).await;

        dispatcher.dispatch(profile_mounted("le")).await;

        assert_eq!(
            Job::count_live(NOTIFY_JOB_KIND, queue.database())
                .await
                .unwrap(),
            0
        );
    }

    /// One row **per backend**, so a retry against a failing one never re-sends
    /// through a healthy one that already delivered.
    #[tokio::test]
    async fn one_dispatch_queues_one_row_per_wanting_backend() {
        let queue = test_queue().await;
        let dispatcher = NotifyDispatcher::new(
            "le",
            vec![
                BackendSlot::new(
                    "email",
                    Arc::new(RecordingNotifyBackend::default()),
                    &every_kind(),
                ),
                BackendSlot::new(
                    "custom:webhook",
                    Arc::new(RecordingNotifyBackend::default()),
                    &every_kind(),
                ),
                BackendSlot::new(
                    "custom:pager",
                    Arc::new(RecordingNotifyBackend::default()),
                    &["certificate_revoked".to_string()],
                ),
            ],
            queue.clone(),
        );

        dispatcher.dispatch(profile_mounted("le")).await;

        assert_eq!(
            Job::count_live(NOTIFY_JOB_KIND, queue.database())
                .await
                .unwrap(),
            2,
            "the third backend does not want this kind"
        );
    }

    /// Two dispatches of the same event are two notifications, as they always
    /// were: the per-call `delivery_id` keeps the identity index from mistaking
    /// the second for a duplicate of the first.
    #[tokio::test]
    async fn the_same_event_dispatched_twice_queues_twice() {
        let (dispatcher, _recorder, queue) = recording_dispatcher(&every_kind()).await;

        dispatcher.dispatch(profile_mounted("le")).await;
        dispatcher.dispatch(profile_mounted("le")).await;

        assert_eq!(
            Job::count_live(NOTIFY_JOB_KIND, queue.database())
                .await
                .unwrap(),
            2
        );
    }

    /// A dispatcher with nothing configured writes nothing at all — the queue is
    /// not a place to park work no backend will ever ask for.
    #[tokio::test]
    async fn a_disabled_dispatcher_queues_nothing() {
        let queue = test_queue().await;
        let dispatcher = NotifyDispatcher::disabled(queue.clone());

        dispatcher.dispatch(profile_mounted("le")).await;

        assert_eq!(
            Job::count_live(NOTIFY_JOB_KIND, queue.database())
                .await
                .unwrap(),
            0
        );
    }

    /// A database that cannot take the row must not become a failed ACME
    /// request: `dispatch` returns `()` and there is nowhere to put the error.
    #[tokio::test]
    async fn a_database_failure_is_swallowed_by_dispatch() {
        let (dispatcher, _recorder, queue) = recording_dispatcher(&every_kind()).await;
        queue.database().pool.close().await;

        dispatcher.dispatch(profile_mounted("le")).await;
    }

    /// `deliver` is the seam the job handler runs through, and the answer for an
    /// id nobody has is `None` rather than an error — the handler has to tell
    /// "this backend refused" from "this backend is gone".
    #[tokio::test]
    async fn deliver_reaches_one_backend_and_reports_an_unknown_id() {
        let (dispatcher, recorder, _queue) = recording_dispatcher(&every_kind()).await;

        let outcome = dispatcher
            .deliver("recording", &profile_mounted("le"))
            .await;
        assert!(matches!(outcome, Some(Ok(()))));
        assert_eq!(recorder.events.lock().unwrap().len(), 1);

        assert!(
            dispatcher
                .deliver("carrier-pigeon", &profile_mounted("le"))
                .await
                .is_none()
        );
        assert_eq!(
            recorder.events.lock().unwrap().len(),
            1,
            "an unknown id must reach no backend at all"
        );
    }

    /// The selector's own arms: each name reaches its constructor and lands in
    /// the dispatcher. Neither backend touches the network at build time —
    /// `lettre` only assembles a transport and `webhook` only parses a URL and
    /// compiles a template — so this is a pure configuration test.
    #[tokio::test]
    async fn each_backend_name_builds_its_own_backend() {
        let cfg = NotifyConfig {
            enabled: vec!["email".to_string(), "webhook".to_string()],
            email: crate::config::EmailNotifyConfig {
                smtp_host: "smtp.example.com".to_string(),
                from: "acme@example.com".to_string(),
                to: vec!["ops@example.com".to_string()],
                // Every `smtp_security` value builds a different transport.
                smtp_security: "none".to_string(),
                smtp_username: "user".to_string(),
                smtp_password: "pass".to_string(),
                ..crate::config::EmailNotifyConfig::default()
            },
            webhook_enabled: vec!["chat".to_string()],
            webhook: BTreeMap::from([("chat".to_string(), webhook_entry())]),
            ..NotifyConfig::default()
        };

        let dispatcher = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .expect("both backends must build");
        let rendered = format!("{dispatcher:?}");
        assert!(rendered.contains("email"), "{rendered}");
        assert!(rendered.contains("webhook:chat"), "{rendered}");
    }

    fn webhook_entry() -> crate::config::WebhookNotifyConfig {
        crate::config::WebhookNotifyConfig {
            url: "https://chat.example.com/hooks/abc".to_string(),
            ..crate::config::WebhookNotifyConfig::default()
        }
    }

    /// Two webhook entries are two slots with distinct ids — the `custom`
    /// property this backend inherits and needs for the same reason: every
    /// entry answers `"webhook"` to `NotifyBackend::name`, so a job row naming
    /// that alone could not say which endpoint it meant, and a retry would
    /// re-send through the one that already succeeded.
    #[tokio::test]
    async fn two_webhook_entries_get_distinct_slot_ids() {
        let cfg = NotifyConfig {
            enabled: vec!["webhook".to_string()],
            webhook_enabled: vec!["slack".to_string(), "teams".to_string()],
            webhook: BTreeMap::from([
                ("slack".to_string(), webhook_entry()),
                ("teams".to_string(), webhook_entry()),
            ]),
            ..NotifyConfig::default()
        };

        let dispatcher = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .expect("both entries must build");

        assert!(dispatcher.slot("webhook:slack").is_some());
        assert!(dispatcher.slot("webhook:teams").is_some());
        assert!(dispatcher.slot("webhook").is_none());
    }

    /// The `mattermost` backend is gone and is refused **by name**, so an
    /// unmigrated configuration stops the server rather than coming up looking
    /// configured and notifying nobody.
    #[tokio::test]
    async fn the_removed_mattermost_backend_is_refused_by_name() {
        let cfg = NotifyConfig {
            enabled: vec!["mattermost".to_string()],
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("mattermost"), "{error}");
        assert!(error.contains("webhook"), "{error}");
    }

    /// The two other `smtp_security` values, which each pick a different
    /// `lettre` builder, plus the one that is not a value at all.
    #[tokio::test]
    async fn every_smtp_security_mode_is_recognised() {
        for mode in ["starttls", "tls", "none"] {
            let cfg = email_config(mode);
            from_config(
                "le",
                &cfg,
                test_resolver(),
                crate::testutil::no_proxies(),
                &test_queue().await,
            )
            .unwrap_or_else(|error| panic!("`{mode}` must build: {error}"));
        }

        let error = from_config(
            "le",
            &email_config("carrier-pigeon"),
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("smtp_security"), "{error}");
    }

    fn email_config(smtp_security: &str) -> NotifyConfig {
        NotifyConfig {
            enabled: vec!["email".to_string()],
            email: crate::config::EmailNotifyConfig {
                smtp_host: "smtp.example.com".to_string(),
                from: "acme@example.com".to_string(),
                to: vec!["ops@example.com".to_string()],
                smtp_security: smtp_security.to_string(),
                ..crate::config::EmailNotifyConfig::default()
            },
            ..NotifyConfig::default()
        }
    }

    /// An event name nobody recognises is caught per backend, before the
    /// backend itself is built — otherwise a typo would silently mean "never
    /// notify" for that channel.
    #[tokio::test]
    async fn an_unknown_event_name_is_caught_on_each_backend() {
        let mut email = email_config("none");
        email.email.events = vec!["certificate_exploded".to_string()];
        let error = from_config(
            "le",
            &email,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("notify.email.events"), "{error}");

        let webhook = NotifyConfig {
            enabled: vec!["webhook".to_string()],
            webhook_enabled: vec!["chat".to_string()],
            webhook: BTreeMap::from([(
                "chat".to_string(),
                crate::config::WebhookNotifyConfig {
                    events: vec!["certificate_exploded".to_string()],
                    ..webhook_entry()
                },
            )]),
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &webhook,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("notify.webhook.chat.events"), "{error}");
    }

    /// `notify.custom_enabled` names entries in `notify.custom`; a name with no
    /// entry behind it is a startup error rather than a silently missing hook.
    #[tokio::test]
    async fn a_custom_name_with_no_entry_is_a_startup_error() {
        let cfg = NotifyConfig {
            enabled: vec!["custom".to_string()],
            custom_enabled: vec!["webhook".to_string()],
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("notify.custom_enabled names `webhook`"),
            "{error}"
        );
    }

    /// A `notify.custom` key that is not a valid environment-variable segment
    /// could name a different entry through `ACME_PROXY_…` than in the file.
    #[tokio::test]
    async fn an_invalid_custom_key_name_is_a_startup_error() {
        let mut custom = std::collections::BTreeMap::new();
        custom.insert("Web Hook".to_string(), CustomNotifyConfig::default());
        let cfg = NotifyConfig {
            enabled: vec!["custom".to_string()],
            custom_enabled: vec!["Web Hook".to_string()],
            custom,
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid name"), "{error}");
    }

    #[tokio::test]
    async fn unknown_backend_name_is_a_startup_error() {
        let cfg = NotifyConfig {
            enabled: vec!["carrier-pigeon".to_string()],
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown notify backend"), "{error}");
    }

    #[tokio::test]
    async fn custom_enabled_empty_is_a_startup_error() {
        let cfg = NotifyConfig {
            enabled: vec!["custom".to_string()],
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("notify.custom_enabled is empty"), "{error}");
    }

    #[tokio::test]
    async fn an_unknown_event_name_is_a_startup_error() {
        let cfg = NotifyConfig {
            enabled: vec!["email".to_string()],
            email: crate::config::EmailNotifyConfig {
                smtp_host: "localhost".to_string(),
                events: vec!["orders_shipped".to_string()],
                ..crate::config::EmailNotifyConfig::default()
            },
            ..NotifyConfig::default()
        };
        let error = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown event"), "{error}");
    }

    /// The `events` list decides membership of the *queue*, not of the delivery:
    /// a backend outside the list never gets a row, so `wants` is asserted on
    /// both sides rather than on what arrived at a backend afterwards.
    #[tokio::test]
    async fn a_backend_only_accepts_events_it_is_configured_for() {
        let wide = BackendSlot::new(
            "wide",
            Arc::new(RecordingNotifyBackend::default()),
            &every_kind(),
        );
        let narrow = BackendSlot::new(
            "narrow",
            Arc::new(RecordingNotifyBackend::default()),
            &["certificate_issued".to_string()],
        );

        assert!(wide.wants(&profile_mounted("default")));
        assert!(!narrow.wants(&profile_mounted("default")));

        let queue = test_queue().await;
        let dispatcher = NotifyDispatcher::new("le", vec![wide, narrow], queue.clone());
        dispatcher.dispatch(profile_mounted("default")).await;

        assert_eq!(
            Job::count_live(NOTIFY_JOB_KIND, queue.database())
                .await
                .unwrap(),
            1,
            "only the wide backend is queued for"
        );
    }

    /// One backend's failure is another's business, and the queue is what keeps
    /// them apart now: two rows, settled independently, so the healthy one is
    /// `done` while the failing one is still being retried.
    #[tokio::test]
    async fn a_failing_backend_does_not_stop_another_from_receiving_the_event() {
        let failing = Arc::new(RecordingNotifyBackend::failing());
        let healthy = Arc::new(RecordingNotifyBackend::default());
        let queue = test_queue().await;
        let dispatcher = NotifyDispatcher::new(
            "le",
            vec![
                BackendSlot::new("failing", failing.clone(), &every_kind()),
                BackendSlot::new("healthy", healthy.clone(), &every_kind()),
            ],
            queue,
        );

        assert!(matches!(
            dispatcher
                .deliver("failing", &profile_mounted("default"))
                .await,
            Some(Err(_))
        ));
        assert!(matches!(
            dispatcher
                .deliver("healthy", &profile_mounted("default"))
                .await,
            Some(Ok(()))
        ));

        assert_eq!(failing.events.lock().unwrap().len(), 1);
        assert_eq!(healthy.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn build_registry_builds_one_dispatcher_per_profile() {
        let profiles = vec![
            ProfileConfig {
                name: "a".to_string(),
                sections: crate::config::ProfileSections::default(),
            },
            ProfileConfig {
                name: "b".to_string(),
                sections: crate::config::ProfileSections::default(),
            },
        ];
        let registry = build_registry(
            &profiles,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .unwrap();
        assert_eq!(registry.len(), 2);
        assert_eq!(registry["a"].profile(), "a");
        assert_eq!(registry["b"].profile(), "b");
    }

    /// Two `custom` entries are two backends, and a job row has to be able to
    /// say which one it means. `NotifyBackend::name` answers `"custom"` for
    /// both, so the slot id is built from the configuration key instead.
    #[tokio::test]
    async fn two_custom_entries_get_distinct_slot_ids() {
        let dir = crate::testutil::TempDir::new("notify-slot");
        let script = crate::testutil::write_script(&dir, "notify.sh", "#!/bin/sh\nexit 0\n");
        let entry = || CustomNotifyConfig {
            script_path: script.display().to_string(),
            ..CustomNotifyConfig::default()
        };
        let mut custom = std::collections::BTreeMap::new();
        custom.insert("webhook".to_string(), entry());
        custom.insert("pager".to_string(), entry());

        let cfg = NotifyConfig {
            enabled: vec!["custom".to_string()],
            custom_enabled: vec!["webhook".to_string(), "pager".to_string()],
            custom,
            ..NotifyConfig::default()
        };

        let dispatcher = from_config(
            "le",
            &cfg,
            test_resolver(),
            crate::testutil::no_proxies(),
            &test_queue().await,
        )
        .expect("both custom entries must build");

        assert!(dispatcher.slot("custom:webhook").is_some());
        assert!(dispatcher.slot("custom:pager").is_some());
        assert!(dispatcher.slot("custom").is_none());
    }

    /// The durable payload has to survive a restart, so every variant must come
    /// back out of JSON as the variant that went in. A wide `match` over an enum
    /// that grows is exactly where a new variant gets forgotten.
    #[test]
    fn every_event_round_trips_through_its_payload() {
        for event in every_event() {
            let encoded = event.payload();
            let decoded: NotifyEvent = serde_json::from_value(encoded.clone())
                .unwrap_or_else(|error| panic!("{} must decode: {error}", event.kind()));
            assert_eq!(decoded.kind(), event.kind());
            assert_eq!(decoded.profile(), event.profile());
            assert_eq!(decoded.payload(), encoded, "re-encoding must be stable");
        }
    }

    /// The `custom` backend's stdin contract: the tag is a `"hook"` member
    /// carrying the event kind, sitting flat beside the event's own fields. That
    /// used to be spliced in by hand and is now serde's internal tag — a script
    /// in the field must not be able to tell the difference.
    #[test]
    fn payload_is_tagged_with_its_own_hook() {
        let event = NotifyEvent::CertificateIssued(CertificateIssuedData {
            profile: "le".to_string(),
            order_id: "ord-1".to_string(),
            account_id: "acct-1".to_string(),
            cert_serial: "0a0b".to_string(),
            identifiers: vec!["a.example.com".to_string()],
            client_ip: Some("203.0.113.5".to_string()),
        });

        assert_eq!(
            event.payload(),
            serde_json::json!({
                "hook": "certificate_issued",
                "profile": "le",
                "order_id": "ord-1",
                "account_id": "acct-1",
                "cert_serial": "0a0b",
                "identifiers": ["a.example.com"],
                "client_ip": "203.0.113.5",
            })
        );
    }

    #[test]
    fn template_dir_override_wins_over_the_embedded_default() {
        let dir = crate::testutil::TempDir::new("notify");
        std::fs::create_dir_all(dir.join("email")).unwrap();
        std::fs::write(
            dir.join("email/profile_mounted.subject.j2"),
            "override: {{ profile }}",
        )
        .unwrap();

        let env = build_environment(dir.path().to_str().unwrap());
        let rendered = render(
            &env,
            "email/profile_mounted.subject.j2",
            &profile_mounted("default"),
        )
        .unwrap();
        assert_eq!(rendered, "override: default");

        // A template not present in `template_dir` still falls back to the
        // compiled-in default rather than failing outright.
        let rendered = render(
            &env,
            "email/profile_mounted.body.j2",
            &profile_mounted("default"),
        )
        .unwrap();
        assert!(rendered.contains("default"));
    }

    /// A template that is not there will not be there next time either, so the
    /// failure must not spend a retry budget getting to the same answer.
    #[test]
    fn a_template_failure_is_permanent() {
        let env = build_environment("");

        let missing = render(&env, "email/no_such_event.body.j2", &profile_mounted("le"))
            .expect_err("there is no such template");
        assert!(!missing.retryable(), "{missing}");

        let dir = crate::testutil::TempDir::new("notify-broken");
        std::fs::create_dir_all(dir.join("email")).unwrap();
        std::fs::write(dir.join("email/profile_mounted.body.j2"), "{{ unclosed").unwrap();
        let env = build_environment(dir.path().to_str().unwrap());
        let broken = render(
            &env,
            "email/profile_mounted.body.j2",
            &profile_mounted("le"),
        )
        .expect_err("the template does not compile");
        assert!(!broken.retryable(), "{broken}");
    }

    #[test]
    fn embedded_defaults_render_with_no_template_dir() {
        let env = build_environment("");
        let event = NotifyEvent::CertificateIssued(CertificateIssuedData {
            profile: "le".to_string(),
            order_id: "ord-1".to_string(),
            account_id: "acc-1".to_string(),
            cert_serial: "AA:BB".to_string(),
            identifiers: vec!["example.com".to_string()],
            client_ip: Some("203.0.113.1".to_string()),
        });

        let subject = render(&env, "email/certificate_issued.subject.j2", &event).unwrap();
        assert!(subject.contains("le"), "{subject}");

        let body = render(&env, "email/certificate_issued.body.j2", &event).unwrap();
        assert!(body.contains("example.com"), "{body}");
        assert!(body.contains("203.0.113.1"), "{body}");
    }
}
