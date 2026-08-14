//! Operator notifications for ACME lifecycle events.
//!
//! The shape mirrors [`filter`](crate::filter)/[`signer`](crate::signer): a
//! trait, an error type, and a [`from_config`] selector building the
//! configured set at startup. Three backends exist today —
//! [`email`], [`mattermost`], and [`custom`] (an external script/webhook,
//! for any channel this server has no built-in support for).
//!
//! ## Fire-and-forget, always
//!
//! A notification can never affect the ACME response that triggered it.
//! [`NotifyDispatcher::dispatch`] is not `async`, returns `()`, and cannot be
//! `?`'d — it spawns the actual delivery and returns immediately. Every
//! backend failure (a refused SMTP connection, a non-2xx webhook, a
//! nonzero/timed-out script) is logged and dropped, never retried and never
//! propagated to the caller. A panicking backend is caught the same way. This
//! is a deliberate API shape, not a convention callers must remember: there is
//! no method on this type whose result a handler *could* propagate.
//!
//! ## Per-backend event filtering
//!
//! Unlike [`FilterConfig::rules`](crate::config::FilterConfig), where every
//! filter must agree, notify backends are independent broadcast side-channels
//! — an operator plausibly wants email only for issuance/revocation and
//! Mattermost for everything including failures. Each backend's own `events`
//! list (defaulting to all six kinds) decides what reaches it; [`from_config`]
//! wraps every configured backend in a [`FilteredBackend`] so this logic lives
//! in one place rather than in each backend's own delivery code.
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
use tracing::{info, warn};

use crate::config::{ALL_NOTIFY_EVENTS, NotifyConfig, ProfileConfig};

pub mod custom;
pub mod email;
pub mod mattermost;

/// A pluggable notification channel.
#[async_trait]
pub trait NotifyBackend: Send + Sync {
    /// The configuration name this backend runs under, used in logs.
    fn name(&self) -> &'static str;

    /// Delivers `event`. Failure is always non-fatal to the caller — see the
    /// module docs — logged by [`NotifyDispatcher`] and never retried.
    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError>;
}

/// Why a notify backend failed to deliver.
#[derive(Debug)]
pub struct NotifyError(String);

impl NotifyError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileMountedData {
    pub profile: String,
}

/// Payload of [`NotifyEvent::AccountCreated`]: a client registered a new
/// account at this endpoint.
///
/// `contact` is what the client supplied, which may legitimately be empty —
/// RFC 8555 does not require one.
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone)]
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
    /// `custom` backend's stdin payload. Not used by the templating backends,
    /// which render from [`Self::context`] instead.
    pub(crate) fn payload(&self) -> serde_json::Value {
        let mut value = match self {
            Self::ProfileMounted(data) => serde_json::to_value(data),
            Self::AccountCreated(data) => serde_json::to_value(data),
            Self::AccountDeactivated(data) => serde_json::to_value(data),
            Self::CertificateIssued(data) => serde_json::to_value(data),
            Self::CertificateRevoked(data) => serde_json::to_value(data),
            Self::ChallengeFailed(data) => serde_json::to_value(data),
        }
        .expect("notify event data always serializes to a JSON object");
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                "hook".to_string(),
                serde_json::Value::String(self.kind().to_string()),
            );
        }
        value
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

/// The configured notify backends for one profile.
///
/// Cheap to clone behind the `Arc` it is always held in (`Profile::notify`,
/// and the `profile name -> dispatcher` map handed to the `relay` signer
/// backend).
#[derive(Default)]
pub struct NotifyDispatcher {
    backends: Vec<Arc<dyn NotifyBackend>>,
    /// In-flight `dispatch` tasks, so shutdown can wait for them.
    ///
    /// A `std::sync::Mutex` and not a `tokio` one on purpose: it is only ever
    /// held for a `spawn` or a `try_join_next`, never across an await, and
    /// `dispatch` has to stay callable from a `&Arc<Self>` in a sync context.
    tasks: std::sync::Mutex<tokio::task::JoinSet<()>>,
}

impl std::fmt::Debug for NotifyDispatcher {
    /// `dyn NotifyBackend` is not `Debug`, so show the names — the only part
    /// worth reading anyway. Mirrors `FilterPolicy`'s own `Debug` impl.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotifyDispatcher")
            .field(
                "backends",
                &self.backends.iter().map(|b| b.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl NotifyDispatcher {
    pub fn new(backends: Vec<Arc<dyn NotifyBackend>>) -> Self {
        Self {
            backends,
            tasks: std::sync::Mutex::new(tokio::task::JoinSet::new()),
        }
    }

    /// Fire-and-forget: spawns delivery and returns immediately. Never `?`'d
    /// or awaited for its result anywhere in this codebase — see the module
    /// docs for why that is the point, not an oversight.
    pub fn dispatch(self: &Arc<Self>, event: NotifyEvent) {
        let this = self.clone();
        let Ok(mut tasks) = self.tasks.lock() else {
            // A poisoned lock means a previous dispatch panicked while holding
            // it. Losing the ability to notify is not a reason to stop
            // notifying, so fall back to a detached spawn.
            tokio::spawn(async move { this.dispatch_now(event).await });
            return;
        };
        // Reap what has already finished, so the set does not grow without
        // bound over a long-running process.
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move { this.dispatch_now(event).await });
    }

    /// Waits for in-flight deliveries, up to `budget`.
    ///
    /// `dispatch` is fire-and-forget by design, and `axum::serve`'s graceful
    /// shutdown drains HTTP requests but knows nothing about these tasks — so a
    /// `certificate_issued` notification for a request that completed during
    /// shutdown was simply lost: the client got its certificate and the
    /// operator never heard about it. Bounded, because a wedged webhook must
    /// not hold the process open indefinitely.
    pub async fn drain(&self, budget: std::time::Duration) {
        let mut set = match self.tasks.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => return,
        };
        if set.is_empty() {
            return;
        }

        let pending = set.len();
        info!(
            event = "notify_drain_started",
            outcome = "progress",
            pending
        );
        let drained =
            tokio::time::timeout(budget, async { while set.join_next().await.is_some() {} }).await;
        if drained.is_err() {
            warn!(
                event = "notify_drain_timed_out",
                outcome = "failure",
                pending,
                budget_ms = crate::millis(budget),
            );
        }
    }

    /// The actual fan-out, directly awaitable. `dispatch` always goes through
    /// this; tests that want deterministic (non-spawned) delivery may call it
    /// directly instead.
    pub(crate) async fn dispatch_now(&self, event: NotifyEvent) {
        let kind = event.kind();
        let mut set = tokio::task::JoinSet::new();
        for backend in &self.backends {
            let backend = backend.clone();
            let event = event.clone();
            set.spawn(async move { (backend.name(), backend.send(&event).await) });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((name, Ok(()))) => {
                    info!(
                        event = "notify_delivered",
                        outcome = "success",
                        backend = name,
                        kind
                    );
                }
                Ok((name, Err(error))) => {
                    warn!(event = "notify_delivery_failed", outcome = "failure", backend = name, kind, error = %error);
                }
                Err(join_error) => {
                    warn!(event = "notify_task_panicked", outcome = "failure", kind, error = %join_error);
                }
            }
        }
    }
}

/// Wraps a backend so it only sees the events its own `events` list names.
/// Built once in [`from_config`], keeping this filtering logic out of every
/// backend's own delivery code.
struct FilteredBackend {
    inner: Arc<dyn NotifyBackend>,
    events: HashSet<String>,
}

#[async_trait]
impl NotifyBackend for FilteredBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        if self.events.contains(event.kind()) {
            self.inner.send(event).await
        } else {
            Ok(())
        }
    }
}

fn filtered(inner: Arc<dyn NotifyBackend>, events: &[String]) -> Arc<dyn NotifyBackend> {
    Arc::new(FilteredBackend {
        inner,
        events: events.iter().cloned().collect(),
    })
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
pub fn from_config(
    cfg: &NotifyConfig,
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
) -> anyhow::Result<Arc<NotifyDispatcher>> {
    // Built once and shared: both templating backends render from the same
    // `template_dir` override, and `Environment` is cheap to clone (it holds
    // an `Arc`-like handle to its loader internally) but not to construct.
    let env = Arc::new(build_environment(&cfg.template_dir));

    let mut backends: Vec<Arc<dyn NotifyBackend>> = Vec::with_capacity(cfg.enabled.len());
    for name in &cfg.enabled {
        let built: Vec<Arc<dyn NotifyBackend>> = match name.as_str() {
            "email" => {
                validate_events("notify.email.events", &cfg.email.events)?;
                vec![filtered(
                    Arc::new(email::EmailNotifier::from_config(&cfg.email, env.clone())?),
                    &cfg.email.events,
                )]
            }
            "mattermost" => {
                validate_events("notify.mattermost.events", &cfg.mattermost.events)?;
                vec![filtered(
                    Arc::new(mattermost::MattermostNotifier::from_config(
                        &cfg.mattermost,
                        env.clone(),
                        resolver.clone(),
                        proxies.clone(),
                    )?),
                    &cfg.mattermost.events,
                )]
            }
            "custom" => build_custom_backends(cfg)?,
            other => anyhow::bail!("unknown notify backend: {other}"),
        };
        backends.extend(built);
    }

    if backends.is_empty() {
        info!(
            event = "notify_disabled",
            outcome = "success",
            "no notification backends configured"
        );
    } else {
        info!(event = "notify_enabled", outcome = "success", backends = ?cfg.enabled);
    }

    Ok(Arc::new(NotifyDispatcher::new(backends)))
}

fn build_custom_backends(cfg: &NotifyConfig) -> anyhow::Result<Vec<Arc<dyn NotifyBackend>>> {
    crate::config::resolve_custom_entries("notify", &cfg.custom, &cfg.custom_enabled)?
        .into_iter()
        .map(|(name, script)| -> anyhow::Result<Arc<dyn NotifyBackend>> {
            validate_events(&format!("notify.custom.{name}.events"), &script.events)?;
            let backend = custom::CustomScriptNotifier::from_config(script)?;
            Ok(filtered(Arc::new(backend), &script.events))
        })
        .collect()
}

/// Builds one [`NotifyDispatcher`] per resolved profile, keyed by profile
/// name — the map the `relay` signer backend needs to notify the right
/// profile from its background completion task, where there is no
/// `AppState`/`Profile` to reach through.
pub fn build_registry(
    profiles: &[ProfileConfig],
    resolver: Arc<dyn crate::dns::Resolver>,
    proxies: Arc<crate::proxy::OutboundProxies>,
) -> anyhow::Result<HashMap<String, Arc<NotifyDispatcher>>> {
    let mut registry = HashMap::with_capacity(profiles.len());
    for profile in profiles {
        let dispatcher = from_config(&profile.sections.notify, resolver.clone(), proxies.clone())
            .map_err(|error| anyhow::anyhow!("profile `{}`: {error}", profile.name))?;
        registry.insert(profile.name.clone(), dispatcher);
    }
    Ok(registry)
}

/// Every default template, embedded so the server needs no external
/// `templates/` directory to run. Keyed the same way [`build_environment`]'s
/// loader looks them up: `"<backend>/<event>.<subject|body>.j2"` for email,
/// `"<backend>/<event>.j2"` for Mattermost.
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
            "mattermost/profile_mounted.j2",
            include_str!("templates/mattermost/profile_mounted.j2"),
        ),
        (
            "mattermost/account_created.j2",
            include_str!("templates/mattermost/account_created.j2"),
        ),
        (
            "mattermost/account_deactivated.j2",
            include_str!("templates/mattermost/account_deactivated.j2"),
        ),
        (
            "mattermost/certificate_issued.j2",
            include_str!("templates/mattermost/certificate_issued.j2"),
        ),
        (
            "mattermost/certificate_revoked.j2",
            include_str!("templates/mattermost/certificate_revoked.j2"),
        ),
        (
            "mattermost/challenge_failed.j2",
            include_str!("templates/mattermost/challenge_failed.j2"),
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
pub(crate) fn render(
    env: &minijinja::Environment<'static>,
    template_name: &str,
    event: &NotifyEvent,
) -> Result<String, NotifyError> {
    let template = env.get_template(template_name).map_err(|error| {
        NotifyError::new(format!("template `{template_name}` not found: {error}"))
    })?;
    template
        .render(event.context())
        .map_err(|error| NotifyError::new(format!("template `{template_name}` failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CustomNotifyConfig;
    use std::sync::Mutex;

    /// The shared resolver `Profile::build_all` supplies at startup.
    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
    }

    /// A backend recording every event it received, for asserting dispatch
    /// behavior without a real SMTP/HTTP/script target.
    #[derive(Default)]
    pub(crate) struct RecordingNotifyBackend {
        pub(crate) events: Mutex<Vec<NotifyEvent>>,
        fail: bool,
    }

    impl RecordingNotifyBackend {
        pub(crate) fn failing() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                fail: true,
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
            if self.fail {
                Err(NotifyError::new("recording backend configured to fail"))
            } else {
                Ok(())
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

    /// `dyn NotifyBackend` is not `Debug`, so the dispatcher renders the names
    /// instead — the part a startup log is read for.
    #[test]
    fn the_dispatcher_debug_names_its_backends() {
        let dispatcher = NotifyDispatcher::new(vec![Arc::new(RecordingNotifyBackend::default())]);
        let rendered = format!("{dispatcher:?}");
        assert!(rendered.contains("NotifyDispatcher"), "{rendered}");
        assert!(rendered.contains("recording"), "{rendered}");

        assert!(format!("{:?}", NotifyDispatcher::default()).contains("[]"));
    }

    /// The selector's own arms: each name reaches its constructor and lands in
    /// the dispatcher. Neither backend touches the network at build time —
    /// `lettre` only assembles a transport and `mattermost` only parses a URL —
    /// so this is a pure configuration test.
    #[tokio::test]
    async fn each_backend_name_builds_its_own_backend() {
        let cfg = NotifyConfig {
            enabled: vec!["email".to_string(), "mattermost".to_string()],
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
            mattermost: crate::config::MattermostNotifyConfig {
                webhook_url: "https://chat.example.com/hooks/abc".to_string(),
                ..crate::config::MattermostNotifyConfig::default()
            },
            ..NotifyConfig::default()
        };

        let dispatcher = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
            .expect("both backends must build");
        let rendered = format!("{dispatcher:?}");
        assert!(rendered.contains("email"), "{rendered}");
        assert!(rendered.contains("mattermost"), "{rendered}");
    }

    /// The two other `smtp_security` values, which each pick a different
    /// `lettre` builder, plus the one that is not a value at all.
    #[tokio::test]
    async fn every_smtp_security_mode_is_recognised() {
        for mode in ["starttls", "tls", "none"] {
            let cfg = email_config(mode);
            from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
                .unwrap_or_else(|error| panic!("`{mode}` must build: {error}"));
        }

        let error = from_config(
            &email_config("carrier-pigeon"),
            test_resolver(),
            crate::testutil::no_proxies(),
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
        let error = from_config(&email, test_resolver(), crate::testutil::no_proxies())
            .unwrap_err()
            .to_string();
        assert!(error.contains("notify.email.events"), "{error}");

        let mattermost = NotifyConfig {
            enabled: vec!["mattermost".to_string()],
            mattermost: crate::config::MattermostNotifyConfig {
                webhook_url: "https://chat.example.com/hooks/abc".to_string(),
                events: vec!["certificate_exploded".to_string()],
                ..crate::config::MattermostNotifyConfig::default()
            },
            ..NotifyConfig::default()
        };
        let error = from_config(&mattermost, test_resolver(), crate::testutil::no_proxies())
            .unwrap_err()
            .to_string();
        assert!(error.contains("notify.mattermost.events"), "{error}");
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
        let error = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
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
        let error = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
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
        let error = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
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
        let error = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
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
        let error = from_config(&cfg, test_resolver(), crate::testutil::no_proxies())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown event"), "{error}");
    }

    #[tokio::test]
    async fn a_backend_only_receives_events_it_is_configured_for() {
        let wide = Arc::new(RecordingNotifyBackend::default());
        let narrow = Arc::new(RecordingNotifyBackend::default());
        let dispatcher = NotifyDispatcher::new(vec![
            filtered(wide.clone(), &ALL_NOTIFY_EVENTS.map(str::to_string)),
            filtered(narrow.clone(), &["certificate_issued".to_string()]),
        ]);

        dispatcher.dispatch_now(profile_mounted("default")).await;

        assert_eq!(wide.events.lock().unwrap().len(), 1);
        assert!(
            narrow.events.lock().unwrap().is_empty(),
            "narrow backend must not receive an event outside its list"
        );
    }

    #[tokio::test]
    async fn a_failing_backend_does_not_stop_another_from_receiving_the_event() {
        let failing = Arc::new(RecordingNotifyBackend::failing());
        let healthy = Arc::new(RecordingNotifyBackend::default());
        let dispatcher = NotifyDispatcher::new(vec![failing.clone(), healthy.clone()]);

        dispatcher.dispatch_now(profile_mounted("default")).await;

        assert_eq!(failing.events.lock().unwrap().len(), 1);
        assert_eq!(healthy.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn build_registry_builds_one_dispatcher_per_profile() {
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
        let registry =
            build_registry(&profiles, test_resolver(), crate::testutil::no_proxies()).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(registry.contains_key("a"));
        assert!(registry.contains_key("b"));
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
