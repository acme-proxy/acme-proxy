//! The CA's audit trail: who asked this server to sign or withdraw a
//! certificate, from where, and how it ended.
//!
//! Three things live here, and they are deliberately one module rather than
//! three:
//!
//! - the **vocabulary** ([`AuditEvent`], [`Actor`], [`AuditRecord`]) every call
//!   site builds a row from;
//! - the **reverse lookup**, which is the only part that touches the network and
//!   the only part an operator can switch off (`audit.reverse_dns`);
//! - the **write**, which is best-effort by design — see [`Auditor::record`].
//!
//! ## Why this is not [`notify`](crate::notify)
//!
//! The two fire at nearly the same call sites and carry nearly the same fields,
//! which invites merging them. They answer different questions. A notification
//! is *outbound and lossy*: it goes to a chat room, it is fire-and-forget, and a
//! backend that is down loses the event with a warning. An audit row is
//! *inbound and durable*: it is the record the CA is answerable for, it is
//! queried months later by serial or by account, and it exists for the events
//! nobody wants a notification about — the refusals. Notifications also fire for
//! things that never touch the CA (`account_created`, `challenge_failed`), and
//! the audit trail records things nothing is notified about. Sharing a type
//! would mean every future field arguing about which of the two it is for.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use tracing::{debug, error, info};

use crate::config::{AuditConfig, DnsConfig};
use crate::dns::{HickoryResolver, Resolver, resolver_addr};
use crate::sqlite::audit::AuditEntry;
use crate::sqlite::db::Database;

/// The four things this trail records: each CA action, and its refusal.
///
/// A refusal is an audit record in its own right. "Who tried to revoke this
/// certificate and was turned away" is the question the successes cannot
/// answer, and it is the one asked after something has gone wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    CertificateIssued,
    CertificateIssueFailed,
    CertificateRevoked,
    CertificateRevokeFailed,
}

impl AuditEvent {
    /// The stored form, matching the `CHECK` in
    /// `migrations/20260809120000_add_audit_log.sql`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CertificateIssued => "certificate_issued",
            Self::CertificateIssueFailed => "certificate_issue_failed",
            Self::CertificateRevoked => "certificate_revoked",
            Self::CertificateRevokeFailed => "certificate_revoke_failed",
        }
    }

    /// `success` or `failure`, and the **only** definition of which is which.
    ///
    /// The column exists so "show me everything that was refused" is an index
    /// lookup rather than `event LIKE '%_failed'` written out in the CLI, the
    /// API and the page. Deriving it here rather than at each insert is what
    /// stops the two columns ever disagreeing.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::CertificateIssued | Self::CertificateRevoked => "success",
            Self::CertificateIssueFailed | Self::CertificateRevokeFailed => "failure",
        }
    }

    /// Parses the stored form back. `None` for anything the `CHECK` would have
    /// refused, which is also how the CLI validates `--event`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "certificate_issued" => Self::CertificateIssued,
            "certificate_issue_failed" => Self::CertificateIssueFailed,
            "certificate_revoked" => Self::CertificateRevoked,
            "certificate_revoke_failed" => Self::CertificateRevokeFailed,
            _ => return None,
        })
    }
}

/// Every [`AuditEvent`], for the CLI's `--event` help text and the page's filter.
pub const ALL_AUDIT_EVENTS: &[AuditEvent] = &[
    AuditEvent::CertificateIssued,
    AuditEvent::CertificateIssueFailed,
    AuditEvent::CertificateRevoked,
    AuditEvent::CertificateRevokeFailed,
];

/// Which front end acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// A certificate client over the ACME API.
    Acme,
    /// An operator through the web admin.
    Admin,
    /// `acme-proxy order revoke` on the host.
    Cli,
    /// The `relay` signer's background task, settling an issuance this
    /// server already answered `processing`. The one actor with no request
    /// behind it, and therefore no address — see [`Actor::system`].
    System,
}

impl ActorKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Acme => "acme",
            Self::Admin => "admin",
            Self::Cli => "cli",
            Self::System => "system",
        }
    }
}

/// Who acted, and their identity within that kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: Option<String>,
}

impl Actor {
    /// An ACME client acting as a known account.
    #[must_use]
    pub fn acme(account_id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Acme,
            id: Some(account_id.into()),
        }
    }

    /// An ACME client that proved possession of the certificate's own key pair
    /// and named no account — RFC 8555 §7.6's accountless revocation.
    ///
    /// The `None` is the honest answer and not a gap: there is no identity to
    /// record beyond "whoever holds this certificate's private key", which the
    /// `cert_serial` on the same row already says.
    #[must_use]
    pub fn acme_certificate_key() -> Self {
        Self {
            kind: ActorKind::Acme,
            id: None,
        }
    }

    /// An operator signed in to the web admin.
    #[must_use]
    pub fn admin(username: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Admin,
            id: Some(username.into()),
        }
    }

    /// The command line, identified by whichever of `$USER`/`$LOGNAME` is set.
    ///
    /// Advisory only, and unavoidably so: anything running this binary can set
    /// those variables. It narrows "somebody on the host" to "somebody on the
    /// host, probably this account", which is the most a process can say about
    /// its own invoker without help from the audit subsystem of the OS.
    #[must_use]
    pub fn cli() -> Self {
        let id = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
            .filter(|value| !value.is_empty());
        Self {
            kind: ActorKind::Cli,
            id,
        }
    }

    /// This server's own background work.
    #[must_use]
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: None,
        }
    }
}

/// The request a row came from: address, its reverse name, and the two headers
/// worth keeping.
///
/// Entirely empty for [`ActorKind::Cli`] and [`ActorKind::System`], which is
/// why every field is optional rather than a placeholder string — "there was no
/// client" and "the client sent no User-Agent" are both `None`, and the
/// `actor_kind` on the row already tells them apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientContext {
    pub ip: Option<String>,
    pub ptr: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// What a request carries before the reverse lookup has run.
///
/// An extractor rather than three `Extension`s at each call site: a handler
/// that records an audit row wants all of this or none of it, and gathering it
/// in one place is what keeps `User-Agent`'s truncation rule (below) from being
/// re-decided per handler. Resolve it into a [`ClientContext`] with
/// [`Auditor::client`].
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// Longest `User-Agent` kept. Real ones are well under this; the header is
/// attacker-controlled and ends up in a database column and an HTML page, so it
/// gets a ceiling rather than trust.
const USER_AGENT_MAX: usize = 256;

impl RequestContext {
    /// Reads the address the filter middleware resolved, plus the two headers.
    ///
    /// Free of the request body, so this composes with `AcmeRequest<T>` — which
    /// consumes it — in the usual axum order.
    pub fn from_parts(parts: &Parts) -> Self {
        Self::gather(&parts.headers, &parts.extensions)
    }

    /// Same, from a whole request.
    ///
    /// `verify_jws` needs this: it is handed the `Request` and consumes it into
    /// a body string, so it has to read the context *before* the point where
    /// the extractor machinery would hand it `Parts`.
    pub fn from_request<B>(request: &axum::http::Request<B>) -> Self {
        Self::gather(request.headers(), request.extensions())
    }

    fn gather(headers: &axum::http::HeaderMap, extensions: &axum::http::Extensions) -> Self {
        let ip = extensions
            .get::<crate::filter::ClientIp>()
            .and_then(|client| client.0);
        let user_agent = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(USER_AGENT_MAX).collect::<String>())
            .filter(|value| !value.is_empty());
        let request_id = extensions
            .get::<crate::middlewares::access::RequestId>()
            .map(|id| id.0.clone());
        Self {
            ip,
            user_agent,
            request_id,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_parts(parts))
    }
}

/// One row, before it is written.
///
/// Built with [`AuditRecord::new`] plus the `with_*` setters rather than a
/// struct literal: the four events populate different subsets — an issuance
/// failure has no serial, an accountless revocation has no account — and a
/// literal would mean a column of `None`s at every call site.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event: AuditEvent,
    pub profile: String,
    pub actor: Actor,
    pub account_id: Option<String>,
    pub order_id: Option<String>,
    pub cert_serial: Option<String>,
    pub identifiers: Vec<String>,
    pub client: ClientContext,
    pub reason: Option<String>,
    pub detail: Option<String>,
}

impl AuditRecord {
    #[must_use]
    pub fn new(event: AuditEvent, profile: impl Into<String>, actor: Actor) -> Self {
        Self {
            event,
            profile: profile.into(),
            actor,
            account_id: None,
            order_id: None,
            cert_serial: None,
            identifiers: Vec::new(),
            client: ClientContext::default(),
            reason: None,
            detail: None,
        }
    }

    /// Fills in the subject from the order: its id, its account and the names
    /// it covers, the last frozen into the row rather than joined back — the
    /// order may be deleted long before the row is read.
    #[must_use]
    pub fn with_order(mut self, order: &crate::sqlite::order::Order) -> Self {
        self.order_id = Some(order.id.clone().to_string());
        self.account_id = Some(order.account_id.clone().to_string());
        self.identifiers = order
            .identifiers
            .iter()
            .map(|identifier| identifier.value.clone())
            .collect();
        self
    }

    #[must_use]
    pub fn with_account(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    #[must_use]
    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.cert_serial = Some(serial.into());
        self
    }

    #[must_use]
    pub fn with_client(mut self, client: ClientContext) -> Self {
        self.client = client;
        self
    }

    /// The RFC 8555 problem type on a refusal, or the RFC 5280 reason code on a
    /// revocation. Never both — see the column comment in the migration.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Writes audit rows, and resolves the reverse names that go in them.
///
/// One per process, shared by the ACME listener ([`crate::AppState`]), the web
/// admin ([`crate::webadmin::AdminState`]) and the CLI. Process-wide because
/// `[audit]` is: the trail describes the CA, not one of its endpoints.
pub struct Auditor {
    database: Arc<Database>,
    /// `None` when `audit.reverse_dns` is off, which is what makes the switch
    /// structural: there is no resolver to call rather than a boolean checked
    /// at each call site. Same shape as `ChallengeRegistry`'s bypass flag
    /// refusing to *construct* the validators.
    resolver: Option<Arc<dyn Resolver>>,
    ptr_timeout: Duration,
    /// The process's Prometheus counters.
    ///
    /// `None` only for an auditor built through [`Auditor::with_resolver`],
    /// which is test scaffolding. The serving path goes through
    /// [`Auditor::from_config`], where it is a **required argument** rather
    /// than a builder step — see that constructor.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl Auditor {
    /// Builds the auditor, and with it the **cached** resolver its PTR lookups
    /// go through.
    ///
    /// Cached, unlike the shared resolver `Profile::build_all` threads through
    /// the challenge and signer subsystems, and for the reason
    /// `filter::reverse_dns` makes the same choice: a PTR record for an address
    /// that keeps connecting is exactly what a cache is for, and there is no
    /// just-published-record problem here — the answer being a few minutes old
    /// is not a failure mode for a column that says "the name this address had
    /// at the time".
    ///
    /// A second cached resolver rather than sharing `reverse_dns`'s: that one
    /// is per-profile and built only when the filter is enabled, and reaching
    /// across for it would tie the audit trail's completeness to whether an
    /// unrelated filter happens to be switched on.
    /// `metrics` is a required argument and deliberately not a builder step.
    /// It was one, briefly, and the omission it invited happened immediately:
    /// the serving path built its auditor without ever calling the builder, so
    /// `acme_proxy_certificates_issued_total` stayed at zero in production
    /// while every test passed — the test harness wired the registry itself, so
    /// what the tests proved was the harness's wiring and not the server's. A
    /// parameter cannot be forgotten. Test scaffolding that genuinely has no
    /// registry uses [`Auditor::with_resolver`] instead.
    pub fn from_config(
        cfg: &AuditConfig,
        dns: &DnsConfig,
        database: Arc<Database>,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> anyhow::Result<Self> {
        let resolver: Option<Arc<dyn Resolver>> = if cfg.reverse_dns {
            Some(Arc::new(match resolver_addr(dns)? {
                Some(addr) => HickoryResolver::from_address(addr)
                    .map_err(|error| anyhow::anyhow!("audit.reverse_dns: {error}"))?,
                None => HickoryResolver::from_system()
                    .map_err(|error| anyhow::anyhow!("audit.reverse_dns: {error}"))?,
            }))
        } else {
            None
        };
        info!(
            event = "audit_loaded",
            outcome = "success",
            reverse_dns = cfg.reverse_dns,
            reverse_dns_timeout_ms = cfg.reverse_dns_timeout_ms,
            retention_days = cfg.retention_days,
        );
        Ok(Self {
            database,
            resolver,
            ptr_timeout: Duration::from_millis(cfg.reverse_dns_timeout_ms),
            metrics: Some(metrics),
        })
    }

    /// Same, against a caller-supplied resolver — or none, for the reverse
    /// lookup switched off. Used by tests and by [`Self::from_config`].
    #[must_use]
    pub fn with_resolver(
        database: Arc<Database>,
        resolver: Option<Arc<dyn Resolver>>,
        ptr_timeout: Duration,
    ) -> Self {
        Self {
            database,
            resolver,
            ptr_timeout,
            metrics: None,
        }
    }

    /// The reverse name for `ip`, or `None`.
    ///
    /// Every failure is `None`: no PTR record, a resolver that timed out, a
    /// SERVFAIL, `audit.reverse_dns` off, or no client address at all. Nothing
    /// downstream distinguishes them, because nothing downstream *authorises*
    /// on this value — it is a label on a row, and a label that is sometimes
    /// missing is worth more than a request that failed to get one.
    ///
    /// The first name only when several PTR records answer. Storing all of them
    /// would make the column a list nothing queries; `filter.reverse_dns` is
    /// where multiple candidates genuinely matter, and it looks them up itself.
    pub async fn reverse(&self, ip: Option<IpAddr>) -> Option<String> {
        let (resolver, ip) = (self.resolver.as_ref()?, ip?);
        match tokio::time::timeout(self.ptr_timeout, resolver.reverse(ip)).await {
            Ok(Ok(names)) => names.into_iter().next(),
            Ok(Err(error)) => {
                debug!(event = "audit_reverse_dns_failed", outcome = "failure", ip = %ip, error = %error);
                None
            }
            Err(_) => {
                debug!(
                    event = "audit_reverse_dns_timeout",
                    outcome = "failure",
                    ip = %ip,
                    timeout_ms = crate::millis(self.ptr_timeout),
                );
                None
            }
        }
    }

    /// Resolves a [`RequestContext`] into the [`ClientContext`] a row stores,
    /// running the reverse lookup on the way.
    pub async fn client(&self, request: &RequestContext) -> ClientContext {
        let canonical = request.ip.map(crate::filter::canonical);
        ClientContext {
            ip: canonical.map(|ip| ip.to_string()),
            ptr: self.reverse(canonical).await,
            user_agent: request.user_agent.clone(),
            request_id: request.request_id.clone(),
        }
    }

    /// Attaches the Prometheus registry to an auditor built by
    /// [`Auditor::with_resolver`].
    ///
    /// Exists for the test harness, which builds its auditor with a stub
    /// resolver and still wants the counters. The serving path does **not** use
    /// this — [`Auditor::from_config`] takes the registry as a parameter, so it
    /// cannot be left off.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Writes one row, and counts it.
    ///
    /// The counter is driven off the *same* [`AuditRecord`] that is about to be
    /// stored, which is what makes "how many certificates did we issue" answer
    /// identically whether it is asked of the metrics endpoint or of
    /// `acme-proxy audit list`. A second set of call sites incrementing
    /// counters beside the audit writes would have been free to drift.
    ///
    /// See [`write()`], which this is the stateful spelling of.
    pub async fn record(&self, record: AuditRecord) {
        if let Some(metrics) = &self.metrics {
            metrics.record_audit(&record);
        }
        write(record, &self.database).await;
    }
}

/// Writes one row against a bare database handle.
///
/// The free function exists for the `relay` backend: it settles an issuance
/// from a background task that holds an `Arc<Database>` and no [`Auditor`], and
/// it needs no reverse lookup either — the address it records was resolved
/// during the finalize request and stored on the `upstream_orders` row. Giving
/// that task an `Auditor` would have meant threading one through
/// `signer::build_backends` and `Profile::build_all` for the sake of a resolver
/// it would never call.
///
/// **A failed write is logged and swallowed.** The alternative — failing the
/// request — would turn a certificate this CA has already signed into a 500 the
/// client retries, issuing a second one, which is a worse outcome for the same
/// underlying fault. It is also nearly unreachable in practice: this is the
/// same SQLite file the order was just written to, so a failure here means the
/// write that preceded it had already failed. The `error!` carries the record's
/// identifying fields, so the trail survives in the log even when the table did
/// not get it.
pub async fn write(record: AuditRecord, database: &Database) {
    let (event, profile) = (record.event, record.profile.clone());
    let (order_id, serial) = (record.order_id.clone(), record.cert_serial.clone());
    if let Err(error) = AuditEntry::insert(record, database).await {
        error!(
            event = "audit_write_failed",
            outcome = "failure",
            audit_event = event.as_str(),
            profile = %profile,
            order_id = ?order_id,
            cert_serial = ?serial,
            error = %error,
            "the action succeeded but its audit row was not written"
        );
    }
}

impl std::fmt::Debug for Auditor {
    /// Renders the configured policy. `dyn Resolver` is not `Debug`, so the
    /// resolver shows as whether there is one — which is the whole of what it
    /// contributes to behaviour here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auditor")
            .field("reverse_dns", &self.resolver.is_some())
            .field("ptr_timeout", &self.ptr_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests;
