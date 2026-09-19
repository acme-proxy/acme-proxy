//! Writing the CA's audit trail, and resolving the reverse names that go in it.
//!
//! Two things live here, beside the vocabulary in [`acme_proxy_core::audit`]:
//!
//! - the **reverse lookup**, which is the only part that touches the network and
//!   the only part an operator can switch off (`audit.reverse_dns`);
//! - the **write**, which is best-effort by design — see [`Auditor::record`].
//!
//! [`admin`] builds the records for the administrative actions the front ends
//! take on the CA itself.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};

use crate::dns::{HickoryResolver, Resolver, resolver_addr};
use crate::sqlite::audit::AuditEntry;
use crate::sqlite::db::Database;
use acme_proxy_core::audit::AuditRecord;
use acme_proxy_core::audit::ClientContext;
use acme_proxy_core::audit::RequestContext;
use acme_proxy_core::config::AuditConfig;
use acme_proxy_core::config::DnsConfig;

pub mod admin;

/// Writes audit rows, and resolves the reverse names that go in them.
///
/// One per process, shared by the ACME listener ([`crate::router::AppState`]),
/// the web admin ([`crate::webadmin::AdminState`]) and the CLI. Process-wide
/// because `[audit]` is: the trail describes the CA, not one of its endpoints.
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
    /// `None` for an auditor built through [`Auditor::with_resolver`] or
    /// [`Auditor::offline`] and never given one: test scaffolding, and the host
    /// CLI, which serves no `/metrics`. The serving path goes through
    /// [`Auditor::from_config`], where it is a **required argument** rather
    /// than a builder step — see that constructor.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl Auditor {
    /// Builds the auditor, and with it the **cached** resolver its PTR lookups
    /// go through.
    ///
    /// Cached, unlike the shared resolver `server::profile::build_all` threads through
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
                    timeout_ms = acme_proxy_core::logfields::millis(self.ptr_timeout),
                );
                None
            }
        }
    }

    /// An auditor with no resolver and no metrics registry, for a caller that
    /// has no request to resolve an address from: the host CLI, and the
    /// background tasks that settle work long after the request that asked.
    ///
    /// Attach the process's registry with [`Auditor::with_metrics`] wherever one
    /// exists — a background task inside `serve` has one, the CLI does not (it
    /// serves no `/metrics`, so a count there would reach nobody).
    #[must_use]
    pub fn offline(database: Arc<Database>) -> Self {
        Self::with_resolver(database, None, Duration::ZERO)
    }

    /// Resolves a [`RequestContext`] into the [`ClientContext`] a row stores,
    /// running the reverse lookup on the way.
    pub async fn client(&self, request: &RequestContext) -> ClientContext {
        let canonical = request.ip.map(acme_proxy_core::client::canonical);
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

/// Writes one row against a bare database handle, counting nothing.
///
/// Every writer outside this module goes through [`Auditor::record`], so a row
/// and its Prometheus count cannot come apart — the relay's settlement, the
/// operator's revocation and the web admin's action rows each used to write
/// here directly and each skipped the counter. What is left is the host CLI's
/// administrative rows ([`admin::record_cli_action`]), whose process serves no
/// `/metrics` for a count to reach.
///
/// **A failed write is logged and swallowed.** The alternative — failing the
/// request — would turn a certificate this CA has already signed into a 500 the
/// client retries, issuing a second one, which is a worse outcome for the same
/// underlying fault. It is also nearly unreachable in practice: this is the
/// same SQLite file the order was just written to, so a failure here means the
/// write that preceded it had already failed. The `error!` carries the record's
/// identifying fields, so the trail survives in the log even when the table did
/// not get it.
pub(crate) async fn write(record: AuditRecord, database: &Database) {
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
