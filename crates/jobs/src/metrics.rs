//! The Prometheus exposition endpoint (`GET /metrics`, `[metrics]`).
//!
//! ## Why `prometheus-client`
//!
//! The counters were hand-written text until the latency histograms: buckets,
//! a running sum and a count per series, each rendered cumulatively, are where
//! the format stops being a `write!` per series. ADR 0011 records the choice.
//! `prometheus-client` was picked because it has **no global registry**: a
//! global would make two tests' counters each other's, the objection
//! ADR 0009 raises against every process-wide install. Here every
//! [`Metrics`] owns its families, and [`Metrics::render`] builds a
//! [`Registry`] over them for the one scrape.
//!
//! The output is the **OpenMetrics** text format ([`CONTENT_TYPE`]), which
//! Prometheus reads natively. Two differences from the older text format show
//! in a scrape: a counter's `# TYPE` line names it without `_total` (the
//! series keep it), and the body ends with `# EOF`.
//!
//! ## Every family declares itself, even empty
//!
//! `prometheus-client` leaves an empty family out of the exposition entirely.
//! [`Declared`] overrides that, so a family nobody has exercised still emits
//! its `# HELP`/`# TYPE` lines: a dashboard built against a name that has not
//! happened yet should find the name, not an absence it cannot tell from a
//! typo. `tests/grafana_dashboard.rs` reads the names off an empty registry
//! and depends on it.
//!
//! ## Cardinality is bounded by construction
//!
//! Every label value comes from a closed set, and that is a requirement rather
//! than an observation — a Prometheus series is memory in this process *and* in
//! the scraper for as long as it is retained, so one unbounded label is a leak
//! that outlives the request that caused it. A histogram multiplies that by its
//! bucket count, which is why neither histogram carries `status` or `reason`.
//!
//! - `profile` is a configured profile name, or `none` for the root routes.
//! - `route` is the **matched route pattern** (`/order/{id}`), never the request
//!   URI (`/order/9f3c…`), which would be one series per order ever finalized.
//!   A request that matched nothing at all is [`ROUTE_UNMATCHED`], so a scanner
//!   probing ten thousand paths adds one series and not ten thousand.
//! - `status` is an HTTP status code, and `reason` an ACME problem type this
//!   crate itself chose.
//!
//! `prometheus-client` writes a label value verbatim, so [`escape_label`] is
//! applied here to every value on its way in. Nothing that reaches it can
//! currently contain a quote or a newline; it is there for a format where
//! getting it wrong produces a scrape the collector rejects wholesale.
//!
//! ## Counters survive a reload
//!
//! The registry lives in `server::Assembly`, which is built once and
//! carried across every generation, rather than in a `Generation`, which is
//! rebuilt on each `SIGHUP`. A rebuilt registry would reset every counter to
//! zero, and a counter that goes backwards is exactly how Prometheus detects a
//! process restart: `rate()` would report a spike of the entire pre-reload
//! total on every configuration change. It does *not* survive a real restart,
//! which is correct — that genuinely is a new process.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric, MetricEncoder};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};

use acme_proxy_store::db::Database;

/// The `route` label of a request that matched no route at all.
///
/// A literal rather than the request's own path: an unmatched path is
/// attacker-chosen, so using it would be an unbounded label.
pub const ROUTE_UNMATCHED: &str = "<unmatched>";

/// The `profile` label of a request served by the root router.
///
/// `/health`, `/metrics` itself, the redirect and the `http-01` responder
/// belong to no endpoint. Spelled explicitly rather than left empty so a query
/// can say `profile="none"` and mean it.
pub const PROFILE_NONE: &str = "none";

/// The media type of [`Metrics::render`]'s output, version parameter included:
/// a collector reading `text/plain` with no `version` falls back to guessing.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Upper bounds, in seconds, of `acme_proxy_request_duration_seconds`.
///
/// From a nonce (a few milliseconds) to a request held by the admission
/// limiter or a slow database (seconds). Nothing in a request waits on the
/// network any more (ADR 0006), so ten seconds is already pathological.
const REQUEST_SECONDS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Upper bounds, in seconds, of `acme_proxy_certificate_issue_duration_seconds`.
///
/// Measured from job timestamps, which are whole seconds, so nothing finer
/// than a second is meaningful. A local CA signs within the first bucket or
/// two; a relayed order waits on an upstream CA and its own challenges, which
/// can take many minutes.
const ISSUE_SECONDS: [f64; 11] = [
    1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
];

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    profile: String,
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteLabels {
    profile: String,
    route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ProfileLabels {
    profile: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct FailureLabels {
    profile: String,
    reason: String,
}

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

fn request_histogram() -> Histogram {
    Histogram::new(REQUEST_SECONDS)
}

fn issue_histogram() -> Histogram {
    Histogram::new(ISSUE_SECONDS)
}

/// The process's metric families, and the handle `GET /metrics` renders from.
///
/// Cloneable through an `Arc` by every recorder. A family is a lock over a
/// map of series, held only for the increment itself.
pub struct Metrics {
    requests: Family<RequestLabels, Counter>,
    request_duration: HistogramFamily<RouteLabels>,
    certificates_issued: Family<ProfileLabels, Counter>,
    certificate_issue_failures: Family<FailureLabels, Counter>,
    certificate_issue_duration: HistogramFamily<ProfileLabels>,
    /// Read at scrape time rather than tracked: `sqlx` already knows, and a
    /// gauge this crate maintained itself could only ever be a worse copy.
    database: Arc<Database>,
    /// The roles this process runs, on every series it reports.
    ///
    /// Families are per-process memory, so a split deployment has one scrape
    /// target per process and needs a way to tell them apart. Constant for the
    /// life of the process, which is why it is a label of the registry built
    /// at render time rather than a field of every label set.
    roles: String,
}

impl std::fmt::Debug for Metrics {
    /// Deliberately says nothing about the counters.
    ///
    /// `Config`'s `Debug` is this crate's configuration-identity primitive
    /// (`reload::FROZEN` projects through it), and a `Debug` whose output
    /// changed on every request would make anything built on that comparison
    /// meaningless.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Metrics")
    }
}

impl Metrics {
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            requests: Family::default(),
            request_duration: Family::new_with_constructor(request_histogram),
            certificates_issued: Family::default(),
            certificate_issue_failures: Family::default(),
            certificate_issue_duration: Family::new_with_constructor(issue_histogram),
            database,
            // Every role, matching `serve` with no `--role`.
            roles: "acme,admin,worker".to_string(),
        }
    }

    /// Counts one served request, and how long it took.
    ///
    /// `route` must already be a matched pattern or [`ROUTE_UNMATCHED`]; see the
    /// cardinality note on this module.
    pub fn record_request(&self, profile: &str, route: &str, status: u16, elapsed: Duration) {
        let profile = escape_label(profile);
        let route = escape_label(route);
        self.request_duration
            .get_or_create(&RouteLabels {
                profile: profile.clone(),
                route: route.clone(),
            })
            .observe(elapsed.as_secs_f64());
        self.requests
            .get_or_create(&RequestLabels {
                profile,
                route,
                status,
            })
            .inc();
    }

    /// Counts one CA action from the audit record that describes it.
    ///
    /// Driven off [`acme_proxy_core::audit::AuditRecord`] rather than called separately at
    /// each issuance site, so the counter and the audit trail cannot disagree
    /// about what happened: both are written from the same value. Events this
    /// exposes no series for are ignored rather than enumerated, which is what
    /// keeps a new `AuditEvent` variant from being a compile error in a
    /// subsystem that has no opinion about it.
    pub fn record_audit(&self, record: &acme_proxy_core::audit::AuditRecord) {
        use acme_proxy_core::audit::AuditEvent;
        match record.event {
            AuditEvent::CertificateIssued => {
                self.certificates_issued
                    .get_or_create(&ProfileLabels {
                        profile: escape_label(&record.profile),
                    })
                    .inc();
            }
            AuditEvent::CertificateIssueFailed => {
                self.certificate_issue_failures
                    .get_or_create(&FailureLabels {
                        profile: escape_label(&record.profile),
                        // An ACME problem type this crate chose (`badCSR`,
                        // `serverInternal`), not text from the request.
                        reason: escape_label(record.reason.as_deref().unwrap_or("unknown")),
                    })
                    .inc();
            }
            _ => {}
        }
    }

    /// Observes one issuance: from the moment the finalize was accepted to the
    /// moment the certificate was stored.
    ///
    /// Not driven off the audit record like the counters, because the record
    /// carries no duration and should not grow one for this.
    pub fn observe_issuance(&self, profile: &str, elapsed: Duration) {
        self.certificate_issue_duration
            .get_or_create(&ProfileLabels {
                profile: escape_label(profile),
            })
            .observe(elapsed.as_secs_f64());
    }

    /// Names the roles this process runs, for the `role` label.
    ///
    /// A builder step rather than a `new` parameter for `Auditor::with_metrics`'
    /// reason inverted: every test that builds a registry would otherwise have
    /// to know about roles, and all-in-one — the default — is what the plain
    /// constructor already says.
    #[must_use]
    pub fn with_roles(mut self, roles: &[&str]) -> Self {
        self.roles = roles.join(",");
        self
    }

    /// Renders every family in the OpenMetrics text format ([`CONTENT_TYPE`]).
    ///
    /// The registry is built here, per scrape, over clones of the families
    /// (a clone shares its series). That keeps the `role` label a registry
    /// label, set once, and keeps [`Metrics::with_roles`] a builder step.
    #[must_use]
    pub fn render(&self) -> String {
        let mut registry = Registry::with_prefix_and_labels(
            "acme_proxy",
            std::iter::once((Cow::Borrowed("role"), Cow::Owned(escape_label(&self.roles)))),
        );
        registry.register(
            "requests",
            "Requests served, by endpoint, matched route and response status",
            Declared(self.requests.clone()),
        );
        registry.register_with_unit(
            "request_duration",
            "Time to answer a request, by endpoint and matched route",
            Unit::Seconds,
            Declared(self.request_duration.clone()),
        );
        registry.register(
            "certificates_issued",
            "Certificates signed, by endpoint",
            Declared(self.certificates_issued.clone()),
        );
        registry.register(
            "certificate_issue_failures",
            "Issuance attempts the CA refused, by endpoint and ACME problem type",
            Declared(self.certificate_issue_failures.clone()),
        );
        registry.register_with_unit(
            "certificate_issue_duration",
            "Time from an accepted finalize to a stored certificate, by endpoint",
            Unit::Seconds,
            Declared(self.certificate_issue_duration.clone()),
        );
        registry.register_collector(Box::new(PoolConnections(self.database.clone())));

        let mut out = String::new();
        // Writing into a `String` cannot fail.
        let _ = prometheus_client::encoding::text::encode(&mut out, &registry);
        out
    }
}

/// A family that is encoded even with no series.
///
/// `prometheus-client` skips a metric whose `is_empty` is true, and a
/// [`Family`] is empty until its first series. This wrapper keeps the trait's
/// default, `false`; see "Every family declares itself" on this module.
#[derive(Debug)]
struct Declared<M>(M);

impl<M: EncodeMetric> EncodeMetric for Declared<M> {
    fn encode(&self, encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        self.0.encode(encoder)
    }

    fn metric_type(&self) -> MetricType {
        self.0.metric_type()
    }
}

/// `acme_proxy_database_pool_connections`, read from `sqlx` at scrape time.
///
/// A gauge, and the one number here that is read rather than accumulated:
/// `size` is every connection the pool holds and `idle` those not currently
/// checked out, so `size - idle` is in-flight database work. Reported as two
/// series of one gauge rather than a derived third, so a scrape cannot see
/// them disagree.
struct PoolConnections(Arc<Database>);

impl std::fmt::Debug for PoolConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoolConnections")
    }
}

impl Collector for PoolConnections {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let stats = self.0.pool_stats();
        let size = i64::from(stats.size);
        let idle = i64::try_from(stats.idle).unwrap_or(i64::MAX);
        let mut metric = encoder.encode_descriptor(
            "database_pool_connections",
            "Connections in the SQLite pool.",
            None,
            MetricType::Gauge,
        )?;
        for (state, value) in [("idle", idle), ("busy", size.saturating_sub(idle))] {
            ConstGauge::new(value).encode(metric.encode_family(&[("state", state)])?)?;
        }
        Ok(())
    }
}

/// Escapes a label value for the text exposition format.
///
/// The format defines exactly three escapes — backslash, double quote and
/// newline — and a collector rejects the *whole* scrape when one is missing, so
/// a single stray character would take out every metric rather than one series.
/// `prometheus-client` writes values as given, so this is applied to each one
/// before it becomes a label.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Splits a matched route pattern into its `(profile, route)` labels.
///
/// A nested router reports the whole pattern, prefix and all
/// (`/profile/le/order/{id}`), so this is what turns one string into the two
/// dimensions a query wants: "how many 500s did `le` serve" and "how many 500s
/// did `/newOrder` serve anywhere". The split is unambiguous because
/// [`PROFILE_PREFIX`](acme_proxy_core::routes::PROFILE_PREFIX) is reserved and a profile
/// name matches `^[a-z0-9-]+$`, so the second segment can never itself contain
/// a slash.
#[must_use]
pub fn split_matched_path(matched: Option<&str>) -> (String, String) {
    let Some(matched) = matched else {
        return (PROFILE_NONE.to_string(), ROUTE_UNMATCHED.to_string());
    };
    let prefix = format!("{}/", acme_proxy_core::routes::PROFILE_PREFIX);
    let Some(rest) = matched.strip_prefix(&prefix) else {
        return (PROFILE_NONE.to_string(), matched.to_string());
    };
    match rest.split_once('/') {
        Some((profile, route)) => (profile.to_string(), format!("/{route}")),
        // `/profile/le` with nothing after it routes nowhere today, but a
        // pattern this cannot split must still yield two bounded labels.
        None => (rest.to_string(), "/".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::audit::Actor;
    use acme_proxy_core::audit::AuditEvent;
    use acme_proxy_core::audit::AuditRecord;

    async fn metrics() -> Metrics {
        Metrics::new(Arc::new(Database::connect_in_memory().await.unwrap()))
    }

    /// The exposition format, asserted as text: a collector parses this, so the
    /// bytes are the contract and not an implementation detail.
    #[tokio::test]
    async fn requests_render_as_one_series_per_label_set() {
        let metrics = metrics().await;
        metrics.record_request("le", "/newOrder", 201, Duration::from_millis(20));
        metrics.record_request("le", "/newOrder", 201, Duration::from_millis(20));
        metrics.record_request("le", "/newOrder", 400, Duration::from_millis(20));

        let rendered = metrics.render();

        assert!(rendered.contains(
            "# HELP acme_proxy_requests Requests served, by endpoint, matched route and response status.\n"
        ));
        // OpenMetrics names a counter's family without `_total`; its series
        // keep it, so a query is written exactly as before.
        assert!(rendered.contains("# TYPE acme_proxy_requests counter\n"));
        assert!(rendered.contains(
            "acme_proxy_requests_total{role=\"acme,admin,worker\",profile=\"le\",route=\"/newOrder\",status=\"201\"} 2\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_requests_total{role=\"acme,admin,worker\",profile=\"le\",route=\"/newOrder\",status=\"400\"} 1\n"
        ));
    }

    /// A family nobody has exercised keeps its metadata lines. A dashboard
    /// built on the name must be able to tell "has not happened yet" from
    /// "misspelled".
    #[tokio::test]
    async fn an_empty_family_still_declares_itself() {
        let rendered = metrics().await.render();

        assert!(rendered.contains("# TYPE acme_proxy_certificates_issued counter\n"));
        assert!(
            !rendered.contains("acme_proxy_certificates_issued_total{role=\"acme,admin,worker\",")
        );
    }

    /// The pool gauge is read from `sqlx`, so it reports a real connection
    /// rather than a number this crate maintains in parallel.
    /// The label a split deployment is told apart by.
    ///
    /// Counters are per-process memory, so three role processes are three
    /// scrape targets reporting the same family names; without this they would
    /// be indistinguishable at the collector. Asserted on **every** family,
    /// including the gauge, because a process reporting its pool under no role
    /// would be the one series nobody could attribute.
    #[tokio::test]
    async fn every_series_carries_the_roles_this_process_runs() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let metrics = Metrics::new(database).with_roles(&["acme", "worker"]);
        metrics.record_request("le", "/newOrder", 201, Duration::from_millis(20));
        metrics.record_audit(&AuditRecord::new(
            AuditEvent::CertificateIssued,
            "le",
            Actor::acme("acct-1"),
        ));

        let rendered = metrics.render();
        for line in rendered
            .lines()
            .filter(|line| line.starts_with("acme_proxy_"))
        {
            assert!(
                line.contains("role=\"acme,worker\""),
                "every series must name its roles: {line}"
            );
        }
        // And the default really is all three, which is what an all-in-one
        // deployment — still the default — reports.
        assert!(
            Metrics::new(Arc::new(Database::connect_in_memory().await.unwrap()))
                .render()
                .contains("role=\"acme,admin,worker\"")
        );
    }

    #[tokio::test]
    async fn the_pool_gauge_reports_both_states() {
        let rendered = metrics().await.render();

        assert!(rendered.contains("# TYPE acme_proxy_database_pool_connections gauge\n"));
        assert!(rendered.contains(
            "acme_proxy_database_pool_connections{role=\"acme,admin,worker\",state=\"idle\"}"
        ));
        assert!(rendered.contains(
            "acme_proxy_database_pool_connections{role=\"acme,admin,worker\",state=\"busy\"}"
        ));
    }

    /// Driving the counters off the audit record is what keeps the metric and
    /// the trail from disagreeing, so the mapping is asserted from a real one.
    #[tokio::test]
    async fn the_certificate_counters_come_off_the_audit_record() {
        let metrics = metrics().await;

        metrics.record_audit(&AuditRecord::new(
            AuditEvent::CertificateIssued,
            "le",
            Actor::acme("acct-1"),
        ));
        metrics.record_audit(
            &AuditRecord::new(
                AuditEvent::CertificateIssueFailed,
                "le",
                Actor::acme("acct-1"),
            )
            .with_reason("badCSR"),
        );
        // An event this subsystem has no series for changes nothing.
        metrics.record_audit(&AuditRecord::new(
            AuditEvent::CertificateRevoked,
            "le",
            Actor::acme("acct-1"),
        ));

        let rendered = metrics.render();

        assert!(rendered.contains(
            "acme_proxy_certificates_issued_total{role=\"acme,admin,worker\",profile=\"le\"} 1\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_certificate_issue_failures_total{role=\"acme,admin,worker\",profile=\"le\",reason=\"badCSR\"} 1\n"
        ));
        assert!(!rendered.contains("revoked"));
    }

    /// A refusal recorded without a reason still lands in a series rather than
    /// silently vanishing, because "the CA refused and did not say why" is
    /// itself worth seeing on a graph.
    #[tokio::test]
    async fn a_failure_with_no_reason_is_counted_as_unknown() {
        let metrics = metrics().await;
        metrics.record_audit(&AuditRecord::new(
            AuditEvent::CertificateIssueFailed,
            "le",
            Actor::acme("acct-1"),
        ));

        assert!(metrics.render().contains(
            "acme_proxy_certificate_issue_failures_total{role=\"acme,admin,worker\",profile=\"le\",reason=\"unknown\"} 1\n"
        ));
    }

    /// Both histograms, with their unit, their buckets and the `+Inf` bucket
    /// every histogram must end with.
    #[tokio::test]
    async fn both_histograms_observe_into_their_buckets() {
        let metrics = metrics().await;
        metrics.record_request("le", "/newOrder", 201, Duration::from_millis(20));
        metrics.observe_issuance("le", Duration::from_secs(3));

        let rendered = metrics.render();

        assert!(rendered.contains("# TYPE acme_proxy_request_duration_seconds histogram\n"));
        assert!(rendered.contains("# UNIT acme_proxy_request_duration_seconds seconds\n"));
        assert!(rendered.contains(
            "acme_proxy_request_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"0.01\",profile=\"le\",route=\"/newOrder\"} 0\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_request_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"0.025\",profile=\"le\",route=\"/newOrder\"} 1\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_request_duration_seconds_count{role=\"acme,admin,worker\",profile=\"le\",route=\"/newOrder\"} 1\n"
        ));
        // No `status` on the histogram: it would multiply every bucket.
        assert!(!rendered.contains("acme_proxy_request_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"0.01\",profile=\"le\",route=\"/newOrder\",status="));

        assert!(rendered.contains(
            "acme_proxy_certificate_issue_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"2.0\",profile=\"le\"} 0\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_certificate_issue_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"5.0\",profile=\"le\"} 1\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_certificate_issue_duration_seconds_bucket{role=\"acme,admin,worker\",le=\"+Inf\",profile=\"le\"} 1\n"
        ));
        assert!(rendered.contains(
            "acme_proxy_certificate_issue_duration_seconds_sum{role=\"acme,admin,worker\",profile=\"le\"} 3.0\n"
        ));
    }

    /// Every family an empty registry has, in order, and the `# EOF` an
    /// OpenMetrics body must end with. `tests/grafana_dashboard.rs` reads the
    /// names this way, so a family that disappeared while empty would blank a
    /// panel with nothing failing.
    #[tokio::test]
    async fn an_empty_registry_declares_every_family_and_ends_with_eof() {
        let rendered = metrics().await.render();

        let declared: Vec<&str> = rendered
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .collect();
        assert_eq!(
            declared,
            [
                "acme_proxy_requests counter",
                "acme_proxy_request_duration_seconds histogram",
                "acme_proxy_certificates_issued counter",
                "acme_proxy_certificate_issue_failures counter",
                "acme_proxy_certificate_issue_duration_seconds histogram",
                "acme_proxy_database_pool_connections gauge",
            ]
        );
        assert!(rendered.ends_with("# EOF\n"), "{rendered}");
        // One full stop, not the library's appended to ours.
        assert!(!rendered.contains(".."), "{rendered}");
    }

    /// `Debug` must not change as the counters move; see `Metrics`' own impl.
    #[tokio::test]
    async fn debug_says_nothing_about_the_counters() {
        let metrics = metrics().await;
        let before = format!("{metrics:?}");
        metrics.record_request("le", "/newOrder", 201, Duration::from_millis(20));

        assert_eq!(format!("{metrics:?}"), before);
        assert_eq!(
            format!("{:?}", PoolConnections(metrics.database.clone())),
            "PoolConnections"
        );
    }

    /// The nested-router split, which is what keeps `route` comparable across
    /// endpoints instead of one series per profile per route.
    #[test]
    fn a_matched_path_splits_into_a_profile_and_a_route() {
        for (matched, expected) in [
            (Some("/profile/le/order/{id}"), ("le", "/order/{id}")),
            (Some("/profile/staging/newOrder"), ("staging", "/newOrder")),
            // Root routes belong to no endpoint.
            (Some("/health"), (PROFILE_NONE, "/health")),
            (Some("/"), (PROFILE_NONE, "/")),
            // A path that matched nothing is attacker-chosen and must collapse
            // to one series.
            (None, (PROFILE_NONE, ROUTE_UNMATCHED)),
        ] {
            let (profile, route) = split_matched_path(matched);
            assert_eq!(
                (profile.as_str(), route.as_str()),
                expected,
                "for {matched:?}"
            );
        }
    }

    /// The three escapes the format defines. Nothing reaching a label can carry
    /// one today; a scrape a collector rejects wholesale is the cost of that
    /// stopping being true unnoticed.
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_label(r"a\b"), r"a\\b");
        assert_eq!(escape_label("a\nb"), r"a\nb");
    }
}
