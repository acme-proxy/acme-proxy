//! The Prometheus exposition endpoint (`GET /metrics`, `[metrics]`).
//!
//! ## Why this is hand-rolled
//!
//! The text exposition format is a metric name, an optional label set, and a
//! number — three `# HELP`/`# TYPE` lines and a `write!` per series. A façade
//! crate (`metrics` + `metrics-exporter-prometheus`) or a client library
//! (`prometheus`, `prometheus-client`) each bring six or more crates into a
//! graph `cargo deny` audits at `all-features = true`, and every one of them
//! also brings a *global recorder*, which this crate has refused elsewhere for
//! a concrete reason: `rustls`'s `CryptoProvider::install_default` was passed
//! explicitly rather than installed globally precisely so test ordering could
//! not matter. The same objection applies here, and more sharply, because a
//! global would make two tests' counters each other's.
//!
//! This is the same trade `src/admin/totp.rs` (RFC 6238 by hand on `ring`),
//! `src/signer/relay/client.rs` (an ACME client by hand on `hyper`) and
//! `src/admin/password.rs` (PBKDF2 rather than four crates for Argon2) already
//! made. Histograms are the thing a library would genuinely earn, and nothing
//! here exposes one.
//!
//! ## Cardinality is bounded by construction
//!
//! Every label value comes from a closed set, and that is a requirement rather
//! than an observation — a Prometheus series is memory in this process *and* in
//! the scraper for as long as it is retained, so one unbounded label is a leak
//! that outlives the request that caused it.
//!
//! - `profile` is a configured profile name, or `none` for the root routes.
//! - `route` is the **matched route pattern** (`/order/{id}`), never the request
//!   URI (`/order/9f3c…`), which would be one series per order ever finalized.
//!   A request that matched nothing at all is [`ROUTE_UNMATCHED`], so a scanner
//!   probing ten thousand paths adds one series and not ten thousand.
//! - `status` is an HTTP status code, and `reason` an ACME problem type this
//!   crate itself chose.
//!
//! [`Metrics::render`] is therefore the only place that needs to escape a label
//! value, and it does — but nothing that reaches it can currently contain a
//! quote or a newline. That is belt and braces for a format where getting it
//! wrong produces a scrape the collector rejects wholesale.
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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

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

/// One series' label set, in the order it is rendered.
type Labels = Vec<(&'static str, String)>;

/// The process's counters, and the handle `GET /metrics` renders from.
///
/// Cloneable through an `Arc` by every recorder; the `Mutex` is held only for
/// the increment itself. A lock per request is not a cost worth avoiding here —
/// every ACME request already commits at least one database write, and the
/// admission limiter caps concurrency at `server.max_concurrent_requests`.
pub struct Metrics {
    requests: Mutex<BTreeMap<Labels, u64>>,
    certificates_issued: Mutex<BTreeMap<Labels, u64>>,
    certificate_issue_failures: Mutex<BTreeMap<Labels, u64>>,
    /// Read at scrape time rather than tracked: `sqlx` already knows, and a
    /// gauge this crate maintained itself could only ever be a worse copy.
    database: Arc<Database>,
    /// The roles this process runs, on every series it reports.
    ///
    /// Counters are per-process memory by design — the whole reason this is a
    /// `write!` per series and not a façade crate with a global recorder — so a
    /// split deployment has one scrape target per process and needs a way to
    /// tell them apart. Constant for the life of the process, which is why it
    /// is added at render time rather than carried through every increment: a
    /// label whose value never varies would otherwise be threaded through
    /// `record_request` and `record_audit` for nothing.
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
            requests: Mutex::new(BTreeMap::new()),
            certificates_issued: Mutex::new(BTreeMap::new()),
            certificate_issue_failures: Mutex::new(BTreeMap::new()),
            database,
            // Every role, matching `serve` with no `--role`.
            roles: "acme,admin,worker".to_string(),
        }
    }

    /// Counts one served request.
    ///
    /// `route` must already be a matched pattern or [`ROUTE_UNMATCHED`]; see the
    /// cardinality note on this module.
    pub fn record_request(&self, profile: &str, route: &str, status: u16) {
        self.bump(
            &self.requests,
            vec![
                ("profile", profile.to_string()),
                ("route", route.to_string()),
                ("status", status.to_string()),
            ],
        );
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
            AuditEvent::CertificateIssued => self.bump(
                &self.certificates_issued,
                vec![("profile", record.profile.clone())],
            ),
            AuditEvent::CertificateIssueFailed => self.bump(
                &self.certificate_issue_failures,
                vec![
                    ("profile", record.profile.clone()),
                    // An ACME problem type this crate chose (`badCSR`,
                    // `serverInternal`), not text from the request.
                    (
                        "reason",
                        record.reason.clone().unwrap_or_else(|| "unknown".into()),
                    ),
                ],
            ),
            _ => {}
        }
    }

    fn bump(&self, family: &Mutex<BTreeMap<Labels, u64>>, labels: Labels) {
        // A poisoned lock would mean a panic inside one of the three-line
        // critical sections below, which cannot happen — but a metric must
        // never be the thing that takes the server down, so this recovers
        // rather than propagating.
        let mut guard = match family.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard.entry(labels).or_insert(0) += 1;
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

    /// Renders the whole registry in the Prometheus text exposition format.
    ///
    /// Series come out in `BTreeMap` order, which makes the output stable
    /// across scrapes and lets a test assert on it as text.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();

        self.render_family(
            &mut out,
            "acme_proxy_requests_total",
            "counter",
            "Requests served, by endpoint, matched route and response status.",
            &self.requests,
        );
        self.render_family(
            &mut out,
            "acme_proxy_certificates_issued_total",
            "counter",
            "Certificates signed, by endpoint.",
            &self.certificates_issued,
        );
        self.render_family(
            &mut out,
            "acme_proxy_certificate_issue_failures_total",
            "counter",
            "Issuance attempts the CA refused, by endpoint and ACME problem type.",
            &self.certificate_issue_failures,
        );

        // A gauge, and the one number here that is read rather than
        // accumulated: `size` is every connection the pool holds and `idle`
        // those not currently checked out, so `size - idle` is in-flight
        // database work. Reported as two series of one gauge rather than a
        // derived third, so a scrape cannot see them disagree.
        let stats = self.database.pool_stats();
        let size = u64::from(stats.size);
        let idle = stats.idle as u64;
        out.push_str(
            "# HELP acme_proxy_database_pool_connections Connections in the SQLite pool.\n",
        );
        out.push_str("# TYPE acme_proxy_database_pool_connections gauge\n");
        let role = escape_label(&self.roles);
        let _ = writeln!(
            out,
            "acme_proxy_database_pool_connections{{role=\"{role}\",state=\"idle\"}} {idle}"
        );
        let _ = writeln!(
            out,
            "acme_proxy_database_pool_connections{{role=\"{role}\",state=\"busy\"}} {}",
            size.saturating_sub(idle)
        );

        out
    }

    /// One metric family: its two metadata lines, then a line per series.
    ///
    /// A family with no series still emits `# HELP`/`# TYPE` and nothing else,
    /// which is deliberate: a dashboard built against a name that has simply
    /// not happened yet should find the name, not an absence it cannot tell
    /// from a typo.
    fn render_family(
        &self,
        out: &mut String,
        name: &str,
        kind: &str,
        help: &str,
        family: &Mutex<BTreeMap<Labels, u64>>,
    ) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        let guard = match family.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (labels, value) in guard.iter() {
            // `role` first, so every series of every family carries it in the
            // same position — the labels themselves are already sorted.
            let mut rendered = vec![format!("role=\"{}\"", escape_label(&self.roles))];
            rendered.extend(
                labels
                    .iter()
                    .map(|(key, value)| format!("{key}=\"{}\"", escape_label(value))),
            );
            let _ = writeln!(out, "{name}{{{}}} {value}", rendered.join(","));
        }
    }
}

/// Escapes a label value for the text exposition format.
///
/// The format defines exactly three escapes — backslash, double quote and
/// newline — and a collector rejects the *whole* scrape when one is missing, so
/// a single stray character would take out every metric rather than one series.
/// Nothing that currently reaches here can contain any of them; this exists so
/// that stays true of whatever is added next.
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
        metrics.record_request("le", "/newOrder", 201);
        metrics.record_request("le", "/newOrder", 201);
        metrics.record_request("le", "/newOrder", 400);

        let rendered = metrics.render();

        assert!(rendered.contains(
            "# HELP acme_proxy_requests_total Requests served, by endpoint, matched route and response status.\n"
        ));
        assert!(rendered.contains("# TYPE acme_proxy_requests_total counter\n"));
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

        assert!(rendered.contains("# TYPE acme_proxy_certificates_issued_total counter\n"));
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
        metrics.record_request("le", "/newOrder", 201);
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
