//! Tests for the auditor: every way a PTR lookup can fail, the two shapes of
//! `from_config`, and a failed write staying quiet.
//!
//! The *write* itself is exercised through `src/sqlite/audit.rs` (the model)
//! and `tests/audit.rs` (the whole router).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::*;
use acme_proxy_core::audit::Actor;
use acme_proxy_core::audit::AuditEvent;
use acme_proxy_core::audit::AuditRecord;
use acme_proxy_core::audit::RequestContext;
use acme_proxy_net::dns::Resolver;
use acme_proxy_store::db::Database;

/// A resolver answering from canned data, or failing however the test asks.
#[derive(Default)]
struct StubResolver {
    ptr: HashMap<IpAddr, Vec<String>>,
    error: Option<String>,
    hang: bool,
}

#[async_trait]
impl Resolver for StubResolver {
    async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        if self.hang {
            // Longer than any timeout a test sets, and cancelled by the
            // `tokio::time::timeout` under test rather than ever elapsing.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
    }

    async fn forward(&self, _name: &str) -> Result<Vec<IpAddr>, String> {
        unreachable!("the auditor only ever asks for PTR records")
    }

    async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
        unreachable!("the auditor only ever asks for PTR records")
    }
}

async fn auditor(resolver: Option<Arc<dyn Resolver>>) -> Auditor {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    Auditor::with_resolver(database, resolver, Duration::from_millis(50))
}

fn metrics(database: Arc<Database>) -> Arc<crate::metrics::Metrics> {
    Arc::new(crate::metrics::Metrics::new(database))
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

/// `audit.reverse_dns = false` is structural: there is no resolver to call, not
/// a boolean checked at the call site.
#[tokio::test]
async fn no_resolver_means_no_lookup_and_no_name() {
    let auditor = auditor(None).await;
    assert_eq!(auditor.reverse(Some(ip("203.0.113.7"))).await, None);
    assert!(format!("{auditor:?}").contains("reverse_dns: false"));
}

/// The happy path, plus the rule that several PTR records collapse to the
/// first: this column is a label, and a list nothing queries would be worse.
#[tokio::test]
async fn a_ptr_record_is_recorded_and_several_collapse_to_the_first() {
    let mut stub = StubResolver::default();
    stub.ptr.insert(
        ip("203.0.113.7"),
        vec!["a.example.com".to_string(), "b.example.com".to_string()],
    );
    let auditor = auditor(Some(Arc::new(stub))).await;

    assert_eq!(
        auditor.reverse(Some(ip("203.0.113.7"))).await.as_deref(),
        Some("a.example.com")
    );
    // No record for this address at all.
    assert_eq!(auditor.reverse(Some(ip("203.0.113.8"))).await, None);
    // And no address at all.
    assert_eq!(auditor.reverse(None).await, None);
    assert!(format!("{auditor:?}").contains("reverse_dns: true"));
}

/// Every failure is the same `None`. Nothing downstream authorises on this
/// value, so a resolver outage must cost a missing label and never a refused
/// request.
#[tokio::test]
async fn a_resolver_failure_and_a_timeout_are_both_just_no_name() {
    let failing = StubResolver {
        error: Some("SERVFAIL".to_string()),
        ..StubResolver::default()
    };
    assert_eq!(
        auditor(Some(Arc::new(failing)))
            .await
            .reverse(Some(ip("203.0.113.7")))
            .await,
        None
    );

    let hanging = StubResolver {
        hang: true,
        ..StubResolver::default()
    };
    let started = std::time::Instant::now();
    assert_eq!(
        auditor(Some(Arc::new(hanging)))
            .await
            .reverse(Some(ip("203.0.113.7")))
            .await,
        None
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the timeout must cut the lookup off, not wait for it"
    );
}

/// The dual-stack `[::]:3000` bind sees an IPv4 client as `::ffff:…`, so the
/// same client arriving over either socket has to read as one address — the
/// rule every other address this crate stores already follows.
#[tokio::test]
async fn the_client_context_canonicalizes_the_address_before_storing_or_looking_it_up() {
    let mut stub = StubResolver::default();
    stub.ptr
        .insert(ip("203.0.113.7"), vec!["host.example.com".to_string()]);
    let auditor = auditor(Some(Arc::new(stub))).await;

    let request = RequestContext {
        ip: Some(ip("::ffff:203.0.113.7")),
        user_agent: Some("lego".to_string()),
        request_id: Some("req-1".to_string()),
    };
    let client = auditor.client(&request).await;

    assert_eq!(client.ip.as_deref(), Some("203.0.113.7"));
    // And the lookup went to the canonical form too, or the stub would not
    // have matched.
    assert_eq!(client.ptr.as_deref(), Some("host.example.com"));
    assert_eq!(client.user_agent.as_deref(), Some("lego"));
    assert_eq!(client.request_id.as_deref(), Some("req-1"));
}

/// `from_config`'s two shapes, the same way `filter::reverse_dns::from_config`
/// is exercised: with the lookup on it builds a **cached** resolver (from
/// `dns.resolver` when set, from the system configuration otherwise), and with
/// it off there is no resolver to build at all.
#[tokio::test]
async fn from_config_builds_a_resolver_only_when_the_lookup_is_on() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let dns = acme_proxy_core::config::DnsConfig::default();

    let off = Auditor::from_config(
        &AuditConfig {
            reverse_dns: false,
            ..AuditConfig::default()
        },
        &dns,
        database.clone(),
        metrics(database.clone()),
    )
    .unwrap();
    assert!(format!("{off:?}").contains("reverse_dns: false"));
    // And with nothing to call, an address still resolves to no name.
    assert_eq!(off.reverse(Some(ip("203.0.113.7"))).await, None);

    // Against an explicit nameserver, so this reads no `/etc/resolv.conf` and
    // makes no query — building the resolver is what is under test.
    let on = Auditor::from_config(
        &AuditConfig {
            reverse_dns: true,
            reverse_dns_timeout_ms: 1,
            ..AuditConfig::default()
        },
        &acme_proxy_core::config::DnsConfig {
            resolver: Some("127.0.0.1:5399".to_string()),
        },
        database.clone(),
        metrics(database.clone()),
    )
    .unwrap();
    assert!(format!("{on:?}").contains("reverse_dns: true"));

    // The default `[dns]` path — the system configuration — is the one a real
    // deployment takes.
    let system = Auditor::from_config(
        &AuditConfig::default(),
        &dns,
        database.clone(),
        metrics(database),
    )
    .unwrap();
    assert!(format!("{system:?}").contains("reverse_dns: true"));
}

/// An auditor built the way the serving path builds one counts into the
/// registry it was given.
///
/// The regression test for a bug that shipped: the registry used to arrive
/// through a `with_metrics` builder, the serving path never called it, and
/// `acme_proxy_certificates_issued_total` therefore stayed at zero in
/// production while the whole suite passed — because the test harness wired
/// the registry itself, so what was under test was the harness rather than the
/// server. It is a constructor argument now, which makes the omission a
/// compile error; this pins the other half, that the argument is actually
/// used.
#[tokio::test]
async fn from_config_counts_into_the_registry_it_was_given() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let registry = metrics(database.clone());
    let auditor = Auditor::from_config(
        &AuditConfig {
            reverse_dns: false,
            ..AuditConfig::default()
        },
        &acme_proxy_core::config::DnsConfig::default(),
        database,
        registry.clone(),
    )
    .unwrap();

    auditor
        .record(AuditRecord::new(
            AuditEvent::CertificateIssued,
            "default",
            Actor::acme("acct-1"),
        ))
        .await;

    assert!(
        registry
            .render()
            .contains("acme_proxy_certificates_issued_total{role=\"acme,admin,worker\",profile=\"default\"} 1\n"),
        "the audit write did not reach the registry:\n{}",
        registry.render()
    );
}

/// A write against a closed pool is logged and swallowed: a certificate this CA
/// has already signed must not become a 500 the client retries into a second
/// issuance. The row is lost, loudly, and the request stands.
#[tokio::test]
async fn a_failed_write_does_not_propagate() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let auditor = Auditor::with_resolver(database.clone(), None, Duration::from_millis(50));
    database.close().await;

    // No panic, no error to handle — the point of the signature.
    auditor
        .record(AuditRecord::new(
            AuditEvent::CertificateIssued,
            "le",
            Actor::system(),
        ))
        .await;
    write(
        AuditRecord::new(AuditEvent::CertificateRevoked, "le", Actor::system()),
        &database,
    )
    .await;
}
