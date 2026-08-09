//! Tests for the audit vocabulary and the reverse lookup.
//!
//! The *write* is exercised through `src/sqlite/audit.rs` (the model) and
//! `tests/audit.rs` (the whole router), so what is left here is the part with
//! no database in it: the enums the schema's `CHECK` constraints mirror, the
//! request-context gathering, and every way a PTR lookup can fail.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::*;
use crate::dns::Resolver;
use crate::sqlite::db::Database;

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

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

/// The stored strings and the success/failure split are what the migration's
/// two `CHECK` constraints are written against, so a rename here that is not
/// mirrored there parks every row in a state SQLite refuses to insert.
#[test]
fn every_event_round_trips_through_its_stored_form_and_knows_its_outcome() {
    for event in ALL_AUDIT_EVENTS {
        assert_eq!(
            AuditEvent::parse(event.as_str()),
            Some(*event),
            "{} did not round-trip",
            event.as_str()
        );
    }
    assert_eq!(AuditEvent::CertificateIssued.outcome(), "success");
    assert_eq!(AuditEvent::CertificateRevoked.outcome(), "success");
    assert_eq!(AuditEvent::CertificateIssueFailed.outcome(), "failure");
    assert_eq!(AuditEvent::CertificateRevokeFailed.outcome(), "failure");
    assert_eq!(AuditEvent::parse("certificate_renewed"), None);
    assert_eq!(AuditEvent::parse(""), None);
}

/// `actor_kind`'s own `CHECK`, and the one distinction the column exists for:
/// an accountless RFC 8555 §7.6 revocation is still an `acme` actor, just one
/// with nothing to name.
#[test]
fn the_actor_kinds_match_the_schema_and_only_two_carry_no_id() {
    assert_eq!(Actor::acme("acct-1").kind.as_str(), "acme");
    assert_eq!(Actor::acme("acct-1").id.as_deref(), Some("acct-1"));

    let accountless = Actor::acme_certificate_key();
    assert_eq!(accountless.kind.as_str(), "acme");
    assert_eq!(accountless.id, None);

    assert_eq!(Actor::admin("root").kind.as_str(), "admin");
    assert_eq!(Actor::admin("root").id.as_deref(), Some("root"));

    let system = Actor::system();
    assert_eq!(system.kind.as_str(), "system");
    assert_eq!(system.id, None);

    // `cli` reads the environment, so only its kind is asserted — the value is
    // whatever the runner's `$USER` happens to be, including absent.
    assert_eq!(Actor::cli().kind.as_str(), "cli");
}

/// `User-Agent` is attacker-controlled and lands in a database column and an
/// HTML page, so it gets a ceiling; an empty one is `None` rather than `""`,
/// which is what keeps "sent nothing" and "sent a blank header" the same row.
#[test]
fn the_request_context_caps_the_user_agent_and_drops_an_empty_one() {
    let request = |value: &str| {
        let mut builder = axum::http::Request::builder();
        if !value.is_empty() {
            builder = builder.header(axum::http::header::USER_AGENT, value);
        }
        let mut request = builder.body(()).unwrap();
        request
            .extensions_mut()
            .insert(crate::filter::ClientIp(Some(ip("203.0.113.7"))));
        request
            .extensions_mut()
            .insert(crate::middlewares::access::RequestId("req-9".to_string()));
        RequestContext::from_request(&request)
    };

    let long = "u".repeat(USER_AGENT_MAX * 3);
    let context = request(&long);
    assert_eq!(context.user_agent.as_ref().unwrap().chars().count(), 256);
    assert_eq!(context.ip, Some(ip("203.0.113.7")));
    assert_eq!(context.request_id.as_deref(), Some("req-9"));

    assert_eq!(request("").user_agent, None);
    assert_eq!(
        request("certbot/2.9.0").user_agent.as_deref(),
        Some("certbot/2.9.0")
    );
}

/// Nothing in the request means an entirely empty context rather than a
/// half-filled one — a `cli`-shaped row arriving over HTTP.
#[test]
fn a_request_with_no_extensions_yields_an_empty_context() {
    let request = axum::http::Request::builder().body(()).unwrap();
    let context = RequestContext::from_request(&request);
    assert_eq!(context.ip, None);
    assert_eq!(context.user_agent, None);
    assert_eq!(context.request_id, None);
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

/// The builders exist so the four events can populate different subsets; this
/// pins that an untouched field stays absent rather than becoming empty.
#[test]
fn a_record_carries_only_what_was_set_on_it() {
    let record = AuditRecord::new(AuditEvent::CertificateIssued, "le", Actor::admin("root"));
    assert_eq!(record.profile, "le");
    assert!(record.account_id.is_none());
    assert!(record.order_id.is_none());
    assert!(record.cert_serial.is_none());
    assert!(record.identifiers.is_empty());
    assert!(record.reason.is_none());
    assert!(record.detail.is_none());
    assert_eq!(record.client, ClientContext::default());

    let record = record
        .with_account("acct-1")
        .with_serial("0a0b")
        .with_reason("badCSR")
        .with_detail("nope");
    assert_eq!(record.account_id.as_deref(), Some("acct-1"));
    assert_eq!(record.cert_serial.as_deref(), Some("0a0b"));
    assert_eq!(record.reason.as_deref(), Some("badCSR"));
    assert_eq!(record.detail.as_deref(), Some("nope"));
}

/// `with_order` is the one builder that reads another model: it freezes the
/// identifiers into the row so the trail survives the order being deleted.
#[test]
fn with_order_freezes_the_identifiers_rather_than_leaving_a_reference() {
    let order = crate::sqlite::order::Order::new(
        "le",
        "acct-7",
        vec![
            crate::sqlite::order::Identifier::dns("a.example.com"),
            crate::sqlite::order::Identifier::dns("*.example.com"),
        ],
        0,
        None,
        None,
    );
    let record =
        AuditRecord::new(AuditEvent::CertificateIssued, "le", Actor::system()).with_order(&order);

    assert_eq!(record.order_id.as_deref(), Some(order.id.as_str()));
    assert_eq!(record.account_id.as_deref(), Some("acct-7"));
    assert_eq!(record.identifiers, vec!["a.example.com", "*.example.com"]);
}

/// `from_config`'s two shapes, the same way `filter::reverse_dns::from_config`
/// is exercised: with the lookup on it builds a **cached** resolver (from
/// `dns.resolver` when set, from the system configuration otherwise), and with
/// it off there is no resolver to build at all.
#[tokio::test]
async fn from_config_builds_a_resolver_only_when_the_lookup_is_on() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let dns = crate::config::DnsConfig::default();

    let off = Auditor::from_config(
        &AuditConfig {
            reverse_dns: false,
            ..AuditConfig::default()
        },
        &dns,
        database.clone(),
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
        &crate::config::DnsConfig {
            resolver: Some("127.0.0.1:5399".to_string()),
        },
        database.clone(),
    )
    .unwrap();
    assert!(format!("{on:?}").contains("reverse_dns: true"));

    // The default `[dns]` path — the system configuration — is the one a real
    // deployment takes.
    let system = Auditor::from_config(&AuditConfig::default(), &dns, database).unwrap();
    assert!(format!("{system:?}").contains("reverse_dns: true"));
}

/// A write against a closed pool is logged and swallowed: a certificate this CA
/// has already signed must not become a 500 the client retries into a second
/// issuance. The row is lost, loudly, and the request stands.
#[tokio::test]
async fn a_failed_write_does_not_propagate() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let auditor = Auditor::with_resolver(database.clone(), None, Duration::from_millis(50));
    database.pool.close().await;

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
