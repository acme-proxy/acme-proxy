//! Tests for the audit vocabulary: the enums the stored strings and the
//! schema's `CHECK` constraints mirror, the request-context gathering, and the
//! record builders. The writer and its reverse lookup are `auditor`'s.

use std::net::IpAddr;

use super::*;

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

/// The stored strings are the `audit_log.event` vocabulary (no `CHECK` mirrors
/// them any more — `AuditEvent` is the authority), and the success/failure
/// split is what the `outcome` `CHECK` still guards.
#[test]
fn every_event_round_trips_through_its_stored_form_and_knows_its_outcome() {
    for event in ALL_AUDIT_EVENTS {
        assert_eq!(
            AuditEvent::parse(event.as_str()),
            Some(*event),
            "{} did not round-trip",
            event.as_str()
        );
        assert!(
            matches!(event.outcome(), "success" | "failure"),
            "{} has no outcome",
            event.as_str()
        );
    }
    assert_eq!(AuditEvent::CertificateIssued.outcome(), "success");
    assert_eq!(AuditEvent::CertificateRevoked.outcome(), "success");
    assert_eq!(AuditEvent::CertificateIssueFailed.outcome(), "failure");
    assert_eq!(AuditEvent::CertificateRevokeFailed.outcome(), "failure");
    // Every administrative action is recorded only on success.
    assert_eq!(AuditEvent::AccountDeleted.outcome(), "success");
    assert_eq!(AuditEvent::OperatorDisabled.outcome(), "success");
    assert_eq!(AuditEvent::SessionRevoked.outcome(), "success");
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
            .insert(crate::client::ClientIp(Some(ip("203.0.113.7"))));
        request
            .extensions_mut()
            .insert(crate::client::RequestId("req-9".to_string()));
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
    let (order_id, account) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    let identifiers = [
        crate::identifier::Identifier::dns("a.example.com"),
        crate::identifier::Identifier::dns("*.example.com"),
    ];
    let record = AuditRecord::new(AuditEvent::CertificateIssued, "le", Actor::system()).with_order(
        order_id,
        account,
        &identifiers,
    );

    assert_eq!(record.order_id, Some(order_id.to_string()));
    assert_eq!(record.account_id, Some(account.to_string()));
    assert_eq!(record.identifiers, vec!["a.example.com", "*.example.com"]);
}
