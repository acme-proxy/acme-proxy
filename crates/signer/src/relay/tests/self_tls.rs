//! The server ordering a certificate for **its own** listener.
//!
//! Same upstream, same `dns-01` answering, one difference that matters: the
//! order belongs to nobody but this process, so there is no local order to
//! settle and no client to notify. These tests therefore assert on the upstream's
//! counters and on what the stub updater saw — the two things that show an
//! issuance really happened, which is what [`super::dns01_strategy`] proves for a
//! client's issuance by other means.

use super::*;

/// The name a listener certificate is asked for here.
///
/// Deliberately not `example.com`, the identifier the scripted upstream names its
/// authorization with: a test has to be able to tell the name this server asked
/// for apart from whatever the upstream answered with.
const LISTENER: &str = "acme.int.example.com";

/// A signer answering `dns-01` through `updater`, against `upstream`.
async fn dns01_signer(upstream: &Upstream, updater: Arc<StubUpdater>) -> RelaySigner {
    let dir = TempDir::new("self-tls");
    let db = database().await;
    with_updater(
        RelaySigner::from_config(
            &config(upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        )
        .unwrap(),
        updater,
    )
}

/// One issuance, which is what every case below varies: the strategy, the
/// updater's health, or the upstream's cooperation.
async fn issue(signer: &RelaySigner) -> Result<String, SelfTlsError> {
    signer
        .relay_state()
        .expect("a relay backend always has state to hand over")
        .issue_listener_certificate(LISTENER, &csr_der())
        .await
}

/// The whole path against an upstream that poses a challenge: order, publish,
/// trigger, finalize, download — and the record left behind on neither side.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_publishes_answers_and_returns_the_chain() {
    let chain = real_chain().await;
    let upstream = testsrv::start(Script {
        chain: chain.clone(),
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let updater = Arc::new(StubUpdater::default());
    let signer = dns01_signer(&upstream, updater.clone()).await;

    let obtained = match issue(&signer).await {
        Ok(chain) => chain,
        Err(error) => panic!("the issuance must succeed, failed: {error}"),
    };
    assert_eq!(obtained, chain, "the chain is what the upstream issued");

    // One order, opened for this server alone: no local order stands behind it,
    // which is the whole difference from a relayed issuance.
    assert_eq!(upstream.orders_opened(), 1);
    assert_eq!(upstream.finalized(), 1);
    assert_eq!(upstream.challenge_triggered(), 1);

    // The record is published at the authorization's own name — the scripted
    // upstream names it `example.com` whatever was asked for, as a real CA names
    // the authorization it hands back — with the digest of *this* proxy's key
    // authorization, and retracted afterwards.
    let thumbprint =
        acme_proxy_core::jws::signature::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    let expected = acme_proxy_net::challenge::dns_01::expected_value(&format!(
        "{}.{thumbprint}",
        testsrv::CHALLENGE_TOKEN
    ));
    let published = updater.published.lock().unwrap().clone();
    assert_eq!(
        published,
        vec![("_acme-challenge.example.com.".to_string(), expected)]
    );
    assert_eq!(
        updater.deleted.lock().unwrap().clone(),
        published,
        "a finished issuance takes its record back down"
    );
}

/// The refusal an operator has to be able to read: a profile answering `http-01`
/// or `bypass` upstream cannot obtain the listener certificate, and saying so
/// must not cost an upstream order to find out.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_refuses_a_strategy_that_cannot_publish() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    // The default strategy, `bypass`: a backend that publishes nothing at all.
    let dir = TempDir::new("self-tls-bypass");
    let db = database().await;
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
    )
    .unwrap();

    let (retryable, reason) = refused(issue(&signer).await);
    assert!(!retryable, "a strategy problem is not bad luck: {reason}");
    assert!(
        reason.contains("dns01"),
        "the refusal has to name the key that fixes it: {reason}"
    );
    assert_eq!(
        upstream.orders_opened(),
        0,
        "refusing must not spend an order from the CA's weekly allowance"
    );
}

/// A DNS API that refused the update is the commonest failure on this path, and
/// the caller has to be told it is worth another try.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_reports_a_publish_failure_as_retryable() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let updater = Arc::new(StubUpdater {
        fail: true,
        ..StubUpdater::default()
    });
    let signer = dns01_signer(&upstream, updater).await;

    let (retryable, reason) = refused(issue(&signer).await);
    assert!(
        retryable,
        "an unpublished record may publish next time: {reason}"
    );
    assert!(reason.contains("_acme-challenge.example.com."), "{reason}");
    assert_eq!(upstream.finalized(), 0, "nothing to finalize");
    assert_eq!(upstream.challenge_triggered(), 0, "nothing to validate");
}

/// An upstream offering only `http-01` cannot be answered by this server — the
/// listener that would have to serve the token is what the certificate is *for*
/// — so the refusal is permanent and names the offer.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_refuses_an_upstream_offering_no_dns01() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_http01: true,
        ..Script::default()
    })
    .await;
    let signer = dns01_signer(&upstream, Arc::new(StubUpdater::default())).await;

    let (retryable, reason) = refused(issue(&signer).await);
    assert!(!retryable, "the CA's offer will not change: {reason}");
    assert!(reason.contains("no dns-01 challenge"), "{reason}");
    assert_eq!(upstream.finalized(), 0);
}

/// An order that reaches `valid` without advertising where its certificate is
/// has nowhere to fetch from. Nothing published is left behind either, which is
/// the part a caller cannot check for itself.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_reports_an_order_with_no_certificate_url() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        omit_certificate_url: true,
        ..Script::default()
    })
    .await;
    let updater = Arc::new(StubUpdater::default());
    let signer = dns01_signer(&upstream, updater.clone()).await;

    let (retryable, reason) = refused(issue(&signer).await);
    assert!(!retryable, "{reason}");
    assert!(reason.contains("no certificate URL"), "{reason}");
    assert_eq!(
        updater.deleted.lock().unwrap().len(),
        1,
        "a failed issuance must not leave a TXT record behind"
    );
}

/// An order the upstream opened but did not name: there is no URL to poll, no URL
/// to finalize and nothing asking again would change, so the refusal is permanent
/// and the TXT record is already retracted by the time it is reported.
#[tokio::test(flavor = "multi_thread")]
async fn self_tls_reports_a_new_order_with_no_location() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        omit_order_location: true,
        ..Script::default()
    })
    .await;
    let updater = Arc::new(StubUpdater::default());
    let signer = dns01_signer(&upstream, updater.clone()).await;

    let (retryable, reason) = refused(issue(&signer).await);
    assert!(!retryable, "{reason}");
    assert!(reason.contains("no Location header"), "{reason}");
    assert_eq!(upstream.order_polls(), 0, "there is no order to poll");
    assert!(
        updater.published.lock().unwrap().is_empty(),
        "no record is published for an order that has no URL"
    );
}

/// The refusal's text, and which half of [`SelfTlsError`] it was.
fn refused(result: Result<String, SelfTlsError>) -> (bool, String) {
    match result {
        Ok(chain) => panic!("this configuration must not issue, got a chain: {chain}"),
        Err(SelfTlsError::Retryable(reason)) => (true, reason),
        Err(SelfTlsError::Permanent(reason)) => (false, reason),
    }
}
