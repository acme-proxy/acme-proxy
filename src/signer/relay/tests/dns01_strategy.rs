use super::*;

/// A `DnsUpdater` that records what it was asked to publish, so a test can
/// assert on the record without a DNS server.
#[derive(Default)]
struct StubUpdater {
    published: std::sync::Mutex<Vec<(String, String)>>,
    deleted: std::sync::Mutex<Vec<(String, String)>>,
    fail: bool,
}

#[async_trait]
impl dns01::DnsUpdater for StubUpdater {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String> {
        if self.fail {
            return Err("no DNS for you".to_string());
        }
        self.published
            .lock()
            .unwrap()
            .push((name.to_string(), value.to_string()));
        Ok(())
    }
    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        self.deleted
            .lock()
            .unwrap()
            .push((name.to_string(), value.to_string()));
        Ok(())
    }
}

/// Swaps the strategy on an already-built signer, so these tests do not
/// need a live RFC 2136 server to exercise the orchestration around it.
fn with_updater(signer: RelaySigner, updater: Arc<StubUpdater>) -> RelaySigner {
    let inner = Arc::try_unwrap(signer.0).unwrap_or_else(|_| panic!("sole owner"));
    RelaySigner(Arc::new(Inner {
        strategy: ChallengeStrategy::Dns01(updater),
        ..inner
    }))
}

/// The `bypass` strategy against an upstream that *does* pose a challenge.
///
/// Bypass does not mean "the upstream asks nothing" — it means this server
/// publishes nothing and simply triggers whatever is offered, which is the
/// right behaviour against an upstream validating by some out-of-band
/// arrangement. Whichever challenge comes first is triggered, without
/// caring about its type.
#[tokio::test(flavor = "multi_thread")]
async fn bypass_triggers_the_offered_challenge() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    // No `with_updater`: the default strategy is bypass.
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "valid").await;

    assert_eq!(
        upstream.challenge_triggered(),
        1,
        "bypass still has to trigger the challenge the upstream posed"
    );
}

/// Bypass is type-agnostic: an `http-01`-only authorization is triggered
/// just the same, where the `dns01` strategy refuses it for lack of a
/// record it could publish.
#[tokio::test(flavor = "multi_thread")]
async fn bypass_triggers_a_challenge_of_any_type() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_http01: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "valid").await;
}

/// A rejected challenge fails the order rather than hanging: under bypass
/// there is nothing to retract, so the only thing to get right is that the
/// failure reaches the local order.
#[tokio::test(flavor = "multi_thread")]
async fn bypass_fails_the_order_when_the_upstream_rejects() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        fail_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "invalid").await;
}

/// The dns-01 path end to end: publish the record the upstream asked for,
/// trigger it, and clean up afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_publishes_triggers_and_cleans_up() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let updater = Arc::new(StubUpdater::default());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap(),
        updater.clone(),
    );
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "valid").await;

    assert_eq!(
        upstream.challenge_triggered(),
        1,
        "the challenge must be triggered"
    );

    let published = updater.published.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    let (name, value) = &published[0];
    assert_eq!(name, "_acme-challenge.example.com.");

    // The value must be the digest of a key authorization built from THIS
    // proxy's thumbprint at the upstream — not the end client's, which is
    // the whole reason the client cannot answer this itself.
    let thumbprint = crate::extractors::acme::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    let expected =
        crate::challenge::dns_01::expected_value(&format!("upstream-token-value.{thumbprint}"));
    assert_eq!(value, &expected);

    // And the record must not be left behind.
    assert_eq!(updater.deleted.lock().unwrap().clone(), published);
}

/// The record must be retracted even when validation fails, so a failed
/// attempt does not litter the zone.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_cleans_up_after_a_rejected_challenge() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        fail_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let updater = Arc::new(StubUpdater::default());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap(),
        updater.clone(),
    );
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "invalid").await;

    assert_eq!(
        updater.deleted.lock().unwrap().len(),
        1,
        "a failed attempt must still retract its record"
    );
}

/// An upstream offering no dns-01 cannot be satisfied by this server, and
/// must say so rather than trying a challenge it cannot answer.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_refuses_an_upstream_offering_only_http01() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        offer_http01: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap(),
        Arc::new(StubUpdater::default()),
    );
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db.clone(), &order.id, "invalid").await;

    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        mapping.error.unwrap().contains("no dns-01"),
        "the reason must name what was missing"
    );
    assert_eq!(upstream.challenge_triggered(), 0);
}

/// A DNS provider that cannot publish must fail the order rather than
/// triggering a challenge that is guaranteed to fail.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_fails_when_the_record_cannot_be_published() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
            crate::testutil::no_proxies(),
        )
        .unwrap(),
        Arc::new(StubUpdater {
            fail: true,
            ..StubUpdater::default()
        }),
    );
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, &order.id, "invalid").await;
    assert_eq!(
        upstream.challenge_triggered(),
        0,
        "nothing should be triggered when the record was never published"
    );
}
