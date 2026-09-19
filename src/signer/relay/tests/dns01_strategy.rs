use super::*;
use crate::sqlite::status::OrderStatus;

/// A `DnsUpdater` that records what it was asked to publish, so a test can
/// assert on the record without a DNS server.
#[derive(Default)]
struct StubUpdater {
    published: std::sync::Mutex<Vec<(String, String)>>,
    deleted: std::sync::Mutex<Vec<(String, String)>>,
    /// When the last publish and the last retraction happened, so a test can
    /// measure what the relay did between the two.
    published_at: std::sync::Mutex<Option<std::time::Instant>>,
    deleted_at: std::sync::Mutex<Option<std::time::Instant>>,
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
        *self.published_at.lock().unwrap() = Some(std::time::Instant::now());
        Ok(())
    }
    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        self.deleted
            .lock()
            .unwrap()
            .push((name.to_string(), value.to_string()));
        *self.deleted_at.lock().unwrap() = Some(std::time::Instant::now());
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;

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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Invalid).await;
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
    let queue = test_queue(db.clone());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        )
        .unwrap(),
        updater.clone(),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;

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
    let thumbprint =
        acme_proxy_core::jws::signature::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    let expected =
        crate::challenge::dns_01::expected_value(&format!("upstream-token-value.{thumbprint}"));
    assert_eq!(value, &expected);

    // And the record must not be left behind.
    assert_eq!(updater.deleted.lock().unwrap().clone(), published);
}

/// Replaces the configured propagation wait on an already-built signer, the
/// `with_updater` way — a delay short enough for a test, which configuration
/// cannot express in whole seconds.
fn with_propagation(signer: RelaySigner, propagation: propagation::Propagation) -> RelaySigner {
    let inner = Arc::try_unwrap(signer.0).unwrap_or_else(|_| panic!("sole owner"));
    RelaySigner(Arc::new(Inner {
        dns01_propagation: propagation,
        ..inner
    }))
}

/// A configured delay sits between publishing the record and the trigger.
///
/// Measured from publish to retraction: cleanup runs only once the triggered
/// challenge has resolved, so a gap at least as long as the delay places the
/// wait before the trigger finished — and the code orders it before the
/// trigger started. Without the wait the gap is a few loopback round trips.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_waits_the_configured_delay_before_triggering() {
    const DELAY: Duration = Duration::from_millis(400);

    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let updater = Arc::new(StubUpdater::default());
    let queue = test_queue(db.clone());
    let signer = with_propagation(
        with_updater(
            RelaySigner::from_config(
                &config(&upstream, &dir),
                &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            )
            .unwrap(),
            updater.clone(),
        ),
        propagation::Propagation::Delay(DELAY),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;

    assert_eq!(upstream.challenge_triggered(), 1);
    let published_at = updater.published_at.lock().unwrap().expect("published");
    let deleted_at = updater.deleted_at.lock().unwrap().expect("retracted");
    assert!(
        deleted_at.duration_since(published_at) >= DELAY,
        "the challenge was answered {:?} after publishing, inside the {DELAY:?} delay",
        deleted_at.duration_since(published_at)
    );
}

/// A propagation setting that cannot work stops the server, before any
/// round trip to the upstream: an unknown mode, and a delay the attempt budget
/// (`poll_timeout_secs`, the job's lease) could never let finish.
#[tokio::test(flavor = "multi_thread")]
async fn an_unworkable_propagation_setting_is_a_startup_error() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");

    for (mode, delay_secs, expected) in [
        ("sometimes", 30, "propagation.mode: sometimes"),
        (
            "delay",
            5,
            "must be less than signer.relay.poll_timeout_secs",
        ),
    ] {
        let mut cfg = config(&upstream, &dir);
        cfg.challenge_strategy = "dns01".to_string();
        cfg.dns01.propagation.mode = mode.to_string();
        cfg.dns01.propagation.delay_secs = delay_secs;

        let error = startup_error(RelaySigner::from_config(
            &cfg,
            &relay_parts(
                database().await,
                no_notifiers(),
                test_queue(database().await),
            ),
        ));
        assert!(
            error.contains(expected),
            "expected {expected:?} in: {error}"
        );
    }
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
    let queue = test_queue(db.clone());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        )
        .unwrap(),
        updater.clone(),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Invalid).await;

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
    let queue = test_queue(db.clone());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        )
        .unwrap(),
        Arc::new(StubUpdater::default()),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(
        db.clone(),
        order.id.to_string().as_str(),
        OrderStatus::Invalid,
    )
    .await;

    let mapping = UpstreamOrder::find_by_order_id(order.id.to_string().as_str(), &db)
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
    let queue = test_queue(db.clone());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        )
        .unwrap(),
        Arc::new(StubUpdater {
            fail: true,
            ..StubUpdater::default()
        }),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Invalid).await;
    assert_eq!(
        upstream.challenge_triggered(),
        0,
        "nothing should be triggered when the record was never published"
    );
}

/// The regression: an upstream offering a challenge type this server does not
/// implement, ahead of the one it does.
///
/// Let's Encrypt began posing `dns-persist-01` beside the three familiar types,
/// and it carries no `token` — which is legal, since its TXT value derives from
/// the account URI. The relay's view of a challenge required one, so serde
/// failed the parse of the **whole** authorization and the `dns-01` challenge
/// next to it was never reached: every relayed order sat `processing` until the
/// client gave up. Nothing here is about `dns-persist-01` in particular; what is
/// asserted is that a type the relay does not answer cannot break an
/// authorization it does not participate in.
#[tokio::test(flavor = "multi_thread")]
async fn dns01_answers_past_a_challenge_type_carrying_no_token() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_tokenless_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let updater = Arc::new(StubUpdater::default());
    let queue = test_queue(db.clone());
    let signer = with_updater(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        )
        .unwrap(),
        updater.clone(),
    );
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;

    // The record published must still be the dns-01 one, derived from the
    // token of the challenge the relay actually answered.
    let thumbprint =
        acme_proxy_core::jws::signature::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    let expected = crate::challenge::dns_01::expected_value(&format!(
        "{}.{thumbprint}",
        testsrv::CHALLENGE_TOKEN
    ));
    assert_eq!(
        updater.published.lock().unwrap().clone(),
        vec![("_acme-challenge.example.com.".to_string(), expected)]
    );
    assert_eq!(upstream.challenge_triggered(), 1);
    assert_eq!(
        upstream.tokenless_triggered(),
        0,
        "the relay must never trigger a challenge it has no way to answer"
    );
}

/// Bypass triggers *something*, and with a tokenless type on offer that has to
/// be the one it could actually satisfy — an upstream validating out of band
/// still decides against the challenge it was told to look at.
#[tokio::test(flavor = "multi_thread")]
async fn bypass_prefers_a_challenge_it_could_answer() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_tokenless_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    let order = ready_order(db.clone()).await;

    signer
        .issue(
            order.id.to_string().as_str(),
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    await_status(db, order.id.to_string().as_str(), OrderStatus::Valid).await;

    assert_eq!(upstream.challenge_triggered(), 1);
    assert_eq!(upstream.tokenless_triggered(), 0);
}
