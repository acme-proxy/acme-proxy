use super::*;
use crate::sqlite::status::OrderStatus;

/// Serves `tokens` from the **production** handler on an ephemeral loopback
/// port, so the scripted upstream fetches what a deployment would.
///
/// The handler and the route path are the real ones; only `build_app`'s
/// surrounding profile machinery is skipped — building it here would need a
/// `FilterPolicy`, a `ChallengeRegistry` and a `NotifyDispatcher` for no
/// added coverage, and `tests/http01_responder.rs` covers the mounting
/// against the real `build_app` instead.
async fn spawn_responder(tokens: Arc<dyn http01::TokenStore>) -> String {
    let app = axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(crate::handlers::get_challenge_file),
        )
        .with_state(crate::handlers::Http01Stores(Arc::new(vec![tokens])));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// The http-01 path end to end, with the upstream really fetching the file:
/// publish the key authorization, serve it, trigger, and retract.
#[tokio::test(flavor = "multi_thread")]
async fn http01_serves_the_key_authorization_triggers_and_retracts() {
    let tokens = Arc::new(StubTokens::default());
    let responder = spawn_responder(tokens.clone()).await;
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_http01: true,
        http01_responder: Some(responder),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = with_tokens(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        tokens.clone(),
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

    // The served body must be the key authorization VERBATIM — no digest,
    // unlike dns-01 — built from THIS proxy's thumbprint at the upstream,
    // which is the whole reason the end client cannot answer this itself.
    let thumbprint = crate::extractors::acme::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    assert_eq!(
        upstream.http01_body(),
        Some(format!("{}.{thumbprint}", testsrv::CHALLENGE_TOKEN)),
        "the upstream must have read the exact key authorization off the responder"
    );

    let published = tokens.published.lock().unwrap().clone();
    assert_eq!(
        published,
        vec![(
            testsrv::CHALLENGE_TOKEN.to_string(),
            format!("{}.{thumbprint}", testsrv::CHALLENGE_TOKEN),
        )]
    );
    assert_eq!(
        tokens.retracted.lock().unwrap().clone(),
        vec![testsrv::CHALLENGE_TOKEN.to_string()],
        "the token must not stay fetchable after the attempt"
    );
}

/// The token must be retracted even when validation fails, so a failed
/// attempt does not leave a live key authorization behind.
#[tokio::test(flavor = "multi_thread")]
async fn http01_retracts_after_a_rejected_challenge() {
    let tokens = Arc::new(StubTokens::default());
    let responder = spawn_responder(tokens.clone()).await;
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        offer_http01: true,
        fail_challenge: true,
        http01_responder: Some(responder),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = with_tokens(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        tokens.clone(),
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
        tokens.retracted.lock().unwrap().len(),
        1,
        "a failed attempt must still retract its token"
    );
    assert!(
        tokens.lookup(testsrv::CHALLENGE_TOKEN).is_none(),
        "nothing must remain fetchable"
    );
}

/// The mirror of `dns01_refuses_an_upstream_offering_only_http01`: an
/// upstream offering no http-01 must be reported, not answered with a
/// challenge type this strategy cannot serve.
#[tokio::test(flavor = "multi_thread")]
async fn http01_refuses_an_upstream_offering_only_dns01() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = with_tokens(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        Arc::new(StubTokens::default()),
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
        mapping.error.unwrap().contains("no http-01"),
        "the reason must name what was missing"
    );
    assert_eq!(upstream.challenge_triggered(), 0);
}

/// `http-01` fetches from the identifier itself, so nothing can answer for
/// `*.example.com`. The refusal must name the wildcard rather than blaming
/// the challenge list — a CA correctly offers dns-01 alone for one.
#[tokio::test(flavor = "multi_thread")]
async fn http01_refuses_a_wildcard_authorization() {
    let upstream = testsrv::start(Script {
        pose_challenge: true,
        offer_http01: true,
        wildcard_identifier: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = with_tokens(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        Arc::new(StubTokens::default()),
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
    let error = mapping.error.unwrap();
    assert!(
        error.contains("wildcard") && error.contains("dns01"),
        "the reason must name the wildcard and point at the strategy that can: {error}"
    );
    assert_eq!(upstream.challenge_triggered(), 0);
}

/// A bad DNS provider name must stop the server, not be discovered on the
/// first certificate request.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_dns_provider_is_a_startup_error() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let mut cfg = config(&upstream, &dir);
    cfg.challenge_strategy = "dns01".to_string();
    cfg.dns01.provider = "route53".to_string();

    let error = startup_error(RelaySigner::from_config(
        &cfg,
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(error.contains("route53"), "{error}");
}

/// The key authorizations published for the upstream survive a configuration
/// reload that rebuilt this backend.
///
/// The half of `CarriedState` that has no durable home at all. A multi-
/// perspective CA may have a fetch in flight for a token published seconds ago,
/// and an empty store answers it `404` — failing an issuance over a
/// configuration change that had nothing to do with it.
// Multi-threaded, like every other test here that really provisions: the first
// build blocks its thread on `thread::scope` while the scripted upstream needs
// the runtime to answer it.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_carries_the_published_key_authorizations_across() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let mut cfg = config(&upstream, &dir);
    cfg.challenge_strategy = "http01".to_string();

    let parts = relay_parts(
        database().await,
        no_notifiers(),
        test_queue(database().await),
    );
    let build = |cfg: &RelayConfig, carried: &crate::signer::CarriedState| {
        RelaySigner::from_config(cfg, &parts, carried).unwrap()
    };

    let running = build(&cfg, &crate::signer::CarriedState::new());
    running
        .http01_tokens()
        .expect("the http01 strategy has a store")
        .publish("tok", "tok.thumbprint");

    // The operator edits an unrelated key and signals.
    let mut edited = cfg;
    edited.poll_interval_ms += 1;
    let reloaded = build(&edited, &running.carried_state());
    assert_eq!(
        reloaded
            .http01_tokens()
            .expect("still the http01 strategy")
            .lookup("tok"),
        Some("tok.thumbprint".to_string()),
        "a fetch already in flight must still be answerable after the reload",
    );

    // A strategy switched *away* from http01 offers nothing on, so switching
    // back starts empty rather than resurrecting a token nobody is serving.
    let mut bypassing = edited.clone();
    bypassing.challenge_strategy = "bypass".to_string();
    let intermediate = build(&bypassing, &reloaded.carried_state());
    assert!(intermediate.http01_tokens().is_none());

    let back = build(&edited, &intermediate.carried_state());
    assert!(
        back.http01_tokens()
            .expect("http01 again")
            .lookup("tok")
            .is_none(),
        "nothing was live to carry: the intermediate backend served no tokens",
    );
}

/// The `dns01_strategy` regression's twin: a tokenless challenge type ahead of
/// the `http-01` one must not stop the relay reading past it, and the key
/// authorization served has to stay bound to the `http-01` token.
#[tokio::test(flavor = "multi_thread")]
async fn http01_answers_past_a_challenge_type_carrying_no_token() {
    let tokens = Arc::new(StubTokens::default());
    let responder = spawn_responder(tokens.clone()).await;
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        pose_challenge: true,
        offer_http01: true,
        offer_tokenless_challenge: true,
        http01_responder: Some(responder),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = with_tokens(
        RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), queue.clone()),
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        tokens.clone(),
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

    let thumbprint = crate::extractors::acme::jwk_thumbprint(signer.0.account.spki_der()).unwrap();
    assert_eq!(
        upstream.http01_body(),
        Some(format!("{}.{thumbprint}", testsrv::CHALLENGE_TOKEN)),
        "the body served must come from the http-01 token, not the entry beside it"
    );
    assert_eq!(upstream.tokenless_triggered(), 0);
}
