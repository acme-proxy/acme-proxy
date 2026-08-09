use super::*;

/// A `TokenStore` that records what it was asked to publish *and* answers
/// lookups, so one type both drives the real responder route and carries
/// the assertions.
#[derive(Default)]
struct StubTokens {
    published: std::sync::Mutex<Vec<(String, String)>>,
    retracted: std::sync::Mutex<Vec<String>>,
    live: std::sync::Mutex<HashMap<String, String>>,
}

impl http01::TokenStore for StubTokens {
    fn publish(&self, token: &str, key_authorization: &str) {
        self.published
            .lock()
            .unwrap()
            .push((token.to_string(), key_authorization.to_string()));
        self.live
            .lock()
            .unwrap()
            .insert(token.to_string(), key_authorization.to_string());
    }
    fn retract(&self, token: &str) {
        self.retracted.lock().unwrap().push(token.to_string());
        self.live.lock().unwrap().remove(token);
    }
    fn lookup(&self, token: &str) -> Option<String> {
        self.live.lock().unwrap().get(token).cloned()
    }
}

/// The twin of [`with_updater`], for the `http01` strategy.
fn with_tokens(signer: AcmeProxySigner, tokens: Arc<StubTokens>) -> AcmeProxySigner {
    let inner = Arc::try_unwrap(signer.0).unwrap_or_else(|_| panic!("sole owner"));
    AcmeProxySigner(Arc::new(Inner {
        strategy: ChallengeStrategy::Http01(tokens),
        ..inner
    }))
}

/// Serves `tokens` from the **production** handler on an ephemeral loopback
/// port, so the scripted upstream fetches what a deployment would.
///
/// The handler and the route path are the real ones; only `build_app`'s
/// surrounding profile machinery is skipped — building it here would need a
/// `FilterChain`, a `ChallengeRegistry` and a `NotifyDispatcher` for no
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
    let signer = with_tokens(
        AcmeProxySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
        )
        .unwrap(),
        tokens.clone(),
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
    let signer = with_tokens(
        AcmeProxySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
        )
        .unwrap(),
        tokens.clone(),
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
    let signer = with_tokens(
        AcmeProxySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
        )
        .unwrap(),
        Arc::new(StubTokens::default()),
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
    let signer = with_tokens(
        AcmeProxySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            db.clone(),
            no_notifiers(),
            test_resolver(),
        )
        .unwrap(),
        Arc::new(StubTokens::default()),
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

    let error = startup_error(AcmeProxySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        test_resolver(),
    ));
    assert!(error.contains("route53"), "{error}");
}
