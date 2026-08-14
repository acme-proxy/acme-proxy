use super::*;

#[test]
fn the_kid_sidecar_sits_next_to_the_key() {
    assert_eq!(
        kid_path("/etc/acme/upstream.key"),
        PathBuf::from("/etc/acme/upstream.kid")
    );
    assert_eq!(kid_path("relative.key"), PathBuf::from("relative.kid"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_directory_url_is_a_startup_error() {
    let db = database().await;
    let error = startup_error(RelaySigner::from_config(
        &RelayConfig::default(),
        vec!["default".to_string()],
        db,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    ));
    assert!(error.contains("directory_url"), "{error}");
}

/// A strategy this server does not implement must stop it, not sit silent
/// until someone points it at a validating upstream.
///
/// Driven with a plausible *future* strategy rather than a typo, so the
/// test keeps meaning "a name that is not implemented is refused" as the
/// set grows.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_challenge_strategy_is_a_startup_error() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let mut cfg = config(&upstream, &dir);
    cfg.challenge_strategy = "tlsalpn01".to_string();

    let error = startup_error(RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        db,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    ));
    assert!(
        error.contains("challenge_strategy") && error.contains("tlsalpn01"),
        "{error}"
    );
    // The message is now the only place a reader learns the set.
    assert!(
        error.contains("bypass, dns01, http01"),
        "the refusal must name what IS supported: {error}"
    );
}

/// Selecting dns-01 without configuring a DNS provider must stop the
/// server at startup: the credential will never appear on its own, and
/// discovering it at the first certificate request is far worse.
#[tokio::test(flavor = "multi_thread")]
async fn the_dns01_strategy_needs_its_provider_configured() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let mut cfg = config(&upstream, &dir);
    cfg.challenge_strategy = "dns01".to_string();

    let error = startup_error(RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        db,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    ));
    assert!(error.contains("rfc2136.server"), "{error}");
}

/// First start registers and writes both files; the second must reuse them
/// and not register again — that is what keeps startup independent of the
/// upstream after the first time.
#[tokio::test(flavor = "multi_thread")]
async fn the_account_is_provisioned_once_and_then_reloaded() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let cfg = config(&upstream, &dir);

    let _first = RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    let key_file = PathBuf::from(cfg.account_key_path.clone());
    let kid_file = kid_path(&cfg.account_key_path);
    assert!(key_file.exists(), "the account key must be written");
    assert!(kid_file.exists(), "the kid sidecar must be written");
    let kid = std::fs::read_to_string(&kid_file).unwrap();
    let key = std::fs::read_to_string(&key_file).unwrap();

    let _second = RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        db,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(&kid_file).unwrap(), kid);
    assert_eq!(
        std::fs::read_to_string(&key_file).unwrap(),
        key,
        "a restart must not mint a second account key"
    );
}

/// The generated account key must not be world-readable, the same
/// guarantee `local_ca` gives its CA key.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_generated_account_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let cfg = config(&upstream, &dir);
    let _signer = RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();

    let mode = std::fs::metadata(&cfg.account_key_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
}

/// The whole point of the backend: a local order finalized here ends up
/// carrying a certificate the *upstream* issued.
#[tokio::test(flavor = "multi_thread")]
async fn issue_relays_the_order_and_finalizes_it_locally() {
    let chain = real_chain().await;
    let upstream = testsrv::start(Script {
        chain: chain.clone(),
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

    // Issuance returns immediately, before the upstream has finished.
    let outcome = signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, IssueOutcome::Processing));

    let settled = await_status(db.clone(), &order.id, "valid").await;
    assert_eq!(settled.certificate.as_deref(), Some(chain.as_str()));
    assert!(
        settled.cert_serial.is_some(),
        "the leaf's serial must be recorded"
    );
    assert!(
        settled.cert_pubkey.is_some(),
        "the leaf's SPKI must be recorded"
    );
    assert!(
        upstream.finalized() > 0,
        "the upstream must have been asked to finalize"
    );

    // And the mapping row records where it came from.
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.status, "valid");
    assert!(mapping.upstream_certificate_url.is_some());
}

/// A local order can be deleted by an operator between `issue` and the
/// upstream answering — the relay runs in a detached task. There is then
/// nothing to write the outcome onto, which must be survived quietly.
#[tokio::test(flavor = "multi_thread")]
async fn a_settle_for_an_order_that_vanished_is_survived() {
    let upstream = testsrv::start(Script::default()).await;
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

    settle(&signer.0, "ord-deleted", Ok(real_chain().await)).await;
}

/// The upstream is a foreign server: what it returns at the certificate URL
/// is not this server's to trust blindly. A body that is not a chain, or a
/// chain whose leaf will not parse, has to fail the local order rather than
/// be stored as a certificate no client can use.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_upstream_chain_fails_the_order() {
    use base64::prelude::*;

    let upstream = testsrv::start(Script::default()).await;
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

    // Not a PEM chain at all.
    let order = ready_order(db.clone()).await;
    settle(&signer.0, &order.id, Ok("not a PEM chain".to_string())).await;
    assert_eq!(
        Order::find_by_id(&order.id, &db)
            .await
            .unwrap()
            .unwrap()
            .status,
        "invalid"
    );

    // A well-formed PEM CERTIFICATE block whose DER is not a certificate:
    // past `leaf_der_from_chain`, and caught by the X.509 parse after it.
    let order = ready_order(db.clone()).await;
    let chain = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        BASE64_STANDARD.encode(b"not a certificate")
    );
    settle(&signer.0, &order.id, Ok(chain)).await;
    assert_eq!(
        Order::find_by_id(&order.id, &db)
            .await
            .unwrap()
            .unwrap()
            .status,
        "invalid"
    );
}

/// This is what actually proves the async-completion notification
/// mechanism works, not just compiles: one shared backend serves two
/// profiles, and `settle()` must dispatch `CertificateIssued` to the
/// *owning* profile's dispatcher only — the other profile's recorder must
/// stay empty.
#[tokio::test(flavor = "multi_thread")]
async fn settle_notifies_only_the_owning_profile() {
    let chain = real_chain().await;
    let upstream = testsrv::start(Script {
        chain: chain.clone(),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;

    let recorder_a = Arc::new(RecordingNotifyBackend::new());
    let recorder_b = Arc::new(RecordingNotifyBackend::new());
    let mut notifiers: HashMap<String, Arc<NotifyDispatcher>> = HashMap::new();
    notifiers.insert(
        "a".to_string(),
        Arc::new(NotifyDispatcher::new(vec![recorder_a.clone()])),
    );
    notifiers.insert(
        "b".to_string(),
        Arc::new(NotifyDispatcher::new(vec![recorder_b.clone()])),
    );

    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["a".to_string(), "b".to_string()],
        db.clone(),
        Arc::new(notifiers),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    let order = ready_order_for("a", db.clone()).await;

    let outcome = signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, IssueOutcome::Processing));

    await_status(db.clone(), &order.id, "valid").await;

    // The background task's own `dispatch()` spawns; give it a moment to
    // actually run before asserting on the recorder, the same technique
    // this file's other background-task assertions use.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let events_a = recorder_a.events.lock().unwrap();
    assert_eq!(
        events_a.len(),
        1,
        "profile `a` must be notified exactly once"
    );
    match &events_a[0] {
        NotifyEvent::CertificateIssued(data) => {
            assert_eq!(data.profile, "a");
            assert_eq!(data.order_id, order.id);
            assert!(data.client_ip.is_none(), "no request is in scope here");
        }
        other => panic!("expected CertificateIssued, got {other:?}"),
    }

    assert!(
        recorder_b.events.lock().unwrap().is_empty(),
        "profile `b` must not be notified of another profile's order"
    );
}

/// The upstream is allowed to take its time; the relay must keep polling
/// rather than giving up on the first non-terminal answer.
#[tokio::test(flavor = "multi_thread")]
async fn issue_polls_until_the_upstream_settles() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
        polls_before_ready: 2,
        polls_before_valid: 2,
        retry_after: true,
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
    assert!(
        upstream.order_polls() >= 4,
        "expected repeated polling, saw {}",
        upstream.order_polls()
    );
}

/// An upstream that refuses the order must leave the local order
/// terminally `invalid` with a problem document the client can read —
/// never stuck in `processing` forever.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_upstream_marks_the_order_invalid() {
    let upstream = testsrv::start(Script {
        order_fails: true,
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

    let settled = await_status(db.clone(), &order.id, "invalid").await;
    assert!(settled.error.is_some(), "the client must be told why");

    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.status, "invalid");
    assert!(
        mapping.error.unwrap().contains("invalid"),
        "the operator-facing row must record the upstream's reason"
    );
}

/// A relay that never settles must be cut off by the budget rather than
/// leaving the order processing indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_upstream_times_out_and_invalidates_the_order() {
    let upstream = testsrv::start(Script {
        // Far more polls than the budget allows.
        polls_before_ready: usize::MAX,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let mut cfg = config(&upstream, &dir);
    cfg.poll_timeout_secs = 1;
    let signer = RelaySigner::from_config(
        &cfg,
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

    await_status(db.clone(), &order.id, "invalid").await;
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        mapping.error.unwrap().contains("timed out"),
        "the timeout must be named, not reported as a generic failure"
    );
}

/// Two finalize requests racing on one order must not open two upstream
/// orders — the mapping row's primary key is the guard.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_issue_for_the_same_order_does_not_open_a_second_upstream_order() {
    let upstream = testsrv::start(Script {
        chain: real_chain().await,
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

    let first = signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    let second = signer
        .issue(
            &order.id,
            &csr_der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
        .unwrap();
    assert!(matches!(first, IssueOutcome::Processing));
    assert!(matches!(second, IssueOutcome::Processing));

    await_status(db.clone(), &order.id, "valid").await;
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        mapping.upstream_order_url,
        format!("{}/order/1", upstream.base)
    );
}

/// A CSR the upstream rejects is the client's mistake, so it must come
/// back as `BadCsr` — which leaves the local order `ready` and retryable —
/// rather than an internal error that invalidates it.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_bad_csr_surfaces_as_bad_csr() {
    let upstream = testsrv::start(Script {
        bad_csr: true,
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
    // The rejection happens at the upstream's finalize, inside the relay,
    // so it lands as an invalid order rather than an inline error.
    await_status(db, &order.id, "invalid").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_reaches_the_upstream() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();

    let chain = real_chain().await;
    let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
    signer.revoke(&leaf, Some(1)).await.unwrap();
    assert_eq!(upstream.revoked(), 1);
}

/// `SignerBackend::revoke` is contractually idempotent, so an upstream
/// already-revoked answer is success — a retry after a partial failure
/// must not surface as an error.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_treats_already_revoked_as_success() {
    let upstream = testsrv::start(Script {
        already_revoked: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();

    let leaf = crate::cert::leaf_der_from_chain(&real_chain().await).unwrap();
    signer
        .revoke(&leaf, None)
        .await
        .expect("alreadyRevoked must read as success");
}

/// The restart case: a row left `processing` by a dead process must be
/// picked up and carried to a certificate, without the original request.
#[tokio::test(flavor = "multi_thread")]
async fn resume_finishes_a_relay_left_behind_by_a_restart() {
    let chain = real_chain().await;
    let upstream = testsrv::start(Script {
        chain: chain.clone(),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let mut order = ready_order(db.clone()).await;

    // Stand in for what the previous process left behind: the order is
    // processing and the mapping row exists, but no task is running.
    order.mark_processing(&db).await.unwrap();
    UpstreamOrder::create(
        &order.id,
        &format!("{}/order/1", upstream.base),
        None,
        &csr_der(),
        &db,
    )
    .await
    .unwrap();

    // A fresh backend, as a restarted process would build.
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    signer.resume().await;

    let settled = await_status(db.clone(), &order.id, "valid").await;
    assert_eq!(settled.certificate.as_deref(), Some(chain.as_str()));
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.status, "valid");
}

/// Settled rows must be left alone: re-running a finished relay would
/// finalize an upstream order twice.
#[tokio::test(flavor = "multi_thread")]
async fn resume_ignores_rows_that_already_settled() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let order = ready_order(db.clone()).await;

    UpstreamOrder::create(
        &order.id,
        &format!("{}/order/1", upstream.base),
        None,
        &csr_der(),
        &db,
    )
    .await
    .unwrap();
    UpstreamOrder::mark_valid(&order.id, None, &db)
        .await
        .unwrap();

    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        db.clone(),
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    signer.resume().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        upstream.order_polls(),
        0,
        "a settled relay must not be touched again"
    );
}

/// Nothing to resume is the common case and must be silent and harmless.
#[tokio::test(flavor = "multi_thread")]
async fn resume_with_no_pending_rows_does_nothing() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        test_resolver(),
        crate::testutil::no_proxies(),
    )
    .unwrap();
    signer.resume().await;
    assert_eq!(upstream.order_polls(), 0);
}
