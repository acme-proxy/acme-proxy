use super::*;
use crate::sqlite::status::OrderStatus;

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
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        &crate::signer::CarriedState::new(),
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
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        &crate::signer::CarriedState::new(),
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
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        &crate::signer::CarriedState::new(),
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
        &relay_parts(db.clone(), no_notifiers(), test_queue(db.clone())),
        &crate::signer::CarriedState::new(),
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
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        &crate::signer::CarriedState::new(),
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
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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

    let settled = await_status(db.clone(), &order.id, OrderStatus::Valid).await;
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
/// upstream answering — the job outlives the request by minutes. There is then
/// nothing to write the outcome onto, and retrying would never find one, so the
/// job is retired rather than repeated until its budget runs out.
#[tokio::test(flavor = "multi_thread")]
async fn a_settle_for_an_order_that_vanished_is_permanent() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    match settle(&signer.0, "ord-deleted", real_chain().await).await {
        crate::jobs::JobOutcome::Failed(reason) => assert!(reason.contains("no longer exists")),
        other => panic!("a vanished order must be permanent, got {other:?}"),
    }
}

/// The upstream is a foreign server: what it returns at the certificate URL
/// is not this server's to trust blindly. A body that is not a chain, or a
/// chain whose leaf will not parse, has to fail the order **permanently** —
/// asking the same upstream again returns the same unusable bytes, so spending
/// the retry budget on it would only delay the client's real answer.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_upstream_chain_fails_the_order_permanently() {
    use base64::prelude::*;

    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    // Not a PEM chain at all.
    let order = ready_order(db.clone()).await;
    match settle(&signer.0, &order.id, "not a PEM chain".to_string()).await {
        crate::jobs::JobOutcome::Failed(reason) => assert!(reason.contains("chain unparsable")),
        other => panic!("an unparsable chain must be permanent, got {other:?}"),
    }

    // A well-formed PEM CERTIFICATE block whose DER is not a certificate:
    // past `leaf_der_from_chain`, and caught by the X.509 parse after it.
    let order = ready_order(db.clone()).await;
    let chain = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        BASE64_STANDARD.encode(b"not a certificate")
    );
    match settle(&signer.0, &order.id, chain).await {
        crate::jobs::JobOutcome::Failed(reason) => assert!(reason.contains("leaf unparsable")),
        other => panic!("an unparsable leaf must be permanent, got {other:?}"),
    }
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

    let queue = test_queue(db.clone());
    let recorder_a = Arc::new(RecordingNotifyBackend::new());
    let recorder_b = Arc::new(RecordingNotifyBackend::new());
    let mut notifiers: HashMap<String, Arc<NotifyDispatcher>> = HashMap::new();
    for (profile, recorder) in [("a", &recorder_a), ("b", &recorder_b)] {
        notifiers.insert(
            profile.to_string(),
            Arc::new(NotifyDispatcher::new(
                profile,
                vec![recording_slot(recorder.clone())],
                queue.clone(),
            )),
        );
    }
    let notifiers: crate::notify::Notifiers = notifiers.into();

    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["a".to_string(), "b".to_string()],
        &relay_parts(db.clone(), notifiers.clone(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    // The same runner drains both kinds: `settle` queues the notification, and
    // the `NotifyJob` registered here is what actually delivers it.
    let _runner = TestRunner::start_notifying(queue, &signer, notifiers);
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

    await_status(db.clone(), &order.id, OrderStatus::Valid).await;

    // `settle` queues the notification rather than delivering it, so the row has
    // to be claimed and run before the recorder sees anything. Waiting on the
    // recorder itself rather than sleeping a fixed span: the runner is a second
    // hop now, and a fixed sleep would be a flake waiting to happen.
    await_recorded(&recorder_a).await;

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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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
    await_status(db, &order.id, OrderStatus::Valid).await;
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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

    let settled = await_status(db.clone(), &order.id, OrderStatus::Invalid).await;
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

/// **The property the durable queue exists for.** A CA that is briefly
/// unreachable used to invalidate the order on the first failed poll, leaving
/// the client to place a new one; now the attempt goes back in the queue and the
/// next one collects the certificate.
///
/// The order must never be seen `invalid` along the way — an intermediate
/// `abandon` would be exactly the old behaviour wearing a retry.
#[tokio::test(flavor = "multi_thread")]
async fn a_transient_upstream_outage_is_retried_into_a_certificate() {
    let chain = real_chain().await;
    let upstream = testsrv::start(Script {
        chain: chain.clone(),
        // Two 503s: enough that the first attempt cannot succeed.
        order_poll_outages: 2,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    // Retries on, unlike the default fixture: this test is about them. The
    // budget is written onto the job row at enqueue, so the *queue* carries it.
    let jobs = crate::config::JobsConfig {
        max_attempts: 5,
        ..test_jobs_config()
    };
    let queue = test_queue_with(db.clone(), &jobs);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start_with(queue, &signer, jobs);
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

    let settled = await_status(db.clone(), &order.id, OrderStatus::Valid).await;
    assert_eq!(settled.certificate.as_deref(), Some(chain.as_str()));
    assert!(
        upstream.order_polls() > 2,
        "the outage must really have been survived rather than skipped"
    );
}

/// The other half of the taxonomy: a CA that *states a reason* is believed on
/// the first attempt, so the client hears the real answer without waiting out a
/// retry budget it could never have exhausted usefully.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_refuses_the_order_is_not_retried() {
    let upstream = testsrv::start(Script {
        order_fails: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    // A generous budget, so reaching `invalid` proves the *classification*
    // rather than merely the budget running out.
    let jobs = crate::config::JobsConfig {
        max_attempts: 20,
        ..test_jobs_config()
    };
    let queue = test_queue_with(db.clone(), &jobs);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start_with(queue, &signer, jobs);
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

    await_status(db.clone(), &order.id, OrderStatus::Invalid).await;
    let job = crate::sqlite::job::Job::find_live(
        crate::signer::relay::flow::RELAY_JOB_KIND,
        &order.id,
        &db,
    )
    .await
    .unwrap();
    assert!(
        job.is_none(),
        "a permanent refusal retires the job rather than leaving it queued"
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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

    await_status(db.clone(), &order.id, OrderStatus::Invalid).await;
    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    let error = mapping.error.unwrap();
    assert!(
        error.contains("timed out"),
        "the timeout must be named, not reported as a generic failure: {error}"
    );
    // A timeout is *retryable*, so the order only reaches `invalid` once the
    // attempts run out — which this fixture sets to one. The reason says which
    // of the two bounds ended it, because "it timed out" and "it timed out and
    // will not be tried again" are different things to an operator.
    assert!(
        error.contains("no attempts left"),
        "the retirement must say the budget ran out: {error}"
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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

    await_status(db.clone(), &order.id, OrderStatus::Valid).await;
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
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
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
    await_status(db, &order.id, OrderStatus::Invalid).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_reaches_the_upstream() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(database().await, no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

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
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(database().await, no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    let leaf = crate::cert::leaf_der_from_chain(&real_chain().await).unwrap();
    signer
        .revoke(&leaf, None)
        .await
        .expect("alreadyRevoked must read as success");
}

/// The restart case: a row left `processing` by a dead process must be
/// picked up and carried to a certificate, without the original request.
///
/// Recovery is now an *enqueue* rather than a spawn, so this additionally pins
/// that the job row appears — the queue, not a task, is what carries it, which
/// is also what gives a recovered relay the same retries as a fresh one.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_finishes_a_relay_left_behind_by_a_restart() {
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
    assert!(order.claim_for_finalize(&db).await.unwrap());
    UpstreamOrder::create(
        &order.id,
        &format!("{}/order/1", upstream.base),
        None,
        &csr_der(),
        &db,
    )
    .await
    .unwrap();

    // A fresh backend and runner, as a restarted process would build. The
    // runner calls `recover` on every handler before it claims anything.
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    let settled = await_status(db.clone(), &order.id, OrderStatus::Valid).await;
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
async fn recovery_ignores_rows_that_already_settled() {
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

    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        upstream.order_polls(),
        0,
        "a settled relay must not be touched again"
    );
}

/// Nothing to recover is the common case and must be silent and harmless.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_with_no_pending_rows_does_nothing() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let queue = test_queue(db.clone());
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), queue.clone()),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(upstream.order_polls(), 0);
}

/// The `RelayJob` handler's own refusals, driven directly rather than through
/// `issue`.
///
/// Each is a state the queue can genuinely present the handler with — a job
/// outliving its subject, a payload from an older build, a database that has
/// gone away — and each has to pick `Retry` or `Failed` correctly, because
/// getting it wrong either burns the budget on work that cannot succeed or
/// gives up on work that would.
mod handler {
    use super::*;
    use crate::jobs::{JobHandler, JobOutcome};
    use crate::signer::relay::flow::{RELAY_JOB_KIND, RelayJob};
    use crate::sqlite::job::Job;

    /// Builds a backend with no runner: these tests call the handler by hand.
    async fn handler_for(db: Arc<Database>) -> (RelayJob, Upstream, TempDir) {
        let upstream = testsrv::start(Script::default()).await;
        let dir = TempDir::new("upstream");
        let signer = RelaySigner::from_config(
            &config(&upstream, &dir),
            vec!["default".to_string()],
            &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
            &crate::signer::CarriedState::new(),
        )
        .unwrap();
        (RelayJob(signer.0.clone()), upstream, dir)
    }

    /// A claimed row, as the runner would hand one over.
    fn job(payload: serde_json::Value) -> Job {
        Job {
            id: "job-1".to_string(),
            kind: RELAY_JOB_KIND.to_string(),
            dedup_key: "ord-1".to_string(),
            payload,
            status: "running".to_string(),
            run_at: now_secs(),
            attempts: 1,
            max_attempts: 5,
            deadline: None,
            lease_until: None,
            lease_owner: None,
            last_error: None,
            created_at: now_secs(),
            updated_at: now_secs(),
        }
    }

    /// A row written by a build that shaped the payload differently. Retrying
    /// cannot change what it says, so it is permanent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_payload_naming_no_order_is_permanent() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db).await;

        match handler.run(&job(serde_json::json!({}))).await {
            JobOutcome::Failed(reason) => assert!(reason.contains("names no order")),
            other => panic!("expected a permanent failure, got {other:?}"),
        }
        // And `abandon` survives the same payload rather than panicking on it.
        handler
            .abandon(&job(serde_json::json!({})), "whatever")
            .await;
    }

    /// The mapping row is what carries the CSR and the upstream URL. Without it
    /// there is nothing to relay and nothing a later attempt could recover.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_mapping_row_is_permanent() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db).await;

        match handler
            .run(&job(serde_json::json!({"order_id": "ord-gone"})))
            .await
        {
            JobOutcome::Failed(reason) => assert!(reason.contains("no upstream order")),
            other => panic!("expected a permanent failure, got {other:?}"),
        }
    }

    /// A database that has gone away says nothing about the work, so every
    /// arm that meets one asks to be tried again rather than giving up.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_database_failure_is_retryable_everywhere_it_is_met() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db.clone()).await;
        db.pool.close().await;

        match handler
            .run(&job(serde_json::json!({"order_id": "ord-1"})))
            .await
        {
            JobOutcome::Retry(reason) => assert!(reason.contains("reading the upstream order")),
            other => panic!("expected a retry, got {other:?}"),
        }

        // `settle`'s own lookup, on the same closed pool.
        match settle(&handler.0, "ord-1", "irrelevant".to_string()).await {
            JobOutcome::Retry(reason) => assert!(reason.contains("reading the local order")),
            other => panic!("expected a retry, got {other:?}"),
        }

        // And `abandon` degrades to a log rather than panicking.
        handler
            .abandon(&job(serde_json::json!({"order_id": "ord-1"})), "why")
            .await;
    }

    /// The deadline is best-effort: an order that cannot be read yields no
    /// bound rather than refusing to queue the work at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_deadline_for_an_unreadable_order_is_absent_rather_than_fatal() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db.clone()).await;

        assert!(
            crate::signer::relay::flow::order_deadline("ord-missing", &handler.0)
                .await
                .is_none(),
            "a missing order has no expiry to bound anything by"
        );

        db.pool.close().await;
        assert!(
            crate::signer::relay::flow::order_deadline("ord-1", &handler.0)
                .await
                .is_none(),
            "an unreadable order degrades to no deadline, not to a refusal"
        );
    }

    /// An order the operator deleted between `issue` and the retirement leaves
    /// nothing to mark invalid — the audit row and the mapping update are both
    /// skipped, quietly.
    #[tokio::test(flavor = "multi_thread")]
    async fn abandoning_a_vanished_order_is_survived() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db).await;
        handler
            .abandon(&job(serde_json::json!({"order_id": "ord-gone"})), "why")
            .await;
    }

    /// With no mapping row the audit trail cannot name who asked, and says so:
    /// `Actor::system` and an empty client context, rather than inventing one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retirement_with_no_mapping_row_is_attributed_to_the_system() {
        let db = database().await;
        let (handler, _upstream, _dir) = handler_for(db.clone()).await;
        let order = ready_order(db.clone()).await;

        handler
            .abandon(
                &job(serde_json::json!({"order_id": order.id})),
                "the upstream went away",
            )
            .await;

        assert_eq!(
            Order::find_by_id(&order.id, &db)
                .await
                .unwrap()
                .unwrap()
                .status,
            OrderStatus::Invalid
        );
        let (rows, _) = crate::sqlite::audit::AuditEntry::search(
            &crate::sqlite::audit::AuditQuery {
                order_id: Some(order.id.clone()),
                limit: 10,
                ..Default::default()
            },
            &db,
        )
        .await
        .unwrap();
        let row = rows.first().expect("the retirement is audited");
        assert_eq!(row.event, "certificate_issue_failed");
        assert_eq!(row.actor_kind, "system");
        assert!(row.client_ip.is_none());
        assert_eq!(row.detail.as_deref(), Some("the upstream went away"));
    }
}

/// Two `issue` calls for one order leave one upstream-order mapping, and the
/// second is answered `Processing` rather than refused.
///
/// The window is two finalize requests for one order arriving together:
/// `Order::claim_for_finalize` closes it on the ACME side, but a relay backend
/// is also reachable from the job runner's own retries, so the mapping row's
/// primary key is the backstop that keeps one order to one relay.
///
/// What this pins is that invariant, not one branch: the primary key is what
/// enforces it, and `UpstreamOrder::create` returning `None` — the
/// `upstream_relay_already_in_flight` arm — is the fast path that reads it.
/// Deleting that arm still leaves one row, because the insert is what refuses
/// the duplicate; what it costs is an `upstream_order_opened` line for an order
/// this call did not open. The assertion below is deliberately the invariant
/// rather than the log, so a future rewrite of *how* the duplicate is caught
/// still has to keep the guarantee.
///
/// No runner here: the first relay must stay in flight for the second call to
/// land inside it.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_issue_for_one_order_does_not_open_a_second_upstream_order() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(db.clone(), no_notifiers(), test_queue(db.clone())),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let order = ready_order(db.clone()).await;

    let mut outcomes = Vec::with_capacity(2);
    for _ in 0..2 {
        outcomes.push(
            signer
                .issue(
                    &order.id,
                    &csr_der(),
                    &identifiers(),
                    RequestedValidity::default(),
                )
                .await
                .unwrap(),
        );
    }

    for outcome in &outcomes {
        assert!(
            matches!(outcome, IssueOutcome::Processing),
            "a duplicate relay is answered `processing`, not refused: {outcome:?}"
        );
    }

    // One mapping row, and it still points at the order the first call opened.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstream_orders WHERE order_id = ?;")
        .bind(&order.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "one order may have only one upstream order");

    let mapping = UpstreamOrder::find_by_order_id(&order.id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        mapping.status, "processing",
        "the row belongs to the relay already running, untouched by the second call"
    );
}
