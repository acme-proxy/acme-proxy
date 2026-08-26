//! Several relay profiles in one process, and the one handler over them all.
//!
//! The trap this exists for: [`crate::jobs::JobRegistry::register`] refuses two
//! handlers for one `kind`, so returning a handler from each backend — which
//! `SignerBackend::jobs()` used to do — made two profiles relaying to
//! *different* upstreams a startup error, `build_backends` deliberately not
//! collapsing two `[signer]` sections that differ. **Nothing in a
//! single-profile test can see that**, which is why every other file here
//! passed while a two-upstream deployment could not start. It is the same trap
//! `local_ca::tests::one_sweep_handler_serves_every_ca_in_the_process` guards
//! on the CRL side.
//!
//! Registering cleanly is only half of it, though: one handler over two
//! backends has to send each row to the *right* one, and a handler that always
//! answered from the first backend would still register. So the rest of this
//! file is about which backend actually ran, and the discriminator is the
//! **strategy** — the backend brings that, where the upstream URL and the CSR
//! travel on the `upstream_orders` row and would be right either way.

use super::*;
use crate::jobs::{JobHandler, JobOutcome, JobRegistry};
use crate::signer::relay::flow::{RELAY_JOB_KIND, RelayJob};
use crate::sqlite::job::Job;
use crate::sqlite::status::OrderStatus;

/// Two relay backends over two upstreams, plus the profiles they serve.
struct TwoUpstreams {
    bypassing: RelaySigner,
    challenged: RelaySigner,
    tokens: Arc<StubTokens>,
    bypassing_upstream: Upstream,
    challenged_upstream: Upstream,
    chain_a: String,
    chain_b: String,
    _dirs: (TempDir, TempDir),
}

/// Builds the pair: profile `a` relays to an upstream that validates nothing,
/// profile `b` to one that poses an `http-01` challenge and is answered by a
/// backend holding a token store.
///
/// The two differ in `directory_url` and `account_key_path`, which is exactly
/// what makes `build_backends` keep them apart in production — and what used to
/// make this configuration refuse to start.
async fn two_upstreams(db: &Arc<Database>, queue: &crate::jobs::JobQueue) -> TwoUpstreams {
    let chain_a = real_chain().await;
    let chain_b = real_chain().await;
    assert_ne!(
        chain_a, chain_b,
        "the two upstreams must issue distinguishable chains, or nothing below proves anything"
    );

    let bypassing_upstream = testsrv::start(Script {
        chain: chain_a.clone(),
        ..Script::default()
    })
    .await;
    let challenged_upstream = testsrv::start(Script {
        chain: chain_b.clone(),
        pose_challenge: true,
        offer_http01: true,
        ..Script::default()
    })
    .await;

    let dir_a = TempDir::new("upstream-a");
    let dir_b = TempDir::new("upstream-b");
    let parts = relay_parts(db.clone(), no_notifiers(), queue.clone());

    let bypassing = RelaySigner::from_config(
        &config(&bypassing_upstream, &dir_a),
        &parts,
        &crate::signer::CarriedState::new(),
    )
    .unwrap();
    let tokens = Arc::new(StubTokens::default());
    let challenged = with_tokens(
        RelaySigner::from_config(
            &config(&challenged_upstream, &dir_b),
            &parts,
            &crate::signer::CarriedState::new(),
        )
        .unwrap(),
        tokens.clone(),
    );

    TwoUpstreams {
        bypassing,
        challenged,
        tokens,
        bypassing_upstream,
        challenged_upstream,
        chain_a,
        chain_b,
        _dirs: (dir_a, dir_b),
    }
}

/// One handler over two backends, mounted under the profiles each serves.
fn handler(db: &Arc<Database>, pair: &TwoUpstreams) -> RelayJob {
    RelayJob::new(
        db.clone(),
        vec![
            ("a".to_string(), pair.bypassing.relay_state().unwrap()),
            ("b".to_string(), pair.challenged.relay_state().unwrap()),
        ],
    )
}

/// The reported bug, at its smallest: two relay backends must produce **one**
/// registration, not two of one kind.
///
/// Before this, `build_generation` asked each backend for its handlers and the
/// second `register` refused with "two job handlers registered for kind
/// `signer_relay_issue`" — so `acme-proxy serve` exited on a configuration the
/// rest of the process supports (`build_app` already merges several relays'
/// http-01 token stores).
#[tokio::test(flavor = "multi_thread")]
async fn two_relay_backends_register_one_handler() {
    let db = database().await;
    let pair = two_upstreams(&db, &test_queue(db.clone())).await;

    let mut registry = JobRegistry::new();
    registry
        .register(Arc::new(handler(&db, &pair)))
        .expect("one handler over both relay backends must register");

    assert_eq!(
        registry.kinds(),
        vec![RELAY_JOB_KIND],
        "two backends contribute one kind between them"
    );
}

/// Each profile's orders are relayed by **its own** backend.
///
/// The proof is the strategy, not the chain: profile `b`'s upstream poses a
/// challenge only a backend holding the token store can answer, so a row
/// dispatched to profile `a`'s bypassing backend would leave that order
/// `processing` until the test times out. The chains are asserted too, since a
/// certificate landing on the wrong order would be the other half of the same
/// mistake.
#[tokio::test(flavor = "multi_thread")]
async fn each_profile_is_relayed_by_its_own_backend() {
    let db = database().await;
    let queue = test_queue(db.clone());
    let pair = two_upstreams(&db, &queue).await;

    let mut registry = JobRegistry::new();
    registry.register(Arc::new(handler(&db, &pair))).unwrap();
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    crate::jobs::spawn_runner(
        queue,
        Arc::new(registry),
        &test_jobs_config(),
        receiver.clone(),
    );

    let order_a = ready_order_for("a", db.clone()).await;
    let order_b = ready_order_for("b", db.clone()).await;
    for order in [&order_a, &order_b] {
        let signer = if order.profile == "a" {
            &pair.bypassing
        } else {
            &pair.challenged
        };
        signer
            .issue(
                order.id.to_string().as_str(),
                &csr_der(),
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
            .unwrap();
    }

    let settled_a = await_status(
        db.clone(),
        order_a.id.to_string().as_str(),
        OrderStatus::Valid,
    )
    .await;
    let settled_b = await_status(
        db.clone(),
        order_b.id.to_string().as_str(),
        OrderStatus::Valid,
    )
    .await;
    let _ = shutdown.send(true);

    assert_eq!(
        settled_a.certificate.as_deref(),
        Some(pair.chain_a.as_str()),
        "profile `a` must hold what its own upstream issued"
    );
    assert_eq!(
        settled_b.certificate.as_deref(),
        Some(pair.chain_b.as_str()),
        "profile `b` must hold what its own upstream issued"
    );

    // The strategy assertion, which is the one a shared handler can get wrong:
    // only the challenged backend has a token store, and only its upstream
    // posed anything to answer.
    assert_eq!(
        pair.tokens.published().len(),
        1,
        "profile `b`'s own backend must be the one that answered its challenge"
    );
    assert_eq!(pair.challenged_upstream.challenge_triggered(), 1);
    assert_eq!(pair.bypassing_upstream.challenge_triggered(), 0);
}

/// A claimed row, as the runner would hand one over.
fn job(payload: serde_json::Value) -> Job {
    Job {
        id: crate::sqlite::id::mint(),
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

/// The per-attempt budget follows the row's own profile.
///
/// It is the only bound on `poll_until`, so answering one number for the whole
/// handler would let an endpoint configured for a minute poll for as long as
/// the most patient one in the process.
#[tokio::test(flavor = "multi_thread")]
async fn the_lease_is_the_owning_profile_s_own_poll_timeout() {
    let db = database().await;
    let queue = test_queue(db.clone());
    let chain = real_chain().await;
    let quick_upstream = testsrv::start(Script {
        chain: chain.clone(),
        ..Script::default()
    })
    .await;
    let patient_upstream = testsrv::start(Script {
        chain,
        ..Script::default()
    })
    .await;
    let (dir_quick, dir_patient) = (TempDir::new("quick"), TempDir::new("patient"));
    let parts = relay_parts(db.clone(), no_notifiers(), queue);

    let mut quick_config = config(&quick_upstream, &dir_quick);
    quick_config.poll_timeout_secs = 11;
    let mut patient_config = config(&patient_upstream, &dir_patient);
    patient_config.poll_timeout_secs = 97;

    let quick =
        RelaySigner::from_config(&quick_config, &parts, &crate::signer::CarriedState::new())
            .unwrap();
    let patient =
        RelaySigner::from_config(&patient_config, &parts, &crate::signer::CarriedState::new())
            .unwrap();

    let handler = RelayJob::new(
        db.clone(),
        vec![
            ("quick".to_string(), quick.relay_state().unwrap()),
            ("patient".to_string(), patient.relay_state().unwrap()),
        ],
    );

    assert_eq!(
        handler.lease(&job(
            serde_json::json!({"order_id": "o", "profile": "quick"})
        )),
        Some(Duration::from_secs(11))
    );
    assert_eq!(
        handler.lease(&job(
            serde_json::json!({"order_id": "o", "profile": "patient"})
        )),
        Some(Duration::from_secs(97))
    );
    // A row from a build that wrote no profile cannot be resolved without a
    // database, and this is synchronous — so it gets the most generous budget
    // configured. Longer than one backend asked for is the safe direction: an
    // attempt runs to its own conclusion instead of being cut short.
    assert_eq!(
        handler.lease(&job(serde_json::json!({"order_id": "o"}))),
        Some(Duration::from_secs(97))
    );
}

/// A row whose profile is no longer mounted asks to be tried again.
///
/// **Not `Failed`**: that would call `abandon`, which tells the client its order
/// is `invalid` — a terminal answer to what may be one reload's worth of
/// absence. The attempt budget and the job's own deadline still retire it if the
/// profile really has gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_row_for_an_unmounted_profile_is_retried_rather_than_abandoned() {
    let db = database().await;
    let pair = two_upstreams(&db, &test_queue(db.clone())).await;
    let handler = handler(&db, &pair);

    match handler
        .run(&job(
            serde_json::json!({"order_id": super::order_id("ord-1"), "profile": "gone"}),
        ))
        .await
    {
        JobOutcome::Retry(reason) => assert!(
            reason.contains("gone"),
            "the retry must name the profile: {reason}"
        ),
        other => panic!("expected a retry, got {other:?}"),
    }
}

/// A payload written before the profile was recorded still resolves.
///
/// A relay job outlives the process, so an upgrade meets rows carrying only an
/// order id. The order itself still says which endpoint it was placed against,
/// which is what the payload would have carried — so the fallback is the same
/// answer, read later, and it has to reach all four of a lookup's outcomes.
#[tokio::test(flavor = "multi_thread")]
async fn a_payload_from_before_the_profile_was_recorded_resolves_from_the_order() {
    let db = database().await;
    let pair = two_upstreams(&db, &test_queue(db.clone())).await;
    let handler = handler(&db, &pair);
    let order = ready_order_for("b", db.clone()).await;

    // No mapping row was ever written, so this stops at the first thing the
    // resolved backend looks for — which is exactly what proves it resolved.
    match handler
        .run(&job(serde_json::json!({"order_id": order.id})))
        .await
    {
        JobOutcome::Failed(reason) => assert!(
            reason.contains("no upstream order"),
            "the backend was resolved and then found no mapping: {reason}"
        ),
        other => panic!("expected a permanent failure, got {other:?}"),
    }

    // And an order that is gone as well as unnamed retires rather than looping.
    match handler
        .run(&job(
            serde_json::json!({"order_id": super::order_id("ord-vanished")}),
        ))
        .await
    {
        JobOutcome::Failed(reason) => assert!(reason.contains("no longer exists"), "{reason}"),
        other => panic!("expected a permanent failure, got {other:?}"),
    }

    // An order on a profile this process no longer mounts reaches the same
    // answer the named case does, by the longer route: a retry, never the
    // `Failed` that would tell the client its order is invalid.
    let elsewhere = ready_order_for("c", db.clone()).await;
    match handler
        .run(&job(serde_json::json!({"order_id": elsewhere.id})))
        .await
    {
        JobOutcome::Retry(reason) => assert!(reason.contains('c'), "{reason}"),
        other => panic!("expected a retry, got {other:?}"),
    }

    // And a database that has gone away says nothing about the work, so the
    // fallback asks to be tried again rather than deciding anything.
    db.pool.close().await;
    match handler
        .run(&job(serde_json::json!({"order_id": order.id})))
        .await
    {
        JobOutcome::Retry(reason) => {
            assert!(reason.contains("reading the local order"), "{reason}")
        }
        other => panic!("expected a retry, got {other:?}"),
    }
}

/// Recovery covers **every** backend, and asks each only for the profiles this
/// generation says it serves.
///
/// One handler means one `recover`, so a fan-out that stopped at the first
/// backend would leave the other's in-flight orders on the floor until a
/// restart — the failure the durable queue exists to prevent.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_re_queues_the_in_flight_orders_of_every_backend() {
    let db = database().await;
    let queue = test_queue(db.clone());
    let pair = two_upstreams(&db, &queue).await;

    // One order left `processing` on each profile, as a killed process leaves
    // them: the mapping row exists, but no job row does.
    let mut queued = Vec::new();
    for profile in ["a", "b"] {
        let order = ready_order_for(profile, db.clone()).await;
        UpstreamOrder::create(
            order.id.to_string().as_str(),
            "https://upstream.example/order/1",
            Some("https://upstream.example/order/1/finalize"),
            &csr_der(),
            &db,
        )
        .await
        .unwrap();
        queued.push((profile, order.id));
    }

    handler(&db, &pair).recover(&queue).await;

    for (profile, id) in queued {
        let row = crate::sqlite::job::Job::find_live(RELAY_JOB_KIND, id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("order {id} on profile `{profile}` must be re-queued"));
        assert_eq!(
            row.payload.get("profile").and_then(|value| value.as_str()),
            Some(profile),
            "a recovered row names the profile it belongs to, like a fresh one"
        );
    }
}
