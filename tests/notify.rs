//! Covers the notify subsystem's wiring into the real router.
//!
//! Deliberately narrow: per-event field-shape assertions (what fields a
//! `NotifyEvent` carries, template rendering, the `events` filter, the
//! `custom` script contract) belong to the inline unit tests under
//! `src/notify/*` and `src/signer/relay/mod.rs`. This file only covers
//! what *requires* the real router — that each handler actually calls
//! `dispatch(...)` at the right point with the right data, and that a
//! failing/panicking notify backend never affects the HTTP response.

use std::sync::Arc;
use std::time::Duration;

use acme_proxy::config::{Config, JobsConfig};
use acme_proxy::filter::FilterPolicy;
use acme_proxy::jobs::JobRegistry;
use acme_proxy::notify::{BackendSlot, NotifyDispatcher, NotifyEvent, NotifyJob};
use acme_proxy::signer::local_ca::LocalCa;
use acme_proxy::sqlite::job::Job;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::json;

mod common;
use common::{
    EcSigner, NotifyHarness, StubValidator, TestSigner, body_json, challenges_with, fetch_nonce,
    first_certificate, make_csr, p, send_from, test_app_full, test_app_with_notify,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";
const REVOKE_URL: &str = "http://localhost:3000/profile/default/revokeCert";

/// Every request in this file carries a real peer address, so the handlers
/// that extract `ClientIp` (and therefore populate `client_ip` on a
/// `NotifyEvent`) have something real to extract — matching an actual
/// client, unlike a plain `oneshot()` with no `ConnectInfo` at all.
const PEER: &str = "203.0.113.7:41000";

async fn post(app: &Router, path: &str, body: String) -> Response {
    send_from(
        app,
        Request::post(path)
            .header("content-type", "application/jose+json")
            .body(Body::from(body))
            .unwrap(),
        PEER,
    )
    .await
}

/// Registers an account and returns its account URL (used as `kid`).
async fn register(app: &Router, signer: &impl TestSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// The last path segment of a `Location`-style URL — an account/order id.
fn last_segment(url: &str) -> &str {
    url.rsplit('/').next().unwrap()
}

/// Drives a full order → authz → trigger → finalize lifecycle for `account_url`
/// (already registered under `signer`), returning `(order_id, chain_pem)`.
async fn issue_certificate(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
) -> (String, String) {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &authz_url, &nonce);
    let res = post(app, authz_path, body).await;
    let authz = body_json(res).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, &challenge_url, &nonce, &json!({}));
    let res = post(app, challenge_path, body).await;
    assert_eq!(body_json(res).await["status"], "valid");

    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &order_url, &nonce);
    let res = post(app, order_path, body).await;
    assert_eq!(body_json(res).await["status"], "ready");

    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(account_url, &finalize_url, &nonce, &payload);
    let res = post(app, finalize_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let cert_path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &cert_url, &nonce);
    let res = post(app, cert_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let chain = String::from_utf8(bytes.to_vec()).unwrap();

    (last_segment(order_path).to_string(), chain)
}

#[tokio::test]
async fn account_created_dispatches_with_the_new_account_id() {
    let notify = NotifyHarness::new().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let account_id = last_segment(&account_url);

    let events = notify.recorded(1).await;
    assert_eq!(events.len(), 1, "{events:?}");
    match &events[0] {
        NotifyEvent::AccountCreated(data) => assert_eq!(data.account_id, account_id),
        other => panic!("expected AccountCreated, got {other:?}"),
    }
}

/// A repeat `newAccount` for an already-registered key is a find, not a
/// create (RFC 8555 §7.3) — it must not notify a second time.
#[tokio::test]
async fn account_created_does_not_refire_on_an_idempotent_replay() {
    let notify = NotifyHarness::new().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    register(&app, &signer).await;

    // A second `newAccount` for the same key is a find, not a create — it
    // answers `200`, not `201`, so this deliberately doesn't reuse
    // `register()` (which asserts `CREATED`).
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        &app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let events = notify.settled().await;
    assert_eq!(
        events.len(),
        1,
        "a repeat newAccount for the same key must not notify again: {events:?}"
    );
}

#[tokio::test]
async fn account_deactivated_dispatches_with_the_account_id() {
    let notify = NotifyHarness::new().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let account_id = last_segment(&account_url).to_string();
    let account_path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "status": "deactivated" });
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &payload);
    let res = post(&app, account_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);

    // Two events: this account's own `AccountCreated`, then the deactivation.
    let events = notify.recorded(2).await;
    // The first event is this account's own AccountCreated; the deactivation
    // is the last one dispatched.
    match events.last().expect("no event recorded") {
        NotifyEvent::AccountDeactivated(data) => assert_eq!(data.account_id, account_id),
        other => panic!("expected AccountDeactivated, got {other:?}"),
    }
}

#[tokio::test]
async fn certificate_issued_dispatches_with_the_order_id_and_identifiers() {
    let notify = NotifyHarness::new().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (order_id, _chain) = issue_certificate(&app, &signer, &account_url).await;

    let events = notify.recorded(2).await;
    let issued = events
        .iter()
        .find_map(|event| match event {
            NotifyEvent::CertificateIssued(data) => Some(data),
            _ => None,
        })
        .expect("no CertificateIssued event recorded");
    assert_eq!(issued.order_id, order_id);
    assert_eq!(issued.identifiers, vec!["example.com".to_string()]);
    assert!(
        issued.client_ip.is_some(),
        "the synchronous path has a request in scope"
    );
}

#[tokio::test]
async fn certificate_revoked_dispatches_with_the_serial_and_reason() {
    let notify = NotifyHarness::new().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (_order_id, chain) = issue_certificate(&app, &signer, &account_url).await;
    let cert_field = BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain));

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field, "reason": 1 });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = post(&app, &p("/revokeCert"), body).await;
    assert_eq!(res.status(), StatusCode::OK);

    let events = notify.recorded(3).await;
    let revoked = events
        .iter()
        .find_map(|event| match event {
            NotifyEvent::CertificateRevoked(data) => Some(data),
            _ => None,
        })
        .expect("no CertificateRevoked event recorded");
    assert_eq!(revoked.reason, Some(1));
}

#[tokio::test]
async fn challenge_failed_dispatches_with_the_error_kind() {
    let notify = NotifyHarness::new().await;
    let signer_backend = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    let (app, _db) = test_app_full(
        Config::default(),
        signer_backend,
        Arc::new(FilterPolicy::default()),
        challenges_with(
            &["http-01"],
            vec![Arc::new(StubValidator::failing(
                "http-01",
                "wrong response",
            ))],
        ),
        notify.dispatcher.clone(),
    )
    .await;

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &authz_url, &nonce);
    let res = post(&app, authz_path, body).await;
    let authz = body_json(res).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
    let res = post(&app, challenge_path, body).await;
    assert_eq!(body_json(res).await["status"], "invalid");

    let events = notify.recorded(2).await;
    let failed = events
        .iter()
        .find_map(|event| match event {
            NotifyEvent::ChallengeFailed(data) => Some(data),
            _ => None,
        })
        .expect("no ChallengeFailed event recorded");
    assert_eq!(failed.identifier, "example.com");
    assert!(!failed.error.is_empty());
}

/// The load-bearing proof: a notify backend that always fails to deliver
/// must never change the HTTP response a client sees. Fire-and-forget is a
/// design decision (see `NotifyDispatcher::dispatch`'s doc comment), not
/// something that happens to be true today — this pins it.
#[tokio::test]
async fn a_failing_notify_backend_never_affects_the_http_response() {
    let notify = NotifyHarness::failing().await;
    let (app, _db) = test_app_with_notify(notify.dispatcher.clone()).await;

    let signer = EcSigner::new();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        &app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;

    // Same expectation as the non-failing case in
    // `account_created_dispatches_with_the_new_account_id`: a broken notify
    // backend is invisible to the client.
    assert_eq!(res.status(), StatusCode::CREATED);

    let events = notify.recorded(1).await;
    assert_eq!(
        events.len(),
        1,
        "the backend must still have been *called*, just failed: {events:?}"
    );
}

/// A backend that takes its time, so a test can watch a delivery still be in
/// flight — and, more to the point, still be *owed* — when the process stops.
struct SlowBackend {
    delivered: Arc<std::sync::atomic::AtomicUsize>,
    delay: Duration,
}

#[async_trait::async_trait]
impl acme_proxy::notify::NotifyBackend for SlowBackend {
    fn name(&self) -> &'static str {
        "slow"
    }

    async fn send(&self, _event: &NotifyEvent) -> Result<(), acme_proxy::notify::NotifyError> {
        tokio::time::sleep(self.delay).await;
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// The property that replaced `drain`.
///
/// A notification used to be a spawned task, so a process that stopped before it
/// ran simply lost it — the client got its certificate and the operator never
/// heard. A best-effort five-second drain at shutdown was the mitigation, and it
/// still lost anything slower than the budget. Now `dispatch` writes a row and
/// returns: nothing has been delivered when it comes back, and the row is
/// sitting in the queue for whoever runs next. That is the whole change, so it
/// is asserted directly rather than through a timing window.
#[tokio::test]
async fn a_dispatch_that_never_ran_is_still_owed_afterwards() {
    let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let queue = common::test_job_queue().await;
    let every: Vec<String> = acme_proxy::config::ALL_NOTIFY_EVENTS
        .iter()
        .map(|kind| (*kind).to_string())
        .collect();
    let dispatcher = NotifyDispatcher::new(
        "default",
        vec![BackendSlot::new(
            "slow",
            Arc::new(SlowBackend {
                delivered: delivered.clone(),
                delay: Duration::from_millis(50),
            }),
            &every,
        )],
        queue.clone(),
    );

    dispatcher
        .dispatch(NotifyEvent::ProfileMounted(
            acme_proxy::notify::ProfileMountedData {
                profile: "default".to_string(),
            },
        ))
        .await;

    // Nothing delivered — and, unlike before, nothing lost either.
    assert_eq!(delivered.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        Job::count_live("notify_deliver", queue.database())
            .await
            .unwrap(),
        1,
        "the delivery is owed, on a row that outlives this process"
    );

    // A runner started afterwards — as a restart would — picks it up.
    let mut registry = JobRegistry::new();
    let mut dispatchers = std::collections::HashMap::new();
    dispatchers.insert("default".to_string(), Arc::new(dispatcher));
    registry
        .register(Arc::new(NotifyJob::new(Arc::new(dispatchers))))
        .unwrap();
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    acme_proxy::jobs::spawn_runner(
        queue.clone(),
        Arc::new(registry),
        &JobsConfig {
            poll_interval_ms: 5,
            ..JobsConfig::default()
        },
        receiver,
    );

    for _ in 0..400 {
        if delivered.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            let _ = shutdown.send(true);
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the queued notification was never delivered");
}

/// The expiry digest, end to end through a real runner: an expiring
/// certificate in the database, a registered `ExpiryDigestJob`, and a
/// `certificates_expiring` event coming out of a backend.
///
/// The inline suite in `src/notify/expiry.rs` drives `collect` and `run`
/// directly, which proves the query and the annotation but never that the
/// event *reaches* anybody — the handler only dispatches, which queues a
/// second job that a runner then delivers. This is the only test that puts
/// both hops together, and so the only one that would catch the digest being
/// registered but never wired to a dispatcher.
#[tokio::test]
async fn the_expiry_digest_reaches_a_backend_through_the_runner() {
    use acme_proxy::config::{ExpiryNotifyConfig, NotifyConfig, ProfileConfig, ProfileSections};
    use acme_proxy::notify::expiry::ExpiryDigestJob;
    use acme_proxy::sqlite::db::Database;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let config = JobsConfig {
        poll_interval_ms: 5,
        max_attempts: 1,
        retry_base_seconds: 0,
        ..JobsConfig::default()
    };
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let queue = acme_proxy::jobs::JobQueue::new(database.clone(), &config);

    // An account with a certificate lapsing inside the window.
    let (account, _created) = acme_proxy::sqlite::account::Account::find_or_create(
        "default",
        b"a-key",
        Vec::new(),
        &acme_proxy::audit::ClientContext::default(),
        &database,
    )
    .await
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut order = Order::create(
        "default",
        &account.id,
        vec![Identifier::dns("lapsing.example.com")],
        now + 3600,
        None,
        None,
        &database,
    )
    .await
    .unwrap();
    order
        .finalize(
            "-----BEGIN CERTIFICATE-----\n...".to_string(),
            "0a0b".to_string(),
            vec![1],
            Some(now + 3 * 24 * 60 * 60),
            &database,
        )
        .await
        .unwrap();

    let recorder = Arc::new(common::RecordingNotifyBackend::default());
    let every: Vec<String> = acme_proxy::config::ALL_NOTIFY_EVENTS
        .iter()
        .map(|kind| (*kind).to_string())
        .collect();
    let dispatcher = Arc::new(NotifyDispatcher::new(
        "default",
        vec![BackendSlot::new("recording", recorder.clone(), &every)],
        queue.clone(),
    ));
    let dispatchers: std::collections::HashMap<String, Arc<NotifyDispatcher>> =
        std::collections::HashMap::from([("default".to_string(), dispatcher)]);
    let (_notifiers_tx, notifiers) = acme_proxy::notify::notifiers_channel(dispatchers.clone());

    let profile = ProfileConfig {
        name: "default".to_string(),
        sections: ProfileSections {
            notify: NotifyConfig {
                expiry: ExpiryNotifyConfig {
                    lead_days: 14,
                    ..ExpiryNotifyConfig::default()
                },
                ..NotifyConfig::default()
            },
            ..ProfileSections::default()
        },
    };

    let mut registry = JobRegistry::new();
    registry
        .register(Arc::new(NotifyJob::new(Arc::new(dispatchers))))
        .unwrap();
    registry
        .register(Arc::new(
            ExpiryDigestJob::from_profiles(
                std::slice::from_ref(&profile),
                notifiers,
                database.clone(),
                queue.clone(),
            )
            .expect("lead_days is set, so a digest is configured"),
        ))
        .unwrap();

    // `recover` runs on the way into the loop and queues the profile's row at
    // `run_at = now`, so the first pass produces the digest with nothing else
    // to trigger it.
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    acme_proxy::jobs::spawn_runner(queue, Arc::new(registry), &config, receiver);

    let mut recorded = Vec::new();
    for _ in 0..400 {
        recorded = recorder.events();
        if !recorded.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let _ = shutdown.send(true);

    assert_eq!(
        recorded.len(),
        1,
        "one digest, not one message per certificate"
    );
    match &recorded[0] {
        NotifyEvent::CertificatesExpiring(data) => {
            assert_eq!(data.profile, "default");
            assert_eq!(data.total, 1);
            assert_eq!(
                data.certificates[0].identifiers,
                vec!["lapsing.example.com".to_string()]
            );
        }
        other => panic!("expected a digest, got {other:?}"),
    }
}
