//! The `relay` backend's tests.
//!
//! A directory rather than an inline `mod tests`, which had reached 2027 lines
//! — 82% of the file, and the reason `mod.rs` read as the largest module in the
//! crate when its production half is 457 lines. Nothing moved *out* of the
//! module: these are still `relay`'s own tests, entered through
//! `SignerBackend::issue` and asserting a relay outcome, so they still follow
//! the entry point rather than the assertion. They are just no longer one file.
//!
//! This file holds only what every section needs — the fixtures and the shared
//! stubs. Each submodule is one concern:
//!
//! - [`lifecycle`] — startup, provisioning, `issue`/relay/settle, revoke, recovery
//! - [`eab`] — the upstream credential, both ways of supplying it
//! - [`dns01_strategy`] / [`http01_strategy`] — the two answering strategies
//! - [`multi_profile`] — several relay profiles, and the one handler over them
//! - [`renewal`] — RFC 9773 windows, and the `UpstreamError` mapping
//!
//! Since the relay became a [`crate::jobs`] handler, `issue` **enqueues** rather
//! than spawning, so a test that expects an order to settle must have a runner
//! in the process. [`TestRunner`] is that, and every test driving `issue` to a
//! conclusion starts one — which is also the only structural change the
//! migration forced on this suite.

mod dns01_strategy;
mod eab;
mod http01_strategy;
mod lifecycle;
mod multi_profile;
mod renewal;

/// The job configuration the tests run under: everything fast, retries off.
///
/// `max_attempts: 1` is deliberate for the default fixture. Most of these tests
/// assert on the *first* outcome, and a retried failure would make them wait out
/// a backoff before the order reached `invalid` — so retrying is opted into by
/// the two tests that are about it, not out of by the rest.
fn test_jobs_config() -> crate::config::JobsConfig {
    crate::config::JobsConfig {
        poll_interval_ms: 5,
        max_attempts: 1,
        retry_base_seconds: 0,
        retry_max_seconds: 0,
        lease_seconds: 5,
        retention_days: 0,
        ..crate::config::JobsConfig::default()
    }
}

/// The queue a signer under test enqueues into.
///
/// Handed to `from_config` and then, for the tests that need the work actually
/// done, to [`TestRunner::start`] — the *same* instance both times, so an
/// enqueue wakes the runner directly rather than waiting for its next tick.
fn test_queue(database: Arc<Database>) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, &test_jobs_config())
}

/// A queue with a configuration of its own.
///
/// Needed because `max_attempts` is **frozen onto the row at enqueue**, not read
/// by the runner: a test that wants retries has to say so on the queue that
/// writes the row, and handing only the runner a bigger budget changes nothing.
fn test_queue_with(
    database: Arc<Database>,
    config: &crate::config::JobsConfig,
) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, config)
}

/// The runner draining a queue, stopped when the guard drops.
///
/// The `watch` sender is held rather than the receiver so `Drop` signals a
/// *graceful* stop, which is what releases the leases. An abort would leave rows
/// `running` and a later assertion reading a state no production restart
/// produces.
struct TestRunner {
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl TestRunner {
    fn start(queue: crate::jobs::JobQueue, signer: &RelaySigner) -> Self {
        Self::start_with(queue, signer, test_jobs_config())
    }

    /// The profile every fixture here places its orders under, and therefore
    /// the one the handler has to be told this signer relays for.
    const DEFAULT_PROFILES: &'static [&'static str] = &["default"];

    /// The runner, plus the [`NotifyJob`] that actually delivers what `settle`
    /// queues. Only the notification test needs it: everywhere else the relay's
    /// dispatcher has no backends, so the rows are never written.
    fn start_notifying(
        queue: crate::jobs::JobQueue,
        signer: &RelaySigner,
        profiles: &[&str],
        notifiers: crate::notify::Notifiers,
    ) -> Self {
        Self::start_inner(queue, signer, profiles, test_jobs_config(), Some(notifiers))
    }

    fn start_with(
        queue: crate::jobs::JobQueue,
        signer: &RelaySigner,
        config: crate::config::JobsConfig,
    ) -> Self {
        Self::start_inner(queue, signer, Self::DEFAULT_PROFILES, config, None)
    }

    fn start_inner(
        queue: crate::jobs::JobQueue,
        signer: &RelaySigner,
        profiles: &[&str],
        config: crate::config::JobsConfig,
        notifiers: Option<crate::notify::Notifiers>,
    ) -> Self {
        let mut registry = crate::jobs::JobRegistry::new();
        registry
            .register(Arc::new(relay_handler(signer, profiles)))
            .unwrap();
        if let Some(notifiers) = notifiers {
            registry
                .register(Arc::new(crate::notify::NotifyJob::new(notifiers)))
                .unwrap();
        }
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        crate::jobs::spawn_runner(queue, Arc::new(registry), &config, receiver);
        Self { shutdown }
    }
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// The shared resolver `Profile::build_all` supplies at startup.
fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
    Arc::new(crate::dns::HickoryResolver::from_system_uncached().unwrap())
}

use super::account::kid_path;
use super::client::UpstreamError;
use super::flow::settle;
use super::http01::TokenStore;
use super::*;
use crate::audit::ClientContext;
use crate::notify::{NotifyDispatcher, NotifyEvent};
use crate::signer::local_ca::LocalCa;
use crate::sqlite::account::Account;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::Order;
use crate::sqlite::status::OrderStatus;
use crate::testutil::TempDir;
use std::collections::HashMap;
use std::path::PathBuf;
use testsrv::{Script, Upstream};

/// A throwaway directory for the account key/kid files, so no test writes
/// into the repository.
/// The upstream account key path inside a scratch directory.
fn key_path(dir: &TempDir) -> String {
    dir.join("upstream.key").to_string_lossy().into_owned()
}

fn config(upstream: &Upstream, dir: &TempDir) -> RelayConfig {
    RelayConfig {
        directory_url: upstream.directory_url(),
        account_key_path: key_path(dir),
        // Fast polling: the fake upstream answers instantly, so the
        // interval only governs how long a test waits for nothing.
        poll_interval_ms: 5,
        poll_timeout_secs: 5,
        ..RelayConfig::default()
    }
}

async fn database() -> Arc<Database> {
    Arc::new(Database::connect_in_memory().await.unwrap())
}

fn no_notifiers() -> crate::notify::Notifiers {
    HashMap::new().into()
}

/// The dependencies `RelaySigner::from_config` takes, minus the three a test
/// here actually varies: which database, which notifiers and which queue.
///
/// The remaining two are the same at every call site — a registry nothing
/// scrapes, and a resolver reaching loopback by IP literal (which
/// `dns::connect` short-circuits). They used to be spelled out at all
/// forty-eight of them.
fn relay_parts(
    database: Arc<Database>,
    notifiers: crate::notify::Notifiers,
    jobs: crate::jobs::JobQueue,
) -> crate::signer::SignerParts {
    crate::signer::SignerParts {
        database: database.clone(),
        notifiers,
        metrics: crate::testutil::test_metrics(database),
        egress: crate::testutil::egress_with(test_resolver()),
        jobs,
    }
}

/// A `TokenStore` that records what it was asked to publish *and* answers
/// lookups, so one type both drives the real responder route and carries
/// the assertions.
#[derive(Default)]
struct StubTokens {
    published: std::sync::Mutex<Vec<(String, String)>>,
    retracted: std::sync::Mutex<Vec<String>>,
    live: std::sync::Mutex<HashMap<String, String>>,
}

impl StubTokens {
    /// The tokens this store was asked to publish, as `(token, key auth)`.
    ///
    /// Which store saw a publish is how [`multi_profile`] tells two relay
    /// backends apart: a row routed to the wrong one leaves this empty.
    fn published(&self) -> Vec<(String, String)> {
        self.published.lock().unwrap().clone()
    }
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

/// The twin of `with_updater`, for the `http01` strategy.
///
/// Shared by [`http01_strategy`] and [`multi_profile`] — hoisted here when the
/// second consumer arrived, this file being where the fixtures every section
/// needs live.
fn with_tokens(signer: RelaySigner, tokens: Arc<StubTokens>) -> RelaySigner {
    let inner = Arc::try_unwrap(signer.0).unwrap_or_else(|_| panic!("sole owner"));
    RelaySigner(Arc::new(Inner {
        strategy: ChallengeStrategy::Http01(tokens),
        ..inner
    }))
}

/// One signer as the process-wide handler holds it: mounted under the profiles
/// this fixture places its orders on.
///
/// The handler is no longer the backend's own — it dispatches per row from the
/// profile the payload names — so every fixture has to say which profiles the
/// signer under test answers for, exactly as `cli::build_generation` does from
/// the live profile list.
fn relay_handler(signer: &RelaySigner, profiles: &[&str]) -> flow::RelayJob {
    // The pool comes off the backend here where `cli::build_generation` hands
    // over the process's own: every relay shares it, so the two are the same
    // handle either way.
    flow::RelayJob::new(
        signer.0.database.clone(),
        profiles
            .iter()
            .map(|profile| {
                (
                    (*profile).to_string(),
                    signer
                        .relay_state()
                        .expect("a relay backend always has state to hand over"),
                )
            })
            .collect(),
    )
}

/// Records every event it receives, so a test can assert `settle()`
/// dispatched to the right profile's dispatcher — and only that one.
struct RecordingNotifyBackend {
    events: std::sync::Mutex<Vec<NotifyEvent>>,
}

impl RecordingNotifyBackend {
    fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl crate::notify::NotifyBackend for RecordingNotifyBackend {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), crate::notify::NotifyError> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

/// Waits for a recorder to receive its first event.
///
/// A notification is two hops now — `settle` queues it, the runner delivers it —
/// so a fixed sleep would be a flake. Bounded, so a genuine regression fails
/// rather than hangs.
async fn await_recorded(recorder: &Arc<RecordingNotifyBackend>) {
    for _ in 0..200 {
        if !recorder.events.lock().unwrap().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no notification was delivered within the budget");
}

/// A recorder as a dispatcher slot, wanting every event kind.
fn recording_slot(recorder: Arc<RecordingNotifyBackend>) -> crate::notify::BackendSlot {
    let every: Vec<String> = crate::config::ALL_NOTIFY_EVENTS
        .iter()
        .map(|kind| (*kind).to_string())
        .collect();
    crate::notify::BackendSlot::new("recording", recorder, &every)
}

/// Persists a `ready` order under `profile`, for the profile-scoped
/// notification test — [`ready_order`] hardcodes `"default"`.
async fn ready_order_for(profile: &str, database: Arc<Database>) -> Order {
    let (account, _) = Account::find_or_create(
        profile,
        uuid::Uuid::new_v4().as_bytes(),
        Vec::new(),
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();
    let mut order = Order::create(
        profile,
        &account.id,
        vec![Identifier::dns("example.com")],
        now_secs() + 3600,
        None,
        None,
        &database,
    )
    .await
    .unwrap();
    order.mark_ready(&database).await.unwrap();
    order
}

// Every test here runs on a multi-threaded runtime. `from_config` is
// synchronous and blocks on a scoped thread (see its comment), and the
// scripted upstream lives on this same runtime — on the default
// current-thread flavor the block would stop the server being driven and
// every request would time out. In production the upstream is a separate
// process, so this constraint is the harness's, not the backend's.

/// A real `leaf + CA` chain, so the relay's own parsing of what the
/// upstream returned is exercised rather than stubbed.
async fn real_chain() -> String {
    let ca = LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    let csr = params.serialize_request(&key_pair).unwrap();
    match ca
        .issue(
            "ord-x",
            csr.der(),
            &identifiers(),
            RequestedValidity::default(),
        )
        .await
    {
        Ok(IssueOutcome::Issued(chain)) => chain,
        _ => panic!("the in-memory CA must issue"),
    }
}

/// Persists an order in `ready`, the state finalize requires.
async fn ready_order(database: Arc<Database>) -> Order {
    let (account, _) = Account::find_or_create(
        "default",
        uuid::Uuid::new_v4().as_bytes(),
        Vec::new(),
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();
    let mut order = Order::create(
        "default",
        &account.id,
        vec![Identifier::dns("example.com")],
        now_secs() + 3600,
        None,
        None,
        &database,
    )
    .await
    .unwrap();
    order.mark_ready(&database).await.unwrap();
    order
}

/// A CA-signed leaf carrying an Authority Key Identifier — the shape a
/// real upstream issues, and the only kind an ARI certID can be built
/// from. `LocalCa`'s own leaves have no AKI (it never enables the
/// extension), so they cannot stand in here.
fn ca_signed_leaf_with_aki() -> Vec<u8> {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["ca.example".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap()
        .der()
        .to_vec()
}

fn csr_der() -> Vec<u8> {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params.serialize_request(&key_pair).unwrap().der().to_vec()
}

/// The error text of a failed construction. `RelaySigner` deliberately
/// does not implement `Debug` — it holds an account private key — so
/// `unwrap_err` is unavailable, the same reason `signer::from_config`'s own
/// test matches instead.
fn startup_error(result: anyhow::Result<RelaySigner>) -> String {
    match result {
        Err(error) => error.to_string(),
        Ok(_) => panic!("this configuration must not build"),
    }
}

fn identifiers() -> Vec<Identifier> {
    vec![Identifier::dns("example.com")]
}

/// Waits for the background relay to settle the order, so a test asserts
/// on the finished state rather than racing it.
async fn await_status(database: Arc<Database>, order_id: &str, wanted: OrderStatus) -> Order {
    for _ in 0..200 {
        let order = Order::find_by_id(order_id, &database)
            .await
            .unwrap()
            .unwrap();
        if order.status == wanted {
            return order;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let order = Order::find_by_id(order_id, &database)
        .await
        .unwrap()
        .unwrap();
    panic!("order stayed {}, expected {wanted}", order.status);
}
