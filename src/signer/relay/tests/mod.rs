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
//! - [`lifecycle`] — startup, provisioning, `issue`/relay/settle, revoke, resume
//! - [`eab`] — the upstream credential, both ways of supplying it
//! - [`dns01_strategy`] / [`http01_strategy`] — the two answering strategies
//! - [`renewal`] — RFC 9773 windows, and the `UpstreamError` mapping

mod dns01_strategy;
mod eab;
mod http01_strategy;
mod lifecycle;
mod renewal;

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
use crate::notify::NotifyEvent;
use crate::signer::local_ca::LocalCa;
use crate::sqlite::account::Account;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::Order;
use crate::testutil::TempDir;
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

fn no_notifiers() -> Arc<HashMap<String, Arc<NotifyDispatcher>>> {
    Arc::new(HashMap::new())
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
async fn await_status(database: Arc<Database>, order_id: &str, wanted: &str) -> Order {
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
