//! Scratch-directory and script helpers shared by the crate's unit tests.
//!
//! `TempDir` had grown seven independent copies (`tls`, `pemfile`,
//! `signer::custom`, `signer::relay`, `filter::custom`, `notify::custom`,
//! and one in the integration harness), and `write_script` four — including a
//! verbatim ten-line comment about `ETXTBSY`, which is the sort of hard-won
//! explanation that should exist in one place or it stops being maintained in
//! any of them.
//!
//! `#[cfg(test)]` rather than a real module: this is scaffolding, and shipping
//! it in the library would be shipping test code to every consumer. Integration
//! tests cannot see it for the same reason and keep their own copy under
//! `tests/common/`.

use crate::audit::ClientContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A Prometheus registry for a test that only needs one to exist.
///
/// Every `RelaySigner::from_config` takes one because the backend counts a
/// deferred issuance through it; almost no test asserts on the counters, so
/// this keeps the noise to one call.
pub(crate) fn test_metrics(
    database: Arc<crate::sqlite::db::Database>,
) -> Arc<crate::metrics::Metrics> {
    Arc::new(crate::metrics::Metrics::new(database))
}

/// Captures the fields of one named tracing span.
///
/// The only way to assert on a *span* field: unlike an event field, nothing in
/// a response or a captured log line says whether it was recorded or what with.
/// Both halves of the deferred-record pattern are collected — `on_new_span` for
/// the fields set at creation, `on_record` for the ones a later layer fills in
/// (`client_ip`, `profile`, `alg`, `account_id`).
#[derive(Clone)]
pub(crate) struct SpanFields {
    name: &'static str,
    fields: Arc<Mutex<HashMap<String, String>>>,
}

impl SpanFields {
    pub(crate) fn capturing(name: &'static str) -> Self {
        Self {
            name,
            fields: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The recorded value of `field`, or `None` when it was never recorded —
    /// which is what a `field::Empty` nobody filled in looks like.
    pub(crate) fn get(&self, field: &str) -> Option<String> {
        self.fields.lock().unwrap().get(field).cloned()
    }
}

impl tracing::field::Visit for SpanFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .lock()
            .unwrap()
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanFields {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attrs.metadata().name() == self.name {
            attrs.record(&mut self.clone());
        }
    }

    fn on_record(
        &self,
        _id: &tracing::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        values.record(&mut self.clone());
    }
}

/// Runs `body` under a subscriber capturing the `request` span, and returns
/// what it recorded.
///
/// `#[tokio::test]` is a current-thread runtime, so the thread-local default
/// this installs covers the whole future including its awaits.
pub(crate) async fn capture_request_span<F, T>(body: F) -> SpanFields
where
    F: std::future::Future<Output = T>,
{
    use tracing_subscriber::layer::SubscriberExt;

    let captured = SpanFields::capturing("request");
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    body.await;
    captured
}

/// A scratch directory that removes itself on drop, so a failing assertion
/// cannot leave files behind.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Creates a uniquely named directory; `label` only makes it recognisable
    /// if one ever survives a hard crash.
    pub(crate) fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("acme-proxy-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).expect("temp directory must be creatable");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The path of `name` inside this directory, without creating it.
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `contents` to `name` and returns its path.
    pub(crate) fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, contents).expect("temp file must be writable");
        path
    }
}

/// So a `TempDir` drops straight into anything taking a path — `std::fs`,
/// `Path::join`, a config field — without `.path()` at every call site. Most of
/// the callers this replaced were passing `&dir` to exactly those.
impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes an executable script and returns its path.
///
/// ## Why the suite must run under `cargo nextest`, not `cargo test`
///
/// Every caller of this exec's a file it has just written. Under plain
/// `cargo test`, which runs tests as threads of a single process, that
/// intermittently fails with `ETXTBSY`: another thread's `Command::spawn` forks
/// while this file's write descriptor is still open, and the forked child holds
/// that descriptor until its own `exec`. The kernel refuses to execute a file
/// any process holds open for writing.
///
/// Nothing here can avoid it. The check is against the inode, so writing
/// elsewhere and renaming into place does not help either, and the window is
/// owned by an unrelated thread. `cargo test --lib` fails roughly one run in
/// three because of it. `nextest`'s process-per-test isolation removes it
/// entirely, which is why it is a requirement of this project rather than a
/// preference.
#[cfg(unix)]
pub(crate) fn write_script(dir: &TempDir, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.write(name, body);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("script must be made executable");
    path
}

/// Sets `ACME_PROXY_*`-style variables for the life of the guard, holding
/// [`crate::config::ENV_LOCK`] throughout.
///
/// Environment variables are process state, so a test setting one while another
/// calls `Config::load()` makes the second read the first's. Lives here rather
/// than inside `config::tests` because [`crate::proxy`] reads the conventional
/// `http_proxy` family and needs exactly the same serialisation — a second copy
/// would take a *different* lock and serialise nothing.
///
/// `ACME_PROXY_CONFIG` is always pinned at a path that does not exist, so a
/// `config.toml` in the working directory cannot leak into a test.
pub(crate) struct EnvGuard {
    keys: Vec<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub(crate) fn new(vars: &[(&str, &str)]) -> Self {
        let _lock = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut keys = vec!["ACME_PROXY_CONFIG".to_string()];
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", "/nonexistent/acme-proxy-config");
            for (key, value) in vars {
                std::env::set_var(key, value);
                keys.push((*key).to_string());
            }
        }
        Self { keys, _lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            for key in &self.keys {
                std::env::remove_var(key);
            }
        }
    }
}

/// No proxy at all — what every test that is not *about* proxying wants.
pub(crate) fn no_proxies() -> std::sync::Arc<crate::proxy::OutboundProxies> {
    std::sync::Arc::new(crate::proxy::OutboundProxies::direct())
}

/// Outbound transport for a test: the given resolver and no proxy.
///
/// The pair used to be passed separately at every one of these call sites, and
/// `no_proxies()` names what it is for — a test that is not *about* proxying.
pub(crate) fn outbound_with(
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> crate::http_client::Outbound {
    crate::http_client::Outbound::new(resolver, no_proxies())
}

/// A job queue with nothing draining it.
///
/// What every test that merely has to *construct* a signer backend wants: the
/// queue is a constructor argument since the `relay` backend defers issuance
/// into it, and a test asserting on a startup refusal or a synchronous backend
/// never enqueues anything. A test that needs the work actually done starts a
/// runner over its own queue instead — see `signer::relay::tests::TestRunner`.
pub(crate) fn idle_job_queue(
    database: std::sync::Arc<crate::sqlite::db::Database>,
) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, &crate::config::JobsConfig::default())
}

/// Egress for a test: the given resolver, no proxy, and an identity nothing
/// compares against.
///
/// The identity only matters to `signer::build_backends`, which uses it to
/// decide whether a reload has to rebuild a backend. A test constructing one
/// directly has no previous generation, so any value does.
pub(crate) fn egress_with(
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> std::sync::Arc<crate::Egress> {
    std::sync::Arc::new(crate::Egress {
        resolver,
        proxies: no_proxies(),
        identity: "test".to_string(),
    })
}

/// The dependencies a signer backend is built from, for a test that is not about
/// any of them.
///
/// No notifiers (nothing dispatches), a registry nothing scrapes and a queue
/// nothing drains — the same three "throwaway" arguments every one of these call
/// sites used to spell out one by one before `SignerParts` gathered them.
pub(crate) fn signer_parts(
    database: std::sync::Arc<crate::sqlite::db::Database>,
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> crate::signer::SignerParts {
    crate::signer::SignerParts {
        database: database.clone(),
        notifiers: std::collections::HashMap::new().into(),
        metrics: test_metrics(database.clone()),
        egress: egress_with(resolver),
        jobs: idle_job_queue(database),
    }
}

/// How a [`FakeProxy`] answers the request it is handed.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum ProxyBehaviour {
    /// Answer a `CONNECT` with this literal status line and headers (the
    /// trailing blank line is added), then splice the two sockets together.
    ///
    /// The status line is a parameter because real proxies do not agree on it:
    /// squid answers `HTTP/1.0 200 Connection established` with a `Proxy-Agent`
    /// header, which is what the framing here has to survive.
    Tunnel {
        status: &'static str,
        /// Ignore the `CONNECT` target's host and dial `127.0.0.1` on this port
        /// instead, so a test can use a real *name* in the request — which is
        /// what an SNI assertion needs — without that name having to resolve.
        force_port: Option<u16>,
    },
    /// Refuse, with this literal response including its body — the `407` shape.
    Refuse(&'static str),
    /// Answer a forwarded (absolute-form) request with this literal response.
    Forward(&'static str),
}

/// A loopback forward proxy that records what it was asked for.
///
/// Real proxies are not available in a unit test and a container would be a
/// different suite; what this has to prove is the wire shape — the `CONNECT`
/// request-target, the absolute-form request line, `Proxy-Authorization`, and
/// that a tunnel really carries bytes end to end.
#[cfg(test)]
pub(crate) struct FakeProxy {
    pub port: u16,
    /// The head of every request this proxy received, in order.
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Connections accepted. A bypass test asserts this is zero, which no
    /// assertion about the *response* could ever prove.
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl FakeProxy {
    pub(crate) async fn start(behaviour: ProxyBehaviour) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let seen = requests.clone();
        let counter = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let seen = seen.clone();
                tokio::spawn(async move {
                    // Read exactly the head: anything past the blank line is the
                    // tunnelled payload and belongs to the far end.
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while stream.read_exact(&mut byte).await.is_ok() {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let target = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    seen.lock().unwrap().push(head);

                    match behaviour {
                        ProxyBehaviour::Refuse(response) => {
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        ProxyBehaviour::Forward(response) => {
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        ProxyBehaviour::Tunnel { status, force_port } => {
                            let target = match force_port {
                                Some(port) => format!("127.0.0.1:{port}"),
                                None => target,
                            };
                            let Ok(mut upstream) = tokio::net::TcpStream::connect(&target).await
                            else {
                                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                                return;
                            };
                            let _ = stream.write_all(status.as_bytes()).await;
                            let _ = stream.write_all(b"\r\n").await;
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        }
                    }
                });
            }
        });

        Self {
            port,
            requests,
            connections,
        }
    }

    /// `http://127.0.0.1:<port>`, for a `proxy.http_url`/`https_url`.
    pub(crate) fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A list of `(type, value)` pairs as [`Identifier`]s.
///
/// The `Identifier::dns`/`Identifier::new` constructors cover the single-name
/// case, which is most of them; this is the twelfth-copy problem's other half —
/// two modules had a verbatim `fn ids(&[(&str, &str)])` and several more built
/// the same `Vec` inline.
#[cfg(test)]
pub(crate) fn identifiers(pairs: &[(&str, &str)]) -> Vec<crate::sqlite::order::Identifier> {
    pairs
        .iter()
        .map(|(typ, value)| crate::sqlite::order::Identifier::new(*typ, *value))
        .collect()
}

/// The `dns`-only shorthand for [`identifiers`].
#[cfg(test)]
pub(crate) fn dns_identifiers(values: &[&str]) -> Vec<crate::sqlite::order::Identifier> {
    values
        .iter()
        .map(|value| crate::sqlite::order::Identifier::dns(*value))
        .collect()
}

/// An account in the `default` profile, returning its id.
///
/// Three modules had grown a verbatim copy of this (`admin::ops`,
/// `admin::render`, `sqlite::order`) — the same accumulation as `TempDir` and
/// the `Identifier` builders, and the reason both now live somewhere shared.
#[cfg(test)]
pub(crate) async fn account_id(
    database: &std::sync::Arc<crate::sqlite::db::Database>,
) -> uuid::Uuid {
    let (account, _) = crate::sqlite::account::Account::find_or_create(
        "default",
        &[1u8, 2, 3],
        vec![],
        &ClientContext::default(),
        database,
    )
    .await
    .expect("an in-memory database always accepts an account");
    account.id
}

/// A `ClientContext` carrying nothing but an address and its reverse name.
///
/// The three states a renderer has to tell apart (`ip (ptr)`, the address
/// alone, neither) are exactly the three ways this is called.
#[cfg(test)]
pub(crate) fn client_context(ip: Option<&str>, ptr: Option<&str>) -> ClientContext {
    ClientContext {
        ip: ip.map(str::to_string),
        ptr: ptr.map(str::to_string),
        ..ClientContext::default()
    }
}

/// An account created from `client`, whose traceability columns are therefore
/// whatever that context carried.
///
/// `pubkey` is a parameter because `find_or_create` dedupes on it: two calls
/// sharing one would hand back the *first* account, contexts and all.
#[cfg(test)]
pub(crate) async fn account_seen_from(
    pubkey: &[u8],
    client: &ClientContext,
    database: &std::sync::Arc<crate::sqlite::db::Database>,
) -> crate::sqlite::account::Account {
    crate::sqlite::account::Account::find_or_create(
        "default",
        pubkey,
        vec!["mailto:a@example.com".to_string()],
        client,
        database,
    )
    .await
    .expect("an in-memory database always accepts an account")
    .0
}

/// An unsaved order in the `default` profile, in `status`.
#[cfg(test)]
pub(crate) fn order_fixture(
    account_id: uuid::Uuid,
    status: crate::sqlite::status::OrderStatus,
) -> crate::sqlite::order::Order {
    let mut order = crate::sqlite::order::Order::new(
        "default",
        account_id,
        vec![crate::sqlite::order::Identifier::dns("example.com")],
        0,
        None,
        None,
    );
    order.status = status;
    order
}

/// A *really issued* order on `profile`: signed by an in-memory local CA, so
/// the stored chain parses and the RFC 9773 certID the `replaces` signal rests
/// on can actually be derived from it.
///
/// Hoisted out of `notify::expiry`'s suite when the supersession annotation
/// moved to `admin::ops` — the digest's tests and the annotation's own both
/// need a row no hand-built fixture can stand in for. Distinct from
/// [`order_fixture`], which is an unsaved row with no certificate at all.
#[cfg(test)]
pub(crate) async fn issued_order(
    database: &crate::sqlite::db::Database,
    profile: &str,
    account: uuid::Uuid,
    names: &[&str],
    not_after_days: i64,
) -> crate::sqlite::order::Order {
    use crate::sqlite::order::{Identifier, Order};

    const DAY: i64 = 24 * 60 * 60;

    let signer = crate::signer::local_ca::LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap();
    let mut order = Order::create(
        profile,
        account,
        names.iter().map(|name| Identifier::dns(*name)).collect(),
        crate::sqlite::nonce::now_secs() + 3600,
        None,
        None,
        database,
    )
    .await
    .unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>())
            .unwrap();
    let csr = params.serialize_request(&key_pair).unwrap();
    let chain = match crate::signer::SignerBackend::issue(
        &signer,
        order.id.to_string().as_str(),
        csr.der(),
        &order.identifiers,
        crate::signer::RequestedValidity::default(),
    )
    .await
    .unwrap()
    {
        crate::signer::IssueOutcome::Issued(chain) => chain,
        crate::signer::IssueOutcome::Processing => panic!("the in-memory CA is synchronous"),
    };
    let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
    let (serial, pubkey) = crate::cert::cert_serial_and_spki(&leaf).unwrap();
    order
        .finalize(
            chain,
            serial,
            pubkey,
            Some(crate::sqlite::nonce::now_secs() + not_after_days * DAY),
            database,
        )
        .await
        .unwrap();
    order
}

/// One `certificate_issued` row with every optional column filled in, so a
/// renderer test can blank the ones it wants absent.
#[cfg(test)]
pub(crate) fn audit_entry() -> crate::sqlite::audit::AuditEntry {
    crate::sqlite::audit::AuditEntry {
        id: 41_812,
        created_at: 1_700_000_000,
        event: "certificate_issued".to_string(),
        outcome: "success".to_string(),
        profile: "le".to_string(),
        actor_kind: "acme".to_string(),
        actor_id: Some("acct-1".to_string()),
        account_id: Some("acct-1".to_string()),
        order_id: Some("order-1".to_string()),
        cert_serial: Some("0a0b".to_string()),
        identifiers: vec!["a.example.com".to_string(), "b.example.com".to_string()],
        client_ip: Some("203.0.113.7".to_string()),
        client_ptr: Some("host.example.com".to_string()),
        user_agent: Some("certbot/2.9.0".to_string()),
        request_id: Some("req-1".to_string()),
        reason: None,
        detail: None,
    }
}

/// An `active` operator with no second factor and no login yet.
///
/// The id both admin fixtures carry, so the session keeps naming its user.
#[cfg(test)]
pub(crate) const ADMIN_FIXTURE_ID: uuid::Uuid = uuid::uuid!("11111111-2222-3333-4444-555555555555");

/// The `password_hash` is a syntactically valid stored hash rather than a
/// placeholder, because more than one test asserts `pbkdf2` never reaches a
/// terminal and a fake would pass that vacuously.
#[cfg(test)]
pub(crate) fn admin_user_fixture() -> crate::sqlite::admin_user::AdminUser {
    crate::sqlite::admin_user::AdminUser {
        id: ADMIN_FIXTURE_ID,
        username: "alice".to_string(),
        password_hash: "pbkdf2-sha256$600000$c2FsdA$aGFzaA".to_string(),
        status: "active".to_string(),
        totp_secret: None,
        totp_pending_secret: None,
        totp_last_step: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        last_login_at: None,
    }
}

/// An `active` session for [`admin_user_fixture`].
#[cfg(test)]
pub(crate) fn admin_session_fixture() -> crate::sqlite::admin_session::AdminSession {
    crate::sqlite::admin_session::AdminSession {
        token_hash: "0123456789abcdef0123456789abcdef".to_string(),
        user_id: ADMIN_FIXTURE_ID,
        csrf_token: "the-csrf-token".to_string(),
        state: "active".to_string(),
        mfa_attempts: 0,
        created_at: 1_700_000_000,
        expires_at: 1_700_043_200,
        last_seen_at: 1_700_000_000,
        created_ip: Some("192.0.2.1".to_string()),
        user_agent: Some("curl/8".to_string()),
    }
}
