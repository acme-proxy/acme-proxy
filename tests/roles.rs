//! Role processes, against real servers on real sockets over one database.
//!
//! `acme-proxy serve --role acme,admin,worker` is one binary run several times,
//! each doing a subset of the work, so that the process parsing untrusted JWS
//! from the internet is not the one holding operator sessions, and neither is
//! the one reaching out to client-chosen hosts. All-in-one stays the default;
//! this is the split.
//!
//! What only this suite can show is that the three really are one system: the
//! inline tests prove `RoleSet` parses and `plan_schema` decides, but nothing
//! there starts three processes against one **file-backed** `SQLite` and watches
//! work cross between them. The four claims here are the ones a split
//! deployment rests on:
//!
//! 1. An `acme` process serves ACME and an `admin` process serves the panel,
//!    each answering `404` on the other's routes — the split is real, not a
//!    flag that builds everything anyway.
//! 2. The `acme` process **enqueues and does not drain**: a challenge it
//!    triggers stays `processing` until a worker exists, and is decided once one
//!    runs. That is the whole point of the worker role, and the one thing a
//!    single-process test cannot observe.
//! 3. A process that runs no worker refuses to start against a schema that is
//!    behind, naming `acme-proxy migrate` — `SQLite` gives `sqlx` no migration
//!    lock, so one owner is what removes the startup race.
//! 4. The three start **concurrently** without racing the migrations.
//! 5. **Only the worker holds the CA key.** The `acme` and `admin` processes
//!    start, serve the CA's certificate and its CRL, and record revocations,
//!    with no key file to read — and one that finds no CA at all refuses,
//!    naming `acme-proxy init`. The worker signs what they queue.
//!
//! Every test that starts a process runs `acme-proxy init` first, which is the
//! documented topology: the schema and the first-run material belong to one
//! step, before anything serves.
//!
//! **Its own binary, and it touches the disk**, for `reload.rs`'s reasons: the
//! database has to be a file for several processes to share it, and each test
//! writes a `config.toml`. `cargo nextest` gives each test its own process,
//! which is what makes that safe.

mod common;

use std::sync::Arc;

use acme_proxy::config::Config;
use acme_proxy::server::sockets::Sockets as ServerSockets;
use acme_proxy::server::{ProcessRole, RoleSet, serve_on_with_reloads};
use acme_proxy::sqlite::db::Database;
use common::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One role process, with the levers a test needs.
struct Process {
    acme: Option<std::net::SocketAddr>,
    admin: Option<std::net::SocketAddr>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Process {
    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), self.handle).await;
    }
}

/// A single-profile configuration over a database file in `dir`.
///
/// Deliberately one file for every process in the test: sharing the database is
/// what makes them one deployment rather than three unrelated servers.
fn write_config(dir: &TempDir) {
    let ca = dir.join("ca");
    write_config_at(dir, dir, &format!("{}.key", ca.display()));
}

/// [`write_config`] into `into`, over `dir`'s database and CA certificate but
/// with the CA key at `key_path` — what a process running under a uid that
/// cannot read the worker's key sees.
fn write_config_at(dir: &TempDir, into: &TempDir, key_path: &str) {
    let ca = dir.join("ca");
    let body = format!(
        r#"
        [database]
        url = "sqlite://{dir}/roles.db"

        [server]
        base_url = "http://localhost:3000"

        [admin]
        enabled = true

        [profiles.default]
        signer.local_ca.cert_path = "{ca}.pem"
        signer.local_ca.key_path = "{key_path}"
        signer.local_ca.crl_path = "{ca}.crl"
        "#,
        dir = dir.path().display(),
        ca = ca.display(),
    );
    std::fs::write(into.join("config.toml"), body).unwrap();
}

/// `acme-proxy init`: the schema, then the first-run material — here the CA.
async fn initialise(config: &Config) {
    let database = Arc::new(
        Database::open(&config.database.url)
            .await
            .expect("the database must open"),
    );
    acme_proxy::cli::init(
        acme_proxy::palette::Palette::plain(),
        &Arc::new(config.clone()),
        database,
    )
    .await
    .expect("init must succeed");
}

/// Points `ACME_PROXY_CONFIG` at `dir` and loads what is there.
fn load_from(dir: &TempDir) -> Config {
    // SAFETY: nextest gives this test its own process, so nothing else is
    // reading or writing the environment concurrently.
    unsafe {
        std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
    }
    Config::load().expect("the configuration must load")
}

/// Starts one process running `roles`, binding only the sockets those roles own.
///
/// Goes through `serve_on_with_reloads` rather than `server::run` for the
/// harness's usual reason: `run` owns the process's signal handlers and a fixed
/// port, where this needs ephemeral ports and a shutdown a test can trigger.
/// Everything under it — the schema gate, the runner, the listeners — is the
/// same code path `serve` takes.
async fn start(config: &Config, roles: RoleSet) -> Process {
    let database = Arc::new(
        Database::open(&config.database.url)
            .await
            .expect("the database must open"),
    );

    let (acme_listener, acme) = match roles.has(ProcessRole::Acme) {
        false => (None, None),
        true => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            (Some(listener), Some(addr))
        }
    };
    let (admin_listener, admin) = match roles.has(ProcessRole::Admin) {
        false => (None, None),
        true => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            (Some(listener), Some(addr))
        }
    };

    let (shutdown, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_on_with_reloads(
        roles,
        Arc::new(config.clone()),
        database,
        ServerSockets {
            acme: acme_listener,
            admin: admin_listener,
            metrics: None,
        },
        async {
            let _ = rx.await;
        },
        acme_proxy::reload::Reloads::none(),
    ));

    Process {
        acme,
        admin,
        shutdown: Some(shutdown),
        handle,
    }
}

/// A raw `GET`, returning the status line's code.
///
/// Hand-written rather than through a client, `reload.rs`'s choice: the suite
/// needs one number from one request and has no use for a dependency.
async fn status_of(addr: std::net::SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("the port must accept");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let head = String::from_utf8_lossy(&response);
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {head}"))
}

/// The split is real: each process serves its own surface and neither serves
/// the other's.
///
/// Asserted from outside, over real sockets, because the thing being checked is
/// which process answers — a claim no in-process router test can make.
#[tokio::test]
async fn each_role_serves_only_its_own_surface() {
    let dir = TempDir::new("roles-surfaces");
    write_config(&dir);
    let config = load_from(&dir);

    // `acme-proxy init` first, which is the documented topology: the schema
    // and the CA before anything serves. Starting the worker and racing the
    // others against its migration is the case
    // `a_process_without_the_worker_role_refuses_an_unmigrated_database` covers.
    initialise(&config).await;

    let worker = start(&config, RoleSet::parse(Some("worker")).unwrap()).await;
    let acme = start(&config, RoleSet::parse(Some("acme")).unwrap()).await;
    let admin = start(&config, RoleSet::parse(Some("admin")).unwrap()).await;

    let acme_addr = acme.acme.expect("the acme role binds the ACME socket");
    let admin_addr = admin.admin.expect("the admin role binds the admin socket");
    assert!(
        acme.admin.is_none(),
        "an acme process holds no admin socket"
    );
    assert!(
        admin.acme.is_none(),
        "an admin process holds no ACME socket"
    );

    // The ACME process serves the directory and no panel.
    assert_eq!(
        status_of(acme_addr, "/profile/default/directory").await,
        200
    );
    assert_eq!(status_of(acme_addr, "/api/accounts").await, 404);

    // The admin process is the mirror image: the panel answers `401` because
    // there is no session, which is an answer — `404` would mean not routed.
    assert_eq!(status_of(admin_addr, "/api/accounts").await, 401);
    assert_eq!(
        status_of(admin_addr, "/profile/default/directory").await,
        404
    );

    admin.stop().await;
    acme.stop().await;
    worker.stop().await;
}

/// **The claim the worker role exists for.** An `acme` process queues work and
/// drains none of it, so a triggered challenge stays `processing` until a
/// worker runs — and is decided once one does.
///
/// Driven through the database rather than the wire: the trigger's own HTTP
/// answer is covered by `challenges.rs`, and what matters here is *which
/// process* moved the row.
#[tokio::test]
async fn an_acme_process_queues_work_a_worker_performs() {
    let dir = TempDir::new("roles-queue");
    write_config(&dir);
    let config = load_from(&dir);

    // Initialise up front, so the acme process may start on its own below.
    initialise(&config).await;

    let acme = start(&config, RoleSet::parse(Some("acme")).unwrap()).await;
    let acme_addr = acme.acme.expect("the acme role binds the ACME socket");
    assert_eq!(
        status_of(acme_addr, "/profile/default/directory").await,
        200
    );

    // A row this process cannot possibly run: no handler for it is registered
    // anywhere, so only the *claiming* half of the queue is exercised, and the
    // assertion is about who drains rather than about any one subsystem.
    let database = Arc::new(
        Database::open(&config.database.url)
            .await
            .expect("the database must open"),
    );
    let queue = acme_proxy::jobs::JobQueue::new(database.clone(), &config.jobs);
    let sweep =
        acme_proxy::jobs::SweepJob::nonces(database.clone(), std::time::Duration::from_secs(1));
    assert!(
        queue
            .enqueue(acme_proxy::jobs::JobSpec::now(
                acme_proxy::jobs::JobHandler::kind(&sweep),
                "nonces",
            ))
            .await
            .expect("the enqueue must land")
    );

    // Nothing here drains it, however long we wait.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        acme_proxy::sqlite::job::Job::count_live("nonce_sweep", &database)
            .await
            .unwrap(),
        1,
        "an acme-only process must not have run the job"
    );

    // A worker does.
    let worker = start(&config, RoleSet::parse(Some("worker")).unwrap()).await;
    let mut ran = false;
    for _ in 0..200 {
        let row =
            acme_proxy::sqlite::job::Job::find_latest_by_dedup("nonce_sweep", "nonces", &database)
                .await
                .unwrap()
                .expect("the row exists");
        // A sweep reschedules rather than settling, so "it ran" is its `run_at`
        // moving into the future rather than a terminal status.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if row.run_at > now {
            ran = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ran, "the worker must have performed the queued sweep");

    worker.stop().await;
    acme.stop().await;
}

/// A role that does not own the schema refuses to serve against one that is
/// behind, rather than failing later as a missing table.
///
/// The refusal names `acme-proxy migrate`, because an operator meeting it is
/// one step away from the fix.
#[tokio::test]
async fn a_process_without_the_worker_role_refuses_an_unmigrated_database() {
    let dir = TempDir::new("roles-schema");
    write_config(&dir);
    let config = load_from(&dir);

    // Deliberately *not* migrated: `Database::open` no longer does it.
    let database = Arc::new(
        Database::open(&config.database.url)
            .await
            .expect("the database must open"),
    );
    assert!(
        !database.pending_migrations().await.unwrap().is_empty(),
        "the fixture must start behind, or this proves nothing"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = serve_on_with_reloads(
        RoleSet::parse(Some("acme")).unwrap(),
        Arc::new(config.clone()),
        database.clone(),
        ServerSockets {
            acme: Some(listener),
            admin: None,
            metrics: None,
        },
        std::future::pending(),
        acme_proxy::reload::Reloads::none(),
    )
    .await
    .expect_err("an acme process must refuse a schema it does not own");

    let message = error.to_string();
    assert!(message.contains("worker"), "{message}");
    assert!(message.contains("acme-proxy migrate"), "{message}");

    // And it really did not migrate on its way out.
    assert!(!database.pending_migrations().await.unwrap().is_empty());
}

/// The three start together without racing the migrations.
///
/// `SQLite` gives `sqlx` no migration lock, which is why exactly one role owns
/// the schema. Started concurrently, the two that do not own it either find it
/// done or refuse — and a refusal here would fail the assertion below, which is
/// what makes "start the worker first" a documented topology rather than a
/// hidden requirement of the happy path.
#[tokio::test]
async fn the_three_roles_start_concurrently_over_one_database() {
    let dir = TempDir::new("roles-concurrent");
    write_config(&dir);
    let config = load_from(&dir);

    // Initialised first, so the other two are given a schema that is already
    // current and a CA that already exists, which is the topology
    // `deployment.md` documents.
    initialise(&config).await;

    let (worker, acme, admin) = tokio::join!(
        start(&config, RoleSet::parse(Some("worker")).unwrap()),
        start(&config, RoleSet::parse(Some("acme")).unwrap()),
        start(&config, RoleSet::parse(Some("admin")).unwrap()),
    );

    assert_eq!(
        status_of(acme.acme.unwrap(), "/profile/default/directory").await,
        200
    );
    assert_eq!(status_of(admin.admin.unwrap(), "/api/accounts").await, 401);

    // All three are still running: none of them fell over on the way up.
    assert!(!worker.handle.is_finished());
    assert!(!acme.handle.is_finished());
    assert!(!admin.handle.is_finished());

    admin.stop().await;
    acme.stop().await;
    worker.stop().await;
}

/// A raw `GET`, returning the status code and the body.
async fn fetch(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("the port must accept");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a response has a head");
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {head}"));
    (status, response[split + 4..].to_vec())
}

/// **Phase E's claim.** The `acme` and `admin` processes run with no CA key to
/// read — their configuration points `key_path` at a file that does not exist,
/// as a uid that cannot read the worker's would see it — and still serve the
/// CA's certificate and CRL, while the worker signs what is queued and the CRL
/// the acme process serves follows a revocation recorded without the key.
///
/// The key path is the tell: a process that built the backend there would
/// find no key and **generate one** — a new CA, overwriting `ca.pem` — so the
/// file staying absent, and the certificate unchanged, is the proof that
/// nothing but the worker ever touched signing material.
#[tokio::test]
async fn the_acme_and_admin_processes_never_touch_the_ca_key() {
    let dir = TempDir::new("roles-keyless");
    write_config(&dir);
    let config = load_from(&dir);
    initialise(&config).await;
    let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();

    let keyless_dir = TempDir::new("roles-keyless-conf");
    let absent_key = keyless_dir.join("no-such.key");
    write_config_at(&dir, &keyless_dir, absent_key.to_str().unwrap());
    let keyless = load_from(&keyless_dir);

    let acme = start(&keyless, RoleSet::parse(Some("acme")).unwrap()).await;
    let admin = start(&keyless, RoleSet::parse(Some("admin")).unwrap()).await;
    let acme_addr = acme.acme.expect("the acme role binds the ACME socket");

    // Both came up and serve, the acme process the CA's own certificate.
    let (status, body) = fetch(acme_addr, "/profile/default/ca.pem").await;
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8(body).unwrap(), ca_pem);
    assert_eq!(status_of(admin.admin.unwrap(), "/api/accounts").await, 401);
    assert!(!acme.handle.is_finished() && !admin.handle.is_finished());

    // Work queued with no worker running stays queued: an order claimed for
    // issuance, exactly as `finalize` in the acme process leaves one.
    let database = Arc::new(Database::open(&config.database.url).await.unwrap());
    let queue = acme_proxy::jobs::JobQueue::new(database.clone(), &config.jobs);
    let order_id = claimed_order(&database, &queue).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let order = acme_proxy::sqlite::order::Order::find_by_id(&order_id, &database)
        .await
        .unwrap()
        .unwrap();
    assert!(order.certificate.is_none(), "nothing without the key signs");

    // The worker, with the key, signs it.
    let worker = start(&config, RoleSet::parse(Some("worker")).unwrap()).await;
    let order = settled(&database, &order_id).await;
    assert!(order.certificate.is_some(), "the worker must have signed");

    // A revocation recorded without the key — the ledger row the acme and
    // admin roles write — reaches the CRL the acme process serves, once the
    // worker has signed it in.
    let route = acme_proxy::signer::revocation_route(
        &keyless.resolve_profiles().unwrap()[0].sections.signer,
    )
    .unwrap();
    let audit = acme_proxy::auditor::Auditor::offline(database.clone());
    acme_proxy::acme::revoke::Revocations {
        database: &database,
        audit: &audit,
        notify: None,
        revoker: acme_proxy::acme::revoke::Revoker::for_route(
            &route,
            &queue,
            std::time::Duration::ZERO,
        ),
    }
    .revoke_order(
        &order_id,
        Some(1),
        acme_proxy::audit::Actor::cli(),
        acme_proxy::audit::ClientContext::default(),
    )
    .await
    .expect("a local CA's revocation needs no key");
    let serial = order.cert_serial.clone().unwrap();
    let mut listed = false;
    for _ in 0..300 {
        let (status, der) = fetch(acme_addr, "/profile/default/crl").await;
        assert_eq!(status, 200);
        use x509_parser::prelude::FromDer;
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
        if crl
            .iter_revoked_certificates()
            .any(|entry| hex::encode(entry.raw_serial()).eq_ignore_ascii_case(&serial))
        {
            listed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(listed, "the acme process must serve the worker's CRL");

    assert!(
        !absent_key.exists(),
        "a process without the worker role must never create a CA key"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("ca.pem")).unwrap(),
        ca_pem,
        "nor replace the CA"
    );

    worker.stop().await;
    admin.stop().await;
    acme.stop().await;
}

/// B4, the first-run race: a process without the worker role that finds no CA
/// refuses to start, naming the two ways to make one, and makes none itself.
#[tokio::test]
async fn a_process_without_the_worker_role_refuses_a_missing_ca() {
    let dir = TempDir::new("roles-no-ca");
    write_config(&dir);
    let config = load_from(&dir);
    // The schema, but no CA: `migrate` rather than `init`.
    Database::connect_and_migrate(&config.database.url)
        .await
        .expect("the schema must apply");

    let database = Arc::new(Database::open(&config.database.url).await.unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = serve_on_with_reloads(
        RoleSet::parse(Some("acme")).unwrap(),
        Arc::new(config.clone()),
        database,
        ServerSockets {
            acme: Some(listener),
            admin: None,
            metrics: None,
        },
        std::future::pending(),
        acme_proxy::reload::Reloads::none(),
    )
    .await
    .expect_err("an acme process must refuse to start without a CA");

    let message = error.to_string();
    assert!(message.contains("acme-proxy init"), "{message}");
    assert!(message.contains("worker"), "{message}");
    assert!(!dir.join("ca.pem").exists());
    assert!(!dir.join("ca.key").exists());
}

/// A `ready` order for `a.example.com`, claimed with its `signer_issue` row
/// queued — what `finalize` leaves behind — returning its id.
async fn claimed_order(database: &Arc<Database>, queue: &acme_proxy::jobs::JobQueue) -> String {
    use acme_proxy::identifier::Identifier;
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::Order;
    use base64::prelude::*;

    let (account, _) = Account::find_or_create(
        "default",
        &[1, 2, 3],
        vec![],
        &acme_proxy::audit::ClientContext::default(),
        database,
    )
    .await
    .unwrap();
    let mut order = Order::create(
        "default",
        account.id,
        vec![Identifier::dns("a.example.com")],
        2_000_000_000,
        None,
        None,
        database,
    )
    .await
    .unwrap();
    order.mark_ready(database).await.unwrap();
    assert!(order.claim_for_finalize(database).await.unwrap());
    let csr = BASE64_URL_SAFE_NO_PAD
        .decode(common::make_csr("a.example.com"))
        .unwrap();
    assert!(
        queue
            .enqueue(acme_proxy::acme::issue::signer_issue_spec(
                &order,
                &csr,
                &acme_proxy::audit::ClientContext::default(),
                None,
            ))
            .await
            .unwrap()
    );
    order.id.to_string()
}

/// The order once it has left `processing`.
async fn settled(database: &Database, id: &str) -> acme_proxy::sqlite::order::Order {
    for _ in 0..500 {
        let order = acme_proxy::sqlite::order::Order::find_by_id(id, database)
            .await
            .unwrap()
            .unwrap();
        if order.status != acme_proxy::sqlite::status::OrderStatus::Processing {
            return order;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("order {id} never left `processing`");
}
