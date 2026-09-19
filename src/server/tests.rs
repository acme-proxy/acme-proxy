//! The startup path end to end, over real sockets.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

/// A single-profile configuration whose CA and TLS material all live
/// under `dir`, so a test never touches the repository.
fn config_in(dir: impl AsRef<std::path::Path>, tls: bool) -> Config {
    let dir = dir.as_ref();
    let _lock = acme_proxy_core::config::ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ca = dir.join("ca");
    let body = format!(
        r#"
        [server]
        bind_address = "127.0.0.1:0"
        base_url = "http://localhost:3000"

        [server.tls]
        enabled = {tls}
        cert_path = "{dir}/server.pem"
        key_path = "{dir}/server.key"

        [profiles.default]
        signer.local_ca.cert_path = "{ca}.pem"
        signer.local_ca.key_path = "{ca}.key"
        signer.local_ca.crl_path = "{ca}.crl"
        "#,
        dir = dir.display(),
        ca = ca.display(),
    );
    std::fs::write(dir.join("config.toml"), body).unwrap();
    // SAFETY: the lock above makes this the only thread touching the
    // environment, and the variable is removed before returning.
    unsafe {
        std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
    }
    let config = Config::load().expect("the configuration must load");
    unsafe {
        std::env::remove_var("ACME_PROXY_CONFIG");
    }
    config
}

/// Two profiles, each relaying to an upstream of its own.
///
/// The two `[signer]` sections must genuinely differ — different
/// `directory_url` *and* `account_key_path` — or `build_backends`
/// collapses them to one shared backend and the case under test never
/// arises. `signer_paths` would refuse a shared account key outright.
fn two_relay_profiles(
    dir: impl AsRef<std::path::Path>,
    first: &crate::signer::relay::testsrv::Upstream,
    second: &crate::signer::relay::testsrv::Upstream,
) -> Config {
    let dir = dir.as_ref();
    let _lock = acme_proxy_core::config::ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let body = format!(
        r#"
        [server]
        bind_address = "127.0.0.1:0"
        base_url = "http://localhost:3000"

        [profiles.first]
        signer.backend = "relay"
        signer.relay.directory_url = "{first_url}"
        signer.relay.account_key_path = "{dir}/first.key"

        [profiles.second]
        signer.backend = "relay"
        signer.relay.directory_url = "{second_url}"
        signer.relay.account_key_path = "{dir}/second.key"
        "#,
        first_url = first.directory_url(),
        second_url = second.directory_url(),
        dir = dir.display(),
    );
    std::fs::write(dir.join("config.toml"), body).unwrap();
    // SAFETY: the lock above makes this the only thread touching the
    // environment, and the variable is removed before returning.
    unsafe {
        std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
    }
    let config = Config::load().unwrap();
    unsafe {
        std::env::remove_var("ACME_PROXY_CONFIG");
    }
    config
}

fn temp_dir() -> acme_proxy_core::testutil::TempDir {
    acme_proxy_core::testutil::TempDir::new("serve")
}

/// Boots `serve_on` on an ephemeral loopback port and returns it with
/// the handle and the trigger that shuts it back down.
async fn boot(
    config: Config,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_on(Arc::new(config), database, listener, async {
        let _ = rx.await;
    }));
    (addr, tx, handle)
}

/// The cleartext path: real socket, real router, real graceful
/// shutdown. `/health` is a root route, so this also proves the app
/// `serve_on` assembles is the one `build_app` produces.
#[tokio::test]
async fn a_cleartext_server_answers_then_shuts_down() {
    let dir = temp_dir();
    let (addr, shutdown, handle) = boot(config_in(&dir, false)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    shutdown.send(()).unwrap();
    handle
        .await
        .unwrap()
        .expect("a clean shutdown is not an error");
}

/// The same path with `server.tls.enabled`, which swaps the listener
/// for a `TlsListener` — a different `axum::serve` arm, and the only
/// place `TlsListener::spawn` is wired up in production.
#[tokio::test]
async fn a_tls_server_answers_over_a_real_handshake() {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    let dir = temp_dir();
    let (addr, shutdown, handle) = boot(config_in(&dir, true)).await;

    // The generated certificate is self-signed, so the client must not
    // try to verify it — the point here is the listener, not the trust
    // chain.
    let client = crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    shutdown.send(()).unwrap();
    handle
        .await
        .unwrap()
        .expect("a clean shutdown is not an error");
}

/// The three-listener path: one shutdown signal, three sockets, and
/// each one serving only what belongs to it.
///
/// This is the regression test for the `watch` split — before it, the
/// `shutdown` future was consumed once and only one listener stopped —
/// and now also for the metrics listener being genuinely *separate*:
/// `/metrics` answering on the ACME port would put issuance volume and
/// every profile name on the public socket, which is exactly what
/// giving it its own port is for.
#[tokio::test]
async fn all_three_listeners_serve_and_one_signal_stops_them() {
    let dir = temp_dir();
    let mut config = config_in(&dir, false);
    config.admin.enabled = true;
    config.metrics.enabled = true;

    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let acme_addr = acme_listener.local_addr().unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let metrics_addr = metrics_listener.local_addr().unwrap();
    assert_ne!(acme_addr, admin_addr);
    assert_ne!(acme_addr, metrics_addr);
    assert_ne!(admin_addr, metrics_addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_on_with(
        Arc::new(config),
        database,
        acme_listener,
        Some(admin_listener),
        Some(metrics_listener),
        async {
            let _ = rx.await;
        },
    ));

    // `/health` is on both of the two that have it.
    for addr in [acme_addr, admin_addr] {
        let response = get(addr, "/health").await;
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{addr}: {response}"
        );
    }

    // The admin API answers on the admin socket (401, since this
    // request carries no session) and is absent from the ACME one.
    let admin = get(admin_addr, "/api/accounts").await;
    assert!(admin.starts_with("HTTP/1.1 401"), "{admin}");
    let acme = get(acme_addr, "/api/accounts").await;
    assert!(acme.starts_with("HTTP/1.1 404"), "{acme}");

    // And the converse: ACME is on the ACME socket only.
    let directory = get(acme_addr, "/profile/default/directory").await;
    assert!(directory.starts_with("HTTP/1.1 200 OK"), "{directory}");
    let no_directory = get(admin_addr, "/profile/default/directory").await;
    assert!(no_directory.starts_with("HTTP/1.1 404"), "{no_directory}");

    // The exposition is on its own socket...
    let metrics = get(metrics_addr, "/metrics").await;
    assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{metrics}");
    assert!(metrics.contains("acme_proxy_requests_total"), "{metrics}");
    // ...and on **neither** of the other two. The whole point of the
    // third listener is that firewalling this port is what controls who
    // can read it.
    for addr in [acme_addr, admin_addr] {
        let leaked = get(addr, "/metrics").await;
        assert!(leaked.starts_with("HTTP/1.1 404"), "{addr}: {leaked}");
    }

    // One signal, all three stop.
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("every listener must stop on one signal")
        .unwrap()
        .expect("a clean shutdown is not an error");
}

/// Three listeners means the collision check is pairwise, and
/// `webadmin::check_config` only covers admin-versus-server.
#[tokio::test]
async fn a_metrics_bind_colliding_with_another_listener_is_refused() {
    let dir = temp_dir();

    for (other, set) in [
        (
            "server.bind_address",
            Box::new(|c: &mut Config| c.metrics.bind_address = c.server.bind_address.clone())
                as Box<dyn Fn(&mut Config)>,
        ),
        (
            "admin.bind_address",
            Box::new(|c: &mut Config| {
                c.admin.enabled = true;
                c.metrics.bind_address = c.admin.bind_address.clone();
            }),
        ),
    ] {
        let mut config = config_in(&dir, false);
        config.metrics.enabled = true;
        set(&mut config);

        let error = bind_metrics(&Arc::new(config))
            .await
            .expect_err("a shared socket must not start");
        let message = error.to_string();
        assert!(message.contains(other), "{message}");
    }
}

/// The admin bind is only a conflict when the panel is actually going
/// to bind it. Both default to loopback ports, so refusing on the
/// *value* alone would reject a configuration that works.
#[tokio::test]
async fn a_metrics_bind_matching_a_disabled_admin_is_allowed() {
    let dir = temp_dir();
    let mut config = config_in(&dir, false);
    config.metrics.enabled = true;
    config.admin.enabled = false;
    config.metrics.bind_address = config.admin.bind_address.clone();

    let listener = bind_metrics(&Arc::new(config))
        .await
        .expect("a disabled panel holds no socket");
    assert!(listener.is_some());
}

/// Off by default, and off means no socket at all rather than one
/// answering 404.
#[tokio::test]
async fn metrics_disabled_binds_nothing() {
    let dir = temp_dir();
    let config = config_in(&dir, false);
    assert!(!config.metrics.enabled);

    assert!(bind_metrics(&Arc::new(config)).await.unwrap().is_none());
}

/// The admin listener's **own** TLS arm.
///
/// `[server.tls]` and `[admin.tls]` are separate settings with separate
/// certificate paths, on purpose — the two listeners answer to
/// different names — and they go through separate `axum::serve` arms in
/// `serve_admin`. `a_tls_server_answers_over_a_real_handshake` covers
/// the ACME one; this one was the only `TlsListener::spawn` call site
/// in the crate with no test at all, which for the listener that
/// carries an operator's session cookie is the wrong one to miss.
#[tokio::test]
async fn the_admin_listener_answers_over_its_own_tls() {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    let dir = temp_dir();
    let mut config = config_in(&dir, false);
    config.admin.enabled = true;
    // A distinct certificate from the ACME listener's, which is the
    // whole reason these are two settings.
    config.admin.tls.enabled = true;
    config.admin.tls.cert_path = dir.as_ref().join("admin.pem").display().to_string();
    config.admin.tls.key_path = dir.as_ref().join("admin.key").display().to_string();
    // `check_config` refuses a non-loopback bind without TLS; with TLS
    // on it is allowed, and this exercises that branch too.
    config.admin.base_url = "https://localhost:3001".to_string();

    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let acme_addr = acme_listener.local_addr().unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_on_with(
        Arc::new(config),
        database,
        acme_listener,
        Some(admin_listener),
        // This test is about the admin listener's own TLS arm; the
        // metrics listener has none.
        None,
        async {
            let _ = rx.await;
        },
    ));

    // The ACME socket is still cleartext — the two settings really are
    // independent, which a shared switch would hide.
    let acme = get(acme_addr, "/health").await;
    assert!(acme.starts_with("HTTP/1.1 200 OK"), "{acme}");

    // The admin socket needs a handshake. Self-signed, so the client
    // verifies nothing: the listener is the subject, not the chain.
    let client = crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
    let stream = TcpStream::connect(admin_addr).await.unwrap();
    let mut tls = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .expect("the admin listener must complete a handshake");
    tls.write_all(b"GET /api/accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "the admin API answers over TLS, unauthenticated: {response}"
    );

    // The certificate really was written to the admin paths, not the
    // server's — a shared path would make one listener overwrite the
    // other's key on every start.
    assert!(dir.as_ref().join("admin.pem").exists());
    assert!(dir.as_ref().join("admin.key").exists());
    assert!(!dir.as_ref().join("server.pem").exists());

    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("both listeners must stop")
        .unwrap()
        .expect("a clean shutdown is not an error");
}

/// With `[admin]` off — the default — nothing is bound but the ACME
/// socket, and the panel's routes do not exist anywhere.
#[tokio::test]
async fn the_admin_listener_is_absent_by_default() {
    let dir = temp_dir();
    let config = config_in(&dir, false);
    assert!(!config.admin.enabled, "the default must stay off");
    let (addr, shutdown, handle) = boot(config).await;

    let response = get(addr, "/api/accounts").await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");

    shutdown.send(()).unwrap();
    handle.await.unwrap().unwrap();
}

/// A `[admin]` section that cannot work stops the whole process before
/// either socket is bound — it must not leave the ACME listener up and
/// the panel silently missing.
#[tokio::test]
async fn an_invalid_admin_section_refuses_to_serve() {
    let dir = temp_dir();
    let mut config = config_in(&dir, false);
    config.admin.enabled = true;
    // Non-loopback with TLS off: the `Secure` cookie would never be
    // stored, so this is a hard startup error.
    config.admin.bind_address = "0.0.0.0:0".to_string();

    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = serve_on(Arc::new(config), database, listener, std::future::ready(()))
        .await
        .expect_err("a panel that cannot work must not start");
    assert!(error.to_string().contains("is not loopback"), "{error}");
}

/// Sends one request and returns the raw response.
async fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

/// Two profiles relaying to **different** upstreams start.
///
/// The whole shape of the reported bug: each profile's `[signer]`
/// section differs, so `build_backends` keeps them apart, so there are
/// two relay backends — and asking each for its own job handler made
/// `JobRegistry::register` refuse the second for kind
/// `signer_relay_issue`, taking the process down before the socket was
/// ever served. This is the end-to-end form of
/// `signer::relay::tests::multi_profile`, and the only test here that
/// exercises `build_generation` assembling the registry from more than
/// one relay.
#[tokio::test(flavor = "multi_thread")]
async fn two_profiles_relaying_to_different_upstreams_start() {
    use crate::signer::relay::testsrv;

    let first = testsrv::start(testsrv::Script::default()).await;
    let second = testsrv::start(testsrv::Script::default()).await;
    let dir = temp_dir();
    let config = two_relay_profiles(&dir, &first, &second);

    let (addr, shutdown, handle) = boot(config).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    shutdown.send(()).unwrap();
    handle
        .await
        .unwrap()
        .expect("two relay profiles must not refuse to start");
}

/// A configuration mounting nothing fails before the socket is ever
/// served, rather than starting a server that answers 404 everywhere.
#[tokio::test]
async fn a_configuration_with_no_profile_refuses_to_serve() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = serve_on(
        Arc::new(Config::default()),
        database,
        listener,
        std::future::ready(()),
    )
    .await
    .expect_err("a server with no endpoint must not start");
    assert!(error.to_string().contains("profile"), "{error}");
}

/// Unreadable TLS material stops startup instead of silently falling
/// back to cleartext on a port operators believe is HTTPS.
#[tokio::test]
async fn unusable_tls_material_stops_startup() {
    let dir = temp_dir();
    let mut config = config_in(&dir, true);
    std::fs::write(dir.join("server.pem"), "not a certificate").unwrap();
    std::fs::write(dir.join("server.key"), "not a key").unwrap();
    config.server.tls.cert_path = dir.join("server.pem").display().to_string();
    config.server.tls.key_path = dir.join("server.key").display().to_string();

    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = serve_on(Arc::new(config), database, listener, std::future::ready(()))
        .await
        .expect_err("unreadable TLS material must not start a server");
    assert!(!error.to_string().is_empty());
}

/// `run` binds `server.bind_address` itself, so an unusable one is reported
/// rather than panicking.
#[tokio::test]
async fn an_unbindable_address_is_reported() {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let mut config = Config::default();
    // A port on an address this process does not hold.
    config.server.bind_address = "192.0.2.1:1".to_string();
    let error = run(RoleSet::default(), Arc::new(config), database)
        .await
        .expect_err("binding an unroutable address must fail");
    assert!(error.to_string().contains("192.0.2.1:1"), "{error}");
}

/// Only the `worker` role builds a backend: a process running `acme` and
/// `admin` alone has an empty backend set — so no job handler of its holds a
/// key — and serves every profile from a read side over the CA's certificate,
/// without ever reading, or generating, the key.
#[tokio::test]
async fn a_process_without_the_worker_role_builds_no_backend() {
    let dir = temp_dir();
    let config = config_in(dir.path(), false);
    let resolved = config.resolve_profiles().unwrap();
    let database = Arc::new(
        crate::sqlite::db::Database::connect_in_memory()
            .await
            .unwrap(),
    );
    let jobs = crate::testutil::idle_job_queue(database.clone());

    // No CA yet: refused by name, and nothing generated.
    let roles = RoleSet::parse(Some("acme,admin")).unwrap();
    let error = match Assembly::new(roles, &resolved, database.clone(), jobs.clone(), &config) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a process without the worker role must not start without a CA"),
    };
    assert!(error.contains("acme-proxy init"), "{error}");
    assert!(!dir.join("ca.pem").exists() && !dir.join("ca.key").exists());

    // The worker creates it: its assembly builds the backend.
    let (_, worker) = Assembly::new(
        RoleSet::parse(Some("worker")).unwrap(),
        &resolved,
        database.clone(),
        jobs.clone(),
        &config,
    )
    .unwrap();
    assert_eq!(worker.signers.len(), 1);
    assert!(dir.join("ca.key").exists());

    // Now the other roles start — with the key out of reach — and build none.
    std::fs::rename(dir.join("ca.key"), dir.join("elsewhere.key")).unwrap();
    let (_, serving) = Assembly::new(roles, &resolved, database, jobs, &config).unwrap();
    assert!(serving.signers.is_empty(), "no backend outside the worker");
    assert_eq!(serving.infos.len(), 1, "every profile has its read side");
    assert!(
        !dir.join("ca.key").exists(),
        "a process without the worker role must not generate a key"
    );
    let profiles = crate::server::profile::build_all_with(&config, &resolved, &serving).unwrap();
    assert_eq!(
        profiles[0].signer_info.ca_chain_pem().await,
        Some(std::fs::read_to_string(dir.join("ca.pem")).unwrap())
    );
}
