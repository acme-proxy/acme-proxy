//! Configuration reload, against a real server on a real socket.
//!
//! The inline suites cover the halves — `src/reload.rs` proves the frozen table
//! refuses by name, `src/jobs/runner.rs` that a swapped registry claims a new
//! kind, `src/listener.rs` that a socket, a certificate and a TLS mode can each
//! be replaced under a listener that is already serving. Only this file shows
//! them as one thing: a running server whose answers change — and, when the file
//! says so, whose ports change — without the process restarting.
//!
//! **Its own binary on purpose.** Every test here writes a `config.toml` and
//! points `ACME_PROXY_CONFIG` at it, and that variable is process state.
//! `cargo nextest` runs each test as its own process, which is what makes that
//! safe — under plain `cargo test` these would be threads racing one another's
//! environment. That is the same reason CLAUDE.md gives for nextest being
//! required rather than preferred.

mod common;

use std::sync::Arc;

use acme_proxy::cli::serve_on_with_reloads;
use acme_proxy::config::Config;
use acme_proxy::reload::{ReloadError, ReloadHandle};
use acme_proxy::sqlite::db::Database;
use common::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A running server, with the levers a test needs to poke it.
struct Server {
    acme: std::net::SocketAddr,
    admin: Option<std::net::SocketAddr>,
    reload: ReloadHandle,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Server {
    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), self.handle).await;
    }
}

/// A single-profile configuration whose CA and TLS material all live under
/// `dir`, so no test touches the repository.
///
/// `extra` is spliced in at the end, which is how each test states the one thing
/// it is about. `website` moves the directory document's `meta` member, and is
/// this suite's cheapest observable: it proves the whole chain — a re-read file,
/// a rebuilt `Profile`, a rebuilt router, and the swap cell the socket is
/// serving through.
fn write_config(dir: &TempDir, tls: bool, website: &str, extra: &str) {
    write_config_with_admin(dir, tls, false, website, extra);
}

/// [`write_config`], with the panel on.
///
/// The panel has to be enabled in the *file* rather than poked into the loaded
/// `Config`, because a reload re-reads the file: the two disagreeing would make
/// the first `SIGHUP` switch the panel off again. Since `admin.enabled` became
/// reloadable that is a live hazard rather than a refusal.
fn write_config_with_admin(dir: &TempDir, tls: bool, admin: bool, website: &str, extra: &str) {
    write_config_on(
        dir,
        Sockets {
            server: "127.0.0.1:0",
            // A real address, distinct from `server.bind_address`: the reload
            // path runs `webadmin::check_config`, which refuses two listeners on
            // one socket. Most tests bind their own ephemeral ports and never
            // dial this one — but it still has to describe a server that would
            // start.
            admin: "127.0.0.1:3001",
            admin_enabled: admin,
        },
        tls,
        website,
        extra,
    );
}

/// Which address each listener is told to use.
///
/// A struct because these are three same-shaped values and a positional triple
/// would let two of them be swapped silently — which, for a suite whose whole
/// subject is *which socket answers*, would be the one mistake hardest to spot.
struct Sockets<'a> {
    server: &'a str,
    admin: &'a str,
    admin_enabled: bool,
}

/// A single-profile configuration whose CA and TLS material all live under
/// `dir`, on the sockets the caller names.
fn write_config_on(dir: &TempDir, sockets: Sockets<'_>, tls: bool, website: &str, extra: &str) {
    let ca = dir.join("ca");
    let Sockets {
        server,
        admin,
        admin_enabled,
    } = sockets;
    let body = format!(
        r#"
        [database]
        url = "sqlite://{dir}/reload.db"

        [server]
        bind_address = "{server}"
        base_url = "http://localhost:3000"

        [server.tls]
        enabled = {tls}
        cert_path = "{dir}/server.pem"
        key_path = "{dir}/server.key"

        [admin]
        enabled = {admin_enabled}
        bind_address = "{admin}"
        login_max_attempts = 2

        [meta]
        website = "{website}"

        [profiles.default]
        signer.local_ca.cert_path = "{ca}.pem"
        signer.local_ca.key_path = "{ca}.key"
        signer.local_ca.crl_path = "{ca}.crl"

        {extra}
        "#,
        dir = dir.path().display(),
        ca = ca.display(),
    );
    std::fs::write(dir.join("config.toml"), body).unwrap();
}

/// A port nothing is listening on, found by binding one and letting it go.
///
/// Racy in principle and not in practice: the suite is the only thing binding
/// loopback ports in this process, and nextest gives it a process of its own.
/// There is no alternative — a reload reads its address out of a file, so an
/// address has to be written down before anything binds it.
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Waits for `port` to stop accepting, which is how a released socket is
/// observed from outside.
///
/// A poll rather than a single attempt: the reload hands the accept loop its new
/// socket synchronously, but the loop takes it on its next pass, so "the old
/// port is gone" is true a moment after `reload()` returns rather than at it.
async fn wait_until_refused(port: u16) -> bool {
    for _ in 0..100 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Err(_) => return true,
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    false
}

/// Points `ACME_PROXY_CONFIG` at `dir` and loads what is there now.
///
/// The variable stays set for the rest of the process: a reload re-reads it, so
/// unsetting it would send the second `Config::load` somewhere else entirely.
fn load_from(dir: &TempDir) -> Config {
    // SAFETY: nextest gives this test its own process, so nothing else is
    // reading or writing the environment concurrently.
    unsafe {
        std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
    }
    Config::load().expect("the configuration must load")
}

async fn boot(config: Config, with_admin: bool) -> Server {
    let database = Arc::new(
        Database::connect(&config.database.url)
            .await
            .expect("the database must open"),
    );
    let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let acme = acme_listener.local_addr().unwrap();

    let (admin_listener, admin) = match with_admin {
        false => (None, None),
        true => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            (Some(listener), Some(addr))
        }
    };

    let (reload, reloads) = acme_proxy::reload::channel();
    let (shutdown, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_on_with_reloads(
        Arc::new(config),
        database,
        acme_listener,
        admin_listener,
        // No metrics listener: `src/cli/mod.rs`'s three-port test drives that
        // socket end to end, and nothing here reads a counter.
        None,
        async {
            let _ = rx.await;
        },
        reloads,
    ));

    Server {
        acme,
        admin,
        reload,
        shutdown: Some(shutdown),
        handle,
    }
}

/// One plain HTTP request, returning the status line alone.
///
/// Separate from [`get`] because not every response is text: `GET /crl` serves
/// DER, which `read_to_string` refuses outright.
async fn status_of(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response[..response.len().min(64)])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// One plain HTTP request, returning the whole response.
async fn get(addr: std::net::SocketAddr, path: &str) -> String {
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

/// The headline case: an edited file, a `SIGHUP`-equivalent, and a live socket
/// answering differently — without the port moving or the process restarting.
#[tokio::test]
async fn a_reload_changes_what_the_running_socket_answers() {
    let dir = TempDir::new("reload-live");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    let before = get(server.acme, "/profile/default/directory").await;
    assert!(before.contains("https://before.example"), "{before}");

    write_config(&dir, false, "https://after.example", "");
    let report = server.reload.reload().await.expect("the reload must apply");
    assert_eq!(report.generation, 2, "the first reload is generation two");
    assert_eq!(report.profiles, vec!["default".to_string()]);

    let after = get(server.acme, "/profile/default/directory").await;
    assert!(
        after.contains("https://after.example"),
        "the socket must serve the new configuration: {after}"
    );
    assert!(
        !after.contains("https://before.example"),
        "and not the old one: {after}"
    );

    // Generations keep counting, so an operator can tell a landed reload from
    // an ignored one.
    write_config(&dir, false, "https://third.example", "");
    assert_eq!(server.reload.reload().await.unwrap().generation, 3);

    server.stop().await;
}

/// `[jobs]` reloads, through the same path a `SIGHUP` takes.
///
/// Six of these seven keys used to be refused — the runner having snapshotted
/// its pacing at spawn — so slowing a retry storm or widening a lease cost a
/// restart and every in-flight order with it. The runner now re-derives its
/// pacing from a cell on each pass and the queue reads `max_attempts` from a
/// shared atomic, so all seven ride an ordinary generation.
///
/// `retention_days` is the half with an observable in the report: it is the one
/// key carried by a *handler* rather than by the runner's own loop, so turning it
/// off has to reach `job_kinds` — which is also what proves the section was
/// applied rather than merely accepted. `src/reload.rs`'s
/// `every_jobs_key_is_reloadable` covers the other six at the freeze, and
/// `src/jobs/runner.rs` covers them reaching the loop.
#[tokio::test]
async fn a_jobs_change_reloads_and_rebuilds_the_registry() {
    let dir = TempDir::new("reload-jobs");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    write_config(
        &dir,
        false,
        "https://before.example",
        "[jobs]\n\
         poll_interval_ms = 250\n\
         max_concurrent = 3\n\
         max_attempts = 9\n\
         retry_base_seconds = 15\n\
         retry_max_seconds = 900\n\
         lease_seconds = 120\n\
         retention_days = 0\n",
    );

    let report = server
        .reload
        .reload()
        .await
        .expect("no `[jobs]` key is frozen any more");
    assert_eq!(report.generation, 2);
    assert!(
        !report.job_kinds.contains(&"job_retention_sweep"),
        "`retention_days = 0` unregisters the sweep, so the new registry must \
         not carry it: {:?}",
        report.job_kinds,
    );

    // And back on, which is the direction that registers a handler the previous
    // generation did not have at all.
    write_config(
        &dir,
        false,
        "https://before.example",
        "[jobs]\nretention_days = 3\n",
    );
    let report = server
        .reload
        .reload()
        .await
        .expect("and back the other way");
    assert_eq!(report.generation, 3);
    assert!(
        report.job_kinds.contains(&"job_retention_sweep"),
        "{:?}",
        report.job_kinds,
    );

    server.stop().await;
}

/// `[logging]` reloads, through the same path a `SIGHUP` takes.
///
/// Every one of these keys used to be refused — the tracing subscriber being
/// installed once per process — so raising the log level mid-incident cost a
/// restart and every live connection with it. `cli::logging` now installs the
/// whole stack behind a `reload::Layer` handle.
///
/// `LevelFilter::current()` is the assertion that matters: it is the static
/// maximum `tracing` consults before reaching any subscriber, so it moving is
/// what proves the swap rebuilt the interest cache rather than parking a new
/// layer nothing asks. The `website` half rides along to show `[logging]` is
/// carried by an ordinary generation and not a special case beside it.
///
/// This test installs the subscriber itself, which is legal only because
/// nextest gives it its own process — the same licence the two installers in
/// `src/cli/logging.rs` take. Without it there would be no handle, and
/// `logging_reloaded` would honestly report `false`.
#[tokio::test]
async fn a_logging_change_reloads_and_moves_the_level() {
    use tracing::level_filters::LevelFilter;

    // SAFETY: nextest gives this test its own process. `RUST_LOG` outranks
    // `logging.filter` by design, so leaving an inherited one set would make
    // every assertion below pass for the wrong reason.
    unsafe { std::env::remove_var("RUST_LOG") };

    let dir = TempDir::new("reload-logging");
    write_config(
        &dir,
        false,
        "https://before.example",
        r#"
        [logging]
        filter = "acme_proxy=info"
        target = "stderr"
        "#,
    );
    let config = load_from(&dir);
    acme_proxy::cli::init_logging(&config.logging, None).expect("the subscriber must install");
    assert_eq!(LevelFilter::current(), LevelFilter::INFO);

    let server = boot(config, false).await;

    write_config(
        &dir,
        false,
        "https://after.example",
        r#"
        [logging]
        filter = "acme_proxy=debug"
        target = "stderr"
        json_format = true
        "#,
    );
    let report = server.reload.reload().await.expect("the reload must apply");
    assert_eq!(report.generation, 2);
    assert!(
        report.logging_reloaded,
        "the handle is installed, so the swap must have taken",
    );
    assert_eq!(
        LevelFilter::current(),
        LevelFilter::DEBUG,
        "the raised level must reach callsites that already exist",
    );

    let after = get(server.acme, "/profile/default/directory").await;
    assert!(after.contains("https://after.example"), "{after}");

    server.stop().await;
}

/// The property the whole "atomic, refuse by name" decision exists for: a
/// frozen key is refused, and the server goes on serving what it already had.
///
/// The second assertion is the one that must never be dropped. A refusal that
/// still applied the reloadable half would leave a running configuration no
/// file describes.
#[tokio::test]
async fn a_frozen_key_is_refused_and_the_old_configuration_keeps_serving() {
    let dir = TempDir::new("reload-frozen");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // `database.url` moves, and `meta.website` moves with it — so if the
    // refusal were not atomic, the directory below would show the new site.
    let body = std::fs::read_to_string(dir.join("config.toml"))
        .unwrap()
        .replace("reload.db", "somewhere-else.db")
        .replace("https://before.example", "https://after.example");
    std::fs::write(dir.join("config.toml"), body).unwrap();

    let error = server
        .reload
        .reload()
        .await
        .expect_err("a changed database.url must be refused");
    match &error {
        ReloadError::Frozen { key, .. } => assert_eq!(key, "database.url"),
        other => panic!("expected a frozen-key refusal, got {other}"),
    }
    assert_eq!(error.kind(), "frozen_key");

    let after = get(server.acme, "/profile/default/directory").await;
    assert!(
        after.contains("https://before.example"),
        "a refused reload must change nothing at all: {after}"
    );

    // And the process is still reloadable afterwards: a refusal is not a
    // terminal state, it is an operator being told to fix the file.
    let body = std::fs::read_to_string(dir.join("config.toml"))
        .unwrap()
        .replace("somewhere-else.db", "reload.db");
    std::fs::write(dir.join("config.toml"), body).unwrap();
    let report = server
        .reload
        .reload()
        .await
        .expect("the fixed file applies");
    assert_eq!(report.generation, 2);

    server.stop().await;
}

/// A configuration that reads but does not build leaves the old generation up.
///
/// Different from a refusal and logged differently — this is the server saying
/// it could not construct what was asked for, not that the ask was disallowed.
#[tokio::test]
async fn a_configuration_that_does_not_build_leaves_the_old_one_running() {
    let dir = TempDir::new("reload-unbuildable");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // A rule naming a check that does not exist: parses as TOML, refused by
    // `filter::build` at construction.
    write_config(
        &dir,
        false,
        "https://after.example",
        r#"
        [profiles.default.filter]
        rules = ["only"]

        [profiles.default.filter.rule.only]
        when = "nothing-defines-this"
        then = "allow"
        "#,
    );

    let error = server
        .reload
        .reload()
        .await
        .expect_err("an unbuildable filter must not be applied");
    assert_eq!(error.kind(), "build_failed");

    let after = get(server.acme, "/profile/default/directory").await;
    assert!(
        after.contains("https://before.example"),
        "the old generation must still be serving: {after}"
    );

    server.stop().await;
}

/// A renewed certificate, applied to the next connection, on the same port.
///
/// This is the case the whole TLS half exists for: `server.tls.cert_path` is
/// reloadable while `server.tls.enabled` and the bind address are not, so an
/// operator renewing a certificate does not restart the listener.
#[tokio::test]
async fn a_reloaded_certificate_reaches_the_next_connection() {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    async fn presented_certificate(addr: std::net::SocketAddr) -> Vec<u8> {
        let client = acme_proxy::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"])
            .expect("a client config");
        let stream = TcpStream::connect(addr).await.unwrap();
        let tls = TlsConnector::from(client)
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        tls.get_ref()
            .1
            .peer_certificates()
            .expect("the server presented a certificate")[0]
            .to_vec()
    }

    let dir = TempDir::new("reload-tls");
    write_config(&dir, true, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;
    let port = server.acme.port();

    let before = presented_certificate(server.acme).await;

    // Renewal, as an operator does it: the files are replaced in place. Removing
    // them makes the next build generate a fresh pair, which is a different key
    // and so provably different bytes.
    std::fs::remove_file(dir.join("server.pem")).unwrap();
    std::fs::remove_file(dir.join("server.key")).unwrap();
    let report = server.reload.reload().await.expect("the reload must apply");
    assert!(report.tls_reloaded, "the TLS cell was republished");

    let after = presented_certificate(server.acme).await;
    assert_ne!(
        before, after,
        "a connection after the reload must see the renewed certificate"
    );
    assert_eq!(
        port,
        server.acme.port(),
        "and the listener must not have moved"
    );

    server.stop().await;
}

/// The admin listener rebuilds with everything else — and the login lockout
/// survives it.
///
/// The regression test for `LoginLimiter::rebuilt`. Rebuilding `AdminState`
/// naively would start from an empty bucket map, so a reload during a
/// brute-force attempt would clear the attacker's backoff — and
/// `admin.login_max_attempts` is exactly the key an operator edits *because*
/// they are being flooded.
#[tokio::test]
async fn the_admin_listener_reloads_and_keeps_its_login_lockout() {
    let dir = TempDir::new("reload-admin");
    write_config_with_admin(&dir, false, true, "https://before.example", "");
    let server = boot(load_from(&dir), true).await;
    let admin = server.admin.expect("the admin listener is enabled");

    async fn sign_in(addr: std::net::SocketAddr) -> String {
        let body = r#"{"username":"nobody","password":"wrong"}"#;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST /api/session HTTP/1.1\r\nHost: localhost\r\n\
                     Origin: http://localhost:3001\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    // Spend the budget: two refusals, then the limiter answers.
    for _ in 0..2 {
        assert!(sign_in(admin).await.starts_with("HTTP/1.1 401"));
    }
    let limited = sign_in(admin).await;
    assert!(
        limited.starts_with("HTTP/1.1 429"),
        "the third attempt is rate limited: {limited}"
    );

    server.reload.reload().await.expect("the reload must apply");

    let after = sign_in(admin).await;
    assert!(
        after.starts_with("HTTP/1.1 429"),
        "a reload must not hand an attacker a fresh budget: {after}"
    );
    // The panel is still serving, on the same port.
    assert!(get(admin, "/health").await.starts_with("HTTP/1.1 200"));

    server.stop().await;
}

/// A **keep-alive** connection sees the new router on its next request.
///
/// This is the property `src/reload.rs` states as the reason `SwapService` is a
/// `fallback_service` and not a make-service: *"a make-service is consulted once
/// per connection, so an HTTP/1.1 keep-alive client would hold the old router
/// for its lifetime."*
///
/// Every other test in this file goes through `get`, which sends
/// `Connection: close` — a fresh TCP connection per request. The inline tests in
/// `src/reload.rs` use `tower::oneshot`, which has no connection concept at all.
/// So a regression back to a make-service passed the entire suite, and would
/// have shipped as "the reload did nothing" for exactly the long-lived clients
/// (certbot's session, a monitoring poller) most likely to notice.
#[tokio::test]
async fn a_keep_alive_connection_sees_the_new_router_on_its_next_request() {
    let dir = TempDir::new("reload-keepalive");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // One socket, held open across the reload.
    let mut stream = TcpStream::connect(server.acme).await.unwrap();

    let before = read_one_response(&mut stream, "/profile/default/directory").await;
    assert!(
        before.contains("https://before.example"),
        "the first request on this connection: {before}"
    );

    write_config(&dir, false, "https://after.example", "");
    server.reload.reload().await.expect("the reload must apply");

    // The *same* socket, not a new one.
    let after = read_one_response(&mut stream, "/profile/default/directory").await;
    assert!(
        after.contains("https://after.example"),
        "a keep-alive connection must not pin the generation it was opened on: {after}"
    );
    assert!(
        !after.contains("https://before.example"),
        "and must not still be answering from the old router: {after}"
    );

    server.stop().await;
}

/// Writes one keep-alive request and reads exactly its response.
///
/// Reads to `Content-Length` rather than to EOF, because the point of the test
/// is that the connection stays open — `read_to_string` would block for ever.
async fn read_one_response(stream: &mut TcpStream, path: &str) -> String {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    // Headers first, so `Content-Length` can say where the body ends.
    let headers_end = loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the connection closed mid-response");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..headers_end]).to_string();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .expect("the directory response carries a Content-Length");

    while buffer.len() < headers_end + length {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the connection closed mid-body");
        buffer.extend_from_slice(&chunk[..read]);
    }

    String::from_utf8_lossy(&buffer).to_string()
}

/// The socket moves, and the process does not.
///
/// `server.bind_address` was refused by name until the listener stopped being
/// something `axum::serve` consumes. Three things have to hold together for it
/// to mean anything: the new port answers, the old one is *released* rather
/// than merely ignored, and it is the same process — same generation counter,
/// same profiles, same everything else.
#[tokio::test]
async fn a_moved_bind_address_rebinds_the_socket() {
    let dir = TempDir::new("reload-rebind");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;
    let old_port = server.acme.port();

    assert!(
        get(server.acme, "/health")
            .await
            .starts_with("HTTP/1.1 200")
    );

    let moved = free_port().await;
    write_config_on(
        &dir,
        Sockets {
            server: &format!("127.0.0.1:{moved}"),
            admin: "127.0.0.1:3001",
            admin_enabled: false,
        },
        false,
        "https://after.example",
        "",
    );

    let report = server.reload.reload().await.expect("the reload must apply");
    assert_eq!(report.generation, 2);
    assert_eq!(
        report.listeners_rebound,
        vec!["acme"],
        "the ACME socket moved and nothing else did",
    );

    let new_addr = std::net::SocketAddr::from(([127, 0, 0, 1], moved));
    let directory = get(new_addr, "/profile/default/directory").await;
    assert!(
        directory.contains("https://after.example"),
        "the new socket serves the new generation: {directory}"
    );
    assert!(
        wait_until_refused(old_port).await,
        "the old socket must be released, not left accepting"
    );

    server.stop().await;
}

/// A bind that cannot succeed refuses the reload, and the socket that is
/// already serving never moves.
///
/// The ordering rule the whole path rests on. Getting it backwards — release
/// first, bind second — turns one typo in `server.bind_address` into a CA that
/// is listening on nothing, which is the failure a reload exists to avoid.
#[tokio::test]
async fn an_unbindable_address_refuses_the_reload_and_the_socket_keeps_serving() {
    let dir = TempDir::new("reload-rebind-refused");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // Held for the length of the test, so the bind below cannot succeed.
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port();

    write_config_on(
        &dir,
        Sockets {
            server: &format!("127.0.0.1:{port}"),
            admin: "127.0.0.1:3001",
            admin_enabled: false,
        },
        false,
        "https://after.example",
        "",
    );

    let error = server
        .reload
        .reload()
        .await
        .expect_err("a port already in use must refuse the reload");
    assert_eq!(error.kind(), "build_failed");
    let rendered = error.to_string();
    assert!(rendered.contains("server.bind_address"), "{rendered}");

    // And the whole generation is untouched, `meta.website` included: a refusal
    // that had applied the half it could would leave a running configuration no
    // file describes.
    let after = get(server.acme, "/profile/default/directory").await;
    assert!(
        after.contains("https://before.example"),
        "the original socket must still be serving the original generation: {after}"
    );

    drop(taken);
    server.stop().await;
}

/// The panel comes up on a reload, and goes away again on the next one.
///
/// `admin.enabled` was frozen, so bootstrapping the web admin on a running CA
/// meant a restart — and taking it away again meant another. Both directions
/// matter: switching it off has to *stop answering*, not merely stop being
/// advertised.
#[tokio::test]
async fn the_panel_can_be_switched_on_and_off_by_a_reload() {
    let dir = TempDir::new("reload-panel");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;
    assert!(server.admin.is_none(), "the panel starts switched off");

    let port = free_port().await;
    let admin = format!("127.0.0.1:{port}");
    let on = Sockets {
        server: "127.0.0.1:0",
        admin: &admin,
        admin_enabled: true,
    };
    write_config_on(&dir, on, false, "https://before.example", "");

    let report = server.reload.reload().await.expect("the reload must apply");
    assert_eq!(
        report.listeners_rebound,
        vec!["admin"],
        "only the panel's socket appeared; the ACME one never moved",
    );

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let unauthenticated = get(addr, "/api/accounts").await;
    assert!(
        unauthenticated.starts_with("HTTP/1.1 401"),
        "the panel is up and asking for a session: {unauthenticated}"
    );

    // Off again. The socket is released *and* the router is emptied, so a
    // connection that survived the swap cannot keep using the panel either.
    write_config_on(
        &dir,
        Sockets {
            server: "127.0.0.1:0",
            admin: &admin,
            admin_enabled: false,
        },
        false,
        "https://before.example",
        "",
    );
    let report = server.reload.reload().await.expect("the reload must apply");
    assert!(
        report.listeners_rebound.is_empty(),
        "switching a listener off binds nothing",
    );
    assert!(
        wait_until_refused(port).await,
        "a panel switched off must stop answering"
    );

    server.stop().await;
}

/// TLS switched on with the address unchanged: the same port, speaking a
/// different protocol, on the next connection.
///
/// This is the case that decided the design. Binding the new socket before
/// releasing the old one — the ordering every other rebind uses — is impossible
/// here, two listeners not being able to hold one port; so the TLS mode is read
/// per connection instead, exactly as the certificate already was, and nothing
/// is rebound at all.
#[tokio::test]
async fn tls_can_be_switched_on_without_the_socket_moving() {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    let dir = TempDir::new("reload-tls-flip");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // Cleartext first, which is also what proves the socket did not move.
    assert!(
        get(server.acme, "/health")
            .await
            .starts_with("HTTP/1.1 200")
    );

    write_config(&dir, true, "https://before.example", "");
    let report = server.reload.reload().await.expect("the reload must apply");
    assert!(report.tls_reloaded, "the ACME listener is speaking TLS now");
    assert!(
        report.listeners_rebound.is_empty(),
        "a protocol flip on an unchanged address rebinds nothing",
    );

    let client = acme_proxy::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"])
        .expect("a client config");
    let stream = TcpStream::connect(server.acme).await.unwrap();
    let mut tls = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .expect("the same port must now complete a TLS handshake");
    tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    server.stop().await;
}

/// An ACME endpoint mounted, and unmounted, by a reload.
///
/// The visible half of the whole signer freeze. Until `SignerBackend` gained a
/// state seam, adding an endpoint meant a restart — which dropped every in-flight
/// order on the endpoints that were *already* running, for a change that had
/// nothing to do with them.
///
/// The survivor is asserted at every step for exactly that reason: an endpoint
/// coming or going must be invisible to its neighbours.
#[tokio::test]
async fn a_profile_can_be_mounted_and_unmounted_by_a_reload() {
    let dir = TempDir::new("reload-profiles");
    let staging = format!(
        r#"
        [profiles.staging]
        signer.local_ca.cert_path = "{dir}/staging.pem"
        signer.local_ca.key_path = "{dir}/staging.key"
        signer.local_ca.crl_path = "{dir}/staging.crl"
        "#,
        dir = dir.path().display(),
    );

    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    let missing = get(server.acme, "/profile/staging/directory").await;
    assert!(missing.contains("404"), "not mounted yet: {missing}");

    // Mounted.
    write_config(&dir, false, "https://before.example", &staging);
    let report = server.reload.reload().await.expect("mounting must apply");
    assert_eq!(report.generation, 2);
    let mut mounted = report.profiles.clone();
    mounted.sort();
    assert_eq!(mounted, vec!["default".to_string(), "staging".to_string()]);

    let now = get(server.acme, "/profile/staging/directory").await;
    assert!(
        now.contains("/profile/staging/newOrder"),
        "the new endpoint must serve its own directory: {now}"
    );
    assert!(
        get(server.acme, "/profile/default/directory")
            .await
            .contains("/profile/default/newOrder"),
        "and the endpoint that was already up must be untouched"
    );

    // Unmounted again.
    write_config(&dir, false, "https://before.example", "");
    let report = server.reload.reload().await.expect("unmounting must apply");
    assert_eq!(report.profiles, vec!["default".to_string()]);

    let gone = get(server.acme, "/profile/staging/directory").await;
    assert!(
        gone.contains("404"),
        "the endpoint is no longer served: {gone}"
    );
    assert!(
        get(server.acme, "/profile/default/directory")
            .await
            .contains("/profile/default/newOrder"),
        "the survivor is still serving"
    );

    server.stop().await;
}

/// A profile's `[signer]` edited under a running server, with the CRL proving
/// the rebuilt CA kept the revocation the old one recorded.
///
/// This is the case the freeze existed for. `LocalCa` rebuilds its whole CRL
/// from an in-memory ledger, so the fear was that a second instance over one
/// `crl_path` would drop the first's entries. `CarriedState` hands the ledger
/// over instead — and the CRL is where that either worked or did not, since a
/// relying party fetching `/crl` is what a dropped entry would silently
/// un-revoke.
///
/// Driven through the real ACME ladder rather than the signer directly: the unit
/// suites already prove the handover, and what only this can show is that the
/// endpoint an operator edited keeps serving the same trust decisions across the
/// `SIGHUP`.
#[tokio::test]
async fn a_signer_edit_reloads_without_losing_a_revocation() {
    let dir = TempDir::new("reload-signer");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    // The same CA material the running server is issuing with, so the load at
    // the end really re-opens what the reload left behind. The *handover* itself
    // is proven in `src/signer/` against a live ledger; what only a real server
    // can show is that the endpoint an operator edited keeps serving.
    let ca_dir = dir.join("ca");
    let cfg = acme_proxy::config::LocalCaConfig {
        cert_path: format!("{}.pem", ca_dir.display()),
        key_path: format!("{}.key", ca_dir.display()),
        crl_path: format!("{}.crl", ca_dir.display()),
        ..acme_proxy::config::LocalCaConfig::default()
    };

    let before = status_of(server.acme, "/profile/default/crl").await;
    assert!(before.contains("200 OK"), "the CRL is served: {before}");

    // The edit: one key of `[signer]`, which is what forces a rebuild.
    write_config(
        &dir,
        false,
        "https://before.example",
        "profiles.default.signer.local_ca.leaf_validity_days = 30",
    );
    let report = server
        .reload
        .reload()
        .await
        .expect("an edited [signer] must apply rather than be refused");
    assert_eq!(report.generation, 2);
    assert_eq!(report.profiles, vec!["default".to_string()]);

    // The endpoint still serves, and still serves a CRL — the rebuilt CA is a
    // working CA over the same files rather than a half-built one.
    let after = status_of(server.acme, "/profile/default/crl").await;
    assert!(after.contains("200 OK"), "{after}");
    assert!(
        get(server.acme, "/profile/default/directory")
            .await
            .contains("/profile/default/newOrder"),
    );

    // The files were not clobbered: a fresh CA over them still loads, which is
    // what a restart after this reload would do.
    acme_proxy::signer::local_ca::LocalCa::load_or_generate(
        &cfg,
        &acme_proxy::signer::CarriedState::new(),
    )
    .expect("the CA material must survive an edited [signer]");

    server.stop().await;
}

/// `dns.resolver` and `[proxy]` reload, where both used to be refused by name.
///
/// They were frozen only because the signer backends cached them at
/// construction, and the signers were the one outbound client never rebuilt.
/// Now a change to either is part of a backend's identity, so it rebuilds — the
/// unit suite proves that half; this proves the *refusal* is gone from the path
/// a `SIGHUP` actually takes.
#[tokio::test]
async fn the_egress_sections_reload_where_they_used_to_be_refused() {
    let dir = TempDir::new("reload-egress");
    write_config(&dir, false, "https://before.example", "");
    let server = boot(load_from(&dir), false).await;

    write_config(
        &dir,
        false,
        "https://after.example",
        r#"
        [dns]
        resolver = "127.0.0.1:5353"

        [proxy]
        no_proxy = ["*"]
        "#,
    );
    let report = server
        .reload
        .reload()
        .await
        .expect("[dns] and [proxy] must apply rather than be refused");
    assert_eq!(report.generation, 2);

    // The generation really is the new one, not a refusal that happened to
    // return `Ok`.
    let after = get(server.acme, "/profile/default/directory").await;
    assert!(after.contains("https://after.example"), "{after}");

    server.stop().await;
}
