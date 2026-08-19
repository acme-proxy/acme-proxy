//! Configuration reload, against a real server on a real socket.
//!
//! The inline suites cover the halves — `src/reload.rs` proves the frozen table
//! refuses by name, `src/jobs/runner.rs` that a swapped registry claims a new
//! kind, `src/tls.rs` that a swapped certificate reaches the next connection.
//! Only this file shows them as one thing: a running server whose answers change
//! while the port it is answering on never moves.
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
/// `admin.enabled` is itself a frozen key, so it has to come from the *file*
/// rather than be poked into the loaded `Config` — a reload re-reads the file
/// and would refuse the difference. That is the check doing its job, and it is
/// why this parameter exists.
fn write_config_with_admin(dir: &TempDir, tls: bool, admin: bool, website: &str, extra: &str) {
    let ca = dir.join("ca");
    let body = format!(
        r#"
        [database]
        url = "sqlite://{dir}/reload.db"

        [server]
        bind_address = "127.0.0.1:0"
        base_url = "http://localhost:3000"

        [server.tls]
        enabled = {tls}
        cert_path = "{dir}/server.pem"
        key_path = "{dir}/server.key"

        # A real address, distinct from `server.bind_address`: the reload path
        # runs `webadmin::check_config`, which refuses two listeners on one
        # socket. The test binds its own ephemeral ports, so these two values
        # are never dialled — but they still have to describe a server that
        # would start.
        [admin]
        enabled = {admin}
        bind_address = "127.0.0.1:3001"
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
        // No metrics listener: `[metrics]` is frozen, so the reload suite has
        // nothing to say about it.
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
    acme_proxy::cli::init_logging(&config.logging).expect("the subscriber must install");
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
