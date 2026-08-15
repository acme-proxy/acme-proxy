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
use std::path::{Path, PathBuf};

/// A scratch directory that removes itself on drop, so a failing assertion
/// cannot leave files behind.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Creates a uniquely named directory; `label` only makes it recognisable
    /// if one ever survives a hard crash.
    pub(crate) fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("acme-proxy-{label}-{}", uuid::Uuid::new_v4()));
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
pub(crate) async fn account_id(database: &std::sync::Arc<crate::sqlite::db::Database>) -> String {
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
