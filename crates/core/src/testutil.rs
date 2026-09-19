//! Scratch directories, scripts, environment guards and span capture, shared
//! by every crate's unit tests.
//!
//! `TempDir` had grown seven independent copies (`tls`, `pemfile`,
//! `signer::custom`, `signer::relay`, `filter::custom`, `notify::custom`,
//! and one in the integration harness), and `write_script` four — including a
//! verbatim ten-line comment about `ETXTBSY`, which is the sort of hard-won
//! explanation that should exist in one place or it stops being maintained in
//! any of them.
//!
//! Compiled only under `cfg(test)` or the `test-util` feature, which the other
//! crates of this workspace turn on through their `[dev-dependencies]` alone,
//! so no normal build ships it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Captures the fields of one named tracing span.
///
/// The only way to assert on a *span* field: unlike an event field, nothing in
/// a response or a captured log line says whether it was recorded or what with.
/// Both halves of the deferred-record pattern are collected — `on_new_span` for
/// the fields set at creation, `on_record` for the ones a later layer fills in
/// (`client_ip`, `profile`, `alg`, `account_id`).
#[derive(Clone)]
pub struct SpanFields {
    name: &'static str,
    fields: Arc<Mutex<HashMap<String, String>>>,
}

impl SpanFields {
    pub fn capturing(name: &'static str) -> Self {
        Self {
            name,
            fields: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The recorded value of `field`, or `None` when it was never recorded —
    /// which is what a `field::Empty` nobody filled in looks like.
    pub fn get(&self, field: &str) -> Option<String> {
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
pub async fn capture_request_span<F, T>(body: F) -> SpanFields
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
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a uniquely named directory; `label` only makes it recognisable
    /// if one ever survives a hard crash.
    pub fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("acme-proxy-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).expect("temp directory must be creatable");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The path of `name` inside this directory, without creating it.
    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `contents` to `name` and returns its path.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
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
pub fn write_script(dir: &TempDir, name: &str, body: &str) -> PathBuf {
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
/// than inside `config::tests` because `proxy` reads the conventional
/// `http_proxy` family and needs exactly the same serialisation — a second copy
/// would take a *different* lock and serialise nothing.
///
/// `ACME_PROXY_CONFIG` is always pinned at a path that does not exist, so a
/// `config.toml` in the working directory cannot leak into a test.
pub struct EnvGuard {
    keys: Vec<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn new(vars: &[(&str, &str)]) -> Self {
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
