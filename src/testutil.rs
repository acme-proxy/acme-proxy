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
