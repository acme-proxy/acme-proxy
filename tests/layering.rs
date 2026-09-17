//! Module boundaries the compiler cannot draw inside one crate, enforced
//! against the source itself.
//!
//! `Database`'s pool is private to `src/sqlite/`, so SQL — and the dialect it
//! is written in — lives in one module tree. The integration tests still need
//! raw SQL for fixtures no table module writes (a back-dated row, a forced
//! constraint violation), and they are another crate, so the escape hatch,
//! `Database::raw_pool`, has to be `pub`. Nothing but this test stops
//! production code calling it, which would make the private field `pub pool`
//! under a longer name.
//!
//! The same walk keeps the host CLI from building a signing backend, which
//! would put the CA key in a process that has no business holding it.
//!
//! An integration test rather than a `#[cfg(test)]` module for the reason
//! `logging_convention.rs` gives: a source-walking helper belongs neither in
//! the shipped library nor in the coverage denominator.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src/ is readable").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Whether a whole file is compiled only under `cfg(test)`: a `tests.rs`, a
/// file under a `tests/` directory, or the crate's `testutil.rs`. Each is
/// declared behind `#[cfg(test)]` by its parent.
fn is_test_file(relative: &str) -> bool {
    relative.contains("/tests/") || relative.ends_with("/tests.rs") || relative == "src/testutil.rs"
}

/// The part of a file compiled into the shipped library: everything before its
/// first `#[cfg(test)]` **module**.
///
/// A `#[cfg(test)]` on a lone function or impl does not end production code —
/// `proxy.rs` has several ahead of more production items — so only the
/// attribute followed by a `mod` line counts.
///
/// The declaration may carry a visibility: `src/acme/order.rs` exports its
/// fixtures to the sibling job suite as `pub(crate) mod tests`. Missing that
/// spelling is the dangerous direction — the boundary is simply not found, the
/// whole file reads as production, and the scan reports every fixture in it.
fn production_part(text: &str) -> &str {
    let mut offset = 0;
    let mut lines = text.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]" && lines.peek().is_some_and(|next| is_mod_decl(next)) {
            return &text[..offset];
        }
        offset += line.len();
    }
    text
}

/// Whether a line declares a module, with or without a visibility prefix.
fn is_mod_decl(line: &str) -> bool {
    let line = line.trim_start();
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub(super) "))
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    rest.starts_with("mod ")
}

#[test]
fn production_code_never_reaches_the_raw_pool() {
    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative.starts_with("src/sqlite/") || is_test_file(&relative) {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for (index, line) in production_part(&text).lines().enumerate() {
            if line.contains("raw_pool(") {
                offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "`Database::raw_pool` is for test fixtures only; production code goes \
         through a table module in `src/sqlite/`, `Database::transaction` or \
         `Database::pool_stats`:\n{}",
        offenders.join("\n"),
    );
}

/// The host CLI never builds a signing backend (PLAN.md #10). Building one
/// loads a CA key, logs in to a PKCS#11 token or registers with an upstream —
/// none of which a one-shot command should do beside the server that owns
/// them. A revocation from the CLI is a database write plus a queued job for
/// that server (`signer::revocation_route`); the test fixtures under
/// `#[cfg(test)]` still build one to issue what they revoke.
#[test]
fn the_cli_never_builds_a_signer() {
    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src/cli"), &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&relative) {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for (index, line) in production_part(&text).lines().enumerate() {
            if line.contains("signer::from_config(") || line.contains("build_backends(") {
                offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the CLI records what it asks of a signer in the database and the job \
         queue, and never builds a backend:\n{}",
        offenders.join("\n"),
    );
}

/// The scanner itself: a stray call above the test module is found, one inside
/// it is not, and a `#[cfg(test)]` helper function does not end the scan early.
#[test]
fn the_production_part_ends_at_the_first_test_module() {
    let text = "fn a() {}\n\
                #[cfg(test)]\n\
                fn helper() {}\n\
                fn b() { db.raw_pool(); }\n\
                #[cfg(test)]\n\
                mod tests {\n\
                    fn c() { db.raw_pool(); }\n\
                }\n";
    let production = production_part(text);
    assert_eq!(production.matches("raw_pool(").count(), 1, "{production}");
    assert!(production.contains("fn b()"));
    assert!(!production.contains("mod tests"));

    // A visibility on the test module must not hide the boundary: without
    // this the whole file would read as production and every fixture in it
    // would be reported.
    for visibility in ["", "pub ", "pub(crate) ", "pub(super) "] {
        let text = format!(
            "fn b() {{ db.raw_pool(); }}\n#[cfg(test)]\n{visibility}mod tests {{\n\
             fn c() {{ db.raw_pool(); }}\n}}\n"
        );
        let production = production_part(&text);
        assert_eq!(
            production.matches("raw_pool(").count(),
            1,
            "`{visibility}mod tests` did not end the production part"
        );
    }

    assert_eq!(production_part("fn only() {}\n"), "fn only() {}\n");
    assert!(is_test_file("src/signer/relay/tests/lifecycle.rs"));
    assert!(is_test_file("src/audit/tests.rs"));
    assert!(!is_test_file("src/admin/ops.rs"));
}
