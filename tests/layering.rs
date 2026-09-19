//! Module boundaries the compiler cannot draw inside one crate, enforced
//! against the source itself.
//!
//! `Database`'s pool is private to `crates/store/`, so SQL — and the dialect it
//! is written in — lives in one module tree. The integration tests still need
//! raw SQL for fixtures no table module writes (a back-dated row, a forced
//! constraint violation), and they are another crate, so the escape hatch,
//! `Database::raw_pool`, has to be `pub`. Nothing but this test stops
//! production code calling it, which would make the private field `pub pool`
//! under a longer name.
//!
//! The same walk keeps the host CLI from building a signing backend, and every
//! request-serving module from naming one, since either would put the CA key in
//! a process that has no business holding it.
//!
//! An integration test rather than a `#[cfg(test)]` module for the reason
//! `logging_convention.rs` gives: a source-walking helper belongs neither in
//! the shipped library nor in the coverage denominator.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every Rust source of the workspace: the binary's `src/` and each library
/// crate's `crates/<name>/src/`.
fn workspace_sources() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    for krate in fs::read_dir(root.join("crates"))
        .expect("crates/ is readable")
        .flatten()
    {
        let src = krate.path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut files);
        }
    }
    files
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

/// Whether a whole file is compiled only for tests: a `tests.rs`, a file under
/// a `tests/` directory, or a crate's `testutil.rs`. Each is declared behind
/// `#[cfg(test)]` (or the `test-util` feature) by its parent.
fn is_test_file(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.ends_with("/tests.rs")
        || relative.ends_with("/testutil.rs")
}

/// The part of a file compiled into the shipped library: everything before its
/// first `#[cfg(test)]` **module**.
///
/// A `#[cfg(test)]` on a lone function or impl does not end production code —
/// `proxy.rs` has several ahead of more production items — so only the
/// attribute followed by a `mod` line counts.
///
/// The declaration may carry a visibility: `crates/protocol/src/acme/order.rs` exports its
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
    let files = workspace_sources();

    let mut offenders = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative.starts_with("crates/store/src/") || is_test_file(&relative) {
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
         through a table module in `crates/store/`, `Database::transaction` or \
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

/// No request-serving code names a signing backend (PLAN.md §9.3).
///
/// A request is served from a [`Profile`], whose signer is its read side —
/// `SignerInfo`, built from public material — and the compiler already keeps
/// the backend off it. What it cannot keep out is a handler reaching for a
/// backend some other way: taking a `SignerBackend` from state, building one,
/// or revoking through `Revoker::Backend`. Any of those would put the CA key
/// back in the `acme` or `admin` process, the one thing the split exists to
/// prevent. The backend is the job handlers' alone
/// (`crates/protocol/src/acme/issue.rs`, `crates/protocol/src/acme/revoke.rs`'s
/// `SignerRevokeJob`), in the `worker` role.
///
/// [`Profile`]: acme_proxy_protocol::profile::Profile
#[test]
fn the_request_path_never_holds_a_signer() {
    const REQUEST_PATH: &[&str] = &[
        "crates/protocol/src/handlers",
        "crates/protocol/src/extractors",
        "crates/protocol/src/middlewares",
        "src/webadmin",
        "src/admin",
        "crates/protocol/src/router.rs",
        "crates/protocol/src/profile.rs",
    ];
    const FORBIDDEN: &[&str] = &[
        "SignerBackend",
        "Revoker::Backend(",
        "signer::from_config(",
        "build_backends(",
    ];

    let root = repo_root();
    let mut files = Vec::new();
    for entry in REQUEST_PATH {
        let path = root.join(entry);
        if path.is_dir() {
            rust_sources(&path, &mut files);
        } else {
            files.push(path);
        }
    }
    assert!(
        files.len() > REQUEST_PATH.len(),
        "the walk found the sources"
    );

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
            let code = line.split("//").next().unwrap_or_default();
            if FORBIDDEN.iter().any(|name| code.contains(name)) {
                offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a request is served from the signer's read side and queues what needs \
         the key; it never holds a backend:\n{}",
        offenders.join("\n"),
    );
}

/// Applying the schema is the `worker` role's job and nothing else's.
///
/// Opening the database used to migrate it as a side effect, which made every
/// subcommand an upgrade step and let two processes starting together race
/// `MIGRATOR::run` — `SQLite` gives `sqlx` no migration lock. The split is only
/// worth anything while it stays a split, so the two functions that apply
/// migrations may be called from exactly two places: the commands that own the
/// schema (`acme-proxy migrate` and `init`, in `src/cli/mod.rs`) and the role
/// gate in `src/server/mod.rs`.
///
/// Anywhere else is a silent migration returning, which is the thing this phase
/// removed.
#[test]
fn only_the_schema_owners_apply_migrations() {
    let root = repo_root();
    let sources = workspace_sources();

    // The two owners, plus the module the functions themselves live in.
    const OWNERS: &[&str] = &[
        "src/cli/mod.rs",
        "src/server/mod.rs",
        "crates/store/src/db.rs",
    ];

    let mut offenders = Vec::new();
    for path in sources {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&relative) || OWNERS.contains(&relative.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file must be readable");
        for (number, line) in production_part(&text).lines().enumerate() {
            // Documentation, including the crate doc's compiled startup
            // example, is not production code: it *shows* a caller rather than
            // being one, and the example is deliberately the owner's path.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains(".migrate()") || code.contains("connect_and_migrate(") {
                offenders.push(format!("{relative}:{}: {}", number + 1, code));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "applying the schema belongs to `acme-proxy migrate`/`init` and to the `worker` role's \
         startup gate; everything else checks `pending_migrations` and refuses by name:\n{}",
        offenders.join("\n")
    );
}

/// The crate each top-level module of `src/` is headed for (PLAN.md #6), in
/// dependency order: a crate may name only the crates listed before it in
/// [`CRATE_DEPS`].
const MODULE_CRATE: &[(&str, &str)] = &[
    ("cert", "core"),
    ("client", "core"),
    ("config", "core"),
    ("eab", "core"),
    ("error", "core"),
    ("identifier", "core"),
    ("jws", "core"),
    ("key_change", "core"),
    ("logfields", "core"),
    ("palette", "core"),
    ("pemfile", "core"),
    ("random", "core"),
    ("routes", "core"),
    ("script_hook", "core"),
    ("templating", "core"),
    ("sqlite", "store"),
    ("challenge", "net"),
    ("dns", "net"),
    ("egress", "net"),
    ("http_client", "net"),
    ("listener", "net"),
    ("proxy", "net"),
    ("tls", "net"),
    ("filter", "policy"),
    ("ipam", "policy"),
    ("audit", "core"),
    ("auditor", "jobs"),
    ("jobs", "jobs"),
    ("metrics", "jobs"),
    ("notify", "jobs"),
    ("signer", "signer"),
    ("acme", "protocol"),
    ("extractors", "protocol"),
    ("handlers", "protocol"),
    ("middlewares", "protocol"),
    ("profile", "protocol"),
    ("router", "protocol"),
    ("admin", "admin"),
    ("webadmin", "admin"),
    ("reload", "server"),
    ("server", "server"),
    ("cli", "bin"),
];

/// Each crate and the crates it may depend on.
const CRATE_DEPS: &[(&str, &[&str])] = &[
    ("core", &[]),
    ("store", &["core"]),
    ("net", &["core"]),
    ("policy", &["core", "store", "net"]),
    ("jobs", &["core", "store", "net"]),
    ("signer", &["core", "store", "net", "jobs"]),
    (
        "protocol",
        &["core", "store", "net", "policy", "jobs", "signer"],
    ),
    (
        "admin",
        &[
            "core", "store", "net", "policy", "jobs", "signer", "protocol",
        ],
    ),
    (
        "server",
        &[
            "core", "store", "net", "policy", "jobs", "signer", "protocol", "admin",
        ],
    ),
    (
        "bin",
        &[
            "core", "store", "net", "policy", "jobs", "signer", "protocol", "admin", "server",
        ],
    ),
];

/// Module references that still cross a future crate boundary the wrong way.
/// Each untangling commit deletes its entries; an entry that no longer occurs
/// fails the test too, so this list only ever shrinks.
const KNOWN_BACK_EDGES: &[(&str, &str)] = &[];

/// The top-level modules one line of source names through `crate::`, either
/// directly (`crate::audit::Actor`) or in a group (`use crate::{dns, proxy};`).
fn crate_paths(line: &str) -> Vec<&str> {
    fn ident(text: &str) -> &str {
        let end = text
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(text.len());
        &text[..end]
    }
    let mut found = Vec::new();
    for (index, _) in line.match_indices("crate::") {
        let rest = &line[index + "crate::".len()..];
        if let Some(group) = rest.strip_prefix('{') {
            let group = &group[..group.find('}').unwrap_or(group.len())];
            found.extend(group.split(',').map(|item| ident(item.trim())));
        } else {
            found.push(ident(rest));
        }
    }
    found.retain(|name| !name.is_empty());
    found
}

/// Every module reference in `src/` — production **and** test code, since a
/// test cannot name a crate its own crate is a dependency of either — must
/// point at the module's own crate or one it depends on.
#[test]
fn module_layers_form_a_dag() {
    let crate_of = |module: &str| {
        MODULE_CRATE
            .iter()
            .find(|(name, _)| *name == module)
            .map(|(_, krate)| *krate)
    };
    let may_use = |from: &str, to: &str| {
        from == to
            || CRATE_DEPS
                .iter()
                .find(|(krate, _)| *krate == from)
                .is_some_and(|(_, deps)| deps.contains(&to))
    };

    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);

    let mut unmapped = Vec::new();
    let mut offenders = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let module = relative
            .trim_start_matches("src/")
            .split('/')
            .next()
            .unwrap()
            .trim_end_matches(".rs")
            .to_string();
        // The crate root and the shared test helpers are split up by the
        // extraction itself rather than untangled ahead of it.
        if ["lib", "main", "testutil"].contains(&module.as_str()) {
            continue;
        }
        let Some(from) = crate_of(&module) else {
            unmapped.push(module);
            continue;
        };
        let text = fs::read_to_string(&path).unwrap();
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for target in crate_paths(line) {
                let Some(to) = crate_of(target) else { continue };
                if target == module || may_use(from, to) {
                    continue;
                }
                let edge = (module.clone(), target.to_string());
                if KNOWN_BACK_EDGES.contains(&(edge.0.as_str(), edge.1.as_str())) {
                    seen.insert(edge);
                } else {
                    offenders.push(format!("{relative}:{}: {}", index + 1, line.trim()));
                }
            }
        }
    }

    unmapped.sort();
    unmapped.dedup();
    assert!(
        unmapped.is_empty(),
        "every top-level module needs a crate in MODULE_CRATE: {unmapped:?}"
    );
    assert!(
        offenders.is_empty(),
        "a module names one in a crate its own crate may not depend on:\n{}",
        offenders.join("\n")
    );
    let stale: Vec<_> = KNOWN_BACK_EDGES
        .iter()
        .filter(|(from, to)| !seen.contains(&(from.to_string(), to.to_string())))
        .collect();
    assert!(
        stale.is_empty(),
        "these back-edges are gone; delete them from KNOWN_BACK_EDGES: {stale:?}"
    );
}

#[test]
fn crate_paths_finds_direct_and_grouped_references() {
    assert_eq!(crate_paths("use crate::audit::Actor;"), ["audit"]);
    assert_eq!(
        crate_paths("use crate::{challenge, dns::Resolver, proxy};"),
        ["challenge", "dns", "proxy"]
    );
    assert_eq!(
        crate_paths("let a = crate::cert::x(crate::sqlite::y);"),
        ["cert", "sqlite"]
    );
    assert!(crate_paths("use super::Profile;").is_empty());
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
