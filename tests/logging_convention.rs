//! The structured-logging convention, enforced against the source itself.
//!
//! `CLAUDE.md` and `doc/src/operations/monitoring.md` both describe how a
//! `tracing` call in this crate is shaped, and operators are told to alert on
//! `event` and `outcome`. Prose alone did not hold: an audit found two call
//! sites computing `event` instead of writing a literal, ~24 names with no
//! subsystem prefix, nine concepts spelled two ways (three of them inside a
//! single file), and one field name meaning two different quantities eight
//! lines apart. Every one of those was individually reasonable and collectively
//! made a prefix grep miss half its family.
//!
//! So the rules are checked rather than described. This walks `src/`, extracts
//! every `info!`/`warn!`/`error!`/`debug!`/`trace!` invocation by balanced-paren
//! scan, and asserts the nine rules stated in `CLAUDE.md`. It is the sibling of
//! `admin_api.rs`'s `mutating_endpoints()`: a new call site that strays fails
//! here, by name, rather than at review time or not at all.
//!
//! One check reaches outside the crate — `every_documented_event_is_still_emitted`
//! reads `doc/src/operations/monitoring.md`, so a rename that misses the
//! operator catalogue fails CI rather than leaving somebody's alert rule
//! pointing at a name nothing emits.
//!
//! An integration test rather than a `#[cfg(test)]` module because this is a
//! repo-wide invariant: a source-walking helper belongs neither in the shipped
//! library nor in the `--fail-under-lines 96` denominator.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The closed subsystem vocabulary (rule 3).
///
/// A name is `<subsystem>_<object>_<outcome>`, and the subsystem half comes
/// from here. Adding an entry is a deliberate act: it means a genuinely new
/// area of the server, not a call site that could not find its family.
const SUBSYSTEMS: &[&str] = &[
    "account",
    "admin",
    "audit",
    "authz",
    "certificate",
    "challenge",
    "contact",
    "csr",
    "db",
    "directory",
    "eab",
    "filter",
    "http_01",
    "ipam",
    "jws",
    "key_change",
    "local_ca",
    "nonce",
    "notify",
    "order",
    "profile",
    "renewal_info",
    "replaces",
    "request",
    "script",
    "server",
    "signer",
    "tls",
    "upstream",
];

/// The four values `outcome` may take (rule 7).
///
/// `advisory` is the one that is not obvious: a configuration statement or a
/// deliberate posture the operator should keep seeing (`tls_disabled`,
/// `challenge_validation_bypassed`). Without it those lines would have to claim
/// `success`, and `outcome = "failure"` would stop meaning exactly one thing.
const OUTCOMES: &[&str] = &["success", "failure", "progress", "advisory"];

/// `pemfile::warn_if_key_is_readable` takes its event name as a `&'static str`
/// so four subsystems share one warning. The only place `event` is not a bare
/// literal, and the reasoning is in that function's doc comment.
const NON_LITERAL_EVENT_EXEMPT: &str = "src/pemfile.rs";

/// The access line is emitted at three levels by response status, which
/// `doc/src/operations/monitoring.md` documents as a table. The only name that
/// may do so.
const MULTI_LEVEL_EXEMPT: &str = "request_completed";

/// Field-name suffixes that hid an ambiguity (rule 9).
///
/// `payload_length` meant base64 characters at one call site and decoded bytes
/// eight lines below it, so a threshold set on it was meaningless. A size field
/// now says which it is: `_bytes` or `_b64_chars`.
const BANNED_FIELD_SUFFIXES: &[&str] = &["_length", "_size"];

/// Field names that used to spell one concept several ways.
const BANNED_FIELD_NAMES: &[&str] = &[
    "removed",     // -> rows_removed
    "deleted",     // -> rows_removed
    "pubkey_hash", // -> pubkey_fp
];

/// One extracted `tracing` call.
struct Site {
    file: String,
    line: usize,
    level: String,
    /// `None` where `event` is not a bare string literal.
    event: Option<String>,
    outcome: Option<String>,
    fields: Vec<String>,
    body: String,
}

impl Site {
    fn at(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

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

/// Index just past the `)` matching the `(` at `open`, skipping string bodies
/// so a parenthesis inside a message does not end the scan early.
fn matching_paren(text: &[u8], open: usize) -> usize {
    let (mut depth, mut i, mut in_string) = (0usize, open, false);
    while i < text.len() {
        match text[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    text.len()
}

/// Every `tracing` macro invocation under `src/`, with its event, outcome and
/// field names pulled out.
fn call_sites() -> Vec<Site> {
    const LEVELS: &[&str] = &["info", "warn", "error", "debug", "trace"];

    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    files.sort();

    let mut sites = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("source file is UTF-8");
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = text.as_bytes();

        for (offset, _) in text.match_indices('!') {
            let Some(level) = LEVELS.iter().find(|level| {
                text[..offset].ends_with(*level)
                    // `!` must open a call, and the token before the level must
                    // not make it part of a longer identifier.
                    && bytes.get(offset + 1) == Some(&b'(')
                    && text[..offset - level.len()]
                        .chars()
                        .next_back()
                        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
            }) else {
                continue;
            };

            let open = offset + 1;
            let body = text[open + 1..matching_paren(bytes, open)].to_string();
            sites.push(Site {
                file: rel.clone(),
                line: text[..offset].matches('\n').count() + 1,
                level: (*level).to_string(),
                event: literal_after(&body, "event"),
                outcome: literal_after(&body, "outcome"),
                fields: field_names(&body),
                body,
            });
        }
    }
    sites
}

/// The string literal assigned to `key`, if `key = "…"` appears in the body.
fn literal_after(body: &str, key: &str) -> Option<String> {
    let at = body.find(&format!("{key} ="))?;
    let rest = body[at + key.len() + 1..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let value = &rest[..end];
    value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        .then(|| value.to_string())
}

/// Field names in a macro body: every `ident =` at the start of an argument.
fn field_names(body: &str) -> Vec<String> {
    let mut names = Vec::new();
    for (index, part) in body.split(',').enumerate() {
        // Only the head of an argument is a field name; `a = b(c, d)` splits
        // mid-call, and those fragments start with the tail of a value.
        let trimmed = part.trim_start();
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let name = trimmed[..eq].trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        // `==` is a comparison, not a field.
        if trimmed[eq + 1..].starts_with('=') {
            continue;
        }
        if index == 0 || part.starts_with(' ') || part.starts_with('\n') {
            names.push(name.to_string());
        }
    }
    names
}

#[test]
fn the_scanner_finds_the_call_sites_it_is_supposed_to() {
    let sites = call_sites();
    // A guard on the guard: a scanner that silently matched nothing would make
    // every assertion below vacuously true.
    assert!(
        sites.len() > 400,
        "expected the crate's several hundred tracing calls, found {}",
        sites.len()
    );
    assert!(
        sites
            .iter()
            .any(|s| s.event.as_deref() == Some("request_completed")),
        "the access line is the one event every request emits; the scanner missed it"
    );
}

#[test]
fn every_event_is_a_bare_string_literal() {
    for site in call_sites() {
        if site.file == NON_LITERAL_EVENT_EXEMPT {
            continue;
        }
        assert!(
            site.event.is_some(),
            "{}: `event` must be a bare string literal, so a name in a log can be \
             grepped straight back to the call site that wrote it. Found: {}",
            site.at(),
            site.body.lines().next().unwrap_or("").trim(),
        );
    }
}

#[test]
fn every_event_name_starts_with_a_known_subsystem() {
    for site in call_sites() {
        let Some(event) = &site.event else { continue };
        assert!(
            SUBSYSTEMS.iter().any(|subsystem| event
                .strip_prefix(subsystem)
                .is_some_and(|rest| rest.starts_with('_'))),
            "{}: event `{event}` has no subsystem prefix. Names are \
             `<subsystem>_<object>_<outcome>`, and operators grep the prefix -- \
             a name outside the family is a name nobody finds. Pick one of: {}",
            site.at(),
            SUBSYSTEMS.join(", "),
        );
    }
}

#[test]
fn every_storage_layer_event_is_db_prefixed() {
    // `db_` marks the layer, not the importance: level stays whatever the event
    // deserves. Enforced off the file path, which is the part that cannot rot.
    for site in call_sites() {
        let Some(event) = &site.event else { continue };
        if !site.file.starts_with("src/sqlite/") {
            continue;
        }
        assert!(
            event.starts_with("db_"),
            "{}: `{event}` is emitted from the storage layer and must be `db_`-prefixed, \
             so a reader can tell a row being written from the operation that asked for it",
            site.at(),
        );
    }
}

#[test]
fn every_site_carries_an_outcome_from_the_closed_set() {
    // No exemption here, `src/pemfile.rs` included: only the *event* may be a
    // parameter there, and the outcome of a permissions warning is knowable.
    for site in call_sites() {
        let outcome = site.outcome.as_deref().unwrap_or_else(|| {
            panic!(
                "{}: every tracing call carries `outcome` beside `event`. Alerting on \
                 failure is an exact match on this field -- without it the only way to \
                 ask is a suffix glob, which misses `_invalid`, `_mismatch`, `_missing` \
                 and `_error`.",
                site.at(),
            )
        });
        assert!(
            OUTCOMES.contains(&outcome),
            "{}: outcome `{outcome}` is not one of {}",
            site.at(),
            OUTCOMES.join(" / "),
        );
    }
}

#[test]
fn the_outcome_agrees_with_the_name_and_the_level() {
    for site in call_sites() {
        let Some(event) = &site.event else { continue };
        let outcome = site.outcome.as_deref().unwrap_or("");

        if event.ends_with("_failed") || event.ends_with("_panicked") {
            assert_eq!(
                outcome,
                "failure",
                "{}: `{event}` says it failed but is marked `{outcome}`",
                site.at(),
            );
        }
        if event.ends_with("_started") || event.ends_with("_requested") {
            assert_eq!(
                outcome,
                "progress",
                "{}: `{event}` names the beginning of an operation, whose result is \
                 not yet known, but is marked `{outcome}`",
                site.at(),
            );
        }
        if site.level == "error" {
            assert_eq!(
                outcome,
                "failure",
                "{}: `{event}` is logged at `error`, which is a failure by definition. \
                 An advisory belongs at `warn`.",
                site.at(),
            );
        }
    }
}

#[test]
fn one_event_name_is_emitted_at_one_level() {
    let mut levels: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for site in call_sites() {
        let Some(event) = site.event.clone() else {
            continue;
        };
        levels
            .entry(event)
            .or_default()
            .insert((site.level.clone(), site.at()));
    }

    for (event, seen) in levels {
        if event == MULTI_LEVEL_EXEMPT {
            continue;
        }
        let distinct: BTreeSet<&String> = seen.iter().map(|(level, _)| level).collect();
        assert!(
            distinct.len() == 1,
            "`{event}` is emitted at {distinct:?}. One name means one thing, and that \
             includes how loud it is -- an operator filtering by level would see the \
             same condition sometimes and not others. Sites: {:?}",
            seen.iter().map(|(_, at)| at).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn numeric_fields_carry_their_unit() {
    for site in call_sites() {
        for field in &site.fields {
            if field == "outcome" || field == "event" {
                continue;
            }
            for banned in BANNED_FIELD_SUFFIXES {
                assert!(
                    !field.ends_with(banned),
                    "{}: field `{field}` ends in `{banned}`, which does not say what it \
                     counts. A size field is `_bytes` (decoded) or `_b64_chars` (encoded) \
                     -- `payload_length` once meant both, eight lines apart.",
                    site.at(),
                );
            }
            assert!(
                !BANNED_FIELD_NAMES.contains(&field.as_str()),
                "{}: field `{field}` is a spelling of a concept that already has a \
                 canonical name (`rows_removed` for a delete count, `*_fp` for a \
                 fingerprint)",
                site.at(),
            );
        }
    }
}

#[test]
fn durations_go_through_the_millis_helper() {
    // `Duration::as_millis` is `u128`, which `tracing` records via `Display`:
    // the JSON output then carries `"42"` where every consumer expects `42`.
    for site in call_sites() {
        assert!(
            !site.body.contains("as_millis()"),
            "{}: a duration field goes through `acme_proxy::millis`, never \
             `Duration::as_millis()` -- the latter lands in JSON as a string",
            site.at(),
        );
    }
}

#[test]
fn every_documented_event_is_still_emitted() {
    let emitted: BTreeSet<String> = call_sites().into_iter().filter_map(|s| s.event).collect();

    let path = repo_root().join("doc/src/operations/monitoring.md");
    let doc = fs::read_to_string(&path).expect("the monitoring page is readable");

    // The event catalogue is the first cell of each row in the page's two
    // tables: a backticked, snake_case token with no dots (which would make it
    // a configuration key instead).
    let mut documented = BTreeSet::new();
    for line in doc.lines() {
        let Some(rest) = line.strip_prefix("| ") else {
            continue;
        };
        let Some(cell) = rest.split('|').next() else {
            continue;
        };
        for chunk in cell.split('`').skip(1).step_by(2) {
            for name in chunk.split(',').map(str::trim) {
                let snake = name.contains('_')
                    && !name.contains('.')
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                if snake {
                    documented.insert(name.to_string());
                }
            }
        }
    }

    assert!(
        documented.len() > 40,
        "expected the operator catalogue to name dozens of events, parsed {}",
        documented.len(),
    );

    let stale: Vec<&String> = documented.difference(&emitted).collect();
    assert!(
        stale.is_empty(),
        "doc/src/operations/monitoring.md documents events this build does not emit: \
         {stale:?}. The check is one-directional on purpose -- the page is a curated \
         subset of {} names and is not expected to list them all -- but it may not \
         promise an operator a name that no longer exists.",
        emitted.len(),
    );
}
