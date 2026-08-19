//! The shipped Grafana dashboard, checked against the metrics this build
//! actually emits.
//!
//! The second test in the crate that reads an artifact rather than running the
//! server — `logging_convention.rs` is the first, and this is the same idea
//! applied to `dashboards/acme-proxy.json`. A dashboard is exactly the sort of
//! thing that rots silently: rename a metric and every panel built on it goes
//! blank, with nothing failing and nobody told until an operator opens it
//! during an incident.
//!
//! ## The source of truth is `render()`, not the source code
//!
//! The set of real metric names comes from calling
//! [`acme_proxy::metrics::Metrics::render`] on an **empty** registry and
//! parsing its `# TYPE` lines. That works because `render_family` emits the
//! `# HELP`/`# TYPE` pair for every family even when it holds no series — a
//! deliberate property (a dashboard built on a name that has not happened yet
//! should find the name, not an absence it cannot tell from a typo), and one
//! this file turns into a guarantee.
//!
//! Grepping `src/metrics.rs` for `acme_proxy_` string literals would have been
//! the obvious alternative and is strictly worse: it would pass for a name that
//! is written in the source but never reaches the wire.

use std::collections::BTreeSet;
use std::sync::Arc;

use acme_proxy::metrics::Metrics;
use acme_proxy::sqlite::db::Database;
use serde_json::Value;

/// Every metric name this build emits, read out of a real exposition.
async fn emitted_metrics() -> BTreeSet<String> {
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let rendered = Metrics::new(database).render();

    let names: BTreeSet<String> = rendered
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect();

    assert!(
        names.len() >= 4,
        "an empty registry must still declare every family; parsed {names:?} from:\n{rendered}"
    );
    names
}

fn dashboard() -> (String, Value) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("dashboards/acme-proxy.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let parsed = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("{} is valid JSON: {error}", path.display()));
    (raw, parsed)
}

/// Every `acme_proxy_*` token anywhere in the file.
///
/// Deliberately over-broad — it scans the whole document rather than only the
/// `expr` fields — because a metric name also appears in panel descriptions and
/// in the `profile` variable's `label_values(...)` query, and a rename has to
/// reach those too.
fn referenced_metrics(raw: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(&['a', 'c', 'm', 'e', '_', 'p', 'r', 'o', 'x', 'y', '_']) {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i] == '_') {
                i += 1;
            }
            found.insert(bytes[start..i].iter().collect::<String>());
        } else {
            i += 1;
        }
    }
    found
}

/// The rename guard, and the reason this file exists.
#[tokio::test]
async fn every_metric_the_dashboard_queries_is_one_this_build_emits() {
    let emitted = emitted_metrics().await;
    let (raw, _) = dashboard();

    let referenced = referenced_metrics(&raw);
    assert!(
        !referenced.is_empty(),
        "the scanner found no metric names at all, which would make every \
         assertion here vacuously true"
    );

    let unknown: Vec<&String> = referenced.difference(&emitted).collect();
    assert!(
        unknown.is_empty(),
        "dashboards/acme-proxy.json references metrics this build does not \
         emit: {unknown:?}. A renamed metric leaves a silently empty panel, so \
         the dashboard moves with the rename or the rename does not land. \
         Emitted: {emitted:?}"
    );
}

/// The converse. Four families is few enough to insist the dashboard covers
/// them all — where `logging_convention.rs` checks only one direction, because
/// its page is a curated subset of ~490 event names and never claimed to be
/// exhaustive.
#[tokio::test]
async fn every_metric_this_build_emits_appears_on_the_dashboard() {
    let emitted = emitted_metrics().await;
    let (raw, _) = dashboard();

    let referenced = referenced_metrics(&raw);
    let missing: Vec<&String> = emitted.difference(&referenced).collect();
    assert!(
        missing.is_empty(),
        "these metrics are emitted but appear nowhere on the dashboard: \
         {missing:?}. A new family that nothing visualises is one an operator \
         will never know they have."
    );
}

/// A panel with no query renders as a blank box, which reads as "no data"
/// rather than as the mistake it is.
#[test]
fn every_panel_has_a_datasource_and_at_least_one_query() {
    let (_, dashboard) = dashboard();

    let panels = dashboard["panels"]
        .as_array()
        .expect("the dashboard has a panels array");
    assert!(
        panels.len() > 5,
        "expected a dashboard, got {} panels",
        panels.len()
    );

    for panel in panels {
        let title = panel["title"].as_str().unwrap_or("<untitled>");
        let kind = panel["type"].as_str().expect("every panel has a type");

        // A row is a layout element and carries no query of its own.
        if kind == "row" {
            continue;
        }

        assert!(
            panel["datasource"].is_object(),
            "panel `{title}` has no datasource, so it would not follow the \
             dashboard's data source variable"
        );
        let targets = panel["targets"]
            .as_array()
            .unwrap_or_else(|| panic!("panel `{title}` has no targets array"));
        assert!(
            !targets.is_empty(),
            "panel `{title}` has no query and would render as a blank box"
        );
        for target in targets {
            let expr = target["expr"].as_str().unwrap_or("");
            assert!(
                !expr.trim().is_empty(),
                "panel `{title}` has a target with an empty expression"
            );
        }
    }
}

/// The trap the dashboard exists partly to encode.
///
/// `acme_proxy_database_pool_connections` is process-wide and carries **no
/// `profile` label**, so scoping it to the dashboard's profile variable — which
/// is the reflex, since every other query does — would match nothing and leave
/// the panel silently empty. Anyone editing these two panels will reach for the
/// variable; this is what stops them.
#[test]
fn the_pool_gauge_is_never_scoped_to_the_profile_variable() {
    let (_, dashboard) = dashboard();

    for panel in dashboard["panels"].as_array().unwrap() {
        let title = panel["title"].as_str().unwrap_or("<untitled>");
        for target in panel["targets"].as_array().unwrap_or(&Vec::new()) {
            let expr = target["expr"].as_str().unwrap_or("");
            if expr.contains("acme_proxy_database_pool_connections") {
                assert!(
                    !expr.contains("$profile"),
                    "panel `{title}` filters the pool gauge by $profile, but \
                     that gauge has no profile label -- the panel would be \
                     empty with no error shown. Query was:\n{expr}"
                );
            }
        }
    }
}

/// Import and provisioning both need these, and a dashboard whose `uid` moves
/// between releases is a second dashboard rather than an update.
#[test]
fn the_dashboard_is_importable() {
    let (_, dashboard) = dashboard();

    assert_eq!(dashboard["uid"], "acme-proxy");
    assert_eq!(dashboard["title"], "acme-proxy");
    assert!(
        dashboard["schemaVersion"].as_u64().unwrap_or(0) >= 36,
        "an older schema version than Grafana 10 reads"
    );

    // A `datasource` *variable* rather than an `__inputs` block: the block is
    // what "export for sharing externally" produces and is never substituted
    // under file provisioning, which would leave a broken dashboard for anyone
    // deploying it as config.
    assert!(
        dashboard.get("__inputs").is_none(),
        "an __inputs block breaks file provisioning; use the datasource variable"
    );
    let names: Vec<&str> = dashboard["templating"]["list"]
        .as_array()
        .expect("the dashboard has template variables")
        .iter()
        .filter_map(|v| v["name"].as_str())
        .collect();
    assert!(names.contains(&"datasource"), "variables: {names:?}");
    assert!(names.contains(&"profile"), "variables: {names:?}");
}
