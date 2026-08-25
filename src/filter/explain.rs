//! Rendering a policy, and what it would do to one hypothetical request.
//!
//! Everything `acme-proxy filter show` and `acme-proxy filter explain` print
//! lives here; [`crate::cli::filter`] marshals arguments and does nothing else.
//! That split is the one the rest of the admin surface uses, and it is what
//! lets the web panel serve `show` — `GET /api/profiles/{name}/filter` and
//! `/ui/profiles/{name}/filter` render [`policy_json`], the same document
//! `filter show --json` prints, without moving any logic. The warning below is
//! about `explain`, which has no web surface and is not getting one.
//!
//! ## `explain` really runs the policy
//!
//! It executes the operator's `custom` scripts and issues real IPAM and DNS
//! requests, exactly as a request would, because a stubbed answer would be
//! worse than nothing the first time it disagreed with production. It touches
//! no database and creates nothing. [`Explanation::side_effects`] names the
//! checks that reached outside the process, so the output says which parts of
//! it were not free.
//!
//! That is also why this is a host-only command. The inputs — a client address
//! and a list of names — are chosen by the caller, so behind an admin session
//! it would be script execution and outbound requests driven from one stolen
//! cookie, on a listener that deliberately carries no filter chain and no
//! admission control.
//!
//! [`render_policy`] and [`policy_json`] are the other half of that argument
//! rather than an exception to it: they call four accessors on an
//! already-built [`FilterPolicy`], invoke no [`Check`](super::policy::Check),
//! and are not even `async`. Nothing a caller can type reaches outside this
//! process, which is what makes `show` proposable behind a session where
//! `explain` is not.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde_json::{Value, json};

use super::policy::{Evaluation, FilterPolicy, Outcome, Stage, Verdict};
use super::{ConnectionContext, EabIdentity, IdentifierContext, IdentifierStage};
use crate::cli::style::Palette;
use crate::sqlite::order::Identifier;

/// Which check kinds reach outside this process when they run.
///
/// Used only to warn, so an over-broad answer is the safe direction: a check
/// listed here that happens not to have made a request this time is a harmless
/// caution, where an omission would be a lie.
const REACHES_OUT: &[&str] = &["custom", "ipam", "reverse_dns"];

/// What both renderings say about a policy with no rules.
///
/// One `const` rather than a sentence per renderer: `render_policy` paints it
/// and [`policy_json`] carries it bare, and a warning this load-bearing said
/// two slightly different ways in two front ends is how one of them stops
/// being read.
const INACTIVE_WARNING: &str = "no rules configured: this endpoint filters \
     nothing, and any client that can reach it may request a certificate for \
     any name";

/// The request `explain` is asked about.
#[derive(Debug, Clone, Default)]
pub struct Subject {
    pub client_ip: Option<IpAddr>,
    pub account_id: String,
    pub identifiers: Vec<Identifier>,
    pub path: String,
    pub eab: Option<EabIdentity>,
}

/// One stage's evaluation, plus the checks it never reached.
#[derive(Debug)]
pub struct StageReport {
    pub label: &'static str,
    pub evaluation: Evaluation,
    /// Checks some applicable rule names that were never evaluated, because a
    /// decisive operand short-circuited past them. Reporting these is half the
    /// diagnostic value: "why did my `ipam` check not run" is otherwise
    /// invisible, since a skipped check and a passing one look identical in
    /// the outcome.
    pub skipped: Vec<String>,
    /// The HTTP answer this stage would produce.
    pub answer: &'static str,
}

/// What the whole request would get.
#[derive(Debug)]
pub struct Explanation {
    pub stages: Vec<StageReport>,
    /// Names of the checks that reached outside the process while explaining.
    pub side_effects: Vec<String>,
}

impl Explanation {
    /// Whether every stage allowed. Both must, which is the thing operators
    /// most often misread, so the rendering states it explicitly.
    #[must_use]
    pub fn allowed(&self) -> bool {
        self.stages
            .iter()
            .all(|stage| matches!(stage.evaluation.outcome, Outcome::Allow))
    }
}

/// Evaluates the policy at the connection stage and both identifier
/// sub-stages, keeping every trace.
pub async fn explain(policy: &FilterPolicy, subject: &Subject) -> Explanation {
    let mut stages = Vec::new();

    let connection = policy
        .evaluate_connection(&ConnectionContext {
            client_ip: subject.client_ip,
            method: &axum::http::Method::POST,
            path: &subject.path,
        })
        .await;
    stages.push(report("connection", connection, policy, Stage::Connection));

    for (label, sub_stage) in [
        ("newOrder", IdentifierStage::NewOrder),
        ("CSR", IdentifierStage::Csr),
    ] {
        let evaluation = policy
            .evaluate_identifiers(&IdentifierContext {
                client_ip: subject.client_ip,
                account_id: &subject.account_id,
                stage: sub_stage,
                identifiers: &subject.identifiers,
                eab: subject.eab.clone(),
            })
            .await;
        stages.push(report(label, evaluation, policy, Stage::Identifiers));
    }

    let mut side_effects: Vec<String> = stages
        .iter()
        .flat_map(|stage| stage.evaluation.checks.iter())
        .filter(|outcome| REACHES_OUT.contains(&outcome.kind))
        .map(|outcome| outcome.name.clone())
        .collect();
    side_effects.sort_unstable();
    side_effects.dedup();

    Explanation {
        stages,
        side_effects,
    }
}

/// Works out which checks the evaluation never reached, and the HTTP answer.
fn report(
    label: &'static str,
    evaluation: Evaluation,
    policy: &FilterPolicy,
    stage: Stage,
) -> StageReport {
    let evaluated: Vec<&str> = evaluation
        .checks
        .iter()
        .map(|outcome| outcome.name.as_str())
        .collect();

    let mut skipped: Vec<String> = policy
        .rules()
        .iter()
        .filter(|rule| rule.stages.contains(stage))
        .flat_map(|rule| rule.when.check_names())
        .filter(|name| !evaluated.contains(name))
        .map(std::string::ToString::to_string)
        .collect();
    skipped.sort_unstable();
    skipped.dedup();

    let answer = match (&evaluation.outcome, label) {
        (Outcome::Allow, _) => "allowed",
        (Outcome::Deny(_), "connection") => "403 access_denied",
        (Outcome::Deny(_), "newOrder") => "403 rejectedIdentifier",
        (Outcome::Deny(_), _) => "400 badCSR",
        (Outcome::Undecided(_), _) => "500 serverInternal",
    };

    StageReport {
        label,
        evaluation,
        skipped,
        answer,
    }
}

/// The resolved policy, as `filter show` prints it.
///
/// Conditions are re-printed through [`Condition`](super::expr::Condition)'s
/// `Display`, which makes every grouping explicit — so an operator who wrote
/// `a or b and c` sees `a or (b and c)` and has their answer about precedence.
#[must_use]
pub fn render_policy(profile: &str, policy: &FilterPolicy, palette: Palette) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "profile: {profile}");

    if !policy.is_active() {
        let _ = writeln!(out, "\n{}", palette.warn(INACTIVE_WARNING));
        return out;
    }

    let _ = writeln!(
        out,
        "default: {} (when a rule was applicable and none matched)",
        palette.status(policy.default_effect().as_str())
    );

    let _ = writeln!(out, "\nchecks");
    for check in policy.checks() {
        let _ = writeln!(
            out,
            "  {:<20} {:<12} {}",
            check.name, check.kind, check.stages
        );
    }

    let _ = writeln!(out, "\nrules (first match wins)");
    for rule in policy.rules() {
        let mode = match rule.mode {
            super::Mode::Enforce => String::new(),
            super::Mode::Warn => palette.warn("  [warn: matches but does not decide]"),
        };
        let _ = writeln!(
            out,
            "  {:<20} {} -> {}{}",
            rule.name,
            rule.when,
            palette.status(rule.then.as_str()),
            mode
        );
        let _ = writeln!(out, "  {:<20}   evaluated at: {}", "", rule.stages);
    }

    out
}

/// The human rendering of [`explain`].
#[must_use]
pub fn render_explanation(
    profile: &str,
    subject: &Subject,
    explanation: &Explanation,
    palette: Palette,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "profile: {profile}");
    let _ = writeln!(
        out,
        "client:  {}",
        subject
            .client_ip
            .map_or_else(|| "(none)".to_string(), |ip| ip.to_string())
    );
    let _ = writeln!(out, "path:    {}", subject.path);
    if subject.identifiers.is_empty() {
        let _ = writeln!(out, "names:   (none)");
    } else {
        let names: Vec<&str> = subject
            .identifiers
            .iter()
            .map(|identifier| identifier.value.as_str())
            .collect();
        let _ = writeln!(out, "names:   {}", names.join(", "));
    }

    for stage in &explanation.stages {
        let _ = writeln!(out, "\n{} stage", stage.label);

        if stage.evaluation.checks.is_empty() && stage.skipped.is_empty() {
            let _ = writeln!(out, "  no rule applies here, so it allows");
        }

        for outcome in &stage.evaluation.checks {
            let (verdict, reason) = match &outcome.verdict {
                Verdict::Pass => (palette.ok("pass"), String::new()),
                Verdict::Fail(detail) => (palette.bad("fail"), format!("  {detail}")),
                Verdict::Undecided(detail) => (palette.unknown("unknown"), format!("  {detail}")),
            };
            let _ = writeln!(
                out,
                "  {:<20} {:<12} {}{}",
                outcome.name, outcome.kind, verdict, reason
            );
        }
        for name in &stage.skipped {
            let _ = writeln!(
                out,
                "  {name:<20} {:<12} skipped (an earlier operand already decided)",
                ""
            );
        }

        for warned in &stage.evaluation.warned {
            let _ = writeln!(
                out,
                "  rule {} matched in warn mode and would have {}",
                warned.name,
                warned.then.as_str()
            );
        }

        match (&stage.evaluation.matched, &stage.evaluation.outcome) {
            (Some(rule), _) => {
                let _ = writeln!(out, "  rule {rule} matched");
            }
            (None, Outcome::Allow) if stage.evaluation.checks.is_empty() => {}
            (None, _) => {
                let _ = writeln!(out, "  no rule matched, so the default applies");
            }
        }

        // Painted off the outcome rather than off `answer`, which is an HTTP
        // status line (`403 rejectedIdentifier`) and not a status word — and
        // the Kleene third value has to read apart from a refusal here, since
        // telling those two apart is the whole reason `explain` exists.
        let (answer, detail) = match &stage.evaluation.outcome {
            Outcome::Allow => (palette.ok(stage.answer), String::new()),
            Outcome::Deny(detail) => (palette.bad(stage.answer), format!("  {detail}")),
            Outcome::Undecided(detail) => (palette.unknown(stage.answer), format!("  {detail}")),
        };
        let _ = writeln!(out, "  -> {answer}{detail}");
    }

    let _ = writeln!(
        out,
        "\nresult: {}",
        if explanation.allowed() {
            palette.ok("allowed (every stage must allow, and every stage did)")
        } else {
            palette.bad("refused (a request is served only when every stage allows)")
        }
    );

    if !explanation.side_effects.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            palette.warn(&format!(
                "note: these checks really ran, reaching outside this process exactly as a \
                 request would: {}",
                explanation.side_effects.join(", ")
            ))
        );
    }

    out
}

/// The `--json` rendering of [`explain`].
#[must_use]
pub fn explanation_json(profile: &str, subject: &Subject, explanation: &Explanation) -> Value {
    let stages: Vec<Value> = explanation
        .stages
        .iter()
        .map(|stage| {
            let checks: Vec<Value> = stage
                .evaluation
                .checks
                .iter()
                .map(|outcome| {
                    let (verdict, detail) = match &outcome.verdict {
                        Verdict::Pass => ("pass", None),
                        Verdict::Fail(detail) => ("fail", Some(detail.clone())),
                        Verdict::Undecided(detail) => ("unknown", Some(detail.clone())),
                    };
                    json!({
                        "name": outcome.name,
                        "type": outcome.kind,
                        "verdict": verdict,
                        "detail": detail,
                    })
                })
                .collect();

            json!({
                "stage": stage.label,
                "checks": checks,
                "skipped": stage.skipped,
                "matchedRule": stage.evaluation.matched,
                "warned": stage.evaluation.warned.iter().map(|warned| json!({
                    "rule": warned.name,
                    "wouldHave": warned.then.as_str(),
                })).collect::<Vec<_>>(),
                "answer": stage.answer,
            })
        })
        .collect();

    json!({
        "profile": profile,
        "request": {
            "clientIp": subject.client_ip.map(|ip| ip.to_string()),
            "path": subject.path,
            "identifiers": subject.identifiers,
            "accountId": subject.account_id,
        },
        "stages": stages,
        "allowed": explanation.allowed(),
        "sideEffects": explanation.side_effects,
    })
}

/// The resolved policy as a JSON document.
///
/// The one shape three consumers share: `filter show --json`,
/// `GET /api/profiles/{name}/filter`, and the context the `/ui` page's
/// template walks. Member for member it carries what [`render_policy`] prints
/// and nothing more — an operator reading the panel and an operator reading
/// the terminal are looking at the same policy, and neither front end may grow
/// a field the other cannot show.
///
/// **Reaches nothing outside this process.** Four accessors on an
/// already-built [`FilterPolicy`]; no [`Check`](super::policy::Check) is ever
/// invoked, which is why this is not `async` and why, unlike [`explain`], it
/// is safe behind an admin session.
///
/// Two orderings are load-bearing and neither is stated in the document:
/// `rules` is evaluation order, because the first match decides, and `checks`
/// is name-sorted, because a check has no order of its own.
///
/// `defaultEffect` is `null` when the policy is inactive, and the `warning` is
/// there instead. That is not a formality: `filter.default` is consulted only
/// where some rule was applicable, so with no rules at all the configured
/// value is not a fact about this endpoint's behaviour — which is the same
/// thing [`render_policy`] says by returning before it prints one.
#[must_use]
pub fn policy_json(profile: &str, policy: &FilterPolicy) -> Value {
    if !policy.is_active() {
        return json!({
            "profile": profile,
            "active": false,
            "defaultEffect": Value::Null,
            "warning": INACTIVE_WARNING,
            "checks": [],
            "rules": [],
        });
    }

    let checks: Vec<Value> = policy
        .checks()
        .iter()
        .map(|check| {
            json!({
                "name": check.name,
                "type": check.kind,
                "stages": check.stages.to_string(),
            })
        })
        .collect();

    let rules: Vec<Value> = policy
        .rules()
        .iter()
        .map(|rule| {
            json!({
                "name": rule.name,
                // `Condition`'s `Display`: the re-parenthesized expression,
                // which is the member this whole surface exists for.
                "when": rule.when.to_string(),
                "then": rule.then.as_str(),
                "mode": rule.mode.as_str(),
                "stages": rule.stages.to_string(),
            })
        })
        .collect();

    json!({
        "profile": profile,
        "active": true,
        "defaultEffect": policy.default_effect().as_str(),
        "warning": Value::Null,
        "checks": checks,
        "rules": rules,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::filter::expr::Condition;
    use crate::filter::policy::{Check, Effect, Mode, Rule};
    use crate::filter::{ProxyPolicy, ip_allow};
    use crate::testutil::dns_identifiers;

    fn net(allow: &[&str]) -> Arc<dyn Check> {
        Arc::new(
            ip_allow::AllowedFromIpAddress::from_settings(
                "net",
                &ip_allow::Settings {
                    allow: allow.iter().map(std::string::ToString::to_string).collect(),
                    deny: Vec::new(),
                },
            )
            .unwrap(),
        )
    }

    fn names(allow: &[&str]) -> Arc<dyn Check> {
        Arc::new(
            crate::filter::identifiers::IdentifierList::from_settings(
                "names",
                &crate::filter::identifiers::Settings {
                    allow: allow.iter().map(std::string::ToString::to_string).collect(),
                    ..crate::filter::identifiers::Settings::default()
                },
            )
            .unwrap(),
        )
    }

    fn rule(name: &str, when: &str, then: Effect, mode: Mode) -> Rule {
        Rule {
            name: name.to_string(),
            when: Condition::parse(when).unwrap(),
            then,
            message: None,
            mode,
        }
    }

    fn subject(ip: &str, names: &[&str]) -> Subject {
        Subject {
            client_ip: Some(ip.parse().unwrap()),
            account_id: "explain".to_string(),
            identifiers: dns_identifiers(names),
            path: "/newOrder".to_string(),
            eab: None,
        }
    }

    fn policy() -> FilterPolicy {
        FilterPolicy::new(
            vec![
                ("net".to_string(), net(&["10.0.0.0/8"])),
                ("names".to_string(), names(&["*.example.com"])),
            ],
            vec![
                rule("mgmt", "net", Effect::Allow, Mode::Enforce),
                rule("corp", "names", Effect::Allow, Mode::Enforce),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        )
    }

    #[tokio::test]
    async fn a_permitted_request_reports_every_stage_allowing() {
        let policy = policy();
        let subject = subject("10.0.0.5", &["web.example.com"]);
        let explanation = explain(&policy, &subject).await;

        assert!(explanation.allowed());
        assert_eq!(explanation.stages.len(), 3);
        let labels: Vec<&str> = explanation.stages.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["connection", "newOrder", "CSR"]);

        let rendered = render_explanation("default", &subject, &explanation, Palette::plain());
        assert!(rendered.contains("rule mgmt matched"), "{rendered}");
        assert!(rendered.contains("-> allowed"), "{rendered}");
        assert!(rendered.contains("every stage must allow"), "{rendered}");
    }

    /// The mapping an operator most wants: which HTTP answer each stage
    /// produces, and that they are not the same one.
    #[tokio::test]
    async fn each_stage_names_its_own_http_answer() {
        let policy = policy();
        let subject = subject("203.0.113.9", &["web.evil.net"]);
        let explanation = explain(&policy, &subject).await;

        assert!(!explanation.allowed());
        let answers: Vec<&str> = explanation.stages.iter().map(|s| s.answer).collect();
        assert_eq!(
            answers,
            vec!["403 access_denied", "403 rejectedIdentifier", "400 badCSR"]
        );

        let rendered = render_explanation("default", &subject, &explanation, Palette::plain());
        assert!(rendered.contains("no rule matched"), "{rendered}");
        assert!(rendered.contains("refused"), "{rendered}");
    }

    /// A skipped check and a passing one look identical in the outcome, so
    /// reporting the skip is the only way the output can answer "why did my
    /// inventory check not run".
    #[tokio::test]
    async fn a_short_circuited_check_is_reported_as_skipped() {
        let policy = FilterPolicy::new(
            vec![
                ("net".to_string(), net(&["10.0.0.0/8"])),
                ("names".to_string(), names(&["*.example.com"])),
            ],
            // `net` passes, so the `or` never reaches `names`.
            vec![rule("either", "net or names", Effect::Allow, Mode::Enforce)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let subject = subject("10.0.0.5", &["web.evil.net"]);
        let explanation = explain(&policy, &subject).await;

        let identifiers = &explanation.stages[1];
        assert_eq!(identifiers.skipped, vec!["names".to_string()]);
        let rendered = render_explanation("default", &subject, &explanation, Palette::plain());
        assert!(
            rendered.contains("skipped (an earlier operand"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn a_warn_rule_is_rendered_as_what_it_would_have_done() {
        let policy = FilterPolicy::new(
            vec![("net".to_string(), net(&["10.0.0.0/8"]))],
            vec![rule("would-deny", "net", Effect::Deny, Mode::Warn)],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        let subject = subject("10.0.0.5", &[]);
        let explanation = explain(&policy, &subject).await;
        assert!(explanation.allowed());

        let rendered = render_explanation("default", &subject, &explanation, Palette::plain());
        assert!(
            rendered.contains("matched in warn mode and would have deny"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn a_stage_with_no_rules_says_so_rather_than_looking_empty() {
        let policy = FilterPolicy::new(
            vec![("names".to_string(), names(&["*.example.com"]))],
            vec![rule("corp", "names", Effect::Allow, Mode::Enforce)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let subject = subject("10.0.0.5", &["web.example.com"]);
        let rendered = render_explanation(
            "default",
            &subject,
            &explain(&policy, &subject).await,
            Palette::plain(),
        );
        assert!(rendered.contains("no rule applies here"), "{rendered}");
    }

    #[tokio::test]
    async fn checks_that_reach_outside_the_process_are_named() {
        let dir = crate::testutil::TempDir::new("filter-explain");
        let script = crate::testutil::write_script(&dir, "hook.sh", "#!/bin/sh\nexit 0\n");
        let hook: Arc<dyn Check> = Arc::new(
            crate::filter::custom::CustomScriptFilter::from_settings(
                "hook",
                &crate::filter::custom::Settings {
                    script_path: script.to_string_lossy().into_owned(),
                    ..crate::filter::custom::Settings::default()
                },
            )
            .unwrap(),
        );

        let policy = FilterPolicy::new(
            vec![("hook".to_string(), hook)],
            vec![rule("scripted", "hook", Effect::Allow, Mode::Enforce)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let subject = subject("10.0.0.5", &["web.example.com"]);
        let explanation = explain(&policy, &subject).await;
        assert_eq!(explanation.side_effects, vec!["hook".to_string()]);

        let rendered = render_explanation("default", &subject, &explanation, Palette::plain());
        assert!(rendered.contains("these checks really ran"), "{rendered}");
    }

    #[tokio::test]
    async fn the_json_shape_carries_every_stage_and_its_verdicts() {
        let policy = policy();
        let subject = subject("203.0.113.9", &["web.evil.net"]);
        let explanation = explain(&policy, &subject).await;
        let value = explanation_json("default", &subject, &explanation);

        assert_eq!(value["profile"], "default");
        assert_eq!(value["allowed"], false);
        assert_eq!(value["request"]["clientIp"], "203.0.113.9");
        let stages = value["stages"].as_array().unwrap();
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0]["stage"], "connection");
        assert_eq!(stages[0]["answer"], "403 access_denied");
        assert_eq!(stages[0]["checks"][0]["verdict"], "fail");
        assert!(
            stages[0]["checks"][0]["detail"]
                .as_str()
                .unwrap()
                .contains("not allowed")
        );
    }

    /// `show` re-prints conditions with grouping made explicit, which is the
    /// whole reason it exists rather than an operator re-reading their file.
    #[test]
    fn show_renders_the_policy_with_explicit_grouping() {
        let policy = FilterPolicy::new(
            vec![
                ("net".to_string(), net(&["10.0.0.0/8"])),
                ("names".to_string(), names(&["*.example.com"])),
            ],
            vec![rule(
                "mixed",
                "names or net and names",
                Effect::Allow,
                Mode::Enforce,
            )],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let rendered = render_policy("default", &policy, Palette::plain());
        assert!(rendered.contains("names or (net and names)"), "{rendered}");
        assert!(rendered.contains("net"), "{rendered}");
        assert!(rendered.contains("allowed_ip"), "{rendered}");
        assert!(rendered.contains("default: deny"), "{rendered}");
        assert!(rendered.contains("identifiers only"), "{rendered}");
    }

    #[test]
    fn show_says_plainly_when_nothing_is_configured() {
        let rendered = render_policy("default", &FilterPolicy::default(), Palette::plain());
        assert!(rendered.contains("filters nothing"), "{rendered}");
    }

    #[test]
    fn show_marks_a_warn_rule() {
        let policy = FilterPolicy::new(
            vec![("net".to_string(), net(&["10.0.0.0/8"]))],
            vec![rule("dry", "net", Effect::Deny, Mode::Warn)],
            Effect::Deny,
            ProxyPolicy::default(),
        );
        assert!(render_policy("default", &policy, Palette::plain()).contains("does not decide"));
    }

    /// The fixture both `show` renderings are asserted over.
    ///
    /// Its condition is written **unparenthesized** on purpose: what comes
    /// back out is `names or (net and names)`, and that is the whole reason
    /// either rendering exists.
    fn two_rule_policy() -> FilterPolicy {
        FilterPolicy::new(
            vec![
                ("net".to_string(), net(&["10.0.0.0/8"])),
                ("names".to_string(), names(&["*.example.com"])),
            ],
            vec![
                rule(
                    "mixed",
                    "names or net and names",
                    Effect::Allow,
                    Mode::Enforce,
                ),
                rule("dry", "net", Effect::Deny, Mode::Warn),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        )
    }

    #[test]
    fn the_policy_json_carries_every_check_and_every_rule() {
        let value = policy_json("default", &two_rule_policy());

        assert_eq!(value["profile"], "default");
        assert_eq!(value["active"], true);
        assert_eq!(value["defaultEffect"], "deny");
        assert!(value["warning"].is_null());

        // Name-sorted, as `FilterPolicy::checks` walks a `BTreeMap`.
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["name"], "names");
        assert_eq!(checks[0]["type"], "identifiers");
        assert_eq!(checks[0]["stages"], "identifiers only");
        assert_eq!(checks[1]["name"], "net");
        assert_eq!(checks[1]["type"], "allowed_ip");
        assert_eq!(checks[1]["stages"], "connection and identifiers");

        // Evaluation order, because the first match decides.
        let rules = value["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["name"], "mixed");
        assert_eq!(rules[0]["when"], "names or (net and names)");
        assert_eq!(rules[0]["then"], "allow");
        assert_eq!(rules[0]["mode"], "enforce");
        assert_eq!(rules[0]["stages"], "identifiers only");
        assert_eq!(rules[1]["mode"], "warn");
    }

    /// A policy with no rules is a state, not an error — and `filter.default`
    /// is not a fact about it, since no stage ever has an applicable rule.
    #[test]
    fn an_inactive_policy_says_so_and_carries_no_default() {
        let value = policy_json("default", &FilterPolicy::default());

        assert_eq!(value["active"], false);
        assert!(value["defaultEffect"].is_null());
        assert!(
            value["warning"]
                .as_str()
                .unwrap()
                .contains("filters nothing")
        );
        assert!(value["checks"].as_array().unwrap().is_empty());
        assert!(value["rules"].as_array().unwrap().is_empty());
    }

    /// `message` is the operator's own words for a refusal, and `show` does
    /// not print it. Its absence here is a decision, not an oversight: the
    /// panel and the terminal describe a policy identically or one of them is
    /// lying, and adding it is an addition to *both*.
    #[test]
    fn the_operator_message_is_not_in_the_json() {
        let policy = FilterPolicy::new(
            vec![("net".to_string(), net(&["10.0.0.0/8"]))],
            vec![Rule {
                name: "spoken".to_string(),
                when: Condition::parse("net").unwrap(),
                then: Effect::Deny,
                message: Some("ask the network team".to_string()),
                mode: Mode::Enforce,
            }],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let value = policy_json("default", &policy);
        assert!(value["rules"][0].get("message").is_none());
        assert!(!value.to_string().contains("network team"));
    }

    /// The text and the JSON are two walks over one [`FilterPolicy`] rather
    /// than one built on the other, so this is what stops them drifting: every
    /// word the document carries has to appear in what `filter show` prints.
    #[test]
    fn the_two_renderings_agree_on_the_vocabulary() {
        let policy = two_rule_policy();
        let value = policy_json("default", &policy);
        let rendered = render_policy("default", &policy, Palette::plain());

        assert!(rendered.contains(value["defaultEffect"].as_str().unwrap()));
        for check in value["checks"].as_array().unwrap() {
            for member in ["name", "type", "stages"] {
                let word = check[member].as_str().unwrap();
                assert!(rendered.contains(word), "`{word}` missing from {rendered}");
            }
        }
        for rule in value["rules"].as_array().unwrap() {
            for member in ["name", "when", "then", "stages"] {
                let word = rule[member].as_str().unwrap();
                assert!(rendered.contains(word), "`{word}` missing from {rendered}");
            }
        }

        // And the sentence an inactive policy is described by, byte for byte:
        // one `const`, painted on one side and carried bare on the other.
        let inactive = FilterPolicy::default();
        assert!(
            render_policy("default", &inactive, Palette::plain()).contains(
                policy_json("default", &inactive)["warning"]
                    .as_str()
                    .unwrap()
            )
        );
    }
}
