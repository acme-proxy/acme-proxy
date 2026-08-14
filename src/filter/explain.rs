//! Rendering a policy, and what it would do to one hypothetical request.
//!
//! Everything `acme-proxy filter show` and `acme-proxy filter explain` print
//! lives here; [`crate::cli::filter`] marshals arguments and does nothing else.
//! That split is the one the rest of the admin surface uses, and it is what
//! would let the web panel serve this later without moving any logic — see the
//! warning below for why it does not today.
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

use std::fmt::Write as _;
use std::net::IpAddr;

use serde_json::{Value, json};

use super::policy::{Evaluation, FilterPolicy, Outcome, Stage, Verdict};
use super::{ConnectionContext, EabIdentity, IdentifierContext, IdentifierStage};
use crate::sqlite::order::Identifier;

/// Which check kinds reach outside this process when they run.
///
/// Used only to warn, so an over-broad answer is the safe direction: a check
/// listed here that happens not to have made a request this time is a harmless
/// caution, where an omission would be a lie.
const REACHES_OUT: &[&str] = &["custom", "ipam", "reverse_dns"];

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
pub fn render_policy(profile: &str, policy: &FilterPolicy) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "profile: {profile}");

    if !policy.is_active() {
        let _ = writeln!(
            out,
            "\nno rules configured: this endpoint filters nothing, and any client that \
             can reach it may request a certificate for any name"
        );
        return out;
    }

    let _ = writeln!(
        out,
        "default: {} (when a rule was applicable and none matched)",
        policy.default_effect().as_str()
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
            super::Mode::Warn => "  [warn: matches but does not decide]".to_string(),
        };
        let _ = writeln!(
            out,
            "  {:<20} {} -> {}{}",
            rule.name,
            rule.when,
            rule.then.as_str(),
            mode
        );
        let _ = writeln!(out, "  {:<20}   evaluated at: {}", "", rule.stages);
    }

    out
}

/// The human rendering of [`explain`].
#[must_use]
pub fn render_explanation(profile: &str, subject: &Subject, explanation: &Explanation) -> String {
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
                Verdict::Pass => ("pass", String::new()),
                Verdict::Fail(detail) => ("fail", format!("  {detail}")),
                Verdict::Undecided(detail) => ("unknown", format!("  {detail}")),
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

        let detail = match &stage.evaluation.outcome {
            Outcome::Allow => String::new(),
            Outcome::Deny(detail) | Outcome::Undecided(detail) => format!("  {detail}"),
        };
        let _ = writeln!(out, "  -> {}{}", stage.answer, detail);
    }

    let _ = writeln!(
        out,
        "\nresult: {}",
        if explanation.allowed() {
            "allowed (every stage must allow, and every stage did)"
        } else {
            "refused (a request is served only when every stage allows)"
        }
    );

    if !explanation.side_effects.is_empty() {
        let _ = writeln!(
            out,
            "\nnote: these checks really ran, reaching outside this process exactly as a \
             request would: {}",
            explanation.side_effects.join(", ")
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

        let rendered = render_explanation("default", &subject, &explanation);
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

        let rendered = render_explanation("default", &subject, &explanation);
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
        let rendered = render_explanation("default", &subject, &explanation);
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

        let rendered = render_explanation("default", &subject, &explanation);
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
        let rendered = render_explanation("default", &subject, &explain(&policy, &subject).await);
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

        let rendered = render_explanation("default", &subject, &explanation);
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

        let rendered = render_policy("default", &policy);
        assert!(rendered.contains("names or (net and names)"), "{rendered}");
        assert!(rendered.contains("net"), "{rendered}");
        assert!(rendered.contains("allowed_ip"), "{rendered}");
        assert!(rendered.contains("default: deny"), "{rendered}");
        assert!(rendered.contains("identifiers only"), "{rendered}");
    }

    #[test]
    fn show_says_plainly_when_nothing_is_configured() {
        let rendered = render_policy("default", &FilterPolicy::default());
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
        assert!(render_policy("default", &policy).contains("does not decide"));
    }
}
