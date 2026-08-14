//! The policy engine: named checks, boolean rules over them, and the evaluator.
//!
//! A [`Check`] is one named question about a request — "is this address in the
//! management network?", "does the inventory say this address owns this name?".
//! A [`Rule`] is a boolean expression over check names plus what to do when it
//! matches. [`FilterPolicy`] holds both and answers one request.
//!
//! ## Three-valued, on purpose
//!
//! A check answers [`Verdict::Pass`], [`Verdict::Fail`] or
//! [`Verdict::Undecided`]. The third is what makes composition possible at all:
//! a two-valued check cannot distinguish "the inventory says no" from "the
//! inventory is down", so `mgmt-net or inventory` would either refuse every
//! request during an inventory outage or quietly admit every request during
//! one. Combination follows **Kleene three-valued logic** ([`kleene_and`],
//! [`kleene_or`], [`kleene_not`]): an unknown propagates only when it could
//! change the answer.
//!
//! The same principle applies one level up, at the rule loop — see
//! [`FilterPolicy::evaluate`], where a rule whose condition could not be
//! evaluated poisons the result only if it would have decided differently from
//! the rule that did.
//!
//! ## Two stages, evaluated independently
//!
//! Some checks decide from the connection alone; others need the names being
//! requested, which only the handlers know. A rule's [`StageSet`] is the
//! **intersection** of its checks' — never the union, because evaluating a rule
//! at a stage where one of its checks cannot run would silently substitute
//! `Pass` for that check and change the boolean answer.
//!
//! Each stage evaluates its own applicable subset of the rules and both must
//! allow. `IdentifierStage::NewOrder` and `IdentifierStage::Csr` are *sub*-stages
//! of [`Stage::Identifiers`] and evaluate the same rules; a check that wants to
//! tell them apart reads
//! [`IdentifierContext::stage`](crate::filter::IdentifierContext::stage).
//!
//! **A stage with no applicable rules allows.** [`FilterPolicy::default_effect`]
//! is consulted only when at least one rule was applicable and none matched —
//! otherwise a policy made entirely of identifier-stage rules would refuse every
//! connection before a name was ever mentioned.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use super::client_ip::ProxyPolicy;
use super::expr::Condition;
use super::{ConnectionContext, IdentifierContext};

/// What one check decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The check is satisfied.
    Pass,
    /// The check is not satisfied. The detail may reach the client.
    Fail(String),
    /// The check could not decide — a DNS timeout, an inventory outage. Never
    /// a refusal: a check that cannot reach its authority knows nothing, and
    /// treating that as either answer is a bug.
    Undecided(String),
}

/// Where in a request's life a check is being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Before the handler, from the connection alone.
    Connection,
    /// At `newOrder` and again at `finalize`, with the requested names in hand.
    Identifiers,
}

impl Stage {
    /// Short label for logs and `explain` output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Identifiers => "identifiers",
        }
    }
}

/// The stages a check can decide at, or a rule is evaluated at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageSet {
    pub connection: bool,
    pub identifiers: bool,
}

impl StageSet {
    /// A check needing only the client address, which both contexts carry.
    #[must_use]
    pub const fn both() -> Self {
        Self {
            connection: true,
            identifiers: true,
        }
    }

    #[must_use]
    pub const fn connection_only() -> Self {
        Self {
            connection: true,
            identifiers: false,
        }
    }

    #[must_use]
    pub const fn identifiers_only() -> Self {
        Self {
            connection: false,
            identifiers: true,
        }
    }

    /// The empty set — a rule with this never runs.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            connection: false,
            identifiers: false,
        }
    }

    #[must_use]
    pub const fn contains(self, stage: Stage) -> bool {
        match stage {
            Stage::Connection => self.connection,
            Stage::Identifiers => self.identifiers,
        }
    }

    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            connection: self.connection && other.connection,
            identifiers: self.identifiers && other.identifiers,
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.connection && !self.identifiers
    }
}

impl fmt::Display for StageSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.connection, self.identifiers) {
            (true, true) => formatter.write_str("connection and identifiers"),
            (true, false) => formatter.write_str("connection only"),
            (false, true) => formatter.write_str("identifiers only"),
            (false, false) => formatter.write_str("no stage"),
        }
    }
}

/// One named question a policy can ask about a request.
///
/// Both hooks default to [`Verdict::Pass`] so an implementation writes only the
/// one it serves — but [`Check::stages`] has **no** default, because a check
/// that claims a stage it cannot decide at would silently pass there, which is
/// exactly the failure the stage intersection exists to prevent.
#[async_trait]
pub trait Check: Send + Sync {
    /// The check *type* (`allowed_ip`, `ipam`, …), not the instance name — the
    /// instance name is the policy's key for it.
    fn kind(&self) -> &'static str;

    /// Where this instance can decide.
    fn stages(&self) -> StageSet;

    async fn check_connection(&self, _context: &ConnectionContext<'_>) -> Verdict {
        Verdict::Pass
    }

    async fn check_identifiers(&self, _context: &IdentifierContext<'_>) -> Verdict {
        Verdict::Pass
    }
}

/// `Fail and Undecided` is `Fail`: the conjunction is already false whatever
/// the unknown turns out to be.
#[must_use]
pub fn kleene_and(left: &Verdict, right: &Verdict) -> Verdict {
    match (left, right) {
        (Verdict::Fail(detail), _) | (_, Verdict::Fail(detail)) => Verdict::Fail(detail.clone()),
        (Verdict::Undecided(detail), _) | (_, Verdict::Undecided(detail)) => {
            Verdict::Undecided(detail.clone())
        }
        (Verdict::Pass, Verdict::Pass) => Verdict::Pass,
    }
}

/// `Pass or Undecided` is `Pass`: the disjunction is already true whatever the
/// unknown turns out to be. This is the property that lets an operator write
/// `mgmt-net or inventory` and survive an inventory outage.
#[must_use]
pub fn kleene_or(left: &Verdict, right: &Verdict) -> Verdict {
    match (left, right) {
        (Verdict::Pass, _) | (_, Verdict::Pass) => Verdict::Pass,
        (Verdict::Undecided(detail), _) | (_, Verdict::Undecided(detail)) => {
            Verdict::Undecided(detail.clone())
        }
        (Verdict::Fail(detail), Verdict::Fail(_)) => Verdict::Fail(detail.clone()),
    }
}

/// Negation swaps the two decisive answers and leaves the unknown alone.
#[must_use]
pub fn kleene_not(verdict: &Verdict) -> Verdict {
    match verdict {
        Verdict::Pass => Verdict::Fail("the condition was negated".to_string()),
        Verdict::Fail(_) => Verdict::Pass,
        Verdict::Undecided(detail) => Verdict::Undecided(detail.clone()),
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Whether a rule decides or only reports what it would have decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    /// Dry run: a match is logged as `filter_rule_warned` and evaluation
    /// continues, so a policy of nothing but `warn` rules falls through to
    /// [`FilterPolicy::default_effect`].
    Warn,
}

/// One authored rule, before its stages are derived.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub when: Condition,
    pub then: Effect,
    /// The operator's own words for the refusal, shown to the client verbatim.
    pub message: Option<String>,
    pub mode: Mode,
}

/// A rule plus the stages its checks agree on.
#[derive(Debug, Clone)]
struct CompiledRule {
    rule: Rule,
    stages: StageSet,
}

struct CheckSlot {
    kind: &'static str,
    stages: StageSet,
    check: Arc<dyn Check>,
}

/// What one check answered, in the order the evaluator reached it.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub name: String,
    pub kind: &'static str,
    pub verdict: Verdict,
}

/// A `warn`-mode rule that matched without deciding.
#[derive(Debug, Clone)]
pub struct WarnedRule {
    pub name: String,
    pub then: Effect,
}

/// What a policy decided about one request at one stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    /// Refused. The detail is shown to the client.
    Deny(String),
    /// The policy could not be evaluated. Maps to a 500 so the client retries,
    /// rather than to a refusal it would believe.
    Undecided(String),
}

/// Everything the evaluator learned, for logs and `acme-proxy filter explain`.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub outcome: Outcome,
    /// The rule that decided, or `None` when the default did (or when no rule
    /// was applicable at this stage).
    pub matched: Option<String>,
    /// Every check actually evaluated, in order. A check skipped by
    /// short-circuit is absent — which is what `explain` reports as *skipped*.
    pub checks: Vec<CheckOutcome>,
    pub warned: Vec<WarnedRule>,
}

/// One configured check, as `filter show` and `filter explain` describe it.
#[derive(Debug, Clone, Copy)]
pub struct CheckSummary<'a> {
    pub name: &'a str,
    pub kind: &'static str,
    pub stages: StageSet,
}

/// One configured rule, as `filter show` and `filter explain` describe it.
#[derive(Debug, Clone, Copy)]
pub struct RuleSummary<'a> {
    pub name: &'a str,
    pub when: &'a Condition,
    pub then: Effect,
    pub mode: Mode,
    pub stages: StageSet,
}

/// A rule that could not be evaluated, remembered until the answer is known.
struct PendingUnknown {
    rule: String,
    then: Effect,
    detail: String,
}

/// The configured checks, the rules over them, and how the middleware turns a
/// peer address into a client address.
///
/// Cheap to clone behind the `Arc` it is always held in.
pub struct FilterPolicy {
    checks: BTreeMap<String, CheckSlot>,
    rules: Vec<CompiledRule>,
    default_effect: Effect,
    proxy: ProxyPolicy,
}

impl fmt::Debug for FilterPolicy {
    /// `dyn Check` is not `Debug`, so show the names and conditions — which is
    /// the only part worth reading anyway.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilterPolicy")
            .field(
                "checks",
                &self
                    .checks
                    .iter()
                    .map(|(name, slot)| format!("{name}: {}", slot.kind))
                    .collect::<Vec<_>>(),
            )
            .field(
                "rules",
                &self
                    .rules
                    .iter()
                    .map(|compiled| {
                        format!(
                            "{}: {} -> {}",
                            compiled.rule.name,
                            compiled.rule.when,
                            compiled.rule.then.as_str()
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .field("default", &self.default_effect.as_str())
            .field("proxy", &self.proxy)
            .finish()
    }
}

impl Default for FilterPolicy {
    /// No checks and no rules: every stage has an empty applicable set, so
    /// everything is allowed. This is what a server with no `[filter]` section
    /// and every test that does not care about filtering uses.
    fn default() -> Self {
        Self {
            checks: BTreeMap::new(),
            rules: Vec::new(),
            default_effect: Effect::Deny,
            proxy: ProxyPolicy::default(),
        }
    }
}

impl FilterPolicy {
    /// Assembles a policy, deriving each rule's stages from its checks.
    ///
    /// The stage intersection is computed here rather than passed in, so the
    /// one place that knows the rule is what fills it in. A rule naming a check
    /// that does not exist gets [`StageSet::none`] and therefore never runs —
    /// the builder refuses that configuration at startup, and this is only the
    /// net under it.
    #[must_use]
    pub fn new(
        checks: Vec<(String, Arc<dyn Check>)>,
        rules: Vec<Rule>,
        default_effect: Effect,
        proxy: ProxyPolicy,
    ) -> Self {
        let checks: BTreeMap<String, CheckSlot> = checks
            .into_iter()
            .map(|(name, check)| {
                let slot = CheckSlot {
                    kind: check.kind(),
                    stages: check.stages(),
                    check,
                };
                (name, slot)
            })
            .collect();

        let rules = rules
            .into_iter()
            .map(|rule| {
                let stages = stages_for(&rule.when, &checks);
                CompiledRule { rule, stages }
            })
            .collect();

        Self {
            checks,
            rules,
            default_effect,
            proxy,
        }
    }

    /// How the middleware turns a peer address plus headers into a client IP.
    pub fn proxy(&self) -> &ProxyPolicy {
        &self.proxy
    }

    /// What happens when a rule was applicable at a stage and none matched.
    #[must_use]
    pub fn default_effect(&self) -> Effect {
        self.default_effect
    }

    /// Whether any rule is evaluated at `stage`.
    ///
    /// `post_finalize` asks about [`Stage::Identifiers`] to skip re-parsing the
    /// CSR when nothing would look at the result.
    #[must_use]
    pub fn has_rules_at(&self, stage: Stage) -> bool {
        self.rules
            .iter()
            .any(|compiled| compiled.stages.contains(stage))
    }

    /// Whether the policy would decide anything at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Every configured check, for `acme-proxy filter show` and for working
    /// out which checks an evaluation short-circuited past.
    pub fn checks(&self) -> Vec<CheckSummary<'_>> {
        self.checks
            .iter()
            .map(|(name, slot)| CheckSummary {
                name,
                kind: slot.kind,
                stages: slot.stages,
            })
            .collect()
    }

    /// Every rule, in evaluation order.
    pub fn rules(&self) -> Vec<RuleSummary<'_>> {
        self.rules
            .iter()
            .map(|compiled| RuleSummary {
                name: &compiled.rule.name,
                when: &compiled.rule.when,
                then: compiled.rule.then,
                mode: compiled.rule.mode,
                stages: compiled.stages,
            })
            .collect()
    }

    /// Whether any check asks about the requesting account's EAB credential.
    ///
    /// The handlers gate the two database reads that resolve one on this, so a
    /// policy with no `eab` check pays nothing for the field's existence.
    #[must_use]
    pub fn needs_eab(&self) -> bool {
        self.checks.values().any(|slot| slot.kind == "eab")
    }

    /// Evaluates the connection stage, keeping the whole trace.
    ///
    /// The trace is what `acme-proxy filter explain` renders; a request path
    /// wants [`FilterPolicy::check_connection`], which logs the decision.
    pub async fn evaluate_connection(&self, context: &ConnectionContext<'_>) -> Evaluation {
        self.evaluate(Hook::Connection(context)).await
    }

    /// Evaluates the identifier stage, keeping the whole trace.
    pub async fn evaluate_identifiers(&self, context: &IdentifierContext<'_>) -> Evaluation {
        self.evaluate(Hook::Identifiers(context)).await
    }

    /// The connection stage's answer, with the decision logged.
    pub async fn check_connection(&self, context: &ConnectionContext<'_>) -> Outcome {
        let evaluation = self.evaluate_connection(context).await;
        log_decision(&evaluation, Stage::Connection.as_str(), context.client_ip);
        evaluation.outcome
    }

    /// The identifier stage's answer, with the decision logged.
    ///
    /// The hook is logged as `newOrder` or `CSR` rather than `identifiers`,
    /// because which of the two refused is the first thing an operator reading
    /// the line wants to know.
    pub async fn check_identifiers(&self, context: &IdentifierContext<'_>) -> Outcome {
        let evaluation = self.evaluate_identifiers(context).await;
        log_decision(&evaluation, context.stage.as_str(), context.client_ip);
        evaluation.outcome
    }

    /// Runs the applicable rules in order and reduces them to one answer.
    ///
    /// The loop is first-match-wins with two wrinkles.
    ///
    /// A `warn`-mode rule that matches is recorded and **does not decide**, so
    /// a policy can be tightened in production and watched before it bites.
    ///
    /// A rule whose condition came back [`Verdict::Undecided`] is remembered
    /// rather than skipped. It might have matched, so once the answer is known
    /// the loop asks whether that would have mattered: if the unknown rule's
    /// effect differs from the effect actually reached, the whole stage is
    /// [`Outcome::Undecided`] — a retryable 500 — because there is no honest
    /// answer to give. If it agrees, the answer stands whichever way the
    /// unknown would have gone. This is [`kleene_or`]'s principle at the rule
    /// level, and it is what keeps rule *order* from deciding whether an
    /// inventory outage is survivable.
    async fn evaluate(&self, hook: Hook<'_>) -> Evaluation {
        let stage = hook.stage();
        let applicable: Vec<&CompiledRule> = self
            .rules
            .iter()
            .filter(|compiled| compiled.stages.contains(stage))
            .collect();

        // Law: a stage nobody wrote a rule for is not a stage that refuses.
        if applicable.is_empty() {
            return Evaluation {
                outcome: Outcome::Allow,
                matched: None,
                checks: Vec::new(),
                warned: Vec::new(),
            };
        }

        let mut run = Run {
            policy: self,
            hook,
            stage,
            memo: BTreeMap::new(),
            trace: Vec::new(),
        };
        let mut decision: Option<&Rule> = None;
        let mut warned = Vec::new();
        let mut pending: Vec<PendingUnknown> = Vec::new();
        // Where the last rule's own checks begin in the trace — see
        // `denial_detail` for why the *last* rule is the one whose refusal is
        // worth quoting.
        let mut last_rule_start = 0;

        for compiled in applicable {
            last_rule_start = run.trace.len();
            match run.eval(&compiled.rule.when).await {
                Verdict::Pass => {
                    if compiled.rule.mode == Mode::Warn {
                        warn!(
                            event = "filter_rule_warned",
                            outcome = "advisory",
                            rule = %compiled.rule.name,
                            then = compiled.rule.then.as_str(),
                            stage = stage.as_str(),
                            "rule matched in warn mode and did not decide",
                        );
                        warned.push(WarnedRule {
                            name: compiled.rule.name.clone(),
                            then: compiled.rule.then,
                        });
                        continue;
                    }
                    decision = Some(&compiled.rule);
                    break;
                }
                Verdict::Fail(_) => continue,
                Verdict::Undecided(detail) => {
                    if compiled.rule.mode == Mode::Enforce {
                        pending.push(PendingUnknown {
                            rule: compiled.rule.name.clone(),
                            then: compiled.rule.then,
                            detail,
                        });
                    }
                }
            }
        }

        let effect = decision.map_or(self.default_effect, |rule| rule.then);

        if let Some(unknown) = pending.into_iter().find(|entry| entry.then != effect) {
            return Evaluation {
                outcome: Outcome::Undecided(format!(
                    "rule `{}` could not be evaluated ({}), and it would have \
                     decided differently from the rule that did",
                    unknown.rule, unknown.detail
                )),
                matched: decision.map(|rule| rule.name.clone()),
                checks: run.trace,
                warned,
            };
        }

        let outcome = match effect {
            Effect::Allow => Outcome::Allow,
            Effect::Deny => Outcome::Deny(denial_detail(decision, &run.trace, last_rule_start)),
        };

        Evaluation {
            outcome,
            matched: decision.map(|rule| rule.name.clone()),
            checks: run.trace,
            warned,
        }
    }
}

/// One log line per refusal, at the level the reason deserves: a refusal is
/// routine operation, an unknown is something an operator should see.
///
/// Only the *decision* logs. A check whose `Undecided` was absorbed by an `or`
/// must not produce an `error!` — that would be one line per check per request
/// on a policy that is working exactly as written.
///
/// `check` is the instance name and `filter` its type, so a family grep still
/// finds every `allowed_ip` refusal while three `custom` scripts are finally
/// distinguishable from one another.
fn log_decision(evaluation: &Evaluation, hook: &str, client_ip: Option<IpAddr>) {
    let rule = evaluation.matched.as_deref().unwrap_or("default");
    let source = evaluation
        .checks
        .iter()
        .find(|outcome| matches!(outcome.verdict, Verdict::Fail(_) | Verdict::Undecided(_)));
    let check = source.map(|outcome| outcome.name.as_str());
    let kind = source.map(|outcome| outcome.kind);

    match &evaluation.outcome {
        Outcome::Allow => {}
        Outcome::Deny(detail) => tracing::warn!(
            event = "filter_denied",
            outcome = "failure",
            check = ?check,
            filter = ?kind,
            rule,
            hook,
            client_ip = ?client_ip,
            detail = %detail,
        ),
        Outcome::Undecided(detail) => tracing::error!(
            event = "filter_failed",
            outcome = "failure",
            check = ?check,
            filter = ?kind,
            rule,
            hook,
            client_ip = ?client_ip,
            detail = %detail,
        ),
    }
}

/// The intersection of the stages every check the condition names can serve.
fn stages_for(condition: &Condition, checks: &BTreeMap<String, CheckSlot>) -> StageSet {
    condition
        .check_names()
        .into_iter()
        .fold(StageSet::both(), |accumulated, name| {
            let stages = checks
                .get(name)
                .map_or_else(StageSet::none, |slot| slot.stages);
            accumulated.intersect(stages)
        })
}

/// What the client is told when a stage refuses.
///
/// A matching rule speaks for itself — the operator's `message` if they wrote
/// one, otherwise its own name, which is at least greppable.
///
/// Falling through to the default is different: nothing *decided* to refuse, so
/// the most useful thing to hand back is a check that actually said no. Which
/// one matters. Rules are first-match-wins, so the ones an operator writes
/// first are the narrow bypasses and the last is the general case — and the
/// general case is the one a refused client was expected to satisfy. Quoting
/// the first failure across the whole stage instead would answer a policy of
///
/// ```text
/// rules = ["public-paths", "mgmt-net", "corp-names-from-inventory"]
/// ```
///
/// with "path /newOrder is not allowed", which is true of the bypass and
/// actively misleading about the request: the path is fine, the address is not.
/// So the search starts at the last rule evaluated and only widens if that rule
/// left no refusal behind.
fn denial_detail(
    decision: Option<&Rule>,
    trace: &[CheckOutcome],
    last_rule_start: usize,
) -> String {
    if let Some(rule) = decision {
        return rule
            .message
            .clone()
            .unwrap_or_else(|| format!("refused by policy rule `{}`", rule.name));
    }

    let first_failure = |slice: &[CheckOutcome]| {
        slice.iter().find_map(|outcome| match &outcome.verdict {
            Verdict::Fail(detail) => Some(detail.clone()),
            _ => None,
        })
    };

    first_failure(trace.get(last_rule_start..).unwrap_or_default())
        .or_else(|| first_failure(trace))
        .unwrap_or_else(|| "no policy rule permits this request".to_string())
}

/// Which hook is being evaluated, so one recursion serves both.
#[derive(Clone, Copy)]
enum Hook<'a> {
    Connection(&'a ConnectionContext<'a>),
    Identifiers(&'a IdentifierContext<'a>),
}

impl Hook<'_> {
    fn stage(self) -> Stage {
        match self {
            Self::Connection(_) => Stage::Connection,
            Self::Identifiers(_) => Stage::Identifiers,
        }
    }
}

/// One evaluation of one stage.
struct Run<'a> {
    policy: &'a FilterPolicy,
    hook: Hook<'a>,
    stage: Stage,
    /// A check named twice in one expression runs once. This is not an
    /// optimisation: `custom` forks a process and `ipam` makes four HTTP
    /// requests, so a second evaluation would be a second side effect.
    memo: BTreeMap<String, Verdict>,
    trace: Vec<CheckOutcome>,
}

type VerdictFuture<'a> = Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

impl Run<'_> {
    /// Evaluates a condition, skipping operands that cannot change the answer.
    ///
    /// Short-circuiting lives here rather than in [`kleene_and`]/[`kleene_or`]
    /// because the hooks are `async`: a lazy combinator would need to take a
    /// future, and the truth tables are worth keeping pure and table-testable.
    ///
    /// Note which cases actually skip. `Fail and _` and `Pass or _` are
    /// decided by the left operand alone. An **`Undecided` left operand skips
    /// nothing** — the right operand is exactly what might rescue it.
    fn eval<'s>(&'s mut self, condition: &'s Condition) -> VerdictFuture<'s> {
        Box::pin(async move {
            match condition {
                Condition::Check(name) => self.eval_check(name).await,
                Condition::Not(inner) => kleene_not(&self.eval(inner).await),
                Condition::And(left, right) => {
                    let left = self.eval(left).await;
                    if matches!(left, Verdict::Fail(_)) {
                        return left;
                    }
                    let right = self.eval(right).await;
                    kleene_and(&left, &right)
                }
                Condition::Or(left, right) => {
                    let left = self.eval(left).await;
                    if matches!(left, Verdict::Pass) {
                        return left;
                    }
                    let right = self.eval(right).await;
                    kleene_or(&left, &right)
                }
            }
        })
    }

    async fn eval_check(&mut self, name: &str) -> Verdict {
        if let Some(cached) = self.memo.get(name) {
            return cached.clone();
        }

        let Some(slot) = self.policy.checks.get(name) else {
            // The builder resolves every name in every condition, so reaching
            // this is a bug in the builder rather than in the configuration —
            // hence an unknown rather than a refusal the operator would chase.
            return Verdict::Undecided(format!("check `{name}` is not configured"));
        };

        // Belt and braces for the stage intersection: a check asked at a stage
        // it does not serve would otherwise fall through to the trait's
        // default `Pass`, which is precisely the silent substitution the
        // intersection exists to prevent.
        if !slot.stages.contains(self.stage) {
            return Verdict::Undecided(format!(
                "check `{name}` cannot decide at the {} stage",
                self.stage.as_str()
            ));
        }

        let kind = slot.kind;
        let check = Arc::clone(&slot.check);

        let verdict = match self.hook {
            Hook::Connection(context) => check.check_connection(context).await,
            Hook::Identifiers(context) => check.check_identifiers(context).await,
        };

        self.memo.insert(name.to_string(), verdict.clone());
        self.trace.push(CheckOutcome {
            name: name.to_string(),
            kind,
            verdict: verdict.clone(),
        });
        verdict
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::Method;

    use super::*;

    /// A check with a fixed answer that counts how often it was asked.
    ///
    /// The counter is the only thing that can prove a *skip*: a short-circuited
    /// operand and an evaluated one that happens not to matter produce the same
    /// verdict, so the assertion has to be about the call, not the result.
    struct StubCheck {
        verdict: Verdict,
        stages: StageSet,
        calls: Arc<AtomicUsize>,
    }

    impl StubCheck {
        fn with(verdict: Verdict, stages: StageSet) -> (Arc<dyn Check>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let check = Arc::new(Self {
                verdict,
                stages,
                calls: Arc::clone(&calls),
            });
            (check, calls)
        }

        fn passing() -> (Arc<dyn Check>, Arc<AtomicUsize>) {
            Self::with(Verdict::Pass, StageSet::both())
        }

        fn failing() -> (Arc<dyn Check>, Arc<AtomicUsize>) {
            Self::with(Verdict::Fail("stub refused".to_string()), StageSet::both())
        }

        fn undecided() -> (Arc<dyn Check>, Arc<AtomicUsize>) {
            Self::with(
                Verdict::Undecided("stub is down".to_string()),
                StageSet::both(),
            )
        }
    }

    #[async_trait]
    impl Check for StubCheck {
        fn kind(&self) -> &'static str {
            "stub"
        }

        fn stages(&self) -> StageSet {
            self.stages
        }

        async fn check_connection(&self, _context: &ConnectionContext<'_>) -> Verdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict.clone()
        }

        async fn check_identifiers(&self, _context: &IdentifierContext<'_>) -> Verdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict.clone()
        }
    }

    fn rule(name: &str, when: &str, then: Effect) -> Rule {
        Rule {
            name: name.to_string(),
            when: Condition::parse(when).expect("test condition should parse"),
            then,
            message: None,
            mode: Mode::Enforce,
        }
    }

    fn connection_context() -> ConnectionContext<'static> {
        ConnectionContext {
            client_ip: Some("10.0.0.5".parse().expect("literal address")),
            method: &Method::POST,
            path: "/newOrder",
        }
    }

    async fn decide(policy: &FilterPolicy) -> Outcome {
        policy
            .evaluate_connection(&connection_context())
            .await
            .outcome
    }

    // ---- the truth tables -------------------------------------------------

    /// The whole design rests on these twenty-one rows, so they are asserted
    /// directly rather than inferred from the evaluator's behaviour.
    #[test]
    fn kleene_and_is_complete() {
        let pass = Verdict::Pass;
        let fail = Verdict::Fail("no".to_string());
        let unknown = Verdict::Undecided("down".to_string());

        let cases = [
            (&pass, &pass, &pass),
            (&pass, &fail, &fail),
            (&pass, &unknown, &unknown),
            (&fail, &pass, &fail),
            (&fail, &fail, &fail),
            // The row that matters: already false, so the unknown is irrelevant.
            (&fail, &unknown, &fail),
            (&unknown, &pass, &unknown),
            (&unknown, &fail, &fail),
            (&unknown, &unknown, &unknown),
        ];

        for (left, right, expected) in cases {
            assert!(
                same_kind(&kleene_and(left, right), expected),
                "{left:?} and {right:?} should be {expected:?}"
            );
        }
    }

    #[test]
    fn kleene_or_is_complete() {
        let pass = Verdict::Pass;
        let fail = Verdict::Fail("no".to_string());
        let unknown = Verdict::Undecided("down".to_string());

        let cases = [
            (&pass, &pass, &pass),
            (&pass, &fail, &pass),
            // The row the whole feature exists for: an inventory outage does
            // not defeat an address that already matched.
            (&pass, &unknown, &pass),
            (&fail, &pass, &pass),
            (&fail, &fail, &fail),
            (&fail, &unknown, &unknown),
            (&unknown, &pass, &pass),
            (&unknown, &fail, &unknown),
            (&unknown, &unknown, &unknown),
        ];

        for (left, right, expected) in cases {
            assert!(
                same_kind(&kleene_or(left, right), expected),
                "{left:?} or {right:?} should be {expected:?}"
            );
        }
    }

    #[test]
    fn kleene_not_leaves_the_unknown_alone() {
        assert!(same_kind(
            &kleene_not(&Verdict::Pass),
            &Verdict::Fail(String::new())
        ));
        assert!(same_kind(
            &kleene_not(&Verdict::Fail("no".to_string())),
            &Verdict::Pass
        ));
        assert!(same_kind(
            &kleene_not(&Verdict::Undecided("down".to_string())),
            &Verdict::Undecided(String::new())
        ));
    }

    /// Compares which of the three a verdict is, ignoring its detail.
    fn same_kind(left: &Verdict, right: &Verdict) -> bool {
        matches!(
            (left, right),
            (Verdict::Pass, Verdict::Pass)
                | (Verdict::Fail(_), Verdict::Fail(_))
                | (Verdict::Undecided(_), Verdict::Undecided(_))
        )
    }

    // ---- short-circuiting and memoisation ---------------------------------

    #[tokio::test]
    async fn a_failing_left_operand_skips_the_right_of_an_and() {
        let (left, left_calls) = StubCheck::failing();
        let (right, right_calls) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("left".to_string(), left), ("right".to_string(), right)],
            vec![rule("r", "left and right", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(matches!(decide(&policy).await, Outcome::Deny(_)));
        assert_eq!(left_calls.load(Ordering::SeqCst), 1);
        assert_eq!(right_calls.load(Ordering::SeqCst), 0, "right was evaluated");
    }

    #[tokio::test]
    async fn a_passing_left_operand_skips_the_right_of_an_or() {
        let (left, left_calls) = StubCheck::passing();
        let (right, right_calls) = StubCheck::failing();
        let policy = FilterPolicy::new(
            vec![("left".to_string(), left), ("right".to_string(), right)],
            vec![rule("r", "left or right", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
        assert_eq!(left_calls.load(Ordering::SeqCst), 1);
        assert_eq!(right_calls.load(Ordering::SeqCst), 0, "right was evaluated");
    }

    /// The converse, and the reason short-circuiting cannot simply be "stop at
    /// the first non-`Pass`": an unknown is exactly the case where the other
    /// operand still matters.
    #[tokio::test]
    async fn an_undecided_left_operand_still_evaluates_the_right() {
        let (left, left_calls) = StubCheck::undecided();
        let (right, right_calls) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("left".to_string(), left), ("right".to_string(), right)],
            vec![rule("r", "left or right", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
        assert_eq!(left_calls.load(Ordering::SeqCst), 1);
        assert_eq!(right_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_check_named_twice_runs_once() {
        let (check, calls) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("only".to_string(), check)],
            vec![rule("r", "only and (only or only)", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn memoisation_spans_rules_within_one_stage() {
        let (check, calls) = StubCheck::failing();
        let policy = FilterPolicy::new(
            vec![("only".to_string(), check)],
            vec![
                rule("first", "only", Effect::Allow),
                rule("second", "only", Effect::Allow),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(matches!(decide(&policy).await, Outcome::Deny(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ---- the rule loop ----------------------------------------------------

    #[tokio::test]
    async fn the_first_matching_rule_decides_and_later_rules_never_run() {
        let (first, _) = StubCheck::passing();
        let (second, second_calls) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("first".to_string(), first), ("second".to_string(), second)],
            vec![
                rule("allow-it", "first", Effect::Allow),
                rule("deny-it", "second", Effect::Deny),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_stage_with_no_applicable_rules_allows() {
        let (check, calls) = StubCheck::with(
            Verdict::Fail("no".to_string()),
            StageSet::identifiers_only(),
        );
        let policy = FilterPolicy::new(
            vec![("names".to_string(), check)],
            vec![rule("names-only", "names", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        // Nothing is applicable at the connection stage, so the default deny
        // must not reach it — otherwise an identifier-only policy would lock
        // out every request before a name was ever mentioned.
        assert_eq!(decide(&policy).await, Outcome::Allow);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!policy.has_rules_at(Stage::Connection));
        assert!(policy.has_rules_at(Stage::Identifiers));
    }

    #[tokio::test]
    async fn the_default_applies_only_once_a_rule_was_applicable() {
        let (check, _) = StubCheck::failing();
        let policy = FilterPolicy::new(
            vec![("no".to_string(), check)],
            vec![rule("never", "no", Effect::Allow)],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
    }

    #[tokio::test]
    async fn a_warn_rule_matches_without_deciding() {
        let (check, _) = StubCheck::passing();
        let mut warned = rule("would-deny", "yes", Effect::Deny);
        warned.mode = Mode::Warn;

        let policy = FilterPolicy::new(
            vec![("yes".to_string(), check)],
            vec![warned],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        let evaluation = policy.evaluate_connection(&connection_context()).await;
        assert_eq!(evaluation.outcome, Outcome::Allow);
        assert_eq!(evaluation.matched, None);
        assert_eq!(evaluation.warned.len(), 1);
        assert_eq!(evaluation.warned[0].name, "would-deny");
        assert_eq!(evaluation.warned[0].then, Effect::Deny);
    }

    #[tokio::test]
    async fn the_enforcing_twin_of_a_warn_rule_denies() {
        let (check, _) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("yes".to_string(), check)],
            vec![rule("deny-it", "yes", Effect::Deny)],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        assert!(matches!(decide(&policy).await, Outcome::Deny(_)));
    }

    // ---- unknowns at the rule level ---------------------------------------

    #[tokio::test]
    async fn an_unknown_rule_poisons_a_differing_answer() {
        let (down, _) = StubCheck::undecided();
        let policy = FilterPolicy::new(
            vec![("inventory".to_string(), down)],
            vec![rule("inventory-owned", "inventory", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        // The rule would have allowed; the default denies. There is no honest
        // answer, so this is a retryable 500 rather than a refusal.
        assert!(matches!(decide(&policy).await, Outcome::Undecided(_)));
    }

    /// The rule that makes order stop mattering: a later rule reaching the same
    /// effect the unknown rule would have reached is a decision either way.
    #[tokio::test]
    async fn an_unknown_rule_is_harmless_when_the_answer_agrees() {
        let (down, _) = StubCheck::undecided();
        let (up, _) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("inventory".to_string(), down), ("mgmt".to_string(), up)],
            vec![
                rule("inventory-owned", "inventory", Effect::Allow),
                rule("mgmt-bypass", "mgmt", Effect::Allow),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
    }

    /// Written as one condition instead of two rules, the same outage is
    /// absorbed by `or` before the rule loop ever sees it.
    #[tokio::test]
    async fn an_or_absorbs_the_outage_within_a_single_rule() {
        let (down, _) = StubCheck::undecided();
        let (up, _) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("inventory".to_string(), down), ("mgmt".to_string(), up)],
            vec![rule("reachable", "mgmt or inventory", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(decide(&policy).await, Outcome::Allow);
    }

    /// ...and the same policy without the disjunct is still a 500, which is
    /// what stops the `or` from reading as "outages are ignored".
    #[tokio::test]
    async fn the_inventory_alone_is_still_an_outage() {
        let (down, _) = StubCheck::undecided();
        let policy = FilterPolicy::new(
            vec![("inventory".to_string(), down)],
            vec![rule("reachable", "inventory", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(matches!(decide(&policy).await, Outcome::Undecided(_)));
    }

    #[tokio::test]
    async fn a_warn_rule_that_cannot_be_evaluated_poisons_nothing() {
        let (down, _) = StubCheck::undecided();
        let mut dry_run = rule("inventory-owned", "inventory", Effect::Allow);
        dry_run.mode = Mode::Warn;

        let policy = FilterPolicy::new(
            vec![("inventory".to_string(), down)],
            vec![dry_run],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(matches!(decide(&policy).await, Outcome::Deny(_)));
    }

    // ---- what the client is told ------------------------------------------

    #[tokio::test]
    async fn a_rule_message_is_shown_verbatim() {
        let (check, _) = StubCheck::passing();
        let mut denying = rule("no-tenants", "yes", Effect::Deny);
        denying.message = Some("this address owns no such name".to_string());

        let policy = FilterPolicy::new(
            vec![("yes".to_string(), check)],
            vec![denying],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        assert_eq!(
            decide(&policy).await,
            Outcome::Deny("this address owns no such name".to_string())
        );
    }

    #[tokio::test]
    async fn a_denying_rule_without_a_message_names_itself() {
        let (check, _) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("yes".to_string(), check)],
            vec![rule("no-tenants", "yes", Effect::Deny)],
            Effect::Allow,
            ProxyPolicy::default(),
        );

        assert_eq!(
            decide(&policy).await,
            Outcome::Deny("refused by policy rule `no-tenants`".to_string())
        );
    }

    #[tokio::test]
    async fn falling_through_to_the_default_reports_the_first_refusing_check() {
        let (check, _) = StubCheck::failing();
        let policy = FilterPolicy::new(
            vec![("addr".to_string(), check)],
            vec![rule("permitted", "addr", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(
            decide(&policy).await,
            Outcome::Deny("stub refused".to_string())
        );
    }

    /// The regression: with rules ordered bypass-first, quoting the first
    /// failure anywhere in the stage tells a refused client about the bypass
    /// it was never going to match, not about the rule it actually failed.
    #[tokio::test]
    async fn a_default_deny_quotes_the_last_rule_not_the_first_bypass() {
        let (bypass, _) = StubCheck::with(
            Verdict::Fail("path /newOrder is not allowed".to_string()),
            StageSet::both(),
        );
        let (main, _) = StubCheck::with(
            Verdict::Fail("address 203.0.113.9 is not allowed".to_string()),
            StageSet::both(),
        );

        let policy = FilterPolicy::new(
            vec![
                ("public-paths".to_string(), bypass),
                ("mgmt-net".to_string(), main),
            ],
            vec![
                rule("public", "public-paths", Effect::Allow),
                rule("mgmt-bypass", "mgmt-net", Effect::Allow),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(
            decide(&policy).await,
            Outcome::Deny("address 203.0.113.9 is not allowed".to_string())
        );
    }

    /// ...and it widens to the whole stage when the last rule left no refusal
    /// of its own, so the fallback never loses information it had before.
    #[tokio::test]
    async fn a_default_deny_widens_when_the_last_rule_refused_nothing() {
        let (failing, _) = StubCheck::failing();
        let (passing, _) = StubCheck::passing();

        let policy = FilterPolicy::new(
            vec![
                ("first".to_string(), failing),
                ("second".to_string(), passing),
            ],
            vec![
                rule("early", "first", Effect::Allow),
                // Passes its check, so `not` refuses the rule without any
                // check having failed.
                rule("late", "not second", Effect::Allow),
            ],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert_eq!(
            decide(&policy).await,
            Outcome::Deny("stub refused".to_string())
        );
    }

    #[tokio::test]
    async fn a_default_deny_with_nothing_to_report_says_so() {
        let (check, _) = StubCheck::passing();
        // The trace records what each *check* answered, not what the condition
        // built out of them came to. `not yes` therefore fails the rule while
        // leaving a single `Pass` behind, so there is genuinely no refusal to
        // quote and the generic sentence is the honest answer.
        let policy = FilterPolicy::new(
            vec![("yes".to_string(), check)],
            vec![rule("permitted", "not yes", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let evaluation = policy.evaluate_connection(&connection_context()).await;
        assert_eq!(
            evaluation.outcome,
            Outcome::Deny("no policy rule permits this request".to_string())
        );
        assert_eq!(evaluation.checks.len(), 1);
        assert_eq!(evaluation.checks[0].verdict, Verdict::Pass);
    }

    // ---- the trace --------------------------------------------------------

    #[tokio::test]
    async fn the_trace_records_every_evaluated_check_in_order() {
        let (first, _) = StubCheck::passing();
        let (second, _) = StubCheck::failing();
        let policy = FilterPolicy::new(
            vec![("first".to_string(), first), ("second".to_string(), second)],
            vec![rule("r", "first and second", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let evaluation = policy.evaluate_connection(&connection_context()).await;
        let names: Vec<&str> = evaluation
            .checks
            .iter()
            .map(|outcome| outcome.name.as_str())
            .collect();
        assert_eq!(names, vec!["first", "second"]);
        assert_eq!(evaluation.checks[0].kind, "stub");
    }

    // ---- stage derivation -------------------------------------------------

    #[test]
    fn a_rule_takes_the_intersection_of_its_checks_stages() {
        let (anywhere, _) = StubCheck::with(Verdict::Pass, StageSet::both());
        let (names_only, _) = StubCheck::with(Verdict::Pass, StageSet::identifiers_only());
        let policy = FilterPolicy::new(
            vec![
                ("anywhere".to_string(), anywhere),
                ("names".to_string(), names_only),
            ],
            vec![rule("mixed", "anywhere or names", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(!policy.has_rules_at(Stage::Connection));
        assert!(policy.has_rules_at(Stage::Identifiers));
    }

    #[test]
    fn a_rule_naming_an_unknown_check_is_never_applicable() {
        let policy = FilterPolicy::new(
            Vec::new(),
            vec![rule("broken", "nonexistent", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        assert!(!policy.has_rules_at(Stage::Connection));
        assert!(!policy.has_rules_at(Stage::Identifiers));
        assert!(policy.is_active());
    }

    #[test]
    fn stage_sets_describe_themselves() {
        assert_eq!(StageSet::both().to_string(), "connection and identifiers");
        assert_eq!(StageSet::connection_only().to_string(), "connection only");
        assert_eq!(StageSet::identifiers_only().to_string(), "identifiers only");
        assert_eq!(StageSet::none().to_string(), "no stage");
        assert!(StageSet::none().is_empty());
        assert!(
            StageSet::connection_only()
                .intersect(StageSet::identifiers_only())
                .is_empty()
        );
        assert_eq!(Stage::Connection.as_str(), "connection");
        assert_eq!(Stage::Identifiers.as_str(), "identifiers");
        assert_eq!(Effect::Allow.as_str(), "allow");
        assert_eq!(Effect::Deny.as_str(), "deny");
    }

    #[test]
    fn the_default_policy_decides_nothing() {
        let policy = FilterPolicy::default();
        assert!(!policy.is_active());
        assert!(!policy.has_rules_at(Stage::Connection));
        assert_eq!(policy.default_effect(), Effect::Deny);
        assert!(format!("{policy:?}").contains("FilterPolicy"));
    }

    #[test]
    fn the_debug_rendering_names_checks_and_rules() {
        let (check, _) = StubCheck::passing();
        let policy = FilterPolicy::new(
            vec![("mgmt".to_string(), check)],
            vec![rule("bypass", "mgmt", Effect::Allow)],
            Effect::Deny,
            ProxyPolicy::default(),
        );

        let rendered = format!("{policy:?}");
        assert!(rendered.contains("mgmt: stub"), "{rendered}");
        assert!(rendered.contains("bypass: mgmt -> allow"), "{rendered}");
    }
}
