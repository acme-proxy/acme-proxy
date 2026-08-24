//! Turning `[filter]` into a [`FilterPolicy`].
//!
//! This is the only module that knows which of [`CheckConfig`]'s flattened keys
//! belong to which `type`, and it is where every startup refusal is worded. The
//! rule throughout is the one the rest of the codebase follows: a configuration
//! that cannot mean what it says stops the server, rather than coming up
//! looking configured and filtering nothing.
//!
//! ## Only referenced checks are built
//!
//! A `[filter.check.<name>]` that no selected rule mentions is never
//! constructed — it opens no HTTP client, resolves no nameserver and validates
//! nothing. That is what lets a global `[filter]` section carry a library of
//! checks (profile inheritance copies every one of them down) while each
//! profile's `filter.rules` picks the subset it wants. An unreferenced check is
//! reported once at startup as `filter_check_unused`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tracing::{info, warn};

use super::expr::{Condition, is_reserved_word};
use super::policy::{Check, Effect, FilterPolicy, Mode, Rule, StageSet};
use super::{ProxyPolicy, custom, eab, identifiers, ip_allow, ipam, path, reverse_dns};
use crate::config::{CheckConfig, DnsConfig, FilterConfig, RuleConfig, validate_key_names};
use crate::ipam::IpamRegistry;

/// What one check type is called, where it can decide, and which of the
/// flattened `[filter.check.<name>]` keys are its own.
struct TypeSpec {
    name: &'static str,
    /// Where an instance decides when `stages` says nothing.
    natural: StageSet,
    /// Where an instance *could* decide if `stages` asked it to. Wider than
    /// `natural` only for `reverse_dns`, which is capable at both stages but
    /// costs a PTR exchange each time.
    capable: StageSet,
    /// Keys beyond the universal `type` and `stages`.
    keys: &'static [&'static str],
}

const TYPES: &[TypeSpec] = &[
    TypeSpec {
        name: "allowed_ip",
        natural: StageSet::both(),
        capable: StageSet::both(),
        keys: &["allow", "deny"],
    },
    TypeSpec {
        name: "path",
        natural: StageSet::connection_only(),
        capable: StageSet::connection_only(),
        keys: &["allow", "deny"],
    },
    TypeSpec {
        name: "reverse_dns",
        natural: StageSet::connection_only(),
        capable: StageSet::both(),
        keys: &[
            "allow",
            "deny",
            "allow_regex",
            "deny_regex",
            "require_forward_confirm",
            "timeout_ms",
        ],
    },
    TypeSpec {
        name: "identifiers",
        natural: StageSet::identifiers_only(),
        capable: StageSet::identifiers_only(),
        keys: &[
            "allow",
            "deny",
            "allow_regex",
            "deny_regex",
            "allowed_types",
            "allow_wildcards",
        ],
    },
    TypeSpec {
        name: "eab",
        natural: StageSet::identifiers_only(),
        capable: StageSet::identifiers_only(),
        keys: &[
            "allow",
            "deny",
            "allow_regex",
            "deny_regex",
            "kids",
            "require_active",
        ],
    },
    TypeSpec {
        name: "ipam",
        natural: StageSet::identifiers_only(),
        capable: StageSet::identifiers_only(),
        keys: &[],
    },
    TypeSpec {
        name: "custom",
        natural: StageSet::both(),
        capable: StageSet::both(),
        keys: &["script_path", "timeout_ms", "pass_stdin", "args"],
    },
];

fn type_spec(name: &str) -> Option<&'static TypeSpec> {
    TYPES.iter().find(|spec| spec.name == name)
}

fn known_types() -> String {
    TYPES
        .iter()
        .map(|spec| format!("`{}`", spec.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Which of the flattened keys this entry actually set.
///
/// Needed because the keys are one flat union: without it, `script_path` on an
/// `allowed_ip` check would be silently ignored, which is the "came up looking
/// configured" failure this codebase refuses.
fn keys_set(config: &CheckConfig) -> Vec<&'static str> {
    let mut keys = Vec::new();
    let mut note = |set: bool, key: &'static str| {
        if set {
            keys.push(key);
        }
    };
    note(!config.allow.is_empty(), "allow");
    note(!config.deny.is_empty(), "deny");
    note(!config.allow_regex.is_empty(), "allow_regex");
    note(!config.deny_regex.is_empty(), "deny_regex");
    note(!config.allowed_types.is_empty(), "allowed_types");
    note(!config.kids.is_empty(), "kids");
    note(!config.args.is_empty(), "args");
    note(config.allow_wildcards.is_some(), "allow_wildcards");
    note(config.require_active.is_some(), "require_active");
    note(
        config.require_forward_confirm.is_some(),
        "require_forward_confirm",
    );
    note(config.timeout_ms.is_some(), "timeout_ms");
    note(!config.script_path.is_empty(), "script_path");
    note(config.pass_stdin.is_some(), "pass_stdin");
    keys
}

/// Which type a misplaced key does belong to, for the error message.
fn owner_of(key: &str) -> Option<&'static str> {
    TYPES
        .iter()
        .find(|spec| spec.keys.contains(&key))
        .map(|spec| spec.name)
}

/// Parses `stages`, refusing a stage the type cannot serve.
fn resolve_stages(name: &str, config: &CheckConfig, spec: &TypeSpec) -> anyhow::Result<StageSet> {
    if config.stages.is_empty() {
        return Ok(spec.natural);
    }

    let mut stages = StageSet::none();
    for value in &config.stages {
        match value.as_str() {
            "connection" => stages.connection = true,
            "identifiers" => stages.identifiers = true,
            other => anyhow::bail!(
                "filter.check.{name}.stages names `{other}`; use \"connection\" \
                 and/or \"identifiers\""
            ),
        }
    }

    if stages.connection && !spec.capable.connection {
        anyhow::bail!(
            "filter.check.{name}.stages names \"connection\", but type = \"{}\" can only \
             decide once the requested names are known",
            spec.name
        );
    }
    if stages.identifiers && !spec.capable.identifiers {
        anyhow::bail!(
            "filter.check.{name}.stages names \"identifiers\", but type = \"{}\" decides \
             from the connection alone",
            spec.name
        );
    }

    Ok(stages)
}

/// Wraps a check so it reports the stages an operator asked for.
///
/// A wrapper rather than a field on every check: `stages` is a policy decision
/// about an instance, and threading it through five constructors would put the
/// same three lines in five places.
struct Restaged {
    inner: Arc<dyn Check>,
    stages: StageSet,
}

#[async_trait::async_trait]
impl Check for Restaged {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn stages(&self) -> StageSet {
        self.stages
    }

    async fn check_connection(&self, context: &super::ConnectionContext<'_>) -> super::Verdict {
        self.inner.check_connection(context).await
    }

    async fn check_identifiers(&self, context: &super::IdentifierContext<'_>) -> super::Verdict {
        self.inner.check_identifiers(context).await
    }
}

/// Builds one check from its `type` and that type's keys.
fn build_check(
    name: &str,
    config: &CheckConfig,
    dns: &DnsConfig,
    inventory: Option<&Arc<IpamRegistry>>,
) -> anyhow::Result<Arc<dyn Check>> {
    let kind = config.r#type.trim();

    if kind.is_empty() {
        anyhow::bail!(
            "filter.check.{name} sets no type; every named check needs one of {}",
            known_types()
        );
    }

    // Renamed when NetBox was lifted into its own subsystem. Refused by name
    // rather than aliased, the way `signer.backend = \"acme_proxy\"` is: the
    // section moved too, so a silent alias would leave `[ipam.netbox]` being
    // read by nothing while the server came up looking configured. This is a
    // diagnostic, not a compatibility path — the old shape is read by nothing,
    // and the arm goes at 1.0.0.
    if kind == "netbox" {
        anyhow::bail!(
            "filter.check.{name}.type = \"netbox\" is now \"ipam\": set type = \"ipam\" and \
             ipam.backend = \"netbox\", and put the inventory's own settings in \
             [ipam.netbox]"
        );
    }

    let Some(spec) = type_spec(kind) else {
        anyhow::bail!(
            "filter.check.{name}.type = \"{kind}\" is not a check type; use one of {}",
            known_types()
        );
    };

    for key in keys_set(config) {
        if spec.keys.contains(&key) {
            continue;
        }
        let hint = owner_of(key).map_or_else(
            || format!("`{key}` belongs to no check type"),
            |owner| format!("`{key}`, which belongs to type = \"{owner}\""),
        );
        anyhow::bail!("filter.check.{name} sets {hint}; this check is type = \"{kind}\"");
    }

    let built: Arc<dyn Check> = match kind {
        "allowed_ip" => Arc::new(ip_allow::AllowedFromIpAddress::from_settings(
            name,
            &ip_allow::Settings {
                allow: config.allow.clone(),
                deny: config.deny.clone(),
            },
        )?),
        "path" => Arc::new(path::PathList::from_settings(
            name,
            &path::Settings {
                allow: config.allow.clone(),
                deny: config.deny.clone(),
            },
        )?),
        "reverse_dns" => Arc::new(reverse_dns::ClientHasValidReverseDns::from_settings(
            name,
            &reverse_dns::Settings {
                require_forward_confirm: config.require_forward_confirm.unwrap_or(true),
                allow: config.allow.clone(),
                deny: config.deny.clone(),
                allow_regex: config.allow_regex.clone(),
                deny_regex: config.deny_regex.clone(),
                timeout_ms: config.timeout_ms.unwrap_or(2000),
            },
            dns,
        )?),
        "identifiers" => Arc::new(identifiers::IdentifierList::from_settings(
            name,
            &identifiers::Settings {
                allowed_types: if config.allowed_types.is_empty() {
                    super::default_identifier_types()
                } else {
                    config.allowed_types.clone()
                },
                allow: config.allow.clone(),
                deny: config.deny.clone(),
                allow_regex: config.allow_regex.clone(),
                deny_regex: config.deny_regex.clone(),
                allow_wildcards: config.allow_wildcards.unwrap_or(false),
            },
        )?),
        "eab" => Arc::new(eab::EabList::from_settings(
            name,
            &eab::Settings {
                allow: config.allow.clone(),
                deny: config.deny.clone(),
                allow_regex: config.allow_regex.clone(),
                deny_regex: config.deny_regex.clone(),
                kids: config.kids.clone(),
                require_active: config.require_active.unwrap_or(false),
            },
        )?),
        "ipam" => {
            let registry = inventory.ok_or_else(|| {
                anyhow::anyhow!(
                    "filter.check.{name} is type = \"ipam\" but ipam.backend is empty; set \
                     ipam.backend (`netbox`, `phpipam` or `custom`) and configure the matching \
                     [ipam.<backend>] section, or drop the check"
                )
            })?;
            Arc::new(ipam::IpamFilter::new(Arc::clone(registry)))
        }
        "custom" => Arc::new(custom::CustomScriptFilter::from_settings(
            name,
            &custom::Settings {
                script_path: config.script_path.clone(),
                timeout_ms: config.timeout_ms.unwrap_or(5000),
                pass_stdin: config.pass_stdin.unwrap_or(true),
                args: config.args.clone(),
            },
        )?),
        other => unreachable!("type_spec accepted an unhandled type: {other}"),
    };

    let stages = resolve_stages(name, config, spec)?;
    if stages == built.stages() {
        Ok(built)
    } else {
        Ok(Arc::new(Restaged {
            inner: built,
            stages,
        }))
    }
}

/// Parses one `[filter.rule.<name>]`.
fn build_rule(name: &str, config: &RuleConfig) -> anyhow::Result<Rule> {
    if config.when.trim().is_empty() {
        anyhow::bail!(
            "filter.rule.{name}.when is empty; a rule with no condition is what \
             filter.default is for"
        );
    }

    let when = Condition::parse(&config.when).map_err(|error| {
        anyhow::anyhow!("filter.rule.{name}.when: {error} in {:?}", config.when)
    })?;

    let then = match config.then.trim() {
        "" => {
            anyhow::bail!("filter.rule.{name} sets no `then`; say whether a match allows or denies")
        }
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        other => anyhow::bail!("filter.rule.{name}.then = \"{other}\": use \"allow\" or \"deny\""),
    };

    let mode = match config.mode.trim() {
        "" | "enforce" => Mode::Enforce,
        "warn" => Mode::Warn,
        other => {
            anyhow::bail!("filter.rule.{name}.mode = \"{other}\": use \"enforce\" or \"warn\"")
        }
    };

    Ok(Rule {
        name: name.to_string(),
        when,
        then,
        message: Some(config.message.clone()).filter(|text| !text.trim().is_empty()),
        mode,
    })
}

/// Refuses a key that the policy redesign removed, naming its replacement.
///
/// The standing pre-1.0 rule: a removed key is deleted rather than aliased, and
/// what it leaves behind is an error message naming the new shape, so an
/// unmigrated configuration stops the server instead of coming up looking
/// configured and filtering nothing. These refusals are diagnostics with no
/// reader behind them and go away at 1.0.0.
fn refuse_removed_keys(cfg: &FilterConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg.enabled.is_empty(),
        "filter.enabled is no longer a setting: `[filter]` is a policy of named checks and \
         rules now. Declare each filter as a [filter.check.<name>] with a `type`, write a \
         [filter.rule.<name>] whose `when` names them, and list the rules in filter.rules."
    );
    anyhow::ensure!(
        cfg.exempt_paths.is_empty(),
        "filter.exempt_paths is no longer a setting: write a check with type = \"path\" \
         listing the paths and a rule allowing it, which can also combine the path with an \
         address and can glob (`/renewalInfo/*`) where the old list could not."
    );
    anyhow::ensure!(
        cfg.custom_enabled.is_empty(),
        "filter.custom_enabled is no longer a setting: `custom` is an ordinary check type, \
         so each script is a [filter.check.<name>] with type = \"custom\", and filter.rules \
         already says which run and in what order."
    );
    Ok(())
}

/// Builds the configured policy, refusing anything that cannot mean what it
/// says.
pub fn build(
    cfg: &FilterConfig,
    dns: &DnsConfig,
    inventory: Option<Arc<IpamRegistry>>,
    eab_enabled: bool,
) -> anyhow::Result<FilterPolicy> {
    refuse_removed_keys(cfg)?;

    let proxy = ProxyPolicy::new(&cfg.trusted_proxies, &cfg.forwarded_header)?;

    let default_effect = match cfg.default.trim() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        other => anyhow::bail!("filter.default = \"{other}\": use \"allow\" or \"deny\""),
    };

    validate_key_names("filter.check", cfg.check.keys())?;
    validate_key_names("filter.rule", cfg.rule.keys())?;

    for name in cfg.check.keys() {
        anyhow::ensure!(
            !is_reserved_word(name),
            "filter.check.{name}: `and`, `or` and `not` are the condition language's own \
             words and cannot name a check"
        );
    }

    if cfg.rules.is_empty() {
        anyhow::ensure!(
            cfg.rule.is_empty(),
            "[filter.rule.{}] is configured but filter.rules is empty; list the rules to \
             evaluate, in order",
            cfg.rule
                .keys()
                .next()
                .expect("non-empty map has a first key")
        );
        // Says only what is true of *this* subsystem. Whether an unfiltered
        // server is also an open CA depends on `challenge.bypass`, which
        // `challenge::from_config` warns about separately and in its own words.
        warn!(
            event = "filter_disabled",
            outcome = "advisory",
            "no filter rules configured: every client that can reach this server may \
             request a certificate for any name (set filter.rules)"
        );
        return Ok(FilterPolicy::new(
            Vec::new(),
            Vec::new(),
            default_effect,
            proxy,
        ));
    }

    // Rules first, so a condition that will not parse is reported before any
    // check opens a socket.
    let mut rules = Vec::with_capacity(cfg.rules.len());
    for name in &cfg.rules {
        let config = cfg.rule.get(name).ok_or_else(|| {
            anyhow::anyhow!(
                "filter.rules names `{name}`, but no [filter.rule.{name}] is configured"
            )
        })?;
        rules.push(build_rule(name, config)?);
    }

    let referenced: BTreeSet<&str> = rules
        .iter()
        .flat_map(|rule| rule.when.check_names())
        .collect();

    for rule in &rules {
        for name in rule.when.check_names() {
            anyhow::ensure!(
                cfg.check.contains_key(name),
                "filter.rule.{}.when names `{name}`, but no [filter.check.{name}] is \
                 configured",
                rule.name
            );
        }
    }

    let unused: Vec<&String> = cfg
        .check
        .keys()
        .filter(|name| !referenced.contains(name.as_str()))
        .collect();
    if !unused.is_empty() {
        warn!(
            event = "filter_check_unused",
            outcome = "advisory",
            checks = ?unused,
            "these checks are configured but named by no selected rule, so they are not \
             built and decide nothing",
        );
    }

    let mut checks: Vec<(String, Arc<dyn Check>)> = Vec::with_capacity(referenced.len());
    let mut inventories = 0;
    for name in &referenced {
        let config = &cfg.check[*name];
        // An `eab` check reads which credential the account registered under.
        // With EAB off, every account has none, so the check could do nothing
        // but refuse every request — a policy an operator did not write.
        anyhow::ensure!(
            config.r#type.trim() != "eab" || eab_enabled,
            "filter.check.{name} is type = \"eab\" but eab.enabled is false for this \
             profile, so no account has a credential and the check could only ever \
             refuse; turn EAB on or drop the check"
        );
        if config.r#type.trim() == "ipam" {
            inventories += 1;
            anyhow::ensure!(
                inventories == 1,
                "filter.check.{name} is a second type = \"ipam\" check, but a profile has \
                 exactly one inventory — the one [ipam] configures. Use the one check in \
                 as many rules as you like."
            );
        }
        checks.push((
            (*name).to_string(),
            build_check(name, config, dns, inventory.as_ref())?,
        ));
    }

    let stages: BTreeMap<&str, StageSet> = checks
        .iter()
        .map(|(name, check)| (name.as_str(), check.stages()))
        .collect();
    for rule in &rules {
        check_stage_intersection(rule, &stages)?;
    }

    info!(
        event = "filter_enabled",
        outcome = "success",
        rules = ?cfg.rules,
        checks = checks.len(),
        default = default_effect.as_str(),
    );

    Ok(FilterPolicy::new(checks, rules, default_effect, proxy))
}

/// Refuses a rule whose checks share no stage.
///
/// The intersection is what keeps a rule honest — evaluating it where one of
/// its checks cannot run would substitute a silent `Pass` for that check — so
/// an empty one is not a rule that never fires, it is a rule the operator
/// believes in. The message names both sides, because "no stage in common" on
/// its own leaves them hunting.
fn check_stage_intersection(rule: &Rule, stages: &BTreeMap<&str, StageSet>) -> anyhow::Result<()> {
    let names = rule.when.check_names();
    let combined = names.iter().fold(StageSet::both(), |accumulated, name| {
        accumulated.intersect(stages.get(name).copied().unwrap_or_else(StageSet::none))
    });

    if !combined.is_empty() {
        return Ok(());
    }

    let connection_only = names
        .iter()
        .find(|name| stages.get(**name).is_some_and(|set| !set.identifiers));
    let identifiers_only = names
        .iter()
        .find(|name| stages.get(**name).is_some_and(|set| !set.connection));

    match (connection_only, identifiers_only) {
        (Some(first), Some(second)) => anyhow::bail!(
            "filter.rule.{} combines `{first}` (connection only) and `{second}` \
             (identifiers only), so there is no point in a request where both can be \
             evaluated. Give `{first}` stages = [\"identifiers\"] if it can decide there, \
             or split the rule in two.",
            rule.name
        ),
        _ => anyhow::bail!(
            "filter.rule.{} names checks that share no stage, so it could never be \
             evaluated",
            rule.name
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpamConfig;
    use crate::filter::Stage;
    use crate::testutil::{TempDir, write_script};

    fn no_ipam() -> Option<Arc<IpamRegistry>> {
        None
    }

    fn inventory() -> Option<Arc<IpamRegistry>> {
        let cfg = IpamConfig {
            backend: "netbox".to_string(),
            netbox: crate::config::NetboxConfig {
                url: "http://127.0.0.1:1".to_string(),
                token: "t".to_string(),
                ..crate::config::NetboxConfig::default()
            },
            ..IpamConfig::default()
        };
        crate::ipam::from_config(
            &cfg,
            crate::http_client::Outbound::new(
                test_resolver(),
                std::sync::Arc::new(crate::proxy::OutboundProxies::direct()),
            ),
        )
        .unwrap()
    }

    fn test_resolver() -> Arc<dyn crate::dns::Resolver> {
        Arc::new(crate::dns::HickoryResolver::from_system().unwrap())
    }

    fn check_of(kind: &str) -> CheckConfig {
        CheckConfig {
            r#type: kind.to_string(),
            ..CheckConfig::default()
        }
    }

    fn net_check() -> CheckConfig {
        CheckConfig {
            r#type: "allowed_ip".to_string(),
            allow: vec!["10.0.0.0/8".to_string()],
            ..CheckConfig::default()
        }
    }

    fn rule_of(when: &str, then: &str) -> RuleConfig {
        RuleConfig {
            when: when.to_string(),
            then: then.to_string(),
            ..RuleConfig::default()
        }
    }

    /// A policy with one `allowed_ip` check and one rule naming it.
    fn simple(
        rules: &[&str],
        rule: &[(&str, RuleConfig)],
        check: &[(&str, CheckConfig)],
    ) -> FilterConfig {
        FilterConfig {
            rules: rules.iter().map(std::string::ToString::to_string).collect(),
            rule: rule
                .iter()
                .map(|(name, config)| ((*name).to_string(), config.clone()))
                .collect(),
            check: check
                .iter()
                .map(|(name, config)| ((*name).to_string(), config.clone()))
                .collect(),
            ..FilterConfig::default()
        }
    }

    fn build_with(cfg: &FilterConfig) -> anyhow::Result<FilterPolicy> {
        build(cfg, &DnsConfig::default(), no_ipam(), true)
    }

    fn error_of(cfg: &FilterConfig) -> String {
        build_with(cfg).unwrap_err().to_string()
    }

    // ---- the happy path ---------------------------------------------------

    #[test]
    fn a_default_configuration_decides_nothing() {
        let policy = build_with(&FilterConfig::default()).unwrap();
        assert!(!policy.is_active());
        assert!(!policy.has_rules_at(Stage::Connection));
        assert!(!policy.has_rules_at(Stage::Identifiers));
    }

    #[test]
    fn a_rule_over_one_check_builds() {
        let cfg = simple(
            &["mgmt"],
            &[("mgmt", rule_of("net", "allow"))],
            &[("net", net_check())],
        );
        let policy = build_with(&cfg).unwrap();
        assert!(policy.is_active());
        assert!(policy.has_rules_at(Stage::Connection));
        assert!(policy.has_rules_at(Stage::Identifiers));
        assert_eq!(policy.default_effect(), Effect::Deny);
    }

    #[test]
    fn two_instances_of_one_type_are_ordinary() {
        let mut second = net_check();
        second.allow = vec!["192.168.0.0/16".to_string()];
        let cfg = simple(
            &["either"],
            &[("either", rule_of("net-a or net-b", "allow"))],
            &[("net-a", net_check()), ("net-b", second)],
        );
        assert!(build_with(&cfg).is_ok());
    }

    #[test]
    fn the_default_effect_is_configurable() {
        let mut cfg = simple(
            &["mgmt"],
            &[("mgmt", rule_of("net", "allow"))],
            &[("net", net_check())],
        );
        cfg.default = "allow".to_string();
        assert_eq!(build_with(&cfg).unwrap().default_effect(), Effect::Allow);
    }

    /// The library-of-checks pattern profile inheritance depends on: an
    /// inherited check no selected rule names must not even be constructed, or
    /// a profile would pay for — and could fail startup on — a check it does
    /// not use.
    #[test]
    fn an_unreferenced_check_is_never_built() {
        // `script_path` points nowhere, so building this check would fail.
        let cfg = simple(
            &["mgmt"],
            &[("mgmt", rule_of("net", "allow"))],
            &[
                ("net", net_check()),
                (
                    "unused",
                    CheckConfig {
                        r#type: "custom".to_string(),
                        script_path: String::new(),
                        ..CheckConfig::default()
                    },
                ),
            ],
        );
        assert!(build_with(&cfg).is_ok());
    }

    // ---- stages -----------------------------------------------------------

    #[test]
    fn a_rule_takes_the_intersection_of_its_checks_stages() {
        let cfg = simple(
            &["both"],
            &[("both", rule_of("net and names", "allow"))],
            &[("net", net_check()), ("names", check_of("identifiers"))],
        );
        let policy = build_with(&cfg).unwrap();
        assert!(!policy.has_rules_at(Stage::Connection));
        assert!(policy.has_rules_at(Stage::Identifiers));
    }

    #[test]
    fn stages_can_be_overridden_within_what_the_type_can_serve() {
        let cfg = simple(
            &["ptr"],
            &[("ptr", rule_of("host and names", "allow"))],
            &[
                (
                    "host",
                    CheckConfig {
                        r#type: "reverse_dns".to_string(),
                        stages: vec!["identifiers".to_string()],
                        ..CheckConfig::default()
                    },
                ),
                ("names", check_of("identifiers")),
            ],
        );
        let policy = build_with(&cfg).unwrap();
        // Without the override this rule would have no stage at all.
        assert!(policy.has_rules_at(Stage::Identifiers));
        assert!(!policy.has_rules_at(Stage::Connection));
    }

    #[test]
    fn an_empty_stage_intersection_names_both_sides() {
        let cfg = simple(
            &["impossible"],
            &[("impossible", rule_of("host and names", "allow"))],
            &[
                ("host", check_of("reverse_dns")),
                ("names", check_of("identifiers")),
            ],
        );
        let error = error_of(&cfg);
        assert!(error.contains("`host` (connection only)"), "{error}");
        assert!(error.contains("`names` (identifiers only)"), "{error}");
        assert!(error.contains("split the rule in two"), "{error}");
    }

    #[test]
    fn a_stage_the_type_cannot_serve_is_refused_by_name() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("inv", "allow"))],
            &[(
                "inv",
                CheckConfig {
                    r#type: "ipam".to_string(),
                    stages: vec!["connection".to_string()],
                    ..CheckConfig::default()
                },
            )],
        );
        let error = build(&cfg, &DnsConfig::default(), inventory(), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.inv.stages"), "{error}");
        assert!(error.contains("type = \"ipam\""), "{error}");
    }

    #[test]
    fn an_unknown_stage_is_refused_by_name() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", "allow"))],
            &[(
                "net",
                CheckConfig {
                    stages: vec!["finalize".to_string()],
                    ..net_check()
                },
            )],
        );
        let error = error_of(&cfg);
        assert!(error.contains("names `finalize`"), "{error}");
    }

    // ---- refusals ---------------------------------------------------------

    #[test]
    fn an_unknown_type_is_refused_by_name() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("x", "allow"))],
            &[("x", check_of("geoip"))],
        );
        let error = error_of(&cfg);
        assert!(error.contains("\"geoip\" is not a check type"), "{error}");
        assert!(error.contains("`allowed_ip`"), "{error}");
    }

    #[test]
    fn a_check_with_no_type_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("x", "allow"))],
            &[("x", CheckConfig::default())],
        );
        assert!(error_of(&cfg).contains("sets no type"));
    }

    /// The old name is refused rather than aliased, because the settings moved
    /// to `[ipam.netbox]` as well.
    #[test]
    fn the_netbox_type_is_refused_by_name() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("x", "allow"))],
            &[("x", check_of("netbox"))],
        );
        let error = error_of(&cfg);
        assert!(error.contains("is now \"ipam\""), "{error}");
        assert!(error.contains("[ipam.netbox]"), "{error}");
    }

    /// The cost of flattening the keys: without this, `script_path` on an
    /// `allowed_ip` check would be read by nothing.
    #[test]
    fn a_key_belonging_to_another_type_is_refused_by_name() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", "allow"))],
            &[(
                "net",
                CheckConfig {
                    script_path: "/bin/true".to_string(),
                    ..net_check()
                },
            )],
        );
        let error = error_of(&cfg);
        assert!(error.contains("`script_path`"), "{error}");
        assert!(error.contains("type = \"custom\""), "{error}");
        assert!(
            error.contains("this check is type = \"allowed_ip\""),
            "{error}"
        );
    }

    #[test]
    fn a_rule_naming_an_undefined_check_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net and missing", "allow"))],
            &[("net", net_check())],
        );
        let error = error_of(&cfg);
        assert!(error.contains("names `missing`"), "{error}");
        assert!(error.contains("[filter.check.missing]"), "{error}");
    }

    #[test]
    fn filter_rules_naming_an_undefined_rule_is_refused() {
        let cfg = simple(&["nope"], &[], &[]);
        let error = error_of(&cfg);
        assert!(error.contains("filter.rules names `nope`"), "{error}");
    }

    #[test]
    fn rules_configured_but_none_selected_is_refused() {
        let cfg = simple(
            &[],
            &[("orphan", rule_of("net", "allow"))],
            &[("net", net_check())],
        );
        let error = error_of(&cfg);
        assert!(error.contains("filter.rules is empty"), "{error}");
    }

    #[test]
    fn an_empty_condition_is_refused() {
        let cfg = simple(&["r"], &[("r", rule_of("", "allow"))], &[]);
        assert!(error_of(&cfg).contains("filter.rule.r.when is empty"));
    }

    /// The parser's column survives all the way to the operator.
    #[test]
    fn an_unparsable_condition_reports_its_column() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net and )", "allow"))],
            &[("net", net_check())],
        );
        let error = error_of(&cfg);
        assert!(error.contains("filter.rule.r.when"), "{error}");
        assert!(error.contains("at column 9"), "{error}");
        assert!(error.contains("\"net and )\""), "{error}");
    }

    #[test]
    fn a_missing_or_bad_then_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", ""))],
            &[("net", net_check())],
        );
        assert!(error_of(&cfg).contains("sets no `then`"));

        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", "maybe"))],
            &[("net", net_check())],
        );
        let error = error_of(&cfg);
        assert!(error.contains("filter.rule.r.then = \"maybe\""), "{error}");
    }

    #[test]
    fn a_bad_mode_is_refused() {
        let mut rule = rule_of("net", "allow");
        rule.mode = "dry".to_string();
        let cfg = simple(&["r"], &[("r", rule)], &[("net", net_check())]);
        assert!(error_of(&cfg).contains("filter.rule.r.mode = \"dry\""));
    }

    #[test]
    fn a_bad_default_is_refused() {
        let cfg = FilterConfig {
            default: "maybe".to_string(),
            ..FilterConfig::default()
        };
        assert!(error_of(&cfg).contains("filter.default = \"maybe\""));
    }

    #[test]
    fn a_reserved_word_cannot_name_a_check() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", "allow"))],
            &[("or", net_check())],
        );
        assert!(error_of(&cfg).contains("cannot name a check"));
    }

    #[test]
    fn an_invalid_check_or_rule_name_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("net", "allow"))],
            &[("Net", net_check())],
        );
        assert!(error_of(&cfg).contains("filter.check.Net"));

        let cfg = simple(
            &["R"],
            &[("R", rule_of("net", "allow"))],
            &[("net", net_check())],
        );
        assert!(error_of(&cfg).contains("filter.rule.R"));
    }

    #[test]
    fn a_bad_trusted_proxy_is_refused() {
        let cfg = FilterConfig {
            trusted_proxies: vec!["not-a-cidr".to_string()],
            ..FilterConfig::default()
        };
        assert!(error_of(&cfg).contains("filter.trusted_proxies"));
    }

    #[test]
    fn an_ipam_check_without_a_backend_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("inv", "allow"))],
            &[("inv", check_of("ipam"))],
        );
        let error = error_of(&cfg);
        assert!(error.contains("ipam.backend is empty"), "{error}");
    }

    #[test]
    fn a_second_ipam_check_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("inv-a or inv-b", "allow"))],
            &[("inv-a", check_of("ipam")), ("inv-b", check_of("ipam"))],
        );
        let error = build(&cfg, &DnsConfig::default(), inventory(), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("second type = \"ipam\" check"), "{error}");
    }

    #[test]
    fn an_eab_check_without_eab_enabled_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("tenant", "allow"))],
            &[(
                "tenant",
                CheckConfig {
                    r#type: "eab".to_string(),
                    allow: vec!["tenant-a".to_string()],
                    ..CheckConfig::default()
                },
            )],
        );
        let error = build(&cfg, &DnsConfig::default(), no_ipam(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("eab.enabled is false"), "{error}");
        // ...and it builds once EAB is on.
        assert!(build_with(&cfg).is_ok());
    }

    /// The gate the whole plumbing turns on: nothing resolves a credential
    /// unless some check asks for one.
    #[test]
    fn only_a_policy_with_an_eab_check_needs_one_resolved() {
        let without = simple(
            &["mgmt"],
            &[("mgmt", rule_of("net", "allow"))],
            &[("net", net_check())],
        );
        assert!(!build_with(&without).unwrap().needs_eab());

        let with = simple(
            &["r"],
            &[("r", rule_of("tenant", "allow"))],
            &[(
                "tenant",
                CheckConfig {
                    r#type: "eab".to_string(),
                    allow: vec!["tenant-a".to_string()],
                    ..CheckConfig::default()
                },
            )],
        );
        assert!(build_with(&with).unwrap().needs_eab());
    }

    #[test]
    fn a_custom_check_with_no_script_is_refused() {
        let cfg = simple(
            &["r"],
            &[("r", rule_of("hook", "allow"))],
            &[("hook", check_of("custom"))],
        );
        assert!(error_of(&cfg).contains("filter.check.hook.script_path is empty"));
    }

    #[test]
    fn a_custom_check_builds_from_a_real_script() {
        let dir = TempDir::new("filter-build");
        let path = write_script(&dir, "hook.sh", "#!/bin/sh\nexit 0\n");
        let cfg = simple(
            &["r"],
            &[("r", rule_of("hook", "allow"))],
            &[(
                "hook",
                CheckConfig {
                    r#type: "custom".to_string(),
                    script_path: path.to_string_lossy().into_owned(),
                    ..CheckConfig::default()
                },
            )],
        );
        assert!(build_with(&cfg).is_ok());
    }

    // ---- the keys the redesign removed ------------------------------------

    /// Each of these would otherwise be an unknown key the `config` crate
    /// silently drops, leaving a server that looks configured and filters
    /// nothing.
    #[test]
    fn every_removed_key_is_refused_by_name() {
        /// A key's setter, the key's name, and a phrase its error must carry.
        type RemovedKey = (fn(&mut FilterConfig), &'static str, &'static str);

        let cases: &[RemovedKey] = &[
            (
                |cfg| cfg.enabled = vec!["allowed_ip".to_string()],
                "filter.enabled",
                "filter.rules",
            ),
            (
                |cfg| cfg.exempt_paths = vec!["/crl".to_string()],
                "filter.exempt_paths",
                "type = \"path\"",
            ),
            (
                |cfg| cfg.custom_enabled = vec!["hook".to_string()],
                "filter.custom_enabled",
                "ordinary check type",
            ),
        ];

        for (apply, key, hint) in cases {
            let mut cfg = FilterConfig::default();
            apply(&mut cfg);
            let error = error_of(&cfg);
            assert!(error.contains(key), "{key}: {error}");
            assert!(error.contains(hint), "{key}: {error}");
        }
    }
}
