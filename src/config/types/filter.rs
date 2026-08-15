//! `[filter]` — named checks, the rules over them, and how a client address is
//! resolved.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names the
//! submodule.
//!
//! This is the *TOML shape* and nothing else. Each check type's resolved
//! settings live beside the check that reads them (`filter::ip_allow::Settings`
//! and friends), built from a [`CheckConfig`] by
//! [`filter::build`](crate::filter::build) — which is also the only place that
//! knows which of the flattened keys below belong to which `type`.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::empty_string_is_no_values;

/// Request-filtering configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    /// Which `[filter.rule.<name>]` entries to evaluate, and in what order.
    ///
    /// Empty is the default and means no filtering at all. An array rather
    /// than a map because order *is* the policy: first match wins, so a
    /// profile overriding this means to replace the sequence, which is exactly
    /// what wholesale array inheritance does.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub rules: Vec<String>,
    /// What happens at a stage where a rule was applicable and none matched:
    /// `allow` or `deny`.
    ///
    /// Never consulted at a stage no rule applies to — otherwise a policy made
    /// entirely of identifier-stage rules would refuse every connection before
    /// a name had been mentioned.
    pub default: String,
    /// CIDRs of reverse proxies whose forwarded-for header is believed.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub trusted_proxies: Vec<String>,
    /// Header carrying the original client address, read only from a trusted
    /// proxy.
    pub forwarded_header: String,
    /// The named rules, selected and ordered by `rules`.
    ///
    /// A map rather than an array of tables so a profile can override one
    /// field of one rule — `[profiles.le.filter.rule.inventory] mode = "warn"`
    /// — and inherit the rest. An array would have to be restated whole.
    pub rule: BTreeMap<String, RuleConfig>,
    /// The named checks a rule's condition refers to.
    ///
    /// A check defined but named by no selected rule is never constructed, so
    /// it costs nothing: that is what lets a global section carry a library of
    /// checks and each profile pick a subset.
    pub check: BTreeMap<String, CheckConfig>,

    /// Removed when `[filter]` became a policy engine. Kept as a field for one
    /// reason: an unknown key is silently ignored by the `config` crate, so
    /// without somewhere for it to land, a configuration written against the
    /// old shape would come up looking configured and filtering nothing.
    /// [`filter::build`](crate::filter::build) refuses each of these by name.
    ///
    /// Nothing reads these — a key has to parse before it can be refused *by
    /// name*, and that is the whole job. They are a startup diagnostic rather
    /// than a compatibility path, and go away at 1.0.0 along with the refusals.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub enabled: Vec<String>,
    /// Removed: write a `type = "path"` check and a rule instead. See `enabled`.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub exempt_paths: Vec<String>,
    /// Removed: `custom` is an ordinary check type now, and `rules` already
    /// says which run and in what order. See `enabled`.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub custom_enabled: Vec<String>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            // A loud lockout is self-correcting; a silently open CA is not.
            // Harmless when nothing is configured, because a stage with no
            // applicable rules allows without consulting this at all.
            default: "deny".to_string(),
            trusted_proxies: Vec::new(),
            forwarded_header: "x-forwarded-for".to_string(),
            rule: BTreeMap::new(),
            check: BTreeMap::new(),
            enabled: Vec::new(),
            exempt_paths: Vec::new(),
            custom_enabled: Vec::new(),
        }
    }
}

/// One `[filter.rule.<name>]` entry.
///
/// Deliberately carries **no** list-valued field, so this table needs no
/// runtime environment-variable scan the way `[filter.check.<name>]` does.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RuleConfig {
    /// A boolean expression over check names — see
    /// [`filter::expr`](crate::filter::expr).
    pub when: String,
    /// `allow` or `deny`. No default: a rule that does not say what a match
    /// means is a rule whose author has not finished writing it.
    pub then: String,
    /// The operator's own words for the refusal, shown to the client verbatim
    /// in place of whichever check happened to fail.
    pub message: String,
    /// `enforce` (the default) or `warn`. A `warn` rule that matches is logged
    /// as `filter_rule_warned` and evaluation continues, so a tightened policy
    /// can be watched in production before it bites.
    pub mode: String,
}

/// One `[filter.check.<name>]` entry: a `type` plus that type's own keys.
///
/// The keys are **flattened** — `allow`, not `allowed_ip.allow` — so every
/// check reads the same way whatever its type. The cost is that a key
/// belonging to another type would otherwise be silently ignored, which is why
/// [`filter::build`](crate::filter::build) holds a per-type allowlist and
/// refuses a misplaced key by name.
///
/// `#[serde(tag = "type")]` on an enum would give per-variant fields for free,
/// but serde's `deny_unknown_fields` does not apply to internally tagged
/// variants — they deserialize through a buffered content map — so the
/// misplaced key would come back silently ignored, which is the failure this
/// codebase refuses everywhere else.
///
/// Every list here defaults to empty, and because an unset environment
/// variable arrives as `[]` rather than as absent (see
/// [`empty_string_is_no_values`]), **empty always means "the type's natural
/// default"** and never "none". `stages = []` is "infer from the type";
/// `allowed_types = []` is `["dns", "cn"]`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CheckConfig {
    /// Which check type this instance is.
    pub r#type: String,
    /// Override the stages the type would naturally decide at: `connection`,
    /// `identifiers`, or both. Empty infers.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub stages: Vec<String>,
    /// Permitted entries. CIDRs for `allowed_ip`; globs everywhere else.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allow: Vec<String>,
    /// Refused entries, checked first and winning over `allow`.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub deny: Vec<String>,
    /// The same as `allow`, written as auto-anchored regexes. Unioned with it.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allow_regex: Vec<String>,
    /// The same as `deny`, written as auto-anchored regexes. Unioned with it.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub deny_regex: Vec<String>,
    /// `identifiers`: which identifier types may appear at all.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub allowed_types: Vec<String>,
    /// `eab`: credential kids matched exactly, beside the label globs above.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub kids: Vec<String>,
    /// `custom`: arguments passed to the script.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub args: Vec<String>,
    /// `identifiers`: permit `*.example.com`. Defaults to `false`.
    pub allow_wildcards: Option<bool>,
    /// `eab`: also require the credential to still be active, so revoking one
    /// reaches accounts already registered under it. Defaults to `false`.
    pub require_active: Option<bool>,
    /// `reverse_dns`: re-resolve the PTR name and require the client's own
    /// address back. Defaults to `true`.
    pub require_forward_confirm: Option<bool>,
    /// `reverse_dns` (2000) and `custom` (5000): the budget for one attempt.
    pub timeout_ms: Option<u64>,
    /// `custom`: path to the executable.
    pub script_path: String,
    /// `custom`: pipe the JSON context to the script's stdin. Defaults to
    /// `true`.
    pub pass_stdin: Option<bool>,
}
