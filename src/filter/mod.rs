//! Request filtering: named checks, boolean rules over them, and the machinery
//! that turns a request into one answer.
//!
//! Filters answer a different question from [`challenge`](crate::challenge):
//! *who* may ask, rather than whether they control the name. Both matter, and
//! when `challenge.bypass` is on, filtering is the **only** thing deciding who
//! may obtain a certificate, because a triggered challenge is then accepted
//! with no network check at all.
//!
//! ## The shape
//!
//! A [`Check`] is one named question — "is this address in the management
//! network?", "does the inventory say this address owns this name?" — declared
//! as `[filter.check.<name>]` with a `type`. A rule is a boolean expression
//! over check names plus what a match means, declared as
//! `[filter.rule.<name>]` and selected and ordered by `filter.rules`.
//! [`FilterPolicy`] holds both and answers one request.
//!
//! ```toml
//! [filter]
//! rules = ["mgmt-bypass", "inventory-owned"]
//!
//! [filter.check.mgmt-net]
//! type  = "allowed_ip"
//! allow = ["10.0.0.0/8"]
//!
//! [filter.check.inventory]
//! type = "ipam"
//!
//! [filter.rule.mgmt-bypass]
//! when = "mgmt-net"
//! then = "allow"
//!
//! [filter.rule.inventory-owned]
//! when = "inventory or mgmt-net"
//! then = "allow"
//! ```
//!
//! Everything is a named check: `custom` is `type = "custom"` like any other,
//! with no separate selection list of its own, and two instances of one type
//! are ordinary rather than impossible.
//!
//! ## Two hook points
//!
//! Some checks decide from the connection alone (is this IP allowed? does it
//! have a valid PTR record?); others need the names being requested, which only
//! the handlers know. Rather than two traits, [`Check`] has two methods, both
//! defaulting to "pass":
//!
//! - [`check_connection`](Check::check_connection) runs in
//!   [`add_filter_middleware`](crate::middlewares::filter::add_filter_middleware)
//!   for every request.
//! - [`check_identifiers`](Check::check_identifiers) runs at `newOrder` (the
//!   order's identifiers) and again at `finalize` (the CSR's subject
//!   alternative names and common name).
//!
//! Which rules run at which hook, and why the answer is an intersection rather
//! than a union, is [`policy`]'s subject.
//!
//! ## Startup validation
//!
//! CIDRs, regexes and conditions are parsed once in [`from_config`], which
//! returns an `anyhow::Error` the binary treats as fatal. A typo in a netmask
//! is a configuration bug that should stop the server, not silently deny (or
//! admit) traffic at runtime.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::Method;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};

use crate::config::FilterConfig;
use crate::sqlite::order::Identifier;

pub mod build;
pub mod client_ip;
pub mod custom;
pub mod eab;
pub mod explain;
pub mod expr;
pub mod identifiers;
pub mod ip_allow;
pub mod ipam;
pub mod path;
pub mod policy;
pub mod reverse_dns;

pub use client_ip::{ClientIp, ProxyPolicy};
pub use eab::EabIdentity;
pub use policy::{
    Check, CheckSummary, Effect, FilterPolicy, Mode, Outcome, Rule, RuleSummary, Stage, StageSet,
    Verdict,
};

/// Identifier types that are subject metadata rather than a name the
/// certificate is issued *for*.
///
/// A common name is legacy subject metadata — RFC 6125 deprecated relying on
/// it, and CSR generators routinely put a human label there (`rcgen`'s own
/// default is the string `rcgen self signed cert`). Checks that decide what a
/// certificate may be issued *for* therefore leave these alone: `identifiers`
/// exempts them from its `allow` list, and `ipam` never asks an inventory to
/// confirm one. Refusals still reach them — see
/// [`identifiers`](self::identifiers) for why the two directions differ.
pub(crate) const SUBJECT_ONLY_TYPES: &[&str] = &["cn"];

/// What a [`Check`] knows about a request before it is dispatched.
#[derive(Debug)]
pub struct ConnectionContext<'a> {
    /// The client address, per [`ProxyPolicy::resolve`]. `None` when the peer
    /// address is unavailable — checks that need it must fail closed.
    pub client_ip: Option<IpAddr>,
    pub method: &'a Method,
    pub path: &'a str,
}

/// Where in the flow a set of identifiers is being checked.
///
/// The same names are validated twice — once as the client's stated intent,
/// once as what its CSR actually requests — and a check may want to treat the
/// two differently. Both are the [`Stage::Identifiers`] stage as far as rule
/// selection is concerned; this is the finer grain underneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierStage {
    /// The `identifiers` array of a `newOrder` payload.
    NewOrder,
    /// The subject alternative names and common name of a finalize CSR.
    Csr,
}

impl IdentifierStage {
    /// Short label for logs and problem details.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewOrder => "newOrder",
            Self::Csr => "CSR",
        }
    }
}

/// What a [`Check`] knows about the names a client wants certified.
///
/// Carries the account as well as the client address so a policy can bind
/// names to either — for example "this network may only request names under
/// its own subdomain".
#[derive(Debug)]
pub struct IdentifierContext<'a> {
    /// The client address, as resolved by the middleware.
    pub client_ip: Option<IpAddr>,
    /// Id of the account making the request (already authenticated by the JWS
    /// extractor and checked to own the order).
    pub account_id: &'a str,
    pub stage: IdentifierStage,
    /// The requested names. At [`IdentifierStage::Csr`] these are projected
    /// from the CSR, so `typ` may be `ip`, `email`, `uri`, `other` or `cn` as
    /// well as `dns`.
    pub identifiers: &'a [Identifier],
    /// The external account binding this account registered under.
    ///
    /// Resolved by the caller **only when the policy contains an `eab` check**
    /// ([`FilterPolicy::needs_eab`]), so a policy without one costs no lookup;
    /// `None` therefore means either "no such check is configured" or "this
    /// account used no EAB", and only [`eab::EabList`] is ever in a position
    /// to tell the two apart — it is the sole reader.
    pub eab: Option<EabIdentity>,
}

/// The client address, canonicalized, or the refusal its absence implies.
///
/// An address the server cannot see is not "absent from the deny list,
/// therefore fine" — every check that reaches for one must fail closed. Having
/// a single helper say so means a check added later gets that behaviour by
/// asking for the address at all.
///
/// Deliberately [`Verdict::Fail`] and not [`Verdict::Undecided`]: the server
/// saw a request it cannot attribute, which is a decision about the client
/// rather than a failure to reach some authority. `Undecided` here would turn
/// every such refusal into a 500.
pub(crate) fn require_client_ip(client_ip: Option<IpAddr>) -> Result<IpAddr, Verdict> {
    client_ip
        .map(canonical)
        .ok_or_else(|| Verdict::Fail("client address unavailable".to_string()))
}

/// Builds the configured policy. Called once at startup, so it may fail fast
/// (the caller exits on error).
///
/// `dns` is [`crate::config::Config::dns`], not a field of `cfg`: the one check
/// that resolves anything builds its own **cached** resolver from it, because a
/// PTR lookup for an address that keeps connecting is exactly what a cache is
/// for, while the shared resolver is deliberately uncached so a `dns-01` record
/// published moments before a trigger is not defeated by a cached negative.
///
/// `eab_enabled` is the profile's `eab.enabled`: an `eab` check under an endpoint
/// that does not require EAB could only ever refuse, which is a startup error
/// rather than a policy.
///
/// `ipam` is the profile's already-built inventory — `None` when `ipam.backend`
/// is unset, which is a startup error if any selected rule names an `ipam`
/// check. It is built by [`Profile::build_all`](crate::Profile::build_all)
/// rather than here because it is its own configuration section with its own
/// selector, and this policy is one of its consumers rather than its owner.
pub fn from_config(
    cfg: &FilterConfig,
    dns: &crate::config::DnsConfig,
    ipam: Option<Arc<crate::ipam::IpamRegistry>>,
    eab_enabled: bool,
) -> anyhow::Result<Arc<FilterPolicy>> {
    build::build(cfg, dns, ipam, eab_enabled).map(Arc::new)
}

/// Parses one allow-list entry as a network.
///
/// Accepts both CIDR notation (`192.168.1.0/24`, `fd00::/8`) and a bare address
/// (`203.0.113.7`), the latter becoming a host route — writing a `/32` for a
/// single machine is noise an operator should not have to remember.
pub(crate) fn parse_net(entry: &str) -> anyhow::Result<IpNet> {
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    match entry.parse::<IpAddr>() {
        Ok(addr) => Ok(IpNet::from(addr)),
        Err(_) => anyhow::bail!("invalid network or address: {entry}"),
    }
}

/// Parses a list of network entries, naming the setting in any error.
pub(crate) fn parse_nets(entries: &[String], setting: &str) -> anyhow::Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| parse_net(entry).map_err(|error| anyhow::anyhow!("{setting}: {error}")))
        .collect()
}

/// Normalizes an address for comparison.
///
/// The default bind is `[::]:3000`, so an IPv4 client arrives over the
/// dual-stack socket as `::ffff:192.168.1.5` and would never match a
/// `192.168.1.0/24` rule. Canonicalizing first makes the operator's v4 rules
/// mean what they look like they mean.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Whether any network contains `ip`, comparing canonical forms.
pub(crate) fn nets_contain(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical(ip);
    nets.iter().any(|net| net.contains(&ip))
}

/// The outcome of an allow/deny pair for one value.
///
/// Distinguishing the two refusals lets each filter word its own message while
/// the decision itself stays in one place.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListVerdict {
    /// Nothing objected: either `allow` was empty, or the value matched it.
    Permitted,
    /// The value matched `deny`.
    Denied,
    /// `allow` was non-empty and the value was not in it.
    NotAllowed,
}

/// Applies an allow/deny pair to one value, given a membership test.
///
/// All three filters — the IP allowlist over `IpNet`, and the identifier and
/// reverse-DNS lists over `Regex` — share one rule, stated once here:
///
/// * **`deny` is checked first and wins.** Plain membership, not
///   longest-prefix-match: a `/32` in `allow` does not beat a `/8` in `deny`.
/// * **An empty `allow` imposes no constraint**, so a deny-only configuration
///   is a working blocklist rather than a list that refuses everything.
///
/// The rule used to be written out three times, with the invariant recorded
/// only in three doc comments; the one thing keeping them in step is that they
/// now call this.
pub(crate) fn check_lists<T>(allow: &[T], deny: &[T], matches: impl Fn(&T) -> bool) -> ListVerdict {
    if deny.iter().any(&matches) {
        return ListVerdict::Denied;
    }
    if !allow.is_empty() && !allow.iter().any(&matches) {
        return ListVerdict::NotAllowed;
    }
    ListVerdict::Permitted
}

/// Compiles allow/deny patterns, anchored and case-insensitive.
///
/// **Anchoring is not optional.** The `regex` crate searches rather than
/// matches, so an allow entry of `example\.com` would also accept
/// `example.com.evil.net` — precisely the bypass an allowlist exists to
/// prevent. Every pattern becomes `^(?:…)$`; a caller wanting a suffix match
/// writes `.*\.example\.com`.
pub(crate) fn compile_anchored(patterns: &[String], setting: &str) -> anyhow::Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            RegexBuilder::new(&format!("^(?:{pattern})$"))
                .case_insensitive(true)
                .build()
                .map_err(|error| anyhow::anyhow!("{setting}: invalid regex {pattern:?}: {error}"))
        })
        .collect()
}

/// The identifier types a new `identifiers` check permits when it says nothing.
///
/// A function rather than a `const` because an unset list arrives as `[]` from
/// the environment and the resolver has to substitute this — see
/// [`CheckConfig`](crate::config::CheckConfig).
pub(crate) fn default_identifier_types() -> Vec<String> {
    vec!["dns".to_string(), "cn".to_string()]
}

/// Turns one glob into a regex source, escaping everything that is not `*`.
///
/// `*` becomes `[^.]+` — one label, the wildcard semantics an operator already
/// knows from certificates, so `*.example.com` matches `a.example.com` and not
/// `a.b.example.com`. Every other character is escaped, so a name that happens
/// to contain regex metacharacters cannot smuggle a pattern in.
///
/// A glob *is* a regex once it reaches [`compile_anchored`], which is the whole
/// design: no second matching engine, and the anchoring guarantee is inherited
/// rather than re-derived.
pub(crate) fn glob_to_pattern(glob: &str) -> String {
    glob.split('*')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join("[^.]+")
}

/// Compiles one side of a check's matching policy: globs and regexes, unioned.
///
/// `side` is `allow` or `deny`; the regex list is the same key suffixed
/// `_regex`, and each half names its own key in an error so an operator is told
/// which list to look at.
pub(crate) fn compile_matchers(
    globs: &[String],
    regexes: &[String],
    check: &str,
    side: &str,
) -> anyhow::Result<Vec<Regex>> {
    let from_globs: Vec<String> = globs.iter().map(|glob| glob_to_pattern(glob)).collect();
    let mut compiled = compile_anchored(&from_globs, &format!("filter.check.{check}.{side}"))?;
    compiled.extend(compile_anchored(
        regexes,
        &format!("filter.check.{check}.{side}_regex"),
    )?);
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_net_accepts_cidr_and_bare_addresses() {
        assert!(parse_net("192.168.1.0/24").is_ok());
        assert!(parse_net("fd00::/8").is_ok());

        // A bare address becomes a host route, so an operator does not have to
        // remember to write `/32`.
        let host = parse_net("203.0.113.7").unwrap();
        assert_eq!(host.prefix_len(), 32);
        assert!(host.contains(&"203.0.113.7".parse::<IpAddr>().unwrap()));
        assert!(!host.contains(&"203.0.113.8".parse::<IpAddr>().unwrap()));

        let host6 = parse_net("2001:db8::1").unwrap();
        assert_eq!(host6.prefix_len(), 128);

        assert!(parse_net("not-a-network").is_err());
        assert!(parse_net("192.168.1.0/99").is_err());
    }

    #[test]
    fn nets_contain_canonicalizes_ipv4_mapped_addresses() {
        let nets = parse_nets(&["192.168.1.0/24".to_string()], "test").unwrap();
        assert!(nets_contain(&nets, "192.168.1.5".parse().unwrap()));
        assert!(nets_contain(&nets, "::ffff:192.168.1.5".parse().unwrap()));
        assert!(!nets_contain(&nets, "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_nets_names_the_offending_setting() {
        let error = parse_nets(&["garbage".to_string()], "filter.check.net.allow")
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.net.allow"), "{error}");
        assert!(error.contains("garbage"), "{error}");
    }

    #[test]
    fn canonical_unmaps_ipv4_in_ipv6() {
        assert_eq!(
            canonical("::ffff:10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn compile_anchored_prevents_suffix_bypass() {
        let patterns =
            compile_anchored(&[r"example\.com".to_string()], "filter.check.x.allow").unwrap();
        assert!(patterns[0].is_match("example.com"));
        // Unanchored, `regex` would have found this.
        assert!(!patterns[0].is_match("example.com.evil.net"));
        assert!(!patterns[0].is_match("notexample.com"));
    }

    #[test]
    fn compile_anchored_is_case_insensitive() {
        let patterns = compile_anchored(&[r"host\.example\.com".to_string()], "test").unwrap();
        assert!(patterns[0].is_match("HOST.Example.COM"));
    }

    #[test]
    fn compile_anchored_reports_a_bad_pattern() {
        let error = compile_anchored(&["[unclosed".to_string()], "filter.check.x.deny")
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.x.deny"), "{error}");
        assert!(error.contains("[unclosed"), "{error}");
    }

    /// The glob vocabulary, table-driven. `*` is one label and nothing else is
    /// a metacharacter — those two rules are the whole surface, and both have
    /// bypasses behind them if they slip.
    #[test]
    fn a_glob_star_is_one_label_and_everything_else_is_literal() {
        let cases: &[(&str, &str, bool)] = &[
            ("*.example.com", "a.example.com", true),
            ("*.example.com", "A.Example.COM", true),
            ("*.example.com", "a.b.example.com", false),
            ("*.example.com", "example.com", false),
            ("*.example.com", "aexample.com", false),
            ("example.com", "example.com", true),
            // `.` must not behave as a regex wildcard.
            ("example.com", "exampleXcom", false),
            // Neither must anything else a hostname could carry.
            ("a+b.example.com", "a+b.example.com", true),
            ("a+b.example.com", "aab.example.com", false),
            // A literal `*` in the requested value is matched by `*`, which is
            // what lets `allow_wildcards` policies name the wildcard form.
            ("*.example.com", "*.example.com", true),
            ("host-*.example.com", "host-1.example.com", true),
            ("host-*.example.com", "host-1.2.example.com", false),
        ];

        for (glob, value, expected) in cases {
            let compiled =
                compile_anchored(&[glob_to_pattern(glob)], "test").expect("a glob always compiles");
            assert_eq!(
                compiled[0].is_match(value),
                *expected,
                "glob {glob:?} against {value:?}"
            );
        }
    }

    #[test]
    fn compile_matchers_unions_globs_and_regexes_and_names_each_key() {
        let compiled = compile_matchers(
            &["*.example.com".to_string()],
            &[r"host\d+\.internal".to_string()],
            "names",
            "allow",
        )
        .unwrap();
        assert_eq!(compiled.len(), 2);
        assert!(compiled[0].is_match("a.example.com"));
        assert!(compiled[1].is_match("host12.internal"));

        let error = compile_matchers(&[], &["[unclosed".to_string()], "names", "deny")
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.names.deny_regex"), "{error}");
    }

    #[test]
    fn identifier_stage_labels() {
        assert_eq!(IdentifierStage::NewOrder.as_str(), "newOrder");
        assert_eq!(IdentifierStage::Csr.as_str(), "CSR");
    }

    #[test]
    fn check_lists_implements_the_shared_allow_deny_rule() {
        fn matches(value: &'static str) -> impl Fn(&&str) -> bool {
            move |entry: &&str| *entry == value
        }

        // Empty allow imposes no constraint, which is what makes a deny-only
        // configuration a working blocklist.
        assert_eq!(
            check_lists::<&str>(&[], &[], matches("a")),
            ListVerdict::Permitted
        );
        assert_eq!(check_lists(&[], &["a"], matches("a")), ListVerdict::Denied);
        assert_eq!(
            check_lists(&["a"], &[], matches("a")),
            ListVerdict::Permitted
        );
        assert_eq!(
            check_lists(&["b"], &[], matches("a")),
            ListVerdict::NotAllowed
        );
        // Deny is checked first and wins even over an explicit allow.
        assert_eq!(
            check_lists(&["a"], &["a"], matches("a")),
            ListVerdict::Denied
        );
    }

    #[test]
    fn require_client_ip_fails_closed_and_canonicalizes() {
        assert_eq!(
            require_client_ip(Some("::ffff:10.0.0.1".parse().unwrap())).unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );

        // A refusal, not an unknown: see the doc comment.
        match require_client_ip(None) {
            Err(Verdict::Fail(detail)) => assert!(detail.contains("unavailable"), "{detail}"),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn the_default_identifier_types_are_dns_and_cn() {
        assert_eq!(default_identifier_types(), vec!["dns", "cn"]);
    }
}
