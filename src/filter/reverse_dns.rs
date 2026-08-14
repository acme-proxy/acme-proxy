//! The `reverse_dns` filter: the client's address must have a usable PTR
//! record.
//!
//! Useful where clients are managed machines with maintained reverse zones and
//! the set of addresses is not fixed enough for a static allowlist.
//!
//! ## Why forward confirmation
//!
//! A PTR record is published by whoever controls the reverse zone for the
//! client's address — which, for an attacker, is often themselves. Left at
//! that, "has a PTR of `trusted.example.com`" proves nothing. Forward
//! confirmation (`FCrDNS`) closes the loop: the name the PTR gives must itself
//! resolve back to the address the request came from, which requires control of
//! the *forward* zone too. It is on by default and should stay on.
//!
//! ## Fail versus Undecided
//!
//! "No PTR record" is a decision about the client and refuses the request.
//! "The resolver timed out" is not — it is the server failing to reach a
//! decision, so it becomes [`Verdict::Undecided`] and surfaces as a 500 the
//! client can retry. Both refuse the request; only one blames the client, and
//! only one can be rescued by the other side of an `or`.
//!
//! ## Stages
//!
//! Naturally connection-only, though it is *capable* of deciding at the
//! identifier stage from the same address. It is not there by default because
//! a PTR plus forward-confirmation exchange at `newOrder` **and** again at
//! `finalize` triples the lookups for an answer that has not changed. An
//! operator who wants it in an identifier-stage rule says so with
//! `stages = ["identifiers"]`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use tracing::{debug, info};

use super::policy::{Check, StageSet, Verdict};
use super::{
    ConnectionContext, IdentifierContext, ListVerdict, canonical, check_lists, compile_matchers,
};
use crate::config::DnsConfig;
use crate::dns::{HickoryResolver, Resolver, resolver_addr};

/// Resolved `[filter.check.<name>]` settings for `type = "reverse_dns"`.
#[derive(Debug, Clone)]
pub struct Settings {
    pub require_forward_confirm: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_regex: Vec<String>,
    pub deny_regex: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            require_forward_confirm: true,
            allow: Vec::new(),
            deny: Vec::new(),
            allow_regex: Vec::new(),
            deny_regex: Vec::new(),
            timeout_ms: 2000,
        }
    }
}

/// Requires the client's address to have a PTR record, optionally
/// forward-confirmed and optionally matching a hostname pattern.
pub struct ClientHasValidReverseDns {
    resolver: Arc<dyn Resolver>,
    require_forward_confirm: bool,
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    timeout: Duration,
}

impl std::fmt::Debug for ClientHasValidReverseDns {
    /// `dyn Resolver` is not `Debug`; the policy is the interesting part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientHasValidReverseDns")
            .field("require_forward_confirm", &self.require_forward_confirm)
            .field("allow", &self.allow)
            .field("deny", &self.deny)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ClientHasValidReverseDns {
    /// Compiles the hostname patterns and builds the resolver — `dns.resolver`
    /// if set, else the system configuration, the same choice
    /// `challenge::from_config` makes for `dns-01`, sharing the `dns` table
    /// rather than each subsystem picking its own resolver.
    ///
    /// The resolver is shared with the rest of the crate, so it reports failures
    /// without knowing who asked; naming the setting is this caller's job.
    pub fn from_settings(name: &str, settings: &Settings, dns: &DnsConfig) -> anyhow::Result<Self> {
        let resolver: Arc<dyn Resolver> = Arc::new(match resolver_addr(dns)? {
            Some(addr) => HickoryResolver::from_address(addr)
                .map_err(|error| anyhow::anyhow!("filter.check.{name}: {error}"))?,
            None => HickoryResolver::from_system()
                .map_err(|error| anyhow::anyhow!("filter.check.{name}: {error}"))?,
        });
        let check = Self::with_resolver(name, settings, resolver)?;
        info!(
            event = "filter_reverse_dns_loaded",
            outcome = "success",
            check = name,
            require_forward_confirm = settings.require_forward_confirm,
            timeout_ms = settings.timeout_ms,
        );
        Ok(check)
    }

    /// Same, against a caller-supplied resolver. Used by tests.
    pub fn with_resolver(
        name: &str,
        settings: &Settings,
        resolver: Arc<dyn Resolver>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            resolver,
            require_forward_confirm: settings.require_forward_confirm,
            allow: compile_matchers(&settings.allow, &settings.allow_regex, name, "allow")?,
            deny: compile_matchers(&settings.deny, &settings.deny_regex, name, "deny")?,
            timeout: Duration::from_millis(settings.timeout_ms),
        })
    }

    /// Resolves and vets the client's hostname, inside the configured budget.
    async fn resolve_hostname(&self, client_ip: IpAddr) -> Result<String, Verdict> {
        let names = self
            .resolver
            .reverse(client_ip)
            .await
            .map_err(|error| Verdict::Undecided(format!("PTR lookup failed: {error}")))?;

        if names.is_empty() {
            return Err(Verdict::Fail(format!("no PTR record for {client_ip}")));
        }

        // `deny` is checked across *all* candidates before any is accepted.
        // Applying it per-candidate inside the loop below would make it
        // bypassable: a host publishing both `bad.example.com` and
        // `ok.example.com` would pass on the second name while the first — the
        // one an operator explicitly refused — still describes the same host.
        // Everywhere else in this subsystem a deny match refuses outright, and
        // it does here too.
        //
        // Only the deny half of `check_lists` applies at this level: `allow` is
        // per-candidate (one acceptable name is enough), so it is passed empty
        // here and applied in `vet`.
        if let Some(denied) = names.iter().find(|name| {
            check_lists(&[], &self.deny, |pattern: &Regex| pattern.is_match(name))
                == ListVerdict::Denied
        }) {
            return Err(Verdict::Fail(format!("hostname {denied} is denied")));
        }

        // A single address may publish several PTR names; one acceptable name
        // is enough. A failure to confirm is not fatal to the whole check
        // until every candidate has been tried.
        let mut last_refusal = None;
        for name in &names {
            match self.vet(client_ip, name).await {
                Ok(()) => return Ok(name.clone()),
                Err(refusal) => {
                    debug!(event = "filter_reverse_dns_candidate_refused", outcome = "failure", name, reason = ?refusal);
                    last_refusal = Some(refusal);
                }
            }
        }

        Err(last_refusal
            .unwrap_or_else(|| Verdict::Fail(format!("no acceptable PTR name for {client_ip}"))))
    }

    /// Applies the allow list to one candidate name and forward-confirms it.
    /// `deny` is handled by the caller, across every candidate at once.
    async fn vet(&self, client_ip: IpAddr, name: &str) -> Result<(), Verdict> {
        // `deny` was already applied across every candidate by the caller.
        if check_lists(&self.allow, &[], |pattern: &Regex| pattern.is_match(name))
            == ListVerdict::NotAllowed
        {
            return Err(Verdict::Fail(format!("hostname {name} is not allowed")));
        }

        if self.require_forward_confirm {
            let addresses =
                self.resolver.forward(name).await.map_err(|error| {
                    Verdict::Undecided(format!("forward lookup failed: {error}"))
                })?;

            if !addresses.iter().any(|addr| canonical(*addr) == client_ip) {
                return Err(Verdict::Fail(format!(
                    "hostname {name} does not resolve back to {client_ip}"
                )));
            }
        }

        Ok(())
    }

    /// The whole decision, shared by both hooks because it reads only the
    /// address.
    async fn decide(&self, client_ip: Option<IpAddr>) -> Verdict {
        // Fail closed, as the IP allowlist does. Canonicalized so the forward
        // confirmation below compares like with like.
        let client_ip = match super::require_client_ip(client_ip) {
            Ok(client_ip) => client_ip,
            Err(verdict) => return verdict,
        };

        // One budget for the whole PTR + confirmation exchange, so a wedged
        // resolver cannot pin a request open.
        match tokio::time::timeout(self.timeout, self.resolve_hostname(client_ip)).await {
            Ok(Ok(hostname)) => {
                debug!(event = "filter_reverse_dns_accepted", outcome = "success", client_ip = %client_ip, hostname);
                Verdict::Pass
            }
            Ok(Err(verdict)) => verdict,
            Err(_) => Verdict::Undecided(format!(
                "reverse DNS for {client_ip} timed out after {}ms",
                self.timeout.as_millis()
            )),
        }
    }
}

#[async_trait]
impl Check for ClientHasValidReverseDns {
    fn kind(&self) -> &'static str {
        "reverse_dns"
    }

    /// Connection-only by default; `stages = ["identifiers"]` moves it, which
    /// is why the identifier hook below is implemented rather than left to the
    /// trait's default.
    fn stages(&self) -> StageSet {
        StageSet::connection_only()
    }

    async fn check_connection(&self, context: &ConnectionContext<'_>) -> Verdict {
        self.decide(context.client_ip).await
    }

    async fn check_identifiers(&self, context: &IdentifierContext<'_>) -> Verdict {
        self.decide(context.client_ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use std::collections::HashMap;

    /// A resolver answering from canned maps, never touching the network.
    #[derive(Default)]
    struct StubResolver {
        ptr: HashMap<IpAddr, Vec<String>>,
        forward: HashMap<String, Vec<IpAddr>>,
        ptr_error: Option<String>,
        forward_error: Option<String>,
        hang: bool,
    }

    // `txt` is on the shared `Resolver` trait for the `dns-01` challenge; this
    // filter never calls it.

    impl StubResolver {
        fn with_ptr(mut self, ip: &str, names: &[&str]) -> Self {
            self.ptr.insert(
                ip.parse().unwrap(),
                names.iter().map(std::string::ToString::to_string).collect(),
            );
            self
        }

        fn with_forward(mut self, name: &str, ips: &[&str]) -> Self {
            self.forward.insert(
                name.to_string(),
                ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            );
            self
        }
    }

    #[async_trait]
    impl Resolver for StubResolver {
        async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
            if self.hang {
                // Outlives any timeout the tests set.
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            if let Some(error) = &self.ptr_error {
                return Err(error.clone());
            }
            Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
        }

        async fn forward(&self, name: &str) -> Result<Vec<IpAddr>, String> {
            if let Some(error) = &self.forward_error {
                return Err(error.clone());
            }
            Ok(self.forward.get(name).cloned().unwrap_or_default())
        }

        async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
            unreachable!("the reverse_dns filter never looks up TXT records")
        }
    }

    fn filter(cfg: &Settings, resolver: StubResolver) -> ClientHasValidReverseDns {
        ClientHasValidReverseDns::with_resolver("ptr", cfg, Arc::new(resolver)).unwrap()
    }

    async fn check(filter: &ClientHasValidReverseDns, ip: &str) -> Verdict {
        filter
            .check_connection(&ConnectionContext {
                client_ip: Some(ip.parse().unwrap()),
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
    }

    fn assert_denied(verdict: Verdict, needle: &str) {
        match verdict {
            Verdict::Fail(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// An unreachable resolver is an *unknown*, never a refusal — that is what
    /// lets the other side of an `or` rescue it, and what keeps a resolver
    /// outage a retryable 500 rather than a permanent-looking 403.
    fn assert_internal(verdict: Verdict, needle: &str) {
        match verdict {
            Verdict::Undecided(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Undecided, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepts_a_forward_confirmed_client() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["host.example.com"])
            .with_forward("host.example.com", &["203.0.113.9"]);
        let filter = filter(&Settings::default(), resolver);
        assert_eq!(check(&filter, "203.0.113.9").await, Verdict::Pass);
    }

    #[tokio::test]
    async fn denies_a_client_without_a_ptr_record() {
        let filter = filter(&Settings::default(), StubResolver::default());
        assert_denied(check(&filter, "203.0.113.9").await, "no PTR");
    }

    #[tokio::test]
    async fn denies_when_the_forward_record_does_not_come_back() {
        // The spoofing case: an attacker controls the reverse zone only.
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["trusted.example.com"])
            .with_forward("trusted.example.com", &["198.51.100.4"]);
        let filter = filter(&Settings::default(), resolver);
        assert_denied(check(&filter, "203.0.113.9").await, "does not resolve back");
    }

    #[tokio::test]
    async fn accepts_an_unconfirmed_ptr_when_confirmation_is_off() {
        let resolver = StubResolver::default().with_ptr("203.0.113.9", &["host.example.com"]);
        let cfg = Settings {
            require_forward_confirm: false,
            ..Settings::default()
        };
        assert_eq!(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            Verdict::Pass
        );
    }

    #[tokio::test]
    async fn applies_the_hostname_allow_list() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["host.other.net"])
            .with_forward("host.other.net", &["203.0.113.9"]);
        let cfg = Settings {
            allow_regex: vec![r".*\.corp\.example\.com".to_string()],
            ..Settings::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            "is not allowed",
        );
    }

    #[tokio::test]
    async fn applies_the_hostname_deny_list() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["bad.example.com"])
            .with_forward("bad.example.com", &["203.0.113.9"]);
        let cfg = Settings {
            deny_regex: vec![r"bad\..*".to_string()],
            ..Settings::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            "is denied",
        );
    }

    /// A denied name refuses the client even when another PTR record for the
    /// same address would pass.
    ///
    /// `deny` used to be applied per-candidate inside the accept loop, so a host
    /// publishing both a denied name and a clean one passed on the second — even
    /// though both describe the same host, which is the entire point of naming
    /// one in a deny list.
    #[tokio::test]
    async fn a_denied_name_cannot_be_masked_by_a_second_ptr_record() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["bad.example.com", "ok.example.com"])
            .with_forward("bad.example.com", &["203.0.113.9"])
            .with_forward("ok.example.com", &["203.0.113.9"]);
        let cfg = Settings {
            deny_regex: vec![r"bad\..*".to_string()],
            ..Settings::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            "bad.example.com",
        );
    }

    /// The same, with the denied name published second — order must not matter.
    #[tokio::test]
    async fn a_denied_name_refuses_whatever_order_the_records_arrive_in() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["ok.example.com", "bad.example.com"])
            .with_forward("bad.example.com", &["203.0.113.9"])
            .with_forward("ok.example.com", &["203.0.113.9"]);
        let cfg = Settings {
            deny_regex: vec![r"bad\..*".to_string()],
            ..Settings::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            "bad.example.com",
        );
    }

    #[tokio::test]
    async fn one_acceptable_name_among_several_is_enough() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["stale.example.com", "host.example.com"])
            .with_forward("stale.example.com", &["198.51.100.4"])
            .with_forward("host.example.com", &["203.0.113.9"]);
        let filter = filter(&Settings::default(), resolver);
        assert_eq!(check(&filter, "203.0.113.9").await, Verdict::Pass);
    }

    #[tokio::test]
    async fn a_ptr_lookup_failure_is_internal_not_a_denial() {
        let resolver = StubResolver {
            ptr_error: Some("SERVFAIL".to_string()),
            ..StubResolver::default()
        };
        let filter = filter(&Settings::default(), resolver);
        assert_internal(check(&filter, "203.0.113.9").await, "SERVFAIL");
    }

    #[tokio::test]
    async fn a_forward_lookup_failure_is_internal() {
        let resolver = StubResolver {
            forward_error: Some("SERVFAIL".to_string()),
            ..StubResolver::default().with_ptr("203.0.113.9", &["host.example.com"])
        };
        let filter = filter(&Settings::default(), resolver);
        assert_internal(check(&filter, "203.0.113.9").await, "forward lookup failed");
    }

    #[tokio::test]
    async fn a_wedged_resolver_times_out_rather_than_hanging() {
        let resolver = StubResolver {
            hang: true,
            ..StubResolver::default()
        };
        let cfg = Settings {
            timeout_ms: 10,
            ..Settings::default()
        };
        assert_internal(
            check(&filter(&cfg, resolver), "203.0.113.9").await,
            "timed out",
        );
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let filter = filter(&Settings::default(), StubResolver::default());
        let error = filter
            .check_connection(&ConnectionContext {
                client_ip: None,
                method: &Method::POST,
                path: "/newOrder",
            })
            .await;
        assert_denied(error, "unavailable");
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_is_canonicalized_before_lookup() {
        let resolver = StubResolver::default()
            .with_ptr("192.168.1.5", &["host.example.com"])
            .with_forward("host.example.com", &["192.168.1.5"]);
        let filter = filter(&Settings::default(), resolver);
        assert_eq!(check(&filter, "::ffff:192.168.1.5").await, Verdict::Pass);
    }

    #[test]
    fn a_bad_hostname_pattern_is_a_startup_error() {
        let cfg = Settings {
            deny_regex: vec!["[unclosed".to_string()],
            ..Settings::default()
        };
        let error =
            ClientHasValidReverseDns::with_resolver("ptr", &cfg, Arc::new(StubResolver::default()))
                .unwrap_err()
                .to_string();
        assert!(error.contains("filter.check.ptr.deny_regex"), "{error}");
    }

    #[test]
    fn reports_its_type_and_stages() {
        let check = filter(&Settings::default(), StubResolver::default());
        assert_eq!(check.kind(), "reverse_dns");
        // Capable of both, but connection-only unless an operator says
        // otherwise — a PTR exchange at newOrder *and* finalize triples the
        // lookups for an answer that has not changed.
        assert_eq!(check.stages(), StageSet::connection_only());
    }

    /// `dyn Resolver` is not `Debug`, so the filter renders the policy it was
    /// configured with instead.
    #[test]
    fn the_filter_debug_shows_its_policy() {
        let filter = ClientHasValidReverseDns::with_resolver(
            "ptr",
            &Settings {
                require_forward_confirm: true,
                allow_regex: vec![r"host\.example\.com".to_string()],
                timeout_ms: 1234,
                ..Settings::default()
            },
            Arc::new(StubResolver::default()),
        )
        .unwrap();

        let rendered = format!("{filter:?}");
        assert!(rendered.contains("ClientHasValidReverseDns"), "{rendered}");
        assert!(rendered.contains("true"), "{rendered}");
        assert!(rendered.contains("1.234s"), "{rendered}");
    }
}
