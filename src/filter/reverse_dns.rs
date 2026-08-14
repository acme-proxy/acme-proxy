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
//! ## Denied versus Internal
//!
//! "No PTR record" is a decision about the client and denies the request. "The
//! resolver timed out" is not — it is the server failing to reach a decision,
//! so it becomes [`FilterError::Internal`] and surfaces as a 500 the client can
//! retry. Both refuse the request; only one blames the client.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use tracing::{debug, info};

use super::{
    ConnectionContext, Filter, FilterError, ListVerdict, canonical, check_lists, compile_anchored,
};
use crate::config::{DnsConfig, ReverseDnsConfig};
use crate::dns::{HickoryResolver, Resolver, resolver_addr};

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
    pub fn from_config(cfg: &ReverseDnsConfig, dns: &DnsConfig) -> anyhow::Result<Self> {
        let resolver: Arc<dyn Resolver> = Arc::new(match resolver_addr(dns)? {
            Some(addr) => HickoryResolver::from_address(addr)
                .map_err(|error| anyhow::anyhow!("filter.reverse_dns: {error}"))?,
            None => HickoryResolver::from_system()
                .map_err(|error| anyhow::anyhow!("filter.reverse_dns: {error}"))?,
        });
        let filter = Self::with_resolver(cfg, resolver)?;
        info!(
            event = "filter_reverse_dns_loaded",
            outcome = "success",
            require_forward_confirm = cfg.require_forward_confirm,
            timeout_ms = cfg.timeout_ms,
        );
        Ok(filter)
    }

    /// Same, against a caller-supplied resolver. Used by tests.
    pub fn with_resolver(
        cfg: &ReverseDnsConfig,
        resolver: Arc<dyn Resolver>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            resolver,
            require_forward_confirm: cfg.require_forward_confirm,
            allow: compile_anchored(&cfg.allow, "filter.reverse_dns.allow")?,
            deny: compile_anchored(&cfg.deny, "filter.reverse_dns.deny")?,
            timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    /// Resolves and vets the client's hostname, inside the configured budget.
    async fn resolve_hostname(&self, client_ip: IpAddr) -> Result<String, FilterError> {
        let names = self
            .resolver
            .reverse(client_ip)
            .await
            .map_err(|error| FilterError::Internal(format!("PTR lookup failed: {error}")))?;

        if names.is_empty() {
            return Err(FilterError::Denied(format!(
                "no PTR record for {client_ip}"
            )));
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
            return Err(FilterError::Denied(format!("hostname {denied} is denied")));
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

        Err(last_refusal.unwrap_or_else(|| {
            FilterError::Denied(format!("no acceptable PTR name for {client_ip}"))
        }))
    }

    /// Applies the allow list to one candidate name and forward-confirms it.
    /// `deny` is handled by the caller, across every candidate at once.
    async fn vet(&self, client_ip: IpAddr, name: &str) -> Result<(), FilterError> {
        // `deny` was already applied across every candidate by the caller.
        if check_lists(&self.allow, &[], |pattern: &Regex| pattern.is_match(name))
            == ListVerdict::NotAllowed
        {
            return Err(FilterError::Denied(format!(
                "hostname {name} is not allowed"
            )));
        }

        if self.require_forward_confirm {
            let addresses = self.resolver.forward(name).await.map_err(|error| {
                FilterError::Internal(format!("forward lookup failed: {error}"))
            })?;

            if !addresses.iter().any(|addr| canonical(*addr) == client_ip) {
                return Err(FilterError::Denied(format!(
                    "hostname {name} does not resolve back to {client_ip}"
                )));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Filter for ClientHasValidReverseDns {
    fn name(&self) -> &'static str {
        "reverse_dns"
    }

    async fn check_connection(&self, ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
        // Fail closed, as the IP allowlist does. Canonicalized so the forward
        // confirmation below compares like with like.
        let client_ip = ctx.require_client_ip()?;

        // One budget for the whole PTR + confirmation exchange, so a wedged
        // resolver cannot pin a request open.
        match tokio::time::timeout(self.timeout, self.resolve_hostname(client_ip)).await {
            Ok(Ok(hostname)) => {
                debug!(event = "filter_reverse_dns_accepted", outcome = "success", client_ip = %client_ip, hostname);
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(FilterError::Internal(format!(
                "reverse DNS for {client_ip} timed out after {}ms",
                self.timeout.as_millis()
            ))),
        }
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

    fn filter(cfg: &ReverseDnsConfig, resolver: StubResolver) -> ClientHasValidReverseDns {
        ClientHasValidReverseDns::with_resolver(cfg, Arc::new(resolver)).unwrap()
    }

    async fn check(filter: &ClientHasValidReverseDns, ip: &str) -> Result<(), FilterError> {
        filter
            .check_connection(&ConnectionContext {
                client_ip: Some(ip.parse().unwrap()),
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
    }

    fn assert_denied(error: FilterError, needle: &str) {
        match error {
            FilterError::Denied(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    fn assert_internal(error: FilterError, needle: &str) {
        match error {
            FilterError::Internal(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepts_a_forward_confirmed_client() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["host.example.com"])
            .with_forward("host.example.com", &["203.0.113.9"]);
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert!(check(&filter, "203.0.113.9").await.is_ok());
    }

    #[tokio::test]
    async fn denies_a_client_without_a_ptr_record() {
        let filter = filter(&ReverseDnsConfig::default(), StubResolver::default());
        assert_denied(check(&filter, "203.0.113.9").await.unwrap_err(), "no PTR");
    }

    #[tokio::test]
    async fn denies_when_the_forward_record_does_not_come_back() {
        // The spoofing case: an attacker controls the reverse zone only.
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["trusted.example.com"])
            .with_forward("trusted.example.com", &["198.51.100.4"]);
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert_denied(
            check(&filter, "203.0.113.9").await.unwrap_err(),
            "does not resolve back",
        );
    }

    #[tokio::test]
    async fn accepts_an_unconfirmed_ptr_when_confirmation_is_off() {
        let resolver = StubResolver::default().with_ptr("203.0.113.9", &["host.example.com"]);
        let cfg = ReverseDnsConfig {
            require_forward_confirm: false,
            ..ReverseDnsConfig::default()
        };
        assert!(check(&filter(&cfg, resolver), "203.0.113.9").await.is_ok());
    }

    #[tokio::test]
    async fn applies_the_hostname_allow_list() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["host.other.net"])
            .with_forward("host.other.net", &["203.0.113.9"]);
        let cfg = ReverseDnsConfig {
            allow: vec![r".*\.corp\.example\.com".to_string()],
            ..ReverseDnsConfig::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9")
                .await
                .unwrap_err(),
            "is not allowed",
        );
    }

    #[tokio::test]
    async fn applies_the_hostname_deny_list() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["bad.example.com"])
            .with_forward("bad.example.com", &["203.0.113.9"]);
        let cfg = ReverseDnsConfig {
            deny: vec![r"bad\..*".to_string()],
            ..ReverseDnsConfig::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9")
                .await
                .unwrap_err(),
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
        let cfg = ReverseDnsConfig {
            deny: vec![r"bad\..*".to_string()],
            ..ReverseDnsConfig::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9")
                .await
                .unwrap_err(),
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
        let cfg = ReverseDnsConfig {
            deny: vec![r"bad\..*".to_string()],
            ..ReverseDnsConfig::default()
        };
        assert_denied(
            check(&filter(&cfg, resolver), "203.0.113.9")
                .await
                .unwrap_err(),
            "bad.example.com",
        );
    }

    #[tokio::test]
    async fn one_acceptable_name_among_several_is_enough() {
        let resolver = StubResolver::default()
            .with_ptr("203.0.113.9", &["stale.example.com", "host.example.com"])
            .with_forward("stale.example.com", &["198.51.100.4"])
            .with_forward("host.example.com", &["203.0.113.9"]);
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert!(check(&filter, "203.0.113.9").await.is_ok());
    }

    #[tokio::test]
    async fn a_ptr_lookup_failure_is_internal_not_a_denial() {
        let resolver = StubResolver {
            ptr_error: Some("SERVFAIL".to_string()),
            ..StubResolver::default()
        };
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert_internal(check(&filter, "203.0.113.9").await.unwrap_err(), "SERVFAIL");
    }

    #[tokio::test]
    async fn a_forward_lookup_failure_is_internal() {
        let resolver = StubResolver {
            forward_error: Some("SERVFAIL".to_string()),
            ..StubResolver::default().with_ptr("203.0.113.9", &["host.example.com"])
        };
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert_internal(
            check(&filter, "203.0.113.9").await.unwrap_err(),
            "forward lookup failed",
        );
    }

    #[tokio::test]
    async fn a_wedged_resolver_times_out_rather_than_hanging() {
        let resolver = StubResolver {
            hang: true,
            ..StubResolver::default()
        };
        let cfg = ReverseDnsConfig {
            timeout_ms: 10,
            ..ReverseDnsConfig::default()
        };
        assert_internal(
            check(&filter(&cfg, resolver), "203.0.113.9")
                .await
                .unwrap_err(),
            "timed out",
        );
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let filter = filter(&ReverseDnsConfig::default(), StubResolver::default());
        let error = filter
            .check_connection(&ConnectionContext {
                client_ip: None,
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
            .unwrap_err();
        assert_denied(error, "unavailable");
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_is_canonicalized_before_lookup() {
        let resolver = StubResolver::default()
            .with_ptr("192.168.1.5", &["host.example.com"])
            .with_forward("host.example.com", &["192.168.1.5"]);
        let filter = filter(&ReverseDnsConfig::default(), resolver);
        assert!(check(&filter, "::ffff:192.168.1.5").await.is_ok());
    }

    #[test]
    fn a_bad_hostname_pattern_is_a_startup_error() {
        let cfg = ReverseDnsConfig {
            deny: vec!["[unclosed".to_string()],
            ..ReverseDnsConfig::default()
        };
        let error =
            ClientHasValidReverseDns::with_resolver(&cfg, Arc::new(StubResolver::default()))
                .unwrap_err()
                .to_string();
        assert!(error.contains("filter.reverse_dns.deny"), "{error}");
    }

    #[test]
    fn reports_its_config_name() {
        assert_eq!(
            filter(&ReverseDnsConfig::default(), StubResolver::default()).name(),
            "reverse_dns"
        );
    }

    /// `dyn Resolver` is not `Debug`, so the filter renders the policy it was
    /// configured with instead.
    #[test]
    fn the_filter_debug_shows_its_policy() {
        let filter = ClientHasValidReverseDns::with_resolver(
            &ReverseDnsConfig {
                require_forward_confirm: true,
                allow: vec![r"host\.example\.com".to_string()],
                deny: Vec::new(),
                timeout_ms: 1234,
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
