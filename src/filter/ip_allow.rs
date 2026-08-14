//! The `allowed_ip` check: which networks may talk to the server.
//!
//! The bluntest and most reliable control available: it needs no DNS, no
//! external service, and cannot be influenced by the client. On a CA serving one
//! LAN it is usually the only check needed — and the one worth having whether
//! or not `challenge.bypass` is set.
//!
//! ## Allow and deny
//!
//! Two lists, with the same semantics the `reverse_dns` and `identifiers`
//! checks use: `deny` is checked first and wins, and an empty `allow` imposes
//! no constraint. That gives three usable shapes —
//!
//! - `allow` only: a strict allowlist.
//! - `deny` only: a blocklist, everything else served.
//! - both: an allowlist with holes punched in it, e.g.
//!   `allow = ["10.0.0.0/8"]` and `deny = ["10.1.2.0/24"]`.
//!
//! Deny-wins is plain set membership, not longest-prefix-match: a `/32` in
//! `allow` does not beat a `/8` in `deny`. That matches the other two checks,
//! and the surprising direction is the safe one.
//!
//! ## Both stages
//!
//! This check reads nothing but the client address, which
//! [`IdentifierContext`] carries as well as [`ConnectionContext`], so it decides
//! at either stage. That is not a detail: it is what lets a rule say
//! `mgmt-net or inventory` and have the address half remain answerable at the
//! point where the inventory is consulted.

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use tracing::info;

use super::policy::{Check, StageSet, Verdict};
use super::{ConnectionContext, IdentifierContext, ListVerdict, check_lists, parse_nets};

/// Resolved `[filter.check.<name>]` settings for `type = "allowed_ip"`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Accepts or refuses a request by the network its client address falls in.
#[derive(Debug)]
pub struct AllowedFromIpAddress {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl AllowedFromIpAddress {
    /// Parses the configured networks, failing startup on a bad entry.
    ///
    /// Both lists empty is rejected rather than honoured: an empty `allow`
    /// imposes no constraint, so the check would accept everything, and an
    /// operator who configured it did not mean to turn on something inert.
    pub fn from_settings(name: &str, settings: &Settings) -> anyhow::Result<Self> {
        if settings.allow.is_empty() && settings.deny.is_empty() {
            anyhow::bail!(
                "filter.check.{name} has neither allow nor deny entries, so it would accept \
                 every request; list the permitted or refused networks, or drop the check"
            );
        }

        let allow = parse_nets(&settings.allow, &format!("filter.check.{name}.allow"))?;
        let deny = parse_nets(&settings.deny, &format!("filter.check.{name}.deny"))?;
        info!(event = "filter_allowed_ip_loaded", outcome = "success", check = name, allow = ?settings.allow, deny = ?settings.deny);
        Ok(Self { allow, deny })
    }

    /// The whole decision, shared by both hooks because it reads only the
    /// address.
    fn decide(&self, client_ip: Option<IpAddr>) -> Verdict {
        // Fails closed on a missing address, in blocklist mode as much as
        // allowlist mode: a blocklist that cannot identify the caller protects
        // nothing. See `ConnectionContext::require_client_ip`.
        let client_ip = match super::require_client_ip(client_ip) {
            Ok(client_ip) => client_ip,
            Err(verdict) => return verdict,
        };

        // The two details differ so a refused client can tell which list bit.
        match check_lists(&self.allow, &self.deny, |net| net.contains(&client_ip)) {
            ListVerdict::Permitted => Verdict::Pass,
            ListVerdict::Denied => Verdict::Fail(format!("address {client_ip} is denied")),
            ListVerdict::NotAllowed => Verdict::Fail(format!("address {client_ip} is not allowed")),
        }
    }
}

#[async_trait]
impl Check for AllowedFromIpAddress {
    fn kind(&self) -> &'static str {
        "allowed_ip"
    }

    fn stages(&self) -> StageSet {
        StageSet::both()
    }

    async fn check_connection(&self, context: &ConnectionContext<'_>) -> Verdict {
        self.decide(context.client_ip)
    }

    async fn check_identifiers(&self, context: &IdentifierContext<'_>) -> Verdict {
        self.decide(context.client_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::IdentifierStage;
    use axum::http::Method;

    fn settings(allow: &[&str], deny: &[&str]) -> Settings {
        Settings {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    /// Allowlist-only check.
    fn check(allow: &[&str]) -> AllowedFromIpAddress {
        AllowedFromIpAddress::from_settings("net", &settings(allow, &[])).unwrap()
    }

    /// Check with both lists.
    fn check_with(allow: &[&str], deny: &[&str]) -> AllowedFromIpAddress {
        AllowedFromIpAddress::from_settings("net", &settings(allow, deny)).unwrap()
    }

    fn assert_failed(verdict: Verdict, needle: &str) {
        match verdict {
            Verdict::Fail(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    async fn connection(check: &AllowedFromIpAddress, ip: Option<&str>) -> Verdict {
        let client_ip: Option<IpAddr> = ip.map(|value| value.parse().unwrap());
        check
            .check_connection(&ConnectionContext {
                client_ip,
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
    }

    #[tokio::test]
    async fn allows_an_address_inside_an_ipv4_cidr() {
        let check = check(&["192.168.1.0/24"]);
        assert_eq!(connection(&check, Some("192.168.1.5")).await, Verdict::Pass);
        assert_eq!(
            connection(&check, Some("192.168.1.255")).await,
            Verdict::Pass
        );
    }

    #[tokio::test]
    async fn denies_an_address_outside_every_network() {
        let check = check(&["192.168.1.0/24", "10.0.0.0/8"]);
        assert_failed(
            connection(&check, Some("203.0.113.9")).await,
            "203.0.113.9 is not allowed",
        );
    }

    #[tokio::test]
    async fn allows_an_address_inside_an_ipv6_cidr() {
        let check = check(&["fd00::/8"]);
        assert_eq!(connection(&check, Some("fd00::1")).await, Verdict::Pass);
        assert_ne!(connection(&check, Some("2001:db8::1")).await, Verdict::Pass);
    }

    #[tokio::test]
    async fn a_bare_address_entry_is_a_host_route() {
        let check = check(&["203.0.113.7"]);
        assert_eq!(connection(&check, Some("203.0.113.7")).await, Verdict::Pass);
        assert_ne!(connection(&check, Some("203.0.113.8")).await, Verdict::Pass);
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_matches_a_v4_rule() {
        // The dual-stack `[::]:3000` default reports IPv4 clients this way.
        let check = check(&["192.168.1.0/24"]);
        assert_eq!(
            connection(&check, Some("::ffff:192.168.1.5")).await,
            Verdict::Pass
        );
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let check = check(&["192.168.1.0/24"]);
        assert_failed(connection(&check, None).await, "unavailable");
    }

    /// Fail-closed applies in blocklist mode too: an address the server cannot
    /// see is not "absent from the deny list, therefore fine".
    #[tokio::test]
    async fn a_missing_client_address_is_denied_in_blocklist_mode() {
        let check = check_with(&[], &["203.0.113.9"]);
        assert_failed(connection(&check, None).await, "unavailable");
    }

    /// A missing address is a *refusal*, not an unknown: the server saw a
    /// request it cannot attribute, which is a decision about the client
    /// rather than a failure to reach an authority. Pinned because
    /// `Undecided` here would silently turn a 403 into a 500.
    #[tokio::test]
    async fn a_missing_client_address_is_a_refusal_not_an_unknown() {
        let check = check(&["192.168.1.0/24"]);
        assert!(matches!(connection(&check, None).await, Verdict::Fail(_)));
    }

    #[tokio::test]
    async fn a_deny_only_config_is_a_blocklist() {
        let check = check_with(&[], &["203.0.113.9", "10.0.0.0/8"]);

        assert_failed(
            connection(&check, Some("203.0.113.9")).await,
            "203.0.113.9 is denied",
        );
        assert_failed(
            connection(&check, Some("10.4.5.6")).await,
            "10.4.5.6 is denied",
        );
        // Anything not listed is served.
        assert_eq!(connection(&check, Some("192.168.1.5")).await, Verdict::Pass);
        assert_eq!(connection(&check, Some("2001:db8::1")).await, Verdict::Pass);
    }

    /// Deny wins, so a subnet can be allowed with holes punched in it.
    #[tokio::test]
    async fn deny_wins_over_allow() {
        let check = check_with(&["10.0.0.0/8"], &["10.1.2.0/24"]);

        assert_eq!(connection(&check, Some("10.0.0.5")).await, Verdict::Pass);
        assert_failed(
            connection(&check, Some("10.1.2.5")).await,
            "10.1.2.5 is denied",
        );
        // Still outside the allow list entirely.
        assert_failed(
            connection(&check, Some("192.168.1.5")).await,
            "192.168.1.5 is not allowed",
        );
    }

    /// Plain set membership, not longest-prefix-match: a host route in `allow`
    /// does not beat a wide block in `deny`.
    #[tokio::test]
    async fn a_more_specific_allow_does_not_beat_a_broader_deny() {
        let check = check_with(&["10.1.2.3"], &["10.0.0.0/8"]);
        assert_failed(
            connection(&check, Some("10.1.2.3")).await,
            "10.1.2.3 is denied",
        );
    }

    #[tokio::test]
    async fn deny_accepts_bare_addresses_and_ipv6() {
        let check = check_with(&[], &["203.0.113.7", "2001:db8::/32"]);

        assert_failed(connection(&check, Some("203.0.113.7")).await, "is denied");
        assert_eq!(connection(&check, Some("203.0.113.8")).await, Verdict::Pass);
        assert_failed(connection(&check, Some("2001:db8::1")).await, "is denied");
        assert_eq!(connection(&check, Some("2001:dba::1")).await, Verdict::Pass);
    }

    /// A denied IPv4 client arriving over the dual-stack socket as
    /// `::ffff:…` must still match a plain v4 deny entry.
    #[tokio::test]
    async fn an_ipv4_mapped_client_matches_a_v4_deny_rule() {
        let check = check_with(&[], &["192.168.1.0/24"]);
        assert_failed(
            connection(&check, Some("::ffff:192.168.1.5")).await,
            "192.168.1.5 is denied",
        );
    }

    /// The property that makes `mgmt-net or inventory` writable: the same
    /// answer at the stage where the inventory is consulted.
    #[tokio::test]
    async fn it_decides_the_same_way_at_the_identifier_stage() {
        let check = check(&["10.0.0.0/8"]);
        let identifiers = vec![crate::sqlite::order::Identifier::dns("example.com")];

        let verdict = check
            .check_identifiers(&IdentifierContext {
                client_ip: Some("10.0.0.5".parse().unwrap()),
                account_id: "acct",
                stage: IdentifierStage::NewOrder,
                identifiers: &identifiers,

                eab: None,
            })
            .await;
        assert_eq!(verdict, Verdict::Pass);

        let verdict = check
            .check_identifiers(&IdentifierContext {
                client_ip: Some("203.0.113.9".parse().unwrap()),
                account_id: "acct",
                stage: IdentifierStage::NewOrder,
                identifiers: &identifiers,

                eab: None,
            })
            .await;
        assert_failed(verdict, "is not allowed");
    }

    #[test]
    fn both_lists_empty_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_settings("net", &Settings::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("would accept every request"), "{error}");
        assert!(error.contains("filter.check.net"), "{error}");
    }

    #[test]
    fn a_bad_allow_network_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_settings("net", &settings(&["192.168.1.0/99"], &[]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.net.allow"), "{error}");
    }

    #[test]
    fn a_bad_deny_network_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_settings("net", &settings(&[], &["garbage"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.net.deny"), "{error}");
    }

    #[test]
    fn reports_its_type_and_stages() {
        let check = check(&["10.0.0.0/8"]);
        assert_eq!(check.kind(), "allowed_ip");
        assert_eq!(check.stages(), StageSet::both());
    }
}
