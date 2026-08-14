//! The `allowed_ip` filter: which networks may talk to the server.
//!
//! The bluntest and most reliable control available: it needs no DNS, no
//! external service, and cannot be influenced by the client. On a CA serving one
//! LAN it is usually the only filter needed — and the one worth having whether
//! or not `challenge.bypass` is set.
//!
//! ## Allow and deny
//!
//! Two lists, with the same semantics the `reverse_dns` and `identifiers`
//! filters use: `deny` is checked first and wins, and an empty `allow` imposes
//! no constraint. That gives three usable shapes —
//!
//! - `allow` only: a strict allowlist.
//! - `deny` only: a blocklist, everything else served.
//! - both: an allowlist with holes punched in it, e.g.
//!   `allow = ["10.0.0.0/8"]` and `deny = ["10.1.2.0/24"]`.
//!
//! Deny-wins is plain set membership, not longest-prefix-match: a `/32` in
//! `allow` does not beat a `/8` in `deny`. That matches the other two filters,
//! and the surprising direction is the safe one.

use async_trait::async_trait;
use ipnet::IpNet;
use tracing::info;

use super::{ConnectionContext, Filter, FilterError, ListVerdict, check_lists, parse_nets};
use crate::config::AllowedIpConfig;

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
    /// imposes no constraint, so the filter would accept everything, and an
    /// operator who enabled it did not mean to turn on something inert.
    pub fn from_config(cfg: &AllowedIpConfig) -> anyhow::Result<Self> {
        if cfg.allow.is_empty() && cfg.deny.is_empty() {
            anyhow::bail!(
                "filter.allowed_ip has neither allow nor deny entries, so it would accept \
                 every request; list the permitted or refused networks, or remove \
                 `allowed_ip` from filter.enabled"
            );
        }

        let allow = parse_nets(&cfg.allow, "filter.allowed_ip.allow")?;
        let deny = parse_nets(&cfg.deny, "filter.allowed_ip.deny")?;
        info!(event = "filter_allowed_ip_loaded", outcome = "success", allow = ?cfg.allow, deny = ?cfg.deny);
        Ok(Self { allow, deny })
    }
}

#[async_trait]
impl Filter for AllowedFromIpAddress {
    fn name(&self) -> &'static str {
        "allowed_ip"
    }

    async fn check_connection(&self, ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
        // Fails closed on a missing address, in blocklist mode as much as
        // allowlist mode: a blocklist that cannot identify the caller protects
        // nothing. See `ConnectionContext::require_client_ip`.
        let client_ip = ctx.require_client_ip()?;

        // The two details differ so a refused client can tell which list bit.
        match check_lists(&self.allow, &self.deny, |net| net.contains(&client_ip)) {
            ListVerdict::Permitted => Ok(()),
            ListVerdict::Denied => Err(FilterError::Denied(format!(
                "address {client_ip} is denied"
            ))),
            ListVerdict::NotAllowed => Err(FilterError::Denied(format!(
                "address {client_ip} is not allowed"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use std::net::IpAddr;

    fn config(allow: &[&str], deny: &[&str]) -> AllowedIpConfig {
        AllowedIpConfig {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    /// Allowlist-only filter.
    fn filter(allow: &[&str]) -> AllowedFromIpAddress {
        AllowedFromIpAddress::from_config(&config(allow, &[])).unwrap()
    }

    /// Filter with both lists.
    fn filter_with(allow: &[&str], deny: &[&str]) -> AllowedFromIpAddress {
        AllowedFromIpAddress::from_config(&config(allow, deny)).unwrap()
    }

    fn assert_denied(error: FilterError, needle: &str) {
        match error {
            FilterError::Denied(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    async fn check(filter: &AllowedFromIpAddress, ip: Option<&str>) -> Result<(), FilterError> {
        let client_ip: Option<IpAddr> = ip.map(|value| value.parse().unwrap());
        filter
            .check_connection(&ConnectionContext {
                client_ip,
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
    }

    #[tokio::test]
    async fn allows_an_address_inside_an_ipv4_cidr() {
        let filter = filter(&["192.168.1.0/24"]);
        assert!(check(&filter, Some("192.168.1.5")).await.is_ok());
        assert!(check(&filter, Some("192.168.1.255")).await.is_ok());
    }

    #[tokio::test]
    async fn denies_an_address_outside_every_network() {
        let filter = filter(&["192.168.1.0/24", "10.0.0.0/8"]);
        assert_denied(
            check(&filter, Some("203.0.113.9")).await.unwrap_err(),
            "203.0.113.9 is not allowed",
        );
    }

    #[tokio::test]
    async fn allows_an_address_inside_an_ipv6_cidr() {
        let filter = filter(&["fd00::/8"]);
        assert!(check(&filter, Some("fd00::1")).await.is_ok());
        assert!(check(&filter, Some("2001:db8::1")).await.is_err());
    }

    #[tokio::test]
    async fn a_bare_address_entry_is_a_host_route() {
        let filter = filter(&["203.0.113.7"]);
        assert!(check(&filter, Some("203.0.113.7")).await.is_ok());
        assert!(check(&filter, Some("203.0.113.8")).await.is_err());
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_matches_a_v4_rule() {
        // The dual-stack `[::]:3000` default reports IPv4 clients this way.
        let filter = filter(&["192.168.1.0/24"]);
        assert!(check(&filter, Some("::ffff:192.168.1.5")).await.is_ok());
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let filter = filter(&["192.168.1.0/24"]);
        assert_denied(check(&filter, None).await.unwrap_err(), "unavailable");
    }

    /// Fail-closed applies in blocklist mode too: an address the server cannot
    /// see is not "absent from the deny list, therefore fine".
    #[tokio::test]
    async fn a_missing_client_address_is_denied_in_blocklist_mode() {
        let filter = filter_with(&[], &["203.0.113.9"]);
        assert_denied(check(&filter, None).await.unwrap_err(), "unavailable");
    }

    /// The configuration this change unlocks: no allowlist at all, just a
    /// blocklist, everything else served.
    #[tokio::test]
    async fn a_deny_only_config_is_a_blocklist() {
        let filter = filter_with(&[], &["203.0.113.9", "10.0.0.0/8"]);

        assert_denied(
            check(&filter, Some("203.0.113.9")).await.unwrap_err(),
            "203.0.113.9 is denied",
        );
        assert_denied(
            check(&filter, Some("10.4.5.6")).await.unwrap_err(),
            "10.4.5.6 is denied",
        );
        // Anything not listed is served.
        assert!(check(&filter, Some("192.168.1.5")).await.is_ok());
        assert!(check(&filter, Some("2001:db8::1")).await.is_ok());
    }

    /// Deny wins, so a subnet can be allowed with holes punched in it.
    #[tokio::test]
    async fn deny_wins_over_allow() {
        let filter = filter_with(&["10.0.0.0/8"], &["10.1.2.0/24"]);

        assert!(check(&filter, Some("10.0.0.5")).await.is_ok());
        assert_denied(
            check(&filter, Some("10.1.2.5")).await.unwrap_err(),
            "10.1.2.5 is denied",
        );
        // Still outside the allow list entirely.
        assert_denied(
            check(&filter, Some("192.168.1.5")).await.unwrap_err(),
            "192.168.1.5 is not allowed",
        );
    }

    /// Plain set membership, not longest-prefix-match: a host route in `allow`
    /// does not beat a wide block in `deny`.
    #[tokio::test]
    async fn a_more_specific_allow_does_not_beat_a_broader_deny() {
        let filter = filter_with(&["10.1.2.3"], &["10.0.0.0/8"]);
        assert_denied(
            check(&filter, Some("10.1.2.3")).await.unwrap_err(),
            "10.1.2.3 is denied",
        );
    }

    #[tokio::test]
    async fn deny_accepts_bare_addresses_and_ipv6() {
        let filter = filter_with(&[], &["203.0.113.7", "2001:db8::/32"]);

        assert_denied(
            check(&filter, Some("203.0.113.7")).await.unwrap_err(),
            "is denied",
        );
        assert!(check(&filter, Some("203.0.113.8")).await.is_ok());
        assert_denied(
            check(&filter, Some("2001:db8::1")).await.unwrap_err(),
            "is denied",
        );
        assert!(check(&filter, Some("2001:dba::1")).await.is_ok());
    }

    /// A denied IPv4 client arriving over the dual-stack socket as
    /// `::ffff:…` must still match a plain v4 deny entry.
    #[tokio::test]
    async fn an_ipv4_mapped_client_matches_a_v4_deny_rule() {
        let filter = filter_with(&[], &["192.168.1.0/24"]);
        assert_denied(
            check(&filter, Some("::ffff:192.168.1.5"))
                .await
                .unwrap_err(),
            "192.168.1.5 is denied",
        );
    }

    #[test]
    fn both_lists_empty_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_config(&AllowedIpConfig::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("would accept every request"), "{error}");
    }

    #[test]
    fn a_bad_allow_network_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_config(&config(&["192.168.1.0/99"], &[]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.allowed_ip.allow"), "{error}");
    }

    #[test]
    fn a_bad_deny_network_is_a_startup_error() {
        let error = AllowedFromIpAddress::from_config(&config(&[], &["garbage"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.allowed_ip.deny"), "{error}");
    }

    #[test]
    fn reports_its_config_name() {
        assert_eq!(filter(&["10.0.0.0/8"]).name(), "allowed_ip");
    }

    #[tokio::test]
    async fn does_not_inspect_identifiers() {
        use super::super::{IdentifierContext, IdentifierStage};
        use crate::sqlite::order::Identifier;

        let identifiers = vec![Identifier::dns("example.com")];
        let allowed = filter(&["10.0.0.0/8"])
            .check_identifiers(&IdentifierContext {
                client_ip: None,
                account_id: "acct",
                stage: IdentifierStage::NewOrder,
                identifiers: &identifiers,
            })
            .await;
        assert!(allowed.is_ok());
    }
}
