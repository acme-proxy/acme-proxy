//! Deciding which address a request actually came from.
//!
//! Every connection-level filter rests on this answer, so getting it wrong
//! either locks out legitimate clients or hands an attacker a trivial bypass.
//!
//! Two deployments have to work:
//!
//! - **Direct.** The socket peer address is the client. Nothing else is
//!   believed, and a forwarded-for header from a client that made it up is
//!   ignored.
//! - **Behind a reverse proxy.** Every peer is the proxy, so the real client
//!   only exists in a header. That header is believed *only* when the peer is
//!   itself listed in `filter.trusted_proxies` — otherwise anyone could set
//!   `X-Forwarded-For: 10.0.0.1` and inherit an allowlisted address.
//!
//! The default is the direct case with an empty trusted list, i.e. headers are
//! never believed.

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName};
use ipnet::IpNet;

use super::{canonical, nets_contain, parse_nets};

/// The client address for a request, inserted into the request extensions by
/// [`add_filter_middleware`](crate::middlewares::filter::add_filter_middleware)
/// so handlers can pass it to the identifier hook.
///
/// `None` means the peer address was unavailable — the socket was not served
/// with `ConnectInfo`. Filters treat that as a denial rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

/// How to derive a client address from the socket peer plus request headers.
#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    trusted: Vec<IpNet>,
    header: HeaderName,
}

impl Default for ProxyPolicy {
    /// Trust nothing: the peer address is always the client.
    fn default() -> Self {
        Self {
            trusted: Vec::new(),
            header: HeaderName::from_static("x-forwarded-for"),
        }
    }
}

impl ProxyPolicy {
    /// Validates the trusted-proxy CIDRs and the header name at startup.
    pub fn new(trusted_proxies: &[String], header: &str) -> anyhow::Result<Self> {
        let trusted = parse_nets(trusted_proxies, "filter.trusted_proxies")?;
        let header = HeaderName::try_from(header.to_ascii_lowercase())
            .map_err(|error| anyhow::anyhow!("filter.forwarded_header: {error}"))?;
        Ok(Self { trusted, header })
    }

    /// Resolves the effective client address.
    ///
    /// Returns the canonicalized peer unless the peer is a trusted proxy, in
    /// which case the forwarded-for header is walked **right to left**, past
    /// any hop that is itself a trusted proxy, to the first address the chain
    /// did not add itself. That is the closest thing to the real client that
    /// the trusted portion of the chain vouches for; entries further left were
    /// written by whoever connected to the outermost proxy and cannot be
    /// believed.
    pub fn resolve(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = canonical(peer?);

        if self.trusted.is_empty() || !nets_contain(&self.trusted, peer) {
            return Some(peer);
        }

        let forwarded: Vec<IpAddr> = headers
            .get_all(&self.header)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|entry| parse_forwarded_entry(entry.trim()))
            .map(canonical)
            .collect();

        // First hop from the right that no trusted proxy vouches for.
        if let Some(client) = forwarded
            .iter()
            .rev()
            .find(|ip| !nets_contain(&self.trusted, **ip))
        {
            return Some(*client);
        }

        // Every hop was a trusted proxy: the leftmost entry is as far back as
        // the chain goes. With no usable entries at all, fall back to the peer.
        Some(forwarded.first().copied().unwrap_or(peer))
    }
}

/// Parses one forwarded-for list entry.
///
/// Handles the bare `1.2.3.4` and `[2001:db8::1]:443` forms proxies emit. A
/// port is only stripped when it is unambiguous — a bare IPv6 address is full
/// of colons, so `2001:db8::1` must not be read as host `2001:db8:` plus port.
fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
    if entry.is_empty() {
        return None;
    }

    // `[v6]:port` or `[v6]`
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return host.parse().ok();
    }

    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }

    // `v4:port` — exactly one colon, so this cannot be a bare IPv6 address.
    if entry.matches(':').count() == 1 {
        let (host, _) = entry.split_once(':')?;
        return host.parse().ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(HeaderName::try_from(*name).unwrap(), value.parse().unwrap());
        }
        map
    }

    fn policy(trusted: &[&str]) -> ProxyPolicy {
        ProxyPolicy::new(
            &trusted
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            "x-forwarded-for",
        )
        .unwrap()
    }

    #[test]
    fn no_peer_means_no_client() {
        assert_eq!(policy(&[]).resolve(None, &HeaderMap::new()), None);
    }

    #[test]
    fn peer_is_used_when_no_proxy_is_trusted() {
        let resolved = policy(&[]).resolve(
            Some(ip("203.0.113.9")),
            &headers(&[("x-forwarded-for", "10.0.0.1")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_header_is_ignored_from_an_untrusted_peer() {
        // The spoofing case: a direct client claiming an allowlisted address.
        let resolved = policy(&["127.0.0.1"]).resolve(
            Some(ip("203.0.113.9")),
            &headers(&[("x-forwarded-for", "10.0.0.1")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_header_is_honoured_from_a_trusted_peer() {
        let resolved = policy(&["127.0.0.1"]).resolve(
            Some(ip("127.0.0.1")),
            &headers(&[("x-forwarded-for", "203.0.113.9")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn chained_proxies_are_walked_past() {
        // client -> edge(10.0.0.8) -> inner(127.0.0.1) -> us
        let resolved = policy(&["127.0.0.1", "10.0.0.0/8"]).resolve(
            Some(ip("127.0.0.1")),
            &headers(&[("x-forwarded-for", "203.0.113.9, 10.0.0.8")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn repeated_header_lines_are_concatenated() {
        let resolved = policy(&["127.0.0.1", "10.0.0.0/8"]).resolve(
            Some(ip("127.0.0.1")),
            &headers(&[
                ("x-forwarded-for", "203.0.113.9"),
                ("x-forwarded-for", "10.0.0.8"),
            ]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn all_hops_trusted_falls_back_to_the_leftmost() {
        let resolved = policy(&["127.0.0.1", "10.0.0.0/8"]).resolve(
            Some(ip("127.0.0.1")),
            &headers(&[("x-forwarded-for", "10.0.0.4, 10.0.0.8")]),
        );
        assert_eq!(resolved, Some(ip("10.0.0.4")));
    }

    #[test]
    fn trusted_peer_without_a_usable_header_falls_back_to_the_peer() {
        let trusted = policy(&["127.0.0.1"]);
        assert_eq!(
            trusted.resolve(Some(ip("127.0.0.1")), &HeaderMap::new()),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(
            trusted.resolve(
                Some(ip("127.0.0.1")),
                &headers(&[("x-forwarded-for", "not-an-ip, also-garbage")])
            ),
            Some(ip("127.0.0.1"))
        );
    }

    #[test]
    fn ipv4_mapped_peer_is_canonicalized() {
        // What the dual-stack `[::]:3000` socket reports for an IPv4 client.
        let resolved = policy(&[]).resolve(Some(ip("::ffff:192.168.1.5")), &HeaderMap::new());
        assert_eq!(resolved, Some(ip("192.168.1.5")));
    }

    #[test]
    fn ipv4_mapped_peer_matches_a_v4_trusted_proxy() {
        let resolved = policy(&["127.0.0.1"]).resolve(
            Some(ip("::ffff:127.0.0.1")),
            &headers(&[("x-forwarded-for", "203.0.113.9")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_entries_may_carry_ports() {
        assert_eq!(parse_forwarded_entry("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_entry("1.2.3.4:8443"), Some(ip("1.2.3.4")));
        assert_eq!(
            parse_forwarded_entry("2001:db8::1"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_entry("[2001:db8::1]:443"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_entry("[2001:db8::1]"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(parse_forwarded_entry(""), None);
        assert_eq!(parse_forwarded_entry("unknown"), None);
        assert_eq!(parse_forwarded_entry("[bad"), None);
        assert_eq!(parse_forwarded_entry("1.2.3.4:notaport:x"), None);
    }

    #[test]
    fn new_validates_its_inputs() {
        assert!(ProxyPolicy::new(&["10.0.0.0/8".to_string()], "x-real-ip").is_ok());
        assert!(ProxyPolicy::new(&["nope".to_string()], "x-forwarded-for").is_err());
        assert!(ProxyPolicy::new(&[], "not a header").is_err());
    }

    #[test]
    fn a_custom_header_name_is_used() {
        let policy = ProxyPolicy::new(&["127.0.0.1".to_string()], "X-Real-IP").unwrap();
        let resolved = policy.resolve(
            Some(ip("127.0.0.1")),
            &headers(&[("x-real-ip", "203.0.113.9")]),
        );
        assert_eq!(resolved, Some(ip("203.0.113.9")));
    }
}
