//! Publishing the `_acme-challenge` TXT record the *upstream* CA asks for.
//!
//! ## Why this exists at all
//!
//! Everywhere else in this codebase DNS is read-only: the `dns-01` validator
//! looks a TXT record up to check a client's claim. This module writes one,
//! and it is the only part of the server that does.
//!
//! The reason is the asymmetry at the heart of the proxy. When the upstream is
//! a real CA, it issues its own `dns-01` challenge, and the key authorization
//! it expects is computed from **this proxy's** account thumbprint at that
//! upstream — not the end client's. The two are different accounts on
//! different servers, so the original client *cannot* answer it even in
//! principle: only this server knows the right value. That is what makes the
//! relay a second, independent proof of domain control rather than a
//! pass-through, and why it needs the ability to write DNS.
//!
//! ## Providers
//!
//! Writing a record is the one part of this that a CA does not standardise, so
//! it is a trait ([`DnsUpdater`]) with one implementation per way of writing:
//!
//! - [`rfc2136`] — an `nsupdate` signed with a TSIG key, to any authoritative
//!   server that implements RFC 2136 (BIND, PowerDNS, Knot, CoreDNS with the
//!   `update` plugin). The default, and the one that binds this server to no
//!   vendor.
//! - [`cloudflare`] — Cloudflare's DNS API, for a zone on Cloudflare's own
//!   nameservers, which take no DNS update and know no TSIG key.
//!
//! A provider is chosen by `signer.relay.dns01.provider`, and adding a third
//! touches nothing outside its own file but that match arm: the orchestration
//! in [`super::flow`] publishes and retracts through the trait and knows
//! nothing about how either one works.
//!
//! ## The record's content is not defined here
//!
//! [`acme_proxy_net::challenge::dns_01`] owns both the record name and the digest
//! computation, and both providers call into it. Restating either would risk the
//! publisher and the validator drifting into a record this server accepts but
//! a real CA rejects.
//!
//! ## Alias mode
//!
//! With `challenge_alias` set, every record goes to `_acme-challenge.<alias>`
//! and the operator CNAMEs each `_acme-challenge.<identifier>` there, so one
//! credential over one zone serves names in any number of zones. The alias is
//! configured, never discovered by following the CNAME: this server's resolver
//! need not see what the CA sees (split horizon, an internal recursor), and
//! publishing at the wrong name makes the upstream authorization `invalid` for
//! good. Every authorization sharing one name is safe for the reason a wildcard
//! and its base already are: a provider appends and retracts **by value**, which
//! is the one behaviour every implementation of [`DnsUpdater`] owes the relay
//! however it gets there.

pub mod cloudflare;
pub mod rfc2136;

pub use rfc2136::Rfc2136Updater;

use async_trait::async_trait;
use hickory_proto::rr::Name;

/// Publishes and retracts the TXT records an upstream `dns-01` challenge needs.
///
/// A trait rather than a concrete type so the orchestration in [`super::flow`]
/// can be tested against a stub — the same seam `ChallengeValidator`'s
/// `HttpFetcher` and `Resolver` draw — and so a provider slots in without
/// touching the relay: [`cloudflare`] arrived that way, after [`rfc2136`].
///
/// What every implementation owes the relay is **append and retract by value**.
/// Several live challenges share one record name, so a name is never this
/// server's to clear wholesale.
#[async_trait]
pub trait DnsUpdater: Send + Sync {
    /// Publishes a TXT record at `name` holding `value`.
    ///
    /// Additive: an order for `example.com` and `*.example.com` produces two
    /// authorizations whose records live at the same name with different
    /// values, and both must be present at once.
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String>;

    /// Retracts a previously published record: only `value`, so any other value
    /// at `name` — another authorization's, or another order's for the same
    /// name — survives. Retracting a value that is not there is not an error.
    ///
    /// Best-effort: the relay logs a failure and carries on, because a leftover
    /// challenge record is untidy rather than harmful.
    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String>;
}

/// Refuses `name` unless it lies inside `zone`, returning it parsed.
///
/// The one zone test, shared by both providers, by every update of either one
/// and by the startup check on `challenge_alias`, so nothing can disagree about
/// what is inside.
pub(crate) fn check_in_zone(zone: &Name, name: &str) -> Result<Name, String> {
    let name =
        Name::from_utf8(name).map_err(|error| format!("{name} is not a DNS name: {error}"))?;
    // The server or the API would answer for a name elsewhere anyway; refusing
    // here says why.
    if !zone.zone_of(&name) {
        return Err(format!("{name} is outside the zone {zone}"));
    }
    Ok(name)
}

/// Turns `signer.relay.dns01.challenge_alias` into the absolute record name
/// every challenge is published at, or `None` when alias mode is off.
///
/// The value is a domain, not a record name: `_acme-challenge.` is prepended by
/// the same [`acme_proxy_net::challenge::dns_01::record_name`] the unaliased
/// path uses. A value already carrying that label is refused rather than
/// doubled, and so is a wildcard, which no CNAME can point at.
pub fn alias_record_name(alias: &str) -> anyhow::Result<Option<String>> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Ok(None);
    }
    let bare = alias.trim_end_matches('.');
    if bare.starts_with('*') {
        anyhow::bail!("signer.relay.dns01.challenge_alias ({alias}) cannot be a wildcard");
    }
    if bare.to_ascii_lowercase().starts_with("_acme-challenge.") {
        anyhow::bail!(
            "signer.relay.dns01.challenge_alias ({alias}) is a domain: drop the leading \
             _acme-challenge., which is added to it"
        );
    }
    let name = format!("{}.", acme_proxy_net::challenge::dns_01::record_name(bare));
    Name::from_utf8(&name).map_err(|error| {
        anyhow::anyhow!("signer.relay.dns01.challenge_alias ({alias}) is not a DNS name: {error}")
    })?;
    Ok(Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alias is a domain: `_acme-challenge.` is added once, the result is
    /// absolute with or without a trailing dot, and empty means "off".
    #[test]
    fn an_alias_becomes_one_absolute_record_name() {
        assert_eq!(alias_record_name("").unwrap(), None);
        assert_eq!(alias_record_name("  ").unwrap(), None);
        for alias in ["acme-alias.net", "acme-alias.net.", " acme-alias.net. "] {
            assert_eq!(
                alias_record_name(alias).unwrap().as_deref(),
                Some("_acme-challenge.acme-alias.net."),
                "{alias:?}"
            );
        }
    }

    #[test]
    fn an_unusable_alias_is_refused_by_key_name() {
        for (alias, expected) in [
            ("*.acme-alias.net", "wildcard"),
            ("_ACME-Challenge.acme-alias.net.", "drop the leading"),
            ("not a dns name", "not a DNS name"),
        ] {
            let error = alias_record_name(alias).unwrap_err().to_string();
            assert!(
                error.contains("challenge_alias") && error.contains(expected),
                "{alias:?}: {error}"
            );
        }
    }
}
