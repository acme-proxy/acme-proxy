//! Who may ask this CA for what: the access policy engine ([`filter`]) and the
//! inventories one of its checks consults ([`ipam`]).
//!
//! Above the network it may reach (a `reverse_dns` lookup, an IPAM API, an
//! operator's script) and below the ACME services that ask it. An internal
//! crate of the `acme-proxy` binary, published in lockstep with it and with no
//! semver promise of its own.

pub mod filter;
pub mod ipam;
