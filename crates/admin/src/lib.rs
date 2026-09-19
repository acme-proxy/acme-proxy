//! Administering the CA: the operation layer both front ends dispatch to
//! ([`admin`] — listings, revocation, EAB, operators, the second factor) and
//! the web front end over it ([`webadmin`] — the `/api` JSON and `/ui` pages on
//! their own listener). The terminal front end is the `acme-proxy` binary's
//! command tree.
//!
//! Above the ACME services it shares with the request path, below the runtime
//! that serves the panel. An internal crate of the `acme-proxy` binary,
//! published in lockstep with it and with no semver promise of its own.

pub mod admin;
pub mod webadmin;
