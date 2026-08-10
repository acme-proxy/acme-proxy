//! Tower layers, split by what they are allowed to see.
//!
//! [`access`] is **server-wide** and outermost: it opens the `request` span
//! every other line nests under and emits the access line. It sits outside the
//! profile routers on purpose, because a request id that stopped at the profile
//! boundary would be missing from exactly the paths that have no profile —
//! `/health`, the http-01 responder, and every admission-control refusal.
//!
//! [`admission`] bounds concurrent ACME work, shedding past the limit rather
//! than queueing. `/health` is mounted outside it: a health probe is asked for
//! precisely when the server is saturated.
//!
//! The rest are per profile. [`filter`] runs the configured access-control
//! chain and inserts the resolved client address. [`nonce`] attaches a
//! `Replay-Nonce` wherever RFC 8555 asks for one, and [`index_link`] the
//! `Link: rel="index"` header — which *appends*, so `post_challenge`'s
//! `rel="up"` survives beside it.

pub mod access;
pub mod admission;
pub mod filter;
pub mod index_link;
pub mod nonce;
