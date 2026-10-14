//! Sends every kind of malformed or unusual request to every ACME route and
//! checks what must hold no matter what was sent.
//!
//! A test needs an independent source for its expected answer. Here there are
//! two, and neither depends on how the server happens to be written:
//!
//! - **Invariants** hold for any request: the server never answers with a 5xx,
//!   every refusal is an RFC 8555 problem document, and every response carries
//!   a fresh nonce (§6.5, §6.7).
//! - **Controls** keep the matrix honest. A well-formed request must be
//!   accepted, and every request with one deliberate flaw must be refused.
//!   Without them a harness that only sent garbage would pass every invariant
//!   and prove nothing.
//!
//! The exact status and problem type for each case belong to the focused suites
//! (`jws_rejections`, `challenges`, ...). This suite finds what no one thought
//! to write a case for.

#[path = "../common/mod.rs"]
mod common;

mod invariants;
mod world;
