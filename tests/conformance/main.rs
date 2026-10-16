//! Sends every kind of malformed or unusual request to every ACME route and
//! checks that each rule of RFC 8555 §6 holds on all of them alike.
//!
//! A test needs an independent source for its expected answer. Here there are
//! three, and none depends on how the server happens to be written:
//!
//! - **Invariants** hold for any request: the server never answers with a 5xx,
//!   every answer links to its profile's directory (§7.1), every refusal is an
//!   RFC 8555 problem document (§6.7), and every answer to a POST carries a
//!   nonce no request or earlier answer used (§6.5).
//! - **Exact answers.** Each refusal is pinned to its status and problem type
//!   on every route, taken from the RFC where it names one. The two answers
//!   that differ from the RFC are marked in `Flaw::accepted_answers`.
//! - **Controls** keep the matrix honest. A well-formed request must be
//!   accepted, and every request with one deliberate flaw must be refused.
//!   Without them a harness that only sent garbage would pass every invariant
//!   and prove nothing.
//!
//! What a single route does beyond that — its `detail` text, its side effects,
//! the payloads only it takes — belongs to that route's suite
//! (`jws_rejections`, `new_account`, `challenges`, ...). A rule that holds on
//! `newAccount` and not on `revokeCert` only shows up here.

#[path = "../common/mod.rs"]
mod common;

mod invariants;
mod jws;
mod post_as_get;
mod world;
