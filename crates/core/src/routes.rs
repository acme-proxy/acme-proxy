//! The ACME resource paths, profile-relative, and the namespace every profile
//! is mounted under.
//!
//! One definition each, because they are written in three places that must
//! agree and previously agreed only by inspection: the router that *mounts*
//! them (`build_router`), the directory that *advertises* them
//! (`handlers::get_directory`), and `middlewares::nonce`, which singles out
//! `newNonce`. A directory advertising a path nothing serves is a client that
//! fails on its very first request, and nothing structural caught it.
//!
//! Only the resources with a fixed path are here; the id-bearing ones
//! (`/acct/{id}`, `/order/{id}/finalize`, …) are never advertised, so they have
//! exactly one call site and gain nothing from a constant.

pub const DIRECTORY: &str = "/directory";
pub const NEW_NONCE: &str = "/newNonce";
pub const NEW_ACCOUNT: &str = "/newAccount";
pub const NEW_ORDER: &str = "/newOrder";
pub const REVOKE_CERT: &str = "/revokeCert";
pub const KEY_CHANGE: &str = "/keyChange";
/// RFC 9773 §4.1 has the client append the certID, so the directory
/// advertises this bare while the router mounts `{id}` under it.
pub const RENEWAL_INFO: &str = "/renewalInfo";
pub const CRL: &str = "/crl";
/// The trust anchor a client installs to accept this profile's leaves.
/// Routed beside [`CRL`] and, like it, deliberately not advertised in the
/// directory — both are CA infrastructure rather than ACME resources.
pub const CA_CHAIN: &str = "/ca.pem";

/// The URL namespace every ACME endpoint is mounted under: a profile named
/// `le` serves `/profile/le/directory`.
///
/// Reserved and fixed, which is the point — server-level routes live at the
/// root and a profile can never collide with one, now or when the next one is
/// added.
pub const PROFILE_PREFIX: &str = "/profile";
