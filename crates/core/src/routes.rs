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

/// The directory (RFC 8555 §7.1.1), the one URL a client is configured with.
pub const DIRECTORY: &str = "/directory";
/// `newNonce` (RFC 8555 §7.2).
pub const NEW_NONCE: &str = "/newNonce";
/// `newAccount` (RFC 8555 §7.3).
pub const NEW_ACCOUNT: &str = "/newAccount";
/// `newOrder` (RFC 8555 §7.4).
pub const NEW_ORDER: &str = "/newOrder";
/// `revokeCert` (RFC 8555 §7.6).
pub const REVOKE_CERT: &str = "/revokeCert";
/// `keyChange` (RFC 8555 §7.3.5).
pub const KEY_CHANGE: &str = "/keyChange";
/// RFC 9773 §4.1 has the client append the certID, so the directory
/// advertises this bare while the router mounts `{id}` under it.
pub const RENEWAL_INFO: &str = "/renewalInfo";
/// The local CA's CRL, DER encoded. Not advertised in the directory.
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

/// The path profile `name` is mounted at: `/profile/<name>`.
#[must_use]
pub fn profile_path(name: &str) -> String {
    format!("{PROFILE_PREFIX}/{name}")
}

/// The public base URL of profile `name` under the process's `base_url` —
/// what every URL a client is handed starts with. One derivation, shared by
/// the router that serves the profile and the admin output that links to it,
/// so the two cannot disagree on a trailing slash.
#[must_use]
pub fn profile_base_url(base_url: &str, name: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), profile_path(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_base_url_has_one_slash_whatever_the_base_ends_with() {
        for base in ["https://acme.example", "https://acme.example/"] {
            assert_eq!(
                profile_base_url(base, "le"),
                "https://acme.example/profile/le"
            );
        }
        assert_eq!(profile_path("le"), "/profile/le");
    }
}
