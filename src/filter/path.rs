//! The `path` check: which request paths a rule applies to.
//!
//! Matched against the **profile-stripped** path, so `/directory` — not
//! `/profile/default/directory` — is the value to list, and one check covers
//! every endpoint.
//!
//! ## What it replaces, and the trap it exists for
//!
//! This is the successor to `filter.exempt_paths`, and the reason it is a check
//! rather than a list is that a path is rarely the whole answer. As a rule it
//! composes: `public-paths or mgmt-net` opens a path to everyone *or* an
//! address to everything, and `not public-paths and mgmt-net` restricts a
//! sensitive path to one network. The old list could only say "skip the
//! connection stage entirely for this exact string".
//!
//! The concrete reason an operator needs it: **`/crl` is served by the profile
//! router**, so it sits behind the policy like every other ACME resource. Turn
//! on an address-based check without exempting it and every relying party
//! outside the allowlist silently loses revocation checking — and relying
//! parties are precisely not the ACME clients that were allowlisted. A
//! `public-paths` check listing `/crl` is the companion to any address policy.
//!
//! Server-level routes (`GET /health`, `/`, the http-01 responder) are served
//! by the *root* router, which no profile's policy ever sees, so they need no
//! entry here.
//!
//! ## Globs
//!
//! `*` matches one or more characters other than `/` — one path segment, the
//! same "one component" reading `*` has in the name checks. So
//! `/renewalInfo/*` covers every certificate id and nothing deeper, which the
//! exact-match list it replaces could not express at all.

use async_trait::async_trait;
use regex::Regex;
use tracing::info;

use super::policy::{Check, StageSet, Verdict};
use super::{ConnectionContext, ListVerdict, check_lists, compile_anchored};

/// Resolved `[filter.check.<name>]` settings for `type = "path"`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Accepts or refuses a request by the path it asks for.
#[derive(Debug)]
pub struct PathList {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
}

impl PathList {
    /// Compiles the path globs, failing startup on an empty policy.
    pub fn from_settings(name: &str, settings: &Settings) -> anyhow::Result<Self> {
        if settings.allow.is_empty() && settings.deny.is_empty() {
            anyhow::bail!(
                "filter.check.{name} has neither allow nor deny entries, so it would match \
                 every request; list the paths it is about, or drop the check"
            );
        }

        let check = Self {
            allow: compile_paths(&settings.allow, name, "allow")?,
            deny: compile_paths(&settings.deny, name, "deny")?,
        };
        info!(event = "filter_path_loaded", outcome = "success", check = name, allow = ?settings.allow, deny = ?settings.deny);
        Ok(check)
    }
}

/// A path glob's `*` is one *segment*, so it stops at `/` rather than at `.`.
///
/// Deliberately not [`super::glob_to_pattern`]: a path is delimited by `/`
/// where a DNS name is delimited by `.`, and sharing one substitution would
/// make `/renewalInfo/*` match `/renewalInfo/a/b`.
fn compile_paths(globs: &[String], check: &str, side: &str) -> anyhow::Result<Vec<Regex>> {
    let patterns: Vec<String> = globs
        .iter()
        .map(|glob| {
            glob.split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("[^/]+")
        })
        .collect();
    compile_anchored(&patterns, &format!("filter.check.{check}.{side}"))
}

#[async_trait]
impl Check for PathList {
    fn kind(&self) -> &'static str {
        "path"
    }

    /// Connection only: by the identifier stage the path is always one of
    /// `/newOrder` or `/finalize/{id}`, so a rule combining this with a name
    /// check would be asking a question with a constant answer.
    fn stages(&self) -> StageSet {
        StageSet::connection_only()
    }

    async fn check_connection(&self, context: &ConnectionContext<'_>) -> Verdict {
        let path = context.path;
        match check_lists(&self.allow, &self.deny, |pattern| pattern.is_match(path)) {
            ListVerdict::Permitted => Verdict::Pass,
            ListVerdict::Denied => Verdict::Fail(format!("path {path} is denied")),
            ListVerdict::NotAllowed => Verdict::Fail(format!("path {path} is not allowed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    fn settings(allow: &[&str], deny: &[&str]) -> Settings {
        Settings {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    fn built(allow: &[&str], deny: &[&str]) -> PathList {
        PathList::from_settings("paths", &settings(allow, deny)).unwrap()
    }

    async fn verdict_for(check: &PathList, path: &str) -> Verdict {
        check
            .check_connection(&ConnectionContext {
                client_ip: Some("10.0.0.5".parse().unwrap()),
                method: &Method::GET,
                path,
            })
            .await
    }

    #[tokio::test]
    async fn an_exact_path_matches_only_itself() {
        let check = built(&["/crl"], &[]);
        assert_eq!(verdict_for(&check, "/crl").await, Verdict::Pass);
        assert!(matches!(
            verdict_for(&check, "/crl/extra").await,
            Verdict::Fail(_)
        ));
        assert!(matches!(
            verdict_for(&check, "/directory").await,
            Verdict::Fail(_)
        ));
    }

    /// The capability the exact-match list it replaces did not have. `*` stops
    /// at `/`, so it is one segment rather than a wildcard over the rest.
    #[tokio::test]
    async fn a_glob_star_matches_exactly_one_path_segment() {
        let check = built(&["/renewalInfo/*"], &[]);
        assert_eq!(
            verdict_for(&check, "/renewalInfo/abc123").await,
            Verdict::Pass
        );
        assert!(matches!(
            verdict_for(&check, "/renewalInfo/abc/def").await,
            Verdict::Fail(_)
        ));
        assert!(matches!(
            verdict_for(&check, "/renewalInfo/").await,
            Verdict::Fail(_)
        ));
    }

    #[tokio::test]
    async fn deny_wins_and_names_which_list_bit() {
        let check = built(&["/*"], &["/revokeCert"]);
        assert_eq!(verdict_for(&check, "/directory").await, Verdict::Pass);
        match verdict_for(&check, "/revokeCert").await {
            Verdict::Fail(detail) => assert!(detail.contains("is denied"), "{detail}"),
            other => panic!("expected Fail, got {other:?}"),
        }

        let allow_only = built(&["/crl"], &[]);
        match verdict_for(&allow_only, "/newOrder").await {
            Verdict::Fail(detail) => assert!(detail.contains("is not allowed"), "{detail}"),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_deny_only_check_permits_everything_else() {
        let check = built(&[], &["/revokeCert"]);
        assert_eq!(verdict_for(&check, "/directory").await, Verdict::Pass);
        assert!(matches!(
            verdict_for(&check, "/revokeCert").await,
            Verdict::Fail(_)
        ));
    }

    /// Nothing in a glob but `*` is a metacharacter, so a path holding regex
    /// syntax cannot smuggle a pattern in.
    #[tokio::test]
    async fn every_other_character_is_literal() {
        let check = built(&["/a.b"], &[]);
        assert_eq!(verdict_for(&check, "/a.b").await, Verdict::Pass);
        assert!(matches!(
            verdict_for(&check, "/axb").await,
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn an_empty_check_is_a_startup_error() {
        let error = PathList::from_settings("paths", &Settings::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("would match every request"), "{error}");
        assert!(error.contains("filter.check.paths"), "{error}");
    }

    #[test]
    fn reports_its_type_and_stages() {
        let check = built(&["/crl"], &[]);
        assert_eq!(check.kind(), "path");
        assert_eq!(check.stages(), StageSet::connection_only());
    }
}
