//! The `identifiers` filter: which names a client may have certified.
//!
//! Runs twice per order — against the `newOrder` identifiers, then against the
//! names the finalize CSR actually requests. The first check is the useful
//! error (the client learns immediately, before doing the challenge dance); the
//! second is the one that is load-bearing, because the CSR is what gets signed.
//!
//! ## Types matter as much as values
//!
//! A CSR is not a list of hostnames. Its subject alternative names can be IP
//! addresses, email addresses or URIs, and its subject can carry a common name
//! that no SAN mentions. All of them are projected into the same
//! [`Identifier`](crate::sqlite::order::Identifier) list by the caller (see
//! `csr_identifiers` in [`crate::handlers`]), so a
//! `deny` pattern cannot be sidestepped by moving a name from a DNS SAN to the
//! common name, or from a DNS SAN to an IP SAN.
//!
//! `allowed_types` is the front door for that: it defaults to `["dns", "cn"]`,
//! so a CSR asking for an IP address is refused outright rather than being
//! matched against hostname regexes that were never written with addresses in
//! mind.
//!
//! ## Why `allow` and `deny` have different reach
//!
//! `deny` applies to **every** projected identifier, the common name included.
//! It means "never certify this string", and the broadest possible reading is
//! the useful one — otherwise a denied name could ride along in the subject.
//!
//! `allow` applies only to the identifiers a certificate is actually *for*,
//! i.e. those derived from subject alternative names. The common name is legacy
//! subject metadata rather than a name being certified (RFC 6125 deprecated
//! relying on it, and it is only honoured at all when no SAN is present), and
//! real-world CSR generators routinely put a human label there —
//! `rcgen`'s own default is the string `rcgen self signed cert`. Requiring that
//! to match a list of domain patterns would reject perfectly valid requests
//! without making anything safer, because the SANs are separately constrained.
//!
//! ## Why wildcards are refused by default
//!
//! Patterns are anchored, so a `deny` entry of `secret\.example\.com` does *not*
//! match the string `*.example.com` — yet a certificate for that wildcard covers
//! `secret.example.com` perfectly well. An operator relying on a deny list would
//! find it silently widened the day `dns-01` was enabled and wildcards became
//! orderable at all.
//!
//! `allow_wildcards` therefore defaults to `false`: a `dns` value beginning
//! `*.` is refused before the lists are consulted. Turning it on is a statement
//! that the patterns were written with the wildcard form in mind.
//!
//! ## Globs first, regexes on request
//!
//! `allow`/`deny` take globs (`*.example.com`), where `*` matches one label —
//! the wildcard semantics an operator already knows from certificates.
//! `allow_regex`/`deny_regex` take the anchored regexes this check used to
//! require. The two are unioned, so a policy can be mostly globs with one
//! regex where a glob will not do. Regex is the sharper tool and the anchoring
//! footgun above is why it is no longer the only one.

use std::collections::BTreeSet;

use async_trait::async_trait;
use regex::Regex;
use tracing::info;

use super::policy::{Check, StageSet, Verdict};
use super::{
    IdentifierContext, ListVerdict, SUBJECT_ONLY_TYPES, check_lists, compile_matchers,
    default_identifier_types,
};

/// Resolved `[filter.check.<name>]` settings for `type = "identifiers"`.
#[derive(Debug, Clone)]
pub struct Settings {
    pub allowed_types: Vec<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_regex: Vec<String>,
    pub deny_regex: Vec<String>,
    pub allow_wildcards: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allowed_types: default_identifier_types(),
            allow: Vec::new(),
            deny: Vec::new(),
            allow_regex: Vec::new(),
            deny_regex: Vec::new(),
            allow_wildcards: false,
        }
    }
}

/// Accepts or refuses each requested name by type, then by pattern.
#[derive(Debug)]
pub struct IdentifierList {
    allowed_types: BTreeSet<String>,
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    allow_wildcards: bool,
}

impl IdentifierList {
    /// Compiles the patterns, failing startup on a bad one.
    pub fn from_settings(name: &str, settings: &Settings) -> anyhow::Result<Self> {
        let check = Self {
            allowed_types: settings
                .allowed_types
                .iter()
                .map(|typ| typ.to_ascii_lowercase())
                .collect(),
            allow: compile_matchers(&settings.allow, &settings.allow_regex, name, "allow")?,
            deny: compile_matchers(&settings.deny, &settings.deny_regex, name, "deny")?,
            allow_wildcards: settings.allow_wildcards,
        };
        info!(
            event = "filter_identifiers_loaded",
            outcome = "success",
            check = name,
            allowed_types = ?settings.allowed_types,
            allow = check.allow.len(),
            deny = check.deny.len(),
            allow_wildcards = settings.allow_wildcards,
        );
        Ok(check)
    }

    fn decide(&self, context: &IdentifierContext<'_>) -> Verdict {
        let stage = context.stage.as_str();

        for identifier in context.identifiers {
            let typ = identifier.typ.to_ascii_lowercase();
            if !self.allowed_types.contains(&typ) {
                return Verdict::Fail(format!(
                    "{stage} requests a {} identifier, which is not permitted",
                    identifier.typ
                ));
            }

            let value = &identifier.value;

            // A wildcard covers every name under a domain, but reads to an
            // anchored pattern as the literal string `*.example.com` — so it
            // slips past a deny rule for a name it then certifies. Refused
            // before the lists are consulted, unless the operator has said the
            // patterns account for it.
            if !self.allow_wildcards && typ == "dns" && value.starts_with("*.") {
                return Verdict::Fail(format!(
                    "{stage} identifier {value} is a wildcard, which policy does not permit"
                ));
            }

            // Deny reaches everything, including the subject common name, and
            // wins over allow: an operator who lists something explicitly means
            // it, even if a broad allow entry would also have matched. Allow, by
            // contrast, constrains only the names the certificate is issued
            // *for*, so a subject-only type skips it — hence the empty slice.
            let allow: &[Regex] = if SUBJECT_ONLY_TYPES.contains(&typ.as_str()) {
                &[]
            } else {
                &self.allow
            };

            match check_lists(allow, &self.deny, |pattern| pattern.is_match(value)) {
                ListVerdict::Permitted => {}
                ListVerdict::Denied => {
                    return Verdict::Fail(format!(
                        "{stage} identifier {value} is denied by policy"
                    ));
                }
                ListVerdict::NotAllowed => {
                    return Verdict::Fail(format!(
                        "{stage} identifier {value} is not permitted by policy"
                    ));
                }
            }
        }

        Verdict::Pass
    }
}

#[async_trait]
impl Check for IdentifierList {
    fn kind(&self) -> &'static str {
        "identifiers"
    }

    fn stages(&self) -> StageSet {
        StageSet::identifiers_only()
    }

    async fn check_identifiers(&self, context: &IdentifierContext<'_>) -> Verdict {
        self.decide(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::IdentifierStage;
    use crate::sqlite::order::Identifier;
    use crate::testutil::identifiers as ids;

    fn globs(allow: &[&str], deny: &[&str]) -> Settings {
        Settings {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
            ..Settings::default()
        }
    }

    fn regexes(allow: &[&str], deny: &[&str]) -> Settings {
        Settings {
            allow_regex: allow.iter().map(std::string::ToString::to_string).collect(),
            deny_regex: deny.iter().map(std::string::ToString::to_string).collect(),
            ..Settings::default()
        }
    }

    fn built(settings: &Settings) -> IdentifierList {
        IdentifierList::from_settings("names", settings).unwrap()
    }

    async fn verdict_for(
        check: &IdentifierList,
        stage: IdentifierStage,
        identifiers: &[Identifier],
    ) -> Verdict {
        check
            .check_identifiers(&IdentifierContext {
                client_ip: None,
                account_id: "acct-1",
                stage,
                identifiers,

                eab: None,
            })
            .await
    }

    fn assert_failed(verdict: Verdict, needle: &str) {
        match verdict {
            Verdict::Fail(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    // ---- globs, the default spelling --------------------------------------

    /// `*` is one label, matching the wildcard semantics of a certificate —
    /// which is the whole reason globs are the default and regexes the opt-in.
    #[tokio::test]
    async fn a_glob_star_matches_exactly_one_label() {
        let check = built(&globs(&["*.example.com"], &[]));

        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.example.com")])
            )
            .await,
            Verdict::Pass
        );
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.b.example.com")]),
            )
            .await,
            "not permitted by policy",
        );
        // The bare name is a separate entry, exactly as in a certificate.
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "example.com")]),
            )
            .await,
            "not permitted by policy",
        );
    }

    #[tokio::test]
    async fn listing_the_bare_name_beside_the_glob_covers_both() {
        let check = built(&globs(&["*.example.com", "example.com"], &[]));
        for name in ["a.example.com", "example.com"] {
            assert_eq!(
                verdict_for(&check, IdentifierStage::NewOrder, &ids(&[("dns", name)])).await,
                Verdict::Pass,
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_glob_ignores_case_and_a_trailing_dot_is_not_special() {
        let check = built(&globs(&["*.example.com"], &[]));
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "A.Example.COM")])
            )
            .await,
            Verdict::Pass
        );
    }

    /// Everything that is not `*` is literal, so a name that happens to hold
    /// regex metacharacters cannot smuggle a pattern in.
    #[tokio::test]
    async fn a_glob_escapes_every_other_metacharacter() {
        let check = built(&globs(&["a.example.com"], &[]));
        // `.` must not match an arbitrary character.
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "axexample.com")]),
            )
            .await,
            "not permitted",
        );
    }

    #[tokio::test]
    async fn a_glob_deny_wins_over_a_glob_allow() {
        let check = built(&globs(&["*.example.com"], &["secret.example.com"]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "secret.example.com")]),
            )
            .await,
            "is denied by policy",
        );
    }

    /// The two spellings are one list each, so a policy can be mostly globs
    /// with one regex where a glob will not do.
    #[tokio::test]
    async fn globs_and_regexes_are_unioned_on_both_sides() {
        let settings = Settings {
            allow: vec!["*.example.com".to_string()],
            allow_regex: vec![r"host\d+\.internal".to_string()],
            deny: vec!["secret.example.com".to_string()],
            deny_regex: vec![r"host666\.internal".to_string()],
            ..Settings::default()
        };
        let check = built(&settings);

        for permitted in ["a.example.com", "host12.internal"] {
            assert_eq!(
                verdict_for(
                    &check,
                    IdentifierStage::NewOrder,
                    &ids(&[("dns", permitted)])
                )
                .await,
                Verdict::Pass,
                "{permitted}"
            );
        }
        for refused in ["secret.example.com", "host666.internal"] {
            assert_failed(
                verdict_for(&check, IdentifierStage::NewOrder, &ids(&[("dns", refused)])).await,
                "is denied by policy",
            );
        }
    }

    #[tokio::test]
    async fn a_glob_allow_skips_the_common_name_but_a_glob_deny_reaches_it() {
        let check = built(&globs(&["*.example.com"], &["secret.example.com"]));

        // `allow` does not constrain subject metadata...
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "rcgen self signed cert")])
            )
            .await,
            Verdict::Pass
        );
        // ...but `deny` does.
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "secret.example.com")]),
            )
            .await,
            "is denied by policy",
        );
    }

    // ---- the list semantics -----------------------------------------------

    #[tokio::test]
    async fn an_empty_allow_list_permits_any_allowed_type() {
        let check = built(&Settings::default());
        let identifiers = ids(&[("dns", "anything.example.com"), ("cn", "other.test")]);
        assert_eq!(
            verdict_for(&check, IdentifierStage::NewOrder, &identifiers).await,
            Verdict::Pass
        );
    }

    #[tokio::test]
    async fn the_allow_list_refuses_everything_else() {
        let check = built(&regexes(&[r".*\.example\.com"], &[]));
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.example.com")])
            )
            .await,
            Verdict::Pass
        );
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.evil.net")]),
            )
            .await,
            "not permitted by policy",
        );
    }

    #[tokio::test]
    async fn deny_wins_over_allow() {
        let check = built(&regexes(&[r".*\.example\.com"], &[r"secret\..*"]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "secret.example.com")]),
            )
            .await,
            "is denied by policy",
        );
    }

    #[tokio::test]
    async fn patterns_are_anchored_so_a_suffix_cannot_bypass_them() {
        let check = built(&regexes(&[r"example\.com"], &[]));
        // Unanchored, this would have been accepted.
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "example.com.evil.net")]),
            )
            .await,
            "not permitted",
        );
    }

    #[tokio::test]
    async fn matching_ignores_case() {
        let check = built(&regexes(&[], &[r"secret\.example\.com"]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "SECRET.Example.COM")]),
            )
            .await,
            "is denied",
        );
    }

    #[tokio::test]
    async fn an_ip_san_is_refused_by_the_default_allowed_types() {
        let check = built(&Settings::default());
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("ip", "10.0.0.1")]),
            )
            .await,
            "requests a ip identifier",
        );
    }

    #[tokio::test]
    async fn email_and_uri_sans_are_refused_too() {
        let check = built(&Settings::default());
        for identifier in [("email", "a@example.com"), ("uri", "https://example.com")] {
            assert_failed(
                verdict_for(&check, IdentifierStage::Csr, &ids(&[identifier])).await,
                "is not permitted",
            );
        }
    }

    #[tokio::test]
    async fn an_operator_can_opt_into_ip_identifiers() {
        let settings = Settings {
            allowed_types: vec!["dns".to_string(), "ip".to_string()],
            allow_regex: vec![r"10\..*".to_string(), r".*\.example\.com".to_string()],
            ..Settings::default()
        };
        let check = built(&settings);
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("ip", "10.0.0.1"), ("dns", "a.example.com")])
            )
            .await,
            Verdict::Pass
        );
    }

    // ---- wildcards --------------------------------------------------------

    /// The regression this guards: patterns are anchored, so a deny rule for
    /// `secret.example.com` never matches the string `*.example.com` — while the
    /// certificate it yields covers that name. Enabling `dns-01` must not widen
    /// an existing list by itself.
    #[tokio::test]
    async fn a_wildcard_is_refused_by_default_even_when_the_lists_would_permit_it() {
        let check = built(&regexes(&[], &[r"secret\.example\.com"]));

        // The deny pattern does not match the wildcard string...
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.example.com")]),
            )
            .await,
            "is a wildcard",
        );
        // ...and the name it would cover is still denied on its own.
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "secret.example.com")]),
            )
            .await,
            "denied by policy",
        );
    }

    /// Opting in puts wildcards back under the ordinary list rules — including
    /// `deny`, which an operator can then write against the `*.` form.
    #[tokio::test]
    async fn an_operator_can_opt_into_wildcards() {
        let settings = Settings {
            allow_regex: vec![r"\*\.example\.com".to_string()],
            deny_regex: vec![r"\*\.internal\.example".to_string()],
            allow_wildcards: true,
            ..Settings::default()
        };
        let check = built(&settings);

        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.example.com")])
            )
            .await,
            Verdict::Pass
        );
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.internal.example")]),
            )
            .await,
            "denied by policy",
        );
    }

    /// A glob is literal outside `*`, so the wildcard form can be listed as a
    /// glob too once `allow_wildcards` is on.
    #[tokio::test]
    async fn a_glob_can_name_the_wildcard_form_itself() {
        let settings = Settings {
            allow: vec!["*.example.com".to_string()],
            allow_wildcards: true,
            ..Settings::default()
        };
        let check = built(&settings);
        // `*` in the glob matches the literal `*` label of the identifier.
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.example.com")])
            )
            .await,
            Verdict::Pass
        );
    }

    /// The wildcard check is about `dns` values, not about a literal asterisk
    /// anywhere: a common name is subject metadata and may well be a label.
    #[tokio::test]
    async fn the_wildcard_check_does_not_reach_the_common_name() {
        let check = built(&Settings::default());
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "example.com"), ("cn", "*.example.com")])
            )
            .await,
            Verdict::Pass
        );
    }

    // ---- allow versus deny reach ------------------------------------------

    #[tokio::test]
    async fn deny_reaches_the_common_name() {
        // The bypass this closes: a benign SAN with the real target in the CN.
        let check = built(&regexes(&[], &[r"secret\.example\.com"]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "secret.example.com")]),
            )
            .await,
            "is denied by policy",
        );
    }

    /// `allow` lists domains, but a common name is frequently a human label —
    /// `rcgen`'s own default is `rcgen self signed cert`. Holding the CN to a
    /// domain allowlist would reject valid requests without gaining anything,
    /// since the SANs are constrained separately.
    #[tokio::test]
    async fn allow_does_not_constrain_the_common_name() {
        let check = built(&regexes(&[r".*\.example\.com"], &[]));
        assert_eq!(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "rcgen self signed cert")])
            )
            .await,
            Verdict::Pass
        );
    }

    /// …but the SANs still are, even when the CN would have satisfied the list.
    #[tokio::test]
    async fn allow_still_constrains_the_sans() {
        let check = built(&regexes(&[r".*\.example\.com"], &[]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "evil.net"), ("cn", "ok.example.com")]),
            )
            .await,
            "evil.net is not permitted",
        );
    }

    /// A common name is still subject to `allowed_types`.
    #[tokio::test]
    async fn the_common_name_can_be_disallowed_by_type() {
        let settings = Settings {
            allowed_types: vec!["dns".to_string()],
            ..Settings::default()
        };
        let check = built(&settings);
        assert_failed(
            verdict_for(&check, IdentifierStage::Csr, &ids(&[("cn", "anything")])).await,
            "requests a cn identifier",
        );
    }

    #[tokio::test]
    async fn the_stage_appears_in_the_detail() {
        let check = built(&regexes(&[], &[r".*"]));
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.example.com")]),
            )
            .await,
            "newOrder identifier",
        );
        assert_failed(
            verdict_for(
                &check,
                IdentifierStage::Csr,
                &ids(&[("dns", "a.example.com")]),
            )
            .await,
            "CSR identifier",
        );
    }

    #[tokio::test]
    async fn an_empty_identifier_list_is_allowed() {
        let check = built(&regexes(&["nothing"], &[]));
        assert_eq!(
            verdict_for(&check, IdentifierStage::Csr, &[]).await,
            Verdict::Pass
        );
    }

    // ---- startup ----------------------------------------------------------

    #[test]
    fn a_bad_pattern_is_a_startup_error() {
        let error = IdentifierList::from_settings("names", &regexes(&[], &["[unclosed"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.check.names.deny_regex"), "{error}");
    }

    #[test]
    fn reports_its_type_and_stages() {
        let check = built(&Settings::default());
        assert_eq!(check.kind(), "identifiers");
        assert_eq!(check.stages(), StageSet::identifiers_only());
    }

    #[test]
    fn the_default_settings_permit_dns_names_and_common_names() {
        assert_eq!(Settings::default().allowed_types, vec!["dns", "cn"]);
        assert!(!Settings::default().allow_wildcards);
    }
}
