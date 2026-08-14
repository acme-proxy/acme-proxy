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

use std::collections::BTreeSet;

use async_trait::async_trait;
use regex::Regex;
use tracing::info;

use super::{
    Filter, FilterError, IdentifierContext, ListVerdict, SUBJECT_ONLY_TYPES, check_lists,
    compile_anchored,
};
use crate::config::IdentifierListConfig;

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
    pub fn from_config(cfg: &IdentifierListConfig) -> anyhow::Result<Self> {
        let filter = Self {
            allowed_types: cfg
                .allowed_types
                .iter()
                .map(|typ| typ.to_ascii_lowercase())
                .collect(),
            allow: compile_anchored(&cfg.allow, "filter.identifiers.allow")?,
            deny: compile_anchored(&cfg.deny, "filter.identifiers.deny")?,
            allow_wildcards: cfg.allow_wildcards,
        };
        info!(
            event = "filter_identifiers_loaded",
            outcome = "success",
            allowed_types = ?cfg.allowed_types,
            allow = cfg.allow.len(),
            deny = cfg.deny.len(),
            allow_wildcards = cfg.allow_wildcards,
        );
        Ok(filter)
    }
}

#[async_trait]
impl Filter for IdentifierList {
    fn name(&self) -> &'static str {
        "identifiers"
    }

    async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        let stage = ctx.stage.as_str();

        for identifier in ctx.identifiers {
            let typ = identifier.typ.to_ascii_lowercase();
            if !self.allowed_types.contains(&typ) {
                return Err(FilterError::Denied(format!(
                    "{stage} requests a {} identifier, which is not permitted",
                    identifier.typ
                )));
            }

            let value = &identifier.value;

            // A wildcard covers every name under a domain, but reads to an
            // anchored pattern as the literal string `*.example.com` — so it
            // slips past a deny rule for a name it then certifies. Refused
            // before the lists are consulted, unless the operator has said the
            // patterns account for it.
            if !self.allow_wildcards && typ == "dns" && value.starts_with("*.") {
                return Err(FilterError::Denied(format!(
                    "{stage} identifier {value} is a wildcard, which policy does not permit"
                )));
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
                    return Err(FilterError::Denied(format!(
                        "{stage} identifier {value} is denied by policy"
                    )));
                }
                ListVerdict::NotAllowed => {
                    return Err(FilterError::Denied(format!(
                        "{stage} identifier {value} is not permitted by policy"
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{ConnectionContext, IdentifierStage};
    use crate::sqlite::order::Identifier;
    use axum::http::Method;

    fn config(allow: &[&str], deny: &[&str]) -> IdentifierListConfig {
        IdentifierListConfig {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
            ..IdentifierListConfig::default()
        }
    }

    use crate::testutil::identifiers as ids;

    async fn check(
        filter: &IdentifierList,
        stage: IdentifierStage,
        identifiers: &[Identifier],
    ) -> Result<(), FilterError> {
        filter
            .check_identifiers(&IdentifierContext {
                client_ip: None,
                account_id: "acct-1",
                stage,
                identifiers,
            })
            .await
    }

    fn assert_denied(error: FilterError, needle: &str) {
        match error {
            FilterError::Denied(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_empty_allow_list_permits_any_allowed_type() {
        let filter = IdentifierList::from_config(&IdentifierListConfig::default()).unwrap();
        let identifiers = ids(&[("dns", "anything.example.com"), ("cn", "other.test")]);
        assert!(
            check(&filter, IdentifierStage::NewOrder, &identifiers)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_allow_list_refuses_everything_else() {
        let filter = IdentifierList::from_config(&config(&[r".*\.example\.com"], &[])).unwrap();
        assert!(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.example.com")])
            )
            .await
            .is_ok()
        );
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.evil.net")]),
            )
            .await
            .unwrap_err(),
            "not permitted by policy",
        );
    }

    #[tokio::test]
    async fn deny_wins_over_allow() {
        let filter =
            IdentifierList::from_config(&config(&[r".*\.example\.com"], &[r"secret\..*"])).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "secret.example.com")]),
            )
            .await
            .unwrap_err(),
            "is denied by policy",
        );
    }

    #[tokio::test]
    async fn patterns_are_anchored_so_a_suffix_cannot_bypass_them() {
        let filter = IdentifierList::from_config(&config(&[r"example\.com"], &[])).unwrap();
        // Unanchored, this would have been accepted.
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "example.com.evil.net")]),
            )
            .await
            .unwrap_err(),
            "not permitted",
        );
    }

    #[tokio::test]
    async fn matching_ignores_case() {
        let filter = IdentifierList::from_config(&config(&[], &[r"secret\.example\.com"])).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "SECRET.Example.COM")]),
            )
            .await
            .unwrap_err(),
            "is denied",
        );
    }

    #[tokio::test]
    async fn an_ip_san_is_refused_by_the_default_allowed_types() {
        let filter = IdentifierList::from_config(&IdentifierListConfig::default()).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("ip", "10.0.0.1")]),
            )
            .await
            .unwrap_err(),
            "requests a ip identifier",
        );
    }

    #[tokio::test]
    async fn email_and_uri_sans_are_refused_too() {
        let filter = IdentifierList::from_config(&IdentifierListConfig::default()).unwrap();
        for identifier in [("email", "a@example.com"), ("uri", "https://example.com")] {
            assert_denied(
                check(&filter, IdentifierStage::Csr, &ids(&[identifier]))
                    .await
                    .unwrap_err(),
                "is not permitted",
            );
        }
    }

    #[tokio::test]
    async fn an_operator_can_opt_into_ip_identifiers() {
        let cfg = IdentifierListConfig {
            allowed_types: vec!["dns".to_string(), "ip".to_string()],
            allow: vec![r"10\..*".to_string(), r".*\.example\.com".to_string()],
            ..IdentifierListConfig::default()
        };
        let filter = IdentifierList::from_config(&cfg).unwrap();
        assert!(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("ip", "10.0.0.1"), ("dns", "a.example.com")])
            )
            .await
            .is_ok()
        );
    }

    /// The regression this guards: patterns are anchored, so a deny rule for
    /// `secret.example.com` never matches the string `*.example.com` — while the
    /// certificate it yields covers that name. Enabling `dns-01` must not widen
    /// an existing list by itself.
    #[tokio::test]
    async fn a_wildcard_is_refused_by_default_even_when_the_lists_would_permit_it() {
        let filter = IdentifierList::from_config(&config(&[], &[r"secret\.example\.com"])).unwrap();

        // The deny pattern does not match the wildcard string...
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.example.com")]),
            )
            .await
            .unwrap_err(),
            "is a wildcard",
        );
        // ...and the name it would cover is still denied on its own.
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "secret.example.com")]),
            )
            .await
            .unwrap_err(),
            "denied by policy",
        );
    }

    /// Opting in puts wildcards back under the ordinary list rules — including
    /// `deny`, which an operator can then write against the `*.` form.
    #[tokio::test]
    async fn an_operator_can_opt_into_wildcards() {
        let cfg = IdentifierListConfig {
            allow: vec![r"\*\.example\.com".to_string()],
            deny: vec![r"\*\.internal\.example".to_string()],
            allow_wildcards: true,
            ..IdentifierListConfig::default()
        };
        let filter = IdentifierList::from_config(&cfg).unwrap();

        assert!(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.example.com")])
            )
            .await
            .is_ok()
        );
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "*.internal.example")]),
            )
            .await
            .unwrap_err(),
            "denied by policy",
        );
    }

    /// The wildcard check is about `dns` values, not about a literal asterisk
    /// anywhere: a common name is subject metadata and may well be a label.
    #[tokio::test]
    async fn the_wildcard_check_does_not_reach_the_common_name() {
        let filter = IdentifierList::from_config(&IdentifierListConfig::default()).unwrap();
        assert!(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "example.com"), ("cn", "*.example.com")])
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn deny_reaches_the_common_name() {
        // The bypass this closes: a benign SAN with the real target in the CN.
        let filter = IdentifierList::from_config(&config(&[], &[r"secret\.example\.com"])).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "secret.example.com")]),
            )
            .await
            .unwrap_err(),
            "is denied by policy",
        );
    }

    /// `allow` lists domains, but a common name is frequently a human label —
    /// `rcgen`'s own default is `rcgen self signed cert`. Holding the CN to a
    /// domain allowlist would reject valid requests without gaining anything,
    /// since the SANs are constrained separately.
    #[tokio::test]
    async fn allow_does_not_constrain_the_common_name() {
        let filter = IdentifierList::from_config(&config(&[r".*\.example\.com"], &[])).unwrap();
        assert!(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "ok.example.com"), ("cn", "rcgen self signed cert")])
            )
            .await
            .is_ok()
        );
    }

    /// …but the SANs still are, even when the CN would have satisfied the list.
    #[tokio::test]
    async fn allow_still_constrains_the_sans() {
        let filter = IdentifierList::from_config(&config(&[r".*\.example\.com"], &[])).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "evil.net"), ("cn", "ok.example.com")]),
            )
            .await
            .unwrap_err(),
            "evil.net is not permitted",
        );
    }

    /// A common name is still subject to `allowed_types`.
    #[tokio::test]
    async fn the_common_name_can_be_disallowed_by_type() {
        let cfg = IdentifierListConfig {
            allowed_types: vec!["dns".to_string()],
            ..IdentifierListConfig::default()
        };
        let filter = IdentifierList::from_config(&cfg).unwrap();
        assert_denied(
            check(&filter, IdentifierStage::Csr, &ids(&[("cn", "anything")]))
                .await
                .unwrap_err(),
            "requests a cn identifier",
        );
    }

    #[tokio::test]
    async fn the_stage_appears_in_the_detail() {
        let filter = IdentifierList::from_config(&config(&[], &[r".*"])).unwrap();
        assert_denied(
            check(
                &filter,
                IdentifierStage::NewOrder,
                &ids(&[("dns", "a.example.com")]),
            )
            .await
            .unwrap_err(),
            "newOrder identifier",
        );
        assert_denied(
            check(
                &filter,
                IdentifierStage::Csr,
                &ids(&[("dns", "a.example.com")]),
            )
            .await
            .unwrap_err(),
            "CSR identifier",
        );
    }

    #[tokio::test]
    async fn an_empty_identifier_list_is_allowed() {
        let filter = IdentifierList::from_config(&config(&[r"nothing"], &[])).unwrap();
        assert!(check(&filter, IdentifierStage::Csr, &[]).await.is_ok());
    }

    #[tokio::test]
    async fn does_not_inspect_connections() {
        let filter = IdentifierList::from_config(&config(&[], &[r".*"])).unwrap();
        let allowed = filter
            .check_connection(&ConnectionContext {
                client_ip: None,
                method: &Method::POST,
                path: "/newOrder",
            })
            .await;
        assert!(allowed.is_ok());
    }

    #[test]
    fn a_bad_pattern_is_a_startup_error() {
        let error = IdentifierList::from_config(&config(&[], &["[unclosed"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.identifiers.deny"), "{error}");
    }

    #[test]
    fn reports_its_config_name() {
        let filter = IdentifierList::from_config(&IdentifierListConfig::default()).unwrap();
        assert_eq!(filter.name(), "identifiers");
    }
}
