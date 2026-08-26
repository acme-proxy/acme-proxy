//! The `eab` check: which credential the account was registered under.
//!
//! The multi-tenant lever. An External Account Binding credential is minted out
//! of band by `acme-proxy eab create --label <text>`, **before any account
//! exists**, so its label is a handle an operator can put in configuration up
//! front — unlike an account id, which is a generated UUID you could only
//! discover after the fact. Credentials are deliberately reusable, so one label
//! naturally names a tenant:
//!
//! ```toml
//! [filter.check.tenant-a]
//! type  = "eab"
//! allow = ["tenant-a"]
//!
//! [filter.check.tenant-a-names]
//! type  = "identifiers"
//! allow = ["*.tenant-a.example.com"]
//!
//! [filter.rule.tenant-a]
//! when = "tenant-a and tenant-a-names"
//! then = "allow"
//! ```
//!
//! It costs no schema change: `accounts.eab_kid` has recorded this since EAB
//! was implemented. That column's own migration calls it "an audit trail only";
//! this promotes it to a policy input, which is a change in what the column
//! *means* rather than in what it holds.
//!
//! ## Fail-closed on an account with no credential
//!
//! An account registered without EAB has no kid, and this check refuses it.
//! That is the only defensible reading: the question is "which credential
//! authorised this account", and "none" is not an answer that can satisfy a
//! tenant rule. It also means an `eab` check while `eab.enabled` is off could
//! never do anything but refuse, which is a startup error rather than a policy.
//!
//! ## `require_active`
//!
//! Revoking an EAB credential stops new *registrations*; accounts already
//! created under it keep issuing for ever, which is what the column's
//! audit-trail-only framing implied. `require_active = true` changes that for
//! this check, so revocation reaches existing accounts too. Off by default,
//! because turning it on retroactively changes what `eab revoke` means — it is
//! the lever an operator reaches for when a tenant's credential leaks.

use std::collections::BTreeSet;

use async_trait::async_trait;
use regex::Regex;
use tracing::info;

use super::policy::{Check, StageSet, Verdict};
use super::{IdentifierContext, ListVerdict, check_lists, compile_matchers};

/// What the handler resolved about the credential an account registered under.
///
/// Present on [`IdentifierContext`] only when the policy contains an `eab`
/// check — see [`FilterPolicy::needs_eab`](super::FilterPolicy::needs_eab) —
/// so a policy without one pays for no lookup.
#[derive(Debug, Clone)]
pub struct EabIdentity {
    pub kid: String,
    /// The operator's label, if the credential was minted with one.
    pub label: Option<String>,
    /// Whether the credential is still `active` rather than revoked.
    pub active: bool,
}

/// Resolved `[filter.check.<name>]` settings for `type = "eab"`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_regex: Vec<String>,
    pub deny_regex: Vec<String>,
    pub kids: Vec<String>,
    pub require_active: bool,
}

/// Accepts or refuses by the EAB credential behind the requesting account.
#[derive(Debug)]
pub struct EabList {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    kids: BTreeSet<String>,
    require_active: bool,
}

impl EabList {
    /// Compiles the label patterns, failing startup on an inert check.
    pub fn from_settings(name: &str, settings: &Settings) -> anyhow::Result<Self> {
        if settings.allow.is_empty()
            && settings.deny.is_empty()
            && settings.allow_regex.is_empty()
            && settings.deny_regex.is_empty()
            && settings.kids.is_empty()
            && !settings.require_active
        {
            anyhow::bail!(
                "filter.check.{name} names no labels, no kids and does not set \
                 require_active, so it only asks whether the account used EAB at all; \
                 list the credentials it is about, or drop the check"
            );
        }

        let check = Self {
            allow: compile_matchers(&settings.allow, &settings.allow_regex, name, "allow")?,
            deny: compile_matchers(&settings.deny, &settings.deny_regex, name, "deny")?,
            kids: settings.kids.iter().cloned().collect(),
            require_active: settings.require_active,
        };
        info!(
            event = "filter_eab_loaded",
            outcome = "success",
            check = name,
            allow = check.allow.len(),
            deny = check.deny.len(),
            kids = check.kids.len(),
            require_active = settings.require_active,
        );
        Ok(check)
    }

    fn decide(&self, context: &IdentifierContext<'_>) -> Verdict {
        let stage = context.stage.as_str();

        let Some(eab) = context.eab.as_ref() else {
            return Verdict::Fail(format!(
                "{stage} comes from an account that was not registered under an external \
                 account binding"
            ));
        };

        if self.require_active && !eab.active {
            return Verdict::Fail(format!(
                "the external account binding {} this account registered under has been \
                 revoked",
                eab.kid
            ));
        }

        // `deny` reads the label, which is the only operator-authored handle a
        // credential carries. A credential with no label can never match one.
        let label = eab.label.as_deref().unwrap_or_default();
        if check_lists(&[], &self.deny, |pattern: &Regex| pattern.is_match(label))
            == ListVerdict::Denied
        {
            return Verdict::Fail(format!(
                "{stage} comes from external account binding {}, which policy refuses",
                describe(eab)
            ));
        }

        // `kids` is a second *allow* source rather than a separate gate: an
        // operator either names the tenant by its label or pins the credential
        // itself, and either should be enough.
        let constrained = !self.allow.is_empty() || !self.kids.is_empty();
        if constrained {
            let permitted = self.kids.contains(&eab.kid.to_string())
                || (eab.label.is_some() && self.allow.iter().any(|p| p.is_match(label)));
            if !permitted {
                return Verdict::Fail(format!(
                    "{stage} comes from external account binding {}, which is not one this \
                     policy permits",
                    describe(eab)
                ));
            }
        }

        Verdict::Pass
    }
}

/// How a credential is named in a refusal: its label if it has one, else its
/// kid, which is at least greppable in `acme-proxy eab list`.
fn describe(eab: &EabIdentity) -> String {
    eab.label
        .as_deref()
        .map_or_else(|| eab.kid.clone(), |label| format!("`{label}`"))
}

#[async_trait]
impl Check for EabList {
    fn kind(&self) -> &'static str {
        "eab"
    }

    /// Identifiers only: at the connection stage no account has been
    /// authenticated, so there is no credential to ask about.
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
    use crate::testutil::dns_identifiers;

    fn identity(label: Option<&str>, active: bool) -> EabIdentity {
        EabIdentity {
            kid: "11111111-2222-3333-4444-555555555555".to_string(),
            label: label.map(std::string::ToString::to_string),
            active,
        }
    }

    fn built(settings: Settings) -> EabList {
        EabList::from_settings("tenant", &settings).unwrap()
    }

    fn labels(allow: &[&str], deny: &[&str]) -> Settings {
        Settings {
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
            deny: deny.iter().map(std::string::ToString::to_string).collect(),
            ..Settings::default()
        }
    }

    async fn verdict_for(check: &EabList, eab: Option<EabIdentity>) -> Verdict {
        let identifiers: Vec<Identifier> = dns_identifiers(&["host.example.com"]);
        check
            .check_identifiers(&IdentifierContext {
                client_ip: None,
                account_id: "acct-1",
                stage: IdentifierStage::NewOrder,
                identifiers: &identifiers,
                eab,
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

    #[tokio::test]
    async fn a_permitted_label_passes() {
        let check = built(labels(&["tenant-a"], &[]));
        assert_eq!(
            verdict_for(&check, Some(identity(Some("tenant-a"), true))).await,
            Verdict::Pass
        );
    }

    #[tokio::test]
    async fn another_tenants_label_is_refused_naming_it() {
        let check = built(labels(&["tenant-a"], &[]));
        assert_failed(
            verdict_for(&check, Some(identity(Some("tenant-b"), true))).await,
            "`tenant-b`",
        );
    }

    #[tokio::test]
    async fn labels_can_be_globbed() {
        let check = built(labels(&["tenant-*"], &[]));
        assert_eq!(
            verdict_for(&check, Some(identity(Some("tenant-a"), true))).await,
            Verdict::Pass
        );
        assert_failed(
            verdict_for(&check, Some(identity(Some("other"), true))).await,
            "not one this policy permits",
        );
    }

    #[tokio::test]
    async fn deny_wins_over_allow() {
        let check = built(labels(&["tenant-*"], &["tenant-retired"]));
        assert_failed(
            verdict_for(&check, Some(identity(Some("tenant-retired"), true))).await,
            "which policy refuses",
        );
    }

    /// `kids` pins the credential itself, for an operator who would rather not
    /// depend on labels being unique. It is a second allow source, so either
    /// half satisfying the check is enough.
    #[tokio::test]
    async fn an_exact_kid_is_permitted_beside_the_labels() {
        let settings = Settings {
            allow: vec!["tenant-a".to_string()],
            kids: vec!["11111111-2222-3333-4444-555555555555".to_string()],
            ..Settings::default()
        };
        let check = built(settings);

        // Matched by kid, despite a label the allow list does not name.
        assert_eq!(
            verdict_for(&check, Some(identity(Some("something-else"), true))).await,
            Verdict::Pass
        );
        // And a different credential with the permitted label still passes.
        let other = EabIdentity {
            kid: "99999999-9999-9999-9999-999999999999".to_string(),
            label: Some("tenant-a".to_string()),
            active: true,
        };
        assert_eq!(verdict_for(&check, Some(other)).await, Verdict::Pass);
    }

    #[tokio::test]
    async fn a_kids_only_check_refuses_an_unlisted_credential() {
        let settings = Settings {
            kids: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            ..Settings::default()
        };
        assert_failed(
            verdict_for(&built(settings), Some(identity(Some("tenant-a"), true))).await,
            "not one this policy permits",
        );
    }

    /// The fail-closed reading: "no credential" cannot satisfy a rule that is
    /// about which credential was used.
    #[tokio::test]
    async fn an_account_with_no_credential_is_refused() {
        let check = built(labels(&["tenant-a"], &[]));
        assert_failed(
            verdict_for(&check, None).await,
            "not registered under an external account binding",
        );
    }

    /// A credential with no label cannot match a label allowlist, which is the
    /// same rule stated from the other side.
    #[tokio::test]
    async fn an_unlabelled_credential_cannot_match_a_label_allowlist() {
        let check = built(labels(&["tenant-a"], &[]));
        let verdict = verdict_for(&check, Some(identity(None, true))).await;
        assert_failed(verdict, "not one this policy permits");
    }

    #[tokio::test]
    async fn a_revoked_credential_passes_unless_require_active_is_set() {
        let permissive = built(labels(&["tenant-a"], &[]));
        assert_eq!(
            verdict_for(&permissive, Some(identity(Some("tenant-a"), false))).await,
            Verdict::Pass,
            "revocation stops new registrations, not existing accounts, by default"
        );

        let strict = built(Settings {
            allow: vec!["tenant-a".to_string()],
            require_active: true,
            ..Settings::default()
        });
        assert_failed(
            verdict_for(&strict, Some(identity(Some("tenant-a"), false))).await,
            "has been revoked",
        );
    }

    /// `require_active` alone is a meaningful policy: "any tenant, but not one
    /// whose credential we have withdrawn".
    #[tokio::test]
    async fn require_active_alone_is_a_usable_check() {
        let check = built(Settings {
            require_active: true,
            ..Settings::default()
        });
        assert_eq!(
            verdict_for(&check, Some(identity(Some("anyone"), true))).await,
            Verdict::Pass
        );
        assert_failed(
            verdict_for(&check, Some(identity(None, false))).await,
            "has been revoked",
        );
    }

    #[test]
    fn a_check_that_asks_nothing_is_a_startup_error() {
        let error = EabList::from_settings("tenant", &Settings::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("names no labels"), "{error}");
        assert!(error.contains("filter.check.tenant"), "{error}");
    }

    #[test]
    fn reports_its_type_and_stages() {
        let check = built(labels(&["t"], &[]));
        assert_eq!(check.kind(), "eab");
        assert_eq!(check.stages(), StageSet::identifiers_only());
    }
}
