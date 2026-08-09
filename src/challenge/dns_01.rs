//! The `dns-01` challenge (RFC 8555 §8.4): a TXT record under
//! `_acme-challenge.<identifier>` whose value is
//! `base64url(SHA256(keyAuthorization))`.
//!
//! The only challenge type that can prove a **wildcard**: publishing a record in
//! a zone demonstrates control of the zone, which is what `*.example.com` claims.
//! The record itself is not wildcard-specific — it lives under the authorization's
//! identifier, and a wildcard authorization's identifier *is* the base name, so
//! this module never looks at [`ValidationContext::wildcard`] at all.
//!
//! ## Dns versus `IncorrectResponse`
//!
//! "The lookup failed, or the name has no TXT record" is a
//! [`ChallengeError::Dns`]; "there are records and none of them match" is a
//! [`ChallengeError::IncorrectResponse`]. The same split
//! [`reverse_dns`](crate::filter::reverse_dns) draws between not reaching a
//! verdict and reaching an unfavourable one — a client debugging a failure needs
//! to know which of the two happened.

use std::sync::Arc;

use async_trait::async_trait;
use base64::prelude::*;
use ring::digest;
use tracing::{debug, info};

use super::{ChallengeError, ChallengeValidator, DNS_01, ValidationContext};
use crate::dns::Resolver;

/// Looks up the challenge TXT record for an identifier.
pub struct Dns01Validator {
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for Dns01Validator {
    /// `dyn Resolver` is not `Debug`, and this validator has no policy of its
    /// own to show.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Dns01Validator").finish()
    }
}

impl Dns01Validator {
    /// Builds the validator against the shared resolver `challenge::from_config`
    /// selected (`dns.resolver` if set, else the system configuration,
    /// uncached either way): the client publishes its record moments before
    /// triggering, so a cached negative answer would fail a challenge that is
    /// in fact satisfied — for a TTL neither side controls.
    pub fn from_config(resolver: Arc<dyn Resolver>) -> Self {
        info!(event = "challenge_dns_01_loaded");
        Self::with_resolver(resolver)
    }

    /// Same, against a caller-supplied resolver. Used by tests.
    pub fn with_resolver(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }
}

/// The name the record must be published at.
///
/// A free function rather than a method because the `acme_proxy` signer
/// backend *publishes* this record when satisfying an upstream's own dns-01
/// challenge, while this module *reads* it. Two copies of the convention could
/// drift into a record this server accepts but no real CA does.
pub(crate) fn record_name(identifier: &str) -> String {
    format!("_acme-challenge.{identifier}")
}

/// The TXT value RFC 8555 §8.4 requires: the SHA-256 digest of the key
/// authorization, base64url-encoded — *not* the key authorization itself,
/// which is what `http-01` serves.
///
/// Shared with the publishing side for the same reason as [`record_name`].
pub(crate) fn expected_value(key_authorization: &str) -> String {
    BASE64_URL_SAFE_NO_PAD
        .encode(digest::digest(&digest::SHA256, key_authorization.as_bytes()).as_ref())
}

#[async_trait]
impl ChallengeValidator for Dns01Validator {
    fn typ(&self) -> &'static str {
        DNS_01
    }

    async fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        let name = record_name(ctx.identifier);
        let expected = expected_value(ctx.key_authorization);

        let records = self.resolver.txt(&name).await.map_err(|error| {
            ChallengeError::Dns(format!("TXT lookup of {name} failed: {error}"))
        })?;

        if records.is_empty() {
            return Err(ChallengeError::Dns(format!("no TXT record at {name}")));
        }

        // Several TXT records at one name is the *normal* case, not a leniency:
        // an order for `example.com` and `*.example.com` produces two
        // authorizations whose records are published side by side, and the two
        // key authorizations differ. Matching any one of them is the rule.
        if records.iter().any(|record| record.trim() == expected) {
            debug!(
                event = "challenge_dns_01_matched",
                name,
                challenge_id = ctx.challenge_id
            );
            return Ok(());
        }

        // The record count, never the values: they are attacker-influenced text
        // and echoing them back buys the client nothing it does not already know.
        Err(ChallengeError::IncorrectResponse(format!(
            "no TXT record at {name} matches the expected value ({} record(s) found)",
            records.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    /// A resolver answering TXT queries from a canned map.
    #[derive(Default)]
    struct StubResolver {
        txt: HashMap<String, Vec<String>>,
        error: Option<String>,
    }

    impl StubResolver {
        fn with_txt(mut self, name: &str, values: &[&str]) -> Self {
            self.txt.insert(
                name.to_string(),
                values
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            );
            self
        }

        fn failing(error: &str) -> Self {
            Self {
                error: Some(error.to_string()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl Resolver for StubResolver {
        async fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
            unreachable!("dns-01 never looks up PTR records")
        }

        async fn forward(&self, _name: &str) -> Result<Vec<IpAddr>, String> {
            unreachable!("dns-01 never looks up A/AAAA records")
        }

        async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.txt.get(name).cloned().unwrap_or_default())
        }
    }

    const KEY_AUTH: &str = "token-value.thumbprint-value";

    /// The expected TXT value, computed independently of the implementation.
    fn expected() -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, KEY_AUTH.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    fn validator(resolver: StubResolver) -> Dns01Validator {
        Dns01Validator::with_resolver(Arc::new(resolver))
    }

    fn context(identifier: &str, wildcard: bool) -> ValidationContext<'_> {
        ValidationContext {
            identifier,
            wildcard,
            token: "token-value",
            key_authorization: KEY_AUTH,
            challenge_id: "chall-1",
        }
    }

    #[tokio::test]
    async fn a_matching_txt_record_passes() {
        let resolver =
            StubResolver::default().with_txt("_acme-challenge.example.com", &[&expected()]);
        assert!(
            validator(resolver)
                .validate(&context("example.com", false))
                .await
                .is_ok()
        );
    }

    /// The digest of the key authorization, not the key authorization itself —
    /// the difference between `dns-01` and `http-01`, and an easy thing to get
    /// backwards.
    #[tokio::test]
    async fn the_record_must_hold_the_digest_not_the_key_authorization() {
        let resolver = StubResolver::default().with_txt("_acme-challenge.example.com", &[KEY_AUTH]);
        assert!(matches!(
            validator(resolver)
                .validate(&context("example.com", false))
                .await,
            Err(ChallengeError::IncorrectResponse(_))
        ));
    }

    /// Publishing `example.com` and `*.example.com` in one order puts two
    /// records at the same name; matching either is required.
    #[tokio::test]
    async fn any_of_several_records_may_match() {
        let resolver = StubResolver::default().with_txt(
            "_acme-challenge.example.com",
            &["some-other-value", &expected(), "yet-another"],
        );
        assert!(
            validator(resolver)
                .validate(&context("example.com", false))
                .await
                .is_ok()
        );
    }

    /// A wildcard authorization proves the *base* name: the handler passes the
    /// stripped identifier, so the record lives at the same place as a plain
    /// authorization's would.
    #[tokio::test]
    async fn a_wildcard_authorization_queries_the_base_name() {
        let resolver =
            StubResolver::default().with_txt("_acme-challenge.example.com", &[&expected()]);
        assert!(
            validator(resolver)
                .validate(&context("example.com", true))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_name_with_no_txt_record_is_a_dns_error() {
        let error = validator(StubResolver::default())
            .validate(&context("example.com", false))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Dns(detail)
                if detail.contains("no TXT record at _acme-challenge.example.com")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_is_a_dns_error() {
        let error = validator(StubResolver::failing("SERVFAIL"))
            .validate(&context("example.com", false))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ChallengeError::Dns(detail) if detail.contains("SERVFAIL")),
            "{error:?}"
        );
    }

    /// Records present but none matching is a statement about the answer, not
    /// about the lookup — and the values themselves are not echoed back.
    #[tokio::test]
    async fn non_matching_records_are_an_incorrect_response() {
        let resolver = StubResolver::default()
            .with_txt("_acme-challenge.example.com", &["wrong-1", "wrong-2"]);
        let error = validator(resolver)
            .validate(&context("example.com", false))
            .await
            .unwrap_err();

        match &error {
            ChallengeError::IncorrectResponse(detail) => {
                assert!(detail.contains("2 record(s)"), "{detail}");
                assert!(!detail.contains("wrong-1"), "{detail}");
            }
            other => panic!("expected IncorrectResponse, got {other:?}"),
        }
    }

    /// Some providers return the value padded with whitespace.
    #[tokio::test]
    async fn surrounding_whitespace_is_ignored() {
        let padded = format!("  {}\n", expected());
        let resolver = StubResolver::default().with_txt("_acme-challenge.example.com", &[&padded]);
        assert!(
            validator(resolver)
                .validate(&context("example.com", false))
                .await
                .is_ok()
        );
    }

    #[test]
    fn reports_its_challenge_type() {
        assert_eq!(validator(StubResolver::default()).typ(), "dns-01");
    }
}
