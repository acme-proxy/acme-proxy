//! The upstream's wire objects, and the two conversions that go with them.
//!
//! These sat in three separate places in `mod.rs` — the order view beside
//! `issue`, the ARI views beside `renewal_info`, the authorization and
//! challenge views beside the relay — which obscured that they are one thing:
//! this server's model of what an upstream ACME server says back. Collected
//! here, extending that model is one file rather than a hunt.

use serde::Deserialize;
use serde_json::Value;

use crate::signer::SignerError;

use super::client::UpstreamError;

/// The upstream order object, as much of it as the relay reads.
#[derive(Debug, Deserialize)]
pub(super) struct UpstreamOrderView {
    pub(super) status: String,
    #[serde(default)]
    pub(super) authorizations: Vec<String>,
    #[serde(default)]
    pub(super) finalize: Option<String>,
    #[serde(default)]
    pub(super) certificate: Option<String>,
    #[serde(default)]
    pub(super) error: Option<Value>,
}

/// The upstream's ARI answer (RFC 9773 §4.2).
#[derive(Debug, Deserialize)]
pub(super) struct RenewalInfoView {
    #[serde(rename = "suggestedWindow")]
    pub(super) suggested_window: SuggestedWindow,
    #[serde(rename = "explanationURL", default)]
    pub(super) explanation_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SuggestedWindow {
    pub(super) start: String,
    pub(super) end: String,
}

/// RFC3339 → epoch seconds, the representation the handler works in.
pub(super) fn parse_rfc3339(value: &str) -> Result<i64, SignerError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|parsed| parsed.unix_timestamp())
        .map_err(|error| {
            SignerError::Internal(format!("upstream ARI window was not RFC3339: {error}"))
        })
}

/// Maps a transport/protocol failure to the trait's error type.
///
/// Only one upstream answer is the *client's* fault rather than an internal
/// problem: a rejected CSR. Mapping that to `BadCsr` is what leaves the local
/// order `ready` and retryable, matching what `local_ca` does for the same
/// mistake, instead of terminally invalidating an order the client could fix.
pub(super) fn upstream_to_signer_error(error: UpstreamError) -> SignerError {
    if error.is_bad_csr() {
        SignerError::BadCsr
    } else {
        SignerError::Internal(error.to_string())
    }
}
/// The upstream's authorization object, as much as the relay reads.
#[derive(Debug, Deserialize)]
pub(super) struct UpstreamAuthzView {
    pub(super) status: String,
    pub(super) identifier: UpstreamIdentifier,
    #[serde(default)]
    pub(super) challenges: Vec<UpstreamChallengeView>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpstreamIdentifier {
    pub(super) value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpstreamChallengeView {
    #[serde(rename = "type")]
    pub(super) typ: String,
    pub(super) url: String,
    /// Absent on challenge types that do not use one.
    ///
    /// `type` and `url` belong to every challenge object (§7.1.4), but `token`
    /// belongs only to the token-based types, and a CA offers types this server
    /// does not implement: Let's Encrypt now poses `dns-persist-01` beside the
    /// three familiar ones, and it derives its TXT value from the account URI
    /// rather than from a token, so the member is simply absent. While this was
    /// a required `String` that one entry failed the parse of the **whole**
    /// authorization — the `dns-01` challenge sitting next to it included — and
    /// the relay never answered a challenge it was perfectly able to answer.
    ///
    /// Deliberately optional here rather than skipping entries that will not
    /// parse: a malformed `dns-01` challenge must stay a loud protocol error,
    /// not become a confusing "offers no dns-01 challenge".
    #[serde(default)]
    pub(super) token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape Let's Encrypt began serving when `dns-persist-01` joined the
    /// offer: a challenge with no `token`, sitting in front of the one the
    /// relay actually answers. While `token` was required this failed the whole
    /// authorization, so the `dns-01` challenge below was never reached.
    #[test]
    fn a_tokenless_challenge_does_not_fail_the_authorization() {
        let body = serde_json::json!({
            "status": "pending",
            "identifier": { "type": "dns", "value": "example.com" },
            "challenges": [
                {
                    "type": "dns-persist-01",
                    "url": "https://ca.example/chall/persist",
                    "status": "pending",
                    "accounturi": "https://ca.example/acct/1",
                },
                {
                    "type": "dns-01",
                    "url": "https://ca.example/chall/dns",
                    "status": "pending",
                    "token": "the-token",
                },
            ],
        });

        let view: UpstreamAuthzView = serde_json::from_value(body).expect("authorization parses");

        assert_eq!(view.identifier.value, "example.com");
        assert_eq!(view.challenges.len(), 2);
        assert_eq!(view.challenges[0].token, None);
        assert_eq!(
            view.challenges[1].token.as_deref(),
            Some("the-token"),
            "the challenge the relay answers still carries its token"
        );
    }

    /// The converse: `type` and `url` belong to every challenge object, so a
    /// body missing one stays a parse failure rather than being skipped.
    #[test]
    fn a_challenge_missing_its_url_is_still_a_parse_failure() {
        let body = serde_json::json!({
            "status": "pending",
            "identifier": { "type": "dns", "value": "example.com" },
            "challenges": [{ "type": "dns-01", "token": "the-token" }],
        });

        serde_json::from_value::<UpstreamAuthzView>(body).unwrap_err();
    }
}
