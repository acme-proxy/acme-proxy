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
    pub(super) token: String,
}
