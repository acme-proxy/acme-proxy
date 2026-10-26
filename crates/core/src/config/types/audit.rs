//! `[audit]` — the CA's traceability settings.
//!
//! Process-wide: no profile can override it. Each key, its default and its
//! environment variable are documented once, in the book's
//! `configuration/reference.md` under `[audit]`.

use serde::Deserialize;

/// Governs the traceability columns and the `audit_log` table.
///
/// Process-wide, so deliberately absent from `PROFILE_SECTIONS`: the retention
/// sweep is one pass over one table, and an audit trail that recorded different
/// things at different endpoints of the same CA would be the wrong shape for
/// the question it exists to answer.
///
/// There is no `enabled` key: certificate and administrative actions are always
/// recorded. Refused ACME responses can additionally be recorded on request.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Persist an audit row for each refused ACME response, including failures
    /// before an account or order exists. Off by default because unauthenticated
    /// traffic can make the audit table grow as fast as requests arrive.
    pub record_refusals: bool,
    /// Resolve a PTR record for the client's address and freeze it into the row.
    ///
    /// On by default. Turn it off on an estate with no usable reverse zone: the
    /// lookups would all fail, every `*_ptr` would be `NULL` anyway, and the
    /// only thing left would be the round trip.
    pub reverse_dns: bool,
    /// Budget for one PTR lookup.
    ///
    /// Small on purpose: this runs inside a request that has already done its
    /// real work, and a slow nameserver must cost a `NULL` in one column rather
    /// than latency on issuance. Matches `filter.reverse_dns.timeout_ms`, whose
    /// lookup is against the same nameserver.
    pub reverse_dns_timeout_ms: u64,
    /// Delete `audit_log` rows older than this many days.
    ///
    /// `0` (the default) keeps everything for ever, which is the right default
    /// for a trail whose value is that it is complete. Set it where a retention
    /// policy says otherwise; `acme-proxy audit cleanup --older-than` is the
    /// same sweep run by hand.
    pub retention_days: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            record_refusals: false,
            reverse_dns: true,
            reverse_dns_timeout_ms: 2_000,
            retention_days: 0,
        }
    }
}
