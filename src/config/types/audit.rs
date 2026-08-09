//! `[audit]` — the CA's traceability settings.

use serde::Deserialize;

/// Governs the traceability columns and the `audit_log` table.
///
/// Process-wide, so deliberately absent from `PROFILE_SECTIONS`: the retention
/// sweep is one pass over one table, and an audit trail that recorded different
/// things at different endpoints of the same CA would be the wrong shape for
/// the question it exists to answer.
///
/// There is no `enabled` key. Recording who asked the CA to sign something is
/// not a feature of this server, it is what a CA does; the only thing an
/// operator can turn off here is the reverse lookup, because that one costs a
/// network round trip and has estates where it can never succeed.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
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
            reverse_dns: true,
            reverse_dns_timeout_ms: 2_000,
            retention_days: 0,
        }
    }
}
