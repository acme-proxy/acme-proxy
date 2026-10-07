//! Datetimes as the wire and the operator surfaces render them.
//!
//! Stored timestamps are epoch seconds; what a client, the admin API, a page or
//! the CLI shows is RFC 3339 — the shape RFC 8555 uses for its datetime fields.
//! One renderer, so a value cannot read differently on two surfaces.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Renders epoch `secs` as an RFC 3339 datetime string, falling back to an
/// empty string for the out-of-range timestamps that should never occur in
/// practice.
#[must_use]
pub fn rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_render_as_utc_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_800_000_000), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn an_unrepresentable_instant_renders_empty() {
        assert_eq!(rfc3339(i64::MAX), "");
    }
}
