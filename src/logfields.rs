//! Typed helpers for structured log fields, so a field has one spelling and
//! one wire type wherever it is logged.

/// A duration in milliseconds, as a log field.
///
/// `Duration::as_millis` returns `u128`, which `tracing` has no primitive
/// visitor for and so records through `Display` — landing in the JSON output as
/// a quoted `"42"` rather than the number `42`. That output exists to be
/// aggregated by machines, and a latency field a collector has to re-parse (or
/// silently indexes as a string) is a defect in it. Every duration logged
/// anywhere in this crate goes through here.
///
/// The saturation is unreachable — `u64::MAX` milliseconds is some 584 million
/// years — and is written out only to avoid a silent truncating cast.
#[must_use]
pub fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
