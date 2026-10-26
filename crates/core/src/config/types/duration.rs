//! [`ConfigDuration`]: every length of time the configuration holds, written
//! with its unit — `"500ms"`, `"30s"`, `"5m"`, `"1h30m"`, `"90d"`, `"1w"`,
//! `"1y"`.
//!
//! The rules, each guarded by a test below:
//!
//! - **The unit is mandatory.** A bare number is refused, from a file and from
//!   the environment alike: nothing in `30` says whether it is seconds or
//!   days, which is the ambiguity the old `_ms` / `_secs` / `_days` suffixes
//!   existed to settle, and the reason those keys are gone.
//! - **Units are fixed lengths**: `d` is 86 400 s, `w` seven of those, `y`
//!   365 of those. No calendar arithmetic, no leap seconds — a certificate
//!   lifetime of `"1y"` is 365 days, not "same date next year". There is no
//!   month unit: `m` is minutes, and a month has no fixed length to give it.
//! - **Segments add up** (`"1h30m"`) in any order, and zero is spelt with a
//!   unit too (`"0s"`): it is how a key whose zero means "off" is turned off.
//! - **Equality is the length, not the spelling**: `"1d"` and `"24h"` compare,
//!   hash and `Debug`-render identically. A signing backend is reused across a
//!   reload when its configuration's `Debug` rendering is unchanged
//!   (`signer::build_backends`), so a respelling must not rebuild one.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Visitor};

/// The units a duration may be written in, longest suffix first so `ms` is
/// tried before `m`. The text of every refusal lists them from this table.
const UNITS: &[(&str, u64)] = &[
    ("ms", 1),
    ("s", 1_000),
    ("m", 60 * 1_000),
    ("h", 60 * 60 * 1_000),
    ("d", DAY_MS),
    ("w", 7 * DAY_MS),
    ("y", 365 * DAY_MS),
];

const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

/// A length of time from the configuration, to the millisecond.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ConfigDuration(Duration);

impl ConfigDuration {
    pub const ZERO: Self = Self(Duration::ZERO);

    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    #[must_use]
    pub const fn from_mins(mins: u64) -> Self {
        Self::from_secs(mins * 60)
    }

    #[must_use]
    pub const fn from_hours(hours: u64) -> Self {
        Self::from_secs(hours * 60 * 60)
    }

    #[must_use]
    pub const fn from_days(days: u64) -> Self {
        Self::from_secs(days * 24 * 60 * 60)
    }

    #[must_use]
    pub const fn as_std(self) -> Duration {
        self.0
    }

    /// Whole seconds, rounded down.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0.as_secs()
    }

    /// Whole seconds as the `i64` the epoch arithmetic in the store uses,
    /// saturating — a parsed duration fits in `u64` milliseconds, so its
    /// seconds always fit, but the saturation keeps that out of every caller.
    #[must_use]
    pub fn as_secs_i64(self) -> i64 {
        i64::try_from(self.as_secs()).unwrap_or(i64::MAX)
    }

    /// Whole milliseconds, saturating at `u64::MAX`.
    #[must_use]
    pub fn as_millis(self) -> u64 {
        u64::try_from(self.0.as_millis()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    /// Parses `"1h30m"`-style text, or says why it cannot.
    ///
    /// # Errors
    ///
    /// An empty value, a segment without a unit, an unknown unit, or a total
    /// past what `u64` milliseconds hold.
    pub fn parse(text: &str) -> Result<Self, String> {
        let units = || {
            UNITS
                .iter()
                .map(|(unit, _)| *unit)
                .collect::<Vec<_>>()
                .join(" ")
        };
        let invalid = |why: &str| {
            format!(
                "invalid duration `{text}`: {why}; write a number followed by a unit \
                 ({}), e.g. \"30s\", \"5m\", \"1h30m\", \"90d\"",
                units()
            )
        };

        if text.is_empty() {
            return Err(invalid("it is empty"));
        }
        let mut rest = text;
        let mut total: u64 = 0;
        while !rest.is_empty() {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return Err(invalid("expected a number"));
            }
            let (number, after) = rest.split_at(digits);
            let Some((unit, scale)) = UNITS.iter().find(|(unit, _)| after.starts_with(unit)) else {
                return Err(if after.is_empty() {
                    invalid("the unit is missing")
                } else {
                    invalid("unknown unit")
                });
            };
            let value: u64 = number
                .parse()
                .map_err(|_| invalid("the number is too large"))?;
            total = value
                .checked_mul(*scale)
                .and_then(|millis| total.checked_add(millis))
                .ok_or_else(|| invalid("the total is too large"))?;
            rest = &after[unit.len()..];
        }
        Ok(Self::from_millis(total))
    }
}

/// The normalized spelling: days, hours, minutes, seconds and milliseconds,
/// largest first, zero parts left out (`90d`, `1h30m`, `6d16h`, `0s`). Weeks
/// and years are accepted on input but never produced, so `"1y"` renders as
/// `365d`, the length it actually is.
impl fmt::Display for ConfigDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut millis = self.as_millis();
        if millis == 0 {
            return f.write_str("0s");
        }
        for (unit, scale) in [
            ("d", DAY_MS),
            ("h", 60 * 60 * 1_000),
            ("m", 60 * 1_000),
            ("s", 1_000),
            ("ms", 1),
        ] {
            let count = millis / scale;
            if count > 0 {
                write!(f, "{count}{unit}")?;
                millis %= scale;
            }
        }
        Ok(())
    }
}

/// Renders as the normalized spelling, quoted, so a configuration's `Debug`
/// output reads like the TOML that produced it.
impl fmt::Debug for ConfigDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

impl From<ConfigDuration> for Duration {
    fn from(value: ConfigDuration) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for ConfigDuration {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DurationVisitor;

        impl Visitor<'_> for DurationVisitor {
            type Value = ConfigDuration;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration with its unit, such as \"30s\" or \"90d\"")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                ConfigDuration::parse(value).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "invalid duration {value}: a bare number has no unit; write it as a \
                     string with one, e.g. \"{value}s\" or \"{value}ms\""
                )))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "invalid duration {value}: a bare number has no unit; write it as a \
                     string with one, e.g. \"30s\""
                )))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "invalid duration {value}: write it as a string with a unit, \
                     e.g. \"1500ms\""
                )))
            }
        }

        deserializer.deserialize_any(DurationVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unit_parses_to_its_fixed_length() {
        for (text, millis) in [
            ("500ms", 500),
            ("10s", 10_000),
            ("5m", 300_000),
            ("2h", 7_200_000),
            ("1d", DAY_MS),
            ("1w", 7 * DAY_MS),
            ("1y", 365 * DAY_MS),
        ] {
            assert_eq!(
                ConfigDuration::parse(text).unwrap(),
                ConfigDuration::from_millis(millis),
                "{text}"
            );
        }
    }

    #[test]
    fn segments_add_up_in_any_order() {
        let expected = ConfigDuration::from_secs(90 * 60);
        for text in ["1h30m", "30m1h", "90m", "5400s", "1h29m60s"] {
            assert_eq!(ConfigDuration::parse(text).unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn zero_is_written_with_a_unit() {
        assert!(ConfigDuration::parse("0s").unwrap().is_zero());
        assert!(ConfigDuration::parse("0d").unwrap().is_zero());
    }

    #[test]
    fn refusals_name_the_value_and_the_units() {
        for text in [
            "", "30", "s", "1x", "1h30", "1.5h", " 1h", "1h ", "-1s", "1M",
        ] {
            let error = ConfigDuration::parse(text).expect_err(text);
            assert!(error.contains(&format!("`{text}`")), "{error}");
            assert!(error.contains("ms s m h d w y"), "{error}");
        }
    }

    #[test]
    fn a_total_past_u64_milliseconds_is_refused_not_wrapped() {
        assert!(ConfigDuration::parse("18446744073709551615ms").is_ok());
        assert!(ConfigDuration::parse("18446744073709551616ms").is_err());
        assert!(ConfigDuration::parse("999999999999y").is_err());
        assert!(ConfigDuration::parse("18446744073709551615ms1ms").is_err());
    }

    #[test]
    fn display_is_normalized_and_round_trips() {
        for (text, shown) in [
            ("0s", "0s"),
            ("90d", "90d"),
            ("1y", "365d"),
            ("1w", "7d"),
            ("160h", "6d16h"),
            ("90m", "1h30m"),
            ("1500ms", "1s500ms"),
        ] {
            let parsed = ConfigDuration::parse(text).unwrap();
            assert_eq!(parsed.to_string(), shown, "{text}");
            assert_eq!(ConfigDuration::parse(shown).unwrap(), parsed, "{shown}");
        }
    }

    /// What lets a reload reuse a backend whose configuration was only
    /// respelt.
    #[test]
    fn respellings_compare_and_debug_render_identically() {
        let day = ConfigDuration::parse("1d").unwrap();
        let hours = ConfigDuration::parse("24h").unwrap();
        assert_eq!(day, hours);
        assert_eq!(format!("{day:?}"), format!("{hours:?}"));
        assert_eq!(format!("{day:?}"), "\"1d\"");
    }

    #[derive(Debug, Deserialize)]
    struct Holder {
        value: ConfigDuration,
    }

    #[test]
    fn deserializes_from_a_string_and_refuses_a_bare_number() {
        let held: Holder = serde_json::from_str(r#"{"value": "5m"}"#).unwrap();
        assert_eq!(held.value, ConfigDuration::from_mins(5));

        let error = serde_json::from_str::<Holder>(r#"{"value": 30}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("bare number has no unit"), "{error}");
        assert!(error.contains("\"30s\""), "{error}");
    }
}
