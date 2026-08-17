//! The three ACME state machines, as types rather than strings.
//!
//! `orders.status`, `authorizations.status` and `challenges.status` are
//! `TEXT` columns with a `CHECK` naming the values each may hold, and the code
//! around them used to compare against string literals — `order.status ==
//! "valid"`, `authz.status != "pending"` — at thirty-odd sites spread over
//! `handlers/`, `sqlite/` and the relay flow. A typo in one of those compiles
//! and silently changes policy: `!= "readyy"` is always true, and the order it
//! guards becomes finalizable for names nobody proved control of.
//!
//! These enums are a Rust-side change only. Each variant's [`as_str`] is the
//! byte-identical string the column already holds, so the frozen migrations and
//! their `CHECK` constraints are untouched, and RFC 8555 still sees exactly the
//! spellings it defines.
//!
//! [`as_str`]: OrderStatus::as_str

use std::fmt;
use std::str::FromStr;

/// A status column held a value outside its `CHECK` — or, far more likely, an
/// operator typed one.
///
/// Carries the permitted values because both places this surfaces want to print
/// them: `acme-proxy order list --status typo` refuses **by name** rather than
/// asking SQL, which would answer "no rows" and look exactly like "nothing is
/// in that state" (the rule `audit list --event` already follows), and a row
/// that somehow holds an unknown value fails to load rather than being silently
/// compared against and mis-handled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {label} `{value}` (expected one of: {})", allowed.join(", "))]
pub struct UnknownStatus {
    pub label: &'static str,
    pub value: String,
    pub allowed: &'static [&'static str],
}

macro_rules! statuses {
    ($(
        $(#[$doc:meta])*
        $name:ident ($label:literal) {
            $( $(#[$vdoc:meta])* $variant:ident => $wire:literal ),+ $(,)?
        }
    )*) => { $(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )+
        }

        impl $name {
            /// Every value, in the order RFC 8555 introduces them. Used to word
            /// [`UnknownStatus`] and to drive the round-trip test.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The exact string the column holds and the wire carries.
            ///
            /// This is the compatibility surface: the `CHECK` constraints in
            /// `migrations/20260727120000_indexes_and_constraints.sql` are
            /// written against these literals and the migrations are frozen, so
            /// changing one is a schema change, not a rename.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $wire, )+ }
            }

            /// The permitted spellings, for an error message.
            const SPELLINGS: &'static [&'static str] = &[ $( $wire, )+ ];
        }

        impl FromStr for $name {
            type Err = UnknownStatus;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownStatus {
                        label: $label,
                        value: other.to_string(),
                        allowed: Self::SPELLINGS,
                    }),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    )* };
}

statuses! {
    /// An order's state (RFC 8555 §7.1.6).
    ///
    /// `processing` is only ever reached by a signer backend that defers
    /// issuance (`relay`); `local_ca` answers inline and goes straight to
    /// `valid`. There is deliberately no `revoked`: RFC 8555 defines none, and
    /// revocation is recorded on its own columns
    /// (see [`Order::revoke`](crate::sqlite::order::Order::revoke)).
    OrderStatus("order status") {
        Pending => "pending",
        Ready => "ready",
        Processing => "processing",
        Valid => "valid",
        Invalid => "invalid",
    }

    /// An authorization's state (RFC 8555 §7.1.6).
    ///
    /// The column's `CHECK` has always permitted `deactivated`, `expired` and
    /// `revoked`; only `deactivated` is ever written today (§7.5.2), which is
    /// why implementing it needed no migration. The other two are kept here so
    /// the type can still load a row holding one.
    AuthzStatus("authorization status") {
        Pending => "pending",
        Valid => "valid",
        Invalid => "invalid",
        Deactivated => "deactivated",
        Expired => "expired",
        Revoked => "revoked",
    }

    /// A challenge's state (RFC 8555 §8).
    ///
    /// `processing` is in the `CHECK` but never written: validation here is
    /// inline and synchronous under `challenge.timeout_ms`, so a triggered
    /// challenge is `valid` or `invalid` by the time the response is built.
    ChallengeStatus("challenge status") {
        Pending => "pending",
        Processing => "processing",
        Valid => "valid",
        Invalid => "invalid",
    }
}

/// Reads a status column, turning an unrecognised value into a decode error.
///
/// Refusing to load is the right failure: the alternative is holding the raw
/// string and comparing against it, which is what this module exists to stop.
/// The `CHECK` constraint means no build honouring the schema can write one.
pub(crate) fn from_column<T>(value: &str) -> Result<T, sqlx::Error>
where
    T: FromStr<Err = UnknownStatus>,
{
    value
        .parse()
        .map_err(|error: UnknownStatus| sqlx::Error::Decode(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant survives the trip its column makes it take. This is the
    /// test that would catch a variant whose `as_str` no longer matches what
    /// the frozen `CHECK` permits.
    #[test]
    fn every_status_round_trips_through_its_stored_string() {
        for status in OrderStatus::ALL {
            assert_eq!(status.as_str().parse::<OrderStatus>().unwrap(), *status);
        }
        for status in AuthzStatus::ALL {
            assert_eq!(status.as_str().parse::<AuthzStatus>().unwrap(), *status);
        }
        for status in ChallengeStatus::ALL {
            assert_eq!(status.as_str().parse::<ChallengeStatus>().unwrap(), *status);
        }
    }

    /// The stored spellings are the compatibility surface, so they are asserted
    /// literally rather than derived — a test that computed them from the enum
    /// would agree with any rename.
    #[test]
    fn the_stored_spellings_are_the_ones_the_check_constraints_permit() {
        assert_eq!(
            OrderStatus::SPELLINGS,
            &["pending", "ready", "processing", "valid", "invalid"]
        );
        assert_eq!(
            AuthzStatus::SPELLINGS,
            &[
                "pending",
                "valid",
                "invalid",
                "deactivated",
                "expired",
                "revoked"
            ]
        );
        assert_eq!(
            ChallengeStatus::SPELLINGS,
            &["pending", "processing", "valid", "invalid"]
        );
    }

    #[test]
    fn an_unknown_status_names_itself_and_the_alternatives() {
        let error = "readyy".parse::<OrderStatus>().unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("unknown order status `readyy`"),
            "{rendered}"
        );
        assert!(
            rendered.contains("pending, ready, processing, valid, invalid"),
            "{rendered}"
        );
    }

    /// A status that belongs to a *different* machine is still unknown here —
    /// the point of three types rather than one.
    #[test]
    fn a_status_from_another_state_machine_is_refused() {
        assert!("deactivated".parse::<OrderStatus>().is_err());
        assert!("ready".parse::<AuthzStatus>().is_err());
        assert!("deactivated".parse::<ChallengeStatus>().is_err());
        // ...but each machine's own values still parse.
        assert!("deactivated".parse::<AuthzStatus>().is_ok());
    }

    #[test]
    fn a_bad_column_value_is_a_decode_error_not_a_panic() {
        let error = from_column::<OrderStatus>("nonsense").unwrap_err();
        assert!(matches!(error, sqlx::Error::Decode(_)), "{error:?}");
    }
}
