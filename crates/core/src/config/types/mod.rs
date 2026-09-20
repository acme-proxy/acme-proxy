//! The configuration structs, one file per TOML section.
//!
//! Split out of a single 1008-line `types.rs`: forty struct + `Default` pairs
//! with no logic and no cross-references, which is exactly the shape that reads
//! better grouped by the section an operator is actually editing. Everything is
//! re-exported flat, so no import anywhere outside this directory changes.

pub mod audit;
pub mod challenge;
pub mod filter;
pub mod ipam;
pub mod jobs;
pub mod metrics;
pub mod notify;
pub mod profile;
pub mod proxy;
pub mod server;
pub mod signer;

pub use audit::*;
pub use challenge::*;
pub use filter::*;
pub use ipam::*;
pub use jobs::*;
pub use metrics::*;
pub use notify::*;
pub use profile::*;
pub use proxy::*;
pub use server::*;
pub use signer::*;

/// Deserializes every list-valued config key: a TOML array, or a
/// comma-separated string from the environment.
///
/// The environment can only carry a string, so `ACME_PROXY_FILTER__RULES=a,b`
/// arrives here as `"a,b"` and is split on `,` (untrimmed, so an element keeps
/// its spaces). Splitting here, at the type, rather than in the environment
/// source is what lets a list inside a profile or inside an operator-named
/// table (`[filter.check.<name>]`, `[notify.custom.<name>]`) work with no
/// registration: the `config` crate can only split keys it was told about by
/// their full literal path, and a profile's or an entry's name is known only
/// at runtime. An unregistered key used to be dropped or refused as a type
/// error; there is now nothing to register.
///
/// The empty string is the empty list, so a variable can clear a list the
/// file set. Items are trimmed, and an empty item — `a,,b`, or a trailing
/// comma — is a startup error rather than a silent entry that matches
/// nothing. A number or a bool is one element, since `try_parsing` turns
/// `ACME_PROXY_SIGNER__CUSTOM__ARGS=7` into an integer before it gets here
/// (which also means `007` arrives as `7`: a value whose leading zeros matter
/// belongs in the file's array form).
pub(crate) fn string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringList;

    impl<'de> serde::de::Visitor<'de> for StringList {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a list of strings, or a comma-separated string")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.trim().is_empty() {
                return Ok(Vec::new());
            }
            // Trimmed, because `a, b` is how anyone writes a list and a value
            // of `" b"` matches nothing — a filter rule that silently never
            // fires, or a script argument with a leading space. An empty item
            // (`a,,b`, or a trailing comma) is refused rather than dropped: it
            // is a typo, and every reading of it is a guess.
            let mut values = Vec::new();
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    return Err(E::custom(format!(
                        "`{value}` has an empty item; a comma-separated list needs a value \
                         between commas, and the empty string is the empty list"
                    )));
                }
                values.push(item.to_string());
            }
            Ok(values)
        }

        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(StringList)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(deserialize_with = "super::string_list")]
        values: Vec<String>,
    }

    fn parse(value: serde_json::Value) -> Vec<String> {
        Holder::deserialize(serde_json::json!({ "values": value }))
            .unwrap()
            .values
    }

    fn refusal(value: serde_json::Value) -> String {
        Holder::deserialize(serde_json::json!({ "values": value }))
            .expect_err("this list must be refused")
            .to_string()
    }

    #[test]
    fn a_comma_separated_string_splits_and_trims() {
        assert_eq!(parse("a,b".into()), ["a", "b"]);
        assert_eq!(parse("a, b".into()), ["a", "b"]);
        assert_eq!(parse(" a , b ".into()), ["a", "b"]);
        assert_eq!(parse("only".into()), ["only"]);
    }

    /// An empty item is a typo — a doubled comma, or a trailing one — and
    /// every reading of it is a guess. Dropping it silently leaves a list one
    /// shorter than it looks; keeping it leaves an entry that matches nothing.
    #[test]
    fn an_empty_item_is_refused_by_name() {
        for bad in ["a,,b", "a,", ",a", "a, ,b"] {
            let message = refusal(bad.into());
            assert!(message.contains("empty item"), "{bad}: {message}");
            assert!(message.contains(bad), "{bad}: {message}");
        }
    }

    #[test]
    fn the_empty_string_is_no_values() {
        assert!(parse("".into()).is_empty());
        assert!(parse("   ".into()).is_empty());
        assert!(parse(serde_json::json!([])).is_empty());
    }

    /// An array is written by hand, in a file, and says what it says: a single
    /// empty string is one empty entry, not the empty list. That lowering
    /// existed only because an empty environment variable used to split into
    /// `[""]`, which it no longer does.
    #[test]
    fn an_array_of_one_empty_string_is_not_the_empty_list() {
        assert_eq!(parse(serde_json::json!([""])), [""]);
    }

    #[test]
    fn an_array_is_taken_as_written() {
        assert_eq!(parse(serde_json::json!(["a,b", "c"])), ["a,b", "c"]);
    }

    /// `try_parsing` has already turned a numeric or boolean variable into a
    /// number or a bool by the time it reaches the field.
    #[test]
    fn a_parsed_scalar_is_one_element() {
        assert_eq!(parse(serde_json::json!(7)), ["7"]);
        assert_eq!(parse(serde_json::json!(-7)), ["-7"]);
        assert_eq!(parse(serde_json::json!(1.5)), ["1.5"]);
        assert_eq!(parse(serde_json::json!(true)), ["true"]);
    }

    #[test]
    fn anything_else_is_refused() {
        let error = Holder::deserialize(serde_json::json!({ "values": { "a": 1 } })).unwrap_err();
        assert!(
            error.to_string().contains("comma-separated string"),
            "{error}"
        );
    }
}
