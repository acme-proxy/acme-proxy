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
/// file set. A number or a bool is one element, since `try_parsing` turns
/// `ACME_PROXY_SIGNER__CUSTOM__ARGS=7` into an integer before it gets here.
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
            if value.is_empty() {
                return Ok(Vec::new());
            }
            Ok(value.split(',').map(str::to_string).collect())
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
            // `[""]` is what an empty environment variable used to split
            // into, and it still means "no values" when written in a file.
            Ok(match values.as_slice() {
                [only] if only.is_empty() => Vec::new(),
                _ => values,
            })
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

    #[test]
    fn a_comma_separated_string_splits_without_trimming() {
        assert_eq!(parse("a,b".into()), ["a", "b"]);
        assert_eq!(parse("a, b".into()), ["a", " b"]);
        assert_eq!(parse("only".into()), ["only"]);
    }

    #[test]
    fn the_empty_string_is_no_values_in_either_shape() {
        assert!(parse("".into()).is_empty());
        assert!(parse(serde_json::json!([""])).is_empty());
        assert!(parse(serde_json::json!([])).is_empty());
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
