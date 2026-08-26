//! The rule every list filter on this listener shares: **a control left at its
//! "any" option is not a filter for the empty string.**
//!
//! An HTML `<select>` inside a submitted form always contributes its `name`, so
//! `<option value="">every profile</option>` arrives as `profile=` rather than
//! as an omitted key, and `serde_urlencoded` deserializes that into `Some("")`.
//! Every predicate builder below then honours it — `AND profile = ''` matches
//! no row, and a `status=` reaches [`crate::sqlite::status`], which refuses an
//! unknown spelling by name and turns the page into a `400`. The CLI never sees
//! this shape at all: clap yields `None` for an omitted `--profile`, which is
//! why `order list --expiring-in` was right where `/ui/expiring` was empty.
//!
//! Normalizing here rather than in the model layer is deliberate. This is the
//! boundary that *produces* the empty string, and it is already the boundary
//! that strips it back out: [`crate::webadmin::pages::pager`] drops an empty
//! filter when it assembles the previous/next URLs. A guard in
//! `push_predicates` would be a second definition of the same rule, sitting
//! where nothing in the query string can be seen.

use serde::Deserialize;

/// A form field or query value left blank is absent, not the empty string.
///
/// Trims first: a text input can carry a stray space, and a filter of `" "` is
/// the same operator intent as a blank one.
pub(crate) fn non_empty(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// `#[serde(default, deserialize_with = "empty_is_absent")]` for an
/// `Option<String>` filter.
///
/// The `default` is not optional: `deserialize_with` is only reached for a key
/// that is *present*, so without it a missing filter becomes a deserialization
/// error rather than `None` — which would break the unfiltered first load of
/// every list page.
pub(crate) fn empty_is_absent<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw.as_deref().and_then(non_empty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::Uri;

    #[derive(Debug, Deserialize)]
    struct Filters {
        #[serde(default, deserialize_with = "empty_is_absent")]
        profile: Option<String>,
    }

    /// Through the real extractor, not a hand-rolled parse: what this module
    /// has to get right is what `Query` does with a key that is present and
    /// blank, which is the whole of the bug.
    fn parse(query: &str) -> Option<String> {
        let uri: Uri = format!("/ui/expiring{query}").parse().expect("a valid URI");
        Query::<Filters>::try_from_uri(&uri)
            .expect("the query string parses")
            .0
            .profile
    }

    /// The reported bug, at the layer that decides it: the spellings a
    /// `<select>` on "every profile" can produce all mean *no filter*, and a
    /// real name still survives — trimmed, since a text input can carry a
    /// space the operator cannot see.
    #[test]
    fn a_blank_filter_is_absent_and_a_named_one_survives_trimmed() {
        assert_eq!(parse(""), None, "an omitted key is the unfiltered load");
        assert_eq!(parse("?profile="), None, "what the form actually submits");
        assert_eq!(parse("?profile=%20%20"), None, "spaces are still blank");
        assert_eq!(parse("?profile=le"), Some("le".to_string()));
        assert_eq!(parse("?profile=%20le%20"), Some("le".to_string()));
    }

    /// The `&str` half, which the EAB write form calls directly.
    #[test]
    fn non_empty_answers_for_the_same_four_shapes() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("   "), None);
        assert_eq!(non_empty("le"), Some("le".to_string()));
        assert_eq!(non_empty("  le  "), Some("le".to_string()));
    }
}
