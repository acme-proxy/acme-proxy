//! Row ids: minting them, and reading one that arrived from outside.
//!
//! Every id this server mints is a **UUID version 7** (RFC 9562 §5.7): a
//! 48-bit big-endian millisecond timestamp, then random bits. Two properties
//! follow, and both are why the version moved from 4.
//!
//! The ids of rows created close together share a prefix, so an index over
//! them is written at its right-hand edge rather than at a fresh random leaf
//! per insert. SQLite feels that only mildly — an id column is a secondary
//! index over the rowid, and one writer at a time dominates — but the
//! PostgreSQL backend `TODO.md` plans is where a random primary key costs a
//! page split and a full-page WAL write per row.
//!
//! And they sort by creation. `ORDER BY created_at, id` is the tie-break seven
//! paged listings use on a whole-second `created_at`, so that tie-break is now
//! chronological where a v4 gave a fresh random permutation per pair. Only
//! among rows minted since the change: the ids already in a table were
//! converted in place and keep the v4 bits they were minted with, so a v4 and a
//! v7 in the same second still tie arbitrarily, for ever.
//!
//! Ids are stored as the 16 bytes themselves, not as text — `sqlx`'s `uuid`
//! feature encodes a [`Uuid`] as a SQLite BLOB and decodes it with
//! `Uuid::from_slice`, and maps the same type to Postgres's native `uuid`. So
//! there is no decode helper here: `row.try_get::<Uuid, _>("id")` is the whole
//! of it. What there is instead is [`parse`], for the one direction that can
//! fail.
//!
//! Three mints in this crate are deliberately **not** row ids and do not come
//! through [`mint`]: the `x-request-id` fallback
//! ([`crate::middlewares::access`]), the job runner's lease-owner id
//! ([`crate::jobs::runner`]) and a notification's `delivery_id`
//! ([`crate::notify`]). None is the identity of a row, and reaching into the
//! storage layer for a value that never reaches storage would be backwards.

use uuid::Uuid;

/// A fresh row id.
///
/// The single place the version is chosen, which is what lets
/// `declared_id_widths_match_a_minted_id` (`crate::sqlite::db`) pin it and what
/// would make a move to some later version one line plus one test.
#[must_use]
pub fn mint() -> Uuid {
    Uuid::now_v7()
}

/// Parses an id that arrived from outside the process.
///
/// `None` for anything an id column could not hold — a `kid` a client invented,
/// a path segment an operator mistyped, a scanner probing `/acct/../..`. Every
/// caller turns that into the same answer an unknown-but-well-formed id gets,
/// so no request path grows a "malformed id" case RFC 8555 has no code for.
///
/// Deliberately narrower than [`Uuid::try_parse`], which also accepts the
/// 32-character simple form, `{braced}` and `urn:uuid:` spellings, and
/// upper-case hex. Every id this server has ever written came from
/// `Uuid::to_string()`, so 36 hyphenated characters is the only shape a column
/// holds and the only one a URL this server minted can carry. Accepting the
/// others would start resolving URLs that answer "not found" today, which is a
/// change of behaviour wearing a refactor's clothes.
#[must_use]
pub fn parse(value: &str) -> Option<Uuid> {
    if value.len() != 36 {
        return None;
    }
    Uuid::try_parse(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_is_a_version_7_uuid_in_the_stored_spelling() {
        let id = mint();

        assert_eq!(id.get_version_num(), 7, "RFC 9562 §5.7");
        assert_eq!(
            id.to_string().len(),
            36,
            "hyphenated, which is what a column holds"
        );
        assert_ne!(mint(), mint());
    }

    /// The property the whole change rests on, and the one nothing else states.
    ///
    /// The second assertion is the load-bearing one: `ORDER BY id` compares the
    /// *stored* value, so a version that sorted correctly as an integer but not
    /// in its own encoding would buy the listings nothing.
    #[test]
    fn two_mints_sort_the_way_they_were_created() {
        let first = mint();
        let second = mint();

        assert!(first < second, "{first} should sort before {second}");
        assert!(
            first.as_bytes() < second.as_bytes(),
            "and so should the bytes a column holds"
        );
    }

    #[test]
    fn parse_takes_the_stored_spelling_and_nothing_else() {
        let id = mint();
        assert_eq!(parse(&id.to_string()), Some(id));

        // Every shape `Uuid::try_parse` would have taken, and which resolved to
        // "not found" before this function existed.
        assert_eq!(
            parse(&id.simple().to_string()),
            None,
            "32-character simple form"
        );
        assert_eq!(parse(&format!("{{{id}}}")), None, "braced");
        assert_eq!(parse(&id.urn().to_string()), None, "urn:uuid:");

        assert_eq!(parse(""), None);
        assert_eq!(parse("nope"), None);
        assert_eq!(parse("../../etc/passwd"), None);
        // Right length, wrong alphabet.
        assert_eq!(parse("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"), None);
    }

    /// A v4 minted before the switch still parses.
    ///
    /// Nothing was backfilled — an account id is a foreign key, a `kid` is a
    /// credential a client stored, and an order id is inside a URL a client
    /// polls for weeks — so the tables hold both versions and will for ever.
    #[test]
    fn an_id_minted_before_the_switch_still_parses() {
        let v4 = "550e8400-e29b-41d4-a716-446655440000";

        let parsed = parse(v4).expect("a v4 is still an id");
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.to_string(), v4);
    }
}
