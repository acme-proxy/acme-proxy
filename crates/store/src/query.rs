//! The one piece every paged listing in this tree builds its `WHERE` from.
//!
//! Five models answer an operator listing — `accounts`, `orders`, `jobs`,
//! `upstream_orders`, `audit_log` — and each does it the same way: a
//! `QueryBuilder` for the page, a second one for the `COUNT(*)`, and one
//! `push_predicates` shared between them so a filter applied to only one cannot
//! report a total the rows disagree with.
//!
//! What was written out per model is the *leading* run of equality predicates:
//! a `separator` that starts at `" WHERE "` and becomes `" AND "` the first
//! time something is pushed. Three copies of seven lines, and the copies had
//! already started to differ in the one way that matters — `OrderQuery`'s last
//! predicate did not advance the separator, correct only because nothing
//! followed it. [`push_equalities`] returns the next separator instead of
//! hiding it, so a model with predicates of its own threads it on and the
//! compiler notices when one does not.

/// Appends `column = ?` for each `Some` value, starting from `separator` and
/// returning the separator the next predicate should use.
///
/// Every value goes through `push_bind`, so a filter is compared and never
/// executed — the property `search_binds_hostile_filters_as_values` exists for
/// in each model's own suite.
pub(crate) fn push_equalities(
    builder: &mut sqlx::QueryBuilder<sqlx::Sqlite>,
    separator: &'static str,
    pairs: &[(&str, Option<&str>)],
) -> &'static str {
    let mut separator = separator;
    for (column, value) in pairs {
        if let Some(value) = value {
            builder
                .push(separator)
                .push(column)
                .push_bind((*value).to_string());
            separator = " AND ";
        }
    }
    separator
}

/// The separator a `WHERE` clause opens with.
pub(crate) const WHERE: &str = " WHERE ";

#[cfg(test)]
mod tests {
    use super::*;

    fn sql_of(pairs: &[(&str, Option<&str>)]) -> (String, &'static str) {
        let mut builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT 1 FROM t");
        let next = push_equalities(&mut builder, WHERE, pairs);
        (builder.into_sql().as_str().to_string(), next)
    }

    #[test]
    fn the_first_predicate_opens_the_clause_and_the_rest_extend_it() {
        let (sql, next) = sql_of(&[("a = ", Some("x")), ("b = ", Some("y"))]);
        assert_eq!(sql, "SELECT 1 FROM t WHERE a = ? AND b = ?");
        assert_eq!(next, " AND ", "a caller with more predicates continues");
    }

    #[test]
    fn a_none_contributes_nothing_and_does_not_consume_the_where() {
        let (sql, next) = sql_of(&[("a = ", None), ("b = ", Some("y"))]);
        assert_eq!(sql, "SELECT 1 FROM t WHERE b = ?");
        assert_eq!(next, " AND ");
    }

    /// The case the returned separator exists for: nothing matched, so a
    /// caller's own predicate still has to open the clause.
    #[test]
    fn all_none_leaves_the_clause_unopened() {
        let (sql, next) = sql_of(&[("a = ", None), ("b = ", None)]);
        assert_eq!(sql, "SELECT 1 FROM t");
        assert_eq!(next, WHERE);
    }

    /// A hostile value is a bound parameter, never SQL.
    #[test]
    fn a_value_is_bound_not_interpolated() {
        let (sql, _) = sql_of(&[("a = ", Some("' OR 1=1 --"))]);
        assert_eq!(sql, "SELECT 1 FROM t WHERE a = ?");
    }
}
