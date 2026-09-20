//! The one place either driver is named, and the reason the SQL is written
//! once.
//!
//! Every statement in this crate is a runtime `sqlx::query` in a dialect both
//! SQLite and PostgreSQL accept: epoch-second integers rather than dates, no
//! `strftime`/`julianday`/`CAST`/`||`, `ON CONFLICT … DO NOTHING` rather than
//! `INSERT OR IGNORE`, and `RETURNING` where a write has to read itself back.
//! What is *not* shared is the parameter marker, the row type and the pool
//! type, and this module is the whole of that seam: [`Query`] carries the SQL
//! and its [`Value`]s until an [`Exec`] says which driver is on the other end,
//! [`Row`] hides which row came back, and [`Builder`] replaces
//! `sqlx::QueryBuilder` for the paged listings.
//!
//! ## Placeholders
//!
//! Statements are written with `?`, as they always were, and
//! [`to_dollar_placeholders`] rewrites them to `$1…$n` on the way to
//! PostgreSQL. Writing `$n` in the source would have worked on both — sqlx's
//! SQLite driver parses a `$N` marker and binds argument `N`
//! (`sqlx-sqlite/src/arguments.rs`) — but every number would then be a hand-
//! maintained constant, and three things here build SQL by concatenation: the
//! `live_certificate!` predicate spliced into the middle of three statements,
//! the `IN (?, ?, …)` lists expanded per element, and the `format!`ed
//! fragments in `job::claim_next` and `job::settle`. One rewrite at the edge is
//! the same answer for all of them, and it cannot drift.
//!
//! The rewrite deliberately skips `'…'` string literals. No statement in this
//! crate holds a `?` inside one today; a test pins that the rewriter would
//! survive it if one arrived.
//!
//! ## Adding a bound type
//!
//! [`Value`] has six variants because six are what the schema holds. A new one
//! means a variant, a [`Bind`] impl and an arm in each of the two encoders —
//! and, if it is read back, a [`Decode`] impl. Prefer reusing one: a JSON
//! column is bound and read as [`Value::Text`], and a status enum as its
//! `as_str`.

use sqlx::postgres::{PgConnection, PgRow};
use sqlx::sqlite::{SqliteConnection, SqliteRow};
use sqlx::{Postgres, Row as _, SqlSafeStr as _, Sqlite};
use uuid::Uuid;

use crate::db::Database;

/// Which dialect is on the other end of a connection.
///
/// Reached through [`Database::dialect`]. Only two things ever branch on it:
/// the identifier search in `order.rs`, whose JSON functions have no shared
/// spelling, and [`is_unique_violation_on`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    /// The `FROM` fragment that walks the JSON array in `column`, aliased
    /// `ident`.
    ///
    /// `orders.identifiers` is a JSON array of `{type, value}` objects and the
    /// operator listing matches a name inside it. Neither dialect indexes that,
    /// so it is a scan either way — defensible on an operator-driven listing
    /// over a retention-swept table, and the reason this is three words of
    /// dialect rather than two whole queries.
    #[must_use]
    pub fn json_array_source(self, column: &str) -> String {
        match self {
            Dialect::Sqlite => format!("json_each({column}) AS ident"),
            // The column is `text`, so it is cast rather than stored as jsonb:
            // the schema is shared with SQLite, which has no such type.
            Dialect::Postgres => format!("jsonb_array_elements({column}::jsonb) AS ident"),
        }
    }

    /// The element's `value` member, as text, from the alias above.
    #[must_use]
    pub fn json_member(self, member: &str) -> String {
        match self {
            Dialect::Sqlite => format!("json_extract(ident.value, '$.{member}')"),
            Dialect::Postgres => format!("ident.value ->> '{member}'"),
        }
    }

    /// `haystack, needle` substring search returning a 1-based position.
    ///
    /// Deliberately not PostgreSQL's `position(needle in haystack)`: it takes
    /// its arguments the other way round, so the two dialects would bind in
    /// different orders from one `push_bind` sequence. `strpos` matches
    /// `instr`'s order, which is what keeps the caller dialect-free.
    #[must_use]
    pub fn substring_position(self) -> &'static str {
        match self {
            Dialect::Sqlite => "instr",
            Dialect::Postgres => "strpos",
        }
    }
}

/// One bound parameter, in the only six shapes this schema stores.
///
/// Timestamps are [`Value::I64`] epoch seconds, not a date type — see the
/// module doc. JSON columns are [`Value::Text`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// An absent value, **carrying the type of the column it is bound to**.
    ///
    /// SQLite has no typed null: a bound `None` is `NULL` whatever the caller
    /// had in mind. PostgreSQL sends a type OID with every parameter and
    /// refuses `column "eab_kid" is of type uuid but expression is of type
    /// bigint`, so the type an absent value would have had has to survive the
    /// trip. Every bind site knows it statically — `Option<Uuid>` is
    /// `Null(NullKind::Uuid)` — so nothing has to be declared twice.
    Null(NullKind),
    Bool(bool),
    I64(i64),
    Text(String),
    Blob(Vec<u8>),
    Uuid(Uuid),
}

/// The type an absent value would have had. See [`Value::Null`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullKind {
    Bool,
    I64,
    Text,
    Blob,
    Uuid,
}

/// What [`Query::bind`] accepts.
///
/// Implemented for the owned and borrowed spellings of each [`Value`], and for
/// `Option<T>` of every one of them, since a nullable column is bound from an
/// `Option` at most call sites.
pub trait Bind {
    fn to_value(self) -> Value;
}

macro_rules! bind {
    ($($ty:ty => $kind:ident, |$v:ident| $body:expr),* $(,)?) => {$(
        impl Bind for $ty {
            fn to_value(self) -> Value {
                let $v = self;
                $body
            }
        }
        impl Bind for Option<$ty> {
            fn to_value(self) -> Value {
                match self {
                    Some($v) => { $body }
                    None => Value::Null(NullKind::$kind),
                }
            }
        }
    )*};
}

bind! {
    bool => Bool, |v| Value::Bool(v),
    i64 => I64, |v| Value::I64(v),
    i32 => I64, |v| Value::I64(i64::from(v)),
    u32 => I64, |v| Value::I64(i64::from(v)),
    String => Text, |v| Value::Text(v),
    &str => Text, |v| Value::Text(v.to_string()),
    &String => Text, |v| Value::Text(v.clone()),
    Vec<u8> => Blob, |v| Value::Blob(v),
    &[u8] => Blob, |v| Value::Blob(v.to_vec()),
    &Vec<u8> => Blob, |v| Value::Blob(v.clone()),
    Uuid => Uuid, |v| Value::Uuid(v),
    &Uuid => Uuid, |v| Value::Uuid(*v),
}

/// A nullable column bound from a reference to the `Option` that holds it.
///
/// Most call sites write `.bind(&row.field)` rather than cloning first, so this
/// is the shape half the binds in the crate take.
impl<T: Clone> Bind for &Option<T>
where
    Option<T>: Bind,
{
    fn to_value(self) -> Value {
        self.clone().to_value()
    }
}

/// Rewrites `?` markers to `$1…$n`, leaving `'…'` literals alone.
///
/// PostgreSQL's only parameter syntax is the numbered one. The numbering is
/// positional and contiguous by construction, which is what makes it safe to
/// apply to SQL assembled from fragments.
#[must_use]
pub fn to_dollar_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut next = 1u32;
    let mut in_literal = false;
    let mut chars = sql.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // `''` inside a literal is an escaped quote, not its end.
            '\'' => {
                out.push(c);
                if in_literal && chars.peek() == Some(&'\'') {
                    out.push('\'');
                    chars.next();
                } else {
                    in_literal = !in_literal;
                }
            }
            '?' if !in_literal => {
                out.push('$');
                out.push_str(&next.to_string());
                next += 1;
            }
            _ => out.push(c),
        }
    }
    out
}

/// A statement and its parameters, before either driver has seen it.
pub struct Query {
    sql: sqlx::SqlStr,
    args: Vec<Value>,
}

/// Starts a statement. The SQL is written with `?` markers.
///
/// Takes [`sqlx::SqlSafeStr`], which is `&'static str` or an explicit
/// [`sqlx::AssertSqlSafe`] — not any `String`. That is the whole of what stops
/// a column list, a predicate or a value being interpolated into a statement
/// by accident: a literal needs nothing, and a statement built at runtime has
/// to say so at the call site. Every value goes through [`Query::bind`]
/// regardless, so a filter is compared and never executed.
#[must_use]
pub fn query(sql: impl sqlx::SqlSafeStr) -> Query {
    Query {
        sql: sql.into_sql_str(),
        args: Vec::new(),
    }
}

/// What a write reports back. A thin wrapper so a call site reads the same
/// whichever driver ran it.
#[derive(Debug, Clone, Copy)]
pub struct QueryResult {
    rows_affected: u64,
}

impl QueryResult {
    /// How many rows the statement changed.
    ///
    /// The single-use idiom several tables rest on — a guarded `DELETE` or
    /// `UPDATE` whose `== 1` names the one caller that won a race. Exact on
    /// both drivers for `UPDATE`/`DELETE`, and `0` on both for an
    /// `ON CONFLICT … DO NOTHING` that conflicted.
    #[must_use]
    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }
}

impl Query {
    /// Appends one parameter, in the order its `?` appears.
    #[must_use]
    pub fn bind(mut self, value: impl Bind) -> Self {
        self.args.push(value.to_value());
        self
    }

    /// The SQL as this query would send it to `dialect`, for tests and for the
    /// placeholder audit.
    #[must_use]
    pub fn sql_for(&self, dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => self.sql.as_str().to_string(),
            Dialect::Postgres => to_dollar_placeholders(self.sql.as_str()),
        }
    }

    /// Runs a statement that returns no rows.
    pub async fn execute<'a>(self, exec: impl Into<Exec<'a>>) -> Result<QueryResult, sqlx::Error> {
        let rows_affected = match exec.into() {
            Exec::SqlitePool(pool) => self.sqlite().execute(pool).await?.rows_affected(),
            Exec::SqliteConn(conn) => self.sqlite().execute(conn).await?.rows_affected(),
            Exec::PgPool(pool) => self.postgres().execute(pool).await?.rows_affected(),
            Exec::PgConn(conn) => self.postgres().execute(conn).await?.rows_affected(),
        };
        Ok(QueryResult { rows_affected })
    }

    /// Runs a statement expecting exactly one row.
    pub async fn fetch_one<'a>(self, exec: impl Into<Exec<'a>>) -> Result<Row, sqlx::Error> {
        Ok(match exec.into() {
            Exec::SqlitePool(pool) => Row::Sqlite(self.sqlite().fetch_one(pool).await?),
            Exec::SqliteConn(conn) => Row::Sqlite(self.sqlite().fetch_one(conn).await?),
            Exec::PgPool(pool) => Row::Postgres(self.postgres().fetch_one(pool).await?),
            Exec::PgConn(conn) => Row::Postgres(self.postgres().fetch_one(conn).await?),
        })
    }

    /// Runs a statement expecting at most one row.
    pub async fn fetch_optional<'a>(
        self,
        exec: impl Into<Exec<'a>>,
    ) -> Result<Option<Row>, sqlx::Error> {
        Ok(match exec.into() {
            Exec::SqlitePool(pool) => self.sqlite().fetch_optional(pool).await?.map(Row::Sqlite),
            Exec::SqliteConn(conn) => self.sqlite().fetch_optional(conn).await?.map(Row::Sqlite),
            Exec::PgPool(pool) => self
                .postgres()
                .fetch_optional(pool)
                .await?
                .map(Row::Postgres),
            Exec::PgConn(conn) => self
                .postgres()
                .fetch_optional(conn)
                .await?
                .map(Row::Postgres),
        })
    }

    /// Runs a statement returning any number of rows.
    pub async fn fetch_all<'a>(self, exec: impl Into<Exec<'a>>) -> Result<Vec<Row>, sqlx::Error> {
        Ok(match exec.into() {
            Exec::SqlitePool(pool) => self
                .sqlite()
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(Row::Sqlite)
                .collect(),
            Exec::SqliteConn(conn) => self
                .sqlite()
                .fetch_all(conn)
                .await?
                .into_iter()
                .map(Row::Sqlite)
                .collect(),
            Exec::PgPool(pool) => self
                .postgres()
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect(),
            Exec::PgConn(conn) => self
                .postgres()
                .fetch_all(conn)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect(),
        })
    }

    /// The SQLite statement, with its arguments bound in order.
    fn sqlite(self) -> sqlx::query::Query<'static, Sqlite, sqlx::sqlite::SqliteArguments> {
        let mut q = sqlx::query(self.sql);
        for value in self.args {
            q = match value {
                Value::Null(NullKind::Bool) => q.bind(None::<bool>),
                Value::Null(NullKind::I64) => q.bind(None::<i64>),
                Value::Null(NullKind::Text) => q.bind(None::<String>),
                Value::Null(NullKind::Blob) => q.bind(None::<Vec<u8>>),
                Value::Null(NullKind::Uuid) => q.bind(None::<Uuid>),
                Value::Bool(v) => q.bind(v),
                Value::I64(v) => q.bind(v),
                Value::Text(v) => q.bind(v),
                Value::Blob(v) => q.bind(v),
                Value::Uuid(v) => q.bind(v),
            };
        }
        q
    }

    /// The PostgreSQL statement, with `?` rewritten and its arguments bound.
    fn postgres(self) -> sqlx::query::Query<'static, Postgres, sqlx::postgres::PgArguments> {
        let mut q = sqlx::query(sqlx::AssertSqlSafe(to_dollar_placeholders(
            self.sql.as_str(),
        )));
        for value in self.args {
            q = match value {
                Value::Null(NullKind::Bool) => q.bind(None::<bool>),
                Value::Null(NullKind::I64) => q.bind(None::<i64>),
                Value::Null(NullKind::Text) => q.bind(None::<String>),
                Value::Null(NullKind::Blob) => q.bind(None::<Vec<u8>>),
                Value::Null(NullKind::Uuid) => q.bind(None::<Uuid>),
                Value::Bool(v) => q.bind(v),
                Value::I64(v) => q.bind(v),
                Value::Text(v) => q.bind(v),
                Value::Blob(v) => q.bind(v),
                Value::Uuid(v) => q.bind(v),
            };
        }
        q
    }
}

/// One row, from whichever driver produced it.
#[derive(Debug)]
pub enum Row {
    Sqlite(SqliteRow),
    Postgres(PgRow),
}

/// A column, named or positional.
///
/// Most reads name the column; the handful that do not are `COUNT(*)` scalars
/// selected without an alias.
pub enum Idx<'a> {
    Name(&'a str),
    Position(usize),
}

impl<'a> From<&'a str> for Idx<'a> {
    fn from(name: &'a str) -> Self {
        Idx::Name(name)
    }
}

impl From<usize> for Idx<'_> {
    fn from(position: usize) -> Self {
        Idx::Position(position)
    }
}

/// What [`Row::try_get`] can read back.
///
/// Two methods rather than one generic bound, because the driver row types
/// decode through separate traits. The impls are mechanical; the list of types
/// is short because the schema stores five.
pub trait Decode: Sized {
    fn from_sqlite(row: &SqliteRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error>;
    fn from_pg(row: &PgRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error>;
}

macro_rules! decode {
    ($($ty:ty),* $(,)?) => {$(
        impl Decode for $ty {
            fn from_sqlite(row: &SqliteRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error> {
                match idx {
                    Idx::Name(name) => row.try_get(*name),
                    Idx::Position(i) => row.try_get(*i),
                }
            }
            fn from_pg(row: &PgRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error> {
                match idx {
                    Idx::Name(name) => row.try_get(*name),
                    Idx::Position(i) => row.try_get(*i),
                }
            }
        }
        impl Decode for Option<$ty> {
            fn from_sqlite(row: &SqliteRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error> {
                match idx {
                    Idx::Name(name) => row.try_get(*name),
                    Idx::Position(i) => row.try_get(*i),
                }
            }
            fn from_pg(row: &PgRow, idx: &Idx<'_>) -> Result<Self, sqlx::Error> {
                match idx {
                    Idx::Name(name) => row.try_get(*name),
                    Idx::Position(i) => row.try_get(*i),
                }
            }
        }
    )*};
}

decode!(bool, i64, String, Vec<u8>, Uuid);

impl Row {
    /// Reads one column.
    ///
    /// The signature every `from_row` in this crate calls, so those bodies read
    /// the same as they did against `SqliteRow`.
    pub fn try_get<'i, T: Decode>(&self, idx: impl Into<Idx<'i>>) -> Result<T, sqlx::Error> {
        let idx = idx.into();
        match self {
            Row::Sqlite(row) => T::from_sqlite(row, &idx),
            Row::Postgres(row) => T::from_pg(row, &idx),
        }
    }
}

/// Where a statement is about to run.
///
/// Built through `Into`, so a call site passes a `&Database`, a transaction's
/// connection or a bare pool and the enum is an implementation detail.
pub enum Exec<'a> {
    SqlitePool(&'a sqlx::Pool<Sqlite>),
    SqliteConn(&'a mut SqliteConnection),
    PgPool(&'a sqlx::Pool<Postgres>),
    PgConn(&'a mut PgConnection),
}

impl<'a> From<&'a Database> for Exec<'a> {
    fn from(database: &'a Database) -> Self {
        database.exec()
    }
}

/// Most callers outside this crate hold the database behind an `Arc`, so a
/// statement takes one without being handed `&*db` at every site.
impl<'a> From<&'a std::sync::Arc<Database>> for Exec<'a> {
    fn from(database: &'a std::sync::Arc<Database>) -> Self {
        database.exec()
    }
}

impl<'a> From<&'a sqlx::Pool<Sqlite>> for Exec<'a> {
    fn from(pool: &'a sqlx::Pool<Sqlite>) -> Self {
        Exec::SqlitePool(pool)
    }
}

impl<'a> From<&'a sqlx::Pool<Postgres>> for Exec<'a> {
    fn from(pool: &'a sqlx::Pool<Postgres>) -> Self {
        Exec::PgPool(pool)
    }
}

impl<'a> From<&'a mut SqliteConnection> for Exec<'a> {
    fn from(conn: &'a mut SqliteConnection) -> Self {
        Exec::SqliteConn(conn)
    }
}

impl<'a> From<&'a mut PgConnection> for Exec<'a> {
    fn from(conn: &'a mut PgConnection) -> Self {
        Exec::PgConn(conn)
    }
}

impl Exec<'_> {
    /// Which dialect this will speak.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        match self {
            Exec::SqlitePool(_) | Exec::SqliteConn(_) => Dialect::Sqlite,
            Exec::PgPool(_) | Exec::PgConn(_) => Dialect::Postgres,
        }
    }

    /// Borrows this executor again, for a caller that runs two statements.
    ///
    /// An `Exec` owns a `&mut` connection, so it cannot be `Copy`; a function
    /// handed one and issuing more than one statement reborrows instead.
    pub fn reborrow(&mut self) -> Exec<'_> {
        match self {
            Exec::SqlitePool(pool) => Exec::SqlitePool(pool),
            Exec::SqliteConn(conn) => Exec::SqliteConn(conn),
            Exec::PgPool(pool) => Exec::PgPool(pool),
            Exec::PgConn(conn) => Exec::PgConn(conn),
        }
    }
}

/// Was this error a unique-violation on one particular constraint?
///
/// The two dialects say so differently and neither says both things. SQLite
/// names the **columns** — `UNIQUE constraint failed: orders.profile,
/// orders.replaces` — and gives sqlx no constraint name. PostgreSQL names the
/// **index** — `duplicate key value violates unique constraint
/// "idx_orders_replaces_claim"` — and exposes it through
/// [`sqlx::error::DatabaseError::constraint`].
///
/// So a caller passes both spellings and this picks the one the driver can
/// answer. Matching on message text alone, as this used to, silently stopped
/// recognising the collision under PostgreSQL and turned a `409` into a `500`.
#[must_use]
pub fn is_unique_violation_on(
    error: &sqlx::Error,
    sqlite_columns: &str,
    pg_constraint: &str,
) -> bool {
    let sqlx::Error::Database(db) = error else {
        return false;
    };
    if !db.is_unique_violation() {
        return false;
    }
    match db.constraint() {
        Some(name) => name == pg_constraint,
        None => db.message().contains(sqlite_columns),
    }
}

/// `sqlx::QueryBuilder`'s job, over [`Value`] rather than one driver.
///
/// The paged listings build two of these per query — the page and its
/// `COUNT(*)` — sharing one `push_predicates`, so a filter applied to only one
/// cannot report a total the rows disagree with. See [`crate::query`].
pub struct Builder {
    dialect: Dialect,
    sql: String,
    args: Vec<Value>,
}

impl Builder {
    /// Starts a builder from a leading fragment.
    ///
    /// The dialect comes in here rather than at `build`, because a predicate
    /// may need it — see [`Dialect::json_array_source`].
    #[must_use]
    pub fn new(dialect: Dialect, sql: impl Into<String>) -> Self {
        Builder {
            dialect,
            sql: sql.into(),
            args: Vec::new(),
        }
    }

    /// Which dialect the fragments pushed onto this must be written for.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Appends SQL verbatim. Never reached by a value from outside.
    pub fn push(&mut self, sql: impl AsRef<str>) -> &mut Self {
        self.sql.push_str(sql.as_ref());
        self
    }

    /// Appends a `?` marker and the value behind it, so a filter is compared
    /// and never executed.
    pub fn push_bind(&mut self, value: impl Bind) -> &mut Self {
        self.sql.push('?');
        self.args.push(value.to_value());
        self
    }

    /// A run of values joined by `sep`, for an `IN (…)` list.
    ///
    /// `QueryBuilder::separated`'s job. Each value is still a `?`, so a list of
    /// ids is parameters rather than interpolated SQL — the rule
    /// `OrderQuery::push_predicates` follows too.
    pub fn separated<'b>(&'b mut self, sep: &'static str) -> Separated<'b> {
        Separated {
            builder: self,
            sep,
            first: true,
        }
    }

    /// The statement built so far, in SQLite's spelling. For tests.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Hands the built statement over to be run.
    ///
    /// The assertion is the builder's own: every fragment reaching [`push`] is
    /// a literal from this crate, and every value went through
    /// [`push_bind`](Self::push_bind) as a `?`.
    ///
    /// [`push`]: Self::push
    #[must_use]
    pub fn build(self) -> Query {
        Query {
            sql: sqlx::AssertSqlSafe(self.sql).into_sql_str(),
            args: self.args,
        }
    }
}

/// A comma-separated run of bound values, handed out by [`Builder::separated`].
pub struct Separated<'b> {
    builder: &'b mut Builder,
    sep: &'static str,
    first: bool,
}

impl Separated<'_> {
    /// Appends the separator (except before the first) and one bound value.
    pub fn push_bind(&mut self, value: impl Bind) -> &mut Self {
        if !self.first {
            self.builder.push(self.sep);
        }
        self.first = false;
        self.builder.push_bind(value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_separated_run_joins_only_between_values() {
        let mut builder = Builder::new(Dialect::Sqlite, "SELECT 1 WHERE id IN (");
        let mut list = builder.separated(", ");
        for id in [1i64, 2, 3] {
            list.push_bind(id);
        }
        builder.push(")");
        assert_eq!(builder.sql(), "SELECT 1 WHERE id IN (?, ?, ?)");
    }

    #[test]
    fn markers_are_numbered_in_order() {
        assert_eq!(
            to_dollar_placeholders("SELECT a FROM t WHERE b = ? AND c = ?;"),
            "SELECT a FROM t WHERE b = $1 AND c = $2;"
        );
    }

    #[test]
    fn nothing_to_rewrite_is_returned_unchanged() {
        let sql = "SELECT COUNT(*) FROM nonces;";
        assert_eq!(to_dollar_placeholders(sql), sql);
    }

    /// The property the whole seam rests on: numbering is contiguous from `$1`.
    ///
    /// sqlx's SQLite driver binds NULL rather than erroring for a `$N` beyond
    /// the argument count, so a gap would not surface as a failure anywhere —
    /// it would surface as a row that quietly did not match.
    #[test]
    fn numbering_is_contiguous_from_one() {
        let rewritten = to_dollar_placeholders("? ? ? ? ? ? ? ? ? ? ?");
        let numbers: Vec<u32> = rewritten
            .split_whitespace()
            .map(|marker| marker.trim_start_matches('$').parse().expect("a number"))
            .collect();
        assert_eq!(numbers, (1..=11).collect::<Vec<u32>>());
    }

    /// A `?` inside a string literal is data, not a marker.
    ///
    /// No statement in this crate has one today. The rewriter skips literals so
    /// that adding one is not a silent renumbering of every marker after it.
    #[test]
    fn a_marker_inside_a_string_literal_is_left_alone() {
        assert_eq!(
            to_dollar_placeholders("UPDATE t SET a = 'what?' WHERE b = ?;"),
            "UPDATE t SET a = 'what?' WHERE b = $1;"
        );
    }

    /// `''` is an escaped quote, so the literal does not end there.
    #[test]
    fn an_escaped_quote_does_not_end_a_literal() {
        assert_eq!(
            to_dollar_placeholders("SELECT 'it''s ? fine' WHERE a = ?;"),
            "SELECT 'it''s ? fine' WHERE a = $1;"
        );
    }

    #[test]
    fn a_builder_pushes_markers_and_values_together() {
        let mut builder = Builder::new(Dialect::Sqlite, "SELECT 1 FROM t");
        builder.push(" WHERE a = ").push_bind("x");
        builder.push(" AND b = ").push_bind(7i64);

        assert_eq!(builder.sql(), "SELECT 1 FROM t WHERE a = ? AND b = ?");
        let query = builder.build();
        assert_eq!(
            query.sql_for(Dialect::Postgres),
            "SELECT 1 FROM t WHERE a = $1 AND b = $2"
        );
        assert_eq!(
            query.args,
            vec![Value::Text("x".to_string()), Value::I64(7)]
        );
    }

    /// An absent value keeps the type it would have had.
    ///
    /// The property PostgreSQL needs: a `None::<Uuid>` bound as `bigint` is
    /// `column "eab_kid" is of type uuid but expression is of type bigint`,
    /// which is how a whole `newAccount` used to fail against it.
    #[test]
    fn an_absent_optional_binds_null_at_its_own_type() {
        assert_eq!(
            super::query("SELECT ?").bind(None::<String>).args,
            vec![Value::Null(NullKind::Text)]
        );
        assert_eq!(
            super::query("SELECT ?").bind(None::<Uuid>).args,
            vec![Value::Null(NullKind::Uuid)]
        );
        assert_eq!(
            super::query("SELECT ?").bind(None::<bool>).args,
            vec![Value::Null(NullKind::Bool)]
        );
    }

    #[test]
    fn a_present_optional_binds_its_value() {
        let query = super::query("SELECT ?").bind(Some(3i64));
        assert_eq!(query.args, vec![Value::I64(3)]);
    }
}
