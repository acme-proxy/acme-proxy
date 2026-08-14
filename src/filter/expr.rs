//! The condition language a `[filter.rule.<name>]` is written in.
//!
//! A rule's `when` is a boolean expression over the names of
//! `[filter.check.<name>]` entries:
//!
//! ```text
//! when = "mgmt-net or (inventory and corp-names)"
//! ```
//!
//! ```text
//! expr   := term ( "or" term )*
//! term   := factor ( "and" factor )*
//! factor := "not" factor | "(" expr ")" | name
//! name   := [a-z0-9-]+
//! ```
//!
//! `not` binds tightest, then `and`, then `or`; `and` and `or` are
//! left-associative. The three keywords are matched case-insensitively, and a
//! check may therefore not be *named* one of them — [`is_reserved_word`] is
//! what the policy builder asks, since the tokenizer resolves the ambiguity in
//! the keyword's favour and a check named `and` would simply be unreachable.
//!
//! ## Why a string and not nested TOML
//!
//! An `all`/`any`/`none` table would need no parser, but
//! [`Config::merged_sections`](crate::config::Config) merges a profile's
//! configuration onto the global one **per key** for tables and *wholesale* for
//! everything else. A global `all = [...]` and a profile's `any = [...]` would
//! therefore merge into one table carrying both keys, and the profile would have
//! meant to replace the condition rather than add to it. A string is a scalar,
//! so it replaces — the only sane inheritance for a policy expression.
//!
//! ## Errors carry a column
//!
//! Every failure names the character position it gave up at, because the whole
//! expression is one line in a configuration file and "invalid condition" would
//! send an operator hunting through it. Columns are 1-based.

use std::fmt;

/// A parsed `when` expression.
///
/// Names are kept as written so an "undefined check" error can quote the
/// operator's own spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// A `[filter.check.<name>]` entry, by name.
    Check(String),
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
}

/// Why an expression would not parse, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprError {
    /// The problem, without the position — [`fmt::Display`] appends that.
    pub message: String,
    /// 1-based character position the parser gave up at.
    pub column: usize,
}

impl fmt::Display for ExprError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at column {}", self.message, self.column)
    }
}

impl ExprError {
    fn new(message: impl Into<String>, column: usize) -> Self {
        Self {
            message: message.into(),
            column,
        }
    }
}

/// Whether `name` is one of the three words the condition language reserves.
///
/// The tokenizer always reads these as keywords, so a check carrying one as a
/// name could never be referred to. The policy builder refuses it at startup
/// rather than letting it sit there unreachable.
#[must_use]
pub fn is_reserved_word(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        KEYWORD_AND | KEYWORD_OR | KEYWORD_NOT
    )
}

const KEYWORD_AND: &str = "and";
const KEYWORD_OR: &str = "or";
const KEYWORD_NOT: &str = "not";

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Name(String),
    And,
    Or,
    Not,
    Open,
    Close,
}

impl TokenKind {
    /// How the token is quoted back in an error message.
    fn describe(&self) -> String {
        match self {
            Self::Name(name) => format!("the check name `{name}`"),
            Self::And => "the keyword `and`".to_string(),
            Self::Or => "the keyword `or`".to_string(),
            Self::Not => "the keyword `not`".to_string(),
            Self::Open => "`(`".to_string(),
            Self::Close => "`)`".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    column: usize,
}

/// Splits the expression into tokens, remembering where each one started.
///
/// A word is lexed as `[A-Za-z0-9_-]+` rather than the grammar's stricter
/// `[a-z0-9-]+` for two reasons: the keywords are case-insensitive, so `AND`
/// has to reach the keyword comparison, and a mis-cased or underscored check
/// name is far better reported as "no such check" — which quotes what the
/// operator wrote — than as "unexpected character".
fn tokenize(source: &str) -> Result<Vec<Token>, ExprError> {
    let characters: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < characters.len() {
        let character = characters[index];
        let column = index + 1;

        if character.is_whitespace() {
            index += 1;
            continue;
        }

        match character {
            '(' => {
                tokens.push(Token {
                    kind: TokenKind::Open,
                    column,
                });
                index += 1;
            }
            ')' => {
                tokens.push(Token {
                    kind: TokenKind::Close,
                    column,
                });
                index += 1;
            }
            c if is_word_character(c) => {
                let start = index;
                while index < characters.len() && is_word_character(characters[index]) {
                    index += 1;
                }
                let word: String = characters[start..index].iter().collect();
                let kind = match word.to_ascii_lowercase().as_str() {
                    KEYWORD_AND => TokenKind::And,
                    KEYWORD_OR => TokenKind::Or,
                    KEYWORD_NOT => TokenKind::Not,
                    _ => TokenKind::Name(word),
                };
                tokens.push(Token { kind, column });
            }
            other => {
                return Err(ExprError::new(
                    format!("unexpected character {other:?}"),
                    column,
                ));
            }
        }
    }

    Ok(tokens)
}

fn is_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-' || character == '_'
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    /// Column reported for a failure at end of input.
    end_column: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next_column(&self) -> usize {
        self.peek().map_or(self.end_column, |token| token.column)
    }

    /// `expr := term ( "or" term )*`
    fn parse_expr(&mut self) -> Result<Condition, ExprError> {
        let mut left = self.parse_term()?;
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Or)) {
            self.position += 1;
            let right = self.parse_term()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `term := factor ( "and" factor )*`
    fn parse_term(&mut self) -> Result<Condition, ExprError> {
        let mut left = self.parse_factor()?;
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::And)) {
            self.position += 1;
            let right = self.parse_factor()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `factor := "not" factor | "(" expr ")" | name`
    fn parse_factor(&mut self) -> Result<Condition, ExprError> {
        let Some(token) = self.peek().cloned() else {
            return Err(ExprError::new(
                "expected a check name, `not` or `(`",
                self.end_column,
            ));
        };

        match token.kind {
            TokenKind::Not => {
                self.position += 1;
                Ok(Condition::Not(Box::new(self.parse_factor()?)))
            }
            TokenKind::Open => {
                let opened_at = token.column;
                self.position += 1;
                let inner = self.parse_expr()?;
                match self.peek().map(|token| &token.kind) {
                    Some(TokenKind::Close) => {
                        self.position += 1;
                        Ok(inner)
                    }
                    _ => Err(ExprError::new("unbalanced `(` opened", opened_at)),
                }
            }
            TokenKind::Name(name) => {
                self.position += 1;
                Ok(Condition::Check(name))
            }
            other => Err(ExprError::new(
                format!(
                    "expected a check name, `not` or `(`, found {}",
                    other.describe()
                ),
                token.column,
            )),
        }
    }
}

impl Condition {
    /// Parses a `when` expression.
    ///
    /// # Errors
    ///
    /// Returns the position of the first token that could not be read, or of
    /// the `(` that was never closed.
    pub fn parse(source: &str) -> Result<Self, ExprError> {
        let tokens = tokenize(source)?;
        let mut parser = Parser {
            tokens,
            position: 0,
            end_column: source.chars().count() + 1,
        };

        let condition = parser.parse_expr()?;

        if parser.position < parser.tokens.len() {
            return Err(ExprError::new(
                format!(
                    "unexpected trailing input starting at {}",
                    parser.tokens[parser.position].kind.describe()
                ),
                parser.next_column(),
            ));
        }

        Ok(condition)
    }

    /// Every check name the condition mentions, in evaluation order, with
    /// duplicates kept — the builder deduplicates when it resolves them.
    pub fn check_names(&self) -> Vec<&str> {
        let mut names = Vec::new();
        self.collect_names(&mut names);
        names
    }

    fn collect_names<'a>(&'a self, into: &mut Vec<&'a str>) {
        match self {
            Self::Check(name) => into.push(name),
            Self::Not(inner) => inner.collect_names(into),
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_names(into);
                right.collect_names(into);
            }
        }
    }

    /// Renders a sub-expression, parenthesized unless it is a bare name.
    fn render_operand(&self) -> String {
        match self {
            Self::Check(name) => name.clone(),
            other => format!("({other})"),
        }
    }
}

impl fmt::Display for Condition {
    /// Re-prints the expression with **every** grouping made explicit.
    ///
    /// This is what `acme-proxy filter show` prints, and the point is that it
    /// shows what the parser understood rather than what was typed: an operator
    /// who expected `a or b and c` to mean `(a or b) and c` sees
    /// `a or (b and c)` and has their answer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check(name) => formatter.write_str(name),
            Self::Not(inner) => write!(formatter, "not {}", inner.render_operand()),
            Self::And(left, right) => write!(
                formatter,
                "{} and {}",
                left.render_operand(),
                right.render_operand()
            ),
            Self::Or(left, right) => write!(
                formatter,
                "{} or {}",
                left.render_operand(),
                right.render_operand()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses and re-prints, which is how every precedence assertion below is
    /// stated: `Display` makes grouping explicit, so the round trip *is* the
    /// parse tree.
    fn printed(source: &str) -> String {
        Condition::parse(source)
            .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"))
            .to_string()
    }

    fn error(source: &str) -> ExprError {
        Condition::parse(source).expect_err(&format!("{source:?} should not parse"))
    }

    #[test]
    fn a_bare_name_is_a_condition() {
        assert_eq!(printed("mgmt-net"), "mgmt-net");
        assert_eq!(
            Condition::parse("mgmt-net").unwrap(),
            Condition::Check("mgmt-net".to_string())
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        assert_eq!(printed("a or b and c"), "a or (b and c)");
        assert_eq!(printed("a and b or c"), "(a and b) or c");
    }

    #[test]
    fn not_binds_tightest() {
        assert_eq!(printed("not a and b"), "(not a) and b");
        assert_eq!(printed("not a or b"), "(not a) or b");
        assert_eq!(printed("not not a"), "not (not a)");
    }

    #[test]
    fn both_operators_are_left_associative() {
        assert_eq!(printed("a and b and c"), "(a and b) and c");
        assert_eq!(printed("a or b or c"), "(a or b) or c");
    }

    #[test]
    fn parentheses_override_precedence() {
        assert_eq!(printed("(a or b) and c"), "(a or b) and c");
        assert_eq!(printed("not (a and b)"), "not (a and b)");
        assert_eq!(printed("((a))"), "a");
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(printed("a AND b"), "a and b");
        assert_eq!(printed("a Or NOT b"), "a or (not b)");
    }

    #[test]
    fn whitespace_is_irrelevant() {
        assert_eq!(printed("  a   and\tb  "), "a and b");
        assert_eq!(printed("not(a)or(b)"), "(not a) or b");
    }

    #[test]
    fn names_may_carry_digits_and_hyphens() {
        assert_eq!(printed("tenant-a1 and net-10"), "tenant-a1 and net-10");
    }

    #[test]
    fn check_names_are_collected_in_evaluation_order_with_duplicates() {
        let condition = Condition::parse("a or (b and not a)").unwrap();
        assert_eq!(condition.check_names(), vec!["a", "b", "a"]);
    }

    #[test]
    fn the_three_keywords_are_reserved_in_any_case() {
        for word in ["and", "or", "not", "AND", "Or", "NOT"] {
            assert!(is_reserved_word(word), "{word} should be reserved");
        }
        assert!(!is_reserved_word("android"));
        assert!(!is_reserved_word("nothing"));
        assert!(!is_reserved_word("mgmt-net"));
    }

    /// Every failure mode, with the column it must report. The column is the
    /// whole point of the error type, so it is asserted rather than the
    /// message alone.
    #[test]
    fn parse_failures_report_a_position() {
        let cases: &[(&str, &str, usize)] = &[
            ("", "expected a check name", 1),
            ("   ", "expected a check name", 4),
            ("a and", "expected a check name", 6),
            ("a and )", "expected a check name", 7),
            ("and b", "expected a check name", 1),
            ("or b", "expected a check name", 1),
            ("(a and b", "unbalanced `(` opened", 1),
            ("a and (b or c", "unbalanced `(` opened", 7),
            ("a b", "unexpected trailing input", 3),
            ("a) or b", "unexpected trailing input", 2),
            ("a and b#c", "unexpected character '#'", 8),
        ];

        for (source, expected, column) in cases {
            let error = error(source);
            assert!(
                error.message.starts_with(expected),
                "{source:?}: expected a message starting {expected:?}, got {:?}",
                error.message
            );
            assert_eq!(error.column, *column, "{source:?}: wrong column");
        }
    }

    #[test]
    fn an_error_renders_its_column() {
        assert_eq!(
            error("a and").to_string(),
            "expected a check name, `not` or `(` at column 6"
        );
    }

    #[test]
    fn a_keyword_in_a_name_position_is_named_in_the_error() {
        assert!(error("a and or b").message.contains("the keyword `or`"));
    }

    #[test]
    fn a_trailing_name_is_named_in_the_error() {
        assert!(error("a b").message.contains("the check name `b`"));
    }

    /// A mis-cased or underscored name reaches the parser as a *name*, so the
    /// builder can refuse it by quoting what was written rather than the
    /// tokenizer refusing the character.
    #[test]
    fn an_unconventional_name_parses_and_is_left_for_the_builder() {
        assert_eq!(printed("Mgmt_Net"), "Mgmt_Net");
    }

    #[test]
    fn re_parsing_a_rendered_condition_is_a_fixed_point() {
        for source in [
            "a",
            "a or b and c",
            "not a and (b or not c)",
            "((a or b) and c) or not d",
        ] {
            let once = printed(source);
            assert_eq!(printed(&once), once, "{source:?} did not round-trip");
        }
    }
}
