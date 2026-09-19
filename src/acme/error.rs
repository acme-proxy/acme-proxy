//! Why an ACME operation did not happen.

use acme_proxy_core::error::Problem;

/// The error an [`OrderService`](super::order::OrderService) or
/// [`AccountService`](super::account::AccountService) operation returns.
///
/// Most refusals are protocol answers the client is owed verbatim — the type,
/// the status and a `detail` several test suites pin byte for byte — and those
/// travel as the [`Problem`] they already are. `Problem` is a data type as much
/// as a response: the documents stored in `challenges.error` and `orders.error`
/// are its RFC 7807 JSON, and only its `IntoResponse` impl belongs to the HTTP
/// edge. Rebuilding every ACME error type here as a variant would be a second
/// definition of each, free to drift from the first.
///
/// The other variants exist because some caller **branches** on them rather than
/// rendering them: an operator front end has its own answer for an order that is
/// not found or not issued, and the HTTP edge needs data a problem document
/// cannot carry (the `Location` of a conflicting account). Each one still maps to
/// the problem an ACME client would have seen, through `From<Error> for Problem`.
#[derive(Debug)]
pub enum Error {
    /// A refusal the client reads as it is.
    Problem(Problem),
    /// `newAccount` without agreeing to the configured terms (RFC 8555 §7.3.3).
    /// Its response carries a `Link` to the terms, which a problem document
    /// cannot.
    TermsNotAgreed,
    /// `keyChange` onto a key another account holds (RFC 8555 §7.3.5). Its
    /// response carries that account's `Location`.
    KeyChangeConflict { holder: uuid::Uuid },
}

impl From<Problem> for Error {
    fn from(problem: Problem) -> Self {
        Self::Problem(problem)
    }
}

impl From<Error> for Problem {
    fn from(error: Error) -> Self {
        match error {
            Error::Problem(problem) => problem,
            Error::TermsNotAgreed => Problem::user_action_required(
                "Terms of service must be agreed to before an account can be created",
            ),
            Error::KeyChangeConflict { .. } => Problem::key_change_conflict(
                "The new key is already associated with a different account",
            ),
        }
    }
}
