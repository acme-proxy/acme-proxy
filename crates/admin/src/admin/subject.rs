//! What a lookup was for, so "not found" reads the same on every surface.
//!
//! The CLI, the `/api` handlers and the `/ui` pages each refuse an unknown id
//! with their own error type — exit code 3, a `404` JSON body, a `404` page —
//! and used to spell the sentence each time, seventeen times over. They had
//! already drifted: an unknown operator was "no such admin user" in a terminal
//! and "no such operator" in a browser. The sentence lives here; each surface
//! keeps only its wrapper.

use std::fmt::Display;

/// The kinds of row an operator names by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Account,
    Order,
    Job,
    EabCredential,
    Operator,
    Session,
    /// A profile, named rather than numbered.
    Profile,
}

impl Subject {
    /// The refusal for `id`, which names no row of this kind.
    #[must_use]
    pub fn missing(self, id: impl Display) -> String {
        let noun = match self {
            Self::Account => "account",
            Self::Order => "order",
            Self::Job => "job",
            Self::EabCredential => "EAB credential",
            Self::Operator => "operator",
            Self::Session => "session",
            Self::Profile => return format!("no profile named `{id}` is mounted"),
        };
        format!("no such {noun}: {id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_subject_names_itself_and_the_id() {
        assert_eq!(Subject::Account.missing("a-1"), "no such account: a-1");
        assert_eq!(
            Subject::EabCredential.missing("kid-9"),
            "no such EAB credential: kid-9"
        );
        assert_eq!(
            Subject::Profile.missing("le"),
            "no profile named `le` is mounted"
        );
    }
}
