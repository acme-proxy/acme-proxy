//! Which invocation gets a subscriber, and at what level — the CLI's half of
//! `[logging]`. Installing and reloading the stack is
//! [`crate::server::logging`]'s.
//!
//! # Who gets a subscriber
//!
//! `[logging]` describes the **server's** log stream, and until this module
//! grew [`plan_logging`] every subcommand got it: with the shipped defaults
//! (`acme_proxy=info`, to **stdout**) `acme-proxy account list --json | jq`
//! read a `db_migration_completed` record before the JSON, and `filter
//! explain` wrote a `warn` into the middle of the explanation it was printing.
//!
//! So the decision is now made per invocation, by a pure function a test can
//! drive rather than in `main.rs`, which the coverage floor excludes:
//!
//! - `serve` gets the stack `[logging]` describes, exactly as before.
//! - **Any other subcommand emits nothing at all** unless the operator asks —
//!   with `--log-level`, or with a non-empty `RUST_LOG`. There is no subscriber
//!   in that case, so every `tracing` call in the process is a no-op rather
//!   than a filtered one.
//! - When one does ask, the records go to **stderr** whatever `logging.target`
//!   says, because stdout is the answer the operator's `jq` or `awk` is reading
//!   and a diagnostic does not belong in it.
//!
//! [`LogLevel`] outranks both `RUST_LOG` and `logging.filter`, which is
//! [`super::style`]'s argument for `--color always` outranking `NO_COLOR`: a
//! flag was typed on this command line where the other two are ambient. See
//! [`FilterSource`], which travels with the filter so a reload can say which of
//! the three won.
//!

use clap::ValueEnum;

/// `--log-level`: how much this invocation logs.
///
/// A crate-local enum rather than [`tracing::Level`] for two reasons: `off` is
/// not a level, and `clap`'s [`ValueEnum`] cannot be implemented for a foreign
/// type anyway. Being a `value_enum` is also what puts the six values into the
/// generated shell completions, which is what `--color` already buys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// The `EnvFilter` directive this level asks for.
    ///
    /// **Scoped to this crate's own target**, so `--log-level debug` does not
    /// also unleash `sqlx`, `hyper` and `rustls` on someone who wanted to see
    /// why one command behaved oddly. `RUST_LOG` stays the way to write a
    /// directive that reaches further — it is the same string this would have
    /// to become, and a flag that took one would be a second spelling of it.
    #[must_use]
    pub fn directive(self) -> String {
        match self {
            // Not `acme_proxy=off`: a per-target directive at `off` still
            // leaves every *other* target at the default level, so the one
            // value asking for silence would be the one that did not deliver
            // it.
            Self::Off => "off".to_string(),
            Self::Error => "acme_proxy=error".to_string(),
            Self::Warn => "acme_proxy=warn".to_string(),
            Self::Info => "acme_proxy=info".to_string(),
            Self::Debug => "acme_proxy=debug".to_string(),
            Self::Trace => "acme_proxy=trace".to_string(),
        }
    }
}

/// Which subscriber, if any, an invocation installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggingPlan {
    /// Install nothing. Every `tracing` call in the process is then a no-op,
    /// which is stronger — and cheaper — than a subscriber filtering them all
    /// out.
    Silent,
    /// Install the stack `[logging]` describes: the server's own log stream.
    Server,
    /// Install a diagnostic stack on stderr for a one-shot admin command.
    Command,
}

/// Decides what this invocation logs, from the subcommand and the two ways an
/// operator can ask.
///
/// Pure, and here rather than in `src/main.rs` because that file is excluded
/// from the coverage floor: every rule below is a row of a table test.
///
/// `rust_log` counts only when **non-empty**, which is
/// [`no_color_set`](crate::palette::no_color_set)'s judgement applied to the other ambient
/// environment variable this CLI reads. A `RUST_LOG=` left behind by a
/// `${RUST_LOG:-}`-style shell default is not somebody asking for logs, and
/// treating it as one would put records back in the pipe this exists to keep
/// clean.
pub fn plan_logging(
    command: Option<&super::Command>,
    level: Option<LogLevel>,
    rust_log: Option<&str>,
) -> LoggingPlan {
    match command {
        // A daemon logs; the flag only sharpens what it says. `None` is the
        // default subcommand, i.e. a bare `acme-proxy`.
        None | Some(super::Command::Serve { .. }) => LoggingPlan::Server,
        // `main.rs` answers both before it loads a configuration, so neither
        // reaches here — but answering them keeps this total over `Command`,
        // the rule `dispatch` follows for the same pair.
        Some(super::Command::Completions { .. } | super::Command::Man) => LoggingPlan::Silent,
        Some(_) => {
            if level.is_some() || rust_log.is_some_and(|value| !value.is_empty()) {
                LoggingPlan::Command
            } else {
                LoggingPlan::Silent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::EnvFilter;

    /// One row of the `plan_logging` table: a command line, the flag, the
    /// environment, and what the three of them must decide.
    type PlanCase<'a> = (
        &'a [&'a str],
        Option<LogLevel>,
        Option<&'a str>,
        LoggingPlan,
    );

    /// Parsed rather than hand-built: naming every subcommand enum here would
    /// be a second copy of the clap tree, and what has to be right is what a
    /// real command line resolves to.
    fn command_of(argv: &[&str]) -> Option<super::super::Command> {
        use clap::Parser;
        super::super::Cli::try_parse_from(argv)
            .expect("the fixture command line parses")
            .command
    }

    /// The whole point of the flag, as a table: **an admin command is silent
    /// unless somebody asked**, `serve` never is, and `RUST_LOG` counts only
    /// when it holds something.
    #[test]
    fn plan_logging_decides_who_gets_a_subscriber() {
        let cases: Vec<PlanCase> = vec![
            // A daemon logs, however it was reached and whatever is unset.
            (&["acme-proxy"], None, None, LoggingPlan::Server),
            (&["acme-proxy", "serve"], None, None, LoggingPlan::Server),
            (
                &["acme-proxy", "serve"],
                Some(LogLevel::Debug),
                None,
                LoggingPlan::Server,
            ),
            // The reported bug: these used to write `db_migration_completed`
            // into the operator's `jq` pipe.
            (
                &["acme-proxy", "account", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "filter", "show"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "audit", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "admin", "user", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            // Both ways of asking, and only those two.
            (
                &["acme-proxy", "account", "list"],
                Some(LogLevel::Debug),
                None,
                LoggingPlan::Command,
            ),
            (
                &["acme-proxy", "account", "list"],
                Some(LogLevel::Off),
                None,
                LoggingPlan::Command,
            ),
            (
                &["acme-proxy", "account", "list"],
                None,
                Some("acme_proxy=debug"),
                LoggingPlan::Command,
            ),
            // A `${RUST_LOG:-}` shell default is present, not a request — the
            // judgement `no_color_set` already makes about the other ambient
            // variable this CLI reads.
            (
                &["acme-proxy", "account", "list"],
                None,
                Some(""),
                LoggingPlan::Silent,
            ),
            // Answered by `main.rs` before any of this, but total here anyway.
            (&["acme-proxy", "man"], None, None, LoggingPlan::Silent),
            (
                &["acme-proxy", "completions", "bash"],
                Some(LogLevel::Trace),
                Some("debug"),
                LoggingPlan::Silent,
            ),
        ];

        for (argv, level, rust_log, expected) in cases {
            let command = command_of(argv);
            let plan = plan_logging(command.as_ref(), level, rust_log);
            assert_eq!(
                plan,
                expected,
                "`{}` with level {level:?} and RUST_LOG {rust_log:?}",
                argv.join(" "),
            );
        }
    }

    /// Each level's directive is **scoped to this crate**, so `--log-level
    /// debug` does not also unleash `sqlx` and `hyper` on somebody debugging
    /// one command. `off` is the exception and has to be: a per-target
    /// directive at `off` leaves every other target at the default level, so
    /// the one value asking for silence would be the one not delivering it.
    #[test]
    fn every_level_renders_a_directive_scoped_to_this_crate() {
        assert_eq!(LogLevel::Off.directive(), "off");
        for (level, expected) in [
            (LogLevel::Error, "acme_proxy=error"),
            (LogLevel::Warn, "acme_proxy=warn"),
            (LogLevel::Info, "acme_proxy=info"),
            (LogLevel::Debug, "acme_proxy=debug"),
            (LogLevel::Trace, "acme_proxy=trace"),
        ] {
            assert_eq!(level.directive(), expected);
            EnvFilter::try_new(level.directive()).expect("every directive parses");
        }
        EnvFilter::try_new(LogLevel::Off.directive()).expect("`off` parses");
    }
}
