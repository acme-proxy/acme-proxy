//! Who owns the database schema for this invocation.
//!
//! Opening the database used to apply the migrations as a side effect, which
//! made every subcommand an upgrade step — `acme-proxy audit list` against a
//! newer binary silently rewrote the schema — and let two processes starting
//! together race `MIGRATOR::run`, `SQLite` giving `sqlx` no migration lock.
//!
//! So the act is named now, and this is the decision: one owner per
//! invocation, everybody else checks and refuses. It lives here rather than in
//! `src/main.rs` for [`plan_logging`](super::logging::plan_logging)'s reason —
//! that file is excluded from the coverage floor, and each rule below is a row
//! of a table test.

use super::Command;

/// What an invocation is entitled to do about the database schema.
///
/// Pure, and here rather than in `src/main.rs` for [`plan_logging`]'s reason:
/// that file is excluded from the coverage floor, and every rule below is a row
/// of a table test.
///
/// [`plan_logging`]: super::logging::plan_logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaPlan {
    /// This command applies the migrations itself: `migrate`, `init`, and
    /// `serve` when the process runs the `worker` role.
    Migrate,
    /// This command needs the schema present but must not write it. An
    /// unapplied migration stops it by name.
    Require,
}

/// Decides whether `command` may migrate, or must find the schema already
/// current.
///
/// **There is no third answer.** Every command here reads or writes rows, so
/// every one needs the schema; `completions` and `man` never reach this, being
/// answered in `main.rs` before the configuration or the database.
///
/// The split exists because migrating used to be a side effect of opening the
/// database, which made `acme-proxy audit list` an upgrade step. It also raced:
/// two processes starting together both ran `MIGRATOR::run`, and `SQLite` gives
/// `sqlx` no migration lock. One owner, named on the command line, removes
/// both.
#[must_use]
pub fn plan_schema(command: Option<&Command>) -> SchemaPlan {
    match command {
        // `serve` with no `--role` runs the worker, which owns the schema; a
        // `--role` naming it does too. The roles are parsed again inside
        // `serve`, where an unknown one is refused by name — an unparseable
        // value here simply does not claim ownership, and the refusal comes
        // from the one place that words it.
        // `None` is `serve` — the default subcommand — so it takes the same
        // arm as an explicit one, `plan_logging`'s own shape.
        None => SchemaPlan::Migrate,
        Some(Command::Serve { role }) => {
            match role
                .unwrap_or_default()
                .has(acme_proxy_server::ProcessRole::Worker)
            {
                true => SchemaPlan::Migrate,
                false => SchemaPlan::Require,
            }
        }
        Some(Command::Migrate | Command::Init) => SchemaPlan::Migrate,
        _ => SchemaPlan::Require,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    /// Parsed from a real command line rather than a hand-built variant: what
    /// has to be right is what an operator's argv resolves to, which is the
    /// same argument `plan_logging`'s table makes.
    fn plan(argv: &[&str]) -> SchemaPlan {
        let cli = Cli::try_parse_from(argv).expect("the command line must parse");
        plan_schema(cli.command.as_ref())
    }

    /// All-in-one is the default and must be unaffected: a bare `serve`
    /// against a fresh database migrates it, exactly as it did when opening
    /// the database was what applied them.
    #[test]
    fn a_default_serve_owns_the_schema() {
        assert_eq!(plan(&["acme-proxy"]), SchemaPlan::Migrate);
        assert_eq!(plan(&["acme-proxy", "serve"]), SchemaPlan::Migrate);
    }

    #[test]
    fn serve_owns_the_schema_exactly_when_it_runs_the_worker() {
        for roles in ["worker", "acme,worker", "admin,worker", "acme,admin,worker"] {
            assert_eq!(
                plan(&["acme-proxy", "serve", "--role", roles]),
                SchemaPlan::Migrate,
                "`--role {roles}` runs the worker, which owns the schema"
            );
        }
        for roles in ["acme", "admin", "acme,admin"] {
            assert_eq!(
                plan(&["acme-proxy", "serve", "--role", roles]),
                SchemaPlan::Require,
                "`--role {roles}` runs no worker and must not migrate"
            );
        }
    }

    #[test]
    fn migrate_and_init_own_the_schema() {
        assert_eq!(plan(&["acme-proxy", "migrate"]), SchemaPlan::Migrate);
        assert_eq!(plan(&["acme-proxy", "init"]), SchemaPlan::Migrate);
    }

    /// Every other command reads or writes rows, so every one needs the schema
    /// and none of them may write it. A sample across the subtrees rather than
    /// all of them: the rule is the `_` arm, and a new command joins it.
    #[test]
    fn every_other_command_requires_a_current_schema() {
        for argv in [
            vec!["acme-proxy", "account", "list"],
            vec!["acme-proxy", "order", "list"],
            vec!["acme-proxy", "audit", "list"],
            vec!["acme-proxy", "jobs", "list"],
            vec!["acme-proxy", "eab", "list"],
            vec!["acme-proxy", "profile", "list"],
            vec!["acme-proxy", "admin", "user", "list"],
            // Reads every row of the source and writes none of the schema:
            // the target is migrated by `acme-proxy migrate` against it, not
            // by this.
            vec!["acme-proxy", "transfer", "--to", "postgres://h/db"],
        ] {
            assert_eq!(
                plan(&argv),
                SchemaPlan::Require,
                "`{}` must not migrate",
                argv.join(" ")
            );
        }
    }

    /// An unknown role never reaches this decision: `clap` refuses it at argv
    /// time, before the configuration is read or the database file created.
    #[test]
    fn an_unknown_role_is_refused_before_anything_is_planned() {
        let Err(error) = Cli::try_parse_from(["acme-proxy", "serve", "--role", "wroker"]) else {
            panic!("an unknown role must not parse");
        };
        assert!(error.to_string().contains("wroker"), "{error}");
    }
}
