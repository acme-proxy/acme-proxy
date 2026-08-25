//! `completions <shell>` and `man`: the two commands whose output *is* the
//! command tree.
//!
//! Both render from [`Cli::command()`] — the same builder `clap` parses argv
//! with — rather than from a script or a roff file checked in beside it. That
//! is the whole reason they exist as generators: the CLI is deliberately not
//! frozen before 1.0.0 (see `CLAUDE.md`), so a hand-maintained completion
//! script or man page goes stale at the first rename with nothing in CI to say
//! so, while a generated one cannot.
//!
//! **Neither reads the configuration or the database**, which is why
//! `src/main.rs` answers them *before* it calls `Config::load` and
//! `Database::connect` — see the note there. Everything below is therefore a
//! plain function over an injectable writer, so the tests assert on the bytes
//! instead of on a process's stdout.

use std::io::Write;

use clap::CommandFactory;
use clap_complete::aot::Shell;

use crate::cli::{Cli, CliError, Command};

/// The book, named in the man page's SEE ALSO. Read from the manifest rather
/// than written out, so a moved documentation site moves this too.
const BOOK_URL: &str = env!("CARGO_PKG_HOMEPAGE");

/// Routes the two generator commands.
///
/// Shared by `src/main.rs` (which answers them before opening anything) and by
/// [`crate::cli::dispatch`] (which stays a total function over [`Command`]), so
/// the match is spelled once rather than in both.
///
/// # Panics
///
/// On any other [`Command`]. The two callers both match first; this is the arm
/// that says so out loud rather than silently generating the wrong thing.
pub fn write(command: &Command, out: &mut impl Write) -> Result<(), CliError> {
    match command {
        Command::Completions { shell } => write_completions(*shell, out),
        Command::Man => write_man(out),
        _ => unreachable!("both callers match the two generator commands first"),
    }
}

/// Writes the completion script for `shell`.
///
/// The name passed to the generator is the binary's, not the crate's: it is
/// what the script registers itself against, so it has to be what an operator
/// types.
pub fn write_completions(shell: Shell, out: &mut impl Write) -> Result<(), CliError> {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::aot::generate(shell, &mut command, name, out);
    Ok(())
}

/// Writes the roff source of `acme-proxy.1`.
///
/// Rendered section by section rather than through `Man::render`, because
/// three of them are facts `clap` has no way to know: the environment this
/// binary reads, the file it looks for, and where the full documentation is.
/// They are written as roff here rather than hung off `after_long_help`, which
/// would put the same block — `.TP` markup and all — into `--help`.
///
/// One page, for the top-level command. The per-flag detail of every subcommand
/// lives in the book's Admin CLI chapter, which SEE ALSO names: a tree of ~50
/// roff files would document `admin user totp reset` for a binary that installs
/// no man pages at all.
pub fn write_man(out: &mut impl Write) -> Result<(), CliError> {
    let man = clap_mangen::Man::new(Cli::command()).section("1");

    let render = |out: &mut dyn Write| -> std::io::Result<()> {
        man.render_title(out)?;
        man.render_name_section(out)?;
        man.render_synopsis_section(out)?;
        man.render_description_section(out)?;
        man.render_options_section(out)?;
        man.render_subcommands_section(out)?;
        render_environment_section(out)?;
        render_files_section(out)?;
        render_see_also_section(out)?;
        man.render_version_section(out)
    };

    render(out).map_err(|error| CliError(format!("cannot write the man page: {error}")))
}

/// What `Config::load` and `main.rs` actually read from the environment.
///
/// Deliberately names the variables without restating their defaults: a default
/// spelled here and in `doc/src/configuration/reference.md` is a default that
/// drifts, which is the rule `doc/lint.py` enforces inside the book.
fn render_environment_section(out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, ".SH ENVIRONMENT")?;
    writeln!(out, ".TP")?;
    writeln!(out, "\\fBACME_PROXY_CONFIG\\fR")?;
    writeln!(
        out,
        "Path to the configuration file, without its extension. \
         Defaults to \\fBconfig\\fR in the working directory."
    )?;
    writeln!(out, ".TP")?;
    writeln!(out, "\\fBACME_PROXY_*\\fR")?;
    writeln!(
        out,
        "Per-key overrides of the configuration file, section and key separated \
         by a double underscore: \\fBACME_PROXY_SERVER__BIND_ADDRESS\\fR \
         sets \\fBserver.bind_address\\fR. List-valued keys are comma-separated."
    )?;
    writeln!(out, ".TP")?;
    writeln!(out, "\\fBNO_COLOR\\fR")?;
    writeln!(
        out,
        "Set and non-empty, suppresses colour in the human-readable output. \
         \\fB\\-\\-color always\\fR outranks it; \\fB\\-\\-json\\fR output never \
         carries colour at any setting."
    )?;
    writeln!(out, ".TP")?;
    writeln!(out, "\\fBRUST_LOG\\fR")?;
    writeln!(
        out,
        "Overrides the log filter from \\fB[logging]\\fR, in \
         \\fBtracing-subscriber\\fR's \\fBEnvFilter\\fR syntax."
    )
}

fn render_files_section(out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, ".SH FILES")?;
    writeln!(out, ".TP")?;
    writeln!(out, "\\fBconfig.toml\\fR")?;
    writeln!(
        out,
        "The configuration, read from the working directory unless \
         \\fBACME_PROXY_CONFIG\\fR says otherwise. There is no \
         \\fB\\-\\-config\\fR flag: every subcommand reads the same one the \
         server does, which is what makes the admin commands act on the same \
         database."
    )
}

fn render_see_also_section(out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, ".SH SEE ALSO")?;
    writeln!(
        out,
        "The full documentation, including the per-flag reference for every \
         subcommand above, the configuration reference and the operator \
         guides:"
    )?;
    writeln!(out, ".UR {BOOK_URL}")?;
    writeln!(out, ".UE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    fn completions(shell: Shell) -> String {
        let mut out = Vec::new();
        write_completions(shell, &mut out).expect("a completion script must render");
        String::from_utf8(out).expect("clap generates UTF-8")
    }

    fn man() -> String {
        let mut out = Vec::new();
        write_man(&mut out).expect("the man page must render");
        String::from_utf8(out).expect("roff is written as UTF-8 here")
    }

    /// `Shell::value_variants()` rather than a list written out: a shell `clap`
    /// adds later is covered without an edit here, which is the point of taking
    /// its enum instead of declaring one.
    #[test]
    fn every_shell_generates_a_script_naming_the_binary() {
        for shell in Shell::value_variants() {
            let script = completions(*shell);
            assert!(!script.is_empty(), "{shell} generated nothing");
            assert!(
                script.contains("acme-proxy"),
                "{shell}'s script does not name the binary"
            );
        }
    }

    /// The whole tree, not just the top level: `recovery-codes` is four levels
    /// down (`admin user totp recovery-codes`), so a script carrying it walked
    /// every subcommand rather than stopping at the first rank.
    ///
    /// `Fish` is deliberately absent, and that is a fact about the generator
    /// rather than about this tree: `clap_complete`'s fish output guards each
    /// candidate with `__fish_seen_subcommand_from`, which cannot express a
    /// fourth rank, so it stops at `admin user totp`. Asserting it here would
    /// pin a limitation of that backend as though it were our contract.
    #[test]
    fn the_scripts_reach_the_deepest_subcommand() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Elvish, Shell::PowerShell] {
            assert!(
                completions(shell).contains("recovery-codes"),
                "{shell}'s script stops short of the deepest subcommand"
            );
        }
    }

    /// The generated half: a title line, and the subcommand list clap builds.
    #[test]
    fn the_man_page_carries_a_title_and_the_subcommands() {
        let page = man();
        // Not `starts_with`: `render_title` emits roff's `\*(Aq` quote
        // definition ahead of the `.TH` line.
        assert!(
            page.contains(".TH acme-proxy 1"),
            "no roff title line: {page:.120}"
        );
        assert!(
            page.contains("acme\\-proxy"),
            "the page does not name itself"
        );
        for subcommand in ["serve", "account", "order", "audit", "eab", "admin"] {
            assert!(
                page.contains(subcommand),
                "the SUBCOMMANDS section omits `{subcommand}`"
            );
        }
    }

    /// The hand-written half — the only part of the page that can be wrong
    /// without a compile error.
    #[test]
    fn the_man_page_carries_the_hand_written_sections() {
        let page = man();
        for section in [
            ".SH ENVIRONMENT",
            "ACME_PROXY_CONFIG",
            "NO_COLOR",
            "RUST_LOG",
            ".SH FILES",
            "config.toml",
            ".SH SEE ALSO",
            BOOK_URL,
        ] {
            assert!(page.contains(section), "the page omits `{section}`");
        }
    }

    /// They land between the generated sections rather than after the last one:
    /// a SEE ALSO under VERSION reads as a footnote to the version.
    #[test]
    fn the_hand_written_sections_precede_the_version() {
        let page = man();
        let environment = page
            .find(".SH ENVIRONMENT")
            .expect("ENVIRONMENT is rendered");
        let see_also = page.find(".SH SEE ALSO").expect("SEE ALSO is rendered");
        let version = page.find(".SH VERSION").expect("VERSION is rendered");
        assert!(environment < see_also, "SEE ALSO comes before ENVIRONMENT");
        assert!(see_also < version, "VERSION comes before SEE ALSO");
    }

    /// [`write`] routes both, which is what `main.rs` and `dispatch` share.
    #[test]
    fn write_routes_both_generator_commands() {
        let mut script = Vec::new();
        write(&Command::Completions { shell: Shell::Fish }, &mut script)
            .expect("completions must render");
        assert!(String::from_utf8_lossy(&script).contains("acme-proxy"));

        let mut page = Vec::new();
        write(&Command::Man, &mut page).expect("the man page must render");
        assert!(String::from_utf8_lossy(&page).contains(".TH acme-proxy 1"));
    }

    /// A write that fails is reported rather than panicking or being dropped:
    /// `acme-proxy man | head` closes the pipe under us, and an operator paging
    /// the output should not see a panic for it.
    #[test]
    fn a_broken_writer_becomes_a_cli_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let error = write_man(&mut Broken).expect_err("a broken pipe must be reported");
        assert!(
            error.to_string().starts_with("cannot write the man page: "),
            "{error}"
        );
    }

    /// The same, but for a pipe that closes *partway* through — which is what
    /// `acme-proxy man | head` actually does. Every section's `?` is a distinct
    /// early return, and a writer that only ever fails on its first call leaves
    /// all but the first of them unexercised.
    #[test]
    fn a_pipe_closing_partway_is_reported_from_every_section() {
        struct FailsAfter(usize);
        impl Write for FailsAfter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
                self.0 -= 1;
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // Every write the page takes, not a handful of samples: each section's
        // `?` is its own early return, and a sample misses most of them.
        let mut counting = FailsAfter(usize::MAX);
        write_man(&mut counting).expect("a writer that never fails must succeed");
        let writes = usize::MAX - counting.0;
        assert!(
            writes > 40,
            "the page should take many writes, took {writes}"
        );

        for stop in 0..writes {
            let error = write_man(&mut FailsAfter(stop))
                .expect_err("a pipe closing mid-page must still be reported");
            assert!(
                error.to_string().starts_with("cannot write the man page: "),
                "closing after {stop} of {writes} writes: {error}"
            );
        }
    }

    /// The bash script matches its own ids.
    ///
    /// It works in two halves: a loop that walks the typed words and builds an
    /// id (`cmd="acme__proxy__subcmd__admin"`), then a `case` over that id
    /// whose labels carry the candidates. The two are generated separately, so
    /// they can disagree — and in `clap_complete` 4.6 they do, for any binary
    /// whose *name* holds a `-`: the loop escapes it to `__` and the labels to
    /// `__subcmd__`, so `acme-proxy admin <TAB>` matches no label and offers
    /// nothing. Every shell but bash is unaffected, and the script is still
    /// valid bash, so nothing else here would have caught it.
    ///
    /// This is why `Cargo.toml` holds `clap_complete` at `~4.5`. A release that
    /// fixes it passes this test and the pin can go.
    #[test]
    fn the_bash_script_is_internally_consistent() {
        let script = completions(Shell::Bash);

        let assigned: Vec<&str> = script
            .lines()
            .filter_map(|line| line.trim().strip_prefix("cmd=\""))
            .filter_map(|rest| rest.strip_suffix('"'))
            .filter(|id| !id.is_empty())
            .collect();
        assert!(
            assigned.len() > 50,
            "expected the whole tree, found {} ids",
            assigned.len()
        );

        let labels: std::collections::HashSet<&str> = script
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_suffix(')'))
            .collect();

        for id in assigned {
            assert!(
                labels.contains(id),
                "the word loop builds `{id}`, which no `case` label matches: \
                 bash completion is dead below that point"
            );
        }
    }

    /// `clap`'s own validity check over the whole tree — duplicate short flags,
    /// a `value_parser` that cannot parse its default, an argument named twice.
    /// It panics rather than returning, and only in debug builds, which is
    /// exactly what a test is.
    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }
}
