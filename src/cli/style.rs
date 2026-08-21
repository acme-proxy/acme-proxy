//! Colour for the admin CLI's human-readable output.
//!
//! Hand-rolled and dependency-free, for [`crate::metrics`]'s reason: an SGR
//! sequence is `\x1b[<n>m` and a reset, which is a `write!`, and every colour
//! crate in the ecosystem brings either a global state cell or a second opinion
//! about what a terminal is.
//!
//! **Nothing here is reachable from `--json`.** A [`Palette`] is threaded into
//! the text renderers in [`crate::cli::render`] and nowhere else; the JSON
//! branches print a `serde_json::Value` that never passes through this module,
//! so machine-readable output stays byte-identical whatever the terminal is.
//!
//! Two rules worth not rediscovering:
//!
//! - **Pad first, then colour.** Every listing renderer builds fixed columns
//!   with `{:<12}`, and a format width counts *bytes* — padding an
//!   already-wrapped field counts the eight-odd bytes of escape and the column
//!   collapses. Call sites therefore read `palette.status(&format!("{:<11}",
//!   status))`, never the other way round.
//! - **Precedence deliberately differs from `logging.ansi`.**
//!   [`crate::cli::logging`] documents that neither its switch nor `NO_COLOR`
//!   can turn colour *on* against the other, which is right for a configuration
//!   file — an ambient setting should not override an ambient veto. A
//!   `--color always` is neither ambient nor a setting: it was typed by the
//!   person reading the output, one command ago, and it beats both the TTY test
//!   and `NO_COLOR`. That is what makes piping into `less -R` work.

/// When to colour human-readable output — the `--color` flag's values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    /// Colour when stdout is a terminal and `NO_COLOR` is unset.
    #[default]
    Auto,
    /// Always colour, whatever the stream and whatever the environment says.
    Always,
    /// Never colour.
    Never,
}

/// Whether `NO_COLOR` is set to something that counts.
///
/// The convention counts only a **non-empty** value, so a `${NO_COLOR:-}`-style
/// shell default does not silently turn colour off everywhere. One definition,
/// shared with [`crate::cli::logging`]'s `logging.ansi` handling, so the two
/// answers cannot drift.
pub(crate) fn no_color_set(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

/// The four roles the CLI paints, and the SGR code each renders as.
#[derive(Clone, Copy)]
enum Role {
    Good,
    Bad,
    Busy,
    Unknown,
}

impl Role {
    /// The SGR parameter, so the escape is built in exactly one place.
    fn code(self) -> u8 {
        match self {
            Self::Good => 32,
            Self::Bad => 31,
            Self::Busy => 33,
            // Magenta rather than a second yellow: the filter engine's third
            // truth value is a distinct answer from "in progress", and
            // `pass`/`fail`/`unknown` have to read as three words at a glance.
            Self::Unknown => 35,
        }
    }
}

/// Whether colour is on, and the vocabulary for painting with it.
///
/// `Copy`, so it threads through the command tree as a value rather than a
/// borrow — it is one `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    on: bool,
}

impl Palette {
    /// A palette that colours nothing.
    ///
    /// What every test renders against, and therefore what pins the plain
    /// output byte-for-byte: with colour off every method here returns its
    /// argument unchanged.
    #[must_use]
    pub const fn plain() -> Self {
        Self { on: false }
    }

    /// The palette a run of the CLI gets, from the flag, the stream and the
    /// environment.
    ///
    /// Pure in all three, so the precedence documented at the top of this
    /// module is testable without a terminal or a process environment.
    #[must_use]
    pub fn resolve(choice: ColorChoice, is_terminal: bool, no_color: Option<&str>) -> Self {
        let on = match choice {
            ColorChoice::Never => false,
            ColorChoice::Always => true,
            ColorChoice::Auto => is_terminal && !no_color_set(no_color),
        };
        Self { on }
    }

    /// Whether this palette emits anything.
    #[must_use]
    pub const fn is_on(self) -> bool {
        self.on
    }

    /// Wraps `text` in one role's escape, or hands it back untouched.
    fn paint(self, role: Role, text: &str) -> String {
        if self.on {
            format!("\x1b[{}m{text}\x1b[0m", role.code())
        } else {
            text.to_string()
        }
    }

    /// Something that worked, or a state an operator wants to see.
    #[must_use]
    pub fn ok(self, text: &str) -> String {
        self.paint(Role::Good, text)
    }

    /// Something that failed, was refused, or was withdrawn.
    #[must_use]
    pub fn bad(self, text: &str) -> String {
        self.paint(Role::Bad, text)
    }

    /// Advisory: nothing failed, but read this line.
    ///
    /// The `advisory` outcome of the logging convention, applied to output.
    #[must_use]
    pub fn warn(self, text: &str) -> String {
        self.paint(Role::Busy, text)
    }

    /// Undecided — a question that was asked and not answered.
    #[must_use]
    pub fn unknown(self, text: &str) -> String {
        self.paint(Role::Unknown, text)
    }

    /// A status word, by what it means rather than by which table it came from.
    ///
    /// One vocabulary covers accounts, orders, authorizations, challenges, EAB
    /// credentials, admin users, sessions and TOTP state: the words do not
    /// collide in meaning across those domains, and an operator scanning a
    /// column is asking the same question of all of them.
    ///
    /// An unrecognised word renders **plain**. A status this build has never
    /// heard of is exactly the case where a guessed colour would mislead — and
    /// `AuditEntry::event` deliberately comes back as the string it was stored
    /// as, so an older binary reading a newer database gets here.
    ///
    /// `off` counts as bad on purpose: the only place it appears is an
    /// operator's second factor, and `admin.require_mfa` exists because that is
    /// a state somebody wants to notice in a listing.
    #[must_use]
    pub fn status(self, text: &str) -> String {
        // Matched on the trimmed word so a call site may hand over its padded
        // column and still be understood -- but note the *padding* is what gets
        // wrapped, which is the whole point (see the module doc).
        let role = match text.trim() {
            "valid" | "ready" | "active" | "enabled" | "success" | "on" | "allow" | "allowed"
            | "pass" => Role::Good,
            "invalid" | "revoked" | "deactivated" | "expired" | "disabled" | "off" | "failure"
            | "deny" | "denied" | "fail" => Role::Bad,
            "pending" | "processing" | "pending_mfa" => Role::Busy,
            "unknown" | "undecided" => Role::Unknown,
            _ => return text.to_string(),
        };
        self.paint(role, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precedence table in full. The row that matters is `Always` beating
    /// `NO_COLOR`: that is where this deliberately parts company with
    /// `logging.ansi`, and without it there is no way to colour into a pager.
    #[test]
    fn resolve_covers_every_choice_against_the_stream_and_the_environment() {
        for (choice, is_terminal, no_color, expected) in [
            (ColorChoice::Auto, true, None, true),
            (ColorChoice::Auto, false, None, false),
            (ColorChoice::Auto, true, Some("1"), false),
            (ColorChoice::Auto, true, Some("anything"), false),
            // The convention counts only a non-empty value.
            (ColorChoice::Auto, true, Some(""), true),
            (ColorChoice::Always, false, None, true),
            (ColorChoice::Always, false, Some("1"), true),
            (ColorChoice::Always, true, Some("1"), true),
            (ColorChoice::Never, true, None, false),
            (ColorChoice::Never, true, Some(""), false),
        ] {
            assert_eq!(
                Palette::resolve(choice, is_terminal, no_color).is_on(),
                expected,
                "{choice:?} tty={is_terminal} NO_COLOR={no_color:?}"
            );
        }
    }

    /// `Auto` is the default, so a bare `acme-proxy account list` behaves the
    /// way every other tool does.
    #[test]
    fn auto_is_the_default_choice() {
        assert_eq!(ColorChoice::default(), ColorChoice::Auto);
    }

    /// The invariant the whole design rests on: with colour off, nothing here
    /// changes a single byte. Every plain-output assertion elsewhere in the
    /// crate is only as good as this one.
    #[test]
    fn a_plain_palette_returns_its_argument_untouched() {
        let plain = Palette::plain();
        for text in ["valid", "invalid", "pending", "unknown", "", "  ready  "] {
            assert_eq!(plain.ok(text), text);
            assert_eq!(plain.bad(text), text);
            assert_eq!(plain.warn(text), text);
            assert_eq!(plain.unknown(text), text);
            assert_eq!(plain.status(text), text);
        }
    }

    #[test]
    fn each_role_emits_its_own_escape() {
        let colour = Palette::resolve(ColorChoice::Always, false, None);
        assert_eq!(colour.ok("x"), "\x1b[32mx\x1b[0m");
        assert_eq!(colour.bad("x"), "\x1b[31mx\x1b[0m");
        assert_eq!(colour.warn("x"), "\x1b[33mx\x1b[0m");
        assert_eq!(colour.unknown("x"), "\x1b[35mx\x1b[0m");
    }

    /// The vocabulary, by meaning rather than by source table.
    #[test]
    fn the_status_vocabulary_maps_every_domains_words() {
        let colour = Palette::resolve(ColorChoice::Always, false, None);
        for good in ["valid", "ready", "active", "enabled", "success", "on"] {
            assert_eq!(colour.status(good), format!("\x1b[32m{good}\x1b[0m"));
        }
        for bad in [
            "invalid",
            "revoked",
            "deactivated",
            "expired",
            "disabled",
            "off",
            "failure",
        ] {
            assert_eq!(colour.status(bad), format!("\x1b[31m{bad}\x1b[0m"));
        }
        for busy in ["pending", "processing", "pending_mfa"] {
            assert_eq!(colour.status(busy), format!("\x1b[33m{busy}\x1b[0m"));
        }
    }

    /// An unrecognised word is left alone rather than guessed at — the case an
    /// older binary reading a newer database lands in.
    #[test]
    fn an_unrecognised_status_is_never_painted() {
        let colour = Palette::resolve(ColorChoice::Always, false, None);
        assert_eq!(colour.status("quiescent"), "quiescent");
        assert!(!colour.status("quiescent").contains('\x1b'));
    }

    /// A padded column keeps its width: the escape goes *around* the padding,
    /// so stripping it recovers exactly the plain rendering.
    #[test]
    fn painting_a_padded_column_preserves_its_width() {
        let colour = Palette::resolve(ColorChoice::Always, false, None);
        let padded = format!("{:<11}", "valid");
        let painted = colour.status(&padded);
        assert_eq!(painted, format!("\x1b[32m{padded}\x1b[0m"));
        assert_eq!(
            painted
                .trim_start_matches("\x1b[32m")
                .trim_end_matches("\x1b[0m"),
            Palette::plain().status(&padded)
        );
    }
}
