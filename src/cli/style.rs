//! Whether the admin CLI's human-readable output is coloured.
//!
//! The palette itself — what colour *means*, and the pad-first rule — is
//! [`acme_proxy_core::palette`]; this module decides whether a run gets one that is on
//! ([`resolve`]).
//!
//! **Precedence deliberately differs from `logging.ansi`.**
//! [`acme_proxy_server::logging`] documents that neither its switch nor `NO_COLOR`
//! can turn colour *on* against the other, which is right for a configuration
//! file — an ambient setting should not override an ambient veto. A
//! `--color always` is neither ambient nor a setting: it was typed by the
//! person reading the output, one command ago, and it beats both the TTY test
//! and `NO_COLOR`. That is what makes piping into `less -R` work.

use acme_proxy_core::palette::Palette;
use acme_proxy_core::palette::no_color_set;

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

/// The palette a run of the CLI gets, from the flag, the stream and the
/// environment.
///
/// Pure in all three, so the precedence documented at the top of this
/// module is testable without a terminal or a process environment.
#[must_use]
pub fn resolve(choice: ColorChoice, is_terminal: bool, no_color: Option<&str>) -> Palette {
    let on = match choice {
        ColorChoice::Never => false,
        ColorChoice::Always => true,
        ColorChoice::Auto => is_terminal && !no_color_set(no_color),
    };
    Palette::new(on)
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
                resolve(choice, is_terminal, no_color).is_on(),
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
}
