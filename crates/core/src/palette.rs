//! Colour for the admin CLI's human-readable output: whether it is on, and what
//! each colour means.
//!
//! Hand-rolled and dependency-free, for `metrics`'s reason: an SGR
//! sequence is `\x1b[<n>m` and a reset, which is a `write!`, and every colour
//! crate in the ecosystem brings either a global state cell or a second opinion
//! about what a terminal is.
//!
//! **Nothing here is reachable from `--json`.** A [`Palette`] is threaded into
//! the text renderers — the CLI's own and `filter::explain`'s — and nowhere
//! else; the JSON branches print a `serde_json::Value` that never passes
//! through this module, so machine-readable output stays byte-identical
//! whatever the terminal is. Deciding whether a run's palette is on is the
//! CLI's (`cli::style::resolve`); this module is below every renderer that
//! paints with one.
//!
//! **Pad first, then colour.** Every listing renderer builds fixed columns
//! with `{:<12}`, and a format width counts *bytes* — padding an
//! already-wrapped field counts the eight-odd bytes of escape and the column
//! collapses. Call sites therefore read `palette.status(&format!("{:<11}",
//! status))`, never the other way round.

/// Whether `NO_COLOR` is set to something that counts.
///
/// The convention counts only a **non-empty** value, so a `${NO_COLOR:-}`-style
/// shell default does not silently turn colour off everywhere. One definition,
/// shared by the CLI's `--color` and `server::logging`'s `logging.ansi` handling, so the two
/// answers cannot drift.
pub fn no_color_set(value: Option<&str>) -> bool {
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

    /// A palette that colours when `on` is.
    ///
    /// Deciding `on` is the CLI's — `cli::style::resolve` weighs the
    /// `--color` flag, the stream and `NO_COLOR`.
    #[must_use]
    pub const fn new(on: bool) -> Self {
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
            | "pass" | "done" => Role::Good,
            "invalid" | "revoked" | "deactivated" | "expired" | "disabled" | "off" | "failure"
            | "deny" | "denied" | "fail" | "failed" | "cancelled" => Role::Bad,
            "pending" | "processing" | "pending_mfa" | "running" => Role::Busy,
            "unknown" | "undecided" => Role::Unknown,
            _ => return text.to_string(),
        };
        self.paint(role, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let colour = Palette::new(true);
        assert_eq!(colour.ok("x"), "\x1b[32mx\x1b[0m");
        assert_eq!(colour.bad("x"), "\x1b[31mx\x1b[0m");
        assert_eq!(colour.warn("x"), "\x1b[33mx\x1b[0m");
        assert_eq!(colour.unknown("x"), "\x1b[35mx\x1b[0m");
    }

    /// The vocabulary, by meaning rather than by source table.
    #[test]
    fn the_status_vocabulary_maps_every_domains_words() {
        let colour = Palette::new(true);
        for good in [
            "valid", "ready", "active", "enabled", "success", "on", "done",
        ] {
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
            "failed",
            "cancelled",
        ] {
            assert_eq!(colour.status(bad), format!("\x1b[31m{bad}\x1b[0m"));
        }
        for busy in ["pending", "processing", "pending_mfa", "running"] {
            assert_eq!(colour.status(busy), format!("\x1b[33m{busy}\x1b[0m"));
        }
    }

    /// An unrecognised word is left alone rather than guessed at — the case an
    /// older binary reading a newer database lands in.
    #[test]
    fn an_unrecognised_status_is_never_painted() {
        let colour = Palette::new(true);
        assert_eq!(colour.status("quiescent"), "quiescent");
        assert!(!colour.status("quiescent").contains('\x1b'));
    }

    /// A padded column keeps its width: the escape goes *around* the padding,
    /// so stripping it recovers exactly the plain rendering.
    #[test]
    fn painting_a_padded_column_preserves_its_width() {
        let colour = Palette::new(true);
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
