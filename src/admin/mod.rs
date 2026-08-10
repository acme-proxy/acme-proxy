//! Administrative operations, shared by both front ends and owned by neither.
//!
//! [`crate::cli`] and [`crate::webadmin`] are the two front ends; everything
//! they can do lives here, so the password policy, the duplicate check and the
//! rehash-on-login cannot drift between a terminal and a browser.
//!
//! - [`ops`] — the operations themselves (accounts, orders, EAB, nonces, audit).
//! - [`render`] — one renderer per shape: a human line for the CLI, JSON for the
//!   API. Both surface the admin-only fields, such as an order's revocation,
//!   that the ACME wire format deliberately does not carry.
//! - [`password`], [`users`] — the credential store and the KDF.
//! - [`totp`], [`recovery`], [`mfa`] — the second factor: RFC 6238 over RFC 4226,
//!   single-use recovery codes, and where those two meet the database.
//! - [`prompt`] — confirmation, over an injectable reader so it is testable.
//!
//! **Destructive operations come in pairs**: a bare form, and a `confirm_*`
//! wrapper taking `assume_yes` and a reader. Those two arguments are a
//! terminal's concern, so the CLI calls the wrapper and the web calls the bare
//! form — rather than an HTTP caller passing `true` and an empty reader to
//! assert a confirmation that never happened.

pub mod mfa;
pub mod ops;
pub mod password;
pub mod prompt;
pub mod recovery;
pub mod render;
pub mod totp;
pub mod users;

pub use ops::*;
pub use prompt::*;
pub use render::*;

// `password`, `totp`, `recovery` and `users` are deliberately *not* re-exported
// flat. The three modules above hold one vocabulary between them, but
// `admin::password::verify` and `admin::users::create_user` read as what they
// are only with the module name attached -- a bare `admin::authenticate` says
// nothing about who, and a bare `admin::verify` says nothing about what.
