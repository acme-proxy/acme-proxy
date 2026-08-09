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
