//! `acme-proxy admin …` — the web admin's operators and their sessions.
//!
//! This is how the panel is bootstrapped: it has no sign-up page and never
//! will, so the first operator is created here, from a shell on the host.
//!
//! ## The password never goes in argv
//!
//! There is deliberately no `--password` flag. argv is visible to every
//! process on the host via `ps` and is routinely written to shell history —
//! the same reasoning `upstream register` already applies to the EAB secret,
//! and pinned by the same kind of negative test. A password arrives either
//! through `--password-file` or on stdin.

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin;
use crate::admin::mfa;
use crate::admin::ops::DeleteOutcome;
use crate::admin::password::PasswordContext;
use crate::admin::prompt::confirm;
use crate::admin::users::{self, UserError};
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::config::Config;
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::{AdminRole, AdminUser};
use crate::sqlite::db::Database;

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Manage the operators who can sign in to the web admin.
    User {
        #[command(subcommand)]
        command: AdminUserCommand,
    },
    /// Inspect and revoke logged-in browser sessions.
    Session {
        #[command(subcommand)]
        command: AdminSessionCommand,
    },
}

#[derive(Subcommand)]
pub enum AdminUserCommand {
    /// Create an operator. The password is read from `--password-file`, or
    /// from stdin.
    Create {
        username: String,
        /// Read the password from this file instead of stdin. A single
        /// trailing newline is stripped.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
        /// Privilege tier for this operator's web sessions: `admin`
        /// (everything), `operator` (every CA action but not managing other
        /// operators), or `viewer` (read-only bar their own account).
        #[arg(long, default_value = "admin")]
        role: String,
    },
    /// List operators, oldest first. Never shows a password hash.
    List {
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one operator, second factor included. Never shows a password hash.
    Show {
        username: String,
        #[arg(long)]
        json: bool,
    },
    /// Replace an operator's password, revoking every session they hold.
    Passwd {
        username: String,
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
    },
    /// Change an operator's privilege tier, revoking every session they hold.
    Role {
        username: String,
        /// The new tier: `admin`, `operator` or `viewer`.
        role: String,
    },
    /// Delete an operator and every session of theirs.
    Delete { username: String },
    /// Bar an operator from signing in, dropping their current sessions.
    Disable { username: String },
    /// Undo `disable`.
    Enable { username: String },
    /// Inspect or remove an operator's second factor.
    Totp {
        #[command(subcommand)]
        command: AdminUserTotpCommand,
    },
}

/// The operator-side half of the second factor.
///
/// There is deliberately **no `enrol`** here, and the omission is the same one
/// that keeps a password out of argv: there is no way to enrol from a terminal
/// that does not put the base32 secret into scrollback and the shell's own
/// history. The panel shows it once, behind `Cache-Control: no-store`, on a
/// loopback listener. What a shell is for is the case the panel cannot serve --
/// an operator who has lost the factor and so cannot sign in to fix it.
#[derive(Subcommand)]
pub enum AdminUserTotpCommand {
    /// Whether an operator has a second factor, and how many recovery codes
    /// are left.
    Status {
        username: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove an operator's second factor and every recovery code, and revoke
    /// their sessions.
    ///
    /// The lockout lever: a lost phone is a shell command on the host, not a
    /// database edit. Asks first, because it takes a security control away.
    Reset { username: String },
    /// Mint a fresh set of recovery codes, printed once. The previous set stops
    /// working immediately.
    RecoveryCodes { username: String },
}

#[derive(Subcommand)]
pub enum AdminSessionCommand {
    /// List live sessions, newest first.
    List {
        /// Only this operator's sessions.
        #[arg(long)]
        username: Option<String>,
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Revoke sessions: one operator's, or everyone's.
    Revoke {
        #[arg(long, conflicts_with = "all")]
        user: Option<String>,
        /// Revoke every session on the server.
        #[arg(long, conflicts_with = "user")]
        all: bool,
    },
}

pub async fn run_admin_command(
    command: AdminCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AdminCommand::User { command } => {
            run_user_command(command, yes, palette, reader, config, database).await
        }
        AdminCommand::Session { command } => run_session_command(command, palette, database).await,
    }
}

async fn run_user_command(
    command: AdminUserCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AdminUserCommand::Create {
            username,
            password_file,
            role,
        } => {
            let role: AdminRole = role
                .parse()
                .map_err(|error| CliError(format!("--role: {error}")))?;
            let password = read_password(password_file.as_deref(), reader)?;
            let context = PasswordContext::from_config(config, &username);
            let user = users::create_user(&username, &password, &context, database.clone())
                .await
                .map_err(user_error)?;
            // `create_user` writes the full tier; narrow it if a lesser one was
            // asked for. A fresh operator holds no sessions, so the revoke
            // `set_role` also does is a no-op here.
            if role != AdminRole::Admin {
                users::set_role(&user.username, role, database)
                    .await?
                    .ok_or_else(|| not_found(&user.username))?;
            }
            // The id, not the password: nothing echoes a credential back.
            println!(
                "Created admin user {} ({}), role {role}.",
                user.username, user.id
            );
        }
        AdminUserCommand::Role { username, role } => {
            let role: AdminRole = role
                .parse()
                .map_err(|error| CliError(format!("role: {error}")))?;
            match users::set_role(&username, role, database).await? {
                None => return Err(not_found(&username)),
                Some(user) => println!(
                    "Role of {} set to {role}. Every session they held was revoked.",
                    user.username
                ),
            }
        }
        AdminUserCommand::List {
            limit,
            offset,
            json,
        } => {
            let window = Window::resolve(limit, offset);
            let (users, total) = users::list_users(window.limit, window.offset, database).await?;
            render::print_page(
                &users,
                total,
                window,
                json,
                admin::render_admin_user_json,
                |user| render::render_admin_user_line(user, palette),
            );
        }
        AdminUserCommand::Show { username, json } => {
            // The same pair `totp status` reads, for the reason
            // `render_admin_user_detail_json` records: the enrolment state and
            // the code count are what a listing cannot carry, and they are the
            // half of an operator's row that decides whether they can sign in.
            let user = find_user(&username, database.clone()).await?;
            let remaining = mfa::recovery_codes_remaining(user.id, database).await?;

            if json {
                println!("{}", admin::render_admin_user_detail_json(&user, remaining));
            } else {
                print!(
                    "{}",
                    render::render_admin_user_detail_text(&user, remaining, palette)
                );
            }
        }
        AdminUserCommand::Passwd {
            username,
            password_file,
        } => {
            let password = read_password(password_file.as_deref(), reader)?;
            let context = PasswordContext::from_config(config, &username);
            match users::set_password(&username, &password, &context, database)
                .await
                .map_err(user_error)?
            {
                None => return Err(not_found(&username)),
                Some(user) => println!(
                    "Password changed for {}. Every session they held was revoked.",
                    user.username
                ),
            }
        }
        AdminUserCommand::Delete { username } => {
            match users::confirm_delete_user(&username, yes, reader, database).await? {
                DeleteOutcome::NotFound => return Err(not_found(&username)),
                DeleteOutcome::Cancelled => println!("Cancelled."),
                DeleteOutcome::Deleted => println!("Deleted admin user {username}."),
            }
        }
        AdminUserCommand::Disable { username } => {
            set_status_or_not_found(&username, "disabled", database).await?;
            println!("Disabled {username}. Their sessions were revoked.");
        }
        AdminUserCommand::Enable { username } => {
            set_status_or_not_found(&username, "active", database).await?;
            println!("Enabled {username}.");
        }
        AdminUserCommand::Totp { command } => {
            run_totp_command(command, yes, palette, reader, database).await?;
        }
    }
    Ok(())
}

async fn run_totp_command(
    command: AdminUserTotpCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AdminUserTotpCommand::Status { username, json } => {
            let user = find_user(&username, database.clone()).await?;
            let remaining = mfa::recovery_codes_remaining(user.id, database).await?;

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "username": user.username,
                        "totpEnabled": user.has_totp(),
                        "enrolmentPending": user.has_pending_totp(),
                        "recoveryCodesRemaining": remaining,
                    })
                );
            } else {
                println!(
                    "{}",
                    render::render_admin_totp_line(&user, remaining, palette)
                );
            }
        }
        AdminUserTotpCommand::Reset { username } => {
            let mut user = find_user(&username, database.clone()).await?;
            if !user.has_totp() && !user.has_pending_totp() {
                println!("{} has no second factor; nothing to reset.", user.username);
                return Ok(());
            }

            let prompt = format!(
                "Remove the second factor and every recovery code for {}, \
                 and revoke their sessions?",
                user.username
            );
            if !confirm(&prompt, yes, reader) {
                println!("Cancelled.");
                return Ok(());
            }

            // `None`: this is a change made on the operator's behalf, from a
            // shell they are not signed in from, so there is no session to keep.
            mfa::disable_totp(&mut user, None, database).await?;
            println!(
                "Removed the second factor for {}. Their sessions were revoked; \
                 they can sign in with a password alone until they enrol again.",
                user.username
            );
        }
        AdminUserTotpCommand::RecoveryCodes { username } => {
            let user = find_user(&username, database.clone()).await?;
            if !user.has_totp() {
                return Err(CliError(format!(
                    "{} has no second factor, so recovery codes would recover nothing: \
                     enrol from the panel first",
                    user.username
                )));
            }

            let codes = mfa::regenerate_recovery_codes(&user, database).await?;
            // The `eab create` treatment: printed once, stored one-way, and the
            // previous set is already dead by the time this prints.
            println!(
                "New recovery codes for {} — the previous set no longer works.\n\
                 Store these now; they are not recoverable.\n",
                user.username
            );
            for code in &codes {
                println!("  {code}");
            }
        }
    }
    Ok(())
}

/// Resolves a username, reporting an unknown one in words rather than as a
/// silent no-op.
async fn find_user(username: &str, database: Arc<Database>) -> Result<AdminUser, CliError> {
    AdminUser::find_by_username(username, &database)
        .await?
        .ok_or_else(|| not_found(username))
}

async fn run_session_command(
    command: AdminSessionCommand,
    palette: Palette,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        AdminSessionCommand::List {
            username,
            limit,
            offset,
            json,
        } => {
            // Resolved to an id first: `admin_sessions` carries the user id,
            // and an unknown name must say so rather than quietly listing
            // every session on the server.
            let user_id = match username.as_deref() {
                None => None,
                Some(name) => match AdminUser::find_by_username(name, &database).await? {
                    None => return Err(not_found(name)),
                    Some(user) => Some(user.id),
                },
            };

            let window = Window::resolve(limit, offset);
            let (sessions, total) =
                AdminSession::search(user_id, window.limit, window.offset, &database).await?;
            render::print_page(
                &sessions,
                total,
                window,
                json,
                admin::render_admin_session_json,
                |session| render::render_admin_session_line(session, palette),
            );
        }
        AdminSessionCommand::Revoke { user, all } => match (user, all) {
            (Some(username), _) => match users::revoke_sessions(&username, database).await? {
                None => return Err(not_found(&username)),
                Some(count) => println!("Revoked {count} session(s) for {username}."),
            },
            (None, true) => {
                let count = AdminSession::delete_all(&database).await?;
                println!("Revoked {count} session(s).");
            }
            (None, false) => {
                return Err(CliError(
                    "say whose sessions to revoke: --user <username>, or --all".to_string(),
                ));
            }
        },
    }
    Ok(())
}

async fn set_status_or_not_found(
    username: &str,
    status: &str,
    database: Arc<Database>,
) -> Result<(), CliError> {
    if users::set_status(username, status, database)
        .await?
        .is_none()
    {
        return Err(not_found(username));
    }
    Ok(())
}

/// Reads a password from a file, or one line of `reader`.
///
/// The file form strips a single trailing newline, so
/// `printf '%s\n' "$pw" > file` and `printf '%s' "$pw" > file` mean the same
/// thing — an operator should not have to know which their editor wrote.
fn read_password(
    path: Option<&std::path::Path>,
    reader: &mut impl BufRead,
) -> Result<String, CliError> {
    match path {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|error| CliError(format!("cannot read {}: {error}", path.display())))?;
            Ok(raw.strip_suffix('\n').unwrap_or(&raw).to_string())
        }
        None => {
            // No `rpassword`: echo suppression needs a real TTY, which would
            // break the injectable-reader testability this whole layer is
            // built on. Warn instead, and point at the flag that avoids it.
            if std::io::stdin().is_terminal() {
                eprintln!(
                    "Note: the password will be echoed. Use --password-file, or pipe it in:\n  \
                     printf '%s' \"$password\" | acme-proxy admin user create <username>"
                );
            }
            eprintln!("Enter the password, then press Enter:");
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return Err(CliError("no password supplied".to_string()));
            }
            // Only the line terminator, never surrounding whitespace: a
            // password may legitimately begin or end with a space.
            let password = line.strip_suffix('\n').unwrap_or(&line);
            let password = password.strip_suffix('\r').unwrap_or(password);
            Ok(password.to_string())
        }
    }
}

fn user_error(error: UserError) -> CliError {
    match error {
        UserError::Database(error) => CliError::from(error),
        other => CliError(other.to_string()),
    }
}

fn not_found(username: &str) -> CliError {
    CliError(format!("no such admin user: {username}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_session::NewSession;
    use crate::testutil::TempDir;

    const GOOD: &str = "a-long-enough-password";

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// Runs a command with a stdin that supplies `input`, against a default
    /// configuration.
    async fn run(
        command: AdminCommand,
        input: &str,
        database: Arc<Database>,
    ) -> Result<(), CliError> {
        run_with_config(command, input, &Config::default(), database).await
    }

    /// [`run`] with the configuration spelled out, for the tests that care
    /// what [`PasswordContext::from_config`] derived from it.
    async fn run_with_config(
        command: AdminCommand,
        input: &str,
        config: &Config,
        database: Arc<Database>,
    ) -> Result<(), CliError> {
        let mut reader = input.as_bytes();
        run_admin_command(
            command,
            true,
            Palette::plain(),
            &mut reader,
            config,
            database,
        )
        .await
    }

    fn create(username: &str) -> AdminCommand {
        create_with_role(username, "admin")
    }

    fn create_with_role(username: &str, role: &str) -> AdminCommand {
        AdminCommand::User {
            command: AdminUserCommand::Create {
                username: username.to_string(),
                password_file: None,
                role: role.to_string(),
            },
        }
    }

    #[tokio::test]
    async fn create_reads_the_password_from_stdin() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert!(user.is_active());
        assert_eq!(
            admin::password::verify_password(&user.password_hash, GOOD),
            Ok(true)
        );
    }

    #[tokio::test]
    async fn create_reads_the_password_from_a_file_and_strips_one_newline() {
        let dir = TempDir::new("admin-passwd");
        let path = dir.join("pw");
        std::fs::write(&path, format!("{GOOD}\n")).unwrap();

        let db = db().await;
        run(
            AdminCommand::User {
                command: AdminUserCommand::Create {
                    username: "alice".to_string(),
                    password_file: Some(path),
                    role: "admin".to_string(),
                },
            },
            "",
            db.clone(),
        )
        .await
        .unwrap();

        let user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            admin::password::verify_password(&user.password_hash, GOOD),
            Ok(true),
            "the trailing newline must not be part of the password"
        );
    }

    #[tokio::test]
    async fn create_refuses_a_missing_password_file() {
        let db = db().await;
        let error = run(
            AdminCommand::User {
                command: AdminUserCommand::Create {
                    username: "alice".to_string(),
                    password_file: Some(PathBuf::from("/nonexistent/pw")),
                    role: "admin".to_string(),
                },
            },
            "",
            db,
        )
        .await
        .unwrap_err();
        assert!(error.0.starts_with("cannot read /nonexistent/pw"));
    }

    /// The words the *configuration* produced have to reach the terminal, or
    /// the operator is told their password is unacceptable and not why. This
    /// is also the only test that proves `dispatch`'s `&Config` is threaded
    /// all the way to `PasswordContext::from_config` rather than dropped.
    #[tokio::test]
    async fn create_surfaces_the_context_and_corpus_rules_in_words() {
        let db = db().await;

        let error = run(create("alice"), "passwordpassword\n", db.clone())
            .await
            .unwrap_err();
        assert!(error.0.contains("commonly used"), "got: {}", error.0);

        let mut config = Config::default();
        config.server.base_url = "https://ca.contoso.example".to_string();
        let error = run_with_config(
            create("alice"),
            "contoso-is-my-password\n",
            &config,
            db.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("contoso"), "got: {}", error.0);
        assert!(
            error.0.contains("names this deployment"),
            "got: {}",
            error.0
        );

        // Neither attempt created anything.
        assert!(AdminUser::list_all(&db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_refuses_empty_stdin() {
        let db = db().await;
        let error = run(create("alice"), "", db).await.unwrap_err();
        assert_eq!(error, CliError("no password supplied".to_string()));
    }

    #[tokio::test]
    async fn create_surfaces_the_policy_and_duplicate_errors_in_words() {
        let db = db().await;
        let error = run(create("alice"), "short\n", db.clone())
            .await
            .unwrap_err();
        assert!(error.0.contains("at least 12"), "got: {}", error.0);

        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let error = run(create("ALICE"), &format!("{GOOD}\n"), db)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            CliError("an admin user named `alice` already exists".to_string())
        );
    }

    #[tokio::test]
    async fn passwd_changes_the_password_and_reports_an_unknown_user() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let passwd = |username: &str| AdminCommand::User {
            command: AdminUserCommand::Passwd {
                username: username.to_string(),
                password_file: None,
            },
        };

        run(passwd("alice"), "another-long-password\n", db.clone())
            .await
            .unwrap();
        let user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            admin::password::verify_password(&user.password_hash, "another-long-password"),
            Ok(true)
        );

        let error = run(passwd("nobody"), &format!("{GOOD}\n"), db)
            .await
            .unwrap_err();
        assert_eq!(error, CliError("no such admin user: nobody".to_string()));
    }

    /// The detail an operator's row could not carry: the enrolment state and
    /// the recovery-code count. Both shapes, and an unknown name refused in
    /// words rather than answered with an empty object.
    #[tokio::test]
    async fn show_reports_the_row_and_the_second_factor() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let show = |username: &str, json: bool| AdminCommand::User {
            command: AdminUserCommand::Show {
                username: username.to_string(),
                json,
            },
        };
        for json in [true, false] {
            run(show("alice", json), "", db.clone()).await.unwrap();
        }
        assert_eq!(
            run(show("nobody", false), "", db.clone())
                .await
                .unwrap_err(),
            CliError("no such admin user: nobody".to_string())
        );

        // The three states the detail shape distinguishes, walked in order: no
        // factor, enrolment started, confirmed. `totpEnabled` alone cannot tell
        // the first two apart, which is why `enrolmentPending` is on this shape
        // and not on the listing's.
        let user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        let rendered = admin::render_admin_user_detail_json(&user, 0);
        assert_eq!(rendered["totpEnabled"], false);
        assert_eq!(rendered["enrolmentPending"], false);
        assert_eq!(rendered["recoveryCodesRemaining"], 0);
        // The listing shape carries neither, and that is the point.
        let listed = admin::render_admin_user_json(&user);
        assert!(listed.get("enrolmentPending").is_none());
        assert!(listed.get("recoveryCodesRemaining").is_none());

        let enrolled = enrol("alice", db.clone()).await;
        let rendered = admin::render_admin_user_detail_json(&enrolled, 10);
        assert_eq!(rendered["totpEnabled"], true);
        assert_eq!(rendered["recoveryCodesRemaining"], 10);
        run(show("alice", true), "", db).await.unwrap();
    }

    /// The window three listings grew when the bare array went. `admin user
    /// list` is the one listing in the binary that is oldest first, so the first
    /// page holds the operator created first -- the bootstrap one.
    #[tokio::test]
    async fn the_user_listing_pages_oldest_first() {
        let db = db().await;
        for name in ["alice", "bob", "carol"] {
            run(create(name), &format!("{GOOD}\n"), db.clone())
                .await
                .unwrap();
        }

        let (first, total) = users::list_users(2, 0, db.clone()).await.unwrap();
        let (second, also_total) = users::list_users(2, 2, db.clone()).await.unwrap();
        assert_eq!((total, also_total), (3, 3), "the total is the table");
        let walked: Vec<&str> = first
            .iter()
            .chain(second.iter())
            .map(|user| user.username.as_str())
            .collect();
        assert_eq!(walked, ["alice", "bob", "carol"]);

        // A nonsense window is clamped rather than refused, `Window::resolve`'s
        // rule -- `LIMIT -1` is SQLite's "no limit", the one answer a page must
        // never accidentally give.
        for (limit, offset) in [(0, 0), (-5, -5)] {
            run(
                AdminCommand::User {
                    command: AdminUserCommand::List {
                        limit,
                        offset,
                        json: true,
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn list_renders_in_both_formats_and_is_empty_when_there_are_none() {
        let db = db().await;
        for json in [true, false] {
            run(
                AdminCommand::User {
                    command: AdminUserCommand::List {
                        limit: DEFAULT_LIMIT,
                        offset: 0,
                        json,
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap();
        }

        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        for json in [true, false] {
            run(
                AdminCommand::User {
                    command: AdminUserCommand::List {
                        limit: DEFAULT_LIMIT,
                        offset: 0,
                        json,
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn disable_and_enable_move_the_status_and_refuse_an_unknown_user() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let disable = |username: &str| AdminCommand::User {
            command: AdminUserCommand::Disable {
                username: username.to_string(),
            },
        };
        let enable = |username: &str| AdminCommand::User {
            command: AdminUserCommand::Enable {
                username: username.to_string(),
            },
        };

        run(disable("alice"), "", db.clone()).await.unwrap();
        assert!(
            !AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );

        run(enable("alice"), "", db.clone()).await.unwrap();
        assert!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );

        for command in [disable("nobody"), enable("nobody")] {
            assert_eq!(
                run(command, "", db.clone()).await.unwrap_err(),
                CliError("no such admin user: nobody".to_string())
            );
        }
    }

    #[tokio::test]
    async fn create_writes_the_requested_role_and_refuses_an_unknown_one() {
        let db = db().await;

        run(
            create_with_role("reader", "viewer"),
            &format!("{GOOD}\n"),
            db.clone(),
        )
        .await
        .unwrap();
        let user = AdminUser::find_by_username("reader", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.role(), AdminRole::Viewer);

        // The default is the full tier.
        run(create("boss"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        assert_eq!(
            AdminUser::find_by_username("boss", &db)
                .await
                .unwrap()
                .unwrap()
                .role(),
            AdminRole::Admin
        );

        let error = run(
            create_with_role("nope", "supervisor"),
            &format!("{GOOD}\n"),
            db.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("--role"), "{}", error.0);
        assert!(error.0.contains("supervisor"), "{}", error.0);
        assert!(
            AdminUser::find_by_username("nope", &db)
                .await
                .unwrap()
                .is_none(),
            "a refused role must not create a row"
        );
    }

    #[tokio::test]
    async fn role_changes_the_tier_revokes_sessions_and_refuses_an_unknown_user() {
        use crate::sqlite::admin_session::{AdminSession, NewSession};

        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: "hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(60),
            &db,
        )
        .await
        .unwrap();

        let role = |username: &str, role: &str| AdminCommand::User {
            command: AdminUserCommand::Role {
                username: username.to_string(),
                role: role.to_string(),
            },
        };

        run(role("alice", "operator"), "", db.clone())
            .await
            .unwrap();
        assert_eq!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .unwrap()
                .role(),
            AdminRole::Operator
        );
        assert!(
            AdminSession::list_all(Some(user.id), &db)
                .await
                .unwrap()
                .is_empty(),
            "a role change revokes the operator's sessions"
        );

        assert_eq!(
            run(role("nobody", "viewer"), "", db.clone())
                .await
                .unwrap_err(),
            CliError("no such admin user: nobody".to_string())
        );

        let error = run(role("alice", "root"), "", db).await.unwrap_err();
        assert!(error.0.contains("role"), "{}", error.0);
        assert!(error.0.contains("root"), "{}", error.0);
    }

    #[tokio::test]
    async fn delete_covers_not_found_cancelled_and_deleted() {
        let db = db().await;
        let delete = AdminCommand::User {
            command: AdminUserCommand::Delete {
                username: "alice".to_string(),
            },
        };

        assert_eq!(
            run(
                AdminCommand::User {
                    command: AdminUserCommand::Delete {
                        username: "nobody".to_string()
                    }
                },
                "",
                db.clone()
            )
            .await
            .unwrap_err(),
            CliError("no such admin user: nobody".to_string())
        );

        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        // Declined: `yes` is false here, so the reader's "n" decides.
        let mut no = b"n\n".as_slice();
        run_admin_command(
            AdminCommand::User {
                command: AdminUserCommand::Delete {
                    username: "alice".to_string(),
                },
            },
            false,
            Palette::plain(),
            &mut no,
            &Config::default(),
            db.clone(),
        )
        .await
        .unwrap();
        assert!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .is_some()
        );

        run(delete, "", db.clone()).await.unwrap();
        assert!(
            AdminUser::find_by_username("alice", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn session_list_filters_by_user_and_refuses_an_unknown_one() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let alice = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        AdminSession::create(
            NewSession {
                user_id: alice.id,
                token_hash: "hash-a",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(60),
            &db,
        )
        .await
        .unwrap();

        for (username, json) in [
            (None, true),
            (None, false),
            (Some("alice".to_string()), true),
            (Some("alice".to_string()), false),
        ] {
            run(
                AdminCommand::Session {
                    command: AdminSessionCommand::List {
                        username,
                        limit: DEFAULT_LIMIT,
                        offset: 0,
                        json,
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap();
        }

        assert_eq!(
            run(
                AdminCommand::Session {
                    command: AdminSessionCommand::List {
                        username: Some("nobody".to_string()),
                        limit: DEFAULT_LIMIT,
                        offset: 0,
                        json: false,
                    },
                },
                "",
                db,
            )
            .await
            .unwrap_err(),
            CliError("no such admin user: nobody".to_string())
        );
    }

    #[tokio::test]
    async fn session_revoke_handles_user_all_and_neither() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let alice = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        for hash in ["a", "b"] {
            AdminSession::create(
                NewSession {
                    user_id: alice.id,
                    token_hash: hash,
                    csrf_token: "csrf",
                    created_ip: None,
                    user_agent: None,
                },
                std::time::Duration::from_secs(60),
                &db,
            )
            .await
            .unwrap();
        }

        // Neither flag: refuse rather than guess which was meant.
        assert_eq!(
            run(
                AdminCommand::Session {
                    command: AdminSessionCommand::Revoke {
                        user: None,
                        all: false
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap_err(),
            CliError("say whose sessions to revoke: --user <username>, or --all".to_string())
        );

        assert_eq!(
            run(
                AdminCommand::Session {
                    command: AdminSessionCommand::Revoke {
                        user: Some("nobody".to_string()),
                        all: false
                    },
                },
                "",
                db.clone(),
            )
            .await
            .unwrap_err(),
            CliError("no such admin user: nobody".to_string())
        );

        run(
            AdminCommand::Session {
                command: AdminSessionCommand::Revoke {
                    user: Some("alice".to_string()),
                    all: false,
                },
            },
            "",
            db.clone(),
        )
        .await
        .unwrap();
        assert!(AdminSession::list_all(None, &db).await.unwrap().is_empty());

        // `--all` on an empty table is a no-op, not a failure.
        run(
            AdminCommand::Session {
                command: AdminSessionCommand::Revoke {
                    user: None,
                    all: true,
                },
            },
            "",
            db,
        )
        .await
        .unwrap();
    }

    // --- Second factor ----------------------------------------------------

    fn totp(command: AdminUserTotpCommand) -> AdminCommand {
        AdminCommand::User {
            command: AdminUserCommand::Totp { command },
        }
    }

    /// Enrols `username` through the operation layer, the way the panel would,
    /// so the CLI arms have a real factor to act on.
    async fn enrol(username: &str, database: Arc<Database>) -> AdminUser {
        let mut user = AdminUser::find_by_username(username, &database)
            .await
            .unwrap()
            .unwrap();
        let enrolment =
            mfa::begin_totp_enrolment(&mut user, "http://localhost:3001", database.clone())
                .await
                .unwrap();
        let code = admin::totp::totp_at(
            &enrolment.secret,
            admin::totp::step_at(crate::sqlite::nonce::now_secs()),
            admin::totp::DIGITS,
        );
        mfa::confirm_totp_enrolment(&mut user, &code, None, database)
            .await
            .unwrap()
            .expect("a freshly generated code must confirm its own enrolment");
        user
    }

    #[tokio::test]
    async fn totp_status_reports_all_three_states() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let status = |json| {
            totp(AdminUserTotpCommand::Status {
                username: "alice".to_string(),
                json,
            })
        };

        // No factor.
        run(status(false), "", db.clone()).await.unwrap();
        run(status(true), "", db.clone()).await.unwrap();

        // Enrolment started and never confirmed: still not a factor, but it
        // must not read the same as "off" -- an operator who thinks they
        // enrolled has no other way to find out.
        let mut user = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        mfa::begin_totp_enrolment(&mut user, "http://localhost:3001", db.clone())
            .await
            .unwrap();
        let line = render::render_admin_totp_line(&user, 0, Palette::plain());
        assert!(line.contains("pending"), "{line}");
        run(status(false), "", db.clone()).await.unwrap();

        // Confirmed.
        let user = enrol("alice", db.clone()).await;
        let line = render::render_admin_totp_line(&user, 10, Palette::plain());
        assert!(line.contains("totp=enabled"), "{line}");
        assert!(line.contains("recovery-codes=10"), "{line}");
        run(status(true), "", db).await.unwrap();
    }

    #[tokio::test]
    async fn totp_reset_clears_the_factor_the_codes_and_the_sessions() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let user = enrol("alice", db.clone()).await;

        AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: "live-session",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(3600),
            &db,
        )
        .await
        .unwrap();

        let reset = || {
            totp(AdminUserTotpCommand::Reset {
                username: "alice".to_string(),
            })
        };

        // Declined: `yes` is false, so the reader's "n" decides and nothing
        // moves. Removing a security control is confirm-gated, unlike
        // `order revoke`, which only ever tightens trust.
        let mut no = b"n\n".as_slice();
        run_admin_command(
            reset(),
            false,
            Palette::plain(),
            &mut no,
            &Config::default(),
            db.clone(),
        )
        .await
        .unwrap();
        let unchanged = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert!(unchanged.has_totp());

        run(reset(), "", db.clone()).await.unwrap();

        let after = AdminUser::find_by_username("alice", &db)
            .await
            .unwrap()
            .unwrap();
        assert!(!after.has_totp());
        assert!(!after.has_pending_totp());
        assert_eq!(
            mfa::recovery_codes_remaining(after.id, db.clone())
                .await
                .unwrap(),
            0
        );
        assert!(
            AdminSession::list_all(Some(after.id), &db)
                .await
                .unwrap()
                .is_empty(),
            "a factor removed that left a live session behind is a change in name only"
        );

        // Idempotent, and says so rather than asking again.
        run(reset(), "", db).await.unwrap();
    }

    #[tokio::test]
    async fn totp_recovery_codes_supersede_the_previous_set() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();
        let user = enrol("alice", db.clone()).await;

        let before =
            crate::sqlite::admin_recovery_code::AdminRecoveryCode::list_unused(user.id, &db)
                .await
                .unwrap();
        assert_eq!(before.len(), 10);

        run(
            totp(AdminUserTotpCommand::RecoveryCodes {
                username: "alice".to_string(),
            }),
            "",
            db.clone(),
        )
        .await
        .unwrap();

        let after =
            crate::sqlite::admin_recovery_code::AdminRecoveryCode::list_unused(user.id, &db)
                .await
                .unwrap();
        assert_eq!(after.len(), 10);
        assert!(
            after
                .iter()
                .all(|code| before.iter().all(|old| old.id != code.id)),
            "the previous set must stop working"
        );
    }

    /// Recovery codes for an operator with no factor would recover nothing, so
    /// the command says so rather than minting ten useless strings.
    #[tokio::test]
    async fn totp_recovery_codes_refuses_an_operator_with_no_factor() {
        let db = db().await;
        run(create("alice"), &format!("{GOOD}\n"), db.clone())
            .await
            .unwrap();

        let error = run(
            totp(AdminUserTotpCommand::RecoveryCodes {
                username: "alice".to_string(),
            }),
            "",
            db,
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("no second factor"), "{}", error.0);
    }

    #[tokio::test]
    async fn every_totp_arm_refuses_an_unknown_operator() {
        let db = db().await;
        let expected = CliError("no such admin user: nobody".to_string());

        for command in [
            AdminUserTotpCommand::Status {
                username: "nobody".to_string(),
                json: false,
            },
            AdminUserTotpCommand::Reset {
                username: "nobody".to_string(),
            },
            AdminUserTotpCommand::RecoveryCodes {
                username: "nobody".to_string(),
            },
        ] {
            assert_eq!(
                run(totp(command), "", db.clone()).await.unwrap_err(),
                expected
            );
        }
    }
}
