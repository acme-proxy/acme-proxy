use std::str::FromStr;

use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::rfc3339;

/// What a web-admin operator's live sessions are allowed to do.
///
/// A privilege tier, not an authentication state (that is `admin_sessions.state`
/// and the `pending_mfa` / `active` split). Stored in `admin_users.role` as one
/// of the [`AdminRole::as_str`] spellings, with **`NULL` read as [`Admin`]** --
/// an operator created before the column existed keeps the authority they had,
/// and so does the bootstrap operator, who is the only way into the panel.
///
/// Variants are declared low privilege to high, so `role >= AdminRole::Operator`
/// is the gate the write extractors run (`src/webadmin/session.rs`).
///
/// [`Admin`]: AdminRole::Admin
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdminRole {
    /// Reads every page and API route; may still act on their **own** account
    /// (password, sessions, second factor, logout). Refused every shared or CA
    /// mutation.
    Viewer,
    /// [`Viewer`], plus every CA mutation: revoke a certificate, deactivate or
    /// delete an ACME account, delete an order, mint or revoke EAB credentials,
    /// run a nonce sweep. Refused the colleague-management surface.
    ///
    /// [`Viewer`]: AdminRole::Viewer
    Operator,
    /// [`Operator`], plus `/operators/*` -- disabling or re-enabling a
    /// colleague, resetting their second factor, revoking one of their
    /// sessions. Everything.
    ///
    /// [`Operator`]: AdminRole::Operator
    Admin,
}

impl AdminRole {
    /// Every value, low privilege to high -- the order the variants are
    /// declared in, and the one an error message lists them in.
    pub const ALL: &'static [Self] = &[Self::Viewer, Self::Operator, Self::Admin];

    /// The exact string stored in `admin_users.role`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// Reads the column back. **Infallible**: `NULL` and `"admin"` are [`Admin`],
    /// and anything unrecognised is [`Viewer`] -- the least-privilege direction,
    /// the same fail-closed choice [`AdminUser::is_active`] makes for a `status`
    /// outside its `CHECK`. A garbage value can only arrive by a hand-edit of
    /// the database; every write path here goes through a canonical
    /// [`AdminRole::as_str`].
    ///
    /// [`Admin`]: AdminRole::Admin
    /// [`Viewer`]: AdminRole::Viewer
    #[must_use]
    pub fn from_storage(raw: Option<&str>) -> Self {
        match raw {
            None | Some("admin") => Self::Admin,
            Some("operator") => Self::Operator,
            _ => Self::Viewer,
        }
    }
}

impl std::fmt::Display for AdminRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a web-admin operator may sign in at all.
///
/// The two values `admin_users.status`'s `CHECK` allows, as a type rather than
/// as the free strings four call sites used to pass. The migration is frozen
/// and its spellings are the compatibility surface, so [`AdminStatus::as_str`]
/// answers the byte-identical value the column already holds -- the
/// `src/sqlite/status.rs` treatment, kept here beside [`AdminRole`] because the
/// two are read together and neither is a state machine the way an order's
/// status is.
///
/// Deliberately no `from_storage`: [`AdminUser::is_active`] is the only reader
/// and it already fails closed on a value outside the `CHECK`, which is the
/// direction a hand-edited row should fall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminStatus {
    /// May sign in.
    Active,
    /// May not. Setting this also revokes every session the operator holds --
    /// a disabled account with a live cookie would be disabled in name only.
    Disabled,
}

impl AdminStatus {
    /// The exact string stored in `admin_users.status`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for AdminStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AdminRole {
    type Err = String;

    /// For operator input (`admin user create --role`, `admin user role`). An
    /// unknown value is refused **by name** listing the alternatives -- the
    /// `--status` / `--event` rule, since a silent fallback would be a privilege
    /// decision made by a typo.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            other => Err(format!(
                "unknown role `{other}` (expected one of: viewer, operator, admin)"
            )),
        }
    }
}

/// An operator of the web admin interface.
///
/// Not an ACME concept and never joined to one: an [`AdminUser`] is a person
/// with a password, an `accounts` row is a client key. There is no `profile`
/// column -- an admin user sees every endpoint this process serves.
///
/// ## Methods
///
/// - `create`: persist a new operator, `active`
/// - `find_by_id` / `find_by_username`: lookup (the latter is the login path)
/// - `list_all`: every operator, oldest first
/// - `set_password_hash` / `set_status` / `set_role` / `mark_logged_in`:
///   in-place updates
/// - `role`: the privilege tier, `NULL` resolved to [`AdminRole::Admin`]
/// - `set_totp_pending` / `confirm_totp` / `clear_totp` / `claim_totp_step`:
///   the second factor's lifecycle, and RFC 6238 §5.2's replay guard
/// - `delete`: remove, cascading to the operator's sessions and recovery codes
/// - `to_json`: admin-facing rendering (never the password hash, never a secret)
#[derive(Debug, Clone)]
pub struct AdminUser {
    pub id: Uuid,
    /// Always lowercase: [`AdminUser::create`] normalizes before writing, so
    /// `Alice` and `alice` cannot become two logins that read as one.
    pub username: String,
    /// The encoded KDF output -- see `crate::admin::password`. Never rendered.
    pub password_hash: String,
    pub status: String,
    /// The privilege tier, raw from the column. `None` is a row that predates
    /// the `role` column and reads as [`AdminRole::Admin`]; use
    /// [`AdminUser::role`] rather than matching this directly.
    pub role: Option<String>,
    /// Set once the owner has proven a code against a pending enrolment.
    /// `None` means no second factor is configured.
    pub totp_secret: Option<Vec<u8>>,
    /// An enrolment begun but not yet confirmed. Not a usable second factor.
    pub totp_pending_secret: Option<Vec<u8>>,
    /// The last TOTP time step accepted, so a code cannot be replayed inside
    /// its own window.
    pub totp_last_step: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
    /// Where to send this operator security notifications (a completed sign-in
    /// from an unfamiliar address, a refused second factor, a credential
    /// change). `None` means none are sent -- the event is still logged.
    pub contact_email: Option<String>,
    /// The operator's recent distinct login addresses, most-recent-first,
    /// capped at [`KNOWN_LOGIN_IPS`]. Compared against the live request, but
    /// **only** to decide whether to notify -- never to authorise. Persisted as
    /// a JSON array (the `accounts.contact` convention).
    pub known_login_ips: Vec<String>,
}

/// Every column of `admin_users`, in one place: each read must select the same set
/// or `from_row` fails on whichever forgot one.
///
/// A `macro_rules!` rather than a `const` so the expansion is a string
/// *literal*, which is what `sqlx::query`'s `SqlSafeStr` bound requires.
macro_rules! columns {
    () => {
        "id, username, password_hash, status, role, totp_secret, totp_pending_secret, \
         totp_last_step, created_at, updated_at, last_login_at, contact_email, known_login_ips"
    };
}

/// How many recent distinct login addresses [`AdminUser::known_login_ips`]
/// keeps. A completed sign-in from an address outside this set (and only while
/// the set is non-empty) is what raises the "unusual location" operator
/// notification -- so the bound is a trade between an operator who moves
/// between a few networks not being alerted on every switch, and a stale entry
/// not masking a genuinely new address for too long. Not a config key: the
/// right value does not depend on the deployment.
pub const KNOWN_LOGIN_IPS: usize = 5;

impl AdminUser {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(AdminUser {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            status: row.try_get("status")?,
            role: row.try_get("role")?,
            totp_secret: row.try_get("totp_secret")?,
            totp_pending_secret: row.try_get("totp_pending_secret")?,
            totp_last_step: row.try_get("totp_last_step")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_login_at: row.try_get("last_login_at")?,
            contact_email: row.try_get("contact_email")?,
            known_login_ips: {
                let raw: String = row.try_get("known_login_ips")?;
                serde_json::from_str(&raw).map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            },
        })
    }

    /// Persists a new operator, `active`. `username` is lowercased and trimmed
    /// here rather than at the call sites, so every path -- the CLI, a future
    /// API -- stores the same thing.
    ///
    /// `password_hash` is already encoded by `crate::admin::password`: this
    /// layer never sees a plaintext password and cannot hash one.
    ///
    /// `role` is written **in the same INSERT**. `None` leaves the column
    /// `NULL`, which reads as [`AdminRole::Admin`] -- the safe default for the
    /// bootstrap operator, and what every row created before the column existed
    /// holds. It used to be the only option, with `admin::users::create_user`
    /// calling [`AdminUser::set_role`] afterwards for a narrower tier; that made
    /// `admin user create --role viewer` two writes, so a failure between them
    /// left an operator at full `admin` with their password already set.
    ///
    /// A duplicate username surfaces as the UNIQUE violation it is; the caller
    /// (`admin::users::create_user`) checks first and reports it in words.
    pub async fn create(
        username: &str,
        password_hash: &str,
        role: Option<AdminRole>,
        database: &Database,
    ) -> Result<AdminUser, sqlx::Error> {
        let now = now_secs();
        let user = AdminUser {
            id: crate::sqlite::id::mint(),
            username: username.trim().to_lowercase(),
            password_hash: password_hash.to_string(),
            status: "active".to_string(),
            role: role.map(|role| role.as_str().to_string()),
            totp_secret: None,
            totp_pending_secret: None,
            totp_last_step: None,
            created_at: now,
            updated_at: now,
            last_login_at: None,
            contact_email: None,
            known_login_ips: Vec::new(),
        };

        debug!(event = "db_admin_user_create_started", outcome = "progress", username = %user.username);
        sqlx::query(
            "INSERT INTO admin_users \
             (id, username, password_hash, status, role, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.status)
        .bind(user.role.clone())
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&database.pool)
        .await?;

        info!(event = "db_admin_user_created", outcome = "success", user_id = %user.id, username = %user.username);
        Ok(user)
    }

    pub async fn find_by_id(
        id: Uuid,
        database: &Database,
    ) -> Result<Option<AdminUser>, sqlx::Error> {
        debug!(event = "db_admin_user_find_by_id_started", outcome = "progress", id = ?id);
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_users WHERE id = ?;"
        ))
        .bind(id)
        .fetch_optional(&database.pool)
        .await?;

        row.map(AdminUser::from_row).transpose()
    }

    /// The login path. Lowercases the argument for the same reason
    /// [`AdminUser::create`] does -- a login typed `Alice` must find `alice`.
    pub async fn find_by_username(
        username: &str,
        database: &Database,
    ) -> Result<Option<AdminUser>, sqlx::Error> {
        debug!(
            event = "db_admin_user_find_by_username_started",
            outcome = "progress"
        );
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_users WHERE username = ?;"
        ))
        .bind(username.trim().to_lowercase())
        .fetch_optional(&database.pool)
        .await?;

        row.map(AdminUser::from_row).transpose()
    }

    /// Every operator, oldest first.
    ///
    /// A **scan**, not a listing: its one caller is
    /// `admin::mfa::operators_without_a_factor`, which counts the operators
    /// with no confirmed factor for the `admin.require_mfa` startup warning.
    /// Nothing renders it, which is why it can sit beside [`AdminUser::search`]
    /// without being the second listing the paging pass deleted
    /// `Account::list_all` for -- an order nothing displays cannot disagree
    /// with the paged one.
    pub async fn list_all(database: &Database) -> Result<Vec<AdminUser>, sqlx::Error> {
        debug!(
            event = "db_admin_user_list_all_started",
            outcome = "progress"
        );
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_users ORDER BY created_at ASC, id ASC;"
        ))
        .fetch_all(&database.pool)
        .await?;

        rows.into_iter().map(AdminUser::from_row).collect()
    }

    /// One page of `admin user list`, plus the total the table holds unpaged.
    ///
    /// **Oldest first**, and the one listing in the binary that is: every other
    /// paged listing puts the newest row on top, but the bootstrap operator --
    /// the one created before the panel could be signed in to at all -- is
    /// precisely the row whose position should not move as colleagues are
    /// added. `id` breaks the `created_at` tie for `Eab::search`'s reason:
    /// `created_at` is a whole second, and operators are created in one go.
    pub async fn search(
        limit: i64,
        offset: i64,
        database: &Database,
    ) -> Result<(Vec<AdminUser>, i64), sqlx::Error> {
        debug!(
            event = "db_admin_user_search_started",
            outcome = "progress",
            limit = limit,
            offset = offset
        );
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM admin_users ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?;"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&database.pool)
        .await?;
        let total: i64 = sqlx::query("SELECT COUNT(*) FROM admin_users;")
            .fetch_one(&database.pool)
            .await?
            .try_get(0)?;

        let users = rows
            .into_iter()
            .map(AdminUser::from_row)
            .collect::<Result<_, _>>()?;
        Ok((users, total))
    }

    /// Replaces the stored hash. Callers are responsible for invalidating the
    /// owner's sessions -- `admin::users::set_password` does, and a password
    /// change that left them alive would be a change in name only.
    pub async fn set_password_hash(
        &mut self,
        password_hash: &str,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?;")
            .bind(password_hash)
            .bind(now)
            .bind(self.id)
            .execute(&database.pool)
            .await?;

        self.password_hash = password_hash.to_string();
        self.updated_at = now;
        info!(event = "db_admin_user_password_changed", outcome = "success", user_id = %self.id, username = %self.username);
        Ok(())
    }

    /// Moves between `active` and `disabled`. A disabled operator cannot log
    /// in, and an existing session of theirs is refused on its next use --
    /// the session rows are left for the reaper rather than deleted here, so
    /// re-enabling is a single UPDATE either way.
    pub async fn set_status(
        &mut self,
        status: &str,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_users SET status = ?, updated_at = ? WHERE id = ?;")
            .bind(status)
            .bind(now)
            .bind(self.id)
            .execute(&database.pool)
            .await?;

        self.status = status.to_string();
        self.updated_at = now;
        info!(event = "db_admin_user_status_changed", outcome = "success", user_id = %self.id, username = %self.username, status = %status);
        Ok(())
    }

    /// Sets the privilege tier. Callers revoke the operator's sessions --
    /// `admin::users::set_role` does, matching a `disable` and a password
    /// change; the write extractors also re-read `role` every request, so a
    /// demotion takes effect on the next call regardless.
    pub async fn set_role(
        &mut self,
        role: AdminRole,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_users SET role = ?, updated_at = ? WHERE id = ?;")
            .bind(role.as_str())
            .bind(now)
            .bind(self.id)
            .execute(&database.pool)
            .await?;

        self.role = Some(role.as_str().to_string());
        self.updated_at = now;
        info!(event = "db_admin_user_role_changed", outcome = "success", user_id = %self.id, username = %self.username, role = %role);
        Ok(())
    }

    /// Sets (or clears, with `None`) the address this operator receives security
    /// notifications at. Not a credential -- no session is revoked. The address
    /// shape is the caller's to validate (`admin::users::set_contact_email`);
    /// this layer only stores what it is handed.
    pub async fn set_contact_email(
        &mut self,
        email: Option<&str>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_users SET contact_email = ?, updated_at = ? WHERE id = ?;")
            .bind(email)
            .bind(now)
            .bind(self.id)
            .execute(&database.pool)
            .await?;

        self.contact_email = email.map(str::to_string);
        self.updated_at = now;
        info!(event = "db_admin_user_contact_changed", outcome = "success", user_id = %self.id, username = %self.username, cleared = email.is_none());
        Ok(())
    }

    /// Stores an enrolment the owner has not yet proven a code against.
    ///
    /// Not a usable second factor: [`AdminUser::has_totp`] stays `false` until
    /// [`AdminUser::confirm_totp`] moves it across, which is what stops an
    /// abandoned enrolment from locking its own owner out.
    pub async fn set_totp_pending(
        &mut self,
        secret: &[u8],
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query("UPDATE admin_users SET totp_pending_secret = ?, updated_at = ? WHERE id = ?;")
            .bind(secret)
            .bind(now)
            .bind(self.id)
            .execute(&database.pool)
            .await?;

        self.totp_pending_secret = Some(secret.to_vec());
        self.updated_at = now;
        info!(event = "db_admin_totp_enrolment_started", outcome = "progress", user_id = %self.id, username = %self.username);
        Ok(())
    }

    /// Promotes the pending secret to the real one.
    ///
    /// One statement, deliberately: a half-applied enrolment would leave the
    /// operator believing they have a factor that nothing checks, or holding a
    /// pending secret alongside a live one. `totp_last_step` is cleared with
    /// them -- the replay guard belongs to the secret it was recorded against.
    ///
    /// A no-op when nothing is pending, so a double-submit cannot clear a live
    /// factor.
    pub async fn confirm_totp(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        let Some(pending) = self.totp_pending_secret.clone() else {
            return Ok(());
        };

        let now = now_secs();
        sqlx::query(
            "UPDATE admin_users SET totp_secret = totp_pending_secret, \
             totp_pending_secret = NULL, totp_last_step = NULL, updated_at = ? \
             WHERE id = ? AND totp_pending_secret IS NOT NULL;",
        )
        .bind(now)
        .bind(self.id)
        .execute(&database.pool)
        .await?;

        self.totp_secret = Some(pending);
        self.totp_pending_secret = None;
        self.totp_last_step = None;
        self.updated_at = now;
        info!(event = "db_admin_totp_enabled", outcome = "success", user_id = %self.id, username = %self.username);
        Ok(())
    }

    /// Removes the factor, any half-finished enrolment and the replay guard
    /// together. Callers drop the recovery codes too -- a code that recovers
    /// access to a factor that no longer exists is a second password.
    pub async fn clear_totp(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query(
            "UPDATE admin_users SET totp_secret = NULL, totp_pending_secret = NULL, \
             totp_last_step = NULL, updated_at = ? WHERE id = ?;",
        )
        .bind(now)
        .bind(self.id)
        .execute(&database.pool)
        .await?;

        self.totp_secret = None;
        self.totp_pending_secret = None;
        self.totp_last_step = None;
        self.updated_at = now;
        info!(event = "db_admin_totp_disabled", outcome = "success", user_id = %self.id, username = %self.username);
        Ok(())
    }

    /// Records `step` as accepted, refusing one that is not strictly newer than
    /// the stored value -- RFC 6238 §5.2's replay guard.
    ///
    /// The comparison lives in the `WHERE` clause rather than in Rust: a code
    /// observed in flight and resubmitted inside its own 30-second window must
    /// not be accepted twice, and with two requests racing it is
    /// `rows_affected` that decides which one was first. Same primitive as
    /// `Nonce::verify`.
    pub async fn claim_totp_step(
        &mut self,
        step: i64,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        let now = now_secs();
        let result = sqlx::query(
            "UPDATE admin_users SET totp_last_step = ?, updated_at = ? \
             WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?);",
        )
        .bind(step)
        .bind(now)
        .bind(self.id)
        .bind(step)
        .execute(&database.pool)
        .await?;

        let claimed = result.rows_affected() == 1;
        if claimed {
            self.totp_last_step = Some(step);
            self.updated_at = now;
        }
        Ok(claimed)
    }

    /// Stamps `last_login_at`, and folds `client_ip` into `known_login_ips`
    /// (move-to-front, deduplicated, capped at [`KNOWN_LOGIN_IPS`]). Advisory
    /// only -- nothing authorises on either column; the address set exists so a
    /// sign-in from an unfamiliar address can be noticed.
    ///
    /// Called when a login *completes*, which for an operator with a second
    /// factor is one request later than the password being accepted. A caller
    /// that needs the *pre-login* address set (to decide whether this sign-in
    /// is from a new address) must read `known_login_ips` before calling.
    pub async fn mark_logged_in(
        &mut self,
        client_ip: Option<&str>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();

        if let Some(ip) = client_ip.filter(|ip| !ip.is_empty()) {
            let mut known = Vec::with_capacity(KNOWN_LOGIN_IPS);
            known.push(ip.to_string());
            known.extend(
                self.known_login_ips
                    .iter()
                    .filter(|seen| seen.as_str() != ip)
                    .take(KNOWN_LOGIN_IPS - 1)
                    .cloned(),
            );
            // `Vec<String>` serialization is infallible.
            let known_json = Value::from(known.clone()).to_string();
            sqlx::query(
                "UPDATE admin_users SET last_login_at = ?, known_login_ips = ? WHERE id = ?;",
            )
            .bind(now)
            .bind(known_json)
            .bind(self.id)
            .execute(&database.pool)
            .await?;
            self.known_login_ips = known;
        } else {
            sqlx::query("UPDATE admin_users SET last_login_at = ? WHERE id = ?;")
                .bind(now)
                .bind(self.id)
                .execute(&database.pool)
                .await?;
        }

        self.last_login_at = Some(now);
        Ok(())
    }

    /// Removes the operator. Their sessions go with them via the schema's
    /// `ON DELETE CASCADE`, which needs `foreign_keys` on -- `Database::connect`
    /// and `connect_in_memory` both pin it. Returns whether a row existed.
    pub async fn delete(id: Uuid, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "db_admin_user_delete_started", outcome = "progress", id = ?id);
        let result = sqlx::query("DELETE FROM admin_users WHERE id = ?;")
            .bind(id)
            .execute(&database.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            info!(event = "db_admin_user_deleted", outcome = "success", user_id = %id);
        }
        Ok(deleted)
    }

    /// Whether this operator may log in and hold a session.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// The privilege tier, with `NULL` resolved to [`AdminRole::Admin`]. Match
    /// on this, never on the raw [`AdminUser::role`] field.
    #[must_use]
    pub fn role(&self) -> AdminRole {
        AdminRole::from_storage(self.role.as_deref())
    }

    /// Whether a confirmed second factor is configured. A pending enrolment
    /// does not count -- it has never been proven against a code.
    #[must_use]
    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }

    /// Whether an enrolment is half-finished: a secret was generated and shown,
    /// and no code has proven it yet.
    ///
    /// Deliberately not folded into [`AdminUser::has_totp`] and deliberately
    /// not in [`AdminUser::to_json`]: the login path must treat this operator as
    /// having *no* factor, and the only surface that cares is the enrolment
    /// page deciding whether to offer "start over".
    #[must_use]
    pub fn has_pending_totp(&self) -> bool {
        self.totp_pending_secret.is_some()
    }

    /// The admin-facing rendering. **Never** includes `password_hash`, nor
    /// either TOTP secret -- only whether one is configured.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "username": self.username,
            "status": self.status,
            "role": self.role().as_str(),
            "totpEnabled": self.has_totp(),
            "createdAt": rfc3339(self.created_at),
            "updatedAt": rfc3339(self.updated_at),
            "lastLoginAt": self.last_login_at.map(rfc3339),
            "contactEmail": self.contact_email,
            "knownLoginIps": self.known_login_ips,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    #[tokio::test]
    async fn create_persists_an_active_user_with_a_lowercased_username() {
        let db = db().await;
        let user = AdminUser::create("  Alice  ", "hash", None, &db)
            .await
            .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.status, "active");
        assert!(user.is_active());
        assert!(user.last_login_at.is_none());
        assert!(!user.has_totp());
    }

    #[tokio::test]
    async fn find_by_username_is_case_insensitive_and_round_trips() {
        let db = db().await;
        let created = AdminUser::create("alice", "hash", None, &db).await.unwrap();
        let found = AdminUser::find_by_username("ALICE", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, created.id);
        assert_eq!(found.password_hash, "hash");

        let by_id = AdminUser::find_by_id(created.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.username, "alice");
    }

    #[tokio::test]
    async fn lookups_of_unknown_users_return_none() {
        let db = db().await;
        assert!(
            AdminUser::find_by_username("nobody", &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            AdminUser::find_by_id(crate::sqlite::id::mint(), &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_duplicate_username_is_refused_by_the_unique_constraint() {
        let db = db().await;
        AdminUser::create("alice", "hash", None, &db).await.unwrap();
        // Also proves the normalization above is a real constraint, not a
        // near-miss: `Alice` collides with the stored `alice`.
        let error = AdminUser::create("Alice", "other", None, &db)
            .await
            .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("unique"),
            "expected a UNIQUE violation, got: {error}"
        );
    }

    #[tokio::test]
    async fn list_all_returns_every_user_and_empty_is_empty() {
        let db = db().await;
        assert!(AdminUser::list_all(&db).await.unwrap().is_empty());

        AdminUser::create("a", "h", None, &db).await.unwrap();
        AdminUser::create("b", "h", None, &db).await.unwrap();
        let all = AdminUser::list_all(&db).await.unwrap();
        assert_eq!(all.len(), 2);
        // Two users created in the same second tie on `created_at`, so the
        // `id ASC` tiebreak decides -- and since `sqlite::id::mint` is a UUID
        // v7, whose leading 48 bits are a millisecond timestamp, that tiebreak
        // is insertion order. It used to be a random UUID, so this assertion
        // failed one run in two and the test sorted the names before making it.
        //
        // Only for rows minted since that change: nothing was backfilled, so a
        // v4 still ties arbitrarily against a v7 in the same second, for ever.
        let names: Vec<&str> = all.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, ["a", "b"], "the v7 tiebreak is insertion order");
    }

    /// The window `admin user list` hands down. Both facts a page needs: the
    /// rows it holds, and the total it is a page *of*.
    #[tokio::test]
    async fn search_pages_without_overlap_and_reports_the_unpaged_total() {
        let db = db().await;
        assert_eq!(AdminUser::search(50, 0, &db).await.unwrap().1, 0);

        for name in ["a", "b", "c", "d", "e"] {
            AdminUser::create(name, "h", None, &db).await.unwrap();
        }

        let (first, total) = AdminUser::search(2, 0, &db).await.unwrap();
        let (second, also_total) = AdminUser::search(2, 2, &db).await.unwrap();
        let (third, _) = AdminUser::search(2, 4, &db).await.unwrap();

        assert_eq!((total, also_total), (5, 5), "the total is the table");
        assert_eq!((first.len(), second.len(), third.len()), (2, 2, 1));

        // Walked end to end the pages are the table exactly once, which is both
        // "no overlap" and "nothing skipped" in one assertion -- and in the
        // creation order the `id` tiebreak preserves, since all five tie on
        // `created_at`.
        let walked: Vec<&str> = first
            .iter()
            .chain(second.iter())
            .chain(third.iter())
            .map(|user| user.username.as_str())
            .collect();
        assert_eq!(walked, ["a", "b", "c", "d", "e"]);
    }

    /// Oldest first, and the only listing in the binary that is: the bootstrap
    /// operator is the row whose position should not move as colleagues are
    /// added.
    #[tokio::test]
    async fn search_reads_the_table_in_the_same_order_as_the_scan() {
        let db = db().await;
        for name in ["a", "b", "c"] {
            AdminUser::create(name, "h", None, &db).await.unwrap();
        }

        let scanned: Vec<String> = AdminUser::list_all(&db)
            .await
            .unwrap()
            .into_iter()
            .map(|user| user.username)
            .collect();
        let paged: Vec<String> = AdminUser::search(50, 0, &db)
            .await
            .unwrap()
            .0
            .into_iter()
            .map(|user| user.username)
            .collect();
        assert_eq!(paged, scanned);
    }

    #[tokio::test]
    async fn list_all_orders_oldest_first() {
        let db = db().await;
        let older = AdminUser::create("older", "h", None, &db).await.unwrap();
        let newer = AdminUser::create("newer", "h", None, &db).await.unwrap();
        // Backdate one so the two no longer tie and `created_at ASC` is what
        // decides, rather than the UUID tiebreak.
        sqlx::query("UPDATE admin_users SET created_at = ? WHERE id = ?;")
            .bind(older.created_at - 60)
            .bind(older.id)
            .execute(&db.pool)
            .await
            .unwrap();

        let all = AdminUser::list_all(&db).await.unwrap();
        assert_eq!(all[0].id, older.id);
        assert_eq!(all[1].id, newer.id);
    }

    #[tokio::test]
    async fn set_password_hash_persists_and_syncs_in_memory() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "old", None, &db).await.unwrap();
        user.set_password_hash("new", &db).await.unwrap();
        assert_eq!(user.password_hash, "new");

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.password_hash, "new");
    }

    #[tokio::test]
    async fn set_status_persists_and_disables() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        user.set_status("disabled", &db).await.unwrap();
        assert!(!user.is_active());

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert!(!reloaded.is_active());
    }

    #[test]
    fn admin_role_maps_storage_both_ways() {
        // NULL and "admin" are the full tier; every unknown value is the
        // least-privilege one, the fail-closed direction.
        assert_eq!(AdminRole::from_storage(None), AdminRole::Admin);
        assert_eq!(AdminRole::from_storage(Some("admin")), AdminRole::Admin);
        assert_eq!(
            AdminRole::from_storage(Some("operator")),
            AdminRole::Operator
        );
        assert_eq!(AdminRole::from_storage(Some("viewer")), AdminRole::Viewer);
        assert_eq!(AdminRole::from_storage(Some("root")), AdminRole::Viewer);
        assert_eq!(AdminRole::from_storage(Some("")), AdminRole::Viewer);

        for role in AdminRole::ALL {
            assert_eq!(
                AdminRole::from_storage(Some(role.as_str())),
                *role,
                "as_str and from_storage must round-trip"
            );
        }

        // Declared low to high, so `>=` is a usable gate.
        assert!(AdminRole::Viewer < AdminRole::Operator);
        assert!(AdminRole::Operator < AdminRole::Admin);
    }

    #[test]
    fn admin_role_from_str_refuses_an_unknown_value_by_name() {
        assert_eq!("operator".parse::<AdminRole>(), Ok(AdminRole::Operator));
        let error = "supervisor".parse::<AdminRole>().unwrap_err();
        assert!(error.contains("supervisor"), "{error}");
        assert!(error.contains("viewer, operator, admin"), "{error}");
    }

    #[tokio::test]
    async fn a_row_with_no_role_reads_as_admin() {
        let db = db().await;
        let user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        assert_eq!(user.role, None);
        assert_eq!(user.role(), AdminRole::Admin);

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.role, None);
        assert_eq!(reloaded.role(), AdminRole::Admin);
    }

    #[tokio::test]
    async fn set_role_persists_and_syncs_in_memory() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();

        user.set_role(AdminRole::Viewer, &db).await.unwrap();
        assert_eq!(user.role(), AdminRole::Viewer);

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.role.as_deref(), Some("viewer"));
        assert_eq!(reloaded.role(), AdminRole::Viewer);

        user.set_role(AdminRole::Operator, &db).await.unwrap();
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.role(), AdminRole::Operator);
    }

    #[tokio::test]
    async fn the_totp_setters_persist_and_sync_in_memory() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();

        user.set_totp_pending(b"secret-bytes", &db).await.unwrap();
        assert!(user.has_pending_totp());
        assert!(
            !user.has_totp(),
            "a pending enrolment must not read as a second factor"
        );
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(
            reloaded.totp_pending_secret.as_deref(),
            Some(&b"secret-bytes"[..])
        );
        assert!(!reloaded.has_totp());

        user.confirm_totp(&db).await.unwrap();
        assert!(user.has_totp());
        assert!(!user.has_pending_totp());
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.totp_secret.as_deref(), Some(&b"secret-bytes"[..]));
        assert_eq!(reloaded.totp_pending_secret, None);

        user.clear_totp(&db).await.unwrap();
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.totp_secret, None);
        assert_eq!(reloaded.totp_pending_secret, None);
        assert_eq!(reloaded.totp_last_step, None);
    }

    /// A double-submit of the confirm form must not clear a live factor by
    /// promoting a pending column that is already empty.
    #[tokio::test]
    async fn confirming_with_nothing_pending_leaves_a_live_factor_alone() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        user.set_totp_pending(b"live", &db).await.unwrap();
        user.confirm_totp(&db).await.unwrap();

        user.confirm_totp(&db).await.unwrap();

        assert!(user.has_totp());
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.totp_secret.as_deref(), Some(&b"live"[..]));
    }

    /// RFC 6238 §5.2's replay guard, and the reason the comparison is in SQL:
    /// two requests carrying one code must not both be accepted.
    #[tokio::test]
    async fn claim_totp_step_refuses_a_step_it_has_already_seen() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();

        assert!(user.claim_totp_step(100, &db).await.unwrap());
        assert_eq!(user.totp_last_step, Some(100));

        // The same step, and any earlier one, are spent.
        assert!(!user.claim_totp_step(100, &db).await.unwrap());
        assert!(!user.claim_totp_step(99, &db).await.unwrap());
        assert_eq!(
            user.totp_last_step,
            Some(100),
            "a refused claim must not move the guard"
        );

        // Strictly newer advances it, and persists.
        assert!(user.claim_totp_step(101, &db).await.unwrap());
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.totp_last_step, Some(101));
    }

    #[tokio::test]
    async fn the_status_check_refuses_a_value_outside_the_schema() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        assert!(user.set_status("banished", &db).await.is_err());
    }

    #[tokio::test]
    async fn mark_logged_in_stamps_last_login_at() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        user.mark_logged_in(None, &db).await.unwrap();
        assert!(user.last_login_at.is_some());

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.last_login_at, user.last_login_at);
        assert!(
            reloaded.known_login_ips.is_empty(),
            "no address was supplied"
        );
    }

    #[tokio::test]
    async fn mark_logged_in_keeps_a_capped_move_to_front_address_set() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();

        // Fill past the cap; the newest address is always at the front.
        for n in 0..KNOWN_LOGIN_IPS + 2 {
            user.mark_logged_in(Some(&format!("10.0.0.{n}")), &db)
                .await
                .unwrap();
        }
        assert_eq!(user.known_login_ips.len(), KNOWN_LOGIN_IPS);
        assert_eq!(
            user.known_login_ips[0],
            format!("10.0.0.{}", KNOWN_LOGIN_IPS + 1)
        );

        // A known address moves back to the front rather than being appended.
        let known = user.known_login_ips[3].clone();
        user.mark_logged_in(Some(&known), &db).await.unwrap();
        assert_eq!(user.known_login_ips.len(), KNOWN_LOGIN_IPS);
        assert_eq!(user.known_login_ips[0], known);
        assert_eq!(
            user.known_login_ips
                .iter()
                .filter(|ip| **ip == known)
                .count(),
            1,
            "deduplicated"
        );

        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.known_login_ips, user.known_login_ips);
    }

    #[tokio::test]
    async fn set_contact_email_persists_and_syncs_and_clears() {
        let db = db().await;
        let mut user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        assert_eq!(user.contact_email, None);

        user.set_contact_email(Some("alice@example.com"), &db)
            .await
            .unwrap();
        assert_eq!(user.contact_email.as_deref(), Some("alice@example.com"));
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.contact_email.as_deref(), Some("alice@example.com"));

        user.set_contact_email(None, &db).await.unwrap();
        assert_eq!(user.contact_email, None);
        let reloaded = AdminUser::find_by_id(user.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.contact_email, None);
    }

    #[tokio::test]
    async fn delete_reports_whether_a_row_existed() {
        let db = db().await;
        let user = AdminUser::create("alice", "h", None, &db).await.unwrap();
        assert!(AdminUser::delete(user.id, &db).await.unwrap());
        assert!(!AdminUser::delete(user.id, &db).await.unwrap());
    }

    #[tokio::test]
    async fn to_json_never_leaks_the_hash_or_the_totp_secret() {
        let db = db().await;
        let user = AdminUser::create("alice", "super-secret-hash", None, &db)
            .await
            .unwrap();
        let json = user.to_json();
        assert!(json.get("password_hash").is_none());
        assert!(json.get("passwordHash").is_none());
        assert!(json.get("totpSecret").is_none());
        assert!(!json.to_string().contains("super-secret-hash"));
        assert_eq!(json["username"], "alice");
        assert_eq!(json["status"], "active");
        assert_eq!(json["totpEnabled"], false);
        assert_eq!(json["lastLoginAt"], Value::Null);
        assert_eq!(json["contactEmail"], Value::Null);
        assert_eq!(json["knownLoginIps"], serde_json::json!([]));
    }
}
