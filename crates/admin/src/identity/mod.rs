//! Operators an external identity provider vouches for: OpenID Connect
//! ([`oidc`]) and LDAP / Active Directory ([`ldap`]), and what a sign-in
//! through either does to the `admin_users` table ([`provision`]).
//!
//! A provider answers one question -- *who is this, and which groups are they
//! in* -- as an [`ExternalIdentity`]. Everything after that is here, once, for
//! both kinds:
//!
//! - **The role is recomputed at every sign-in** from the groups
//!   ([`RoleMap::role_for`]), the highest one any group grants. No match is a
//!   refusal, not a viewer: a person the directory puts in no mapped group was
//!   not meant to have a panel at all. A known operator refused that way also
//!   loses every session they hold -- the sign-in is when this server learns
//!   they were removed, and a tab left open must not outlive it.
//! - **An identity is the provider's stable name for a person**
//!   (`auth_provider`, `external_id`), never the username. A rename at the
//!   provider renames the operator; a subject this server has never seen is a
//!   new operator.
//! - **Never a link to an existing operator.** A provisioned username already
//!   held -- by a local operator or by another provider's -- refuses the
//!   sign-in (`username_taken`). Linking by name would let whoever controls the
//!   provider take over the break-glass `admin` by naming somebody `admin`.
//! - **A disabled operator stays disabled**, whatever their groups say: the
//!   panel's `disable` is the lever for "this person, now", and a provider
//!   that re-enabled them on the next sign-in would make it decorative.
//! - **The last-admin guard holds** for a provider too: a sync that would
//!   demote the only admin refuses the sign-in rather than granting a role the
//!   provider no longer vouches for.
//!
//! The network calls happen inside the sign-in request, which ADR 0006 would
//! otherwise forbid; ADR 0015 argues why this one is acceptable (an
//! operator-chosen host, on the admin listener only, bounded by the provider's
//! `timeout_ms` and behind the login limiter).

mod http;
pub mod ldap;
pub mod oidc;

use std::collections::BTreeMap;
use std::sync::Arc;

use acme_proxy_core::config::{Config, RoleMapConfig};
use acme_proxy_net::http_client::Outbound;
use acme_proxy_store::admin_session::AdminSession;
use acme_proxy_store::admin_user::{AdminRole, AdminUser};
use acme_proxy_store::db::Database;

use crate::admin::changes::{self, OperatorTrail};
use crate::admin::users::{self, UserError};

/// Who a provider says somebody is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    /// `oidc:<name>` or `ldap:<name>` -- the `admin_users.auth_provider` value.
    pub provider: String,
    /// The provider's rename-proof name for the person.
    pub external_id: String,
    /// What the operator is called here, before normalisation.
    pub username: String,
    /// Every group the provider reported, as it reported them.
    pub groups: Vec<String>,
}

/// Why a sign-in through a provider was refused.
///
/// Every variant answers the client the same way a wrong password does; the
/// [`SignInError::reason`] is for the `admin_login_failed` line, and the
/// detail inside a variant for the log only.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    /// The provider could not be asked: unreachable, timed out, or answering
    /// something this server cannot read. This server's failure, not the
    /// person's.
    #[error("the identity provider could not be reached: {0}")]
    Unreachable(String),
    /// The provider answered, and the answer is no -- or is a token this
    /// server will not accept. `reason` names which.
    #[error("{reason}: {detail}")]
    Rejected {
        reason: &'static str,
        detail: String,
    },
    /// The person is in no group [`RoleMap`] maps.
    #[error("no configured group grants a role")]
    NoMatchingGroup,
    /// The provider's username is not one the panel can address.
    #[error("`{0}` is not a usable operator name")]
    InvalidUsername(String),
    /// The username is held by an operator this identity is not.
    #[error("`{0}` is already another operator's name")]
    UsernameTaken(String),
    /// Syncing the role would demote the only admin.
    #[error("{0}")]
    LastAdmin(String),
    /// The operator exists and is disabled.
    #[error("the operator is disabled")]
    Disabled,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl SignInError {
    /// The `reason` field of `admin_login_failed`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "provider_unreachable",
            Self::Rejected { reason, .. } => reason,
            Self::NoMatchingGroup => "no_matching_group",
            Self::InvalidUsername(_) => "invalid_username",
            Self::UsernameTaken(_) => "username_taken",
            Self::LastAdmin(_) => "last_admin",
            Self::Disabled => "account_disabled",
            Self::Database(_) => "database_error",
        }
    }

    fn rejected(reason: &'static str, detail: impl Into<String>) -> Self {
        Self::Rejected {
            reason,
            detail: detail.into(),
        }
    }
}

/// `[admin.auth.*.<name>.roles]`, normalised for comparison.
#[derive(Debug, Clone, Default)]
pub struct RoleMap {
    /// Highest role first, so the first match is the answer.
    grants: Vec<(AdminRole, Vec<String>)>,
}

impl RoleMap {
    #[must_use]
    pub fn from_config(config: &RoleMapConfig) -> Self {
        let normalise = |groups: &[String]| -> Vec<String> {
            groups
                .iter()
                .map(|group| group.trim().to_lowercase())
                .collect()
        };
        Self {
            grants: vec![
                (AdminRole::Admin, normalise(&config.admin)),
                (AdminRole::Operator, normalise(&config.operator)),
                (AdminRole::Viewer, normalise(&config.viewer)),
            ],
        }
    }

    /// The highest role any of `groups` grants, or `None` when none does.
    /// Compared case-insensitively -- see `RoleMapConfig`.
    #[must_use]
    pub fn role_for(&self, groups: &[String]) -> Option<AdminRole> {
        let held: Vec<String> = groups
            .iter()
            .map(|group| group.trim().to_lowercase())
            .collect();
        self.grants
            .iter()
            .find(|(_, granted)| granted.iter().any(|group| held.contains(group)))
            .map(|(role, _)| *role)
    }
}

/// Every configured realm of one generation: built from `[admin.auth]` with
/// that generation's egress, and rebuilt by a reload like the rest of the
/// admin state. Constructing one contacts nothing.
#[derive(Default)]
pub struct Providers {
    /// `admin.auth.local`.
    pub local: bool,
    pub oidc: BTreeMap<String, Arc<oidc::OidcProvider>>,
    pub ldap: BTreeMap<String, Arc<ldap::LdapProvider>>,
}

impl Providers {
    /// Builds every provider `[admin.auth]` names, reading their secrets and
    /// CA files now so a missing one stops a startup or refuses a reload.
    pub fn from_config(config: &Config, outbound: &Outbound) -> anyhow::Result<Self> {
        let auth = &config.admin.auth;
        acme_proxy_core::config::validate_key_names("admin.auth.oidc", auth.oidc.keys())?;
        acme_proxy_core::config::validate_key_names("admin.auth.ldap", auth.ldap.keys())?;
        let oidc = auth
            .oidc
            .iter()
            .map(|(name, provider)| {
                Ok((
                    name.clone(),
                    Arc::new(oidc::OidcProvider::from_config(name, provider, outbound)?),
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        let ldap = auth
            .ldap
            .iter()
            .map(|(name, provider)| {
                Ok((
                    name.clone(),
                    Arc::new(ldap::LdapProvider::from_config(name, provider)?),
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            local: auth.local,
            oidc,
            ldap,
        })
    }
}

/// Reads a secret that may come from a file: `file` wins when set, trimmed of
/// trailing whitespace (an editor's newline is not part of a password) --
/// `signer.local_ca.pkcs11.pin_file`'s rule.
pub(crate) fn read_secret(inline: &str, file: &str, setting: &str) -> anyhow::Result<String> {
    if file.trim().is_empty() {
        return Ok(inline.to_string());
    }
    let contents = std::fs::read_to_string(file.trim())
        .map_err(|error| anyhow::anyhow!("{setting}: cannot read {}: {error}", file.trim()))?;
    Ok(contents.trim_end().to_string())
}

/// Whether `url` names this host -- the one place a provider may be reached
/// without TLS (`ldap://` without StartTLS, an `http://` issuer), because a
/// password or a client secret crossing it never leaves the machine.
pub(crate) fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        // A non-special scheme (`ldap://`) leaves even an address literal as
        // an opaque host, so the literal is recognised here too.
        Some(url::Host::Domain(name)) => {
            name.eq_ignore_ascii_case("localhost")
                || name
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        None => false,
    }
}

/// Finds or creates the operator `identity` names, at the role `roles` gives
/// their groups -- the half of a sign-in after the provider has answered.
///
/// Answers the operator as it now stands; the caller makes the session. Role
/// changes and creations are recorded through `trail`, whose actor is the
/// provider.
pub async fn provision(
    identity: &ExternalIdentity,
    roles: &RoleMap,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<AdminUser, SignInError> {
    let existing =
        AdminUser::find_by_external(&identity.provider, &identity.external_id, &database).await?;
    let Some(role) = roles.role_for(&identity.groups) else {
        if let Some(user) = &existing {
            deprovision(user, &identity.provider, &database, trail).await?;
        }
        return Err(SignInError::NoMatchingGroup);
    };

    let username = identity.username.trim().to_lowercase();
    if !users::valid_username(&username) {
        return Err(SignInError::InvalidUsername(username));
    }

    let Some(mut user) = existing else {
        return create(identity, &username, role, database, trail).await;
    };

    if !user.is_active() {
        return Err(SignInError::Disabled);
    }

    if user.username != username {
        // Renamed at the provider. The new name must be free, for the reason
        // creation refuses a taken one.
        if AdminUser::find_by_username(&username, &database)
            .await?
            .is_some()
        {
            return Err(SignInError::UsernameTaken(username));
        }
        user.rename(&username, &database)
            .await
            .map_err(|error| taken_or(error, &username))?;
    }

    if user.role() != role {
        let (synced, _) = changes::sync_role(user, role, database, trail)
            .await
            .map_err(|error| match error {
                UserError::Policy(message) => SignInError::LastAdmin(message),
                UserError::Database(error) => SignInError::Database(error),
                other => SignInError::Unreachable(other.to_string()),
            })?;
        tracing::info!(event = "admin_role_synced",
                       outcome = "success",
                       username = %synced.username,
                       provider = %identity.provider,
                       role = %role);
        user = synced;
    }
    Ok(user)
}

async fn create(
    identity: &ExternalIdentity,
    username: &str,
    role: AdminRole,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<AdminUser, SignInError> {
    if AdminUser::find_by_username(username, &database)
        .await?
        .is_some()
    {
        return Err(SignInError::UsernameTaken(username.to_string()));
    }
    let user = AdminUser::create_external(
        username,
        role,
        &identity.provider,
        &identity.external_id,
        &database,
    )
    .await
    // Lost a race: another sign-in took the name, or provisioned this very
    // person a moment ago. Either way this one does not get a second row.
    .map_err(|error| taken_or(error, username))?;

    trail
        .record(|actor, client| {
            acme_proxy_jobs::auditor::admin::operator_created(
                actor,
                client,
                &user.username,
                role.as_str(),
            )
        })
        .await;
    tracing::info!(event = "admin_user_provisioned",
                   outcome = "success",
                   username = %user.username,
                   provider = %identity.provider,
                   role = %role);
    Ok(user)
}

/// Ends every session of an operator their provider no longer puts in any
/// mapped group. Their role is only re-read at a sign-in, so this sign-in is
/// the one moment this server learns they were removed: a tab still open from
/// before must not outlive the news. The row stays (the panel's `delete` is
/// the operator's to pull); the next sign-in is refused like this one.
async fn deprovision(
    user: &AdminUser,
    provider: &str,
    database: &Database,
    trail: &impl OperatorTrail,
) -> Result<(), SignInError> {
    let revoked = AdminSession::delete_for_user(user.id, database).await?;
    changes::record_revoked(user, revoked, trail).await;
    tracing::warn!(event = "admin_user_deprovisioned",
                   outcome = "success",
                   username = %user.username,
                   provider = %provider,
                   rows_removed = revoked);
    Ok(())
}

fn taken_or(error: sqlx::Error, username: &str) -> SignInError {
    if acme_proxy_store::sql::is_unique_violation(&error) {
        SignInError::UsernameTaken(username.to_string())
    } else {
        SignInError::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::audit::{Actor, AuditRecord, ClientContext};
    use acme_proxy_jobs::notify::AdminCredentialChange;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<String>>,
    }

    impl OperatorTrail for Recording {
        async fn record(&self, build: impl FnOnce(Actor, ClientContext) -> AuditRecord + Send) {
            let record = build(Actor::system(), ClientContext::default());
            self.events
                .lock()
                .unwrap()
                .push(record.event.as_str().to_string());
        }

        async fn notify(&self, _: &AdminUser, _: AdminCredentialChange, _: Option<String>) {}
    }

    fn roles() -> RoleMap {
        RoleMap::from_config(&RoleMapConfig {
            admin: vec!["CN=Admins,DC=example".to_string()],
            operator: vec!["operators".to_string()],
            viewer: vec!["staff".to_string()],
        })
    }

    fn identity(username: &str, groups: &[&str]) -> ExternalIdentity {
        ExternalIdentity {
            provider: "oidc:corp".to_string(),
            external_id: "https://idp.example sub-1".to_string(),
            username: username.to_string(),
            groups: groups.iter().map(ToString::to_string).collect(),
        }
    }

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_for_test().await.unwrap())
    }

    #[test]
    fn the_highest_granted_role_wins_case_insensitively() {
        let roles = roles();
        let groups = |names: &[&str]| names.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(roles.role_for(&groups(&["staff"])), Some(AdminRole::Viewer));
        assert_eq!(
            roles.role_for(&groups(&["staff", "OPERATORS"])),
            Some(AdminRole::Operator)
        );
        assert_eq!(
            roles.role_for(&groups(&["cn=admins,dc=example", "staff"])),
            Some(AdminRole::Admin)
        );
        assert_eq!(roles.role_for(&groups(&["nobody"])), None);
        assert_eq!(roles.role_for(&[]), None);
    }

    #[tokio::test]
    async fn a_first_sign_in_provisions_at_the_mapped_role() {
        let database = db().await;
        let trail = Recording::default();
        let user = provision(
            &identity("Bob@Example.com", &["operators"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        assert_eq!(user.username, "bob@example.com");
        assert_eq!(user.role(), AdminRole::Operator);
        assert_eq!(user.auth_provider.as_deref(), Some("oidc:corp"));
        assert_eq!(*trail.events.lock().unwrap(), vec!["operator_created"]);

        // The same person again: the same row, nothing recorded.
        let again = provision(
            &identity("bob@example.com", &["operators"]),
            &roles(),
            database,
            &trail,
        )
        .await
        .unwrap();
        assert_eq!(again.id, user.id);
        assert_eq!(trail.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_role_follows_the_groups_at_every_sign_in() {
        let database = db().await;
        // Somebody else holds `admin`, so demoting bob is not the last-admin case.
        AdminUser::create("root", "h", None, &database)
            .await
            .unwrap();
        let trail = Recording::default();
        provision(
            &identity("bob", &["CN=Admins,DC=example"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        let demoted = provision(
            &identity("bob", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        assert_eq!(demoted.role(), AdminRole::Viewer);
        assert_eq!(
            *trail.events.lock().unwrap(),
            vec!["operator_created", "operator_role_changed"]
        );

        let refused = provision(
            &identity("bob", &["contractors"]),
            &roles(),
            database,
            &trail,
        )
        .await;
        assert!(matches!(refused, Err(SignInError::NoMatchingGroup)));
    }

    /// Removed from every mapped group: the sign-in is refused, and the
    /// sessions they already held end with it.
    #[tokio::test]
    async fn losing_every_group_ends_the_operators_sessions() {
        use acme_proxy_store::admin_session::NewSession;

        let database = db().await;
        let trail = Recording::default();
        let user = provision(
            &identity("bob", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: "token",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(3600),
            &database,
        )
        .await
        .unwrap();

        let refused = provision(
            &identity("bob", &["contractors"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await;
        assert!(matches!(refused, Err(SignInError::NoMatchingGroup)));
        assert_eq!(
            AdminSession::delete_for_user(user.id, &database)
                .await
                .unwrap(),
            0,
            "the refusal already ended every session"
        );
        assert_eq!(
            *trail.events.lock().unwrap(),
            vec!["operator_created", "session_revoked"]
        );

        // A stranger in no group has nothing to revoke and records nothing.
        let mut stranger = identity("carol", &["contractors"]);
        stranger.external_id = "https://idp.example sub-9".to_string();
        assert!(matches!(
            provision(&stranger, &roles(), database, &trail).await,
            Err(SignInError::NoMatchingGroup)
        ));
        assert_eq!(trail.events.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_taken_username_is_refused_never_linked() {
        let database = db().await;
        let local = AdminUser::create("admin", "h", None, &database)
            .await
            .unwrap();
        let trail = Recording::default();
        let refused = provision(
            &identity("admin", &["CN=Admins,DC=example"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await;
        assert!(matches!(refused, Err(SignInError::UsernameTaken(name)) if name == "admin"));
        let untouched = AdminUser::find_by_username("admin", &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(untouched.id, local.id);
        assert!(!untouched.is_external());

        // Another provider's operator holds the name too.
        let mut other = identity("carol", &["staff"]);
        other.provider = "ldap:ad".to_string();
        provision(&other, &roles(), database.clone(), &trail)
            .await
            .unwrap();
        let mut clash = identity("carol", &["staff"]);
        clash.external_id = "https://idp.example sub-2".to_string();
        assert!(matches!(
            provision(&clash, &roles(), database, &trail).await,
            Err(SignInError::UsernameTaken(_))
        ));
    }

    #[tokio::test]
    async fn a_rename_at_the_provider_renames_the_operator_when_free() {
        let database = db().await;
        let trail = Recording::default();
        let first = provision(
            &identity("bob", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        let renamed = provision(
            &identity("robert", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        assert_eq!(renamed.id, first.id);
        assert_eq!(renamed.username, "robert");

        AdminUser::create("alice", "h", None, &database)
            .await
            .unwrap();
        assert!(matches!(
            provision(&identity("alice", &["staff"]), &roles(), database, &trail).await,
            Err(SignInError::UsernameTaken(_))
        ));
    }

    #[tokio::test]
    async fn a_disabled_operator_stays_disabled_and_a_bad_name_is_refused() {
        let database = db().await;
        let trail = Recording::default();
        let user = provision(
            &identity("bob", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        users::set_status(
            &user.username,
            acme_proxy_store::admin_user::AdminStatus::Disabled,
            database.clone(),
        )
        .await
        .unwrap();
        assert!(matches!(
            provision(
                &identity("bob", &["CN=Admins,DC=example"]),
                &roles(),
                database.clone(),
                &trail
            )
            .await,
            Err(SignInError::Disabled)
        ));

        let mut odd = identity("bob smith/x", &["staff"]);
        odd.external_id = "other".to_string();
        assert!(matches!(
            provision(&odd, &roles(), database, &trail).await,
            Err(SignInError::InvalidUsername(_))
        ));
    }

    /// The only admin, demoted by their groups, is refused the sign-in rather
    /// than kept at a role the provider no longer grants.
    #[tokio::test]
    async fn demoting_the_last_admin_refuses_the_sign_in() {
        let database = db().await;
        let trail = Recording::default();
        provision(
            &identity("bob", &["CN=Admins,DC=example"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap();
        let refused = provision(
            &identity("bob", &["staff"]),
            &roles(),
            database.clone(),
            &trail,
        )
        .await;
        assert!(matches!(refused, Err(SignInError::LastAdmin(_))));
        assert_eq!(refused.unwrap_err().reason(), "last_admin");
        let still = AdminUser::find_by_username("bob", &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still.role(), AdminRole::Admin);
    }

    #[test]
    fn only_loopback_may_go_without_tls() {
        for (url, loopback) in [
            ("ldap://127.0.0.1", true),
            ("ldap://[::1]:389", true),
            ("http://LOCALHOST:8080", true),
            ("ldap://dc1.example.com", false),
            ("http://10.0.0.1", false),
        ] {
            assert_eq!(
                is_loopback(&url::Url::parse(url).unwrap()),
                loopback,
                "{url}"
            );
        }
    }

    #[test]
    fn a_secret_file_wins_and_is_trimmed() {
        let dir = acme_proxy_core::testutil::TempDir::new("identity-secret");
        let path = dir.path().join("secret");
        std::fs::write(&path, "from-file\n").unwrap();
        let file = path.to_str().unwrap();
        assert_eq!(read_secret("inline", file, "k").unwrap(), "from-file");
        assert_eq!(read_secret("inline", "", "k").unwrap(), "inline");
        let missing = read_secret(
            "inline",
            "/nonexistent/secret",
            "admin.auth.ldap.ad.bind_password_file",
        )
        .unwrap_err()
        .to_string();
        assert!(
            missing.starts_with("admin.auth.ldap.ad.bind_password_file"),
            "{missing}"
        );
    }

    #[test]
    fn every_refusal_has_a_reason() {
        let reasons = [
            SignInError::Unreachable("x".into()).reason(),
            SignInError::rejected("wrong_password", "x").reason(),
            SignInError::NoMatchingGroup.reason(),
            SignInError::InvalidUsername("x".into()).reason(),
            SignInError::UsernameTaken("x".into()).reason(),
            SignInError::LastAdmin("x".into()).reason(),
            SignInError::Disabled.reason(),
        ];
        assert_eq!(
            reasons,
            [
                "provider_unreachable",
                "wrong_password",
                "no_matching_group",
                "invalid_username",
                "username_taken",
                "last_admin",
                "account_disabled"
            ]
        );
    }
}
