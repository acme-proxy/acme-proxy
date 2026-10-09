//! `[admin.auth]` -- who may sign in to the web admin, and who vouches for
//! them: the local password realm, OpenID Connect providers, LDAP directories.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule. What each key means for an operator is
//! `doc/src/operations/webadmin_sso.md`; the reasoning is ADR 0015.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::string_list;

/// The web admin's sign-in realms.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdminAuthConfig {
    /// Whether the password form's **local** realm -- operators created with
    /// `admin user create` -- accepts a sign-in. On by default; turning it off
    /// leaves the external providers as the only way in, so
    /// `webadmin::check_config` refuses it with none configured.
    pub local: bool,
    /// OpenID Connect providers, by name: each is a button on the sign-in
    /// page. A name must match `^[a-z0-9-]+$`.
    pub oidc: BTreeMap<String, OidcProviderConfig>,
    /// LDAP directories (Active Directory included), by name: each is a realm
    /// on the password form. A name must match `^[a-z0-9-]+$`.
    pub ldap: BTreeMap<String, LdapProviderConfig>,
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            local: true,
            oidc: BTreeMap::new(),
            ldap: BTreeMap::new(),
        }
    }
}

/// Which provider groups grant which role. Recomputed at every sign-in: the
/// highest role any of the person's groups names wins, and a person whose
/// groups name none is refused.
///
/// Group names compare **case-insensitively**: an LDAP DN's attribute names
/// and values are case-insensitive in every directory this targets, and a
/// mapping that missed `CN=Admins` for `cn=admins` would refuse an operator
/// for a spelling.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RoleMapConfig {
    #[serde(deserialize_with = "string_list")]
    pub admin: Vec<String>,
    #[serde(deserialize_with = "string_list")]
    pub operator: Vec<String>,
    #[serde(deserialize_with = "string_list")]
    pub viewer: Vec<String>,
}

impl RoleMapConfig {
    /// Whether no group grants anything -- a provider nobody could sign in
    /// through, which `webadmin::check_config` refuses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admin.is_empty() && self.operator.is_empty() && self.viewer.is_empty()
    }
}

/// One OpenID Connect provider (`[admin.auth.oidc.<name>]`), signed in to with
/// the authorization code flow and PKCE.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OidcProviderConfig {
    /// The button's label. Empty means the provider's name.
    pub display_name: String,
    /// The issuer identifier: `https://` (loopback excepted), and exactly what
    /// the provider's discovery document and ID tokens say -- the comparison is
    /// byte for byte, trailing slash included.
    pub issuer: String,
    pub client_id: String,
    /// The client secret. **Secret** -- prefer `client_secret_file` or the
    /// environment variable over writing it here.
    pub client_secret: String,
    /// A file holding the client secret, trailing whitespace trimmed. Wins over
    /// `client_secret` when both are set.
    pub client_secret_file: String,
    /// Scopes requested. `openid` is added if missing.
    #[serde(deserialize_with = "string_list")]
    pub scopes: Vec<String>,
    /// The ID-token claim the operator's username comes from.
    pub username_claim: String,
    /// The claim holding the groups [`OidcProviderConfig::roles`] maps. Entra
    /// ID app roles arrive in `roles`.
    pub groups_claim: String,
    /// Read the groups claim from the userinfo endpoint instead of the ID
    /// token, for a provider that keeps the token small.
    pub userinfo_groups: bool,
    /// Refuse a token whose `acr` is none of these. Empty accepts any.
    #[serde(deserialize_with = "string_list")]
    pub required_acr: Vec<String>,
    /// Refuse a token whose `amr` lacks any of these (e.g. `mfa`). Empty
    /// accepts any.
    #[serde(deserialize_with = "string_list")]
    pub required_amr: Vec<String>,
    /// Extra CA certificates (PEM) to trust on top of the public roots, for a
    /// provider behind an internal PKI.
    pub ca_cert_path: String,
    /// Bound on each call to the provider, in milliseconds.
    pub timeout_ms: u64,
    pub roles: RoleMapConfig,
}

impl Default for OidcProviderConfig {
    fn default() -> Self {
        Self {
            display_name: String::new(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            client_secret_file: String::new(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            username_claim: "preferred_username".to_string(),
            groups_claim: "groups".to_string(),
            userinfo_groups: false,
            required_acr: Vec::new(),
            required_amr: Vec::new(),
            ca_cert_path: String::new(),
            timeout_ms: 10_000,
            roles: RoleMapConfig::default(),
        }
    }
}

/// One LDAP directory (`[admin.auth.ldap.<name>]`): a service account finds
/// the person, a bind as them checks the password, and their groups pick the
/// role.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LdapProviderConfig {
    /// The realm's label on the password form. Empty means the name.
    pub display_name: String,
    /// `ldaps://host[:port]`, or `ldap://host[:port]` with `start_tls`. Plain
    /// `ldap://` without StartTLS is refused unless the host is loopback: the
    /// operator's password crosses this connection.
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS before anything is sent.
    pub start_tls: bool,
    /// Extra CA certificates (PEM) to trust on top of the public roots -- a
    /// directory's certificate is almost always from an internal CA.
    pub ca_cert_path: String,
    /// The service account that searches for the person. Empty binds
    /// anonymously for the search, which most directories refuse.
    pub bind_dn: String,
    /// The service account's password. **Secret** -- prefer
    /// `bind_password_file` or the environment variable.
    pub bind_password: String,
    /// A file holding the service account's password, trailing whitespace
    /// trimmed. Wins over `bind_password` when both are set.
    pub bind_password_file: String,
    /// Where people are searched for (subtree).
    pub user_base_dn: String,
    /// The search, with `{username}` replaced by the escaped (RFC 4515) name
    /// typed on the form. Exactly one entry must match.
    pub user_filter: String,
    /// The attribute the operator's username comes from.
    pub username_attribute: String,
    /// The attribute naming the person stably across renames: `entryUUID`
    /// (OpenLDAP), `objectGUID` (Active Directory). Empty uses the entry's DN.
    pub id_attribute: String,
    /// The attribute on the person's entry listing their groups' DNs.
    /// Ignored when `group_search_base` is set.
    pub group_attribute: String,
    /// Search for groups under this DN instead of reading `group_attribute`.
    pub group_search_base: String,
    /// The group search, with `{dn}` replaced by the escaped DN of the person.
    pub group_filter: String,
    /// Active Directory: count the groups a person is in through other groups
    /// too, with the `LDAP_MATCHING_RULE_IN_CHAIN` rule. Needs
    /// `group_search_base`.
    pub nested_groups: bool,
    /// Bound on the whole exchange with the directory, in milliseconds.
    pub timeout_ms: u64,
    pub roles: RoleMapConfig,
}

impl Default for LdapProviderConfig {
    fn default() -> Self {
        Self {
            display_name: String::new(),
            url: String::new(),
            start_tls: false,
            ca_cert_path: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            bind_password_file: String::new(),
            user_base_dn: String::new(),
            user_filter: "(uid={username})".to_string(),
            username_attribute: "uid".to_string(),
            id_attribute: "entryUUID".to_string(),
            group_attribute: "memberOf".to_string(),
            group_search_base: String::new(),
            group_filter: "(member={dn})".to_string(),
            nested_groups: false,
            timeout_ms: 5_000,
            roles: RoleMapConfig::default(),
        }
    }
}
