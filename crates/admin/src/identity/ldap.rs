//! One LDAP directory (Active Directory included) as a password realm:
//! a service account finds the person, a bind as them checks the password,
//! and their groups pick the role.
//!
//! On `ldap3`, the one identity dependency that is not hand-rolled (ADR 0015:
//! LDAP's encoding and Active Directory's quirks are a library's job). Its TLS
//! is **ours**: every connection is given [`LdapProvider`]'s own `ring`
//! `ClientConfig` through `set_config`, because `ldap3`'s fallback builds one
//! from the process-default provider, which this tree never installs
//! (`a_connection_never_installs_a_process_crypto_provider`).
//!
//! The order of an exchange, and why:
//!
//! 1. **An empty password is refused before anything is sent.** A simple bind
//!    with a DN and no password is an *unauthenticated* bind (RFC 4513 §5.1.2),
//!    which many directories answer with success.
//! 2. The service account binds and searches `user_base_dn` with `user_filter`,
//!    the typed name escaped (RFC 4515) -- reading the person's name, stable id
//!    and groups in the same search. Exactly one entry must match: none is an
//!    unknown user, several is a filter that does not identify people.
//! 3. With `group_search_base`, the groups are a second search, still as the
//!    service account (a person may not be allowed to read groups).
//! 4. Last, a bind **as the person** with the typed password -- the only step
//!    that proves anything.

use std::sync::Arc;
use std::time::Duration;

use acme_proxy_core::config::LdapProviderConfig;
use ldap3::{LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry, ldap_escape};

use super::{ExternalIdentity, RoleMap, SignInError, read_secret};

/// The LDAP result code for a refused simple bind (RFC 4511 appendix A).
const INVALID_CREDENTIALS: u32 = 49;

/// Active Directory's `LDAP_MATCHING_RULE_IN_CHAIN`: membership through
/// nested groups, evaluated by the directory.
const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// One `[admin.auth.ldap.<name>]`.
pub struct LdapProvider {
    pub name: String,
    pub display_name: String,
    config: LdapProviderConfig,
    bind_password: String,
    pub roles: RoleMap,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl std::fmt::Debug for LdapProvider {
    /// Never renders the service account's password.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LdapProvider")
            .field("name", &self.name)
            .field("url", &self.config.url)
            .finish_non_exhaustive()
    }
}

impl LdapProvider {
    /// Builds the provider from its section, reading the bind password and
    /// the CA file now. Contacts nothing.
    pub fn from_config(name: &str, config: &LdapProviderConfig) -> anyhow::Result<Self> {
        let key = format!("admin.auth.ldap.{name}");
        let bind_password = read_secret(
            &config.bind_password,
            &config.bind_password_file,
            &format!("{key}.bind_password_file"),
        )?;
        let tls = acme_proxy_net::http_client::webpki_tls_config_with_ca(
            &config.ca_cert_path,
            &format!("{key}.ca_cert_path"),
        )?;
        Ok(Self {
            name: name.to_string(),
            display_name: if config.display_name.trim().is_empty() {
                name.to_string()
            } else {
                config.display_name.clone()
            },
            config: config.clone(),
            bind_password,
            roles: RoleMap::from_config(&config.roles),
            tls: Arc::new(tls),
            timeout: Duration::from_millis(config.timeout_ms),
        })
    }

    /// `ldap:<name>`, the `admin_users.auth_provider` value.
    #[must_use]
    pub fn key(&self) -> String {
        format!("ldap:{}", self.name)
    }

    /// Checks `username` and `password` against the directory, answering who
    /// they are. The whole exchange is bounded by `timeout_ms`.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ExternalIdentity, SignInError> {
        if password.is_empty() || username.trim().is_empty() {
            return Err(SignInError::rejected(
                "wrong_password",
                "an empty username or password is never sent to a directory",
            ));
        }
        match tokio::time::timeout(self.timeout, self.exchange(username.trim(), password)).await {
            Ok(result) => result,
            Err(_) => Err(SignInError::Unreachable(format!(
                "{}: no answer within {} ms",
                self.config.url,
                self.timeout.as_millis()
            ))),
        }
    }

    async fn exchange(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ExternalIdentity, SignInError> {
        let settings = LdapConnSettings::new()
            .set_config(self.tls.clone())
            .set_starttls(self.config.start_tls)
            .set_conn_timeout(self.timeout);
        let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|error| self.unreachable(&error))?;
        ldap3::drive!(connection);

        ldap.simple_bind(&self.config.bind_dn, &self.bind_password)
            .await
            .and_then(ldap3::LdapResult::success)
            .map_err(|error| self.unreachable(&error))?;

        let filter = self
            .config
            .user_filter
            .replace("{username}", &ldap_escape(username));
        let mut attributes = vec![
            self.config.username_attribute.as_str(),
            self.config.group_attribute.as_str(),
        ];
        if !self.config.id_attribute.is_empty() {
            attributes.push(self.config.id_attribute.as_str());
        }
        let (entries, _) = ldap
            .search(
                &self.config.user_base_dn,
                Scope::Subtree,
                &filter,
                attributes,
            )
            .await
            .and_then(ldap3::SearchResult::success)
            .map_err(|error| self.unreachable(&error))?;
        let mut people = entries
            .into_iter()
            .filter(|entry| !entry.is_ref() && !entry.is_intermediate())
            .map(SearchEntry::construct);
        let (Some(person), None) = (people.next(), people.next()) else {
            let _ = ldap.unbind().await;
            return Err(SignInError::rejected(
                "unknown_user",
                format!(
                    "`{filter}` under `{}` matched no single entry",
                    self.config.user_base_dn
                ),
            ));
        };

        let groups = if self.config.group_search_base.is_empty() {
            first_values(&person, &self.config.group_attribute)
        } else {
            let filter = self.group_filter(&person.dn);
            let (entries, _) = ldap
                .search(
                    &self.config.group_search_base,
                    Scope::Subtree,
                    &filter,
                    vec!["1.1"],
                )
                .await
                .and_then(ldap3::SearchResult::success)
                .map_err(|error| self.unreachable(&error))?;
            entries
                .into_iter()
                .filter(|entry| !entry.is_ref() && !entry.is_intermediate())
                .map(|entry| SearchEntry::construct(entry).dn)
                .collect()
        };

        let verdict = ldap
            .simple_bind(&person.dn, password)
            .await
            .and_then(ldap3::LdapResult::success);
        let _ = ldap.unbind().await;
        match verdict {
            Ok(_) => {}
            Err(LdapError::LdapResult { result }) if result.rc == INVALID_CREDENTIALS => {
                return Err(SignInError::rejected(
                    "wrong_password",
                    format!("bind as `{}` refused", person.dn),
                ));
            }
            Err(error) => return Err(self.unreachable(&error)),
        }

        let username = first_values(&person, &self.config.username_attribute)
            .into_iter()
            .next()
            .unwrap_or_else(|| username.to_string());
        Ok(ExternalIdentity {
            provider: self.key(),
            external_id: stable_id(&person, &self.config.id_attribute),
            username,
            groups,
        })
    }

    /// The group search: `group_filter` with the person's DN, or AD's in-chain
    /// rule when `nested_groups` asks for membership through other groups.
    fn group_filter(&self, dn: &str) -> String {
        let dn = ldap_escape(dn);
        if self.config.nested_groups {
            format!("(member:{IN_CHAIN}:={dn})")
        } else {
            self.config.group_filter.replace("{dn}", &dn)
        }
    }

    fn unreachable(&self, error: &LdapError) -> SignInError {
        SignInError::Unreachable(format!("{}: {error}", self.config.url))
    }
}

/// Every value of `attribute` on `entry`, case-insensitively by name -- a
/// directory answers with its own spelling of the attribute.
fn first_values(entry: &SearchEntry, attribute: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .map(|(_, values)| values.clone())
        .unwrap_or_default()
}

/// The person's rename-proof id: `id_attribute`'s value -- as text, or hex for
/// a binary one such as `objectGUID` -- or the DN when there is none.
fn stable_id(entry: &SearchEntry, id_attribute: &str) -> String {
    if !id_attribute.is_empty() {
        if let Some(value) = first_values(entry, id_attribute).into_iter().next() {
            return value;
        }
        if let Some(value) = entry
            .bin_attrs
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(id_attribute))
            .and_then(|(_, values)| values.first())
        {
            return hex::encode(value);
        }
    }
    entry.dn.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(dn: &str, attrs: &[(&str, &[&str])], bin: &[(&str, &[u8])]) -> SearchEntry {
        SearchEntry {
            dn: dn.to_string(),
            attrs: attrs
                .iter()
                .map(|(name, values)| {
                    (
                        name.to_string(),
                        values.iter().map(ToString::to_string).collect(),
                    )
                })
                .collect::<HashMap<_, _>>(),
            bin_attrs: bin
                .iter()
                .map(|(name, value)| (name.to_string(), vec![value.to_vec()]))
                .collect::<HashMap<_, _>>(),
        }
    }

    fn provider(config: LdapProviderConfig) -> LdapProvider {
        LdapProvider::from_config("ad", &config).unwrap()
    }

    #[test]
    fn the_stable_id_is_text_hex_or_the_dn() {
        let person = entry(
            "CN=Bob,DC=example",
            &[("entryUUID", &["5f3c"])],
            &[("objectGUID", &[0xde, 0xad])],
        );
        assert_eq!(stable_id(&person, "entryuuid"), "5f3c");
        assert_eq!(stable_id(&person, "objectGUID"), "dead");
        assert_eq!(stable_id(&person, "absent"), "cn=bob,dc=example");
        assert_eq!(stable_id(&person, ""), "cn=bob,dc=example");
    }

    #[test]
    fn attributes_are_matched_case_insensitively() {
        let person = entry("cn=bob", &[("memberOf", &["cn=a", "cn=b"])], &[]);
        assert_eq!(first_values(&person, "memberof"), vec!["cn=a", "cn=b"]);
        assert!(first_values(&person, "uid").is_empty());
    }

    /// The DN is escaped into the group filter (RFC 4515), and `nested_groups`
    /// swaps in Active Directory's in-chain rule.
    #[test]
    fn the_group_filter_escapes_the_dn() {
        let flat = provider(LdapProviderConfig::default());
        assert_eq!(
            flat.group_filter("cn=Bob (IT),dc=example"),
            "(member=cn=Bob \\28IT\\29,dc=example)"
        );
        let nested = provider(LdapProviderConfig {
            nested_groups: true,
            ..LdapProviderConfig::default()
        });
        assert_eq!(
            nested.group_filter("cn=bob*"),
            "(member:1.2.840.113556.1.4.1941:=cn=bob\\2a)"
        );
    }

    /// A simple bind with no password is an unauthenticated bind that many
    /// directories accept: refused before any connection, so `url` is never
    /// even parsed here.
    #[tokio::test]
    async fn an_empty_password_is_refused_without_a_connection() {
        let directory = provider(LdapProviderConfig {
            url: "ldaps://unreachable.invalid".to_string(),
            ..LdapProviderConfig::default()
        });
        for (username, password) in [("bob", ""), ("  ", "secret")] {
            let refused = directory
                .authenticate(username, password)
                .await
                .unwrap_err();
            assert_eq!(refused.reason(), "wrong_password");
        }
    }

    #[test]
    fn debug_never_renders_the_bind_password() {
        let directory = provider(LdapProviderConfig {
            bind_password: "hunter2".to_string(),
            ..LdapProviderConfig::default()
        });
        assert!(!format!("{directory:?}").contains("hunter2"));
        assert_eq!(directory.key(), "ldap:ad");
        assert_eq!(directory.display_name, "ad");
    }
}
