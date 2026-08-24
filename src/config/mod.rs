//! ACME Proxy Configuration Management

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

pub mod types;
pub use types::*;

/// Runtime configuration for the ACME proxy server.
///
/// The eight sections a profile can carry (`signer`, `filter`, `ipam`,
/// `challenge`, `eab`, `order`, `notify`, `meta`) are kept here as the **base
/// every profile inherits**; nothing serves them directly. The rest (`database`, `server`,
/// `admin`, `nonce`, `audit`, `jobs`, `logging`, `dns`, `proxy`) is process-wide and has no
/// per-profile form — an operator of the web admin manages every endpoint this process
/// serves, so `admin` in particular has no per-profile meaning, `audit`
/// records one trail for the whole CA, and `jobs` drains one queue.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    /// The web admin listener. Process-wide, so deliberately absent from
    /// [`PROFILE_SECTIONS`].
    pub admin: AdminConfig,
    pub nonce: NonceConfig,
    /// Traceability and the CA's audit trail. Process-wide for the reason
    /// [`AuditConfig`] gives, so also absent from [`PROFILE_SECTIONS`].
    pub audit: AuditConfig,
    /// The durable background-work queue. Process-wide for the reason
    /// [`JobsConfig`] gives, so also absent from [`PROFILE_SECTIONS`].
    pub jobs: JobsConfig,
    /// The Prometheus exposition endpoint. Process-wide for the reason
    /// [`MetricsConfig`] gives, so also absent from [`PROFILE_SECTIONS`].
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub order: OrderConfig,
    pub signer: SignerConfig,
    pub challenge: ChallengeConfig,
    pub filter: FilterConfig,
    /// The inventory the `ipam` filter consults. Per-profile, so two endpoints
    /// may consult different ones — and read by nothing unless that filter is
    /// enabled.
    pub ipam: IpamConfig,
    pub eab: EabConfig,
    pub notify: NotifyConfig,
    pub meta: MetaConfig,
    pub dns: DnsConfig,
    /// The forward proxy every outbound client dials through. Process-wide for
    /// the reason [`ProxyConfig`] gives, so also absent from
    /// [`PROFILE_SECTIONS`].
    pub proxy: ProxyConfig,
    /// The configuration sources as they were read, *before* serde filled in
    /// any default — the only form in which "unset" and "set to the default
    /// value" can still be told apart, which is what per-key inheritance
    /// needs. Populated by [`Config::load`]; `None` for a `Config` built in
    /// code (tests, `Config::default`), which simply has no profiles to
    /// resolve.
    #[serde(skip)]
    raw: Option<::config::Config>,
}

/// The sections a profile may override, in the order they are documented.
const PROFILE_SECTIONS: &[&str] = &[
    "signer",
    "filter",
    "ipam",
    "challenge",
    "eab",
    "order",
    "notify",
    "meta",
];

/// Whether `name` is safe to use as both a TOML table key *and* an
/// environment-variable segment (`ACME_PROXY_..._<NAME>_...`) naming the same
/// entry: `_` would collide with the `__` nesting separator, and the `config`
/// crate lowercases environment keys, so anything outside this set could name
/// one entry in a file and a silently different one through the environment.
///
/// Used for profile names (`[profiles.<name>]` / `ACME_PROXY_PROFILES__<NAME>__…`),
/// `filter.custom` entry names (`[filter.custom.<name>]` /
/// `ACME_PROXY_FILTER__CUSTOM__<NAME>__…`), and `notify.custom` entry names
/// (`[notify.custom.<name>]` / `ACME_PROXY_NOTIFY__CUSTOM__<NAME>__…`) —
/// anywhere a config table is keyed by an operator-chosen name rather than a
/// fixed field.
pub(crate) fn valid_config_key_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Resolves a selection list against the table of named entries it selects
/// from, validating both halves.
///
/// Three tables have this shape now — `notify.custom`, `notify.webhook`, and
/// `filter` grew it independently before its redesign — and they must not
/// drift, because the name rule in particular carries reasoning that is not
/// obvious from the code: an entry's name is also an environment-variable
/// segment, which the `config` crate lowercases, so anything outside the
/// permitted set could name one entry in a file and a silently different one
/// through the environment.
///
/// `table` is the entries' own path (`"notify.custom"`, `"notify.webhook"`) and
/// `enabled_key` the key selecting from it; both are used only to word the
/// errors, so an operator is told which key to go and look at. `backend` is the
/// value in `<subsystem>.enabled` that turned the table on.
pub(crate) fn resolve_named_entries<'a, T>(
    table: &str,
    enabled_key: &str,
    backend: &str,
    entries: &'a BTreeMap<String, T>,
    enabled: &'a [String],
) -> anyhow::Result<Vec<(&'a str, &'a T)>> {
    validate_key_names(table, entries.keys())?;
    let subsystem = table.split('.').next().unwrap_or(table);
    anyhow::ensure!(
        !enabled.is_empty(),
        "{table} is enabled but {enabled_key} is empty; \
         list the [{table}.<name>] entries to use, or remove `{backend}` from \
         {subsystem}.enabled"
    );

    enabled
        .iter()
        .map(|name| {
            let entry = entries.get(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "{enabled_key} names `{name}`, but no [{table}.{name}] is configured"
                )
            })?;
            Ok((name.as_str(), entry))
        })
        .collect()
}

/// Checks every key of an operator-named config table, naming the offender.
///
/// `prefix` is the table's path (`filter.check`, `notify.custom`), used only to
/// word the error so an operator is told which key to go and look at. The
/// reasoning in that error is the part worth stating once rather than three
/// times: a table key is also an environment-variable segment, and the `config`
/// crate lowercases those, so anything outside the permitted set could name one
/// entry in a file and a silently different one through the environment.
pub(crate) fn validate_key_names<'a>(
    prefix: &str,
    keys: impl Iterator<Item = &'a String>,
) -> anyhow::Result<()> {
    let env_prefix = prefix.to_ascii_uppercase().replace('.', "__");
    for key in keys {
        anyhow::ensure!(
            valid_config_key_name(key),
            "{prefix}.{key}: invalid name (use lowercase letters, digits and `-` — the \
             name is also an environment variable segment, and the config crate \
             lowercases those, so anything else could silently name a different entry \
             through ACME_PROXY_{env_prefix}__… than in the file)"
        );
    }
    Ok(())
}

/// Profile names are URL segments (`/profile/<name>`) as well as config-key
/// names; see [`valid_config_key_name`].
fn valid_profile_name(name: &str) -> bool {
    valid_config_key_name(name)
}

/// The list-valued fields of `[filter.check.<name>]`.
///
/// Separate from [`LIST_KEYS`] because the entry name is only known at runtime,
/// so these are registered by scanning the environment rather than by literal.
/// A new list field on `CheckConfig` needs an entry here or its environment
/// variable is silently dropped.
const CHECK_LIST_KEYS: &[&str] = &[
    "stages",
    "allow",
    "deny",
    "allow_regex",
    "deny_regex",
    "allowed_types",
    "kids",
    "args",
];

const LIST_KEYS: &[&str] = &[
    "challenge.enabled",
    "filter.rules",
    "filter.trusted_proxies",
    // Removed keys. Registered so they still parse from the environment,
    // which is what lets `filter::build` refuse them by name there as well as
    // in a file — unregistered, they would fail as an opaque serde type error
    // instead.
    "filter.enabled",
    "filter.exempt_paths",
    "filter.custom_enabled",
    "ipam.netbox.sources",
    "ipam.netbox.vip_roles",
    "ipam.phpipam.sources",
    "ipam.custom.args",
    "signer.relay.contact",
    "signer.custom.args",
    "signer.local_ca.crl_distribution_points",
    "signer.local_ca.ca_issuer_urls",
    "notify.enabled",
    "notify.email.to",
    "notify.email.events",
    "notify.webhook_enabled",
    "notify.custom_enabled",
    "meta.caa_identities",
    "proxy.no_proxy",
];

impl Config {
    #[cfg(test)]
    fn list_key(&self, key: &str) -> Option<Vec<String>> {
        let value = match key {
            "challenge.enabled" => &self.challenge.enabled,
            "filter.rules" => &self.filter.rules,
            "filter.trusted_proxies" => &self.filter.trusted_proxies,
            "filter.enabled" => &self.filter.enabled,
            "filter.exempt_paths" => &self.filter.exempt_paths,
            "filter.custom_enabled" => &self.filter.custom_enabled,
            "ipam.netbox.sources" => &self.ipam.netbox.sources,
            "ipam.netbox.vip_roles" => &self.ipam.netbox.vip_roles,
            "ipam.phpipam.sources" => &self.ipam.phpipam.sources,
            "ipam.custom.args" => &self.ipam.custom.args,
            "signer.relay.contact" => &self.signer.relay.contact,
            "signer.custom.args" => &self.signer.custom.args,
            "signer.local_ca.crl_distribution_points" => {
                &self.signer.local_ca.crl_distribution_points
            }
            "signer.local_ca.ca_issuer_urls" => &self.signer.local_ca.ca_issuer_urls,
            "notify.enabled" => &self.notify.enabled,
            "notify.email.to" => &self.notify.email.to,
            "notify.email.events" => &self.notify.email.events,
            "notify.webhook_enabled" => &self.notify.webhook_enabled,
            "notify.custom_enabled" => &self.notify.custom_enabled,
            "meta.caa_identities" => &self.meta.caa_identities,
            "proxy.no_proxy" => &self.proxy.no_proxy,
            _ => return None,
        };
        Some(value.clone())
    }

    /// Loads configuration from defaults, TOML file, and environment variables.
    pub fn load() -> Result<Self, ::config::ConfigError> {
        let path = std::env::var("ACME_PROXY_CONFIG").unwrap_or_else(|_| "config".into());

        let mut environment = ::config::Environment::with_prefix("ACME_PROXY")
            .prefix_separator("_")
            .separator("__")
            .try_parsing(true)
            .list_separator(",");
        // Every list-valued key, both globally and inside each profile the
        // environment mentions. `with_list_parse_key` takes a *literal* key,
        // and a profile name is only known at runtime — so the names are
        // scanned for first. Without this, `ACME_PROXY_PROFILES__LE__
        // CHALLENGE__ENABLED` would be silently dropped, the same trap the
        // global `LIST_KEYS` registry exists for.
        let profiles_in_env = profile_names_in_env();
        for key in LIST_KEYS {
            environment = environment.with_list_parse_key(key);
            for name in &profiles_in_env {
                environment = environment.with_list_parse_key(&format!("profiles.{name}.{key}"));
            }
        }
        // One level deeper: three sections are tables keyed by a name only
        // known at runtime, each with list-valued fields of its own. Same
        // reasoning as the profile-scoped loop above (and as `profiles_in_env`
        // itself) — without registration every one of these is silently
        // *dropped* from the environment rather than refused, which is the one
        // failure mode a configuration bug should never have.
        //
        // Both scopes of each are registered by walking `None` (global) and
        // then each profile: the two used to be written out separately, four
        // times over, each copy repeating the same comment.
        //
        // (`notify.webhook.<name>.headers` is a map rather than a list, so it
        // needs no entry — `config` nests it from `…__HEADERS__<NAME>` without
        // help.)
        const NAMED_TABLES: &[(&str, &[&str])] = &[
            ("filter.check", CHECK_LIST_KEYS),
            ("notify.custom", &["args", "events"]),
            ("notify.webhook", &["events"]),
        ];
        let scopes = std::iter::once(None).chain(profiles_in_env.iter().map(Some));
        for profile in scopes {
            for (section, keys) in NAMED_TABLES {
                let (env_prefix, key_prefix) = match profile {
                    None => (
                        format!("ACME_PROXY_{}__", env_segment(section)),
                        (*section).to_string(),
                    ),
                    Some(name) => (
                        format!(
                            "ACME_PROXY_PROFILES__{}__{}__",
                            name.to_ascii_uppercase(),
                            env_segment(section)
                        ),
                        format!("profiles.{name}.{section}"),
                    ),
                };
                for entry in names_in_env(&env_prefix) {
                    for key in *keys {
                        environment =
                            environment.with_list_parse_key(&format!("{key_prefix}.{entry}.{key}"));
                    }
                }
            }
        }

        let built = ::config::Config::builder()
            .add_source(::config::File::with_name(&path).required(false))
            .add_source(environment)
            .build()?;

        let mut config: Config = built.clone().try_deserialize()?;
        config.raw = Some(built);
        Ok(config)
    }

    /// The profiles this configuration mounts, each fully populated: what the
    /// profile states, over what the matching global section states, over the
    /// compiled defaults — resolved key by key, not section by section, so a
    /// profile changing one knob keeps the rest of the global section.
    ///
    /// Fails when nothing is left to serve: profiles are the only way to serve
    /// ACME at all, and a server that silently answers nothing would be worse
    /// than one that refuses to start.
    pub fn resolve_profiles(&self) -> anyhow::Result<Vec<ProfileConfig>> {
        let raw_profiles = self
            .raw
            .as_ref()
            .and_then(|raw| raw.get::<::config::Value>("profiles").ok())
            .map(as_table)
            .unwrap_or_default();

        let mut profiles = Vec::new();
        // A `BTreeMap` rather than the source's own ordering: mount order, log
        // order and error messages must not depend on how a file was written.
        for (name, raw_profile) in raw_profiles.into_iter().collect::<BTreeMap<_, _>>() {
            anyhow::ensure!(
                valid_profile_name(&name),
                "invalid profile name `{name}`: use lowercase letters, digits and `-` \
                 (the name is both a URL segment and an environment variable segment)"
            );

            let sections = self.merged_sections(&raw_profile).map_err(|error| {
                anyhow::anyhow!("profile `{name}`: invalid configuration: {error}")
            })?;

            if sections.enabled {
                profiles.push(ProfileConfig { name, sections });
            }
        }

        anyhow::ensure!(!profiles.is_empty(), self.no_profiles_message());
        Ok(profiles)
    }

    /// Deserializes one profile, each of its sections overlaid on the global
    /// one first. Both sides are the *raw* values, so a key nobody wrote falls
    /// through to serde's own default rather than to a default masquerading as
    /// a global setting.
    fn merged_sections(
        &self,
        raw_profile: &::config::Value,
    ) -> Result<ProfileSections, ::config::ConfigError> {
        let profile_table = as_table(raw_profile.clone());
        let mut merged = profile_table.clone();

        for section in PROFILE_SECTIONS {
            let global = self
                .raw
                .as_ref()
                .and_then(|raw| raw.get::<::config::Value>(section).ok());
            let overlay = profile_table.get(*section).cloned();

            match (global, overlay) {
                (Some(global), Some(overlay)) => {
                    merged.insert((*section).to_string(), merge_values(&global, &overlay));
                }
                (Some(global), None) => {
                    merged.insert((*section).to_string(), global);
                }
                // Nothing written anywhere: leave the key out and let the
                // section's own `#[serde(default)]` fill it in.
                (None, _) => {}
            }
        }

        ProfileSections::deserialize(::config::Value::new(
            None,
            ::config::ValueKind::Table(merged),
        ))
    }

    /// The startup error for a configuration that mounts nothing — written to
    /// be copy-pasteable, since "no profiles" is what every first run hits.
    fn no_profiles_message(&self) -> String {
        format!(
            "no enabled [profiles] — acme-proxy serves nothing without one. Minimal config:\n\
             \n    [profiles.default]\n\n\
             Its ACME directory is then at {}/profile/default/directory.",
            self.server.base_url
        )
    }
}

/// A dotted configuration section as its `ACME_PROXY_*` spelling:
/// `filter.check` becomes `FILTER__CHECK`.
///
/// The two spellings of every section used to be written out by hand at each
/// registration site, which is exactly where one of them goes stale.
fn env_segment(section: &str) -> String {
    section.to_ascii_uppercase().replace('.', "__")
}

// The first `__`-delimited segment after `prefix`, for every environment
/// variable that starts with it — lowercased, matching what the `config`
/// crate does to environment keys, so `…__LE__…` and a `[profiles.le]` table
/// (or `…__CUSTOM__MAIN__…` and a `[filter.custom.main]` table) name the same
/// entry.
fn names_in_env(prefix: &str) -> BTreeSet<String> {
    std::env::vars()
        .filter_map(|(key, _)| {
            let rest = key.strip_prefix(prefix)?;
            let name = rest.split("__").next()?;
            (!name.is_empty()).then(|| name.to_ascii_lowercase())
        })
        .collect()
}

/// Profile names mentioned by `ACME_PROXY_PROFILES__<NAME>__…` variables.
fn profile_names_in_env() -> BTreeSet<String> {
    names_in_env("ACME_PROXY_PROFILES__")
}

/// A value's table, or an empty one for anything else (including absent).
fn as_table(value: ::config::Value) -> ::config::Map<String, ::config::Value> {
    match value.kind {
        ::config::ValueKind::Table(table) => table,
        _ => ::config::Map::new(),
    }
}

/// Overlays `overlay` on `base`, recursing into tables.
///
/// Scalars **and arrays** are replaced wholesale: an inherited list a profile
/// could only ever extend (never shorten) would be a trap in a `deny` list.
fn merge_values(base: &::config::Value, overlay: &::config::Value) -> ::config::Value {
    match (&base.kind, &overlay.kind) {
        (::config::ValueKind::Table(base), ::config::ValueKind::Table(overlay)) => {
            let mut merged = base.clone();
            for (key, value) in overlay {
                let merged_value = match merged.get(key) {
                    Some(existing) => merge_values(existing, value),
                    None => value.clone(),
                };
                merged.insert(key.clone(), merged_value);
            }
            ::config::Value::new(None, ::config::ValueKind::Table(merged))
        }
        _ => overlay.clone(),
    }
}

/// Serialises every test that reads or writes the process environment.
///
/// `Config::load` consults `ACME_PROXY_*` and `ACME_PROXY_CONFIG`, which are
/// process-wide: a test setting one while another is loading a configuration
/// makes the second read the first's variables. One lock for the whole crate,
/// not one per module — three independent locks serialise a module against
/// itself and against nothing else, which is the same as no lock at all.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::EnvGuard;

    /// A throwaway directory holding one `config.toml`, removed on drop.
    ///
    /// Profile resolution reads the *raw* configuration sources, so it can only
    /// be exercised through `Config::load()` — a `Config` built in code has no
    /// sources to merge and therefore no profiles at all.
    struct TempConfig {
        dir: crate::testutil::TempDir,
    }

    impl TempConfig {
        fn new(body: &str) -> Self {
            let dir = crate::testutil::TempDir::new("cfg");
            dir.write("config.toml", body);
            Self { dir }
        }

        fn path(&self) -> String {
            self.dir.join("config").to_string_lossy().into_owned()
        }
    }

    /// Loads `body` as the whole configuration file.
    fn load_toml(body: &str) -> Config {
        let file = TempConfig::new(body);
        let path = file.path();
        let _guard = EnvGuard::new(&[("ACME_PROXY_CONFIG", &path)]);
        Config::load().expect("the configuration must load")
    }

    #[test]
    fn a_bare_profile_table_inherits_every_global_section() {
        let config = load_toml(
            r#"
            [challenge]
            enabled = ["dns-01"]
            bypass = false

            [profiles.le]
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "le");
        assert_eq!(profiles[0].sections.challenge.enabled, vec!["dns-01"]);
        assert!(!profiles[0].sections.challenge.bypass);
        // Untouched globally *and* by the profile: the compiled default.
        assert_eq!(profiles[0].sections.signer.backend, "local_ca");
    }

    /// The trap section-level inheritance would fall into: a profile that
    /// overrides one knob of a section must keep the rest of the **global**
    /// section, not silently fall back to the compiled defaults.
    #[test]
    fn overriding_one_key_keeps_the_rest_of_the_global_section() {
        let config = load_toml(
            r#"
            [challenge]
            enabled = ["dns-01"]
            bypass = true
            timeout_ms = 1234

            [profiles.strict]
            challenge.bypass = false
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        let challenge = &profiles[0].sections.challenge;
        assert!(!challenge.bypass, "the profile's own value wins");
        assert_eq!(
            challenge.enabled,
            vec!["dns-01"],
            "the rest of the section is inherited, not reset to the default"
        );
        assert_eq!(challenge.timeout_ms, 1234);
    }

    /// `ipam` is per-profile, which is the whole reason it is a section rather
    /// than a process-wide one: two endpoints of the same server may consult
    /// different inventories, and each keeps the rest of the global section.
    #[test]
    fn two_profiles_may_name_different_inventories() {
        let config = load_toml(
            r#"
            [ipam]
            backend = "netbox"
            timeout_ms = 1234

            [ipam.netbox]
            url = "https://netbox.example.com"
            token = "t0ken"

            [ipam.phpipam]
            url = "https://ipam.example.com"
            token = "appcode"

            [profiles.dmz]

            [profiles.internal]
            ipam.backend = "phpipam"
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        let by_name = |name: &str| {
            profiles
                .iter()
                .find(|p| p.name == name)
                .map(|p| &p.sections.ipam)
                .unwrap()
        };

        assert_eq!(by_name("dmz").backend, "netbox");
        assert_eq!(by_name("internal").backend, "phpipam");
        // …and overriding the one key keeps the rest of the global section,
        // both the sibling tables and the budget.
        assert_eq!(by_name("internal").timeout_ms, 1234);
        assert_eq!(by_name("internal").phpipam.url, "https://ipam.example.com");
        assert_eq!(by_name("internal").netbox.url, "https://netbox.example.com");
    }

    /// A profile may narrow what its inventory is trusted for without
    /// restating the connection details — the per-key inheritance rule applied
    /// to the one list that decides how much an address may claim.
    #[test]
    fn a_profile_may_narrow_the_ipam_sources_alone() {
        let config = load_toml(
            r#"
            [ipam]
            backend = "netbox"

            [ipam.netbox]
            url = "https://netbox.example.com"
            token = "t0ken"
            sources = ["dns_name", "custom_field", "device", "fhrp"]

            [profiles.strict]
            ipam.netbox.sources = ["dns_name"]
            "#,
        );

        let netbox = &config.resolve_profiles().unwrap()[0].sections.ipam.netbox;
        assert_eq!(netbox.sources, vec!["dns_name"]);
        assert_eq!(netbox.url, "https://netbox.example.com");
        assert_eq!(netbox.token, "t0ken");
    }

    /// `notify` joins `PROFILE_SECTIONS` like every other subsystem: a profile
    /// overriding one knob keeps the rest of the *global* `[notify]` section
    /// rather than resetting to compiled defaults.
    #[test]
    fn a_profile_can_override_one_notify_key_and_keep_the_rest() {
        let config = load_toml(
            r#"
            [notify]
            enabled = ["email"]
            email.smtp_host = "mail.example.com"
            email.smtp_port = 2525

            [profiles.staging]
            notify.email.smtp_host = "mail.staging.example.com"
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        let notify = &profiles[0].sections.notify;
        assert_eq!(notify.enabled, vec!["email"], "inherited from global");
        assert_eq!(notify.email.smtp_host, "mail.staging.example.com");
        assert_eq!(
            notify.email.smtp_port, 2525,
            "the rest of the section is inherited, not reset to the default"
        );
    }

    #[test]
    fn a_profile_section_replaces_an_inherited_list_wholesale() {
        let config = load_toml(
            r#"
            [filter]
            check.names.deny = ["a.example", "b.example"]

            [profiles.narrow]
            filter.check.names.deny = ["c.example"]
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        assert_eq!(
            profiles[0].sections.filter.check["names"].deny,
            vec!["c.example"],
            "arrays are replaced, never merged"
        );
    }

    /// The other half of the inheritance promise, and the reason
    /// `[filter.rule.<name>]` is a map rather than an array of tables: a
    /// profile overrides one field of one rule and inherits the rest, which an
    /// array could not express at all.
    #[test]
    fn a_profile_overrides_one_field_of_an_inherited_rule() {
        let config = load_toml(
            r#"
            [filter]
            rules = ["inventory"]
            rule.inventory.when = "inv"
            rule.inventory.then = "allow"
            rule.inventory.message = "not yours"

            [profiles.staging]
            filter.rule.inventory.mode = "warn"
            "#,
        );

        let rule = &config.resolve_profiles().unwrap()[0].sections.filter.rule["inventory"];
        assert_eq!(rule.mode, "warn");
        assert_eq!(rule.when, "inv", "the condition is inherited");
        assert_eq!(rule.message, "not yours", "so is the message");
    }

    #[test]
    fn profiles_are_resolved_in_name_order() {
        let config = load_toml(
            r#"
            [profiles.zulu]
            [profiles.alpha]
            [profiles.mike]
            "#,
        );

        let names: Vec<_> = config
            .resolve_profiles()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn a_disabled_profile_is_not_mounted() {
        let config = load_toml(
            r#"
            [profiles.live]

            [profiles.parked]
            enabled = false
            "#,
        );

        let names: Vec<_> = config
            .resolve_profiles()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["live"]);
    }

    #[test]
    fn a_configuration_with_no_profile_refuses_to_resolve() {
        for body in ["", "[profiles]\n", "[profiles.parked]\nenabled = false\n"] {
            let config = load_toml(body);
            let error = config
                .resolve_profiles()
                .expect_err("a server with no endpoint must not start")
                .to_string();
            assert!(error.contains("[profiles.default]"), "{error}");
            assert!(
                error.contains("/profile/default/directory"),
                "the error must show where the endpoint would answer: {error}"
            );
        }
    }

    #[test]
    fn a_profile_name_outside_the_url_charset_is_refused() {
        for name in ["Le", "my_profile", "we.b"] {
            let config = load_toml(&format!("[profiles.\"{name}\"]\n"));
            let error = config
                .resolve_profiles()
                .expect_err("{name} must be refused")
                .to_string();
            assert!(error.contains("invalid profile name"), "{error}");
        }
    }

    /// A list-valued key inside a profile only survives the environment if its
    /// *runtime* key was registered for list parsing — the whole reason
    /// `Config::load` scans for profile names before building the sources.
    #[test]
    fn a_profile_list_key_round_trips_through_the_environment() {
        let file = TempConfig::new("[profiles.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            (
                "ACME_PROXY_PROFILES__LE__CHALLENGE__ENABLED",
                "dns-01,http-01",
            ),
        ]);

        let config = Config::load().unwrap();
        let profiles = config.resolve_profiles().unwrap();
        assert_eq!(
            profiles[0].sections.challenge.enabled,
            vec!["dns-01".to_string(), "http-01".to_string()]
        );
    }

    /// `[admin]` is a new top-level section, so this pins that the whole
    /// `ACME_PROXY_ADMIN__…` family actually reaches it — the trap being that
    /// `config`'s `Environment` reuses the nested `separator` as the prefix
    /// separator unless `prefix_separator("_")` is set, which would drop every
    /// one of these silently.
    ///
    /// `ENABLED` alone is the key that matters: it is what an environment-only
    /// deployment sets to turn the panel on at all.
    #[test]
    fn the_admin_section_round_trips_through_the_environment() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_ADMIN__ENABLED", "true"),
            ("ACME_PROXY_ADMIN__BIND_ADDRESS", "127.0.0.1:9999"),
            ("ACME_PROXY_ADMIN__BASE_URL", "https://admin.example.com"),
            ("ACME_PROXY_ADMIN__SESSION_TTL_SECONDS", "60"),
            ("ACME_PROXY_ADMIN__LOGIN_MAX_ATTEMPTS", "1"),
            ("ACME_PROXY_ADMIN__REQUIRE_MFA", "true"),
            ("ACME_PROXY_ADMIN__PAGE_SIZE_MAX", "10"),
            ("ACME_PROXY_ADMIN__TLS__ENABLED", "true"),
            ("ACME_PROXY_ADMIN__TLS__CERT_PATH", "/tmp/admin.pem"),
        ]);

        let config = Config::load().unwrap();
        assert!(config.admin.enabled);
        assert_eq!(config.admin.bind_address, "127.0.0.1:9999");
        assert_eq!(config.admin.base_url, "https://admin.example.com");
        assert_eq!(config.admin.session_ttl_seconds, 60);
        assert_eq!(config.admin.login_max_attempts, 1);
        assert!(config.admin.require_mfa);
        assert_eq!(config.admin.page_size_max, 10);
        assert!(config.admin.tls.enabled);
        assert_eq!(config.admin.tls.cert_path, "/tmp/admin.pem");
        // Untouched keys keep their defaults rather than resetting.
        assert_eq!(
            config.admin.tls.key_path,
            AdminConfig::default().tls.key_path
        );
        assert_eq!(
            config.admin.session_idle_timeout_seconds,
            AdminConfig::default().session_idle_timeout_seconds
        );
    }

    /// The `[proxy]` section, the other one an environment-only deployment is
    /// likely to set without a file at all.
    ///
    /// The `ACME_PROXY_PROXY__` prefix reads oddly and is worth pinning for
    /// exactly that reason: the section is `proxy`, and the crate prefix is not
    /// dropped for a section that happens to share its name.
    #[test]
    fn the_proxy_section_round_trips_through_the_environment() {
        let _guard = EnvGuard::new(&[
            (
                "ACME_PROXY_PROXY__HTTPS_URL",
                "http://proxy.example.com:3128",
            ),
            ("ACME_PROXY_PROXY__NO_PROXY", "10.0.0.0/8,.internal.example"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(config.proxy.https_url, "http://proxy.example.com:3128");
        assert_eq!(
            config.proxy.no_proxy,
            vec!["10.0.0.0/8", ".internal.example"]
        );
        // Untouched keys keep their defaults rather than resetting.
        assert_eq!(config.proxy.http_url, ProxyConfig::default().http_url);
    }

    /// `[filter.check.<name>]` entries are named tables, not a list — so unlike
    /// an ordinary `LIST_KEYS` entry, each of their list-valued fields needs
    /// its own `with_list_parse_key` registration, keyed by a name only known
    /// at runtime. Without that scan every one of them is silently dropped
    /// from the environment rather than refused, which is the single most
    /// forgettable part of this section.
    #[test]
    fn env_configures_multiple_named_checks_with_all_their_lists() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_FILTER__RULES", "main"),
            ("ACME_PROXY_FILTER__CHECK__MAIN__TYPE", "custom"),
            (
                "ACME_PROXY_FILTER__CHECK__MAIN__SCRIPT_PATH",
                "/path/to/one.sh",
            ),
            ("ACME_PROXY_FILTER__CHECK__MAIN__ARGS", "foo,bar"),
            ("ACME_PROXY_FILTER__CHECK__MAIN__STAGES", "connection"),
            ("ACME_PROXY_FILTER__CHECK__EXTRA__TYPE", "identifiers"),
            (
                "ACME_PROXY_FILTER__CHECK__EXTRA__ALLOW",
                "*.example.com,example.com",
            ),
            ("ACME_PROXY_FILTER__CHECK__EXTRA__DENY_REGEX", "secret\\..*"),
            ("ACME_PROXY_FILTER__CHECK__EXTRA__ALLOWED_TYPES", "dns"),
            ("ACME_PROXY_FILTER__CHECK__EXTRA__KIDS", "k1,k2"),
        ]);

        let config = Config::load().expect("load should succeed");
        let check = &config.filter.check;
        assert_eq!(check["main"].script_path, "/path/to/one.sh");
        assert_eq!(check["main"].args, vec!["foo", "bar"]);
        assert_eq!(check["main"].stages, vec!["connection"]);
        assert_eq!(check["extra"].allow, vec!["*.example.com", "example.com"]);
        assert_eq!(check["extra"].deny_regex, vec!["secret\\..*"]);
        assert_eq!(check["extra"].allowed_types, vec!["dns"]);
        assert_eq!(check["extra"].kids, vec!["k1", "k2"]);
        assert_eq!(config.filter.rules, vec!["main"]);
    }

    /// The same, scoped to one profile — proving the runtime name scan also
    /// covers `ACME_PROXY_PROFILES__<NAME>__FILTER__CHECK__<NAME>__…`.
    #[test]
    fn env_configures_a_profile_scoped_named_check() {
        let file = TempConfig::new("[profiles.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_PROFILES__LE__FILTER__RULES", "only"),
            (
                "ACME_PROXY_PROFILES__LE__FILTER__CHECK__MAIN__TYPE",
                "custom",
            ),
            (
                "ACME_PROXY_PROFILES__LE__FILTER__CHECK__MAIN__SCRIPT_PATH",
                "/path/to/profile.sh",
            ),
            (
                "ACME_PROXY_PROFILES__LE__FILTER__CHECK__MAIN__ARGS",
                "a,b,c",
            ),
        ]);

        let config = Config::load().unwrap();
        let profiles = config.resolve_profiles().unwrap();
        let check = &profiles[0].sections.filter.check;
        assert_eq!(check["main"].script_path, "/path/to/profile.sh");
        assert_eq!(check["main"].args, vec!["a", "b", "c"]);
        assert_eq!(profiles[0].sections.filter.rules, vec!["only"]);
    }

    /// The two `[notify]` tables, scoped to a profile — the remaining corner of
    /// the runtime-name scan.
    ///
    /// All six scopes (three sections × global/per-profile) go through one loop
    /// now, where they used to be four blocks written out separately. This is
    /// the one those blocks covered least, and the failure it guards against is
    /// silent: an unregistered list variable is *dropped*, so `events` would
    /// quietly revert to all six rather than being refused.
    #[test]
    fn env_configures_profile_scoped_notify_tables() {
        let file = TempConfig::new("[profiles.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            (
                "ACME_PROXY_PROFILES__LE__NOTIFY__CUSTOM__PAGER__SCRIPT_PATH",
                "/usr/local/bin/page.sh",
            ),
            (
                "ACME_PROXY_PROFILES__LE__NOTIFY__CUSTOM__PAGER__ARGS",
                "--urgent,--team=netops",
            ),
            (
                "ACME_PROXY_PROFILES__LE__NOTIFY__CUSTOM__PAGER__EVENTS",
                "certificate_issued,challenge_failed",
            ),
            (
                "ACME_PROXY_PROFILES__LE__NOTIFY__WEBHOOK__SLACK__URL",
                "https://hooks.example.com/T/B/xyz",
            ),
            (
                "ACME_PROXY_PROFILES__LE__NOTIFY__WEBHOOK__SLACK__EVENTS",
                "certificate_revoked",
            ),
        ]);

        let config = Config::load().unwrap();
        let profiles = config.resolve_profiles().unwrap();
        let notify = &profiles[0].sections.notify;

        let pager = &notify.custom["pager"];
        assert_eq!(pager.script_path, "/usr/local/bin/page.sh");
        assert_eq!(pager.args, vec!["--urgent", "--team=netops"]);
        assert_eq!(
            pager.events,
            vec!["certificate_issued", "challenge_failed"],
            "an unregistered list key is dropped, not refused"
        );

        let slack = &notify.webhook["slack"];
        assert_eq!(slack.url, "https://hooks.example.com/T/B/xyz");
        assert_eq!(slack.events, vec!["certificate_revoked"]);
    }

    /// `[notify.webhook.<name>]` is the third table keyed by a runtime name, so
    /// its `events` needs the same scan-then-register treatment as
    /// `filter.check` and `notify.custom` — without it the variable is silently
    /// dropped rather than refused, and the entry quietly reverts to all six
    /// events. `headers` is the counter-case: a map, which `config` nests from
    /// `…__HEADERS__<NAME>` with no registration at all.
    #[test]
    fn env_configures_a_named_webhook_with_its_list_and_its_header_map() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_NOTIFY__ENABLED", "webhook"),
            ("ACME_PROXY_NOTIFY__WEBHOOK_ENABLED", "slack,matrix"),
            (
                "ACME_PROXY_NOTIFY__WEBHOOK__SLACK__URL",
                "https://hooks.slack.example/services/T/B/x",
            ),
            (
                "ACME_PROXY_NOTIFY__WEBHOOK__SLACK__EVENTS",
                "certificate_issued,certificate_revoked",
            ),
            ("ACME_PROXY_NOTIFY__WEBHOOK__MATRIX__METHOD", "PUT"),
            (
                "ACME_PROXY_NOTIFY__WEBHOOK__MATRIX__HEADERS__AUTHORIZATION",
                "Bearer syt_xxx",
            ),
        ]);

        let config = Config::load().expect("load should succeed");
        assert_eq!(config.notify.webhook_enabled, vec!["slack", "matrix"]);
        assert_eq!(
            config.notify.webhook["slack"].events,
            vec!["certificate_issued", "certificate_revoked"]
        );
        assert_eq!(config.notify.webhook["matrix"].method, "PUT");
        assert_eq!(
            config.notify.webhook["matrix"].headers["authorization"],
            "Bearer syt_xxx"
        );
        // Untouched keys keep their defaults rather than resetting.
        assert_eq!(
            config.notify.webhook["slack"].method,
            WebhookNotifyConfig::default().method
        );
    }

    /// The unindexed shape (`ACME_PROXY_FILTER__CHECK__TYPE`, with no name
    /// segment) is a clear load-time error rather than something silently
    /// accepted or ignored: `filter.check` is a table of *named* entries, so
    /// the missing name segment makes `type`'s plain string value land exactly
    /// where one check's whole table is expected.
    #[test]
    fn an_unindexed_check_env_shape_is_a_clear_load_error() {
        let _guard = EnvGuard::new(&[("ACME_PROXY_FILTER__CHECK__TYPE", "allowed_ip")]);

        let error = Config::load().unwrap_err().to_string();
        assert!(error.contains("filter.check.type"), "{error}");
    }

    /// An environment-only profile: no `[profiles]` table in the file at all.
    #[test]
    fn a_profile_can_be_declared_entirely_from_the_environment() {
        let file = TempConfig::new("[server]\nbase_url = \"http://acme.test\"\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_PROFILES__LE__ENABLED", "true"),
            ("ACME_PROXY_PROFILES__LE__CHALLENGE__BYPASS", "false"),
        ]);

        let config = Config::load().unwrap();
        let profiles = config.resolve_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "le");
        assert!(!profiles[0].sections.challenge.bypass);
    }

    #[test]
    fn default_values_match_expected() {
        let _guard = EnvGuard::new(&[]);
        let config = Config::load().expect("defaults alone must load");

        assert_eq!(config.database.url, "sqlite://sqlite.db");
        assert_eq!(config.server.bind_address, "[::]:3000");
        assert_eq!(config.server.base_url, "http://localhost:3000");
        assert!(!config.server.tls.enabled);
        assert_eq!(config.server.tls.cert_path, "server.pem");
        assert_eq!(config.server.tls.key_path, "server.key");
        assert_eq!(config.server.tls.handshake_timeout_ms, 10_000);
        assert_eq!(config.nonce.ttl_seconds, 300);
        assert_eq!(config.jobs.poll_interval_ms, 1_000);
        assert_eq!(config.jobs.max_concurrent, 8);
        assert_eq!(config.jobs.max_attempts, 5);
        assert_eq!(config.jobs.retry_base_seconds, 30);
        assert_eq!(config.jobs.retry_max_seconds, 3_600);
        assert_eq!(config.jobs.lease_seconds, 300);
        // Non-zero unlike `audit.retention_days`: a finished job is a receipt,
        // not evidence.
        assert_eq!(config.jobs.retention_days, 7);
        assert_eq!(config.logging.filter, "acme_proxy=info");
        assert!(!config.logging.json_format);
        assert_eq!(config.logging.target, "stdout");
        assert!(config.logging.ansi);
        assert_eq!(config.logging.span_events, "none");
        assert!(!config.logging.flatten_event);
        assert_eq!(config.order.validity_seconds, 604800);
        assert_eq!(config.signer.backend, "local_ca");
        assert_eq!(config.signer.local_ca.cert_path, "ca.pem");
        assert_eq!(config.signer.local_ca.key_path, "ca.key");
        assert_eq!(config.signer.local_ca.key_type, "ecdsa-p256");
        assert_eq!(config.signer.local_ca.leaf_validity_days, 90);
        assert_eq!(config.challenge.enabled, vec!["http-01".to_string()]);
        // A CA that issues without proving control is not a safe out-of-the-box
        // posture; see `ChallengeConfig::bypass`.
        assert!(!config.challenge.bypass);
        assert_eq!(config.challenge.timeout_ms, 5000);
        assert_eq!(config.challenge.http_01.port, 80);
        assert_eq!(config.challenge.http_01.https_port, 443);
        assert!(config.challenge.http_01.follow_redirects);
        assert_eq!(config.challenge.http_01.max_redirects, 5);
        assert_eq!(config.challenge.http_01.max_response_bytes, 4096);
        assert_eq!(config.challenge.tls_alpn_01.port, 443);
        assert!(config.filter.rules.is_empty());
        assert_eq!(config.filter.default, "deny");
        assert!(config.filter.trusted_proxies.is_empty());
        assert_eq!(config.filter.forwarded_header, "x-forwarded-for");
        assert!(config.filter.rule.is_empty());
        assert!(config.filter.check.is_empty());
        // The keys the policy redesign removed default to empty so that a
        // configuration which never set them is not refused for having them.
        assert!(config.filter.enabled.is_empty());
        assert!(config.filter.exempt_paths.is_empty());
        assert!(config.filter.custom_enabled.is_empty());
        assert!(!config.eab.enabled);
        assert!(config.notify.enabled.is_empty());
        assert!(config.notify.custom_enabled.is_empty());
        assert!(config.notify.custom.is_empty());
        assert_eq!(config.notify.template_dir, "");
        assert_eq!(config.notify.email.smtp_port, 587);
        assert_eq!(config.notify.email.smtp_security, "starttls");
        assert_eq!(
            config.notify.email.events,
            vec![
                "profile_mounted",
                "account_created",
                "account_deactivated",
                "certificate_issued",
                "certificate_revoked",
                "challenge_failed"
            ]
        );
        assert!(config.notify.webhook_enabled.is_empty());
        assert!(config.notify.webhook.is_empty());
        assert!(config.dns.resolver.is_none());
        assert_eq!(config.proxy.http_url, "");
        assert_eq!(config.proxy.https_url, "");
        assert!(config.proxy.no_proxy.is_empty());
    }

    #[test]
    fn direct_construction_matches_the_loaded_defaults() {
        let _guard = EnvGuard::new(&[]);
        let loaded = Config::load().unwrap();
        let direct = Config::default();

        assert_eq!(loaded.database.url, direct.database.url);
        assert_eq!(loaded.server.base_url, direct.server.base_url);
        assert_eq!(loaded.server.bind_address, direct.server.bind_address);
        assert_eq!(loaded.server.tls.enabled, direct.server.tls.enabled);
        assert_eq!(loaded.server.tls.cert_path, direct.server.tls.cert_path);
        assert_eq!(loaded.server.tls.key_path, direct.server.tls.key_path);
        assert_eq!(
            loaded.server.tls.handshake_timeout_ms,
            direct.server.tls.handshake_timeout_ms
        );
        assert_eq!(loaded.nonce.ttl_seconds, direct.nonce.ttl_seconds);
        assert_eq!(loaded.order.validity_seconds, direct.order.validity_seconds);
        assert_eq!(loaded.signer.backend, direct.signer.backend);
        assert_eq!(loaded.challenge.enabled, direct.challenge.enabled);
        assert_eq!(loaded.challenge.bypass, direct.challenge.bypass);
        assert_eq!(loaded.challenge.timeout_ms, direct.challenge.timeout_ms);
        assert_eq!(loaded.challenge.http_01.port, direct.challenge.http_01.port);
        assert_eq!(loaded.filter.rules, direct.filter.rules);
        assert_eq!(loaded.filter.default, direct.filter.default);
        assert_eq!(loaded.eab.enabled, direct.eab.enabled);
        assert_eq!(loaded.dns.resolver, direct.dns.resolver);
        assert_eq!(loaded.proxy.http_url, direct.proxy.http_url);
        assert_eq!(loaded.proxy.https_url, direct.proxy.https_url);
        assert_eq!(loaded.proxy.no_proxy, direct.proxy.no_proxy);
    }

    #[test]
    fn the_example_config_documents_the_real_defaults() {
        // Copied as-is, the example must actually boot — which now means it has
        // to declare a profile, since a configuration with none is refused.
        let body = std::fs::read_to_string("config.toml.example").unwrap();
        let profiles = load_toml(&body)
            .resolve_profiles()
            .expect("config.toml.example must define at least one profile");
        assert_eq!(
            profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["default"]
        );

        let _guard = EnvGuard::new(&[]);

        let example = ::config::Config::builder()
            .add_source(
                ::config::File::from(std::path::Path::new("config.toml.example"))
                    .format(::config::FileFormat::Toml),
            )
            .build()
            .expect("config.toml.example must be valid TOML")
            .try_deserialize::<Config>()
            .expect("config.toml.example must deserialize into Config");

        let defaults = Config::default();
        assert_eq!(example.database.url, defaults.database.url);
        assert_eq!(example.server.bind_address, defaults.server.bind_address);
        assert_eq!(example.server.base_url, defaults.server.base_url);
        assert_eq!(
            example.server.max_concurrent_requests,
            defaults.server.max_concurrent_requests
        );
        assert_eq!(
            example.server.admission_wait_ms,
            defaults.server.admission_wait_ms
        );
        assert_eq!(
            example.server.request_timeout_ms,
            defaults.server.request_timeout_ms
        );
        assert_eq!(
            example.server.max_body_bytes,
            defaults.server.max_body_bytes
        );
        assert_eq!(example.server.tls.enabled, defaults.server.tls.enabled);
        assert_eq!(example.server.tls.cert_path, defaults.server.tls.cert_path);
        assert_eq!(example.server.tls.key_path, defaults.server.tls.key_path);
        assert_eq!(
            example.server.tls.handshake_timeout_ms,
            defaults.server.tls.handshake_timeout_ms
        );
        assert_eq!(example.admin.enabled, defaults.admin.enabled);
        assert_eq!(example.admin.bind_address, defaults.admin.bind_address);
        assert_eq!(example.admin.base_url, defaults.admin.base_url);
        assert_eq!(
            example.admin.session_ttl_seconds,
            defaults.admin.session_ttl_seconds
        );
        assert_eq!(
            example.admin.session_idle_timeout_seconds,
            defaults.admin.session_idle_timeout_seconds
        );
        assert_eq!(
            example.admin.login_max_attempts,
            defaults.admin.login_max_attempts
        );
        assert_eq!(
            example.admin.login_window_seconds,
            defaults.admin.login_window_seconds
        );
        assert_eq!(example.admin.require_mfa, defaults.admin.require_mfa);
        assert_eq!(example.admin.max_body_bytes, defaults.admin.max_body_bytes);
        assert_eq!(example.admin.page_size_max, defaults.admin.page_size_max);
        assert_eq!(example.admin.template_dir, defaults.admin.template_dir);
        assert_eq!(example.admin.tls.enabled, defaults.admin.tls.enabled);
        assert_eq!(example.admin.tls.cert_path, defaults.admin.tls.cert_path);
        assert_eq!(example.admin.tls.key_path, defaults.admin.tls.key_path);
        assert_eq!(
            example.admin.tls.handshake_timeout_ms,
            defaults.admin.tls.handshake_timeout_ms
        );
        assert_eq!(example.nonce.ttl_seconds, defaults.nonce.ttl_seconds);
        assert_eq!(example.audit.reverse_dns, defaults.audit.reverse_dns);
        assert_eq!(
            example.audit.reverse_dns_timeout_ms,
            defaults.audit.reverse_dns_timeout_ms
        );
        assert_eq!(example.audit.retention_days, defaults.audit.retention_days);
        assert_eq!(
            example.jobs.poll_interval_ms,
            defaults.jobs.poll_interval_ms
        );
        assert_eq!(example.jobs.max_concurrent, defaults.jobs.max_concurrent);
        assert_eq!(example.jobs.max_attempts, defaults.jobs.max_attempts);
        assert_eq!(
            example.jobs.retry_base_seconds,
            defaults.jobs.retry_base_seconds
        );
        assert_eq!(
            example.jobs.retry_max_seconds,
            defaults.jobs.retry_max_seconds
        );
        assert_eq!(example.jobs.lease_seconds, defaults.jobs.lease_seconds);
        assert_eq!(example.jobs.retention_days, defaults.jobs.retention_days);
        assert_eq!(example.logging.filter, defaults.logging.filter);
        assert_eq!(example.logging.json_format, defaults.logging.json_format);
        assert_eq!(example.logging.target, defaults.logging.target);
        assert_eq!(example.logging.ansi, defaults.logging.ansi);
        assert_eq!(example.logging.span_events, defaults.logging.span_events);
        assert_eq!(
            example.logging.flatten_event,
            defaults.logging.flatten_event
        );
        assert_eq!(
            example.order.validity_seconds,
            defaults.order.validity_seconds
        );
        assert_eq!(example.signer.backend, defaults.signer.backend);
        assert_eq!(
            example.signer.local_ca.cert_path,
            defaults.signer.local_ca.cert_path
        );
        assert_eq!(
            example.signer.local_ca.key_path,
            defaults.signer.local_ca.key_path
        );
        assert_eq!(
            example.signer.local_ca.key_type,
            defaults.signer.local_ca.key_type
        );
        assert_eq!(
            example.signer.local_ca.leaf_validity_days,
            defaults.signer.local_ca.leaf_validity_days
        );
        assert_eq!(
            example.signer.local_ca.crl_distribution_points,
            defaults.signer.local_ca.crl_distribution_points
        );
        assert_eq!(
            example.signer.local_ca.ca_issuer_urls,
            defaults.signer.local_ca.ca_issuer_urls
        );
        assert_eq!(
            example.signer.local_ca.subject.common_name,
            defaults.signer.local_ca.subject.common_name
        );
        assert_eq!(
            example.signer.local_ca.subject.organization,
            defaults.signer.local_ca.subject.organization
        );
        assert_eq!(
            example.signer.local_ca.subject.organizational_unit,
            defaults.signer.local_ca.subject.organizational_unit
        );
        assert_eq!(
            example.signer.local_ca.subject.country,
            defaults.signer.local_ca.subject.country
        );
        assert_eq!(
            example.signer.local_ca.subject.state,
            defaults.signer.local_ca.subject.state
        );
        assert_eq!(
            example.signer.local_ca.subject.locality,
            defaults.signer.local_ca.subject.locality
        );
        assert_eq!(example.challenge.enabled, defaults.challenge.enabled);
        assert_eq!(example.challenge.bypass, defaults.challenge.bypass);
        assert_eq!(example.challenge.timeout_ms, defaults.challenge.timeout_ms);
        assert_eq!(
            example.challenge.http_01.port,
            defaults.challenge.http_01.port
        );
        assert_eq!(
            example.challenge.http_01.https_port,
            defaults.challenge.http_01.https_port
        );
        assert_eq!(
            example.challenge.http_01.follow_redirects,
            defaults.challenge.http_01.follow_redirects
        );
        assert_eq!(
            example.challenge.http_01.max_redirects,
            defaults.challenge.http_01.max_redirects
        );
        assert_eq!(
            example.challenge.http_01.max_response_bytes,
            defaults.challenge.http_01.max_response_bytes
        );
        assert_eq!(
            example.challenge.tls_alpn_01.port,
            defaults.challenge.tls_alpn_01.port
        );
        assert_eq!(example.filter.rules, defaults.filter.rules);
        assert_eq!(example.filter.default, defaults.filter.default);
        assert_eq!(
            example.filter.forwarded_header,
            defaults.filter.forwarded_header
        );
        // Every check and rule the example documents is commented out, so the
        // file stays an all-defaults document that still boots.
        assert!(example.filter.check.is_empty());
        assert!(example.filter.rule.is_empty());
        assert_eq!(example.ipam.backend, defaults.ipam.backend);
        assert_eq!(example.ipam.timeout_ms, defaults.ipam.timeout_ms);
        assert_eq!(example.ipam.netbox.url, defaults.ipam.netbox.url);
        assert_eq!(example.ipam.netbox.token, defaults.ipam.netbox.token);
        assert_eq!(
            example.ipam.netbox.custom_field,
            defaults.ipam.netbox.custom_field
        );
        assert_eq!(example.ipam.netbox.sources, defaults.ipam.netbox.sources);
        assert_eq!(
            example.ipam.netbox.vip_roles,
            defaults.ipam.netbox.vip_roles
        );
        assert_eq!(
            example.ipam.netbox.ca_cert_path,
            defaults.ipam.netbox.ca_cert_path
        );
        assert_eq!(
            example.ipam.netbox.insecure_skip_verify,
            defaults.ipam.netbox.insecure_skip_verify
        );
        assert_eq!(example.ipam.phpipam.url, defaults.ipam.phpipam.url);
        assert_eq!(example.ipam.phpipam.app_id, defaults.ipam.phpipam.app_id);
        assert_eq!(example.ipam.phpipam.token, defaults.ipam.phpipam.token);
        assert_eq!(
            example.ipam.phpipam.custom_field,
            defaults.ipam.phpipam.custom_field
        );
        assert_eq!(example.ipam.phpipam.sources, defaults.ipam.phpipam.sources);
        assert_eq!(
            example.ipam.phpipam.ca_cert_path,
            defaults.ipam.phpipam.ca_cert_path
        );
        assert_eq!(
            example.ipam.phpipam.insecure_skip_verify,
            defaults.ipam.phpipam.insecure_skip_verify
        );
        assert_eq!(
            example.ipam.custom.script_path,
            defaults.ipam.custom.script_path
        );
        assert_eq!(example.ipam.custom.args, defaults.ipam.custom.args);
        assert_eq!(example.eab.enabled, defaults.eab.enabled);
        assert_eq!(example.notify.enabled, defaults.notify.enabled);
        assert_eq!(
            example.notify.custom_enabled,
            defaults.notify.custom_enabled
        );
        assert_eq!(example.notify.template_dir, defaults.notify.template_dir);
        assert_eq!(
            example.notify.email.smtp_port,
            defaults.notify.email.smtp_port
        );
        assert_eq!(
            example.notify.email.smtp_security,
            defaults.notify.email.smtp_security
        );
        assert_eq!(example.notify.email.events, defaults.notify.email.events);
        assert_eq!(
            example.notify.webhook_enabled,
            defaults.notify.webhook_enabled
        );
        assert_eq!(example.dns.resolver, defaults.dns.resolver);
        assert_eq!(example.proxy.http_url, defaults.proxy.http_url);
        assert_eq!(example.proxy.https_url, defaults.proxy.https_url);
        assert_eq!(example.proxy.no_proxy, defaults.proxy.no_proxy);
    }

    #[test]
    fn load_applies_env_overrides() {
        let _guard = EnvGuard::new(&[("ACME_PROXY_SERVER__BASE_URL", "https://acme.example.test")]);

        let config = Config::load().expect("load should succeed with env overrides");

        assert_eq!(config.server.base_url, "https://acme.example.test");
        assert_eq!(config.server.bind_address, "[::]:3000");
        assert_eq!(config.nonce.ttl_seconds, 300);
    }

    #[test]
    fn load_applies_eab_env_override() {
        let _guard = EnvGuard::new(&[("ACME_PROXY_EAB__ENABLED", "true")]);
        let config = Config::load().expect("load should succeed with eab env override");
        assert!(config.eab.enabled);
    }

    #[test]
    fn load_applies_dns_resolver_env_override() {
        let _guard = EnvGuard::new(&[("ACME_PROXY_DNS__RESOLVER", "10.60.0.2:53")]);
        let config = Config::load().expect("load should succeed with a dns resolver override");
        assert_eq!(config.dns.resolver.as_deref(), Some("10.60.0.2:53"));
    }

    #[test]
    fn load_treats_an_empty_string_list_env_var_as_no_values() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_FILTER__ENABLED", ""),
            ("ACME_PROXY_CHALLENGE__ENABLED", ""),
        ]);
        let config = Config::load().expect("an empty list env var must not be a parse error");
        assert!(config.filter.enabled.is_empty());
        assert!(config.challenge.enabled.is_empty());
    }

    #[test]
    fn load_applies_doubly_nested_env_overrides() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_SERVER__TLS__ENABLED", "true"),
            ("ACME_PROXY_SERVER__TLS__CERT_PATH", "/etc/acme/tls.pem"),
            ("ACME_PROXY_SERVER__TLS__HANDSHAKE_TIMEOUT_MS", "2500"),
        ]);

        let config = Config::load().expect("load should succeed with nested env overrides");

        assert!(config.server.tls.enabled);
        assert_eq!(config.server.tls.cert_path, "/etc/acme/tls.pem");
        assert_eq!(config.server.tls.handshake_timeout_ms, 2500);
        assert_eq!(config.server.tls.key_path, "server.key");
        assert_eq!(config.server.bind_address, "[::]:3000");
    }

    #[test]
    fn load_applies_local_ca_subject_env_overrides() {
        let _guard = EnvGuard::new(&[
            (
                "ACME_PROXY_SIGNER__LOCAL_CA__SUBJECT__COMMON_NAME",
                "Custom Root CA",
            ),
            (
                "ACME_PROXY_SIGNER__LOCAL_CA__SUBJECT__ORGANIZATION",
                "Example Corp",
            ),
            ("ACME_PROXY_SIGNER__LOCAL_CA__SUBJECT__COUNTRY", "US"),
        ]);

        let config =
            Config::load().expect("load should succeed with local_ca subject env overrides");

        assert_eq!(
            config.signer.local_ca.subject.common_name.as_deref(),
            Some("Custom Root CA")
        );
        assert_eq!(
            config.signer.local_ca.subject.organization.as_deref(),
            Some("Example Corp")
        );
        assert_eq!(
            config.signer.local_ca.subject.country.as_deref(),
            Some("US")
        );
        // Untouched keys, including sibling fields of the same nested table,
        // stay at their compiled defaults.
        assert!(config.signer.local_ca.subject.state.is_none());
        assert_eq!(config.signer.local_ca.cert_path, "ca.pem");
    }

    #[test]
    fn load_parses_list_valued_env_overrides() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_FILTER__RULES", "mgmt-bypass,inventory-owned"),
            (
                "ACME_PROXY_FILTER__CHECK__NET__ALLOW",
                "192.168.1.0/24,fd00::/8",
            ),
        ]);

        let config = Config::load().expect("load should succeed with list env overrides");

        assert_eq!(config.filter.rules, vec!["mgmt-bypass", "inventory-owned"]);
        assert_eq!(
            config.filter.check["net"].allow,
            vec!["192.168.1.0/24", "fd00::/8"]
        );
        assert_eq!(config.filter.forwarded_header, "x-forwarded-for");
    }

    #[test]
    fn every_registered_list_key_round_trips_through_the_environment() {
        let known = LIST_KEYS
            .iter()
            .filter(|key| Config::default().list_key(key).is_some())
            .count();
        assert_eq!(
            known,
            LIST_KEYS.len(),
            "every LIST_KEYS entry must be readable via `list_key`"
        );
        assert_eq!(
            LIST_KEYS.len(),
            21,
            "a config `Vec` field was added or removed: update LIST_KEYS, `list_key`, \
             config.toml.example and this count together"
        );

        for key in LIST_KEYS {
            let (first, second) = match *key {
                "challenge.enabled" => ("http-01", "dns-01"),
                "filter.rules" => ("mgmt-bypass", "inventory-owned"),
                "filter.exempt_paths" => ("/health", "/directory"),
                _ => ("first-value", "second-value"),
            };

            let env_key: &'static str = Box::leak(
                format!("ACME_PROXY_{}", key.replace('.', "__").to_uppercase()).into_boxed_str(),
            );
            let _guard = EnvGuard::new(&[(env_key, &format!("{first},{second}"))]);

            let config = Config::load().expect("load should succeed");
            let actual = config.list_key(key);
            assert_eq!(
                actual,
                Some(vec![first.to_string(), second.to_string()]),
                "{key} (via {env_key}) did not parse as a two-element list; \
                 is it registered in LIST_KEYS and reachable from `list_key`?"
            );
        }
    }
}
