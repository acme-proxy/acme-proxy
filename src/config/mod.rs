//! ACME Proxy Configuration Management

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

pub mod types;
pub use types::*;

/// Runtime configuration for the ACME proxy server.
///
/// The seven sections a profile can carry (`signer`, `filter`, `challenge`,
/// `eab`, `order`, `notify`, `meta`) are kept here as the **base every profile
/// inherits**; nothing serves them directly. The rest (`database`, `server`,
/// `admin`, `nonce`, `audit`, `logging`, `dns`) is process-wide and has no per-profile
/// form — an operator of the web admin manages every endpoint this process
/// serves, so `admin` in particular has no per-profile meaning, and `audit`
/// records one trail for the whole CA.
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
    pub logging: LoggingConfig,
    pub order: OrderConfig,
    pub signer: SignerConfig,
    pub challenge: ChallengeConfig,
    pub filter: FilterConfig,
    pub eab: EabConfig,
    pub notify: NotifyConfig,
    pub meta: MetaConfig,
    pub dns: DnsConfig,
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

/// Resolves a `<subsystem>.custom_enabled` list against the
/// `<subsystem>.custom` table, validating both halves.
///
/// Two subsystems grew this independently — `notify` factored it into a named
/// function, `filter` left it inline inside a `match` arm — and they must not
/// drift, because the name rule in particular carries reasoning that is not
/// obvious from the code: a custom entry's name is also an environment-variable
/// segment, which the `config` crate lowercases, so anything outside the
/// permitted set could name one entry in a file and a silently different one
/// through the environment.
///
/// `subsystem` is the configuration prefix (`"filter"` / `"notify"`), used only
/// to word the errors so an operator is told which key to go and look at.
pub(crate) fn resolve_custom_entries<'a, T>(
    subsystem: &str,
    entries: &'a BTreeMap<String, T>,
    enabled: &'a [String],
) -> anyhow::Result<Vec<(&'a str, &'a T)>> {
    for key in entries.keys() {
        anyhow::ensure!(
            valid_config_key_name(key),
            "{subsystem}.custom.{key}: invalid name (use lowercase letters, digits and `-` \
             — a custom-{subsystem} name is also an environment variable segment, and the \
             config crate lowercases those, so anything else could silently name a \
             different entry through ACME_PROXY_{}__CUSTOM__… than in the file)",
            subsystem.to_ascii_uppercase()
        );
    }
    anyhow::ensure!(
        !enabled.is_empty(),
        "{subsystem}.custom is enabled but {subsystem}.custom_enabled is empty; \
         list the [{subsystem}.custom.<name>] entries to run, or remove `custom` from \
         {subsystem}.enabled"
    );

    enabled
        .iter()
        .map(|name| {
            let entry = entries.get(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "{subsystem}.custom_enabled names `{name}`, but no \
                     [{subsystem}.custom.{name}] is configured"
                )
            })?;
            Ok((name.as_str(), entry))
        })
        .collect()
}

/// Profile names are URL segments (`/profile/<name>`) as well as config-key
/// names; see [`valid_config_key_name`].
fn valid_profile_name(name: &str) -> bool {
    valid_config_key_name(name)
}

const LIST_KEYS: &[&str] = &[
    "challenge.enabled",
    "filter.enabled",
    "filter.exempt_paths",
    "filter.trusted_proxies",
    "filter.allowed_ip.allow",
    "filter.allowed_ip.deny",
    "filter.reverse_dns.allow",
    "filter.reverse_dns.deny",
    "filter.identifiers.allowed_types",
    "filter.identifiers.allow",
    "filter.identifiers.deny",
    "filter.custom_enabled",
    "signer.acme_proxy.contact",
    "signer.custom.args",
    "notify.enabled",
    "notify.email.to",
    "notify.email.events",
    "notify.mattermost.events",
    "notify.custom_enabled",
    "meta.caa_identities",
];

impl Config {
    #[cfg(test)]
    fn list_key(&self, key: &str) -> Option<Vec<String>> {
        let value = match key {
            "challenge.enabled" => &self.challenge.enabled,
            "filter.enabled" => &self.filter.enabled,
            "filter.exempt_paths" => &self.filter.exempt_paths,
            "filter.trusted_proxies" => &self.filter.trusted_proxies,
            "filter.allowed_ip.allow" => &self.filter.allowed_ip.allow,
            "filter.allowed_ip.deny" => &self.filter.allowed_ip.deny,
            "filter.reverse_dns.allow" => &self.filter.reverse_dns.allow,
            "filter.reverse_dns.deny" => &self.filter.reverse_dns.deny,
            "filter.identifiers.allowed_types" => &self.filter.identifiers.allowed_types,
            "filter.identifiers.allow" => &self.filter.identifiers.allow,
            "filter.identifiers.deny" => &self.filter.identifiers.deny,
            "filter.custom_enabled" => &self.filter.custom_enabled,
            "signer.acme_proxy.contact" => &self.signer.acme_proxy.contact,
            "signer.custom.args" => &self.signer.custom.args,
            "notify.enabled" => &self.notify.enabled,
            "notify.email.to" => &self.notify.email.to,
            "notify.email.events" => &self.notify.email.events,
            "notify.mattermost.events" => &self.notify.mattermost.events,
            "notify.custom_enabled" => &self.notify.custom_enabled,
            "meta.caa_identities" => &self.meta.caa_identities,
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
        // One level deeper than the above: `filter.custom.<name>.args` is a
        // list nested inside a table keyed by a name only known at runtime,
        // same reasoning as the profile-scoped loop just above (and as
        // `profiles_in_env` itself).
        for name in names_in_env("ACME_PROXY_FILTER__CUSTOM__") {
            environment = environment.with_list_parse_key(&format!("filter.custom.{name}.args"));
        }
        for profile in &profiles_in_env {
            let prefix = format!(
                "ACME_PROXY_PROFILES__{}__FILTER__CUSTOM__",
                profile.to_ascii_uppercase()
            );
            for name in names_in_env(&prefix) {
                environment = environment
                    .with_list_parse_key(&format!("profiles.{profile}.filter.custom.{name}.args"));
            }
        }
        // Same reasoning, one level deeper: `notify.custom.<name>` is also a
        // table keyed by a runtime name, and it has two nested list fields.
        for name in names_in_env("ACME_PROXY_NOTIFY__CUSTOM__") {
            environment = environment.with_list_parse_key(&format!("notify.custom.{name}.args"));
            environment = environment.with_list_parse_key(&format!("notify.custom.{name}.events"));
        }
        for profile in &profiles_in_env {
            let prefix = format!(
                "ACME_PROXY_PROFILES__{}__NOTIFY__CUSTOM__",
                profile.to_ascii_uppercase()
            );
            for name in names_in_env(&prefix) {
                environment = environment
                    .with_list_parse_key(&format!("profiles.{profile}.notify.custom.{name}.args"));
                environment = environment.with_list_parse_key(&format!(
                    "profiles.{profile}.notify.custom.{name}.events"
                ));
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

/// The first `__`-delimited segment after `prefix`, for every environment
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

    struct EnvGuard {
        keys: Vec<&'static str>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new(vars: &[(&'static str, &str)]) -> Self {
            let _lock = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut keys = vec!["ACME_PROXY_CONFIG"];
            unsafe {
                std::env::set_var("ACME_PROXY_CONFIG", "/nonexistent/acme-proxy-config");
                for (key, value) in vars {
                    std::env::set_var(key, value);
                    keys.push(key);
                }
            }
            Self { keys, _lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                for key in &self.keys {
                    std::env::remove_var(key);
                }
            }
        }
    }

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
            identifiers.deny = ["a\\.example", "b\\.example"]

            [profiles.narrow]
            filter.identifiers.deny = ["c\\.example"]
            "#,
        );

        let profiles = config.resolve_profiles().unwrap();
        assert_eq!(
            profiles[0].sections.filter.identifiers.deny,
            vec!["c\\.example"],
            "arrays are replaced, never merged"
        );
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

    /// `filter.custom` entries are named tables, not a list — so unlike an
    /// ordinary `LIST_KEYS` entry they need their own `with_list_parse_key`
    /// registration for the nested `args` list, keyed by a name only known
    /// at runtime (the same reason `filter.custom_enabled` alone isn't
    /// enough to reconstruct a script's full configuration from env vars).
    #[test]
    fn env_configures_multiple_named_custom_scripts() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_FILTER__CUSTOM_ENABLED", "main,extra"),
            (
                "ACME_PROXY_FILTER__CUSTOM__MAIN__SCRIPT_PATH",
                "/path/to/one.sh",
            ),
            ("ACME_PROXY_FILTER__CUSTOM__MAIN__ARGS", "foo,bar"),
            (
                "ACME_PROXY_FILTER__CUSTOM__EXTRA__SCRIPT_PATH",
                "/path/to/two.sh",
            ),
        ]);

        let config = Config::load().expect("load should succeed");
        assert_eq!(
            config.filter.custom_enabled,
            vec!["main".to_string(), "extra".to_string()]
        );
        assert_eq!(
            config.filter.custom.get("main").unwrap().script_path,
            "/path/to/one.sh"
        );
        assert_eq!(
            config.filter.custom.get("main").unwrap().args,
            vec!["foo".to_string(), "bar".to_string()]
        );
        assert_eq!(
            config.filter.custom.get("extra").unwrap().script_path,
            "/path/to/two.sh"
        );
    }

    /// The same, scoped to one profile — proving the runtime name scan also
    /// covers `ACME_PROXY_PROFILES__<NAME>__FILTER__CUSTOM__<NAME>__…`.
    #[test]
    fn env_configures_a_profile_scoped_named_custom_script() {
        let file = TempConfig::new("[profiles.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_PROFILES__LE__FILTER__CUSTOM_ENABLED", "main"),
            (
                "ACME_PROXY_PROFILES__LE__FILTER__CUSTOM__MAIN__SCRIPT_PATH",
                "/path/to/profile.sh",
            ),
            (
                "ACME_PROXY_PROFILES__LE__FILTER__CUSTOM__MAIN__ARGS",
                "a,b,c",
            ),
        ]);

        let config = Config::load().unwrap();
        let profiles = config.resolve_profiles().unwrap();
        let custom = &profiles[0].sections.filter.custom;
        assert_eq!(
            custom.get("main").unwrap().script_path,
            "/path/to/profile.sh"
        );
        assert_eq!(
            custom.get("main").unwrap().args,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    /// The old (pre-list) unindexed shape
    /// (`ACME_PROXY_FILTER__CUSTOM__SCRIPT_PATH`, with no name segment) is a
    /// clear load-time error rather than something silently accepted or
    /// ignored: `filter.custom` is now a table of *named* entries, so the
    /// missing name segment makes `script_path`'s plain string value land
    /// exactly where one script's whole table is expected.
    #[test]
    fn the_old_unindexed_custom_filter_env_shape_is_a_clear_load_error() {
        let _guard = EnvGuard::new(&[(
            "ACME_PROXY_FILTER__CUSTOM__SCRIPT_PATH",
            "/should/not/work.sh",
        )]);

        let error = Config::load().unwrap_err().to_string();
        assert!(error.contains("filter.custom.script_path"), "{error}");
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
        assert!(config.filter.enabled.is_empty());
        assert!(config.filter.exempt_paths.is_empty());
        assert!(config.filter.trusted_proxies.is_empty());
        assert_eq!(config.filter.forwarded_header, "x-forwarded-for");
        assert!(config.filter.allowed_ip.allow.is_empty());
        assert!(config.filter.allowed_ip.deny.is_empty());
        assert!(config.filter.reverse_dns.require_forward_confirm);
        assert!(config.filter.reverse_dns.allow.is_empty());
        assert!(config.filter.reverse_dns.deny.is_empty());
        assert_eq!(config.filter.reverse_dns.timeout_ms, 2000);
        assert_eq!(
            config.filter.identifiers.allowed_types,
            vec!["dns".to_string(), "cn".to_string()]
        );
        assert!(config.filter.identifiers.allow.is_empty());
        assert!(config.filter.identifiers.deny.is_empty());
        assert!(!config.filter.identifiers.allow_wildcards);
        assert!(config.filter.custom.is_empty());
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
        assert_eq!(config.notify.mattermost.events, config.notify.email.events);
        assert!(config.dns.resolver.is_none());
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
        assert_eq!(loaded.filter.exempt_paths, direct.filter.exempt_paths);
        assert_eq!(
            loaded.filter.identifiers.allowed_types,
            direct.filter.identifiers.allowed_types
        );
        assert_eq!(loaded.eab.enabled, direct.eab.enabled);
        assert_eq!(loaded.dns.resolver, direct.dns.resolver);
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
        assert_eq!(example.filter.enabled, defaults.filter.enabled);
        assert_eq!(example.filter.exempt_paths, defaults.filter.exempt_paths);
        assert_eq!(
            example.filter.forwarded_header,
            defaults.filter.forwarded_header
        );
        assert_eq!(
            example.filter.reverse_dns.require_forward_confirm,
            defaults.filter.reverse_dns.require_forward_confirm
        );
        assert_eq!(
            example.filter.reverse_dns.timeout_ms,
            defaults.filter.reverse_dns.timeout_ms
        );
        assert_eq!(
            example.filter.identifiers.allowed_types,
            defaults.filter.identifiers.allowed_types
        );
        assert_eq!(
            example.filter.identifiers.allow_wildcards,
            defaults.filter.identifiers.allow_wildcards
        );
        assert_eq!(example.filter.netbox.url, defaults.filter.netbox.url);
        assert_eq!(example.filter.netbox.token, defaults.filter.netbox.token);
        assert_eq!(
            example.filter.netbox.custom_field,
            defaults.filter.netbox.custom_field
        );
        assert_eq!(
            example.filter.netbox.use_dns_name,
            defaults.filter.netbox.use_dns_name
        );
        assert_eq!(
            example.filter.netbox.device_fallback,
            defaults.filter.netbox.device_fallback
        );
        assert_eq!(
            example.filter.netbox.ca_cert_path,
            defaults.filter.netbox.ca_cert_path
        );
        assert_eq!(
            example.filter.netbox.insecure_skip_verify,
            defaults.filter.netbox.insecure_skip_verify
        );
        assert_eq!(
            example.filter.netbox.timeout_ms,
            defaults.filter.netbox.timeout_ms
        );
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
            example.notify.mattermost.events,
            defaults.notify.mattermost.events
        );
        assert_eq!(example.dns.resolver, defaults.dns.resolver);
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
            ("ACME_PROXY_FILTER__ENABLED", "allowed_ip,identifiers"),
            (
                "ACME_PROXY_FILTER__ALLOWED_IP__ALLOW",
                "192.168.1.0/24,fd00::/8",
            ),
        ]);

        let config = Config::load().expect("load should succeed with list env overrides");

        assert_eq!(config.filter.enabled, vec!["allowed_ip", "identifiers"]);
        assert_eq!(
            config.filter.allowed_ip.allow,
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
            20,
            "a config `Vec` field was added or removed: update LIST_KEYS, `list_key`, \
             config.toml.example and this count together"
        );

        for key in LIST_KEYS {
            let (first, second) = match *key {
                "challenge.enabled" => ("http-01", "dns-01"),
                "filter.enabled" => ("allowed_ip", "identifiers"),
                "filter.exempt_paths" => ("/health", "/directory"),
                "filter.identifiers.allowed_types" => ("dns", "cn"),
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
