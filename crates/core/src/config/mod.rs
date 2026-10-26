//! The configuration: one [`Config`], loaded once by [`Config::load`] and
//! rebuilt on every reload.
//!
//! Three layers, lowest first: the compiled defaults (each section's
//! `Default`), an optional TOML file (`config.toml`, or `ACME_PROXY_CONFIG`),
//! and `ACME_PROXY_*` environment variables with `__` between nested keys.
//! [`Config::resolve_endpoints`] then builds each `[endpoints.<name>]` endpoint
//! by overlaying it on the global sections in `ENDPOINT_SECTIONS`, **key by
//! key**: an endpoint changing one knob keeps the rest of the section, while an
//! array is replaced whole, never extended.
//!
//! The traps, each guarded by a test here:
//!
//! - **Every list field carries `deserialize_with = "string_list"`**, which
//!   splits a comma-separated environment value at any depth. There is no
//!   registry of list keys; `every_list_field_reads_a_comma_separated_string`
//!   refuses a field without it.
//! - **The environment source pins `prefix_separator("_")`**; without it the
//!   `config` crate ignores every `ACME_PROXY_*` variable.
//! - **A removed key stays a field** so it still parses and can be refused by
//!   name — an unknown key is otherwise dropped silently.
//! - **A test that calls `Config::load` holds [`ENV_LOCK`]**: the environment
//!   is process-wide.

use std::collections::BTreeMap;

use serde::Deserialize;

pub mod types;
pub use types::*;

/// Runtime configuration for the ACME proxy server.
///
/// The eight sections an endpoint can carry (`signer`, `filter`, `ipam`,
/// `challenge`, `eab`, `order`, `notify`, `meta`) are kept here as the **base
/// every endpoint inherits**; nothing serves them directly. The rest (`database`, `server`,
/// `admin`, `nonce`, `audit`, `jobs`, `metrics`, `logging`, `dns`, `proxy`) is process-wide and has no
/// per-endpoint form — an operator of the web admin manages every endpoint this process
/// serves, so `admin` in particular has no per-endpoint meaning, `audit`
/// records one trail for the whole CA, and `jobs` drains one queue.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    /// The web admin listener. Process-wide, so deliberately absent from
    /// [`ENDPOINT_SECTIONS`].
    pub admin: AdminConfig,
    pub nonce: NonceConfig,
    /// Traceability and the CA's audit trail. Process-wide for the reason
    /// [`AuditConfig`] gives, so also absent from [`ENDPOINT_SECTIONS`].
    pub audit: AuditConfig,
    /// The durable background-work queue. Process-wide for the reason
    /// [`JobsConfig`] gives, so also absent from [`ENDPOINT_SECTIONS`].
    pub jobs: JobsConfig,
    /// The Prometheus exposition endpoint. Process-wide for the reason
    /// [`MetricsConfig`] gives, so also absent from [`ENDPOINT_SECTIONS`].
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub order: OrderConfig,
    pub signer: SignerConfig,
    pub challenge: ChallengeConfig,
    pub filter: FilterConfig,
    /// The inventory the `ipam` filter consults. Per-endpoint, so two endpoints
    /// may consult different ones — and read by nothing unless that filter is
    /// enabled.
    pub ipam: IpamConfig,
    pub eab: EabConfig,
    pub notify: NotifyConfig,
    pub meta: MetaConfig,
    pub dns: DnsConfig,
    /// The forward proxy every outbound client dials through. Process-wide for
    /// the reason [`ProxyConfig`] gives, so also absent from
    /// [`ENDPOINT_SECTIONS`].
    pub proxy: ProxyConfig,
    /// The configuration sources as they were read, *before* serde filled in
    /// any default — the only form in which "unset" and "set to the default
    /// value" can still be told apart, which is what per-key inheritance
    /// needs. Populated by [`Config::load`]; `None` for a `Config` built in
    /// code (tests, `Config::default`), which simply has no endpoints to
    /// resolve.
    #[serde(skip)]
    raw: Option<::config::Config>,
}

/// The sections an endpoint may override, in the order they are documented.
const ENDPOINT_SECTIONS: &[&str] = &[
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
/// Used for endpoint names (`[endpoints.<name>]` / `ACME_PROXY_ENDPOINTS__<NAME>__…`),
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
pub fn resolve_named_entries<'a, T>(
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
pub fn validate_key_names<'a>(
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

/// Endpoint names are URL segments (`/endpoint/<name>`) as well as config-key
/// names; see [`valid_config_key_name`].
fn valid_endpoint_name(name: &str) -> bool {
    valid_config_key_name(name)
}

impl Config {
    /// Loads configuration from defaults, TOML file, and environment variables.
    pub fn load() -> Result<Self, ::config::ConfigError> {
        let path = std::env::var("ACME_PROXY_CONFIG").unwrap_or_else(|_| "config".into());

        // No list separator and no list keys: `config` can only split a key it
        // is told about by its full literal path, which a list inside an endpoint
        // or inside an operator-named table never has. Every list field splits
        // its own string instead, through `types::string_list`.
        let environment = ::config::Environment::with_prefix("ACME_PROXY")
            .prefix_separator("_")
            .separator("__")
            .try_parsing(true);

        let built = ::config::Config::builder()
            .add_source(::config::File::with_name(&path).required(false))
            .add_source(environment)
            .build()?;

        let table: ::config::Map<String, ::config::Value> = built.clone().try_deserialize()?;
        let root = ::config::Value::new(None, ::config::ValueKind::Table(table));
        refuse_unit_suffixed_keys(&root, "")?;
        let mut config: Config = built.clone().try_deserialize()?;
        config.raw = Some(built);
        Ok(config)
    }

    /// The endpoints this configuration mounts, each fully populated: what the
    /// endpoint states, over what the matching global section states, over the
    /// compiled defaults — resolved key by key, not section by section, so a
    /// endpoint changing one knob keeps the rest of the global section.
    ///
    /// Fails when nothing is left to serve: endpoints are the only way to serve
    /// ACME at all, and a server that silently answers nothing would be worse
    /// than one that refuses to start.
    pub fn resolve_endpoints(&self) -> anyhow::Result<Vec<EndpointConfig>> {
        // Read off the raw sources, which hold every key a file or the
        // environment wrote whether or not a field still declares it: the
        // renamed table needs no dead field to be refused by name.
        let has_old_table = self
            .raw
            .as_ref()
            .is_some_and(|raw| raw.get::<::config::Value>("profiles").is_ok());
        anyhow::ensure!(
            !has_old_table,
            "`[profiles.<name>]` was renamed to `[endpoints.<name>]` \
             (`ACME_PROXY_PROFILES__…` to `ACME_PROXY_ENDPOINTS__…`), and each one is now \
             served at `/endpoint/<name>/` instead of `/profile/<name>/`"
        );

        let raw_endpoints = self
            .raw
            .as_ref()
            .and_then(|raw| raw.get::<::config::Value>("endpoints").ok())
            .map(as_table)
            .unwrap_or_default();

        let mut endpoints = Vec::new();
        // A `BTreeMap` rather than the source's own ordering: mount order, log
        // order and error messages must not depend on how a file was written.
        for (name, raw_endpoint) in raw_endpoints.into_iter().collect::<BTreeMap<_, _>>() {
            anyhow::ensure!(
                valid_endpoint_name(&name),
                "invalid endpoint name `{name}`: use lowercase letters, digits and `-` \
                 (the name is both a URL segment and an environment variable segment)"
            );

            let sections = self.merged_sections(&raw_endpoint).map_err(|error| {
                anyhow::anyhow!("endpoint `{name}`: invalid configuration: {error}")
            })?;

            if sections.enabled {
                endpoints.push(EndpointConfig { name, sections });
            }
        }

        anyhow::ensure!(!endpoints.is_empty(), self.no_endpoints_message());
        Ok(endpoints)
    }

    /// Deserializes one endpoint, each of its sections overlaid on the global
    /// one first. Both sides are the *raw* values, so a key nobody wrote falls
    /// through to serde's own default rather than to a default masquerading as
    /// a global setting.
    fn merged_sections(
        &self,
        raw_endpoint: &::config::Value,
    ) -> Result<EndpointSections, ::config::ConfigError> {
        let endpoint_table = as_table(raw_endpoint.clone());
        let mut merged = endpoint_table.clone();

        for section in ENDPOINT_SECTIONS {
            let global = self
                .raw
                .as_ref()
                .and_then(|raw| raw.get::<::config::Value>(section).ok());
            let overlay = endpoint_table.get(*section).cloned();

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

        EndpointSections::deserialize(::config::Value::new(
            None,
            ::config::ValueKind::Table(merged),
        ))
    }

    /// The startup error for a configuration that mounts nothing — written to
    /// be copy-pasteable, since "no endpoints" is what every first run hits.
    fn no_endpoints_message(&self) -> String {
        format!(
            "no enabled [endpoints] — acme-proxy serves nothing without one. Minimal config:\n\
             \n    [endpoints.default]\n\n\
             Its ACME directory is then at {}/endpoint/default/directory.",
            self.server.base_url
        )
    }
}

/// A value's table, or an empty one for anything else (including absent).
/// Every key that held a length of time as a bare number with its unit in the
/// name, and the [`ConfigDuration`] key that replaced it.
const UNIT_SUFFIXED_KEYS: &[(&str, &str)] = &[
    ("admission_wait_ms", "admission_wait"),
    ("delay_secs", "delay"),
    ("handshake_timeout_ms", "handshake_timeout"),
    ("interval_days", "interval"),
    ("lead_days", "lead"),
    ("leaf_validity_days", "leaf_validity"),
    ("lease_seconds", "lease"),
    ("login_window_seconds", "login_window"),
    ("poll_interval_ms", "poll_interval"),
    ("poll_timeout_secs", "poll_timeout"),
    ("request_timeout_ms", "request_timeout"),
    ("retention_days", "retention"),
    ("retry_base_seconds", "retry_base"),
    ("retry_max_seconds", "retry_max"),
    ("reverse_dns_timeout_ms", "reverse_dns_timeout"),
    ("session_idle_timeout_seconds", "session_idle_timeout"),
    ("session_ttl_seconds", "session_ttl"),
    ("timeout_ms", "timeout"),
    ("ttl_seconds", "ttl"),
    ("validity_seconds", "validity"),
];

/// Refuses, by name, any key [`UNIT_SUFFIXED_KEYS`] retired — at the top level,
/// inside an `[endpoints.<name>]` overlay, or inside an operator-named entry
/// such as `[filter.custom.<name>]`.
///
/// Walked over the raw sources rather than declared as dead fields: serde
/// drops an unknown key without a word, so the refusal must look at what was
/// written, and one walk covers every nesting a key can appear at. The message
/// carries the value converted, so the fix can be pasted.
fn refuse_unit_suffixed_keys(
    value: &::config::Value,
    path: &str,
) -> Result<(), ::config::ConfigError> {
    let ::config::ValueKind::Table(table) = &value.kind else {
        return Ok(());
    };
    for (key, child) in table {
        let here = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if let Some((_, renamed)) = UNIT_SUFFIXED_KEYS.iter().find(|(old, _)| old == key) {
            let unit = match key.rsplit('_').next() {
                Some("ms") => "ms",
                Some("days") => "d",
                _ => "s",
            };
            let example = child
                .clone()
                .into_uint()
                .map_or_else(|_| format!("30{unit}"), |number| format!("{number}{unit}"));
            let new_path = format!("{}{renamed}", here.strip_suffix(key.as_str()).unwrap_or(""));
            return Err(::config::ConfigError::Message(format!(
                "`{here}` was renamed to `{new_path}`, which takes a duration with its \
                 unit: `{renamed} = \"{example}\"`"
            )));
        }
        refuse_unit_suffixed_keys(child, &here)?;
    }
    Ok(())
}

fn as_table(value: ::config::Value) -> ::config::Map<String, ::config::Value> {
    match value.kind {
        ::config::ValueKind::Table(table) => table,
        _ => ::config::Map::new(),
    }
}

/// Overlays `overlay` on `base`, recursing into tables.
///
/// Scalars **and arrays** are replaced wholesale: an inherited list an endpoint
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
#[cfg(any(test, feature = "test-util"))]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::EnvGuard;

    /// A throwaway directory holding one `config.toml`, removed on drop.
    ///
    /// Endpoint resolution reads the *raw* configuration sources, so it can only
    /// be exercised through `Config::load()` — a `Config` built in code has no
    /// sources to merge and therefore no endpoints at all.
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

    /// [`load_toml`] for a configuration that must be refused, with `env` set
    /// beside it.
    fn load_toml_error(body: &str, env: &[(&str, &str)]) -> String {
        let file = TempConfig::new(body);
        let path = file.path();
        let mut vars = vec![("ACME_PROXY_CONFIG", path.as_str())];
        vars.extend_from_slice(env);
        let _guard = EnvGuard::new(&vars);
        Config::load()
            .expect_err("the configuration must be refused")
            .to_string()
    }

    /// A unit-suffixed key is refused by name wherever it is written, with the
    /// value converted into its replacement so the fix can be pasted.
    #[test]
    fn a_unit_suffixed_key_is_refused_by_name_at_every_depth() {
        for (body, env, old, replacement) in [
            (
                "[order]\nvalidity_seconds = 3600\n",
                &[][..],
                "`order.validity_seconds`",
                "`validity = \"3600s\"`",
            ),
            (
                "[endpoints.le.signer.local_ca]\nleaf_validity_days = 7\n",
                &[],
                "`endpoints.le.signer.local_ca.leaf_validity_days`",
                "`leaf_validity = \"7d\"`",
            ),
            (
                "[filter.custom.gate]\ntimeout_ms = 250\n",
                &[],
                "`filter.custom.gate.timeout_ms`",
                "`timeout = \"250ms\"`",
            ),
            (
                "",
                &[("ACME_PROXY_JOBS__LEASE_SECONDS", "60")],
                "`jobs.lease_seconds`",
                "`lease = \"60s\"`",
            ),
        ] {
            let error = load_toml_error(body, env);
            assert!(error.contains(old), "{error}");
            assert!(error.contains(replacement), "{error}");
        }
    }

    /// A duration is written with its unit, from a file and from the
    /// environment, and an endpoint overriding one keeps the global section's
    /// other keys — strings overlay key by key the way numbers did.
    #[test]
    fn durations_load_with_their_unit_and_overlay_per_endpoint() {
        let file = TempConfig::new(
            r#"
            [order]
            validity = "2h"
            retention = "3d"

            [endpoints.short.order]
            validity = "30m"

            [endpoints.long]
            "#,
        );
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_NONCE__TTL", "90s"),
        ]);
        let config = Config::load().unwrap();
        assert_eq!(config.nonce.ttl, ConfigDuration::from_secs(90));

        let endpoints = config.resolve_endpoints().unwrap();
        let order = |name: &str| {
            endpoints
                .iter()
                .find(|endpoint| endpoint.name == name)
                .unwrap()
                .sections
                .order
                .clone()
        };
        assert_eq!(order("short").validity, ConfigDuration::from_mins(30));
        assert_eq!(order("short").retention, ConfigDuration::from_days(3));
        assert_eq!(order("long").validity, ConfigDuration::from_hours(2));
    }

    /// A bare number has no unit, from the environment too, where
    /// `try_parsing` has already turned it into an integer.
    #[test]
    fn a_bare_number_is_refused_for_a_duration() {
        let error = load_toml_error("[order]\nvalidity = 3600\n", &[]);
        assert!(error.contains("bare number has no unit"), "{error}");
        let error = load_toml_error("", &[("ACME_PROXY_NONCE__TTL", "300")]);
        assert!(error.contains("bare number has no unit"), "{error}");
    }

    /// Every length of time is a [`ConfigDuration`]: a field named for its unit
    /// is the shape this replaced, and one coming back would bring the
    /// ambiguity with it.
    #[test]
    fn no_configuration_field_carries_a_unit_in_its_name() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/types");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let source = std::fs::read_to_string(&path).unwrap();
            for line in source.lines() {
                let Some(name) = line
                    .trim_start()
                    .strip_prefix("pub ")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(name, _)| name)
                else {
                    continue;
                };
                assert!(
                    !["_ms", "_secs", "_seconds", "_days"]
                        .iter()
                        .any(|unit| name.ends_with(unit)),
                    "{}: `{name}` should be a ConfigDuration named without its unit",
                    path.display()
                );
            }
        }
    }

    /// The removed `[filter]` sub-tables have to land somewhere, or the
    /// `config` crate drops them and `filter::build` never sees them to refuse.
    #[test]
    fn the_removed_filter_sub_tables_still_parse() {
        let config = load_toml(
            r#"
            [filter.allowed_ip]
            allow = ["10.0.0.0/8"]

            [filter.reverse_dns]
            suffixes = ["example.com"]

            [filter.identifiers]
            allow = ["*.example.com"]

            [filter.custom.hook]
            command = "/bin/true"

            [filter.netbox]
            url = "https://netbox.example.com"

            [endpoints.le]
            "#,
        );

        assert!(config.filter.allowed_ip.is_some());
        assert!(config.filter.reverse_dns.is_some());
        assert!(config.filter.identifiers.is_some());
        assert!(config.filter.custom.is_some());
        assert!(config.filter.netbox.is_some());
    }

    #[test]
    fn a_bare_endpoint_table_inherits_every_global_section() {
        let config = load_toml(
            r#"
            [challenge]
            enabled = ["dns-01"]
            bypass = false

            [endpoints.le]
            "#,
        );

        let endpoints = config.resolve_endpoints().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "le");
        assert_eq!(endpoints[0].sections.challenge.enabled, vec!["dns-01"]);
        assert!(!endpoints[0].sections.challenge.bypass);
        // Untouched globally *and* by the endpoint: the compiled default.
        assert_eq!(endpoints[0].sections.signer.backend, "local_ca");
    }

    /// The trap section-level inheritance would fall into: an endpoint that
    /// overrides one knob of a section must keep the rest of the **global**
    /// section, not silently fall back to the compiled defaults.
    #[test]
    fn overriding_one_key_keeps_the_rest_of_the_global_section() {
        let config = load_toml(
            r#"
            [challenge]
            enabled = ["dns-01"]
            bypass = true
            timeout = "1234ms"

            [endpoints.strict]
            challenge.bypass = false
            "#,
        );

        let endpoints = config.resolve_endpoints().unwrap();
        let challenge = &endpoints[0].sections.challenge;
        assert!(!challenge.bypass, "the endpoint's own value wins");
        assert_eq!(
            challenge.enabled,
            vec!["dns-01"],
            "the rest of the section is inherited, not reset to the default"
        );
        assert_eq!(challenge.timeout.as_millis(), 1234);
    }

    /// `ipam` is per-endpoint, which is the whole reason it is a section rather
    /// than a process-wide one: two endpoints of the same server may consult
    /// different inventories, and each keeps the rest of the global section.
    #[test]
    fn two_endpoints_may_name_different_inventories() {
        let config = load_toml(
            r#"
            [ipam]
            backend = "netbox"
            timeout = "1234ms"

            [ipam.netbox]
            url = "https://netbox.example.com"
            token = "t0ken"

            [ipam.phpipam]
            url = "https://ipam.example.com"
            token = "appcode"

            [endpoints.dmz]

            [endpoints.internal]
            ipam.backend = "phpipam"
            "#,
        );

        let endpoints = config.resolve_endpoints().unwrap();
        let by_name = |name: &str| {
            endpoints
                .iter()
                .find(|p| p.name == name)
                .map(|p| &p.sections.ipam)
                .unwrap()
        };

        assert_eq!(by_name("dmz").backend, "netbox");
        assert_eq!(by_name("internal").backend, "phpipam");
        // …and overriding the one key keeps the rest of the global section,
        // both the sibling tables and the budget.
        assert_eq!(by_name("internal").timeout.as_millis(), 1234);
        assert_eq!(by_name("internal").phpipam.url, "https://ipam.example.com");
        assert_eq!(by_name("internal").netbox.url, "https://netbox.example.com");
    }

    /// An endpoint may narrow what its inventory is trusted for without
    /// restating the connection details — the per-key inheritance rule applied
    /// to the one list that decides how much an address may claim.
    #[test]
    fn an_endpoint_may_narrow_the_ipam_sources_alone() {
        let config = load_toml(
            r#"
            [ipam]
            backend = "netbox"

            [ipam.netbox]
            url = "https://netbox.example.com"
            token = "t0ken"
            sources = ["dns_name", "custom_field", "device", "fhrp"]

            [endpoints.strict]
            ipam.netbox.sources = ["dns_name"]
            "#,
        );

        let netbox = &config.resolve_endpoints().unwrap()[0].sections.ipam.netbox;
        assert_eq!(netbox.sources, vec!["dns_name"]);
        assert_eq!(netbox.url, "https://netbox.example.com");
        assert_eq!(netbox.token, "t0ken");
    }

    /// `notify` joins `ENDPOINT_SECTIONS` like every other subsystem: an endpoint
    /// overriding one knob keeps the rest of the *global* `[notify]` section
    /// rather than resetting to compiled defaults.
    #[test]
    fn an_endpoint_can_override_one_notify_key_and_keep_the_rest() {
        let config = load_toml(
            r#"
            [notify]
            enabled = ["email"]
            email.smtp_host = "mail.example.com"
            email.smtp_port = 2525

            [endpoints.staging]
            notify.email.smtp_host = "mail.staging.example.com"
            "#,
        );

        let endpoints = config.resolve_endpoints().unwrap();
        let notify = &endpoints[0].sections.notify;
        assert_eq!(notify.enabled, vec!["email"], "inherited from global");
        assert_eq!(notify.email.smtp_host, "mail.staging.example.com");
        assert_eq!(
            notify.email.smtp_port, 2525,
            "the rest of the section is inherited, not reset to the default"
        );
    }

    #[test]
    fn an_endpoint_section_replaces_an_inherited_list_wholesale() {
        let config = load_toml(
            r#"
            [filter]
            check.names.deny = ["a.example", "b.example"]

            [endpoints.narrow]
            filter.check.names.deny = ["c.example"]
            "#,
        );

        let endpoints = config.resolve_endpoints().unwrap();
        assert_eq!(
            endpoints[0].sections.filter.check["names"].deny,
            vec!["c.example"],
            "arrays are replaced, never merged"
        );
    }

    /// The other half of the inheritance promise, and the reason
    /// `[filter.rule.<name>]` is a map rather than an array of tables: a
    /// endpoint overrides one field of one rule and inherits the rest, which an
    /// array could not express at all.
    #[test]
    fn an_endpoint_overrides_one_field_of_an_inherited_rule() {
        let config = load_toml(
            r#"
            [filter]
            rules = ["inventory"]
            rule.inventory.when = "inv"
            rule.inventory.then = "allow"
            rule.inventory.message = "not yours"

            [endpoints.staging]
            filter.rule.inventory.mode = "warn"
            "#,
        );

        let rule = &config.resolve_endpoints().unwrap()[0].sections.filter.rule["inventory"];
        assert_eq!(rule.mode, "warn");
        assert_eq!(rule.when, "inv", "the condition is inherited");
        assert_eq!(rule.message, "not yours", "so is the message");
    }

    #[test]
    fn endpoints_are_resolved_in_name_order() {
        let config = load_toml(
            r#"
            [endpoints.zulu]
            [endpoints.alpha]
            [endpoints.mike]
            "#,
        );

        let names: Vec<_> = config
            .resolve_endpoints()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn a_disabled_endpoint_is_not_mounted() {
        let config = load_toml(
            r#"
            [endpoints.live]

            [endpoints.parked]
            enabled = false
            "#,
        );

        let names: Vec<_> = config
            .resolve_endpoints()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["live"]);
    }

    #[test]
    fn a_configuration_with_no_endpoint_refuses_to_resolve() {
        for body in ["", "[endpoints]\n", "[endpoints.parked]\nenabled = false\n"] {
            let config = load_toml(body);
            let error = config
                .resolve_endpoints()
                .expect_err("a server with no endpoint must not start")
                .to_string();
            assert!(error.contains("[endpoints.default]"), "{error}");
            assert!(
                error.contains("/endpoint/default/directory"),
                "the error must show where the endpoint would answer: {error}"
            );
        }
    }

    /// The table this was called before 0.8 is refused by name, even beside a
    /// valid `[endpoints.*]`: coming up with only half the endpoints an
    /// operator wrote would be worse than not coming up.
    #[test]
    fn the_renamed_profiles_table_is_refused_by_name() {
        for body in ["[profiles.le]\n", "[endpoints.le]\n[profiles.old]\n"] {
            let error = load_toml(body)
                .resolve_endpoints()
                .expect_err("the old table must be refused")
                .to_string();
            assert!(error.contains("[profiles.<name>]"), "{error}");
            assert!(error.contains("[endpoints.<name>]"), "{error}");
        }
    }

    #[test]
    fn an_endpoint_name_outside_the_url_charset_is_refused() {
        for name in ["Le", "my_endpoint", "we.b"] {
            let config = load_toml(&format!("[endpoints.\"{name}\"]\n"));
            let error = config
                .resolve_endpoints()
                .expect_err("{name} must be refused")
                .to_string();
            assert!(error.contains("invalid endpoint name"), "{error}");
        }
    }

    /// A list-valued key inside an endpoint, whose path holds a name only known
    /// at runtime. It used to need that runtime path registered for list
    /// parsing; `types::string_list` now splits it where it lands.
    #[test]
    fn an_endpoint_list_key_round_trips_through_the_environment() {
        let file = TempConfig::new("[endpoints.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            (
                "ACME_PROXY_ENDPOINTS__LE__CHALLENGE__ENABLED",
                "dns-01,http-01",
            ),
        ]);

        let config = Config::load().unwrap();
        let endpoints = config.resolve_endpoints().unwrap();
        assert_eq!(
            endpoints[0].sections.challenge.enabled,
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
            ("ACME_PROXY_ADMIN__SESSION_TTL", "60s"),
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
        assert_eq!(config.admin.session_ttl.as_secs(), 60);
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
            config.admin.session_idle_timeout.as_secs(),
            AdminConfig::default().session_idle_timeout.as_secs()
        );
    }

    /// `[admin.filter]` from the environment alone — the container deployment
    /// the section exists for is the one most likely to have no file. Its
    /// list fields sit one table deeper than `[filter]`'s, and must split the
    /// same way; the global `[filter]` must not leak into it.
    #[test]
    fn the_admin_filter_round_trips_through_the_environment() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_ADMIN__FILTER__RULES", "mgmt"),
            ("ACME_PROXY_ADMIN__FILTER__TRUSTED_PROXIES", "172.16.0.0/12"),
            ("ACME_PROXY_ADMIN__FILTER__CHECK__NET__TYPE", "allowed_ip"),
            (
                "ACME_PROXY_ADMIN__FILTER__CHECK__NET__ALLOW",
                "10.20.0.0/24,127.0.0.1/32",
            ),
            ("ACME_PROXY_ADMIN__FILTER__RULE__MGMT__WHEN", "net"),
            ("ACME_PROXY_ADMIN__FILTER__RULE__MGMT__THEN", "allow"),
            ("ACME_PROXY_FILTER__RULES", "acme-only"),
        ]);

        let config = Config::load().unwrap();
        let filter = &config.admin.filter;
        assert_eq!(filter.rules, vec!["mgmt"]);
        assert_eq!(filter.trusted_proxies, vec!["172.16.0.0/12"]);
        assert_eq!(filter.check["net"].r#type, "allowed_ip");
        assert_eq!(
            filter.check["net"].allow,
            vec!["10.20.0.0/24", "127.0.0.1/32"]
        );
        assert_eq!(filter.rule["mgmt"].when, "net");
        assert_eq!(filter.default, FilterConfig::default().default);
        assert_eq!(config.filter.rules, vec!["acme-only"]);
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

    /// `[filter.check.<name>]` entries are named tables, so each of their
    /// list-valued fields sits under a name only known at runtime. They used to
    /// need a registration found by scanning the environment, and were silently
    /// dropped without one; every list field of every entry must load.
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

    /// The same, scoped to one endpoint:
    /// `ACME_PROXY_ENDPOINTS__<NAME>__FILTER__CHECK__<NAME>__…`, two runtime
    /// names deep.
    #[test]
    fn env_configures_a_endpoint_scoped_named_check() {
        let file = TempConfig::new("[endpoints.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_ENDPOINTS__LE__FILTER__RULES", "only"),
            (
                "ACME_PROXY_ENDPOINTS__LE__FILTER__CHECK__MAIN__TYPE",
                "custom",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__FILTER__CHECK__MAIN__SCRIPT_PATH",
                "/path/to/endpoint.sh",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__FILTER__CHECK__MAIN__ARGS",
                "a,b,c",
            ),
        ]);

        let config = Config::load().unwrap();
        let endpoints = config.resolve_endpoints().unwrap();
        let check = &endpoints[0].sections.filter.check;
        assert_eq!(check["main"].script_path, "/path/to/endpoint.sh");
        assert_eq!(check["main"].args, vec!["a", "b", "c"]);
        assert_eq!(endpoints[0].sections.filter.rules, vec!["only"]);
    }

    /// The two `[notify]` tables, scoped to an endpoint — two runtime names
    /// deep, like the endpoint-scoped check above.
    ///
    /// The failure it guards against is silent: a list variable that does not
    /// reach its field leaves `events` at its default, all six, rather than
    /// being refused.
    #[test]
    fn env_configures_endpoint_scoped_notify_tables() {
        let file = TempConfig::new("[endpoints.le]\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            (
                "ACME_PROXY_ENDPOINTS__LE__NOTIFY__CUSTOM__PAGER__SCRIPT_PATH",
                "/usr/local/bin/page.sh",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__NOTIFY__CUSTOM__PAGER__ARGS",
                "--urgent,--team=netops",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__NOTIFY__CUSTOM__PAGER__EVENTS",
                "certificate_issued,challenge_failed",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__NOTIFY__WEBHOOK__SLACK__URL",
                "https://hooks.example.com/T/B/xyz",
            ),
            (
                "ACME_PROXY_ENDPOINTS__LE__NOTIFY__WEBHOOK__SLACK__EVENTS",
                "certificate_revoked",
            ),
        ]);

        let config = Config::load().unwrap();
        let endpoints = config.resolve_endpoints().unwrap();
        let notify = &endpoints[0].sections.notify;

        let pager = &notify.custom["pager"];
        assert_eq!(pager.script_path, "/usr/local/bin/page.sh");
        assert_eq!(pager.args, vec!["--urgent", "--team=netops"]);
        assert_eq!(
            pager.events,
            vec!["certificate_issued", "challenge_failed"],
            "a list key under two runtime names must reach its field"
        );

        let slack = &notify.webhook["slack"];
        assert_eq!(slack.url, "https://hooks.example.com/T/B/xyz");
        assert_eq!(slack.events, vec!["certificate_revoked"]);
    }

    /// `[notify.webhook.<name>]` is the third table keyed by a runtime name:
    /// its `events` list must load like `filter.check`'s and `notify.custom`'s,
    /// or the entry quietly reverts to all six events. `headers` is a map,
    /// which `config` nests from `…__HEADERS__<NAME>`.
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

    /// An environment-only endpoint: no `[endpoints]` table in the file at all.
    #[test]
    fn an_endpoint_can_be_declared_entirely_from_the_environment() {
        let file = TempConfig::new("[server]\nbase_url = \"http://acme.test\"\n");
        let path = file.path();
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_CONFIG", &path),
            ("ACME_PROXY_ENDPOINTS__LE__ENABLED", "true"),
            ("ACME_PROXY_ENDPOINTS__LE__CHALLENGE__BYPASS", "false"),
        ]);

        let config = Config::load().unwrap();
        let endpoints = config.resolve_endpoints().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "le");
        assert!(!endpoints[0].sections.challenge.bypass);
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
        assert_eq!(config.server.tls.handshake_timeout.as_millis(), 10_000);
        assert_eq!(config.nonce.ttl.as_secs(), 300);
        assert_eq!(config.jobs.poll_interval.as_millis(), 1_000);
        assert_eq!(config.jobs.max_concurrent, 8);
        assert_eq!(config.jobs.max_attempts, 5);
        assert_eq!(config.jobs.retry_base.as_secs(), 30);
        assert_eq!(config.jobs.retry_max.as_secs(), 3_600);
        assert_eq!(config.jobs.lease.as_secs(), 300);
        // Non-zero unlike `audit.retention`: a finished job is a receipt,
        // not evidence.
        assert_eq!(config.jobs.retention, ConfigDuration::from_days(7));
        assert_eq!(config.logging.filter, "acme_proxy=info");
        assert!(!config.logging.json_format);
        assert_eq!(config.logging.target, "stdout");
        assert!(config.logging.ansi);
        assert_eq!(config.logging.span_events, "none");
        assert!(!config.logging.flatten_event);
        assert_eq!(config.order.validity.as_secs(), 604800);
        assert_eq!(config.signer.backend, "local_ca");
        assert_eq!(config.signer.local_ca.cert_path, "ca.pem");
        assert_eq!(config.signer.local_ca.key_path, "ca.key");
        assert_eq!(config.signer.local_ca.key_type, "ecdsa-p256");
        assert_eq!(
            config.signer.local_ca.leaf_validity,
            ConfigDuration::from_days(90)
        );
        assert_eq!(config.challenge.enabled, vec!["http-01".to_string()]);
        // A CA that issues without proving control is not a safe out-of-the-box
        // posture; see `ChallengeConfig::bypass`.
        assert!(!config.challenge.bypass);
        assert_eq!(config.challenge.timeout.as_millis(), 5000);
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
        assert!(config.filter.allowed_ip.is_none());
        assert!(config.filter.reverse_dns.is_none());
        assert!(config.filter.identifiers.is_none());
        assert!(config.filter.custom.is_none());
        assert!(config.filter.netbox.is_none());
        assert!(!config.eab.enabled);
        assert!(config.notify.enabled.is_empty());
        assert!(config.notify.custom_enabled.is_empty());
        assert!(config.notify.custom.is_empty());
        assert_eq!(config.notify.template_dir, "");
        assert!(config.notify.expiry.lead.is_zero());
        assert_eq!(config.notify.expiry.interval, ConfigDuration::from_days(7));
        assert_eq!(config.notify.expiry.max_entries, 50);
        assert!(!config.notify.expiry.contact);
        assert!(config.notify.expiry.contact_domains.is_empty());
        assert_eq!(config.notify.email.smtp_port, 587);
        assert_eq!(config.notify.email.smtp_security, "starttls");
        assert_eq!(
            config.notify.email.events,
            vec![
                "endpoint_mounted",
                "account_created",
                "account_deactivated",
                "certificate_issued",
                "certificate_revoked",
                "challenge_failed",
                "certificates_expiring",
                "account_certificates_expiring",
                "admin_sign_in",
                "admin_credential_changed"
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
            loaded.server.tls.handshake_timeout.as_millis(),
            direct.server.tls.handshake_timeout.as_millis()
        );
        assert_eq!(loaded.nonce.ttl.as_secs(), direct.nonce.ttl.as_secs());
        assert_eq!(
            loaded.order.validity.as_secs(),
            direct.order.validity.as_secs()
        );
        assert_eq!(loaded.signer.backend, direct.signer.backend);
        assert_eq!(loaded.challenge.enabled, direct.challenge.enabled);
        assert_eq!(loaded.challenge.bypass, direct.challenge.bypass);
        assert_eq!(
            loaded.challenge.timeout.as_millis(),
            direct.challenge.timeout.as_millis()
        );
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
        // to declare an endpoint, since a configuration with none is refused.
        // At the repository root, two levels above this crate's manifest.
        let example_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.toml.example");
        let body = std::fs::read_to_string(&example_path).unwrap();
        let endpoints = load_toml(&body)
            .resolve_endpoints()
            .expect("config.toml.example must define at least one endpoint");
        assert_eq!(
            endpoints
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["default"]
        );

        let _guard = EnvGuard::new(&[]);

        let example = ::config::Config::builder()
            .add_source(
                ::config::File::from(example_path.as_path()).format(::config::FileFormat::Toml),
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
            example.server.admission_wait.as_millis(),
            defaults.server.admission_wait.as_millis()
        );
        assert_eq!(
            example.server.request_timeout.as_millis(),
            defaults.server.request_timeout.as_millis()
        );
        assert_eq!(
            example.server.max_body_bytes,
            defaults.server.max_body_bytes
        );
        assert_eq!(example.server.tls.enabled, defaults.server.tls.enabled);
        assert_eq!(example.server.tls.cert_path, defaults.server.tls.cert_path);
        assert_eq!(example.server.tls.key_path, defaults.server.tls.key_path);
        assert_eq!(
            example.server.tls.handshake_timeout.as_millis(),
            defaults.server.tls.handshake_timeout.as_millis()
        );
        assert_eq!(example.admin.enabled, defaults.admin.enabled);
        assert_eq!(example.admin.bind_address, defaults.admin.bind_address);
        assert_eq!(example.admin.base_url, defaults.admin.base_url);
        assert_eq!(
            example.admin.session_ttl.as_secs(),
            defaults.admin.session_ttl.as_secs()
        );
        assert_eq!(
            example.admin.session_idle_timeout.as_secs(),
            defaults.admin.session_idle_timeout.as_secs()
        );
        assert_eq!(
            example.admin.login_max_attempts,
            defaults.admin.login_max_attempts
        );
        assert_eq!(
            example.admin.login_window.as_secs(),
            defaults.admin.login_window.as_secs()
        );
        assert_eq!(example.admin.require_mfa, defaults.admin.require_mfa);
        assert_eq!(example.admin.max_body_bytes, defaults.admin.max_body_bytes);
        assert_eq!(example.admin.page_size_max, defaults.admin.page_size_max);
        assert_eq!(example.admin.template_dir, defaults.admin.template_dir);
        assert_eq!(example.admin.tls.enabled, defaults.admin.tls.enabled);
        assert_eq!(example.admin.tls.cert_path, defaults.admin.tls.cert_path);
        assert_eq!(example.admin.tls.key_path, defaults.admin.tls.key_path);
        assert_eq!(
            example.admin.tls.handshake_timeout.as_millis(),
            defaults.admin.tls.handshake_timeout.as_millis()
        );
        assert_eq!(example.nonce.ttl.as_secs(), defaults.nonce.ttl.as_secs());
        assert_eq!(example.audit.reverse_dns, defaults.audit.reverse_dns);
        assert_eq!(
            example.audit.reverse_dns_timeout.as_millis(),
            defaults.audit.reverse_dns_timeout.as_millis()
        );
        assert_eq!(example.audit.retention, defaults.audit.retention);
        assert_eq!(
            example.jobs.poll_interval.as_millis(),
            defaults.jobs.poll_interval.as_millis()
        );
        assert_eq!(example.jobs.max_concurrent, defaults.jobs.max_concurrent);
        assert_eq!(example.jobs.max_attempts, defaults.jobs.max_attempts);
        assert_eq!(
            example.jobs.retry_base.as_secs(),
            defaults.jobs.retry_base.as_secs()
        );
        assert_eq!(
            example.jobs.retry_max.as_secs(),
            defaults.jobs.retry_max.as_secs()
        );
        assert_eq!(example.jobs.lease.as_secs(), defaults.jobs.lease.as_secs());
        assert_eq!(example.jobs.retention, defaults.jobs.retention);
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
            example.order.validity.as_secs(),
            defaults.order.validity.as_secs()
        );
        assert_eq!(
            example.order.max_identifiers,
            defaults.order.max_identifiers
        );
        assert_eq!(example.order.retention, defaults.order.retention);
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
            example.signer.local_ca.leaf_validity,
            defaults.signer.local_ca.leaf_validity
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
        assert_eq!(
            example.challenge.timeout.as_millis(),
            defaults.challenge.timeout.as_millis()
        );
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
        assert_eq!(
            example.ipam.timeout.as_millis(),
            defaults.ipam.timeout.as_millis()
        );
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
        assert_eq!(config.nonce.ttl.as_secs(), 300);
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
            ("ACME_PROXY_SERVER__TLS__HANDSHAKE_TIMEOUT", "2500ms"),
        ]);

        let config = Config::load().expect("load should succeed with nested env overrides");

        assert!(config.server.tls.enabled);
        assert_eq!(config.server.tls.cert_path, "/etc/acme/tls.pem");
        assert_eq!(config.server.tls.handshake_timeout.as_millis(), 2500);
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

    /// `[admin.notify]` is a whole `NotifyConfig` hung off `[admin]`, and the
    /// book and `config.toml.example` both document its keys under
    /// `ACME_PROXY_ADMIN__NOTIFY__…`. Its lists, and those of its named
    /// tables, must load from the environment like the per-endpoint
    /// `[notify]`'s. They were once refused, arriving as bare strings, which is
    /// what happened until this test existed.
    #[test]
    fn the_admin_notify_section_parses_from_the_environment() {
        let _guard = EnvGuard::new(&[
            ("ACME_PROXY_ADMIN__NOTIFY__ENABLED", "email,webhook,custom"),
            (
                "ACME_PROXY_ADMIN__NOTIFY__EMAIL__EVENTS",
                "admin_sign_in,admin_credential_changed",
            ),
            ("ACME_PROXY_ADMIN__NOTIFY__EMAIL__TO", "ops@example.com"),
            ("ACME_PROXY_ADMIN__NOTIFY__WEBHOOK_ENABLED", "slack"),
            ("ACME_PROXY_ADMIN__NOTIFY__CUSTOM_ENABLED", "pager"),
            (
                "ACME_PROXY_ADMIN__NOTIFY__WEBHOOK__SLACK__EVENTS",
                "admin_sign_in",
            ),
            (
                "ACME_PROXY_ADMIN__NOTIFY__CUSTOM__PAGER__ARGS",
                "--now,--loud",
            ),
        ]);

        let config = Config::load().expect("[admin.notify] must load from the environment");

        assert_eq!(config.admin.notify.enabled, ["email", "webhook", "custom"]);
        assert_eq!(
            config.admin.notify.email.events,
            ["admin_sign_in", "admin_credential_changed"]
        );
        assert_eq!(config.admin.notify.email.to, ["ops@example.com"]);
        assert_eq!(config.admin.notify.webhook_enabled, ["slack"]);
        assert_eq!(config.admin.notify.custom_enabled, ["pager"]);
        assert_eq!(
            config.admin.notify.webhook["slack"].events,
            ["admin_sign_in"]
        );
        assert_eq!(
            config.admin.notify.custom["pager"].args,
            ["--now", "--loud"]
        );

        // The per-endpoint `[notify]` is untouched by any of it.
        assert!(config.notify.enabled.is_empty());
    }

    /// Every list field carries `types::string_list`, which is what reads a
    /// comma-separated environment variable. Without it the field still loads
    /// from a file, and the environment spelling fails as a type error, so the
    /// omission would surface only for an operator configuring through the
    /// environment.
    ///
    /// Read from the source, like `tests/logging_convention.rs`: a `Vec`
    /// field has no runtime marker to enumerate.
    #[test]
    fn every_list_field_reads_a_comma_separated_string() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/types");
        let mut fields = 0;
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let line = line.trim();
                if !(line.starts_with("pub ") && line.contains(": Vec<")) {
                    continue;
                }
                fields += 1;
                // The attributes and doc comments directly above the field.
                let covered = lines[..index]
                    .iter()
                    .rev()
                    .map(|above| above.trim())
                    .take_while(|above| above.starts_with("#[") || above.starts_with("//"))
                    .any(|above| above.starts_with("#[") && above.contains("string_list\""));
                if !covered {
                    missing.push(format!("{}: {line}", path.display()));
                }
            }
        }
        assert!(fields >= 30, "the scan found only {fields} list fields");
        assert!(
            missing.is_empty(),
            "list fields without `deserialize_with = \"string_list\"`:\n{}",
            missing.join("\n")
        );
    }
}
