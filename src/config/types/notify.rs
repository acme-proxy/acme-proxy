//! `[notify]` — the operator-notification backends and their event filters.
//!
//! Re-exported flat from [`super`], so nothing outside this directory names
//! the submodule.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::empty_string_is_no_values;

/// Notification-subsystem configuration: which backends are active, and each
/// backend's own settings. See [`crate::notify`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    /// Which backends are active: `"email"`, `"mattermost"`, `"custom"`.
    /// Empty (default) means no notifications are sent at all.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub enabled: Vec<String>,
    pub email: EmailNotifyConfig,
    pub mattermost: MattermostNotifyConfig,
    /// Which of `custom`'s entries to run, and in what order, when `custom`
    /// is listed in `enabled` — the same shape as `filter.custom_enabled`.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub custom_enabled: Vec<String>,
    /// Named external script/webhook configs, selected and ordered by
    /// `custom_enabled`. Each name must match `^[a-z0-9-]+$`, same as
    /// `filter.custom`'s entries and for the same reason (see
    /// [`valid_config_key_name`](crate::config::valid_config_key_name)).
    pub custom: BTreeMap<String, CustomNotifyConfig>,
    /// Filesystem directory to look for template overrides in, checked
    /// per-template-file before falling back to the compiled-in defaults.
    /// Empty (default) means compiled-in defaults only.
    pub template_dir: String,
}
/// Configuration for the `email` notify backend (SMTP via `lettre`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EmailNotifyConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    /// `"starttls"` (default) | `"tls"` | `"none"`.
    pub smtp_security: String,
    pub from: String,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub to: Vec<String>,
    /// Which lifecycle events this backend reacts to. Defaults to all six,
    /// listed explicitly rather than relying on "empty means all": every
    /// other list field in this codebase treats empty as *off*, so reusing
    /// that convention here would silently mean "no events" the moment an
    /// operator writes `events = []` expecting "all".
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub events: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for EmailNotifyConfig {
    fn default() -> Self {
        Self {
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_security: "starttls".to_string(),
            from: String::new(),
            to: Vec::new(),
            events: all_notify_events(),
            timeout_ms: 5000,
        }
    }
}
/// Configuration for the `mattermost` notify backend (incoming webhook).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MattermostNotifyConfig {
    pub webhook_url: String,
    /// Empty means the webhook's own configured default channel.
    pub channel: String,
    /// Empty means the webhook's own configured default username.
    pub username: String,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub events: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for MattermostNotifyConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            channel: String::new(),
            username: String::new(),
            events: all_notify_events(),
            timeout_ms: 5000,
        }
    }
}
/// Configuration for one named `custom` notify script/webhook — the
/// notify-side counterpart of `CustomFilterConfig`/`CustomSignerConfig`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CustomNotifyConfig {
    pub script_path: String,
    pub timeout_ms: u64,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub args: Vec<String>,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub events: Vec<String>,
}

impl Default for CustomNotifyConfig {
    fn default() -> Self {
        Self {
            script_path: String::new(),
            timeout_ms: 5000,
            args: Vec::new(),
            events: all_notify_events(),
        }
    }
}

/// The six lifecycle events the `notify` subsystem can react to. Kept here
/// rather than in `src/notify` so each backend's `events` default (below) can
/// list them without creating a dependency from `config` on `notify`.
pub(crate) const ALL_NOTIFY_EVENTS: [&str; 6] = [
    "profile_mounted",
    "account_created",
    "account_deactivated",
    "certificate_issued",
    "certificate_revoked",
    "challenge_failed",
];

fn all_notify_events() -> Vec<String> {
    ALL_NOTIFY_EVENTS.iter().map(|s| s.to_string()).collect()
}
