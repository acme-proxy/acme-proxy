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
    /// Which backends are active: `"email"`, `"webhook"`, `"custom"`.
    /// Empty (default) means no notifications are sent at all.
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub enabled: Vec<String>,
    pub email: EmailNotifyConfig,
    /// Which of `webhook`'s entries to POST to, and in what order, when
    /// `webhook` is listed in `enabled` — the same shape as `custom_enabled`
    /// below, and resolved by the same [`resolve_named_entries`].
    ///
    /// [`resolve_named_entries`]: crate::config::resolve_named_entries
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub webhook_enabled: Vec<String>,
    /// Named HTTP webhook targets, selected and ordered by `webhook_enabled`.
    /// Each name must match `^[a-z0-9-]+$`, same as `custom`'s entries and for
    /// the same reason.
    pub webhook: BTreeMap<String, WebhookNotifyConfig>,
    /// Which of `custom`'s entries to run, and in what order, when `custom`
    /// is listed in `enabled` — the same shape as `webhook_enabled`.
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
/// Configuration for one named `webhook` notify target: an HTTP request whose
/// URL, method, headers and body are all the operator's to state.
///
/// This is what makes a chat provider configuration rather than a backend —
/// Slack, Mattermost, Teams, Telegram and Matrix differ only in these four
/// values. See [`crate::notify::webhook`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebhookNotifyConfig {
    /// The endpoint to call. Required once the entry is selected; it routinely
    /// carries the credential in its path (a Slack hook id, a Telegram bot
    /// token), which is why nothing ever logs more of it than the host.
    pub url: String,
    /// `"POST"` (default), `"PUT"` or `"PATCH"`. Matrix's send-message API is
    /// the reason this is configurable at all.
    pub method: String,
    /// Extra request headers, e.g. `Authorization`. Applied after the
    /// defaults, so an entry may override `content-type`.
    pub headers: BTreeMap<String, String>,
    /// The request body, as a MiniJinja template. `message` (the rendered
    /// `webhook/<event>.j2`), `hook` and every field of the event's own
    /// payload are in scope.
    ///
    /// The default is the shape Slack, Mattermost and Teams all accept. Note
    /// the `tojson` filter: `.j2` templates have auto-escaping off, so a
    /// message holding a quote or a newline needs it to stay valid JSON.
    pub body: String,
    #[serde(deserialize_with = "empty_string_is_no_values")]
    pub events: Vec<String>,
    pub timeout_ms: u64,
}

/// The default `body`: the `{"text": …}` payload Slack, Mattermost and
/// Microsoft Teams incoming webhooks all accept, so those three need a `url`
/// and nothing else.
pub const DEFAULT_WEBHOOK_BODY: &str = r#"{"text": {{ message | tojson }}}"#;

impl Default for WebhookNotifyConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: "POST".to_string(),
            headers: BTreeMap::new(),
            body: DEFAULT_WEBHOOK_BODY.to_string(),
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
pub const ALL_NOTIFY_EVENTS: [&str; 6] = [
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
