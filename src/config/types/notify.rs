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
    /// The periodic expiry digest — off until `lead_days` is non-zero.
    pub expiry: ExpiryNotifyConfig,
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
    /// Which lifecycle events this backend reacts to. Defaults to all of
    /// them, listed explicitly rather than relying on "empty means all": every
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
/// `[notify.expiry]` — the periodic digest of certificates approaching expiry
/// (see [`crate::notify::expiry`]).
///
/// One message per profile per `interval_days`, listing what lapses inside
/// `lead_days`, and **not** one message per certificate: a renewal is a new
/// order, so the certificate it replaced still expires on schedule and a
/// per-certificate reminder would tell an operator about every certificate the
/// CA has ever issued. The digest carries the superseded ones annotated
/// instead, so the un-renewed rows are what stands out.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExpiryNotifyConfig {
    /// How far ahead to look, in days. **`0` (the default) is off** — the job
    /// is never registered at all, the shape `audit.retention_days` and
    /// `jobs.retention_days` already use for "do not schedule this sweep".
    pub lead_days: u64,
    /// How often the digest is sent, in days. There is deliberately no
    /// per-certificate rate limit beside it: the digest *is* the rate limit,
    /// which is what the per-certificate shape needed a stored "last reminded"
    /// timestamp for.
    pub interval_days: u64,
    /// The most certificates one message lists. The count of matches is
    /// carried whole regardless, so a truncated digest still says how many it
    /// did not name — a per-certificate message was self-limiting and this is
    /// not, and ten thousand expiring at once is an unreadable mail and a
    /// webhook body a provider refuses.
    pub max_entries: usize,
}

impl Default for ExpiryNotifyConfig {
    fn default() -> Self {
        Self {
            lead_days: 0,
            interval_days: 7,
            max_entries: 50,
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

/// The lifecycle events the `notify` subsystem can react to. Kept here rather
/// than in `src/notify` so each backend's `events` default (below) can list
/// them without creating a dependency from `config` on `notify`.
///
/// `certificates_expiring` is the odd one and worth recognising as such: the
/// other six are things that just happened to one account, order or
/// certificate, where it is a periodic digest about however many certificates
/// are approaching expiry. It reaches a backend only once
/// `notify.expiry.lead_days` is non-zero, so listing it here does not start
/// sending anything on its own.
pub const ALL_NOTIFY_EVENTS: [&str; 7] = [
    "profile_mounted",
    "account_created",
    "account_deactivated",
    "certificate_issued",
    "certificate_revoked",
    "challenge_failed",
    "certificates_expiring",
];

fn all_notify_events() -> Vec<String> {
    ALL_NOTIFY_EVENTS.iter().map(|s| s.to_string()).collect()
}
