//! The `custom` notify backend: shells out to an external script or webhook
//! wrapper, on the same contract as [`crate::filter::custom`] and
//! [`crate::signer::custom`] — env vars plus JSON on stdin, exit code decides
//! outcome. This is what lets an operator wire up a channel this server has
//! no built-in support for (Slack, PagerDuty, …) without a code change.

use async_trait::async_trait;
use tracing::info;

use super::{NotifyBackend, NotifyError, NotifyEvent};
use crate::config::CustomNotifyConfig;
use crate::script_hook::{ScriptHook, ScriptStdin};

/// Executes an external script/binary to deliver one notification.
#[derive(Debug)]
pub struct CustomScriptNotifier {
    hook: ScriptHook,
}

impl CustomScriptNotifier {
    /// Validates the configuration and creates the backend.
    pub fn from_config(cfg: &CustomNotifyConfig) -> anyhow::Result<Self> {
        let Some(hook) = ScriptHook::new(&cfg.script_path, &cfg.args, cfg.timeout_ms) else {
            anyhow::bail!(
                "notify.custom is enabled but notify.custom.script_path is empty; \
                 provide a path to an executable script or remove `custom` from \
                 notify.enabled"
            );
        };

        info!(
            event = "notify_custom_loaded",
            outcome = "success",
            script_path = %hook.path().display(),
            timeout_ms = cfg.timeout_ms,
            args = ?cfg.args,
        );

        Ok(Self { hook })
    }

    /// Runs the script; a non-zero exit is a delivery failure.
    ///
    /// Every failure here is the same kind — `NotifyError` is a newtype, not an
    /// enum, because notification is fire-and-forget and nothing branches on
    /// why it did not arrive. It is logged and dropped either way.
    async fn run_script(
        &self,
        envs: &[(&str, &str)],
        payload: &serde_json::Value,
    ) -> Result<(), NotifyError> {
        let outcome = self
            .hook
            .run(envs, ScriptStdin::Json(payload))
            .await
            .map_err(|error| NotifyError::new(format!("custom notify {error}")))?;

        if outcome.output.status.success() {
            Ok(())
        } else {
            Err(NotifyError::new(ScriptHook::detail(
                &outcome,
                "custom notify script",
            )))
        }
    }
}

#[async_trait]
impl NotifyBackend for CustomScriptNotifier {
    fn name(&self) -> &'static str {
        "custom"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        let client_ip = event.client_ip().unwrap_or_default();
        let account_id = event.account_id().unwrap_or_default();
        let order_id = event.order_id().unwrap_or_default();
        let cert_serial = event.cert_serial().unwrap_or_default();
        let identifiers = event.identifiers_joined();
        let profile = event.profile();
        let kind = event.kind();

        let envs = [
            ("ACME_NOTIFY_HOOK", kind),
            ("ACME_NOTIFY_PROFILE", profile),
            ("ACME_NOTIFY_CLIENT_IP", client_ip),
            ("ACME_NOTIFY_ACCOUNT_ID", account_id),
            ("ACME_NOTIFY_ORDER_ID", order_id),
            ("ACME_NOTIFY_CERT_SERIAL", cert_serial),
            ("ACME_NOTIFY_IDENTIFIERS", identifiers.as_str()),
        ];

        self.run_script(&envs, &event.payload()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{CertificateIssuedData, ProfileMountedData};
    use crate::testutil::TempDir;
    use std::time::Duration;

    /// Writes an executable script and returns the configuration pointing at it.
    /// The `ETXTBSY` reasoning lives in `crate::testutil::write_script`.
    fn write_script(dir: &TempDir, name: &str, body: &str) -> CustomNotifyConfig {
        let script_path = crate::testutil::write_script(dir, name, body);
        CustomNotifyConfig {
            script_path: script_path.to_str().unwrap().to_string(),
            ..Default::default()
        }
    }

    fn profile_mounted() -> NotifyEvent {
        NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: "default".to_string(),
        })
    }

    #[test]
    fn missing_script_path_bails() {
        let cfg = CustomNotifyConfig {
            script_path: "  ".to_string(),
            ..Default::default()
        };
        assert!(CustomScriptNotifier::from_config(&cfg).is_err());
    }

    /// A configured path that vanished between startup and the first event —
    /// an operator repackaging the deployment, say. Spawning fails at delivery
    /// time and reports which script, rather than panicking in a background
    /// dispatch task.
    #[tokio::test]
    async fn a_script_that_cannot_be_spawned_is_reported() {
        let backend = CustomScriptNotifier::from_config(&CustomNotifyConfig {
            script_path: "/nonexistent/notify.sh".to_string(),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(backend.name(), "custom");
        let error = backend
            .send(&profile_mounted())
            .await
            .expect_err("there is no such script");
        assert!(
            error.to_string().contains("failed to spawn script")
                && error.to_string().contains("/nonexistent/notify.sh"),
            "{error}"
        );
    }

    /// A script that exits non-zero saying nothing still has to produce a
    /// message — "it failed" with no detail is worse than the status code.
    #[tokio::test]
    async fn a_silent_failure_reports_its_exit_status() {
        let dir = TempDir::new("notify-custom");
        let cfg = write_script(&dir, "silent.sh", "#!/bin/sh\ncat > /dev/null\nexit 3\n");
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();

        let error = backend
            .send(&profile_mounted())
            .await
            .expect_err("exit 3 is a failure");
        assert!(error.to_string().contains("exited with status"), "{error}");
    }

    #[tokio::test]
    async fn passing_script_delivers() {
        let dir = TempDir::new("notify-custom");
        let cfg = write_script(&dir, "pass.sh", "#!/bin/sh\ncat > /dev/null\nexit 0\n");
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();
        assert!(backend.send(&profile_mounted()).await.is_ok());
    }

    #[tokio::test]
    async fn failing_script_reports_the_first_output_line() {
        let dir = TempDir::new("notify-custom");
        let cfg = write_script(
            &dir,
            "fail.sh",
            "#!/bin/sh\ncat > /dev/null\necho \"webhook rejected\"\nexit 1\n",
        );
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();
        let error = backend.send(&profile_mounted()).await.unwrap_err();
        assert_eq!(error.to_string(), "webhook rejected");
    }

    #[tokio::test]
    async fn script_receives_env_and_stdin() {
        let dir = TempDir::new("notify-custom");
        let script_content = r#"#!/bin/sh
payload=$(cat)
if [ "$ACME_NOTIFY_HOOK" != "certificate_issued" ]; then
    echo "wrong hook: $ACME_NOTIFY_HOOK"
    exit 1
fi
if [ "$ACME_NOTIFY_IDENTIFIERS" != "example.com" ]; then
    echo "wrong identifiers: $ACME_NOTIFY_IDENTIFIERS"
    exit 1
fi
case "$payload" in
    *'"hook":"certificate_issued"'*) exit 0 ;;
    *) echo "stdin missing hook tag: $payload"; exit 1 ;;
esac
"#;
        let cfg = write_script(&dir, "check_env.sh", script_content);
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();

        let event = NotifyEvent::CertificateIssued(CertificateIssuedData {
            profile: "default".to_string(),
            order_id: "ord-1".to_string(),
            account_id: "acc-1".to_string(),
            cert_serial: "AA:BB".to_string(),
            identifiers: vec!["example.com".to_string()],
            client_ip: None,
        });
        assert!(backend.send(&event).await.is_ok());
    }

    /// `CARGO_MANIFEST_DIR` acts as a canary: cargo always places it in the
    /// test binary's environment, so its presence on the child side would
    /// mean full inheritance rather than the documented `ACME_NOTIFY_*` set.
    #[tokio::test]
    async fn the_script_does_not_inherit_the_server_environment() {
        assert!(
            std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
            "the canary must exist in the parent, otherwise the test proves nothing"
        );

        let dir = TempDir::new("notify-custom");
        let cfg = write_script(
            &dir,
            "env_leak.sh",
            r#"#!/bin/sh
cat > /dev/null
if [ -n "$CARGO_MANIFEST_DIR" ]; then
    echo "inherited CARGO_MANIFEST_DIR=$CARGO_MANIFEST_DIR"
    exit 1
fi
if [ -z "$PATH" ]; then
    echo "no PATH"
    exit 1
fi
exit 0
"#,
        );
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();
        assert!(backend.send(&profile_mounted()).await.is_ok());
    }

    /// `tokio::time::timeout` only abandons the future: without
    /// `kill_on_drop`, the child survives and, since one is spawned per
    /// event, a blocked script would accumulate one per notification.
    #[tokio::test]
    async fn a_timed_out_script_is_killed_rather_than_left_running() {
        let dir = TempDir::new("notify-custom");
        let marker = dir.path().join("survived");
        let cfg = CustomNotifyConfig {
            timeout_ms: 50,
            ..write_script(
                &dir,
                "slow.sh",
                &format!(
                    "#!/bin/sh\ncat > /dev/null\nsleep 1\ntouch {}\n",
                    marker.to_str().unwrap()
                ),
            )
        };
        let backend = CustomScriptNotifier::from_config(&cfg).unwrap();

        let error = backend.send(&profile_mounted()).await.unwrap_err();
        assert!(error.to_string().contains("timed out"));

        tokio::time::sleep(Duration::from_millis(1_800)).await;
        assert!(
            !marker.exists(),
            "the script survived the timeout and continued executing"
        );
    }
}
