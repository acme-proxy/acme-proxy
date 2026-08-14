//! The `custom` check: executes an external script/binary to evaluate requests.
//!
//! The script is told which named check invoked it (`ACME_FILTER_CHECK_NAME`),
//! so one script can serve several `[filter.check.<name>]` entries and branch
//! on which one it is.

use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use super::policy::{Check, StageSet, Verdict};
use super::{ConnectionContext, IdentifierContext};
use crate::script_hook::{ScriptError, ScriptHook, ScriptStdin};

/// Resolved `[filter.check.<name>]` settings for `type = "custom"`.
#[derive(Debug, Clone)]
pub struct Settings {
    pub script_path: String,
    pub timeout_ms: u64,
    pub pass_stdin: bool,
    pub args: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            script_path: String::new(),
            timeout_ms: 5000,
            pass_stdin: true,
            args: Vec::new(),
        }
    }
}

/// Executes an external script/binary to evaluate connections and identifiers.
#[derive(Debug)]
pub struct CustomScriptFilter {
    hook: ScriptHook,
    pass_stdin: bool,
    /// The instance name, handed to the script so one script can serve several.
    check_name: String,
}

impl CustomScriptFilter {
    /// Validates the configuration and creates the check.
    pub fn from_settings(name: &str, settings: &Settings) -> anyhow::Result<Self> {
        let Some(hook) =
            ScriptHook::new(&settings.script_path, &settings.args, settings.timeout_ms)
        else {
            anyhow::bail!(
                "filter.check.{name}.script_path is empty; provide a path to an \
                 executable script or drop the check"
            );
        };

        info!(
            event = "filter_custom_loaded",
            outcome = "success",
            check = name,
            script_path = %hook.path().display(),
            timeout_ms = settings.timeout_ms,
            pass_stdin = settings.pass_stdin,
            args = ?settings.args,
        );

        Ok(Self {
            hook,
            pass_stdin: settings.pass_stdin,
            check_name: name.to_string(),
        })
    }

    /// Runs the script and maps its verdict.
    ///
    /// Exit 0 permits; any non-zero exit is a *denial* rather than an internal
    /// error — that is this subsystem's contract, and the difference from the
    /// signer's, where a non-zero exit other than the reserved one means the
    /// backend broke. Everything that stopped the script from answering at all
    /// is `Internal`, so an unreachable or broken filter fails closed with a
    /// retryable 500 rather than looking like a policy refusal.
    async fn run_script(&self, envs: &[(&str, &str)], payload: &serde_json::Value) -> Verdict {
        let stdin = if self.pass_stdin {
            ScriptStdin::Json(payload)
        } else {
            ScriptStdin::Null
        };

        let outcome = match self.hook.run(envs, stdin).await {
            Ok(outcome) => outcome,
            Err(
                error @ (ScriptError::Spawn { .. }
                | ScriptError::Serialize(_)
                | ScriptError::Wait(_)
                | ScriptError::Timeout(_)),
            ) => return Verdict::Undecided(format!("custom filter {error}")),
        };

        if outcome.output.status.success() {
            Verdict::Pass
        } else {
            Verdict::Fail(ScriptHook::detail(&outcome, "custom filter script"))
        }
    }
}

#[async_trait]
impl Check for CustomScriptFilter {
    fn kind(&self) -> &'static str {
        "custom"
    }

    fn stages(&self) -> StageSet {
        StageSet::both()
    }

    async fn check_connection(&self, context: &ConnectionContext<'_>) -> Verdict {
        let client_ip_str = context
            .client_ip
            .map(|ip| super::canonical(ip).to_string())
            .unwrap_or_default();
        let envs = [
            ("ACME_FILTER_HOOK", "connection"),
            ("ACME_FILTER_CHECK_NAME", self.check_name.as_str()),
            ("ACME_FILTER_CLIENT_IP", client_ip_str.as_str()),
            ("ACME_FILTER_METHOD", context.method.as_str()),
            ("ACME_FILTER_PATH", context.path),
        ];

        let payload = json!({
            "hook": "connection",
            "check": self.check_name,
            "client_ip": if client_ip_str.is_empty() { None } else { Some(&client_ip_str) },
            "method": context.method.as_str(),
            "path": context.path,
        });

        self.run_script(&envs, &payload).await
    }

    async fn check_identifiers(&self, context: &IdentifierContext<'_>) -> Verdict {
        let client_ip_str = context
            .client_ip
            .map(|ip| super::canonical(ip).to_string())
            .unwrap_or_default();
        let identifiers_vec: Vec<String> = context
            .identifiers
            .iter()
            .map(|identifier| identifier.value.clone())
            .collect();
        let identifiers_str = identifiers_vec.join(",");

        let envs = [
            ("ACME_FILTER_HOOK", "identifiers"),
            ("ACME_FILTER_CHECK_NAME", self.check_name.as_str()),
            ("ACME_FILTER_CLIENT_IP", client_ip_str.as_str()),
            ("ACME_FILTER_ACCOUNT_ID", context.account_id),
            ("ACME_FILTER_STAGE", context.stage.as_str()),
            ("ACME_FILTER_IDENTIFIERS", identifiers_str.as_str()),
        ];

        let payload = json!({
            "hook": "identifiers",
            "check": self.check_name,
            "client_ip": if client_ip_str.is_empty() { None } else { Some(&client_ip_str) },
            "account_id": context.account_id,
            "stage": context.stage.as_str(),
            "identifiers": context.identifiers,
        });

        self.run_script(&envs, &payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::IdentifierStage;
    use crate::sqlite::order::Identifier;
    use crate::testutil::TempDir;
    use axum::http::Method;
    use std::time::Duration;

    /// Writes an executable script and returns the configuration pointing at it.
    ///
    /// The `ETXTBSY` reasoning that used to live here — and, verbatim, in two
    /// other modules — is now in `crate::testutil::write_script`, which this
    /// wraps.
    fn write_script(dir: &TempDir, name: &str, body: &str) -> Settings {
        let script_path = crate::testutil::write_script(dir, name, body);
        Settings {
            script_path: script_path.to_str().unwrap().to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn missing_script_path_bails() {
        let cfg = Settings {
            script_path: "  ".to_string(),
            ..Default::default()
        };
        assert!(CustomScriptFilter::from_settings("hook", &cfg).is_err());
    }

    /// A script that cannot be spawned is `Internal`, never `Denied`: the same
    /// reasoning as `netbox`'s transport failures. A broken hook must stop
    /// requests with a retryable 500, not look like a permanent refusal — and
    /// certainly not fail open.
    #[tokio::test]
    async fn a_script_that_cannot_be_spawned_is_internal_not_denied() {
        let filter = CustomScriptFilter::from_settings(
            "hook",
            &Settings {
                script_path: "/nonexistent/filter.sh".to_string(),
                ..Default::default()
            },
        )
        .unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/newOrder",
        };
        match filter.check_connection(&ctx).await {
            Verdict::Undecided(detail) => {
                assert!(
                    detail.contains("failed to spawn script")
                        && detail.contains("/nonexistent/filter.sh"),
                    "{detail}"
                )
            }
            other => panic!("expected Undecided, got {other:?}"),
        }

        let identifiers = vec![Identifier::dns("example.com")];
        let ctx = IdentifierContext {
            client_ip: "127.0.0.1".parse().ok(),
            account_id: "acc_1",
            stage: IdentifierStage::NewOrder,
            identifiers: &identifiers,

            eab: None,
        };
        assert!(matches!(
            filter.check_identifiers(&ctx).await,
            Verdict::Undecided(_)
        ));
    }

    #[tokio::test]
    async fn passing_script_allows() {
        let dir = TempDir::new("filter-custom");
        let cfg = write_script(&dir, "pass.sh", "#!/bin/sh\nexit 0\n");
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/health",
        };
        assert_eq!(filter.check_connection(&ctx).await, Verdict::Pass);
    }

    #[tokio::test]
    async fn failing_script_denies() {
        let dir = TempDir::new("filter-custom");
        let cfg = write_script(
            &dir,
            "fail.sh",
            "#!/bin/sh\necho \"custom denial\"\nexit 1\n",
        );
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::POST,
            path: "/acme/new-order",
        };
        let res = filter.check_connection(&ctx).await;
        match res {
            // `starts_with`, not `==`: this script exits without reading its
            // stdin, so the parent's write races the child's exit and an EPIPE
            // is a legitimate outcome — `ScriptOutcome::stdin_error` then
            // appends "(the script did not read its input: …)", by design and
            // only because the script also failed. Which side of the race wins
            // depends on machine load, so an equality assertion here fails
            // intermittently for a reason that is not the behaviour under test:
            // what this asserts is that the script's own message is what the
            // client is denied with.
            Verdict::Fail(detail) => {
                assert!(detail.starts_with("custom denial"), "{detail}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn script_receives_env_and_stdin() {
        let dir = TempDir::new("filter-custom");
        let script_content = r#"#!/bin/sh
if [ "$ACME_FILTER_HOOK" != "identifiers" ]; then
    echo "wrong hook: $ACME_FILTER_HOOK"
    exit 1
fi
if [ "$ACME_FILTER_IDENTIFIERS" != "example.com" ]; then
    echo "wrong identifiers: $ACME_FILTER_IDENTIFIERS"
    exit 1
fi
exit 0
"#;
        let cfg = write_script(&dir, "check_env.sh", script_content);
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let identifiers = vec![Identifier::dns("example.com")];
        let ctx = IdentifierContext {
            client_ip: "10.0.0.1".parse().ok(),
            account_id: "acc_123",
            stage: IdentifierStage::NewOrder,
            identifiers: &identifiers,

            eab: None,
        };

        assert_eq!(filter.check_identifiers(&ctx).await, Verdict::Pass);
    }

    #[tokio::test]
    async fn script_timeout_returns_internal() {
        let dir = TempDir::new("filter-custom");
        let cfg = Settings {
            timeout_ms: 100,
            ..write_script(&dir, "sleep.sh", "#!/bin/sh\nsleep 2\nexit 0\n")
        };
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: None,
            method: &Method::GET,
            path: "/health",
        };

        let res = filter.check_connection(&ctx).await;
        match res {
            Verdict::Undecided(detail) => assert!(detail.contains("timed out")),
            other => panic!("expected Undecided on timeout, got {other:?}"),
        }
    }

    /// The server carries secrets in its environment (the configuration overlays
    /// from `ACME_PROXY_*` variables, including the TSIG secret), so a script
    /// provided by the operator must not inherit anything.
    ///
    /// `CARGO_MANIFEST_DIR` acts as a canary: cargo always places it in the test
    /// binary's environment, so its presence on the child side would mean a full
    /// inheritance, without having to mutate the parent environment from a test
    /// running in parallel with others.
    #[tokio::test]
    async fn the_script_does_not_inherit_the_server_environment() {
        assert!(
            std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
            "the canary must exist in the parent, otherwise the test proves nothing"
        );

        let dir = TempDir::new("filter-custom");
        let cfg = write_script(
            &dir,
            "env_leak.sh",
            r#"#!/bin/sh
if [ -n "$CARGO_MANIFEST_DIR" ]; then
    echo "inherited CARGO_MANIFEST_DIR=$CARGO_MANIFEST_DIR"
    exit 1
fi
# The minimal PATH, however, must be provided.
if [ -z "$PATH" ]; then
    echo "no PATH"
    exit 1
fi
# And the documented filter variables too.
if [ "$ACME_FILTER_HOOK" != "connection" ]; then
    echo "missing ACME_FILTER_HOOK"
    exit 1
fi
exit 0
"#,
        );
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/newOrder",
        };
        assert_eq!(filter.check_connection(&ctx).await, Verdict::Pass);
    }

    /// `tokio::time::timeout` only abandons the future: without `kill_on_drop`,
    /// the child process survives the expiration and, since one process is spawned
    /// per request, a blocked script would accumulate one per call.
    #[tokio::test]
    async fn a_timed_out_script_is_killed_rather_than_left_running() {
        let dir = TempDir::new("filter-custom");
        let marker = dir.path().join("survived");
        let cfg = Settings {
            timeout_ms: 50,
            ..write_script(
                &dir,
                "slow.sh",
                &format!("#!/bin/sh\nsleep 1\ntouch {}\n", marker.to_str().unwrap()),
            )
        };
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: None,
            method: &Method::GET,
            path: "/newOrder",
        };
        match filter.check_connection(&ctx).await {
            Verdict::Undecided(detail) => assert!(detail.contains("timed out")),
            other => panic!("expected Undecided on timeout, got {other:?}"),
        }

        // Well beyond the `sleep 1`: if the child had survived the future's abandonment,
        // it would have had plenty of time to drop its canary.
        tokio::time::sleep(Duration::from_millis(1_800)).await;
        assert!(
            !marker.exists(),
            "the script survived the timeout and continued executing"
        );
    }
}
