//! The `custom` filter: executes an external script/binary to evaluate requests.

use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use super::{ConnectionContext, Filter, FilterError, IdentifierContext};
use crate::config::CustomFilterConfig;
use crate::script_hook::{ScriptError, ScriptHook, ScriptStdin};

/// Executes an external script/binary to evaluate connections and identifiers.
#[derive(Debug)]
pub struct CustomScriptFilter {
    hook: ScriptHook,
    pass_stdin: bool,
}

impl CustomScriptFilter {
    /// Validates the configuration and creates the filter.
    pub fn from_config(cfg: &CustomFilterConfig) -> anyhow::Result<Self> {
        let Some(hook) = ScriptHook::new(&cfg.script_path, &cfg.args, cfg.timeout_ms) else {
            anyhow::bail!(
                "filter.custom is enabled but filter.custom.script_path is empty; \
                 provide a path to an executable script or remove `custom` from filter.enabled"
            );
        };

        info!(
            event = "filter_custom_loaded",
            script_path = %hook.path().display(),
            timeout_ms = cfg.timeout_ms,
            pass_stdin = cfg.pass_stdin,
            args = ?cfg.args,
        );

        Ok(Self {
            hook,
            pass_stdin: cfg.pass_stdin,
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
    async fn run_script(
        &self,
        envs: &[(&str, &str)],
        payload: &serde_json::Value,
    ) -> Result<(), FilterError> {
        let stdin = if self.pass_stdin {
            ScriptStdin::Json(payload)
        } else {
            ScriptStdin::Null
        };

        let outcome = self
            .hook
            .run(envs, stdin)
            .await
            .map_err(|error| match error {
                ScriptError::Spawn { .. } | ScriptError::Serialize(_) | ScriptError::Wait(_) => {
                    FilterError::Internal(format!("custom filter {error}"))
                }
                ScriptError::Timeout(_) => FilterError::Internal(format!("custom filter {error}")),
            })?;

        if outcome.output.status.success() {
            Ok(())
        } else {
            Err(FilterError::Denied(ScriptHook::detail(
                &outcome,
                "custom filter script",
            )))
        }
    }
}

#[async_trait]
impl Filter for CustomScriptFilter {
    fn name(&self) -> &'static str {
        "custom"
    }

    async fn check_connection(&self, ctx: &ConnectionContext<'_>) -> Result<(), FilterError> {
        let client_ip_str = ctx
            .client_ip
            .map(|ip| super::canonical(ip).to_string())
            .unwrap_or_default();
        let envs = [
            ("ACME_FILTER_HOOK", "connection"),
            ("ACME_FILTER_CLIENT_IP", client_ip_str.as_str()),
            ("ACME_FILTER_METHOD", ctx.method.as_str()),
            ("ACME_FILTER_PATH", ctx.path),
        ];

        let payload = json!({
            "hook": "connection",
            "client_ip": if client_ip_str.is_empty() { None } else { Some(&client_ip_str) },
            "method": ctx.method.as_str(),
            "path": ctx.path,
        });

        self.run_script(&envs, &payload).await
    }

    async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        let client_ip_str = ctx
            .client_ip
            .map(|ip| super::canonical(ip).to_string())
            .unwrap_or_default();
        let identifiers_vec: Vec<String> =
            ctx.identifiers.iter().map(|i| i.value.clone()).collect();
        let identifiers_str = identifiers_vec.join(",");

        let envs = [
            ("ACME_FILTER_HOOK", "identifiers"),
            ("ACME_FILTER_CLIENT_IP", client_ip_str.as_str()),
            ("ACME_FILTER_ACCOUNT_ID", ctx.account_id),
            ("ACME_FILTER_STAGE", ctx.stage.as_str()),
            ("ACME_FILTER_IDENTIFIERS", identifiers_str.as_str()),
        ];

        let payload = json!({
            "hook": "identifiers",
            "client_ip": if client_ip_str.is_empty() { None } else { Some(&client_ip_str) },
            "account_id": ctx.account_id,
            "stage": ctx.stage.as_str(),
            "identifiers": ctx.identifiers,
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
    fn write_script(dir: &TempDir, name: &str, body: &str) -> CustomFilterConfig {
        let script_path = crate::testutil::write_script(dir, name, body);
        CustomFilterConfig {
            script_path: script_path.to_str().unwrap().to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn missing_script_path_bails() {
        let cfg = CustomFilterConfig {
            script_path: "  ".to_string(),
            ..Default::default()
        };
        assert!(CustomScriptFilter::from_config(&cfg).is_err());
    }

    /// A script that cannot be spawned is `Internal`, never `Denied`: the same
    /// reasoning as `netbox`'s transport failures. A broken hook must stop
    /// requests with a retryable 500, not look like a permanent refusal — and
    /// certainly not fail open.
    #[tokio::test]
    async fn a_script_that_cannot_be_spawned_is_internal_not_denied() {
        let filter = CustomScriptFilter::from_config(&CustomFilterConfig {
            script_path: "/nonexistent/filter.sh".to_string(),
            ..Default::default()
        })
        .unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/newOrder",
        };
        match filter.check_connection(&ctx).await {
            Err(FilterError::Internal(detail)) => {
                assert!(
                    detail.contains("failed to spawn script")
                        && detail.contains("/nonexistent/filter.sh"),
                    "{detail}"
                )
            }
            other => panic!("expected an Internal error, got {other:?}"),
        }

        let identifiers = vec![Identifier::dns("example.com")];
        let ctx = IdentifierContext {
            client_ip: "127.0.0.1".parse().ok(),
            account_id: "acc_1",
            stage: IdentifierStage::NewOrder,
            identifiers: &identifiers,
        };
        assert!(matches!(
            filter.check_identifiers(&ctx).await,
            Err(FilterError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn passing_script_allows() {
        let dir = TempDir::new("filter-custom");
        let cfg = write_script(&dir, "pass.sh", "#!/bin/sh\nexit 0\n");
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/health",
        };
        assert!(filter.check_connection(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn failing_script_denies() {
        let dir = TempDir::new("filter-custom");
        let cfg = write_script(
            &dir,
            "fail.sh",
            "#!/bin/sh\necho \"custom denial\"\nexit 1\n",
        );
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

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
            Err(FilterError::Denied(detail)) => {
                assert!(detail.starts_with("custom denial"), "{detail}");
            }
            other => panic!("expected Denied, got {other:?}"),
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
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

        let identifiers = vec![Identifier::dns("example.com")];
        let ctx = IdentifierContext {
            client_ip: "10.0.0.1".parse().ok(),
            account_id: "acc_123",
            stage: IdentifierStage::NewOrder,
            identifiers: &identifiers,
        };

        assert!(filter.check_identifiers(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn script_timeout_returns_internal() {
        let dir = TempDir::new("filter-custom");
        let cfg = CustomFilterConfig {
            timeout_ms: 100,
            ..write_script(&dir, "sleep.sh", "#!/bin/sh\nsleep 2\nexit 0\n")
        };
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: None,
            method: &Method::GET,
            path: "/health",
        };

        let res = filter.check_connection(&ctx).await;
        match res {
            Err(FilterError::Internal(detail)) => assert!(detail.contains("timed out")),
            other => panic!("expected Internal error on timeout, got {other:?}"),
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
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: "127.0.0.1".parse().ok(),
            method: &Method::GET,
            path: "/newOrder",
        };
        assert_eq!(filter.check_connection(&ctx).await.unwrap(), ());
    }

    /// `tokio::time::timeout` only abandons the future: without `kill_on_drop`,
    /// the child process survives the expiration and, since one process is spawned
    /// per request, a blocked script would accumulate one per call.
    #[tokio::test]
    async fn a_timed_out_script_is_killed_rather_than_left_running() {
        let dir = TempDir::new("filter-custom");
        let marker = dir.path().join("survived");
        let cfg = CustomFilterConfig {
            timeout_ms: 50,
            ..write_script(
                &dir,
                "slow.sh",
                &format!("#!/bin/sh\nsleep 1\ntouch {}\n", marker.to_str().unwrap()),
            )
        };
        let filter = CustomScriptFilter::from_config(&cfg).unwrap();

        let ctx = ConnectionContext {
            client_ip: None,
            method: &Method::GET,
            path: "/newOrder",
        };
        match filter.check_connection(&ctx).await {
            Err(FilterError::Internal(detail)) => assert!(detail.contains("timed out")),
            other => panic!("expected Internal error on timeout, got {other:?}"),
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
