//! The contract every `custom` hook in this server runs under: one script, a
//! cleared environment, JSON on stdin, an exit code for the verdict.
//!
//! Three subsystems delegate to an operator-supplied script —
//! [`signer::custom`](crate::signer::custom) (issue/revoke/crl/renewal_info),
//! [`filter::custom`](crate::filter::custom) (connection/identifiers) and
//! [`notify::custom`](crate::notify::custom) (one event). They differ in what
//! they put in the environment, what they do with stdout, and how they read the
//! exit code. They differ in nothing else.
//!
//! What they shared was a *security* contract — clear the environment so a
//! script cannot read the RFC 2136 TSIG secret or the SMTP password, restore a
//! minimal `PATH`, kill the child when its deadline passes — written out three
//! times, token for token. That is exactly the kind of thing that has to exist
//! once: a hardening applied to one copy is silently absent from the other two,
//! and nobody reviewing one of them can tell.

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;

/// The `PATH` given to the script, since the server environment is cleared
/// before each execution. Without it, a script starting with
/// `#!/usr/bin/env …` would not find its interpreter.
pub(crate) const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// An operator-supplied script, and the budget it runs under.
#[derive(Debug, Clone)]
pub(crate) struct ScriptHook {
    path: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

/// What to hand the script on stdin.
pub(crate) enum ScriptStdin<'a> {
    /// `/dev/null`. The script gets no payload and cannot block on a read.
    Null,
    /// A JSON object, written and then closed.
    Json(&'a serde_json::Value),
}

/// Why a script produced no verdict at all — as opposed to producing one this
/// caller did not like, which is [`ScriptOutcome`]'s business.
#[derive(Debug)]
pub(crate) enum ScriptError {
    Spawn { path: PathBuf, source: String },
    Serialize(String),
    Wait(String),
    Timeout(Duration),
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { path, source } => {
                write!(f, "failed to spawn script {}: {source}", path.display())
            }
            Self::Serialize(detail) => write!(f, "failed to serialize JSON stdin: {detail}"),
            Self::Wait(detail) => write!(f, "script failed: {detail}"),
            Self::Timeout(budget) => {
                write!(f, "script timed out after {} ms", budget.as_millis())
            }
        }
    }
}

/// What a script answered, plus whether it ever read the question.
#[derive(Debug)]
pub(crate) struct ScriptOutcome {
    pub output: Output,
    /// Set when writing the JSON payload to the child's stdin failed — in
    /// practice `EPIPE`, a script that exited without reading it.
    ///
    /// Deliberately not an error on its own. A script whose payload is
    /// `{"hook":"crl"}` and which exits 0 without reading stdin is behaving
    /// perfectly reasonably, and turning that into a failure would break
    /// working deployments. It only matters when the script *also* failed, and
    /// then it matters a great deal: for the signer's `issue` hook, "the script
    /// never saw the CSR" reads nothing like "the script rejected the CSR".
    pub stdin_error: Option<String>,
}

impl ScriptHook {
    /// Builds a hook, or `None` when no script is configured.
    ///
    /// Each subsystem words its own "you enabled this but gave no path" startup
    /// error, because only it knows which configuration key to name and what to
    /// tell the operator to remove.
    pub(crate) fn new(script_path: &str, args: &[String], timeout_ms: u64) -> Option<Self> {
        if script_path.trim().is_empty() {
            return None;
        }
        Some(Self {
            path: PathBuf::from(script_path),
            args: args.to_vec(),
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Runs the script with `envs` in an otherwise empty environment.
    pub(crate) async fn run(
        &self,
        envs: &[(&str, &str)],
        stdin: ScriptStdin<'_>,
    ) -> Result<ScriptOutcome, ScriptError> {
        let mut cmd = Command::new(&self.path);
        cmd.args(&self.args);

        // The script would otherwise inherit the server's entire environment,
        // which legitimately holds secrets: every `ACME_PROXY_*` configuration
        // overlay, including the DNS update TSIG key
        // (`…SIGNER__ACME_PROXY__DNS01__RFC2136__TSIG_KEY_SECRET`) and
        // `notify.email.smtp_password`. An operator-supplied script has no
        // business receiving those, so it starts from nothing and is given only
        // the documented variables plus a `PATH` without which a
        // `#!/usr/bin/env bash` script would not start at all.
        cmd.env_clear();
        cmd.env("PATH", DEFAULT_PATH);
        for (key, value) in envs {
            cmd.env(key, value);
        }

        // `tokio::time::timeout` below only abandons the future. Without this,
        // a child that ignores its deadline outlives it — and since these hooks
        // run once per request or per event, a blocked script would leak one
        // process per call.
        cmd.kill_on_drop(true);

        let piped_stdin = matches!(stdin, ScriptStdin::Json(_));
        cmd.stdin(if piped_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|error| ScriptError::Spawn {
            path: self.path.clone(),
            source: error.to_string(),
        })?;

        let mut stdin_error = None;
        if let ScriptStdin::Json(payload) = stdin {
            let bytes =
                serde_json::to_vec(payload).map_err(|e| ScriptError::Serialize(e.to_string()))?;
            if let Some(mut pipe) = child.stdin.take() {
                // Recorded rather than propagated; see `ScriptOutcome::stdin_error`.
                if let Err(error) = pipe.write_all(&bytes).await {
                    stdin_error = Some(error.to_string());
                } else if let Err(error) = pipe.flush().await {
                    stdin_error = Some(error.to_string());
                }
                if let Some(detail) = &stdin_error {
                    debug!(
                        event = "script_stdin_write_failed",
                        script_path = %self.path.display(),
                        error = %detail,
                    );
                }
                // `pipe` drops here, closing the write end.
            }
        }

        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(ScriptOutcome {
                output,
                stdin_error,
            }),
            Ok(Err(error)) => Err(ScriptError::Wait(error.to_string())),
            Err(_) => Err(ScriptError::Timeout(self.timeout)),
        }
    }

    /// A one-line reason a script's non-zero exit should be reported as.
    ///
    /// First non-empty line of stdout, else of stderr, else the exit status —
    /// prefixed with the stdin failure when there was one, since a script that
    /// never received its payload failed for a completely different reason than
    /// one that read it and objected.
    pub(crate) fn detail(outcome: &ScriptOutcome, noun: &str) -> String {
        let stdout = String::from_utf8_lossy(&outcome.output.stdout);
        let stderr = String::from_utf8_lossy(&outcome.output.stderr);
        let first_line = stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .or_else(|| stderr.lines().find(|line| !line.trim().is_empty()))
            .unwrap_or("")
            .trim();

        let base = if first_line.is_empty() {
            format!("{noun} exited with status {}", outcome.output.status)
        } else {
            first_line.to_string()
        };

        match &outcome.stdin_error {
            Some(error) => format!("{base} (the script did not read its input: {error})"),
            None => base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, write_script};

    fn hook(path: &Path, timeout_ms: u64) -> ScriptHook {
        ScriptHook::new(&path.display().to_string(), &[], timeout_ms).unwrap()
    }

    #[test]
    fn a_blank_script_path_builds_no_hook() {
        assert!(ScriptHook::new("", &[], 1000).is_none());
        assert!(ScriptHook::new("   ", &[], 1000).is_none());
        assert!(ScriptHook::new("/bin/true", &[], 1000).is_some());
    }

    #[tokio::test]
    async fn a_missing_script_is_a_spawn_error() {
        let hook = ScriptHook::new("/nonexistent/script", &[], 1000).unwrap();
        let error = hook.run(&[], ScriptStdin::Null).await.unwrap_err();
        assert!(matches!(error, ScriptError::Spawn { .. }), "got {error:?}");
        assert!(error.to_string().contains("/nonexistent/script"));
    }

    /// The hardening this module exists to hold in one place: the script must
    /// not inherit the server's environment, which carries the RFC 2136 TSIG
    /// key and the SMTP password among other things.
    #[tokio::test]
    async fn the_script_does_not_inherit_the_server_environment() {
        let dir = TempDir::new("script-hook");
        let script = write_script(
            &dir,
            "env.sh",
            "#!/bin/sh\necho \"MANIFEST=${CARGO_MANIFEST_DIR:-unset}\"\necho \"GIVEN=${ACME_TEST_VAR:-unset}\"\nexit 0\n",
        );

        let outcome = hook(&script, 5_000)
            .run(&[("ACME_TEST_VAR", "provided")], ScriptStdin::Null)
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&outcome.output.stdout);

        assert!(
            stdout.contains("MANIFEST=unset"),
            "the server's own environment must not leak: {stdout}"
        );
        assert!(
            stdout.contains("GIVEN=provided"),
            "the documented variables must be passed: {stdout}"
        );
    }

    #[tokio::test]
    async fn the_script_receives_its_json_payload_on_stdin() {
        let dir = TempDir::new("script-hook");
        let script = write_script(&dir, "cat.sh", "#!/bin/sh\ncat\nexit 0\n");

        let payload = serde_json::json!({ "hook": "issue", "order_id": "abc" });
        let outcome = hook(&script, 5_000)
            .run(&[], ScriptStdin::Json(&payload))
            .await
            .unwrap();

        let stdout = String::from_utf8_lossy(&outcome.output.stdout);
        assert!(stdout.contains("\"order_id\":\"abc\""), "{stdout}");
        assert!(outcome.stdin_error.is_none());
    }

    /// A script that exits without reading stdin is not a failure — the `crl`
    /// hook's payload is `{"hook":"crl"}` and ignoring it is reasonable.
    #[tokio::test]
    async fn a_script_that_ignores_its_stdin_still_succeeds() {
        let dir = TempDir::new("script-hook");
        // Large enough that the write cannot all fit in the pipe buffer, so the
        // failure is actually observable rather than silently absorbed.
        let script = write_script(&dir, "ignore.sh", "#!/bin/sh\nexit 0\n");

        let payload = serde_json::json!({ "blob": "x".repeat(256 * 1024) });
        let outcome = hook(&script, 5_000)
            .run(&[], ScriptStdin::Json(&payload))
            .await
            .unwrap();

        assert!(outcome.output.status.success());
    }

    #[tokio::test]
    async fn a_timed_out_script_is_killed_rather_than_left_running() {
        let dir = TempDir::new("script-hook");
        let marker = dir.path().join("still-running");
        let script = write_script(
            &dir,
            "slow.sh",
            &format!("#!/bin/sh\nsleep 1\ntouch {}\nexit 0\n", marker.display()),
        );

        let error = hook(&script, 100)
            .run(&[], ScriptStdin::Null)
            .await
            .unwrap_err();
        assert!(matches!(error, ScriptError::Timeout(_)), "got {error:?}");

        // `kill_on_drop` must have taken the child with the abandoned future;
        // without it the script would go on to create this file.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert!(
            !marker.exists(),
            "the script outlived its deadline and kept running"
        );
    }

    #[tokio::test]
    async fn detail_prefers_stdout_then_stderr_then_the_status() {
        let dir = TempDir::new("script-hook");

        let both = write_script(
            &dir,
            "both.sh",
            "#!/bin/sh\necho 'from stdout'\necho 'from stderr' >&2\nexit 1\n",
        );
        let outcome = hook(&both, 5_000)
            .run(&[], ScriptStdin::Null)
            .await
            .unwrap();
        assert_eq!(ScriptHook::detail(&outcome, "test script"), "from stdout");

        let stderr_only = write_script(
            &dir,
            "stderr.sh",
            "#!/bin/sh\necho 'from stderr' >&2\nexit 1\n",
        );
        let outcome = hook(&stderr_only, 5_000)
            .run(&[], ScriptStdin::Null)
            .await
            .unwrap();
        assert_eq!(ScriptHook::detail(&outcome, "test script"), "from stderr");

        let silent = write_script(&dir, "silent.sh", "#!/bin/sh\nexit 3\n");
        let outcome = hook(&silent, 5_000)
            .run(&[], ScriptStdin::Null)
            .await
            .unwrap();
        let detail = ScriptHook::detail(&outcome, "test script");
        assert!(
            detail.starts_with("test script exited with status"),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn detail_says_when_the_script_never_read_its_input() {
        let outcome = ScriptOutcome {
            output: std::process::Output {
                status: Default::default(),
                stdout: b"bad CSR\n".to_vec(),
                stderr: Vec::new(),
            },
            stdin_error: Some("Broken pipe (os error 32)".to_string()),
        };
        let detail = ScriptHook::detail(&outcome, "custom signer script");
        assert!(detail.contains("bad CSR"), "{detail}");
        assert!(
            detail.contains("did not read its input"),
            "a script that never saw the CSR must not read as one that rejected it: {detail}"
        );
    }

    #[tokio::test]
    async fn the_configured_arguments_are_passed() {
        let dir = TempDir::new("script-hook");
        let script = write_script(&dir, "args.sh", "#!/bin/sh\necho \"$1|$2\"\nexit 0\n");

        let hook = ScriptHook::new(
            &script.display().to_string(),
            &["first".to_string(), "second".to_string()],
            5_000,
        )
        .unwrap();
        let outcome = hook.run(&[], ScriptStdin::Null).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&outcome.output.stdout).trim(),
            "first|second"
        );
    }
}
