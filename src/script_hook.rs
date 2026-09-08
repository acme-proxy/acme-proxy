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
//! minimal `PATH`, kill the child when its deadline passes, and bound how much
//! it may write ([`MAX_SCRIPT_OUTPUT_BYTES`]) — written out three times, token
//! for token. That is exactly the kind of thing that has to exist once: a
//! hardening applied to one copy is silently absent from the other two, and
//! nobody reviewing one of them can tell.

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

/// Most a script may write to one stream before it is refused.
///
/// Per stream, not combined, so a script that logs to stderr does not spend the
/// budget its answer needs on stdout.
///
/// The value is generous on purpose — every legitimate answer is far below it. A
/// signer's PEM chain is kilobytes; a megabyte of IPAM names is on the order of
/// twenty thousand of them. What the ceiling exists for is the runaway case: a
/// script in a loop, or one that `cat`s something it should not, whose output
/// this process would otherwise buffer whole. The hook timeout bounds how *long*
/// that goes on and says nothing about how large it gets, which on the `ipam`
/// and `filter` hooks is a per-request cost.
///
/// Deliberately its own constant rather than `http_client::MAX_RESPONSE_BYTES`,
/// which happens to carry the same number: that one is a ceiling on a remote
/// party's HTTP body and this is a ceiling on a local child's pipe, and a future
/// reason to move one is not a reason to move the other.
pub(crate) const MAX_SCRIPT_OUTPUT_BYTES: usize = 1024 * 1024;

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
#[derive(Debug, thiserror::Error)]
pub(crate) enum ScriptError {
    #[error("failed to spawn script {}: {detail}", path.display())]
    Spawn { path: PathBuf, detail: String },
    #[error("failed to serialize JSON stdin: {0}")]
    Serialize(String),
    #[error("script failed: {0}")]
    Wait(String),
    #[error("script timed out after {} ms", .0.as_millis())]
    Timeout(Duration),
    /// The script wrote more than [`MAX_SCRIPT_OUTPUT_BYTES`] to one stream.
    ///
    /// An error rather than a silent truncation, and the `signer` hook is why:
    /// a PEM chain cut off in the middle would arrive as an unparsable
    /// certificate, and the operator would go looking at their CA instead of at
    /// the script. A named refusal says which it was.
    #[error("script wrote more than {limit} bytes to {stream}")]
    OutputTooLarge { limit: usize, stream: &'static str },
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
        // (`…SIGNER__RELAY__DNS01__RFC2136__TSIG_KEY_SECRET`) and
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
            detail: error.to_string(),
        })?;

        // Taken out of the child before anything awaits on it: `wait()` needs
        // `&mut child`, and the reads below have to run *concurrently* with it
        // rather than after. A script that fills a pipe buffer nobody is
        // draining blocks in `write` and never exits, so reading only once the
        // child had exited would deadlock until the timeout on exactly the
        // output this function exists to collect.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

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
                        outcome = "failure",
                        script_path = %self.path.display(),
                        error = %detail,
                    );
                }
                // `pipe` drops here, closing the write end.
            }
        }

        // `wait_with_output()`'s job, minus its unbounded appetite: it collects
        // both pipes with no ceiling, which on the `filter` and `ipam` hooks is
        // a per-request allocation an operator script gets to choose the size
        // of. The three futures are joined rather than sequenced for the reason
        // given at the `take()` above.
        let collect = async {
            let (status, stdout, stderr) = tokio::try_join!(
                async {
                    child
                        .wait()
                        .await
                        .map_err(|e| ScriptError::Wait(e.to_string()))
                },
                read_capped(stdout_pipe, "stdout"),
                read_capped(stderr_pipe, "stderr"),
            )?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        };

        match tokio::time::timeout(self.timeout, collect).await {
            Ok(Ok(output)) => Ok(ScriptOutcome {
                output,
                stdin_error,
            }),
            Ok(Err(error)) => Err(error),
            // The child is killed here rather than left running: `kill_on_drop`
            // is set above and `child` is dropped as this future is. That covers
            // the `OutputTooLarge` arm too, where the script is very likely
            // still writing into a pipe this side has stopped reading.
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

/// Reads one of the child's pipes to EOF, refusing it past
/// [`MAX_SCRIPT_OUTPUT_BYTES`].
///
/// `take(limit + 1)` rather than `take(limit)` is what makes "exactly at the
/// limit" distinguishable from "over it": a reader capped at the limit hands
/// back a full buffer in both cases and cannot tell whether more was waiting.
///
/// `None` — a pipe already taken, which cannot happen from [`ScriptHook::run`]
/// since both are `Stdio::piped()` — reads as empty rather than as an error,
/// matching what `wait_with_output` does with an absent pipe.
async fn read_capped(
    pipe: Option<impl tokio::io::AsyncRead + Unpin>,
    stream: &'static str,
) -> Result<Vec<u8>, ScriptError> {
    use tokio::io::AsyncReadExt;

    let Some(pipe) = pipe else {
        return Ok(Vec::new());
    };

    let limit = MAX_SCRIPT_OUTPUT_BYTES;
    let mut buffer = Vec::new();
    pipe.take(limit as u64 + 1)
        .read_to_end(&mut buffer)
        .await
        .map_err(|error| ScriptError::Wait(error.to_string()))?;

    if buffer.len() > limit {
        return Err(ScriptError::OutputTooLarge { limit, stream });
    }
    Ok(buffer)
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

    // ------------------------------------------------------- the output cap

    /// A script that floods a stream is refused rather than buffered whole.
    ///
    /// Both streams, because they are read by two separate futures and a cap
    /// applied to only one of them is exactly the shape this would regress into.
    /// The generous timeout is deliberate: it must be the *size* that refuses
    /// this, not the clock, or the test would pass against no cap at all.
    #[tokio::test]
    async fn a_script_that_floods_a_stream_is_refused_rather_than_buffered() {
        let dir = TempDir::new("script-hook");
        // `yes` is a tight loop with no sleep in it, so this reaches the cap in
        // well under the timeout on any machine that can run the suite.
        let cases = [
            ("stdout", "#!/bin/sh\nyes 0123456789abcdef\n"),
            ("stderr", "#!/bin/sh\nyes 0123456789abcdef >&2\n"),
        ];

        for (stream, body) in cases {
            let script = write_script(&dir, &format!("flood-{stream}.sh"), body);
            let error = hook(&script, 30_000)
                .run(&[], ScriptStdin::Null)
                .await
                .unwrap_err();

            match error {
                ScriptError::OutputTooLarge { limit, stream: got } => {
                    assert_eq!(limit, MAX_SCRIPT_OUTPUT_BYTES);
                    assert_eq!(got, stream, "the wrong stream was named");
                }
                other => panic!("expected OutputTooLarge for {stream}, got {other:?}"),
            }
        }
    }

    /// The other side of the boundary, and the one that decides whether the cap
    /// is usable: output an honest script produces must still arrive whole.
    ///
    /// A quarter of the ceiling is far more than any real hook writes — the
    /// largest is a signer's PEM chain — so a cap that started truncating
    /// legitimate answers would show up here.
    #[tokio::test]
    async fn output_under_the_cap_arrives_intact() {
        let dir = TempDir::new("script-hook");
        let count = MAX_SCRIPT_OUTPUT_BYTES / 4 / 16;
        let script = write_script(
            &dir,
            "bulk.sh",
            &format!("#!/bin/sh\nyes 0123456789abcde | head -n {count}\nexit 0\n"),
        );

        let outcome = hook(&script, 30_000).run(&[], ScriptStdin::Null).await;
        let outcome = outcome.expect("output under the cap must not be refused");

        assert!(outcome.output.status.success());
        // 15 payload bytes plus a newline, per line.
        assert_eq!(outcome.output.stdout.len(), count * 16);
        assert!(outcome.output.stderr.is_empty());
    }

    /// The pipes are read *while* the child runs, not after it exits.
    ///
    /// This is what `wait_with_output` did for free and what taking the pipes
    /// out by hand can quietly lose: a script writing more than one pipe buffer
    /// (64 KiB on Linux) blocks in `write` until somebody drains it, so a
    /// `wait()` that ran to completion first would deadlock here until the
    /// timeout — and report `Timeout`, not this output.
    #[tokio::test]
    async fn a_script_writing_more_than_one_pipe_buffer_does_not_deadlock() {
        let dir = TempDir::new("script-hook");
        // 512 KiB, comfortably past any platform's pipe buffer and comfortably
        // under the cap.
        let count = 32_768;
        let script = write_script(
            &dir,
            "chatty.sh",
            &format!("#!/bin/sh\nyes 0123456789abcde | head -n {count}\nexit 0\n"),
        );

        let outcome = hook(&script, 10_000)
            .run(&[], ScriptStdin::Null)
            .await
            .expect("a script filling the pipe buffer must not time out");
        assert_eq!(outcome.output.stdout.len(), count * 16);
    }
}
