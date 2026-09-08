//! The `custom` check: executes an external script/binary to evaluate requests.
//!
//! The script is told which named check invoked it (`ACME_FILTER_CHECK_NAME`),
//! so one script can serve several `[filter.check.<name>]` entries and branch
//! on which one it is.
//!
//! ## `ACME_FILTER_IDENTIFIERS` carries structure, so its values are checked
//!
//! The identifier list reaches a script twice: as typed JSON on stdin, where
//! each entry is its own object, and as `ACME_FILTER_IDENTIFIERS`, which is the
//! values comma-joined into one string. The second has no escaping, so a value
//! *containing* a comma reads to a script splitting on one as two names — and a
//! value containing a newline does the same to a script reading the variable
//! line-wise.
//!
//! At the `newOrder` stage that cannot happen: every identifier has been through
//! `handlers::helpers::well_formed_name`, whose own doc comment names this
//! variable as the reason it refuses delimiters. At the **CSR** stage it can:
//! `csr_identifiers` projects the subject `CommonName` verbatim as a `cn` entry
//! and renders an unreadable one with `format!("{:?}")` as an `other` entry, and
//! neither is shape-checked — `check_csr_matches_order` only refuses a CN that
//! *looks like* a DNS name, so one carrying a delimiter is waved through as an
//! ordinary human label.
//!
//! [`delimiter_free`] is where that gap is closed, and it is closed **here**
//! rather than at the boundary for three reasons: nothing changes for a
//! deployment with no `custom` check, since the value stays intact for
//! `filter::identifiers`' `deny` regexes (which reach `cn`) and for the JSON on
//! stdin, which is typed and stays the contract for structured data; it covers
//! the `Debug`-rendered `other` variant, which a rule on the CN text alone would
//! miss; and it is fail-closed at the one sink that carries structure over a
//! channel with no way to escape it.
//!
//! The other two comma-joined hook variables need no such guard, and it is worth
//! knowing why rather than rediscovering it: `ACME_SIGNER_IDENTIFIERS`
//! ([`crate::signer::custom`]) and `ACME_NOTIFY_IDENTIFIERS`
//! ([`crate::notify::custom`]) are both joined from the *order*'s identifiers,
//! which `well_formed_name` has already refused a delimiter in.

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
                | ScriptError::Timeout(_)
                // A script that flooded its output decided nothing about this
                // request either — it is a broken script, which is the server's
                // problem and not the client's, so it joins the others rather
                // than becoming a denial.
                | ScriptError::OutputTooLarge { .. }),
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
        // Before the join, and before the script is spawned: a value the
        // variable cannot express unambiguously is refused rather than handed
        // over to be misread. See the module doc for why this is the sink's job.
        if let Some(verdict) = delimiter_free(context.identifiers) {
            return verdict;
        }

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

/// [`Verdict::Fail`] naming the first identifier whose value cannot survive
/// `ACME_FILTER_IDENTIFIERS`, or `None` when every value can.
///
/// Two characters, for the two ways a script reads that variable: a comma,
/// which is the join separator, and any control character — which is a newline
/// for a `while read` loop, and a `NUL` for the `execve` that would otherwise
/// fail with an opaque `InvalidInput` and cost a retryable 500 instead of a
/// clear refusal.
///
/// **The refusal names the identifier's type, never its value.** The value is
/// caller-chosen text, and this string reaches an ACME `badCSR` problem document
/// that goes back over the wire; a server that echoes arbitrary attacker text is
/// a server whose error documents are worth crafting. The type (`cn`, `other`,
/// `dns`) is enough for an operator, and the full identifier list is already in
/// the `certificate_issue_failed` audit row `post_finalize` writes for this arm.
///
/// [`Verdict::Fail`] and not [`Verdict::Undecided`]: nothing failed to be
/// evaluated here — this CSR asks for something the policy cannot express, which
/// is a refusal the client can act on (`badCSR`, 400) rather than a server-side
/// unknown it would retry against for ever.
fn delimiter_free(identifiers: &[crate::sqlite::order::Identifier]) -> Option<Verdict> {
    let offender = identifiers
        .iter()
        .find(|identifier| identifier.value.contains(',') || contains_control(&identifier.value))?;

    Some(Verdict::Fail(format!(
        "{} identifier carries a delimiter or a control character, which \
         ACME_FILTER_IDENTIFIERS cannot express unambiguously",
        offender.typ
    )))
}

/// Whether `value` holds a character that would break a line- or NUL-delimited
/// reading of it. Its own function so [`delimiter_free`] reads as the rule it is.
fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
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

    // --------------------------------------------- ACME_FILTER_IDENTIFIERS

    /// An identifier list a script would misread is refused **before** the
    /// script runs, so the misreading never happens.
    ///
    /// The reachable case is a CSR `CommonName`: `check_csr_matches_order`
    /// refuses one shaped like a DNS name the order does not cover, but a CN
    /// holding a comma is not shaped like a DNS name at all, so it passes as an
    /// ordinary human label and lands in this list. Table-driven over the two
    /// characters and the two identifier types that can carry them.
    #[tokio::test]
    async fn an_identifier_carrying_a_delimiter_is_refused_before_the_script_runs() {
        let dir = TempDir::new("filter-custom");
        // Exits 0: if the guard did not fire, this would answer `Pass` and the
        // assertion below would fail on the verdict rather than on the message.
        let cfg = write_script(&dir, "pass.sh", "#!/bin/sh\nexit 0\n");
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        let cases = [
            (
                "a comma in a cn",
                "cn",
                "evil.example.com,other.example.com",
            ),
            (
                "a newline in a cn",
                "cn",
                "ok.example.com\nevil.example.com",
            ),
            (
                "a carriage return",
                "cn",
                "ok.example.com\revil.example.com",
            ),
            ("a NUL", "cn", "ok.example.com\0evil.example.com"),
            // The `Debug`-rendered variant `csr_identifiers` produces for a
            // CommonName it cannot read as text — a shape no rule on the CN
            // string itself would ever see.
            ("a comma in an other", "other", "BmpString(\"a\", \"b\")"),
        ];

        for (label, typ, value) in cases {
            let identifiers = vec![Identifier::new(typ, value)];
            let ctx = IdentifierContext {
                client_ip: "127.0.0.1".parse().ok(),
                account_id: "acc_1",
                stage: IdentifierStage::Csr,
                identifiers: &identifiers,
                eab: None,
            };

            match filter.check_identifiers(&ctx).await {
                Verdict::Fail(detail) => {
                    assert!(detail.starts_with(typ), "case `{label}`: {detail}");
                    // The value is caller-chosen and this string reaches a
                    // `badCSR` problem document on the wire.
                    assert!(
                        !detail.contains("evil.example.com") && !detail.contains("BmpString"),
                        "case `{label}` echoed the value back: {detail}"
                    );
                }
                other => panic!("case `{label}`: expected Fail, got {other:?}"),
            }
        }
    }

    /// The other direction, and the one that decides whether this rule is worth
    /// having: it must not become a de-facto "a CommonName has to be a DNS
    /// name". rcgen's own default CN is a sentence with spaces in it, and a
    /// certificate whose subject says `Example Corp Issuing CA` is entirely
    /// ordinary — neither carries a delimiter, so neither is this check's
    /// business.
    #[tokio::test]
    async fn an_ordinary_human_label_common_name_still_reaches_the_script() {
        let dir = TempDir::new("filter-custom");
        let cfg = write_script(&dir, "pass.sh", "#!/bin/sh\nexit 0\n");
        let filter = CustomScriptFilter::from_settings("hook", &cfg).unwrap();

        for value in [
            "rcgen self signed cert",
            "Example Corp Issuing CA",
            "ok.example.com",
            "a name with  double  spaces",
        ] {
            let identifiers = vec![
                Identifier::dns("ok.example.com"),
                Identifier::new("cn", value),
            ];
            let ctx = IdentifierContext {
                client_ip: "127.0.0.1".parse().ok(),
                account_id: "acc_1",
                stage: IdentifierStage::Csr,
                identifiers: &identifiers,
                eab: None,
            };
            assert_eq!(
                filter.check_identifiers(&ctx).await,
                Verdict::Pass,
                "`{value}` must still reach the script"
            );
        }
    }

    /// The unit beneath both: `None` is "every value survives the join".
    #[test]
    fn delimiter_free_answers_none_for_a_list_the_variable_can_carry() {
        assert!(delimiter_free(&[]).is_none());
        assert!(
            delimiter_free(&[
                Identifier::dns("a.example.com"),
                Identifier::new("ip", "192.0.2.1"),
                Identifier::new("cn", "Example Corp"),
            ])
            .is_none()
        );
        // A tab is a control character, so it is refused with the rest — a
        // script reading fields off a line would split on it.
        assert!(delimiter_free(&[Identifier::new("cn", "a\tb")]).is_some());
    }
}
