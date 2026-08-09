//! The `custom` signer backend: delegates issuance and revocation to an
//! external script.

use async_trait::async_trait;
use base64::prelude::*;
use serde_json::json;
use tracing::{info, warn};

use super::{IssueOutcome, RenewalWindow, RequestedValidity, SignerBackend, SignerError};
use crate::config::CustomSignerConfig;
use crate::script_hook::{ScriptHook, ScriptOutcome, ScriptStdin};
use crate::sqlite::order::Identifier;

/// Exit code reserved for "the CSR is bad" on the `issue` hook — any other
/// non-zero exit is treated as an internal signer failure. `1` is
/// deliberately not used for this: it's the exit code a script under
/// `set -e` produces for an unrelated bug, and mapping that to a 400 would
/// hide a real 500 behind a client-facing error.
const BAD_CSR_EXIT_CODE: i32 = 3;

/// Delegates issuance/revocation to an external script.
#[derive(Debug)]
pub struct CustomScriptSigner {
    hook: ScriptHook,
    supports_crl: bool,
    supports_renewal_info: bool,
}

impl CustomScriptSigner {
    /// Validates the configuration and creates the signer.
    pub fn from_config(cfg: &CustomSignerConfig) -> anyhow::Result<Self> {
        let Some(hook) = ScriptHook::new(&cfg.script_path, &cfg.args, cfg.timeout_ms) else {
            anyhow::bail!(
                "signer.backend is \"custom\" but signer.custom.script_path is empty; \
                 provide a path to an executable script"
            );
        };

        info!(
            event = "signer_custom_loaded",
            script_path = %hook.path().display(),
            timeout_ms = cfg.timeout_ms,
            supports_crl = cfg.supports_crl,
            supports_renewal_info = cfg.supports_renewal_info,
            args = ?cfg.args,
        );

        Ok(Self {
            hook,
            supports_crl: cfg.supports_crl,
            supports_renewal_info: cfg.supports_renewal_info,
        })
    }

    /// Runs the script and returns its raw outcome.
    ///
    /// Everything that stopped it answering becomes `SignerError::Internal`; a
    /// non-zero exit status is deliberately *not* an error here, because each
    /// hook reads its own exit codes differently — `issue` reserves one for
    /// "bad CSR", the others do not.
    async fn run_script(
        &self,
        envs: &[(&str, &str)],
        payload: &serde_json::Value,
    ) -> Result<ScriptOutcome, SignerError> {
        self.hook
            .run(envs, ScriptStdin::Json(payload))
            .await
            .map_err(|error| SignerError::Internal(format!("custom signer {error}")))
    }

    /// A one-line reason for a non-zero exit; see [`ScriptHook::detail`].
    fn detail_from(outcome: &ScriptOutcome) -> String {
        ScriptHook::detail(outcome, "custom signer script")
    }
}

#[async_trait]
impl SignerBackend for CustomScriptSigner {
    async fn issue(
        &self,
        order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        // The script decides its own validity; there is no contract for passing
        // a requested window to it, and inventing one would break every existing
        // script. RFC 8555 §7.4 permits ignoring the request.
        let _ = validity;
        let identifiers_str = identifiers
            .iter()
            .map(|i| i.value.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let envs = [
            ("ACME_SIGNER_HOOK", "issue"),
            ("ACME_SIGNER_ORDER_ID", order_id),
            ("ACME_SIGNER_IDENTIFIERS", identifiers_str.as_str()),
        ];
        let payload = json!({
            "hook": "issue",
            "order_id": order_id,
            "identifiers": identifiers,
            "csr_der_base64": BASE64_STANDARD.encode(csr_der),
        });

        let outcome = self.run_script(&envs, &payload).await?;
        let output = &outcome.output;
        if output.status.success() {
            // Trim, then put back exactly one trailing newline: a PEM chain
            // must end with one after its last "-----END CERTIFICATE-----"
            // (RFC 7468) for a strict parser to recognize that block at all —
            // certbot's own chain splitter is one such parser, and a bare
            // `.trim()` here silently produced a chain it rejected as having
            // "less than 2 certificates", even though the bytes were
            // otherwise perfectly valid.
            let chain = String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string()
                + "\n";
            return Ok(IssueOutcome::Issued(chain));
        }
        if output.status.code() == Some(BAD_CSR_EXIT_CODE) {
            return Err(SignerError::BadCsr);
        }
        Err(SignerError::Internal(Self::detail_from(&outcome)))
    }

    async fn revoke(&self, cert_der: &[u8], reason: Option<u32>) -> Result<(), SignerError> {
        let reason_str = reason.map(|r| r.to_string()).unwrap_or_default();
        let envs = [
            ("ACME_SIGNER_HOOK", "revoke"),
            ("ACME_SIGNER_REASON", reason_str.as_str()),
        ];
        let payload = json!({
            "hook": "revoke",
            "cert_der_base64": BASE64_STANDARD.encode(cert_der),
            "reason": reason,
        });

        let outcome = self.run_script(&envs, &payload).await?;
        let output = &outcome.output;
        if output.status.success() {
            Ok(())
        } else {
            Err(SignerError::Internal(Self::detail_from(&outcome)))
        }
    }

    async fn crl_der(&self) -> Option<Vec<u8>> {
        if !self.supports_crl {
            return None;
        }
        let envs = [("ACME_SIGNER_HOOK", "crl")];
        let payload = json!({ "hook": "crl" });

        match self.run_script(&envs, &payload).await {
            Ok(outcome) if outcome.output.status.success() => {
                if outcome.output.stdout.is_empty() {
                    None
                } else {
                    Some(outcome.output.stdout)
                }
            }
            // Two different failures: the script ran and refused (a non-zero
            // exit), versus the script could not be run at all (spawn, timeout,
            // a missing binary). Only the second is the operator's own
            // configuration.
            Ok(outcome) => {
                warn!(
                    event = "signer_custom_crl_rejected",
                    detail = %Self::detail_from(&outcome),
                );
                None
            }
            Err(err) => {
                warn!(event = "signer_custom_crl_failed", detail = %err);
                None
            }
        }
    }

    /// Stdout contract: empty for "no opinion", `<start> <end>` as epoch
    /// seconds, or `<start> <end> <explanationURL>` to also supply RFC 9773
    /// §4.2's optional `explanationURL`. The URL is last and optional so an
    /// existing two-token script keeps working unchanged.
    async fn renewal_info(&self, cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        if !self.supports_renewal_info {
            return Ok(None);
        }
        let envs = [("ACME_SIGNER_HOOK", "renewal_info")];
        let payload = json!({
            "hook": "renewal_info",
            "cert_der_base64": BASE64_STANDARD.encode(cert_der),
        });

        let outcome = self.run_script(&envs, &payload).await?;
        let output = &outcome.output;
        if !output.status.success() {
            return Err(SignerError::Internal(Self::detail_from(&outcome)));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let tokens = text.split_whitespace().collect::<Vec<_>>();
        let (start, end, explanation_url) = match tokens.as_slice() {
            [] => return Ok(None),
            [start, end] => (*start, *end, None),
            [start, end, url] => (*start, *end, Some((*url).to_string())),
            other => {
                return Err(SignerError::Internal(format!(
                    "custom signer renewal_info: expected \"<start> <end> [explanationURL]\" or empty stdout, got {} token(s)",
                    other.len()
                )));
            }
        };

        let start = start.parse::<i64>().map_err(|_| {
            SignerError::Internal(format!(
                "custom signer renewal_info: non-integer start `{start}`"
            ))
        })?;
        let end = end.parse::<i64>().map_err(|_| {
            SignerError::Internal(format!(
                "custom signer renewal_info: non-integer end `{end}`"
            ))
        })?;

        Ok(Some(RenewalWindow {
            start,
            end,
            explanation_url,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::time::Duration;

    /// Writes an executable script and returns the configuration pointing at it.
    /// The `ETXTBSY` reasoning lives in `crate::testutil::write_script`.
    fn write_script(dir: &TempDir, name: &str, body: &str) -> CustomSignerConfig {
        let script_path = crate::testutil::write_script(dir, name, body);
        CustomSignerConfig {
            script_path: script_path.to_str().unwrap().to_string(),
            ..Default::default()
        }
    }

    fn identifiers() -> Vec<Identifier> {
        vec![Identifier::dns("example.com")]
    }

    #[test]
    fn missing_script_path_bails() {
        let cfg = CustomSignerConfig {
            script_path: "  ".to_string(),
            ..Default::default()
        };
        assert!(CustomScriptSigner::from_config(&cfg).is_err());
    }

    /// A script path that exists at startup but not when issuance runs — an
    /// operator repackaging the deployment, say. The spawn failure has to name
    /// the script and map to `Internal`, not `BadCsr`: nothing is wrong with
    /// the client's request.
    #[tokio::test]
    async fn a_script_that_cannot_be_spawned_is_internal() {
        let signer = CustomScriptSigner::from_config(&CustomSignerConfig {
            script_path: "/nonexistent/sign.sh".to_string(),
            supports_crl: true,
            supports_renewal_info: true,
            ..Default::default()
        })
        .unwrap();

        match signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
        {
            Err(SignerError::Internal(detail)) => {
                assert!(
                    detail.contains("failed to spawn script") && detail.contains("/nonexistent"),
                    "{detail}"
                )
            }
            other => panic!("expected an Internal error, got {other:?}"),
        }

        // Every other hook goes through the same spawn, so each must report
        // rather than pretend success — a silent `revoke` would be the worst of
        // them, leaving a certificate trusted that an operator believes is not.
        assert!(matches!(
            signer.revoke(&[0x30, 0x00], None).await,
            Err(SignerError::Internal(_))
        ));
        assert!(signer.crl_der().await.is_none());
        assert!(matches!(
            signer.renewal_info(&[0x30, 0x00]).await,
            Err(SignerError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn issue_success_returns_the_chain() {
        let dir = TempDir::new("signer-custom");
        let cfg = write_script(
            &dir,
            "issue.sh",
            "#!/bin/sh\ncat > /dev/null\necho '-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----'\nexit 0\n",
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        let outcome = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        match outcome {
            IssueOutcome::Issued(chain) => {
                assert!(chain.contains("-----BEGIN CERTIFICATE-----leaf"))
            }
            IssueOutcome::Processing => panic!("custom signer must always issue synchronously"),
        }
    }

    /// RFC 7468 requires a trailing newline after each PEM block's
    /// "-----END CERTIFICATE-----" line, and a strict parser (certbot's own
    /// chain-splitting regex among them) silently sees one fewer certificate
    /// without it. A script's stdout may or may not end with one; either way
    /// the chain handed to `IssueOutcome::Issued` must end with exactly one.
    #[tokio::test]
    async fn issue_chain_always_ends_with_exactly_one_trailing_newline() {
        let dir = TempDir::new("signer-custom");
        // `printf` (unlike `echo`) adds no trailing newline of its own, so
        // this script's raw stdout ends right after the second cert's
        // "-----END CERTIFICATE-----" with no newline at all.
        let cfg = write_script(
            &dir,
            "issue.sh",
            "#!/bin/sh\ncat > /dev/null\nprintf -- '-----BEGIN CERTIFICATE-----\\nleaf\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nca\\n-----END CERTIFICATE-----'\nexit 0\n",
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        let outcome = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        let chain = match outcome {
            IssueOutcome::Issued(chain) => chain,
            IssueOutcome::Processing => panic!("custom signer must always issue synchronously"),
        };
        assert!(
            chain.ends_with("-----END CERTIFICATE-----\n") && !chain.ends_with("-----\n\n"),
            "chain must end with exactly one trailing newline, got {chain:?}"
        );
    }

    #[tokio::test]
    async fn issue_bad_csr_exit_code_maps_to_bad_csr() {
        let dir = TempDir::new("signer-custom");
        let cfg = write_script(
            &dir,
            "bad_csr.sh",
            "#!/bin/sh\ncat > /dev/null\necho 'csr does not match order'\nexit 3\n",
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        let result = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await;
        assert!(matches!(result, Err(SignerError::BadCsr)));
    }

    #[tokio::test]
    async fn issue_other_failure_maps_to_internal_with_detail() {
        let dir = TempDir::new("signer-custom");
        let cfg = write_script(
            &dir,
            "fail.sh",
            "#!/bin/sh\ncat > /dev/null\necho 'signing backend unreachable'\nexit 1\n",
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        let result = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await;
        match result {
            Err(SignerError::Internal(detail)) => {
                assert_eq!(detail, "signing backend unreachable")
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issue_receives_env_and_stdin() {
        let dir = TempDir::new("signer-custom");
        let script = r#"#!/bin/sh
if [ "$ACME_SIGNER_HOOK" != "issue" ]; then echo "wrong hook: $ACME_SIGNER_HOOK"; exit 1; fi
if [ "$ACME_SIGNER_ORDER_ID" != "ord-42" ]; then echo "wrong order id"; exit 1; fi
if [ "$ACME_SIGNER_IDENTIFIERS" != "example.com" ]; then echo "wrong identifiers: $ACME_SIGNER_IDENTIFIERS"; exit 1; fi
STDIN=$(cat)
case "$STDIN" in
  *csr_der_base64*) ;;
  *) echo "stdin missing csr_der_base64"; exit 1 ;;
esac
echo '-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----'
exit 0
"#;
        let cfg = write_script(&dir, "check_env.sh", script);
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        let outcome = signer
            .issue(
                "ord-42",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, IssueOutcome::Issued(_)));
    }

    #[tokio::test]
    async fn revoke_success() {
        let dir = TempDir::new("signer-custom");
        let cfg = write_script(&dir, "revoke.sh", "#!/bin/sh\ncat > /dev/null\nexit 0\n");
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.revoke(&[0x30, 0x00], Some(1)).await.is_ok());
    }

    #[tokio::test]
    async fn revoke_receives_reason() {
        let dir = TempDir::new("signer-custom");
        let script = r#"#!/bin/sh
cat > /dev/null
if [ "$ACME_SIGNER_REASON" != "4" ]; then echo "wrong reason: $ACME_SIGNER_REASON"; exit 1; fi
exit 0
"#;
        let cfg = write_script(&dir, "revoke_reason.sh", script);
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.revoke(&[0x30, 0x00], Some(4)).await.is_ok());
    }

    #[tokio::test]
    async fn revoke_failure_maps_to_internal() {
        let dir = TempDir::new("signer-custom");
        let cfg = write_script(
            &dir,
            "revoke_fail.sh",
            "#!/bin/sh\ncat > /dev/null\necho 'already gone'\nexit 1\n",
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        match signer.revoke(&[0x30, 0x00], None).await {
            Err(SignerError::Internal(detail)) => assert_eq!(detail, "already gone"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn crl_der_disabled_by_default_never_spawns() {
        let dir = TempDir::new("signer-custom");
        let marker = dir.path().join("ran");
        let cfg = write_script(
            &dir,
            "crl.sh",
            &format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.to_str().unwrap()),
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.crl_der().await.is_none());
        assert!(!marker.exists(), "crl hook must not run when disabled");
    }

    #[tokio::test]
    async fn crl_der_enabled_returns_raw_bytes() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(
            &dir,
            "crl.sh",
            "#!/bin/sh\ncat > /dev/null\nprintf 'fake-der-bytes'\nexit 0\n",
        );
        cfg.supports_crl = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert_eq!(signer.crl_der().await, Some(b"fake-der-bytes".to_vec()));
    }

    #[tokio::test]
    async fn crl_der_empty_stdout_is_none() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(&dir, "crl.sh", "#!/bin/sh\ncat > /dev/null\nexit 0\n");
        cfg.supports_crl = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.crl_der().await.is_none());
    }

    #[tokio::test]
    async fn crl_der_script_failure_degrades_to_none() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(&dir, "crl.sh", "#!/bin/sh\ncat > /dev/null\nexit 1\n");
        cfg.supports_crl = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.crl_der().await.is_none());
    }

    #[tokio::test]
    async fn renewal_info_disabled_by_default_never_spawns() {
        let dir = TempDir::new("signer-custom");
        let marker = dir.path().join("ran");
        let cfg = write_script(
            &dir,
            "ari.sh",
            &format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.to_str().unwrap()),
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert_eq!(signer.renewal_info(&[0x30, 0x00]).await.unwrap(), None);
        assert!(
            !marker.exists(),
            "renewal_info hook must not run when disabled"
        );
    }

    #[tokio::test]
    async fn renewal_info_enabled_parses_window() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(
            &dir,
            "ari.sh",
            "#!/bin/sh\ncat > /dev/null\necho '1000 2000'\nexit 0\n",
        );
        cfg.supports_renewal_info = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert_eq!(
            signer.renewal_info(&[0x30, 0x00]).await.unwrap(),
            Some(RenewalWindow::new(1000, 2000))
        );
    }

    /// The optional third token: RFC 9773 §4.2's `explanationURL`. Two tokens
    /// must keep working unchanged, which the test above covers.
    #[tokio::test]
    async fn renewal_info_parses_an_optional_explanation_url() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(
            &dir,
            "ari.sh",
            "#!/bin/sh\ncat > /dev/null\necho '1000 2000 https://ca.example/why'\nexit 0\n",
        );
        cfg.supports_renewal_info = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert_eq!(
            signer.renewal_info(&[0x30, 0x00]).await.unwrap(),
            Some(RenewalWindow {
                start: 1000,
                end: 2000,
                explanation_url: Some("https://ca.example/why".to_string()),
            })
        );
    }

    /// A fourth token is not a URL with a space in it — it is a script bug, and
    /// guessing which tokens were meant to be the URL would serve a wrong one.
    #[tokio::test]
    async fn renewal_info_rejects_more_than_three_tokens() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(
            &dir,
            "ari.sh",
            "#!/bin/sh\ncat > /dev/null\necho '1000 2000 a b'\nexit 0\n",
        );
        cfg.supports_renewal_info = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(matches!(
            signer.renewal_info(&[0x30, 0x00]).await,
            Err(SignerError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn renewal_info_enabled_blank_stdout_is_no_opinion() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(&dir, "ari.sh", "#!/bin/sh\ncat > /dev/null\nexit 0\n");
        cfg.supports_renewal_info = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert_eq!(signer.renewal_info(&[0x30, 0x00]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn renewal_info_enabled_garbage_stdout_is_internal_error() {
        let dir = TempDir::new("signer-custom");
        let mut cfg = write_script(
            &dir,
            "ari.sh",
            "#!/bin/sh\ncat > /dev/null\necho 'nonsense'\nexit 0\n",
        );
        cfg.supports_renewal_info = true;
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        assert!(signer.renewal_info(&[0x30, 0x00]).await.is_err());
    }

    /// Two tokens is the right *shape*, so the arity check passes and the
    /// timestamps are parsed. A script emitting a date string instead of a
    /// Unix timestamp is the likely mistake, and it has to name which end was
    /// wrong rather than silently producing a window in 1970.
    #[tokio::test]
    async fn renewal_info_rejects_a_non_integer_timestamp() {
        for (script, expected) in [
            (
                "echo '2026-01-01T00:00:00Z 1800000000'",
                "non-integer start",
            ),
            ("echo '1700000000 2026-01-01T00:00:00Z'", "non-integer end"),
        ] {
            let dir = TempDir::new("signer-custom");
            let mut cfg = write_script(
                &dir,
                "ari.sh",
                &format!("#!/bin/sh\ncat > /dev/null\n{script}\nexit 0\n"),
            );
            cfg.supports_renewal_info = true;
            let signer = CustomScriptSigner::from_config(&cfg).unwrap();

            match signer.renewal_info(&[0x30, 0x00]).await {
                Err(SignerError::Internal(detail)) => {
                    assert!(detail.contains(expected), "expected {expected:?}: {detail}")
                }
                other => panic!("expected an Internal error, got {other:?}"),
            }
        }
    }

    /// The server carries secrets in its environment (e.g. the RFC 2136 TSIG
    /// secret, which lives inside this very `[signer]` config tree), so a
    /// script provided by the operator must not inherit anything.
    #[tokio::test]
    async fn the_script_does_not_inherit_the_server_environment() {
        assert!(
            std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
            "the canary must exist in the parent, otherwise the test proves nothing"
        );

        let dir = TempDir::new("signer-custom");
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
if [ "$ACME_SIGNER_HOOK" != "issue" ]; then
    echo "missing ACME_SIGNER_HOOK"
    exit 1
fi
echo '-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----'
exit 0
"#,
        );
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();
        let outcome = signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, IssueOutcome::Issued(_)));
    }

    #[tokio::test]
    async fn script_timeout_returns_internal() {
        let dir = TempDir::new("signer-custom");
        let cfg = CustomSignerConfig {
            timeout_ms: 100,
            ..write_script(
                &dir,
                "sleep.sh",
                "#!/bin/sh\ncat > /dev/null\nsleep 2\nexit 0\n",
            )
        };
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        match signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
        {
            Err(SignerError::Internal(detail)) => assert!(detail.contains("timed out")),
            other => panic!("expected Internal error on timeout, got {other:?}"),
        }
    }

    /// `tokio::time::timeout` only abandons the future: without
    /// `kill_on_drop`, the child process survives the expiration.
    #[tokio::test]
    async fn a_timed_out_script_is_killed_rather_than_left_running() {
        let dir = TempDir::new("signer-custom");
        let marker = dir.path().join("survived");
        let cfg = CustomSignerConfig {
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
        let signer = CustomScriptSigner::from_config(&cfg).unwrap();

        match signer
            .issue(
                "ord-1",
                &[0x30, 0x00],
                &identifiers(),
                RequestedValidity::default(),
            )
            .await
        {
            Err(SignerError::Internal(detail)) => assert!(detail.contains("timed out")),
            other => panic!("expected Internal error on timeout, got {other:?}"),
        }

        tokio::time::sleep(Duration::from_millis(1_800)).await;
        assert!(
            !marker.exists(),
            "the script survived the timeout and continued executing"
        );
    }
}
