//! The `custom` IPAM backend: the inventory is an operator-supplied script.
//!
//! The third backend, and the one that exists to find out whether the
//! [`Ipam`] seam generalises or merely spans NetBox and phpIPAM. Everything
//! those two have in common falls away here: there is no
//! [`sources`](super::Source) vocabulary, no
//! [shared transport](super::http), no TLS settings and no wire status code to
//! read an answer out of. What is left is the trait itself — one question, two
//! shapes of answer, and an error that cannot express a denial.
//!
//! It is also the escape hatch. An estate whose inventory is a CMDB, a `hosts`
//! file, an LDAP tree or a Python script against a vendor API this server will
//! never carry a client for answers the same question through the same
//! contract [`filter::custom`](crate::filter::custom) and
//! [`signer::custom`](crate::signer::custom) use, over the shared
//! [`script_hook`](crate::script_hook) hardening.
//!
//! ## The contract
//!
//! The script is told the address in `ACME_IPAM_CLIENT_IP` and, redundantly,
//! in the JSON object on its stdin — redundantly on purpose, so a one-line
//! shell script never has to parse JSON and a Python one never has to read the
//! environment.
//!
//! What it answers with is **stdout plus an exit code**:
//!
//! | Exit | stdout | Means |
//! | --- | --- | --- |
//! | `0` | one name per line | [`AddressNames::Known`] of those names |
//! | `0` | empty | `Known` with no names — recorded, entitled to nothing |
//! | [`UNKNOWN_ADDRESS_EXIT_CODE`] | ignored | [`AddressNames::Unknown`] |
//! | anything else | the reason | [`IpamError`] — a retryable 500 |
//!
//! One name per line rather than a separated list because a newline is the
//! shell idiom, and neither a newline nor a comma is legal in a DNS name.
//! Plain text rather than JSON because [`AddressNames`] holds nothing a
//! structure would carry that a list of lines does not, and because a contract
//! needing `jq` for what `echo` already does would be paid for by every script
//! ever written against it — the same choice
//! [`signer::custom`](crate::signer::custom) makes for the certificate chain.
//!
//! ## Why a reserved exit code
//!
//! `Known` with no names and `Unknown` are different answers — the filter
//! words a different 403 for each — and an exit status is the only channel
//! left once stdout means "the names". So "no record of this address" gets a
//! reserved code, exactly as `signer::custom`'s `BadCsr` does, and every
//! *other* non-zero exit stays a failure. That direction matters: a script
//! that breaks, or is missing, or times out, must produce an
//! [`IpamError`] — which the filter turns into a retryable 500 — and never
//! something the client reads as a permanent refusal. The type enforces it,
//! since `IpamError` has no denied variant to reach for.

use std::net::IpAddr;

use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use super::{AddressNames, Ipam, IpamError};
use crate::config::CustomIpamConfig;
use crate::script_hook::{ScriptError, ScriptHook, ScriptStdin};

/// The exit status meaning "this inventory holds no record of that address".
///
/// Reserved the way [`signer::custom`](crate::signer::custom)'s `BadCsr` code
/// is, and for the same reason: it is an *answer*, not a failure, and nothing
/// else in the contract can carry it.
pub const UNKNOWN_ADDRESS_EXIT_CODE: i32 = 3;

/// Reports which names an operator script associates with an address.
pub struct CustomIpamBackend {
    hook: ScriptHook,
}

impl std::fmt::Debug for CustomIpamBackend {
    /// The script is the whole configuration; its path is the readable part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustomIpamBackend")
            .field("script_path", &self.hook.path())
            .finish_non_exhaustive()
    }
}

impl CustomIpamBackend {
    /// Validates the configuration and builds the hook. Runs nothing.
    ///
    /// `timeout_ms` is [`IpamConfig::timeout_ms`](crate::config::IpamConfig),
    /// not a budget of this section's own: the registry already wraps every
    /// lookup in it, and giving the hook the same value is what makes the
    /// child actually killed at the deadline rather than left to
    /// `kill_on_drop` alone.
    pub fn from_config(cfg: &CustomIpamConfig, timeout_ms: u64) -> anyhow::Result<Self> {
        let Some(hook) = ScriptHook::new(&cfg.script_path, &cfg.args, timeout_ms) else {
            anyhow::bail!(
                "ipam.custom.script_path is empty; provide a path to an executable \
                 script or point ipam.backend at another inventory"
            );
        };

        info!(
            event = "ipam_custom_loaded",
            outcome = "success",
            script_path = %hook.path().display(),
            timeout_ms,
            args = ?cfg.args,
        );

        Ok(Self { hook })
    }
}

#[async_trait]
impl Ipam for CustomIpamBackend {
    /// Reads as a subject: every refusal the `ipam` filter words interpolates
    /// this, so an operator sees "the custom IPAM script holds no record of
    /// 10.0.0.5" rather than a bare type name.
    fn name(&self) -> &'static str {
        "the custom IPAM script"
    }

    async fn names_for(&self, ip: IpAddr) -> Result<AddressNames, IpamError> {
        let client_ip = ip.to_string();
        let envs = [
            ("ACME_IPAM_HOOK", "names_for"),
            ("ACME_IPAM_CLIENT_IP", client_ip.as_str()),
        ];
        let payload = json!({ "hook": "names_for", "client_ip": client_ip });

        // Matched variant by variant rather than with a wildcard, so a new
        // `ScriptError` has to be considered here instead of silently joining
        // the others — `filter::custom` makes the same choice.
        let outcome = match self.hook.run(&envs, ScriptStdin::Json(&payload)).await {
            Ok(outcome) => outcome,
            Err(
                error @ (ScriptError::Spawn { .. }
                | ScriptError::Serialize(_)
                | ScriptError::Wait(_)
                | ScriptError::Timeout(_)),
            ) => return Err(IpamError(format!("custom IPAM script {error}"))),
        };

        if outcome.output.status.success() {
            let stdout = String::from_utf8_lossy(&outcome.output.stdout);
            let mut names = AddressNames::known();
            for line in stdout.lines() {
                // `insert` normalizes and drops an empty entry, so a blank
                // line and a stray trailing dot both cost the script nothing.
                names.insert(line);
            }
            return Ok(names);
        }

        if outcome.output.status.code() == Some(UNKNOWN_ADDRESS_EXIT_CODE) {
            return Ok(AddressNames::Unknown);
        }

        Err(IpamError(ScriptHook::detail(
            &outcome,
            "custom IPAM script",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, write_script};
    use std::time::Duration;

    const CLIENT: &str = "203.0.113.5";

    fn client() -> IpAddr {
        CLIENT.parse().unwrap()
    }

    /// Builds a backend over a freshly written script.
    fn backend(dir: &TempDir, name: &str, body: &str) -> CustomIpamBackend {
        let path = write_script(dir, name, body);
        CustomIpamBackend::from_config(
            &CustomIpamConfig {
                script_path: path.display().to_string(),
                args: Vec::new(),
            },
            5_000,
        )
        .expect("a real script should build")
    }

    // ---------------------------------------------------------- from_config

    #[test]
    fn a_blank_script_path_is_a_startup_error_naming_the_key() {
        for path in ["", "   "] {
            let error = CustomIpamBackend::from_config(
                &CustomIpamConfig {
                    script_path: path.to_string(),
                    ..CustomIpamConfig::default()
                },
                5_000,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("ipam.custom.script_path is empty"),
                "{error}"
            );
        }
    }

    #[test]
    fn the_debug_rendering_names_the_script() {
        let dir = TempDir::new("ipam-custom");
        let rendered = format!("{:?}", backend(&dir, "ok.sh", "#!/bin/sh\nexit 0\n"));
        assert!(rendered.contains("ok.sh"), "{rendered}");
    }

    // ------------------------------------------------------------- answers

    /// The happy path, and the normalization that comes with it: the script
    /// may print whatever case and trailing dot its inventory holds, and a
    /// blank line costs it nothing.
    #[tokio::test]
    async fn the_printed_lines_become_the_permitted_names() {
        let dir = TempDir::new("ipam-custom");
        let backend = backend(
            &dir,
            "names.sh",
            "#!/bin/sh\necho 'WWW.Example.COM.'\necho\necho '  api.example.com  '\nexit 0\n",
        );

        let names = backend.names_for(client()).await.unwrap();
        assert!(names.is_known());
        assert_eq!(
            names.names().iter().cloned().collect::<Vec<_>>(),
            vec!["api.example.com".to_string(), "www.example.com".to_string()]
        );
    }

    /// The distinction the whole reserved exit code exists for: the filter
    /// words a different refusal for each of these two, so they must not
    /// collapse.
    #[tokio::test]
    async fn exit_three_is_an_unknown_address_and_exit_zero_with_no_names_is_not() {
        let dir = TempDir::new("ipam-custom");

        let unknown = backend(&dir, "unknown.sh", "#!/bin/sh\nexit 3\n")
            .names_for(client())
            .await
            .unwrap();
        assert_eq!(unknown, AddressNames::Unknown);
        assert!(!unknown.is_known());

        let entitled_to_nothing = backend(&dir, "empty.sh", "#!/bin/sh\nexit 0\n")
            .names_for(client())
            .await
            .unwrap();
        assert_eq!(entitled_to_nothing, AddressNames::known());
        assert!(entitled_to_nothing.is_known());

        assert_ne!(unknown, entitled_to_nothing);
    }

    /// Anything the script prints on the way out of exit 3 is ignored: the
    /// exit code is the answer, and a stray diagnostic must not become a name.
    #[tokio::test]
    async fn stdout_is_ignored_on_the_unknown_exit_code() {
        let dir = TempDir::new("ipam-custom");
        let names = backend(
            &dir,
            "chatty.sh",
            "#!/bin/sh\necho 'no such address'\nexit 3\n",
        )
        .names_for(client())
        .await
        .unwrap();
        assert_eq!(names, AddressNames::Unknown);
    }

    // -------------------------------------------------------------- failures

    /// The property the subsystem rests on: a broken script is the *server*
    /// failing to decide, which the filter turns into a retryable 500. It is
    /// enforced by the type — there is no denial to return from here.
    #[tokio::test]
    async fn any_other_non_zero_exit_is_an_error_carrying_the_scripts_own_words() {
        let dir = TempDir::new("ipam-custom");

        let error = backend(
            &dir,
            "broken.sh",
            "#!/bin/sh\necho 'inventory unreachable'\nexit 1\n",
        )
        .names_for(client())
        .await
        .unwrap_err();
        assert_eq!(error.0, "inventory unreachable");

        let error = backend(
            &dir,
            "stderr.sh",
            "#!/bin/sh\necho 'token refused' >&2\nexit 4\n",
        )
        .names_for(client())
        .await
        .unwrap_err();
        assert_eq!(error.0, "token refused");

        let error = backend(&dir, "silent.sh", "#!/bin/sh\nexit 9\n")
            .names_for(client())
            .await
            .unwrap_err();
        assert!(error.0.starts_with("custom IPAM script exited"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_script_is_an_error_rather_than_a_denial() {
        let backend = CustomIpamBackend::from_config(
            &CustomIpamConfig {
                script_path: "/nonexistent/ipam.sh".to_string(),
                args: Vec::new(),
            },
            5_000,
        )
        .unwrap();

        let error = backend.names_for(client()).await.unwrap_err();
        assert!(error.0.contains("failed to spawn"), "{error}");
        assert!(error.0.contains("/nonexistent/ipam.sh"), "{error}");
    }

    /// A script that never returns must not outlive its deadline: the registry
    /// budget only drops the future, so `kill_on_drop` inside the hook is what
    /// stops one leaked process per `newOrder`.
    #[tokio::test]
    async fn a_timed_out_script_is_an_error_and_is_killed() {
        let dir = TempDir::new("ipam-custom");
        let marker = dir.path().join("still-running");
        let path = write_script(
            &dir,
            "slow.sh",
            &format!("#!/bin/sh\nsleep 1\ntouch {}\nexit 0\n", marker.display()),
        );
        let backend = CustomIpamBackend::from_config(
            &CustomIpamConfig {
                script_path: path.display().to_string(),
                args: Vec::new(),
            },
            100,
        )
        .unwrap();

        let error = backend.names_for(client()).await.unwrap_err();
        assert!(error.0.contains("timed out after 100 ms"), "{error}");

        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert!(
            !marker.exists(),
            "the script outlived its deadline and kept running"
        );
    }

    // -------------------------------------------------------- what it is told

    /// Both channels carry the address, and neither carries the server's own
    /// environment — which holds the NetBox token and the RFC 2136 TSIG key.
    #[tokio::test]
    async fn the_script_is_told_the_address_twice_and_the_server_secrets_never() {
        let dir = TempDir::new("ipam-custom");
        let backend = backend(
            &dir,
            "echo.sh",
            "#!/bin/sh\npayload=$(cat)\n\
             echo \"hook-$ACME_IPAM_HOOK.example.com\"\n\
             echo \"env-$ACME_IPAM_CLIENT_IP.example.com\"\n\
             case \"$payload\" in *'\"client_ip\":\"203.0.113.5\"'*) \
             echo 'stdin.example.com' ;; esac\n\
             echo \"manifest-${CARGO_MANIFEST_DIR:-unset}.example.com\"\n\
             exit 0\n",
        );

        let names = backend.names_for(client()).await.unwrap();
        let names: Vec<_> = names.names().iter().cloned().collect();
        assert!(
            names.contains(&"hook-names_for.example.com".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"env-203.0.113.5.example.com".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"stdin.example.com".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"manifest-unset.example.com".to_string()),
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn the_configured_arguments_are_passed() {
        let dir = TempDir::new("ipam-custom");
        let path = write_script(
            &dir,
            "args.sh",
            "#!/bin/sh\necho \"$1-$2.example.com\"\nexit 0\n",
        );
        let backend = CustomIpamBackend::from_config(
            &CustomIpamConfig {
                script_path: path.display().to_string(),
                args: vec!["first".to_string(), "second".to_string()],
            },
            5_000,
        )
        .unwrap();

        let names = backend.names_for(client()).await.unwrap();
        assert!(names.names().contains("first-second.example.com"));
    }
}
