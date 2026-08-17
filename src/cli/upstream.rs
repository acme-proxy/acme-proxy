//! `acme-proxy upstream …` — managing this server's own ACME account at the
//! upstream CA, when the `relay` signer backend is in use.
//!
//! ## Why this command exists alongside `signer.relay.eab`
//!
//! An upstream that requires External Account Binding hands the operator a
//! `kid` and an HMAC secret out of band. That credential authorizes exactly
//! one thing — a single `newAccount` call — and is useless afterwards. This
//! command takes the secret on **stdin** (or from a file), uses it once, and
//! never writes it anywhere — no bootstrap secret is left readable on disk
//! for the life of the server, unlike the alternative of setting
//! `signer.relay.eab` in configuration (see
//! [`crate::config::RelayEabConfig`]), which trades that property away
//! for not needing this separate step. The secret is deliberately not
//! accepted as a command-line flag either way: argv is visible to every
//! process on the host via `ps` and is routinely written to shell history.

use std::io::BufRead;
use std::path::PathBuf;

use clap::Subcommand;

use crate::cli::{CliError, resolve_profile};
use crate::config::Config;
use crate::signer::relay;

#[derive(Subcommand)]
pub enum UpstreamCommand {
    /// Register this server's account at the upstream ACME server, writing the
    /// `kid` it returns so `serve` never needs the credential again.
    Register {
        /// The EAB key id the upstream's operator issued. Omit when the
        /// upstream requires no External Account Binding.
        #[arg(long = "eab-kid")]
        eab_kid: Option<String>,
        /// Read the EAB HMAC secret (base64url) from this file instead of
        /// prompting on stdin. The file is read, used, and never copied.
        #[arg(long = "eab-hmac-key-file")]
        eab_hmac_key_file: Option<PathBuf>,
        /// Which profile's upstream to register with. Optional when the
        /// configuration defines exactly one profile.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show the configured upstream and whether this server is registered.
    Show {
        #[arg(long)]
        json: bool,
        /// Which profile's upstream to describe. Optional when the
        /// configuration defines exactly one profile.
        #[arg(long)]
        profile: Option<String>,
    },
}

/// Resolves which profile's `[signer.relay]` a command should act on.
///
/// `signer` is a **per-profile** section, but this command read
/// `config.signer.relay` — the global base every profile overlays, which
/// nothing serves from. An operator who configured the upstream only under
/// `[profiles.le].signer.relay` was told "directory_url is not set", which
/// was simply false; and if a *different* upstream happened to be configured
/// globally, `register` would write the account key and `.kid` sidecar for the
pub async fn run_upstream_command(
    command: UpstreamCommand,
    reader: &mut impl BufRead,
    config: &Config,
) -> Result<(), CliError> {
    match command {
        UpstreamCommand::Register {
            eab_kid,
            eab_hmac_key_file,
            profile,
        } => {
            let resolved = resolve_profile(config, profile.as_deref())?;
            let cfg = &resolved.sections.signer.relay;
            if cfg.directory_url.is_empty() {
                return Err(CliError(
                    "signer.relay.directory_url is not set: there is no upstream to register \
                     with"
                        .to_string(),
                ));
            }

            // Only read a secret when a kid names one; an upstream that needs
            // no EAB must not prompt for something the operator does not have.
            let secret = eab_kid
                .as_ref()
                .map(|_| read_secret(eab_hmac_key_file.as_deref(), reader))
                .transpose()?;
            let eab = eab_kid.as_deref().zip(secret.as_deref());

            // A throwaway resolver, for the same reason `order revoke` builds
            // one: a one-shot command has no server around it to share the
            // process-wide one.
            let resolver = crate::dns::resolver_addr(&config.dns)
                .and_then(crate::challenge::build_resolver)
                .map_err(|error| CliError(format!("configuration error: {error}")))?;
            let proxies = crate::proxy::from_config(&config.proxy)
                .map_err(|error| CliError(format!("configuration error: {error}")))?;
            let outbound = crate::http_client::Outbound::new(resolver, proxies);
            match relay::register_upstream_account(cfg, outbound, eab).await {
                Ok(kid) => println!("Registered. kid = {kid}"),
                Err(error) => {
                    return Err(CliError(format!("upstream registration failed: {error}")));
                }
            }
        }

        UpstreamCommand::Show { json, profile } => {
            let resolved = resolve_profile(config, profile.as_deref())?;
            let cfg = &resolved.sections.signer.relay;
            let kid = relay::stored_kid(cfg);
            let key_present = std::path::Path::new(&cfg.account_key_path).exists();

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "directoryUrl": cfg.directory_url,
                        "accountKeyPath": cfg.account_key_path,
                        "accountKeyPresent": key_present,
                        "kid": kid,
                        "registered": kid.is_some(),
                    })
                );
            } else {
                println!("directory:   {}", none_if_empty(&cfg.directory_url));
                println!(
                    "account key: {} ({})",
                    cfg.account_key_path,
                    if key_present { "present" } else { "absent" }
                );
                match kid {
                    Some(kid) => println!("kid:         {kid}"),
                    None => println!("kid:         (not registered)"),
                }
            }
        }
    }
    Ok(())
}

fn none_if_empty(value: &str) -> &str {
    if value.is_empty() { "(not set)" } else { value }
}

/// Reads the EAB HMAC secret from `path`, or prompts for it on stdin.
///
/// Accepts the base64url form `acme-proxy eab create` prints, and falls back
/// to standard base64 so a credential from another CA's console pastes in
/// unchanged. A value that decodes as neither is an error rather than being
/// silently used as raw bytes — that would produce a valid-looking binding the
/// upstream rejects for no visible reason.
fn read_secret(
    path: Option<&std::path::Path>,
    reader: &mut impl BufRead,
) -> Result<Vec<u8>, CliError> {
    let raw = match path {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| CliError(format!("cannot read {}: {error}", path.display())))?,
        None => {
            eprintln!("Enter the upstream EAB HMAC key (base64), then press Enter:");
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return Err(CliError("no EAB key supplied".to_string()));
            }
            line
        }
    };

    relay::decode_secret(raw.trim())
        .ok_or_else(|| CliError("the EAB key is not valid base64".to_string()))
}

#[cfg(test)]
mod tests {
    use crate::config::ENV_LOCK;

    /// Loads a `Config` from TOML the way the server does, so `resolve_profiles`
    /// has the raw sources it needs for per-key inheritance.
    fn config_from(body: &str) -> Config {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = crate::testutil::TempDir::new("upstream");
        std::fs::write(dir.join("config.toml"), body).unwrap();
        // SAFETY: single-threaded test holding ENV_LOCK; removed before return.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    /// The bug this resolution fixes: `[signer.relay]` written *inside* a
    /// profile was invisible, because the command read the global base section
    /// that nothing ever serves from. An operator saw "directory_url is not
    /// set" for a configuration where it plainly was.
    #[test]
    fn a_profiles_own_upstream_is_what_gets_resolved() {
        let config = config_from(
            r#"
            [profiles.le]
            signer.backend = "relay"
            signer.relay.directory_url = "https://upstream.example/directory"
            signer.relay.account_key_path = "/tmp/le-upstream.key"
            "#,
        );

        let resolved = resolve_profile(&config, None).unwrap();
        assert_eq!(resolved.name, "le");
        assert_eq!(
            resolved.sections.signer.relay.directory_url,
            "https://upstream.example/directory"
        );
        assert_eq!(
            resolved.sections.signer.relay.account_key_path,
            "/tmp/le-upstream.key"
        );
    }

    /// With several profiles there is no right answer to guess — and guessing
    /// wrong means `register` writing an account key and `.kid` for the wrong
    /// CA at the wrong paths.
    #[test]
    fn several_profiles_require_saying_which() {
        let config = config_from(
            r#"
            [profiles.le]
            [profiles.internal]
            "#,
        );

        let error = resolve_profile(&config, None).unwrap_err().to_string();
        assert!(error.contains("--profile"), "{error}");
        assert!(
            error.contains("le") && error.contains("internal"),
            "{error}"
        );

        // Named explicitly, it resolves.
        assert_eq!(resolve_profile(&config, Some("le")).unwrap().name, "le");
        // And an unknown name is refused rather than falling back.
        let error = resolve_profile(&config, Some("nope"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("nope"), "{error}");
    }

    use super::*;
    use base64::prelude::*;

    // `decode_secret`'s own decoding tests (base64url, standard base64, a
    // refused non-base64 value) live in `signer::relay::eab`, which now
    // owns the one implementation both this module and `provision()` call.

    #[test]
    fn an_empty_directory_url_renders_as_unset() {
        assert_eq!(none_if_empty(""), "(not set)");
        assert_eq!(none_if_empty("https://x/dir"), "https://x/dir");
    }

    /// The secret must be readable from stdin, so it never reaches argv.
    #[test]
    fn the_secret_can_come_from_stdin() {
        let secret = b"01234567890123456789012345678901";
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(secret);
        let mut reader = std::io::Cursor::new(format!("{encoded}\n").into_bytes());
        assert_eq!(read_secret(None, &mut reader).unwrap(), secret.to_vec());
    }

    #[test]
    fn the_secret_can_come_from_a_file() {
        let secret = b"01234567890123456789012345678901";
        let dir = crate::testutil::TempDir::new("eab");
        let path = dir.join("key.b64");
        // Trailing newline is what an editor or `echo` leaves behind.
        std::fs::write(
            &path,
            format!("{}\n", BASE64_URL_SAFE_NO_PAD.encode(secret)),
        )
        .unwrap();

        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(
            read_secret(Some(&path), &mut empty).unwrap(),
            secret.to_vec()
        );
    }

    #[test]
    fn a_missing_secret_file_is_reported() {
        let mut empty = std::io::Cursor::new(Vec::new());
        let error = read_secret(
            Some(std::path::Path::new("/nonexistent/eab.b64")),
            &mut empty,
        )
        .expect_err("a missing file must be reported");
        assert!(error.to_string().starts_with("cannot read "), "{error}");
    }

    /// Closed stdin means the operator has nothing to give; prompting forever
    /// or reading an empty secret would both be worse than saying so.
    #[test]
    fn an_empty_stdin_is_reported() {
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(
            read_secret(None, &mut empty),
            Err(CliError("no EAB key supplied".to_string()))
        );
    }

    #[test]
    fn a_secret_that_is_not_base64_is_reported() {
        let mut reader = std::io::Cursor::new(b"not base64!!!\n".to_vec());
        assert_eq!(
            read_secret(None, &mut reader),
            Err(CliError("the EAB key is not valid base64".to_string()))
        );
    }

    /// Without `signer.relay.directory_url` there is no upstream at all,
    /// so registration stops before it can prompt for a credential.
    #[tokio::test]
    async fn registering_without_an_upstream_is_refused() {
        // A real profile, but one whose signer is the default `local_ca` — so
        // there genuinely is no upstream, which is what the message must say.
        // (`Config::default()` would now fail earlier, on having no profiles at
        // all, and would not exercise this branch.)
        let config = config_from("[profiles.default]\n");
        let mut reader: &[u8] = &[];
        let error = run_upstream_command(
            UpstreamCommand::Register {
                eab_kid: None,
                eab_hmac_key_file: None,
                profile: None,
            },
            &mut reader,
            &config,
        )
        .await
        .expect_err("there is no upstream to register with");
        assert!(error.to_string().contains("directory_url"), "{error}");
    }

    /// An upstream that cannot be reached is reported, not retried forever:
    /// `register` is a one-shot operator command.
    #[tokio::test]
    async fn an_unreachable_upstream_is_reported() {
        let dir = crate::testutil::TempDir::new("upstream");

        // Port 1 on loopback: nothing listens, so the directory fetch fails
        // fast rather than hanging on a routable-but-silent address.
        let config = config_from(&format!(
            r#"
            [profiles.default]
            signer.backend = "relay"
            signer.relay.directory_url = "http://127.0.0.1:1/directory"
            signer.relay.account_key_path = "{}"
            "#,
            dir.join("upstream.key").display()
        ));

        // A kid means a secret is read first — the path that proves the
        // credential comes off stdin and never from argv.
        let secret = BASE64_URL_SAFE_NO_PAD.encode(b"01234567890123456789012345678901");
        let mut reader = std::io::Cursor::new(format!("{secret}\n").into_bytes());
        let error = run_upstream_command(
            UpstreamCommand::Register {
                eab_kid: Some("kid-1".to_string()),
                eab_hmac_key_file: None,
                profile: None,
            },
            &mut reader,
            &config,
        )
        .await
        .expect_err("nothing is listening on that port");
        assert!(
            error
                .to_string()
                .starts_with("upstream registration failed: "),
            "{error}"
        );
    }

    /// `show` reports an unconfigured, unregistered upstream in both forms
    /// rather than failing — "nothing is set up" is a valid answer.
    #[tokio::test]
    async fn show_renders_an_unregistered_upstream() {
        let config = config_from("[profiles.default]\n");
        for json in [true, false] {
            let mut reader: &[u8] = &[];
            run_upstream_command(
                UpstreamCommand::Show {
                    json,
                    profile: None,
                },
                &mut reader,
                &config,
            )
            .await
            .unwrap();
        }
    }
}
