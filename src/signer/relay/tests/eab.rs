use super::*;

/// An upstream that demands EAB, and finds no credential at all — neither
/// `signer.relay.eab` nor a prior `acme-proxy upstream register` —
/// must name both fixes, rather than surfacing as a bare 403 from a CA
/// the operator may not control.
#[tokio::test(flavor = "multi_thread")]
async fn a_startup_needing_eab_points_at_the_register_command() {
    let upstream = testsrv::start(Script {
        require_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let error = startup_error(RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(
        error.contains("acme-proxy upstream register"),
        "the error must name the fix: {error}"
    );
    assert!(
        error.contains("signer.relay.eab"),
        "the error must also name the config alternative: {error}"
    );
}

/// The config-file alternative to `acme-proxy upstream register`: `serve`
/// registers on its own, with no CLI step, when `signer.relay.eab`
/// supplies a credential the upstream accepts.
#[tokio::test(flavor = "multi_thread")]
async fn from_config_registers_with_a_credential_supplied_in_config() {
    let upstream = testsrv::start(Script {
        require_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: "eab-kid-1".to_string(),
            hmac_key: BASE64_URL_SAFE_NO_PAD.encode(b"secret-bytes-secret-bytes!!"),
        },
        ..config(&upstream, &dir)
    };

    RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    )
    .expect("a config-supplied credential the upstream accepts must register");

    assert!(
        stored_kid(&cfg).is_some(),
        "registration must persist the kid, exactly as the CLI path does"
    );
    let payload = upstream
        .last_eab_payload()
        .expect("an EAB must have been sent");
    assert!(payload.contains("externalAccountBinding"), "{payload}");
}

/// `signer.relay.eab.kid` without `hmac_key`, or vice versa, is a
/// configuration mistake, not "no credential" — silently treating it as
/// the latter would surface as a confusing upstream-side 403 instead of
/// the actual config error.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_supplied_config_credential_is_a_startup_error() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");

    let kid_only = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: "eab-kid-1".to_string(),
            hmac_key: String::new(),
        },
        ..config(&upstream, &dir)
    };
    let error = startup_error(RelaySigner::from_config(
        &kid_only,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(error.contains("hmac_key"), "{error}");

    let secret_only = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: String::new(),
            hmac_key: BASE64_URL_SAFE_NO_PAD.encode(b"secret-bytes-secret-bytes!!"),
        },
        ..config(&upstream, &dir)
    };
    let error = startup_error(RelaySigner::from_config(
        &secret_only,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(error.contains("kid"), "{error}");
}

/// A `hmac_key` that isn't valid base64 in any of the three accepted
/// forms must not be silently used as raw bytes (see
/// `eab::decode_secret`'s own doc comment).
#[tokio::test(flavor = "multi_thread")]
async fn a_config_credential_with_bad_base64_is_a_startup_error() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let cfg = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: "eab-kid-1".to_string(),
            hmac_key: "not base64!!!".to_string(),
        },
        ..config(&upstream, &dir)
    };
    let error = startup_error(RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(error.contains("base64"), "{error}");
}

/// An upstream that rejects the *specific* credential offered (wrong,
/// expired, or already consumed) must name the credential that was
/// actually tried, rather than reading as though none had been offered
/// at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_rejecting_the_configured_credential_says_so() {
    let upstream = testsrv::start(Script {
        reject_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: "eab-kid-1".to_string(),
            hmac_key: BASE64_URL_SAFE_NO_PAD.encode(b"secret-bytes-secret-bytes!!"),
        },
        ..config(&upstream, &dir)
    };
    let error = startup_error(RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    ));
    assert!(
        error.contains("rejected signer.relay.eab"),
        "the error must name the credential that was actually tried, not read as though \
         none had been offered: {error}"
    );
}

/// Once registered, a config-supplied credential left in place is inert
/// but harmless: startup must succeed exactly as it does after a
/// CLI-driven registration (this is also what exercises the
/// `signer_relay_eab_secret_in_config` warning path).
#[tokio::test(flavor = "multi_thread")]
async fn a_leftover_config_credential_does_not_block_a_later_startup() {
    let upstream = testsrv::start(Script {
        require_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = RelayConfig {
        eab: crate::config::RelayEabConfig {
            kid: "eab-kid-1".to_string(),
            hmac_key: BASE64_URL_SAFE_NO_PAD.encode(b"secret-bytes-secret-bytes!!"),
        },
        ..config(&upstream, &dir)
    };

    RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    )
    .unwrap();

    // Second startup: the kid sidecar exists, the (still-configured)
    // secret is unused, and nothing fails.
    RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    )
    .expect("a leftover config credential must not block a registered server");
}

/// `Location` is the *only* thing `newAccount` returns that this server
/// needs — an upstream omitting it leaves nothing to store, so registration
/// must fail loudly rather than write an empty kid sidecar that makes every
/// later request unauthorized for no visible reason.
#[tokio::test(flavor = "multi_thread")]
async fn registering_without_a_location_header_is_refused() {
    let upstream = testsrv::start(Script {
        omit_location: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = config(&upstream, &dir);

    let error =
        register_upstream_account(&cfg, crate::testutil::outbound_with(test_resolver()), None)
            .await
            .expect_err("an account with no URL is not an account")
            .to_string();
    assert!(error.contains("no Location header"), "{error}");
    assert!(
        stored_kid(&cfg).is_none(),
        "nothing must be persisted from a failed registration"
    );
}

/// The admin path: registering with a credential succeeds, writes the kid,
/// and sends a binding over this account's own key.
#[tokio::test(flavor = "multi_thread")]
async fn register_upstream_account_supplies_the_eab() {
    let upstream = testsrv::start(Script {
        require_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = config(&upstream, &dir);

    let kid = register_upstream_account(
        &cfg,
        crate::testutil::outbound_with(test_resolver()),
        Some(("eab-kid-1", b"secret-bytes-secret-bytes!!")),
    )
    .await
    .expect("registration with a credential must succeed");
    assert_eq!(kid, format!("{}/acct/1", upstream.base));

    // Persisted, so `serve` never needs the credential again.
    assert_eq!(stored_kid(&cfg).as_deref(), Some(kid.as_str()));

    // And the binding really travelled, over this account's own key.
    let payload = upstream
        .last_eab_payload()
        .expect("an EAB must have been sent");
    assert!(payload.contains("externalAccountBinding"), "{payload}");
}

/// Once registered, startup succeeds against the same EAB-requiring
/// upstream without any credential — the property the whole design exists
/// for.
#[tokio::test(flavor = "multi_thread")]
async fn after_registering_startup_needs_no_credential() {
    let upstream = testsrv::start(Script {
        require_eab: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let cfg = config(&upstream, &dir);

    register_upstream_account(
        &cfg,
        crate::testutil::outbound_with(test_resolver()),
        Some(("eab-kid-1", b"secret-bytes-secret-bytes!!")),
    )
    .await
    .unwrap();

    RelaySigner::from_config(
        &cfg,
        vec!["default".to_string()],
        &relay_parts(
            database().await,
            no_notifiers(),
            test_queue(database().await),
        ),
        &crate::signer::CarriedState::new(),
    )
    .expect("a registered server must start with no EAB in reach");
}

/// `stored_kid` must treat an absent or blank sidecar as "not registered",
/// not as a kid of "".
#[tokio::test(flavor = "multi_thread")]
async fn stored_kid_ignores_a_missing_or_blank_sidecar() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let cfg = config(&upstream, &dir);

    assert_eq!(stored_kid(&cfg), None);
    std::fs::write(kid_path(&cfg.account_key_path), "   \n").unwrap();
    assert_eq!(stored_kid(&cfg), None);
}
