//! ACME profiles through a relay: the upstream's list passed through, a
//! forced `signer.relay.profile`, and the profile an upstream order carries.

use super::*;

const UPSTREAM_PROFILES: &[(&str, &str)] = &[
    ("classic", "90-day certificates"),
    ("shortlived", "160-hour certificates"),
];

fn advertising(profiles: &[(&'static str, &'static str)]) -> Script {
    Script {
        profiles: profiles.to_vec(),
        ..Script::default()
    }
}

/// Every upstream order would ask for it, so a forced profile the upstream
/// does not offer is refused before the worker serves anything — naming what
/// it does offer, or that it offers nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_forced_profile_the_upstream_does_not_advertise_is_a_startup_error() {
    for (script, expected) in [
        (
            advertising(UPSTREAM_PROFILES),
            "it offers classic, shortlived",
        ),
        (Script::default(), "lists no profiles at all"),
    ] {
        let upstream = testsrv::start(script).await;
        let dir = TempDir::new("upstream");
        let db = database().await;
        let mut cfg = config(&upstream, &dir);
        cfg.profile = "tlsserver".to_string();

        let error = startup_error(RelaySigner::from_config(
            &cfg,
            &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
        ));
        assert!(error.contains("signer.relay.profile"), "{error}");
        assert!(error.contains(expected), "{error}");
    }
}

/// Issue #54 on a relay: `signer.relay.profile = "shortlived"` is the only
/// profile listed, whatever the upstream offers, and every order resolves to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_forced_profile_is_the_only_one_offered_and_every_order_gets_it() {
    let upstream = testsrv::start(advertising(UPSTREAM_PROFILES)).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let mut cfg = config(&upstream, &dir);
    cfg.profile = "shortlived".to_string();
    let signer = RelaySigner::from_config(
        &cfg,
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
    )
    .unwrap();

    let profiles = signer.info().acme_profiles().await;
    assert_eq!(
        profiles.directory(),
        Some(std::collections::BTreeMap::from([(
            "shortlived".to_string(),
            "160-hour certificates".to_string()
        )]))
    );
    for requested in [None, Some("classic"), Some("shortlived"), Some("nonsense")] {
        assert_eq!(
            profiles.resolve(requested).unwrap().as_deref(),
            Some("shortlived"),
            "{requested:?}"
        );
    }
}

/// The profile an order was accepted under is what the upstream order asks
/// for, and an order with none asks for none.
#[tokio::test(flavor = "multi_thread")]
async fn the_order_profile_is_relayed_in_the_upstream_new_order() {
    for profile in [Some("shortlived"), None] {
        let upstream = testsrv::start(advertising(UPSTREAM_PROFILES)).await;
        let dir = TempDir::new("upstream");
        let db = database().await;
        let signer = RelaySigner::from_config(
            &config(&upstream, &dir),
            &relay_parts(db.clone(), no_notifiers(), test_queue(db.clone())),
        )
        .unwrap();
        let order = ready_order(db.clone()).await;

        signer
            .issue(
                order.id.to_string().as_str(),
                &csr_der(),
                &identifiers(),
                OrderRequest {
                    profile: profile.map(str::to_string),
                    ..OrderRequest::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(upstream.last_order_profile().as_deref(), profile);
    }
}

/// The read side alone — a process with no worker — learns the upstream's
/// profiles on first use and passes them through, holding a client's choice
/// to them.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_forced_profile_the_upstream_list_is_passed_through() {
    let upstream = testsrv::start(advertising(UPSTREAM_PROFILES)).await;
    let dir = TempDir::new("upstream");
    let db = database().await;
    let info = RelayInfo::from_config(
        &config(&upstream, &dir),
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
    )
    .unwrap();

    let profiles = info.acme_profiles().await;
    assert_eq!(
        profiles.directory().unwrap().keys().collect::<Vec<_>>(),
        ["classic", "shortlived"]
    );
    assert_eq!(
        profiles.resolve(Some("classic")).unwrap().as_deref(),
        Some("classic")
    );
    assert_eq!(
        profiles.resolve(None).unwrap(),
        None,
        "the upstream picks its own default"
    );
    assert!(profiles.resolve(Some("tlsserver")).is_err());
}

/// An upstream that cannot be reached leaves the offer unknown: the directory
/// lists nothing rather than failing, and a client's choice is passed on for
/// the upstream to judge when the order is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_upstream_leaves_the_offer_unknown() {
    let dir = TempDir::new("upstream");
    let db = database().await;
    let cfg = RelayConfig {
        // A port nothing listens on, on loopback: refused at once.
        directory_url: "http://127.0.0.1:9/directory".to_string(),
        account_key_path: key_path(&dir),
        ..RelayConfig::default()
    };
    let info = RelayInfo::from_config(
        &cfg,
        &relay_parts(db.clone(), no_notifiers(), test_queue(db)),
    )
    .unwrap();

    let profiles = info.acme_profiles().await;
    assert_eq!(profiles.offered, None);
    assert_eq!(profiles.directory(), None);
    assert_eq!(
        profiles.resolve(Some("shortlived")).unwrap().as_deref(),
        Some("shortlived")
    );
}
