//! `SIGHUP` against a running container.
//!
//! `tests/reload.rs` drives `ReloadHandle::reload()` programmatically, which
//! covers the *rebuild* and the *swap* but not the thing an operator actually
//! does. `watch_for_hangup` — the signal stream that turns a `SIGHUP` into that
//! call — was reached by no test at all, and it carries a trap `src/cli/mod.rs`
//! documents in so many words: a one-shot handler would leave the **second**
//! `SIGHUP` at its default disposition, which is *terminate*. That is a
//! production process kill, reachable by an operator reloading twice.
//!
//! The lab configures `acme-proxy` entirely through `ACME_PROXY_*` variables,
//! and the image's `WORKDIR` is `/data`, where `Config::load` looks for
//! `config.toml`. So a file written into a *running* container is invisible
//! until something re-reads it — which makes it exactly the right lever here.
//! Environment beats file, so the file only ever writes keys the lab left
//! unset: `meta.website` (the cheapest proof a reload landed), a whole
//! `[profiles.extra]` section, and `database.url` — the one key that is still
//! refused.

use crate::common::Lab;

/// Fetches a URL from a container that has an HTTP client.
///
/// The `acme-proxy` image carries no `curl` and no Python — deliberately, it is
/// a service image — so the fetch happens from the certbot container, which is
/// on the same network and already has both.
///
/// Returns whether it succeeded rather than asserting, because one caller
/// fetches an endpoint that is *expected* to be absent at first: `urlopen`
/// raises on a 404, so a missing profile is a non-zero exit, not an empty body.
async fn fetch(lab: &Lab, url: &str) -> (bool, String) {
    let (ok, stdout, _) = lab
        .exec_in_with_output(
            &lab.certbot,
            &format!(
                "python3 -c \"import urllib.request;\
                 print(urllib.request.urlopen('{url}').read().decode())\""
            ),
        )
        .await;
    (ok, stdout)
}

/// Reads the default profile's directory object, which must always be there.
///
/// `Lab::proxy_url` is already that **directory** URL (that is what a client
/// takes as `--server`), so it is fetched as-is rather than with a path
/// appended.
async fn directory(lab: &Lab) -> String {
    let (ok, body) = fetch(lab, &lab.proxy_url).await;
    assert!(ok, "fetching the directory failed");
    body
}

/// The `{scheme}://{host}:{port}` the lab's directory URL sits under.
///
/// Derived rather than spelled a second time: a scenario naming a *different*
/// profile has to reach the same server, and two independent renderings of one
/// address are what let them drift.
fn base(lab: &Lab) -> &str {
    lab.proxy_url
        .strip_suffix("/profile/default/directory")
        .expect("the lab's proxy URL is the default profile's directory")
}

/// Sends `SIGHUP` to the server and waits for the Nth reload to land.
///
/// The binary is the container's `ENTRYPOINT`, so it is PID 1. Polls the log
/// rather than sleeping a fixed interval: a reload rebuilds every profile and
/// both TLS acceptors, and how long that takes is not something a test should
/// be guessing at.
///
/// **Counts `server_config_reloaded` rather than matching `generation=N`.** The
/// default human-readable format writes ANSI escapes *between* a field name and
/// its `=`, so the obvious substring never matches — and the failure is
/// indistinguishable from the reload not happening. The count says the same
/// thing (the Nth success is generation N+1) and cannot be broken by
/// formatting.
async fn reloads_reach(lab: &Lab, expected: usize) {
    lab.exec_in(&lab.proxy, "kill -HUP 1").await;

    for _ in 0..100 {
        let logs = lab.get_proxy_logs().await;
        if logs.matches("server_config_reloaded").count() >= expected {
            return;
        }
        // A refusal is terminal — there is no point waiting out the rest.
        assert!(
            !logs.contains("server_config_reload_refused")
                && !logs.contains("server_config_reload_failed"),
            "the reload was refused rather than applied:\n{logs}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "only {} reload(s) landed, expected {expected}:\n{}",
        lab.get_proxy_logs()
            .await
            .matches("server_config_reloaded")
            .count(),
        lab.get_proxy_logs().await
    );
}

/// The operator's own path: edit the file, send the signal, watch the answer
/// change — on the same port, without the process restarting.
///
/// And then do it **again**, which is the half that matters. `watch_for_hangup`
/// does not consume its stream precisely so the second signal is still handled;
/// a one-shot handler passes the first assertion here and kills the server on
/// the second.
#[tokio::test]
#[ignore]
async fn test_reload_on_sighup_twice() {
    let lab = Lab::new(vec![]).await;

    let before = directory(&lab).await;
    assert!(
        !before.contains("https://first.example"),
        "the server must start without the website it is about to be given: {before}"
    );

    lab.exec_in(
        &lab.proxy,
        "printf '[meta]\\nwebsite = \"https://first.example\"\\n' > /data/config.toml",
    )
    .await;
    reloads_reach(&lab, 1).await;

    let after = directory(&lab).await;
    assert!(
        after.contains("https://first.example"),
        "the running socket must serve the new configuration: {after}"
    );

    // The second signal. Before `watch_for_hangup` kept its stream, this is
    // where the process died.
    lab.exec_in(
        &lab.proxy,
        "printf '[meta]\\nwebsite = \"https://second.example\"\\n' > /data/config.toml",
    )
    .await;
    reloads_reach(&lab, 2).await;

    let after = directory(&lab).await;
    assert!(
        after.contains("https://second.example"),
        "a second SIGHUP must reload rather than terminate: {after}"
    );

    // Still the same process. A restart would have reset the reload count, so
    // "two reloads landed" and "one startup happened" together are what rule
    // out the failure this test exists for.
    let logs = lab.get_proxy_logs().await;
    assert_eq!(
        logs.matches("server_startup").count(),
        1,
        "the process must not have restarted: {logs}"
    );
}

/// An endpoint is mounted by a signal, and the one key a running process still
/// cannot change is refused **by name** with the old generation left serving.
///
/// The two halves belong in one scenario because they are the same decision
/// seen from both sides. Mounting a profile is what `signer::CarriedState`
/// bought — the profile set was frozen only because a `LocalCa` rebuilds its
/// CRL from an in-memory ledger and a relay's `http-01` store would come back
/// empty, and carrying both ended it. `database.url` is what is left, and it is
/// the only entry ever frozen *physically*: the pool is open, and the accounts
/// and orders issued against it do not follow a URL elsewhere. Refusing whole
/// rather than half-applying is what keeps "what is this server running?"
/// answerable, so both the refusal and the untouched generation are asserted.
#[tokio::test]
#[ignore]
async fn test_a_profile_mounts_and_a_frozen_key_is_refused() {
    let lab = Lab::new(vec![]).await;

    let extra = format!("{}/profile/extra/directory", base(&lab));
    let (ok, _) = fetch(&lab, &extra).await;
    assert!(
        !ok,
        "the server must start without the endpoint it is about to be given"
    );

    // `meta.website` proves the reload ran at all; the profile is the half that
    // used to be refused by name.
    lab.exec_in(
        &lab.proxy,
        "printf '[meta]\\nwebsite = \"https://live.example\"\\n\
         [profiles.extra]\\nenabled = true\\n' > /data/config.toml",
    )
    .await;
    reloads_reach(&lab, 1).await;

    assert!(directory(&lab).await.contains("https://live.example"));
    let (ok, body) = fetch(&lab, &extra).await;
    assert!(
        ok && body.contains("/profile/extra/"),
        "a profile added to a running server must serve, not merely be accepted: {body}"
    );

    // Serving is the claim; the log line is the lifecycle event beside it. One
    // at startup for `default`, one for `extra`, and never a repeat — that is
    // what makes it a notification rather than a heartbeat.
    let logs = lab.get_proxy_logs().await;
    assert_eq!(
        logs.matches("profile_mounted").count(),
        2,
        "the new endpoint must be announced exactly once: {logs}"
    );

    // `database.url` is unset in the lab's environment, so the file really does
    // move the resolved value. The website moves with it: were the reload
    // wrongly applied, the assertion below would catch it on the *directory*
    // too, rather than passing because the file happened to agree.
    lab.exec_in(
        &lab.proxy,
        "printf '[database]\\nurl = \"sqlite:///data/other.db\"\\n\
         [meta]\\nwebsite = \"https://refused.example\"\\n\
         [profiles.extra]\\nenabled = true\\n' > /data/config.toml",
    )
    .await;
    // Not `reloads_reach`, which treats a refusal as fatal — a refusal is the
    // point here. Give it time to be logged, then assert nothing moved.
    lab.exec_in(&lab.proxy, "kill -HUP 1").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let logs = lab.get_proxy_logs().await;
    assert!(
        logs.contains("server_config_reload_refused"),
        "moving the database of a running server must be refused: {logs}"
    );
    assert!(
        directory(&lab).await.contains("https://live.example"),
        "a refused reload must leave the running generation untouched"
    );
    let (ok, _) = fetch(&lab, &extra).await;
    assert!(ok, "including the endpoint the previous reload mounted");
    assert_eq!(
        logs.matches("server_startup").count(),
        1,
        "and must not restart the process"
    );
}
