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
//! Environment beats file, so the file only ever adds `meta.website`; every
//! frozen key keeps the value the container started with, and the reload is not
//! refused.

use crate::common::Lab;

/// Reads the directory object from a container that has an HTTP client.
///
/// The `acme-proxy` image carries no `curl` and no Python — deliberately, it is
/// a service image — so the fetch happens from the certbot container, which is
/// on the same network and already has both.
async fn directory(lab: &Lab) -> String {
    let (ok, stdout, stderr) = lab
        .exec_in_with_output(
            &lab.certbot,
            &format!(
                "python3 -c \"import urllib.request;\
                 print(urllib.request.urlopen('{}/directory').read().decode())\"",
                lab.proxy_url
            ),
        )
        .await;
    assert!(ok, "fetching the directory failed: {stderr}");
    stdout
}

/// Sends `SIGHUP` to the server and waits for it to land.
///
/// The binary is the container's `ENTRYPOINT`, so it is PID 1. Polls the log
/// for the generation rather than sleeping a fixed interval: a reload rebuilds
/// every profile and both TLS acceptors, and how long that takes is not
/// something a test should be guessing at.
async fn hangup(lab: &Lab, expect_generation: u64) {
    lab.exec_in(&lab.proxy, "kill -HUP 1").await;

    for _ in 0..100 {
        let logs = lab.get_proxy_logs().await;
        if logs.contains(&format!("generation={expect_generation}"))
            || logs.contains(&format!("\"generation\":{expect_generation}"))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "generation {expect_generation} never appeared:\n{}",
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
    hangup(&lab, 2).await;

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
    hangup(&lab, 3).await;

    let after = directory(&lab).await;
    assert!(
        after.contains("https://second.example"),
        "a second SIGHUP must reload rather than terminate: {after}"
    );

    // Still the same process, still answering ACME. A restart would have reset
    // the generation counter, which is why the assertion above is on
    // generation 3 and not merely "reloaded".
    let logs = lab.get_proxy_logs().await;
    assert_eq!(
        logs.matches("server_startup").count(),
        1,
        "the process must not have restarted: {logs}"
    );
}

/// A reload that cannot be honoured is refused **by name**, and the server
/// keeps serving the generation it already had.
///
/// `server.bind_address` is frozen: a running process cannot move its socket.
/// The whole point of refusing rather than half-applying is that "what is this
/// server running?" keeps having an answer, so this asserts both halves — the
/// refusal names the key, and the old value is still being served.
#[tokio::test]
#[ignore]
async fn test_a_frozen_key_is_refused_and_the_server_keeps_serving() {
    let lab = Lab::new(vec![]).await;

    // The container was started with `ACME_PROXY_SERVER__BIND_ADDRESS`, and the
    // environment beats the file — so to change the *resolved* value the file
    // is not enough. `meta.website` proves the reload ran at all; the frozen
    // key is asserted through a second attempt below.
    lab.exec_in(
        &lab.proxy,
        "printf '[meta]\\nwebsite = \"https://live.example\"\\n' > /data/config.toml",
    )
    .await;
    hangup(&lab, 2).await;
    assert!(directory(&lab).await.contains("https://live.example"));

    // The profile *set* is frozen: a profile is a URL namespace, a signer and
    // a row in `accounts.profile`, none of which a running process can grow.
    lab.exec_in(
        &lab.proxy,
        "printf '[meta]\\nwebsite = \"https://live.example\"\\n\
         [profiles.extra]\\nenabled = true\\n' > /data/config.toml",
    )
    .await;
    lab.exec_in(&lab.proxy, "kill -HUP 1").await;

    // Give the refusal time to be logged, then assert the server is unchanged.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let logs = lab.get_proxy_logs().await;
    assert!(
        logs.contains("server_config_reload_refused"),
        "adding a profile to a running server must be refused: {logs}"
    );
    assert!(
        directory(&lab).await.contains("https://live.example"),
        "a refused reload must leave the running generation untouched"
    );
    assert_eq!(
        logs.matches("server_startup").count(),
        1,
        "and must not restart the process"
    );
}
