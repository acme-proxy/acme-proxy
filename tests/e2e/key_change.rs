//! End-to-end coverage for `POST /keyChange` (RFC 8555 §7.3.5): a real
//! client-driven account key rollover, proving the new key actually works
//! afterward rather than just that the client believes it succeeded.
//!
//! Neither certbot nor acme.sh implement key rollover in their current
//! versions (certbot's vendored `acme` library has no keyChange primitives
//! at all; acme.sh dropped `--update-account-key` with no replacement) — see
//! `tests/e2e/README.md`. lego added `accounts keyrollover` in v5.0.0
//! (go-acme/lego#2950), which is why `tests/e2e/lego.Containerfile` builds a
//! pinned v5.3.1 release from source rather than relying on Alpine's `lego`
//! package, which is still on the 4.x line.

use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_lego_key_rollover() {
    let lab = Lab::new(vec![("ACME_PROXY_SERVER__TLS__ENABLED", "true")]).await;

    let lego_script = format!(
        r#"
        set -e
        lego run --accept-tos --email test@example.com \
            --server {0} \
            --tls-skip-verify \
            --path /tmp/lego \
            --domains rollover.example.com \
            --http --http.address :0

        printf 'Y\n' | lego accounts keyrollover \
            --email test@example.com \
            --server {0} \
            --tls-skip-verify \
            --path /tmp/lego

        lego run --accept-tos --email test@example.com \
            --server {0} \
            --tls-skip-verify \
            --path /tmp/lego \
            --domains rollover-after.example.com \
            --http --http.address :0
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.lego, &lego_script).await;

    let logs = lab.get_proxy_logs().await;
    assert!(
        logs.contains("account_key_changed"),
        "acme-proxy log has no account_key_changed marker"
    );
}
