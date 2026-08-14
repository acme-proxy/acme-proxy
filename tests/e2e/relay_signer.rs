use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_relay_signer_bypass_order() {
    let lab = Lab::new_with_upstream(
        vec![
            ("ACME_PROXY_SIGNER__BACKEND", "relay"),
            ("ACME_PROXY_SIGNER__RELAY__DIRECTORY_URL", "UPSTREAM_URL"),
            (
                "ACME_PROXY_SIGNER__RELAY__ACCOUNT_KEY_PATH",
                "/tmp/upstream_account.key",
            ),
            ("ACME_PROXY_SIGNER__RELAY__CHALLENGE_STRATEGY", "bypass"),
        ],
        vec![("ACME_PROXY_PROFILES__DEFAULT__CA_TYPE", "local")],
    )
    .await;

    println!("PROXY LOGS: {}", lab.get_proxy_logs().await);
    println!("UPSTREAM LOGS: {}", lab.get_proxy_upstream_logs().await);

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
        cp /tmp/certbot/config/live/example.com/fullchain.pem /tmp/fullchain.pem
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let (success, out, _) = lab.exec_in_with_output(&lab.certbot, "openssl x509 -in /tmp/fullchain.pem -noout -issuer 2>/dev/null | tr -d '\\r' | tail -n 1").await;
    assert!(success, "Failed to get issuer");
    let issuer = out.trim();

    let (success, out, _) = lab.exec_in_with_output(lab.proxy_upstream.as_ref().unwrap(), "openssl x509 -in /tmp/upstream-ca.pem -noout -subject 2>/dev/null | tr -d '\\r' | tail -n 1").await;
    assert!(success, "Failed to get upstream subject");
    let upstream_subject = out.trim();

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("upstream_order_opened"),
        "the downstream never opened an upstream order"
    );
    assert!(
        proxy_logs.contains("upstream_relay_succeeded"),
        "the relay never completed"
    );

    let upstream_logs = lab.get_proxy_upstream_logs().await;
    assert!(
        upstream_logs.contains("local_ca_leaf_issued"),
        "the upstream never issued a leaf"
    );

    let upstream_dn = upstream_subject.replace("subject=", "").replace(" ", "");
    let issuer_dn = issuer.replace("issuer=", "").replace(" ", "");
    assert_eq!(
        issuer_dn, upstream_dn,
        "the certificate was not issued by the upstream CA"
    );
}

#[tokio::test]
#[ignore]
async fn test_relay_signer_dns_01() {
    let lab = Lab::new_with_upstream(
        vec![
            ("ACME_PROXY_SIGNER__BACKEND", "relay"),
            ("ACME_PROXY_SIGNER__RELAY__DIRECTORY_URL", "UPSTREAM_URL"),
            (
                "ACME_PROXY_SIGNER__RELAY__ACCOUNT_KEY_PATH",
                "/tmp/upstream_account.key",
            ),
            ("ACME_PROXY_SIGNER__RELAY__CHALLENGE_STRATEGY", "dns01"),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__SERVER",
                "DNS_SERVER_HOST:53",
            ),
            ("ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__ZONE", "lab."),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__TSIG_KEY_NAME",
                "tsig-key.",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__TSIG_KEY_SECRET",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__RFC2136__TSIG_ALGORITHM",
                "hmac-sha256",
            ),
            ("ACME_PROXY_SIGNER__RELAY__POLL_INTERVAL_MS", "500"),
            ("ACME_PROXY_SIGNER__RELAY__POLL_TIMEOUT_SECS", "60"),
        ],
        vec![
            ("ACME_PROXY_CHALLENGE__ENABLED", "dns-01"),
            ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
            ("ACME_PROXY_DNS__RESOLVER", "DNS_SERVER_HOST:53"),
        ],
    )
    .await;

    println!("PROXY LOGS:\n{}", lab.get_proxy_logs().await);

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains signer-dns01.lab \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    let (success, out, err) = lab.exec_in_with_output(&lab.certbot, &certbot_script).await;
    if !success {
        println!("Certbot Stdout:\n{}", out);
        println!("Certbot Stderr:\n{}", err);
        println!("PROXY LOGS ON FAILURE:\n{}", lab.get_proxy_logs().await);
        println!(
            "UPSTREAM LOGS ON FAILURE:\n{}",
            lab.get_proxy_upstream_logs().await
        );
        panic!("Certbot failed");
    }

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("upstream_order_opened"),
        "the downstream never opened an upstream order"
    );
    assert!(
        proxy_logs.contains("upstream_relay_succeeded"),
        "the relay never completed"
    );

    let upstream_logs = lab.get_proxy_upstream_logs().await;
    assert!(
        upstream_logs.contains("challenge_dns_01_matched"),
        "the upstream never logged a successful dns-01 match"
    );
}

/// The relaying backend's `http01` strategy: the downstream proxy answers the
/// upstream's own challenge from its root router, and the upstream validates it
/// for real (`challenge.bypass = false`, `challenge.enabled = ["http-01"]`).
///
/// **The upstream fetches on port 3000, not 80.** A real deployment needs a
/// reverse proxy forwarding or redirecting `/.well-known/acme-challenge/` from
/// port 80 of every name being issued — the downstream binds one socket and
/// this lab has no forwarder in front of it. Moving the *validator's* port
/// stands in for that hop: RFC 8555 fixes the path, not the port, so the code
/// path exercised here is the production one and only the nginx hop is missing,
/// which is a property of nginx rather than of this crate.
#[tokio::test]
#[ignore]
async fn test_relay_signer_http_01() {
    let lab = Lab::new_with_upstream(
        vec![
            ("ACME_PROXY_SIGNER__BACKEND", "relay"),
            ("ACME_PROXY_SIGNER__RELAY__DIRECTORY_URL", "UPSTREAM_URL"),
            (
                "ACME_PROXY_SIGNER__RELAY__ACCOUNT_KEY_PATH",
                "/tmp/upstream_account.key",
            ),
            ("ACME_PROXY_SIGNER__RELAY__CHALLENGE_STRATEGY", "http01"),
            ("ACME_PROXY_SIGNER__RELAY__POLL_INTERVAL_MS", "500"),
            ("ACME_PROXY_SIGNER__RELAY__POLL_TIMEOUT_SECS", "60"),
        ],
        vec![
            ("ACME_PROXY_CHALLENGE__ENABLED", "http-01"),
            ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
            ("ACME_PROXY_DNS__RESOLVER", "DNS_SERVER_HOST:53"),
            // Stands in for the reverse proxy a real deployment puts on port 80.
            ("ACME_PROXY_CHALLENGE__HTTP_01__PORT", "3000"),
        ],
    )
    .await;

    // The name the upstream validates resolves to the DOWNSTREAM proxy: it is
    // the one serving `.well-known`, because the key authorization is built
    // from *its* account at the upstream, not from certbot's account here.
    let proxy_ip = Lab::get_ip(lab.proxy.id(), &lab.network).await;
    lab.dns_add_a("signer-http01.lab", &proxy_ip).await;

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains signer-http01.lab \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    let (success, out, err) = lab.exec_in_with_output(&lab.certbot, &certbot_script).await;
    if !success {
        println!("Certbot Stdout:\n{}", out);
        println!("Certbot Stderr:\n{}", err);
        println!("PROXY LOGS ON FAILURE:\n{}", lab.get_proxy_logs().await);
        println!(
            "UPSTREAM LOGS ON FAILURE:\n{}",
            lab.get_proxy_upstream_logs().await
        );
        panic!("Certbot failed");
    }

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("http_01_responder_mounted"),
        "the responder route was never mounted"
    );
    assert!(
        proxy_logs.contains("http_01_responder_served"),
        "the upstream never fetched the challenge file from this server"
    );
    assert!(
        proxy_logs.contains("upstream_order_opened"),
        "the downstream never opened an upstream order"
    );
    assert!(
        proxy_logs.contains("upstream_relay_succeeded"),
        "the relay never completed"
    );

    let upstream_logs = lab.get_proxy_upstream_logs().await;
    assert!(
        upstream_logs.contains("challenge_http_01_matched"),
        "the upstream never logged a successful http-01 match"
    );
}
