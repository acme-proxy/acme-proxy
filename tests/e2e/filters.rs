use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_allowed_ip() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__ENABLED", "allowed_ip"),
        ("ACME_PROXY_FILTER__ALLOWED_IP__ALLOW", "CERTBOT_IP/32"),
    ])
    .await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let acmesh_script = format!(
        r#"
        curl -s -w "\nHTTP_STATUS:%{{http_code}}" {0}
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab.exec_in_with_output(&lab.acme_sh, &acmesh_script).await;
    assert!(success, "curl should not fail execution entirely");
    assert!(
        stdout.contains("HTTP_STATUS:403"),
        "Expected 403 status code, got: {}",
        stdout
    );
    assert!(
        stdout.to_lowercase().contains("unauthorized"),
        "Expected unauthorized in response, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_custom_script() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__ENABLED", "custom"),
        ("ACME_PROXY_FILTER__CUSTOM_ENABLED", "main"),
        (
            "ACME_PROXY_FILTER__CUSTOM__MAIN__SCRIPT_PATH",
            "/tmp/filter_script.sh",
        ),
    ])
    .await;

    let script = r#"#!/bin/sh
if [ "$ACME_FILTER_HOOK" = "identifiers" ]; then
  case "$ACME_FILTER_IDENTIFIERS" in
    *denied*)
      echo "custom script denied domain: $ACME_FILTER_IDENTIFIERS"
      exit 1
      ;;
  esac
fi
exit 0
"#;

    lab.exec_in(
        &lab.proxy,
        &format!(
            "cat > /tmp/filter_script.sh <<'FILTER_SCRIPT_EOF'\n{}\nFILTER_SCRIPT_EOF\nchmod +x /tmp/filter_script.sh",
            script
        ),
    )
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains denied.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout
            .to_lowercase()
            .contains("custom script denied domain"),
        "Expected rejection for custom filter reason, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_identifiers() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__ENABLED", "identifiers"),
        (
            "ACME_PROXY_FILTER__IDENTIFIERS__DENY",
            "denied\\.example\\.com",
        ),
    ])
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains denied.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout.to_lowercase().contains("denied by policy"),
        "Expected rejection for rejectedIdentifier reason, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_netbox() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__ENABLED", "netbox"),
        ("ACME_PROXY_FILTER__NETBOX__URL", "http://NETBOX_IP:8080"),
        ("ACME_PROXY_FILTER__NETBOX__TOKEN", "labtoken"),
    ])
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let acmesh_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        acme.sh --register-account \
            --server {0} \
            --accountemail test@example.com
        acme.sh --issue \
            --server {0} \
            --domain machine.example.com \
            --webroot /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &acmesh_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains machine.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout.to_lowercase().contains("netbox associates"),
        "Expected rejection from NetBox, got: {}",
        stdout
    );

    let netbox_logs = lab.get_netbox_mock_logs().await;
    assert!(
        netbox_logs.contains("querying ip address"),
        "the certbot/allowed.example.com case never queried NetBox's ip-addresses \
         endpoint — got: {}",
        netbox_logs
    );
    assert!(
        netbox_logs.contains("querying device"),
        "the acme.sh/machine.example.com device-fallback case never queried NetBox's \
         devices endpoint — got: {}",
        netbox_logs
    );
}

#[tokio::test]
#[ignore]
async fn test_reverse_dns() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__ENABLED", "reverse_dns"),
        ("ACME_PROXY_DNS__RESOLVER", "dns:53"),
    ])
    .await;

    let certbot_ip = Lab::get_ip(lab.certbot.id(), &lab.network).await;
    lab.dns_add_ptr(&certbot_ip, "trusted-client.lab.").await;
    lab.dns_add_a("trusted-client.lab.", &certbot_ip).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let acmesh_script = format!(
        r#"
        curl -s -w "\nHTTP_STATUS:%{{http_code}}" {0}
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab.exec_in_with_output(&lab.acme_sh, &acmesh_script).await;
    assert!(success, "curl should not fail execution entirely");
    assert!(
        stdout.contains("HTTP_STATUS:403"),
        "Expected 403 status code, got: {}",
        stdout
    );
    assert!(
        stdout.to_lowercase().contains("unauthorized"),
        "Expected unauthorized in response, got: {}",
        stdout
    );
}
