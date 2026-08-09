use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_admin_cli_order() {
    let lab = Lab::new(vec![]).await;

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email admin-cli-test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains admincli.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let (success, out, _) = lab
        .exec_in_with_output(&lab.proxy, "acme-proxy account list --json")
        .await;
    assert!(success, "Failed to list accounts");
    assert!(
        out.contains("admin-cli-test@example.com"),
        "account list did not show the registered contact"
    );

    let (success, out, _) = lab
        .exec_in_with_output(&lab.proxy, "acme-proxy order list --json")
        .await;
    assert!(success, "Failed to list orders");
    assert!(
        out.contains("admincli.example.com"),
        "order list did not show the ordered identifier"
    );
    assert!(
        out.contains(r#""status":"valid""#),
        "order status is not valid"
    );
}
