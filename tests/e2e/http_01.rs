use crate::common::Lab;

#[tokio::test]
#[ignore = "e2e"]
async fn test_http_01_order() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_CHALLENGE__ENABLED", "http-01"),
        ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
        ("ACME_PROXY_DNS__RESOLVER", "dns:53"),
    ])
    .await;

    let certbot_ip = Lab::get_ip(lab.certbot.id(), &lab.network).await;
    lab.dns_add_a("http01-certbot.lab", &certbot_ip).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
        certbot certonly \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --standalone \
            -d http01-certbot.lab --non-interactive
        test -f /tmp/certbot/config/live/http01-certbot.lab/fullchain.pem
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let acme_sh_ip = Lab::get_ip(lab.acme_sh.id(), &lab.network).await;
    lab.dns_add_a("http01-acmesh.lab", &acme_sh_ip).await;

    let acmesh_script = format!(
        r#"
        set -e
        acme.sh --issue \
            --server {0} \
            --home /tmp/acme-sh \
            --standalone \
            -d http01-acmesh.lab
    "#,
        lab.proxy_url
    );
    lab.exec_in(&lab.acme_sh, &acmesh_script).await;

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("challenge_http_01_matched"),
        "the server never logged a successful http-01 fetch — was bypass on?"
    );
}
