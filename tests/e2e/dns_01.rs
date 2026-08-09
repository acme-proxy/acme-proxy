use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_dns_01_order() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_CHALLENGE__ENABLED", "dns-01"),
        ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
        ("ACME_PROXY_DNS__RESOLVER", "dns:53"),
    ])
    .await;

    let dns_ip = Lab::get_ip(lab.dns.id(), &lab.network).await;

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/certbot/config /tmp/certbot/work /tmp/certbot/logs
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
        cat > /tmp/certbot/rfc2136.ini <<INI
dns_rfc2136_server = {1}
dns_rfc2136_port = 53
dns_rfc2136_name = tsig-key.
dns_rfc2136_secret = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
dns_rfc2136_algorithm = HMAC-SHA256
INI
        chmod 600 /tmp/certbot/rfc2136.ini
        certbot certonly \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --authenticator dns-rfc2136 --dns-rfc2136-credentials /tmp/certbot/rfc2136.ini --dns-rfc2136-propagation-seconds 2 \
            -d dns01-certbot.lab --non-interactive
        test -f /tmp/certbot/config/live/dns01-certbot.lab/fullchain.pem
    "#,
        lab.proxy_url, dns_ip
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let certbot_wildcard_script = format!(
        r#"
        set -e
        mkdir -p /tmp/certbot
        cat > /tmp/certbot/rfc2136.ini <<INI
dns_rfc2136_server = {1}
dns_rfc2136_port = 53
dns_rfc2136_name = tsig-key.
dns_rfc2136_secret = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
dns_rfc2136_algorithm = HMAC-SHA256
INI
        chmod 600 /tmp/certbot/rfc2136.ini
        certbot certonly \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --authenticator dns-rfc2136 --dns-rfc2136-credentials /tmp/certbot/rfc2136.ini --dns-rfc2136-propagation-seconds 2 \
            -d "*.wild.lab" --non-interactive
        test -f /tmp/certbot/config/live/wild.lab/fullchain.pem
    "#,
        lab.proxy_url, dns_ip
    );

    lab.exec_in(&lab.certbot, &certbot_wildcard_script).await;

    let acmesh_script = format!(
        r#"
        set -e
        mkdir -p /tmp/acme-sh
        export NSUPDATE_SERVER="{1}"
        export NSUPDATE_KEY="/tmp/acme-sh/tsig.key"
        echo "key \"tsig-key.\" {{ algorithm hmac-sha256; secret \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"; }};" > /tmp/acme-sh/tsig.key
        acme.sh --issue \
            --server {0} \
            --home /tmp/acme-sh \
            --dns dns_nsupdate \
            --dnssleep 2 \
            -d dns01-acmesh.lab
    "#,
        lab.proxy_url, dns_ip
    );

    lab.exec_in(&lab.acme_sh, &acmesh_script).await;

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("challenge_dns_01_matched"),
        "the server never logged a successful dns-01 match — was bypass on?"
    );
}
