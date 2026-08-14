use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_certbot_register() {
    let lab = Lab::new(vec![]).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;
}

#[tokio::test]
#[ignore]
async fn test_certbot_order() {
    let lab = Lab::new(vec![]).await;

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
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;
}

#[tokio::test]
#[ignore]
async fn test_certbot_show_account() {
    let lab = Lab::new(vec![]).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot show_account \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;
}

#[tokio::test]
#[ignore]
async fn test_certbot_unregister() {
    let lab = Lab::new(vec![]).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot unregister \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;
}

#[tokio::test]
#[ignore]
async fn test_certbot_revoke() {
    let lab = Lab::new(vec![]).await;

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

        CERT_PATH=/tmp/certbot/config/live/example.com/cert.pem

        certbot revoke \
            --cert-path "$CERT_PATH" \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive --no-delete-after-revoke

        if certbot revoke \
            --cert-path "$CERT_PATH" \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive --no-delete-after-revoke; then
            echo "FAIL: a second revoke of the same certificate should have been rejected"
            exit 1
        fi

        python3 - "$CERT_PATH" <<PYEOF
import sys
import urllib.request
from cryptography import x509

with open(sys.argv[1], "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
serial = cert.serial_number

crl_der = urllib.request.urlopen("{1}").read()
crl = x509.load_der_x509_crl(crl_der)
if crl.get_revoked_certificate_by_serial_number(serial) is None:
    print(f"FAIL: serial {{serial:x}} not found in the served CRL")
    sys.exit(1)
PYEOF
    "#,
        lab.proxy_url,
        lab.proxy_url.replace("/directory", "/crl")
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("certificate_revoked"),
        "the server never logged a successful revocation"
    );
}
