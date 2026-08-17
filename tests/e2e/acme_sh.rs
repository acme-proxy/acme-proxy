use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_acme_sh_register() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}

#[tokio::test]
#[ignore]
async fn test_acme_sh_order() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh
        acme.sh --issue \
            -d example.com \
            --server {0} \
            -w /tmp/acme-sh \
            --home /tmp/acme-sh
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}

#[tokio::test]
#[ignore]
async fn test_acme_sh_deactivate_account() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh
        acme.sh --deactivate-account \
            --server {0} \
            --home /tmp/acme-sh
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}

#[tokio::test]
#[ignore]
async fn test_acme_sh_update_account() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email initial@example.com \
            --home /tmp/acme-sh
        acme.sh --update-account \
            -m updated@example.com \
            --server {0} \
            --home /tmp/acme-sh
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}

/// Renewal through the *other* client.
///
/// Worth having beside `test_certbot_renew` rather than instead of it: the two
/// clients differ in exactly the places a second order can go wrong. acme.sh
/// reuses its stored account and keeps its own renewal bookkeeping, and
/// `--force` is how it is told to re-issue before its own clock says so.
#[tokio::test]
#[ignore]
async fn test_acme_sh_renew() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh
        acme.sh --issue \
            -d example.com \
            --server {0} \
            -w /tmp/acme-sh \
            --home /tmp/acme-sh

        CERT=/tmp/acme-sh/example.com/example.com.cer
        cp "$CERT" /tmp/first.cer

        acme.sh --renew \
            -d example.com \
            --server {0} \
            --home /tmp/acme-sh \
            --force

        python3 - /tmp/first.cer "$CERT" <<PYEOF
import sys
from cryptography import x509

def load(path):
    with open(path, "rb") as handle:
        return x509.load_pem_x509_certificate(handle.read())

first, second = load(sys.argv[1]), load(sys.argv[2])
assert first.serial_number != second.serial_number, "renewal returned the same serial"
print("renewed:", first.serial_number, "->", second.serial_number)
PYEOF
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}

/// Revocation through acme.sh.
///
/// `tests/e2e/certbot.rs` covers the same endpoint, but only from certbot —
/// and RFC 8555 §7.6 has two authorization forms (the order's account `kid`,
/// and the certificate's own key pair). Two clients reaching the same endpoint
/// is how a client-specific assumption in that handler would surface.
#[tokio::test]
#[ignore]
async fn test_acme_sh_revoke() {
    let lab = Lab::new(vec![]).await;

    let script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh
        acme.sh --issue \
            -d example.com \
            --server {0} \
            -w /tmp/acme-sh \
            --home /tmp/acme-sh

        acme.sh --revoke \
            -d example.com \
            --server {0} \
            --home /tmp/acme-sh

        # The CRL the server publishes must now name it. Fetched from the
        # profile router, which is where `/crl` lives.
        python3 - /tmp/acme-sh/example.com/example.com.cer {0}/crl <<PYEOF
import sys, urllib.request
from cryptography import x509

with open(sys.argv[1], "rb") as handle:
    cert = x509.load_pem_x509_certificate(handle.read())

with urllib.request.urlopen(sys.argv[2]) as response:
    crl = x509.load_der_x509_crl(response.read())

serials = [entry.serial_number for entry in crl]
assert cert.serial_number in serials, (cert.serial_number, serials)
print("revoked and on the CRL:", cert.serial_number)
PYEOF
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}
