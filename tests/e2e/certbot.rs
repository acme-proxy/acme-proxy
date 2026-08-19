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

/// **Renewal** — the operation a deployment performs far more often than a
/// first issuance, and the one this lab did not exercise at all.
///
/// `grep renew tests/e2e/` hit only the `renewalInfo` URL in `ari.rs` before
/// this. What renewal actually goes through is a *second* full order under an
/// existing account: `newOrder`, a fresh authorization, a fresh challenge, and
/// a second `finalize` against a CA that has already issued for this name once.
/// Nothing about that is the first-issuance path, and `orders.rs`'s
/// `UNIQUE(order_id, identifier)` plus the account's own find-or-create are
/// exactly the places a second pass could go wrong.
///
/// `--force-renewal` because a fresh 90-day certificate is nowhere near
/// certbot's 30-day renewal window; the point here is the re-issuance path, not
/// certbot's scheduling.
#[tokio::test]
#[ignore]
async fn test_certbot_renew() {
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
        cp "$CERT_PATH" /tmp/first.pem

        # `--no-random-sleep-on-renew` is not a nicety. certbot's renew path
        # applies `random.uniform(1, 60 * 8)` — a one-to-eight-minute sleep —
        # whenever `sys.stdin.isatty()` is false, which it always is under
        # `podman exec`. It exists to spread load across Let's Encrypt's real
        # clients and does nothing for a CA in a container on this host. Left
        # in, this single line averaged four minutes and made the whole suite's
        # wall time a coin flip.
        certbot renew \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive --force-renewal --no-random-sleep-on-renew \
            --webroot --webroot-path /tmp/webroot

        python3 - /tmp/first.pem "$CERT_PATH" <<PYEOF
import sys
from cryptography import x509

def load(path):
    with open(path, "rb") as handle:
        return x509.load_pem_x509_certificate(handle.read())

first, second = load(sys.argv[1]), load(sys.argv[2])

# A renewal is a new certificate, not the same one handed back. A CA that
# returned the cached chain would satisfy certbot and leave the deployment
# with an expiry that never moves.
assert first.serial_number != second.serial_number, "renewal returned the same serial"

# ...for the same name.
def names(cert):
    return sorted(
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        .value.get_values_for_type(x509.DNSName)
    )

assert names(first) == names(second) == ["example.com"], (names(first), names(second))

# And the new one is at least as long-lived, which is the entire reason to
# renew.
assert second.not_valid_after_utc >= first.not_valid_after_utc, (
    first.not_valid_after_utc, second.not_valid_after_utc
)
print("renewed:", first.serial_number, "->", second.serial_number)
PYEOF
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    // The server's own view: two issuances recorded, not one.
    let logs = lab.get_proxy_logs().await;
    let issued = logs.matches("certificate_issued").count();
    assert!(
        issued >= 2,
        "the CA must have signed twice, once per order: {issued} in {logs}"
    );
}
