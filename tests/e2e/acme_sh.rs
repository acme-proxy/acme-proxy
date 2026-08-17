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
        # `--cert-file` rather than reaching into acme.sh's own store: it
        # defaults to ECC keys and files those under `<domain>_ecc/`, so the
        # internal path depends on the key type and the acme.sh version. The
        # installed copy does not, and `--renew` re-installs to it.
        acme.sh --issue \
            -d example.com \
            --server {0} \
            -w /tmp/acme-sh \
            --home /tmp/acme-sh \
            --cert-file /tmp/cert.pem

        cp /tmp/cert.pem /tmp/first.pem

        acme.sh --renew \
            -d example.com \
            --server {0} \
            --home /tmp/acme-sh \
            --ecc \
            --force

        # `openssl` rather than Python: this image is Debian-slim with curl,
        # openssl and acme.sh, and carries no interpreter.
        FIRST=$(openssl x509 -in /tmp/first.pem -noout -serial)
        SECOND=$(openssl x509 -in /tmp/cert.pem -noout -serial)
        echo "renewed: $FIRST -> $SECOND"

        # A renewal is a new certificate, not the same one handed back. A CA
        # returning the cached chain satisfies acme.sh and leaves the deployment
        # with an expiry that never moves.
        if [ "$FIRST" = "$SECOND" ]; then
            echo "FAIL: renewal returned the same serial"
            exit 1
        fi

        # ...for the same name.
        openssl x509 -in /tmp/cert.pem -noout -text | grep -q "DNS:example.com"
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
            --home /tmp/acme-sh \
            --cert-file /tmp/cert.pem

        # `--ecc` because acme.sh defaults to an ECC key and keeps ECC material
        # in a separate store; without it `--revoke` looks in the RSA one and
        # finds nothing.
        acme.sh --revoke \
            -d example.com \
            --server {0} \
            --home /tmp/acme-sh \
            --ecc

        # The CRL the server publishes must now name it. `{0}` is the
        # directory URL, and `/crl` is its sibling under the profile router.
        SERIAL=$(openssl x509 -in /tmp/cert.pem -noout -serial | cut -d= -f2)
        curl -fsS "$(dirname {0})/crl" -o /tmp/ca.crl
        openssl crl -inform DER -in /tmp/ca.crl -noout -text > /tmp/crl.txt

        # A DER integer carries a leading zero byte when its high bit is set,
        # and openssl may print the CRL entry with or without it — so the
        # comparison tolerates leading zeros on either side rather than
        # stripping them from one. Getting this wrong is a test that passes
        # fifteen runs in sixteen.
        NORMALISED=$(echo "$SERIAL" | sed 's/^0*//')
        if ! grep -qiE "Serial Number: *0*$NORMALISED\\b" /tmp/crl.txt; then
            echo "FAIL: $SERIAL is not on the CRL"
            cat /tmp/crl.txt
            exit 1
        fi
        echo "revoked and on the CRL: $SERIAL"
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &script).await;
}
