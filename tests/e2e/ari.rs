use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_ari_order() {
    let lab = Lab::new(vec![]).await;

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email ari-test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains ari.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    // The RFC 9773 §4.1 certID, built the way a real client does:
    // `base64url(AKI keyIdentifier) "." base64url(serial)`, both unpadded.
    //
    // Both halves matter — the server checks the AKI against the certificate,
    // so a placeholder is rejected — which makes this also the end-to-end proof
    // that the local CA emits an Authority Key Identifier at all. OpenSSL 1.1
    // prefixes the extension value with `keyid:`, OpenSSL 3 does not; strip it
    // either way.
    let extract_script = r#"
        set -e
        CERT=/tmp/certbot/config/live/ari.example.com/cert.pem
        CERT_SERIAL=$(openssl x509 -in $CERT -noout -serial | cut -d= -f2)
        CERT_AKI=$(openssl x509 -in $CERT -noout -ext authorityKeyIdentifier \
            | tail -n +2 | tr -d ' \n' | sed 's/^keyid://' | tr -d ':')
        test -n "$CERT_AKI"
        python3 -c "import base64
b = lambda h: base64.urlsafe_b64encode(bytes.fromhex(h)).decode().rstrip('=')
print(b('$CERT_AKI') + '.' + b('$CERT_SERIAL'))"
    "#;

    let (success, cert_id, stderr) = lab.exec_in_with_output(&lab.certbot, extract_script).await;
    assert!(
        success,
        "Failed to build the certID (does the leaf carry an AKI?): {}",
        stderr
    );
    let cert_id = cert_id.trim();

    let ari_url = format!(
        "{}/renewalInfo/{}",
        lab.proxy_url.replace("/directory", ""),
        cert_id
    );

    let curl_script = format!("curl -s -w \"\\nHTTP_STATUS:%{{http_code}}\" {}", ari_url);
    let (success, ari_response, _) = lab.exec_in_with_output(&lab.acme_sh, &curl_script).await;

    assert!(
        success,
        "Failed to fetch ARI info. Response: {}",
        ari_response
    );
    assert!(
        ari_response.contains("\"suggestedWindow\""),
        "ARI response does not contain suggestedWindow: {}",
        ari_response
    );
}
