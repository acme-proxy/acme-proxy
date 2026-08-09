//! End-to-end coverage for `signer.backend = "custom"`: a real order →
//! finalize round trip against the whole `acme-proxy` HTTP surface, issued by
//! a script running *inside* the server's own container. The hook contract
//! itself (env vars, stdin JSON, exit codes, timeouts) is already covered by
//! `src/signer/custom.rs`'s inline tests, and the wiring through the real
//! router is covered host-side by `tests/custom_signer.rs`; this file's own
//! job is proving the same thing works when the script is a subprocess of a
//! server running in a container it doesn't control the filesystem of ahead
//! of time — the file has to be copied in before the server starts, since
//! `signer.custom.script_path` is read at startup.

use crate::common::Lab;

/// A real `openssl`-backed `issue` script (openssl is installed in the
/// `acme-proxy-e2e` image specifically for this): on first invocation it
/// generates a throwaway self-signed CA next to itself, then signs whatever
/// CSR it's handed against it — a genuine, parseable X.509 leaf, not a stub
/// string, proving delegation actually happened rather than a silent
/// fallback to `local_ca`'s own default CA.
const ISSUE_SCRIPT: &str = r#"#!/bin/sh
set -e
DIR=$(dirname "$0")
if [ ! -f "$DIR/ca.key" ]; then
    openssl genrsa -out "$DIR/ca.key" 2048 2>/dev/null
    openssl req -x509 -new -key "$DIR/ca.key" -sha256 -days 3650 \
        -subj "/CN=e2e custom signer CA" -out "$DIR/ca.pem" 2>/dev/null
fi
STDIN=$(cat)
CSR_B64=$(printf '%s' "$STDIN" | sed -n 's/.*"csr_der_base64":"\([^"]*\)".*/\1/p')
printf '%s' "$CSR_B64" | base64 -d > "$DIR/req.der"
openssl req -inform DER -in "$DIR/req.der" -out "$DIR/req.pem"
openssl x509 -req -in "$DIR/req.pem" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 90 -copy_extensions copy -out "$DIR/leaf.pem"
cat "$DIR/leaf.pem" "$DIR/ca.pem"
"#;

#[tokio::test]
#[ignore = "e2e"]
async fn test_custom_signer_order() {
    let lab = Lab::new_with_files(
        vec![
            ("ACME_PROXY_SIGNER__BACKEND", "custom"),
            ("ACME_PROXY_SIGNER__CUSTOM__SCRIPT_PATH", "/data/signer.sh"),
        ],
        vec![("/data/signer.sh", ISSUE_SCRIPT.as_bytes().to_vec())],
    )
    .await;

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
            --domains custom-signer.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
        openssl x509 -in /tmp/certbot/config/live/custom-signer.example.com/cert.pem -noout -issuer
    "#,
        lab.proxy_url
    );

    let (success, stdout, stderr) = lab.exec_in_with_output(&lab.certbot, &certbot_script).await;
    assert!(
        success,
        "certbot order against the custom signer failed: {}",
        stderr
    );
    assert!(
        stdout.contains("e2e custom signer CA"),
        "the issued certificate's issuer was not the custom script's CA — the custom \
         signer backend was not actually used. Got: {}",
        stdout
    );
}
