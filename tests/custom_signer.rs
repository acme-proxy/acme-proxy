//! End-to-end coverage for the `custom` signer backend (`signer.backend =
//! "custom"`): a real order → finalize → certificate round trip issued by an
//! external `openssl`-backed script, plus revocation through the same
//! script. `src/signer/custom.rs`'s inline tests cover the hook contract in
//! isolation (env vars, exit codes, timeouts, the optional `crl`/
//! `renewal_info` hooks); this file proves the wiring through the real HTTP
//! router end-to-end, the same way `tests/filters.rs`'s
//! `a_custom_script_filter_enforces_policy_end_to_end` does for the filter
//! side.

use std::sync::Arc;

use acme_proxy::config::CustomSignerConfig;
use acme_proxy::signer::SignerBackend;
use acme_proxy::signer::custom::CustomScriptSigner;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use x509_parser::prelude::FromDer;

mod common;
use common::{
    EcSigner, TempDir, TestSigner, body_json, fetch_nonce, first_certificate, make_csr, p,
    test_app_with_signer, write_script,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";
const REVOKE_URL: &str = "http://localhost:3000/profile/default/revokeCert";

/// A real `openssl`-backed `issue` script: on first invocation it generates
/// a throwaway self-signed CA next to itself, then signs whatever CSR it's
/// handed against it — a genuine, parseable X.509 leaf, not a stub string,
/// so this exercises the same `leaf_der_from_chain`/`cert_serial_and_spki`
/// parsing path every real backend goes through.
const ISSUE_SCRIPT: &str = r#"#!/bin/sh
set -e
DIR=$(dirname "$0")
if [ ! -f "$DIR/ca.key" ]; then
    openssl genrsa -out "$DIR/ca.key" 2048 2>/dev/null
    openssl req -x509 -new -key "$DIR/ca.key" -sha256 -days 3650 \
        -subj "/CN=integration test custom signer CA" -out "$DIR/ca.pem" 2>/dev/null
fi
STDIN=$(cat)
CSR_B64=$(printf '%s' "$STDIN" | sed -n 's/.*"csr_der_base64":"\([^"]*\)".*/\1/p')
printf '%s' "$CSR_B64" | base64 -d > "$DIR/req.der"
openssl req -inform DER -in "$DIR/req.der" -out "$DIR/req.pem"
openssl x509 -req -in "$DIR/req.pem" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 90 -copy_extensions copy -out "$DIR/leaf.pem"
cat "$DIR/leaf.pem" "$DIR/ca.pem"
"#;

/// A trivial `revoke` script: this file's own point is the `issue` round
/// trip, so revoke just needs to succeed (idempotency and real CRL
/// reflection are covered by `src/signer/custom.rs`'s inline tests and the
/// `tests/e2e/custom_signer/` lab scenario respectively).
const REVOKE_SCRIPT: &str = "#!/bin/sh\ncat > /dev/null\nexit 0\n";

fn custom_signer(script_path: &std::path::Path) -> Arc<dyn SignerBackend> {
    let cfg = CustomSignerConfig {
        script_path: script_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    Arc::new(CustomScriptSigner::from_config(&cfg).unwrap())
}

async fn post(app: &Router, path: &str, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Registers an account and returns its account URL (used as `kid`).
async fn register(app: &Router, signer: &impl TestSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// Drives a full order → authz → trigger → finalize lifecycle for
/// `account_url` (already registered under `signer`), and returns the
/// issued `leaf + CA` PEM chain the custom script produced.
async fn issue_certificate(app: &Router, signer: &impl TestSigner, account_url: &str) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &authz_url, &nonce);
    let res = post(app, authz_path, body).await;
    let authz = body_json(res).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, &challenge_url, &nonce, &json!({}));
    let res = post(app, challenge_path, body).await;
    assert_eq!(body_json(res).await["status"], "valid");

    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &order_url, &nonce);
    let res = post(app, order_path, body).await;
    assert_eq!(body_json(res).await["status"], "ready");

    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "csr": make_csr("example.com") });
    let body = signer.sign_kid(account_url, &finalize_url, &nonce, &payload);
    let res = post(app, finalize_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let cert_path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &cert_url, &nonce);
    let res = post(app, cert_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

#[tokio::test]
async fn a_custom_script_signer_issues_a_real_certificate_end_to_end() {
    let dir = TempDir::new("custom-signer-it");
    let script_path = write_script(&dir, "issue.sh", ISSUE_SCRIPT);

    let (app, _db) = test_app_with_signer(custom_signer(&script_path)).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url).await;

    // A genuine, parseable X.509 leaf issued by the script's own CA — not the
    // default `local_ca` fallback.
    let leaf_der = first_certificate(&chain);
    let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(&leaf_der)
        .expect("the custom signer's leaf must parse as a real X.509 certificate");
    assert!(
        leaf.issuer()
            .to_string()
            .contains("integration test custom signer CA"),
        "issuer was {}",
        leaf.issuer()
    );
}

#[tokio::test]
async fn revoke_through_a_custom_script_signer_succeeds() {
    let dir = TempDir::new("custom-signer-it");
    let issue_path = write_script(&dir, "issue.sh", ISSUE_SCRIPT);
    write_script(&dir, "revoke.sh", REVOKE_SCRIPT);

    // Both hooks live in the same script in production use, but the
    // `CustomScriptSigner` only ever invokes one script — so this test wires
    // a tiny dispatcher script that forwards to the right one by hook name,
    // proving `revoke`'s own env/exit-code path independently of `issue`'s.
    let dispatcher = format!(
        "#!/bin/sh\ncase \"$ACME_SIGNER_HOOK\" in\n  issue) exec \"{}\" ;;\n  revoke) exec \"{}\" ;;\nesac\n",
        dir.path().join("issue.sh").to_str().unwrap(),
        dir.path().join("revoke.sh").to_str().unwrap(),
    );
    let dispatcher_path = write_script(&dir, "dispatch.sh", &dispatcher);
    let _ = issue_path;

    let (app, _db) = test_app_with_signer(custom_signer(&dispatcher_path)).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url).await;

    let cert_field = BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain));
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = post(&app, &p("/revokeCert"), body).await;
    assert_eq!(res.status(), StatusCode::OK);
}
