use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_endpoints_order() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_ENDPOINTS__SECOND__ENABLED", "true"),
        (
            "ACME_PROXY_ENDPOINTS__SECOND__SIGNER__LOCAL_CA__CERT_PATH",
            "/tmp/second_ca.pem",
        ),
        (
            "ACME_PROXY_ENDPOINTS__SECOND__SIGNER__LOCAL_CA__KEY_PATH",
            "/tmp/second_ca.key",
        ),
        (
            "ACME_PROXY_ENDPOINTS__SECOND__SIGNER__LOCAL_CA__CRL_PATH",
            "/tmp/second_ca.crl",
        ),
        ("ACME_PROXY_ENDPOINTS__SECOND__SIGNER__TYPE", "local_ca"),
    ])
    .await;

    let proxy_base = lab.proxy_url.replace("/endpoint/default/directory", "");

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        for endpoint in default second; do
            certbot register \
            --agree-tos --email test@example.com \
            --server "{0}/endpoint/${{endpoint}}/directory" \
            --config-dir "/tmp/certbot/${{endpoint}}" --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
            certbot certonly \
            --domains "${{endpoint}}.example.com" \
            --server "{0}/endpoint/${{endpoint}}/directory" \
            --config-dir "/tmp/certbot/${{endpoint}}" --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
        done

        python3 - <<PY
from cryptography import x509
from cryptography.hazmat.primitives import hashes

cas = {{}}
for endpoint in ("default", "second"):
    live = f"/tmp/certbot/{{endpoint}}/live/{{endpoint}}.example.com"
    with open(f"{{live}}/cert.pem", "rb") as handle:
        leaf = x509.load_pem_x509_certificate(handle.read())
    with open(f"{{live}}/chain.pem", "rb") as handle:
        ca = x509.load_pem_x509_certificate(handle.read())
    leaf.verify_directly_issued_by(ca)
    cas[endpoint] = ca.fingerprint(hashes.SHA256())
    names = [n.value for n in leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value]
    assert names == [f"{{endpoint}}.example.com"], (endpoint, names)

assert cas["default"] != cas["second"], (
    "both endpoints signed with the same CA: they are not really separate"
)

import urllib.error
import urllib.request

def get(path):
    return urllib.request.urlopen(f"{0}{{path}}").read()

assert get("/endpoint/default/crl") != get("/endpoint/second/crl"), "both endpoints served the same CRL"
get("/health")
try:
    get("/directory")
except urllib.error.HTTPError as error:
    assert error.code == 404, error.code
else:
    raise AssertionError("an ACME directory is served at the root")
PY
    "#,
        proxy_base
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let (success, out, _) = lab
        .exec_in_with_output(&lab.proxy, "acme-proxy account list --json")
        .await;
    assert!(success, "Failed to list accounts");
    assert!(
        out.contains(r#""endpoint":"default""#),
        "account list does not show default endpoint: {}",
        out
    );
    assert!(
        out.contains(r#""endpoint":"second""#),
        "account list does not show second endpoint: {}",
        out
    );

    let (success, out, _) = lab
        .exec_in_with_output(
            &lab.proxy,
            "acme-proxy account list --endpoint second --json",
        )
        .await;
    assert!(success, "Failed to list accounts for second endpoint");
    assert!(
        !out.contains(r#""endpoint":"default""#),
        "account list --endpoint second leaked default endpoint: {}",
        out
    );
}
