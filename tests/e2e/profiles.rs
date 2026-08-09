use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_profiles_order() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_PROFILES__SECOND__ENABLED", "true"),
        (
            "ACME_PROXY_PROFILES__SECOND__SIGNER__LOCAL_CA__CERT_PATH",
            "/tmp/second_ca.pem",
        ),
        (
            "ACME_PROXY_PROFILES__SECOND__SIGNER__LOCAL_CA__KEY_PATH",
            "/tmp/second_ca.key",
        ),
        (
            "ACME_PROXY_PROFILES__SECOND__SIGNER__LOCAL_CA__CRL_PATH",
            "/tmp/second_ca.crl",
        ),
        ("ACME_PROXY_PROFILES__SECOND__SIGNER__TYPE", "local_ca"),
    ])
    .await;

    let proxy_base = lab.proxy_url.replace("/profile/default/directory", "");

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        for profile in default second; do
            certbot register \
            --agree-tos --email test@example.com \
            --server "{0}/profile/${{profile}}/directory" \
            --config-dir "/tmp/certbot/${{profile}}" --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
            certbot certonly \
            --domains "${{profile}}.example.com" \
            --server "{0}/profile/${{profile}}/directory" \
            --config-dir "/tmp/certbot/${{profile}}" --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
        done

        python3 - <<PY
from cryptography import x509
from cryptography.hazmat.primitives import hashes

cas = {{}}
for profile in ("default", "second"):
    live = f"/tmp/certbot/{{profile}}/live/{{profile}}.example.com"
    with open(f"{{live}}/cert.pem", "rb") as handle:
        leaf = x509.load_pem_x509_certificate(handle.read())
    with open(f"{{live}}/chain.pem", "rb") as handle:
        ca = x509.load_pem_x509_certificate(handle.read())
    leaf.verify_directly_issued_by(ca)
    cas[profile] = ca.fingerprint(hashes.SHA256())
    names = [n.value for n in leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value]
    assert names == [f"{{profile}}.example.com"], (profile, names)

assert cas["default"] != cas["second"], (
    "both endpoints signed with the same CA: they are not really separate"
)

import urllib.error
import urllib.request

def get(path):
    return urllib.request.urlopen(f"{0}{{path}}").read()

assert get("/profile/default/crl") != get("/profile/second/crl"), "both endpoints served the same CRL"
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
        out.contains(r#""profile":"default""#),
        "account list does not show default profile: {}",
        out
    );
    assert!(
        out.contains(r#""profile":"second""#),
        "account list does not show second profile: {}",
        out
    );

    let (success, out, _) = lab
        .exec_in_with_output(
            &lab.proxy,
            "acme-proxy account list --profile second --json",
        )
        .await;
    assert!(success, "Failed to list accounts for second profile");
    assert!(
        !out.contains(r#""profile":"default""#),
        "account list --profile second leaked default profile: {}",
        out
    );
}
