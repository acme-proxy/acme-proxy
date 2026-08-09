use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_eab_register() {
    let lab = Lab::new(vec![("ACME_PROXY_EAB__ENABLED", "true")]).await;

    let (_success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.proxy, "acme-proxy eab create --label e2e-lab --json")
        .await;

    // Find the JSON part in stdout
    let json_str = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("Failed to find JSON output");
    let eab_json: serde_json::Value =
        serde_json::from_str(json_str).expect("Failed to parse EAB JSON");

    let kid = eab_json["kid"].as_str().expect("kid missing");
    let hmac = eab_json["hmacKey"].as_str().expect("hmacKey missing");

    let certbot_no_eab_script = format!(
        r#"
        set +e
        certbot register \
            --server {0} \
            --config-dir /tmp/no-eab/config --work-dir /tmp/no-eab/work --logs-dir /tmp/no-eab/logs \
            --agree-tos --register-unsafely-without-email --non-interactive 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, no_eab_out, _) = lab
        .exec_in_with_output(&lab.certbot, &certbot_no_eab_script)
        .await;
    assert!(
        success,
        "Registration without EAB should have failed but script returned error"
    );
    assert!(
        no_eab_out
            .to_lowercase()
            .contains("externalaccountrequired")
            || no_eab_out
                .to_lowercase()
                .contains("external account binding"),
        "Registration was refused, but not for the expected reason: {}",
        no_eab_out
    );

    let certbot_eab_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --eab-kid '{1}' --eab-hmac-key '{2}' \
            --agree-tos --register-unsafely-without-email --non-interactive
    "#,
        lab.proxy_url, kid, hmac
    );

    lab.exec_in(&lab.certbot, &certbot_eab_script).await;

    let acmesh_script = format!(
        r#"
        set -e
        acme.sh --register-account \
            --server {0} \
            --email test@example.com \
            --home /tmp/acme-sh \
            --eab-kid '{1}' --eab-hmac-key '{2}'
    "#,
        lab.proxy_url, kid, hmac
    );

    lab.exec_in(&lab.acme_sh, &acmesh_script).await;
}
