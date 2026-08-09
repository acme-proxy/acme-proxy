use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_tls_alpn_01_order() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_CHALLENGE__ENABLED", "tls-alpn-01"),
        ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
        ("ACME_PROXY_DNS__RESOLVER", "dns:53"),
        ("ACME_PROXY_SERVER__TLS__ENABLED", "true"),
    ])
    .await;

    let lego_ip = Lab::get_ip(lab.lego.id(), &lab.network).await;
    lab.dns_add_a("tlsalpn.lab", &lego_ip).await;

    let lego_script = format!(
        r#"
        set -e
        lego run --accept-tos --email test@example.com \
            --server {0} \
            --tls-skip-verify \
            --path /tmp/lego \
            --domains tlsalpn.lab \
            --tls
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.lego, &lego_script).await;
}
