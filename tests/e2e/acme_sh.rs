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
