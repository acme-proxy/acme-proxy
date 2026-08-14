use crate::common::Lab;

#[tokio::test]
#[ignore]
async fn test_allowed_ip() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "permitted"),
        ("ACME_PROXY_FILTER__RULE__PERMITTED__WHEN", "net"),
        ("ACME_PROXY_FILTER__RULE__PERMITTED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__NET__TYPE", "allowed_ip"),
        ("ACME_PROXY_FILTER__CHECK__NET__ALLOW", "CERTBOT_IP/32"),
    ])
    .await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let acmesh_script = format!(
        r#"
        curl -s -w "\nHTTP_STATUS:%{{http_code}}" {0}
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab.exec_in_with_output(&lab.acme_sh, &acmesh_script).await;
    assert!(success, "curl should not fail execution entirely");
    assert!(
        stdout.contains("HTTP_STATUS:403"),
        "Expected 403 status code, got: {}",
        stdout
    );
    assert!(
        stdout.to_lowercase().contains("unauthorized"),
        "Expected unauthorized in response, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_custom_script() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "scripted"),
        ("ACME_PROXY_FILTER__RULE__SCRIPTED__WHEN", "main"),
        ("ACME_PROXY_FILTER__RULE__SCRIPTED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__MAIN__TYPE", "custom"),
        (
            "ACME_PROXY_FILTER__CHECK__MAIN__SCRIPT_PATH",
            "/tmp/filter_script.sh",
        ),
    ])
    .await;

    let script = r#"#!/bin/sh
if [ "$ACME_FILTER_HOOK" = "identifiers" ]; then
  case "$ACME_FILTER_IDENTIFIERS" in
    *denied*)
      echo "custom script denied domain: $ACME_FILTER_IDENTIFIERS"
      exit 1
      ;;
  esac
fi
exit 0
"#;

    lab.exec_in(
        &lab.proxy,
        &format!(
            "cat > /tmp/filter_script.sh <<'FILTER_SCRIPT_EOF'\n{}\nFILTER_SCRIPT_EOF\nchmod +x /tmp/filter_script.sh",
            script
        ),
    )
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains denied.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout
            .to_lowercase()
            .contains("custom script denied domain"),
        "Expected rejection for custom filter reason, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_identifiers() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "names"),
        ("ACME_PROXY_FILTER__RULE__NAMES__WHEN", "names"),
        ("ACME_PROXY_FILTER__RULE__NAMES__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__NAMES__TYPE", "identifiers"),
        (
            "ACME_PROXY_FILTER__CHECK__NAMES__DENY_REGEX",
            "denied\\.example\\.com",
        ),
    ])
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains denied.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout.to_lowercase().contains("denied by policy"),
        "Expected rejection for rejectedIdentifier reason, got: {}",
        stdout
    );
}

#[tokio::test]
#[ignore]
async fn test_netbox() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "owned"),
        ("ACME_PROXY_FILTER__RULE__OWNED__WHEN", "inventory"),
        ("ACME_PROXY_FILTER__RULE__OWNED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__INVENTORY__TYPE", "ipam"),
        ("ACME_PROXY_IPAM__BACKEND", "netbox"),
        ("ACME_PROXY_IPAM__NETBOX__URL", "http://NETBOX_IP:8080"),
        ("ACME_PROXY_IPAM__NETBOX__TOKEN", "labtoken"),
    ])
    .await;

    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    let acmesh_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        acme.sh --register-account \
            --server {0} \
            --accountemail test@example.com
        acme.sh --issue \
            --server {0} \
            --domain machine.example.com \
            --webroot /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &acmesh_allowed_script).await;

    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains machine.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(
        success,
        "certbot script should have failed the certbot command successfully"
    );
    assert!(
        stdout.to_lowercase().contains("netbox associates"),
        "Expected rejection from NetBox, got: {}",
        stdout
    );

    let netbox_logs = lab.get_netbox_mock_logs().await;
    assert!(
        netbox_logs.contains("querying ip address"),
        "the certbot/allowed.example.com case never queried NetBox's ip-addresses \
         endpoint — got: {}",
        netbox_logs
    );
    assert!(
        netbox_logs.contains("querying device"),
        "the acme.sh/machine.example.com device-fallback case never queried NetBox's \
         devices endpoint — got: {}",
        netbox_logs
    );
}

/// The FHRP membership proof, end to end.
///
/// acme.sh's interface is recorded in group 41, which holds
/// `service.example.com`; certbot's is in no group at all. Both ask for the
/// same name, and the whole point is that only one gets it — the group is
/// reachable only through an assignment naming the client's own interface,
/// never by the name being requested.
///
/// acme.sh's device also carries a role-tagged VIP, so the `vip` source has
/// something to find in the same run.
#[tokio::test]
#[ignore]
async fn test_netbox_fhrp_group_membership() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "owned"),
        ("ACME_PROXY_FILTER__RULE__OWNED__WHEN", "inventory"),
        ("ACME_PROXY_FILTER__RULE__OWNED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__INVENTORY__TYPE", "ipam"),
        ("ACME_PROXY_IPAM__BACKEND", "netbox"),
        ("ACME_PROXY_IPAM__NETBOX__URL", "http://NETBOX_IP:8080"),
        ("ACME_PROXY_IPAM__NETBOX__TOKEN", "labtoken"),
        (
            "ACME_PROXY_IPAM__NETBOX__SOURCES",
            "dns_name,custom_field,device,vip,fhrp",
        ),
    ])
    .await;

    // A member of the group may certify the service name it answers for, and
    // the VIP on its own device besides.
    let acmesh_member_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        acme.sh --register-account \
            --server {0} \
            --accountemail test@example.com
        acme.sh --issue \
            --server {0} \
            --domain service.example.com \
            --webroot /tmp/webroot
        acme.sh --issue \
            --server {0} \
            --domain vip.example.com \
            --webroot /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &acmesh_member_script).await;

    // …and a machine on the same network whose interface is in no group may
    // not, however reachable the group's address is.
    let certbot_outsider_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains service.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_outsider_script)
        .await;
    assert!(
        success,
        "certbot should have been refused the group's service name"
    );
    assert!(
        stdout.to_lowercase().contains("netbox associates"),
        "Expected rejection from NetBox, got: {}",
        stdout
    );

    let netbox_logs = lab.get_netbox_mock_logs().await;
    assert!(
        netbox_logs.contains("querying fhrp membership"),
        "the fhrp source never asked which groups the interface belongs to — got: {}",
        netbox_logs
    );
    assert!(
        netbox_logs.contains("querying fhrp group addresses"),
        "membership was never resolved to the group's addresses — got: {}",
        netbox_logs
    );
    assert!(
        netbox_logs.contains("querying service addresses on device"),
        "the vip source never queried role-tagged addresses — got: {}",
        netbox_logs
    );
}

/// The mirror of `test_netbox`, against a different product: same filter, same
/// assertions, a different inventory speaking a different protocol.
#[tokio::test]
#[ignore]
async fn test_phpipam() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "owned"),
        ("ACME_PROXY_FILTER__RULE__OWNED__WHEN", "inventory"),
        ("ACME_PROXY_FILTER__RULE__OWNED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__INVENTORY__TYPE", "ipam"),
        ("ACME_PROXY_IPAM__BACKEND", "phpipam"),
        ("ACME_PROXY_IPAM__PHPIPAM__URL", "http://PHPIPAM_IP:8080"),
        ("ACME_PROXY_IPAM__PHPIPAM__TOKEN", "labtoken"),
    ])
    .await;

    // certbot's name is on the address's own custom column.
    let certbot_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains allowed.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_allowed_script).await;

    // acme.sh's column is empty, so its name comes from the device fallback.
    let acmesh_allowed_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        acme.sh --register-account \
            --server {0} \
            --accountemail test@example.com
        acme.sh --issue \
            --server {0} \
            --domain machine.example.com \
            --webroot /tmp/webroot
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.acme_sh, &acmesh_allowed_script).await;

    // The refusal names phpIPAM, not NetBox — the message interpolates the
    // backend, and nothing in the filter is vendor-specific.
    let certbot_denied_script = format!(
        r#"
        set +e
        mkdir -p /tmp/webroot
        certbot certonly \
            --domains machine.example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab
        .exec_in_with_output(&lab.certbot, &certbot_denied_script)
        .await;
    assert!(success, "certbot should have been refused acme.sh's name");
    assert!(
        stdout.to_lowercase().contains("phpipam associates"),
        "Expected rejection from phpIPAM, got: {}",
        stdout
    );

    let phpipam_logs = lab.get_phpipam_mock_logs().await;
    assert!(
        phpipam_logs.contains("querying ip address"),
        "the certbot/allowed.example.com case never queried phpIPAM's search \
         endpoint — got: {}",
        phpipam_logs
    );
    assert!(
        phpipam_logs.contains("querying device"),
        "the acme.sh/machine.example.com device-fallback case never queried phpIPAM's \
         devices endpoint — got: {}",
        phpipam_logs
    );
}

/// phpIPAM's one genuinely different wire behaviour, through the whole stack:
/// an address it has never heard of answers `404`, which must **deny** the
/// order rather than 500 it.
///
/// lego is the client because it is the one container the phpIPAM mock holds no
/// row for, and lego needs an HTTPS directory (it refuses a plain-HTTP ACME
/// server outright), which is why this is its own TLS-enabled lab rather than a
/// fourth step of `test_phpipam` — the same shape `key_change.rs` and
/// `tls_alpn_01.rs` already use for lego.
#[tokio::test]
#[ignore]
async fn test_phpipam_unknown_address() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_SERVER__TLS__ENABLED", "true"),
        ("ACME_PROXY_FILTER__RULES", "owned"),
        ("ACME_PROXY_FILTER__RULE__OWNED__WHEN", "inventory"),
        ("ACME_PROXY_FILTER__RULE__OWNED__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__INVENTORY__TYPE", "ipam"),
        ("ACME_PROXY_IPAM__BACKEND", "phpipam"),
        ("ACME_PROXY_IPAM__PHPIPAM__URL", "http://PHPIPAM_IP:8080"),
        ("ACME_PROXY_IPAM__PHPIPAM__TOKEN", "labtoken"),
    ])
    .await;

    let lego_unknown_script = format!(
        r#"
        set +e
        lego run --accept-tos --email test@example.com \
            --server {0} \
            --tls-skip-verify \
            --path /tmp/lego \
            --domains allowed.example.com \
            --http --http.address :0 2>&1
        if [ $? -eq 0 ]; then
            exit 1
        fi
    "#,
        lab.proxy_url
    );

    let (success, stdout, stderr) = lab
        .exec_in_with_output(&lab.lego, &lego_unknown_script)
        .await;
    assert!(
        success,
        "lego's address is absent from phpIPAM and should have been refused"
    );
    // lego reports an ACME problem on stderr, and the script folds it into
    // stdout with `2>&1` — check both rather than depend on which side of that
    // the runtime happens to deliver.
    let output = format!("{stdout}\n{stderr}").to_lowercase();
    assert!(
        output.contains("holds no record"),
        "Expected a 404 to read as \"no such address\", got: {stdout}\n{stderr}"
    );

    let phpipam_logs = lab.get_phpipam_mock_logs().await;
    assert!(
        phpipam_logs.contains("querying ip address"),
        "phpIPAM was never asked about lego's address — got: {}",
        phpipam_logs
    );
}

#[tokio::test]
#[ignore]
async fn test_reverse_dns() {
    let lab = Lab::new(vec![
        ("ACME_PROXY_FILTER__RULES", "has-ptr"),
        ("ACME_PROXY_FILTER__RULE__HAS-PTR__WHEN", "ptr"),
        ("ACME_PROXY_FILTER__RULE__HAS-PTR__THEN", "allow"),
        ("ACME_PROXY_FILTER__CHECK__PTR__TYPE", "reverse_dns"),
        ("ACME_PROXY_DNS__RESOLVER", "dns:53"),
    ])
    .await;

    let certbot_ip = Lab::get_ip(lab.certbot.id(), &lab.network).await;
    lab.dns_add_ptr(&certbot_ip, "trusted-client.lab.").await;
    lab.dns_add_a("trusted-client.lab.", &certbot_ip).await;

    let certbot_script = format!(
        r#"
        set -e
        certbot register \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --agree-tos --register-unsafely-without-email --non-interactive
    "#,
        lab.proxy_url
    );

    lab.exec_in(&lab.certbot, &certbot_script).await;

    let acmesh_script = format!(
        r#"
        curl -s -w "\nHTTP_STATUS:%{{http_code}}" {0}
    "#,
        lab.proxy_url
    );

    let (success, stdout, _stderr) = lab.exec_in_with_output(&lab.acme_sh, &acmesh_script).await;
    assert!(success, "curl should not fail execution entirely");
    assert!(
        stdout.contains("HTTP_STATUS:403"),
        "Expected 403 status code, got: {}",
        stdout
    );
    assert!(
        stdout.to_lowercase().contains("unauthorized"),
        "Expected unauthorized in response, got: {}",
        stdout
    );
}
