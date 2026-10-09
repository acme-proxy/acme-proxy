//! Single sign-on for the web admin against real identity providers: OpenLDAP
//! (`openldap-e2e`) for the LDAP realms, and Dex -- using that same directory as
//! its upstream -- for OpenID Connect.
//!
//! What only this proves, and the in-process suites (`tests/admin_oidc.rs`,
//! `tests/admin_ldap.rs`) cannot: a real provider's discovery document, key set
//! and token endpoint; a real `slapd`'s StartTLS and `ldaps`, under a
//! certificate only `ca_cert_path` makes trustworthy; and the browser half of
//! the redirect dance, cookie jar and all, driven by `curl` on the lab network
//! so every host resolves the same way for the server and for the "browser".
//!
//! The lab is its own here rather than `Lab`: it needs none of the ACME
//! clients, and needs the admin listener on TLS (a non-loopback bind requires
//! it) and a configuration *file*, since an LDAP group's DN holds commas and a
//! list from the environment is split on them.

use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};
use tokio::process::Command;

use crate::common::{container_runtime, ensure_images_built};

const CLIENT_SECRET: &str = "e2e-client-secret";

struct SsoLab {
    network: String,
    ldap: ContainerAsync<GenericImage>,
    _dex: ContainerAsync<GenericImage>,
    proxy: ContainerAsync<GenericImage>,
    browser: ContainerAsync<GenericImage>,
    dex_host: String,
    proxy_host: String,
}

impl Drop for SsoLab {
    fn drop(&mut self) {
        let _ = std::process::Command::new(container_runtime())
            .args(["network", "rm", "-f", &self.network])
            .status();
    }
}

/// A lab CA, and one server certificate for the directory and Dex.
fn certificates(hosts: &[&str]) -> (String, String, String) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "acme-proxy e2e lab CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let server_key = rcgen::KeyPair::generate().unwrap();
    let names: Vec<String> = hosts.iter().map(ToString::to_string).collect();
    let server = rcgen::CertificateParams::new(names)
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();
    (ca.pem(), server.pem(), server_key.serialize_pem())
}

fn proxy_config(lab_hosts: (&str, &str, &str)) -> String {
    let (proxy, ldap, dex) = lab_hosts;
    format!(
        r#"
[server]
bind_address = "[::]:3000"
base_url = "http://{proxy}:3000"

[challenge]
bypass = true

[profiles.default]
enabled = true

[admin]
enabled = true
bind_address = "[::]:3001"
base_url = "https://{proxy}:3001"

[admin.tls]
enabled = true
cert_path = "/tmp/admin.pem"
key_path = "/tmp/admin.key"

[admin.auth.oidc.dex]
display_name = "Dex"
issuer = "https://{dex}:5556/dex"
client_id = "acme-proxy"
client_secret = "{CLIENT_SECRET}"
scopes = ["openid", "profile", "email", "groups"]
ca_cert_path = "/tmp/lab-ca.pem"

[admin.auth.oidc.dex.roles]
admin = ["acme-admins"]
viewer = ["staff"]

[admin.auth.ldap.corp]
url = "ldap://{ldap}:389"
start_tls = true
ca_cert_path = "/tmp/lab-ca.pem"
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "admin-password"
user_base_dn = "ou=people,dc=example,dc=com"
group_search_base = "ou=groups,dc=example,dc=com"

[admin.auth.ldap.corp.roles]
admin = ["cn=acme-admins,ou=groups,dc=example,dc=com"]
viewer = ["cn=staff,ou=groups,dc=example,dc=com"]

[admin.auth.ldap.corps]
url = "ldaps://{ldap}:636"
ca_cert_path = "/tmp/lab-ca.pem"
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "admin-password"
user_base_dn = "ou=people,dc=example,dc=com"
group_search_base = "ou=groups,dc=example,dc=com"

[admin.auth.ldap.corps.roles]
admin = ["cn=acme-admins,ou=groups,dc=example,dc=com"]
viewer = ["cn=staff,ou=groups,dc=example,dc=com"]

# The same directory, and no `ca_cert_path`: its certificate is a stranger's.
[admin.auth.ldap.untrusted]
url = "ldaps://{ldap}:636"
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "admin-password"
user_base_dn = "ou=people,dc=example,dc=com"
group_search_base = "ou=groups,dc=example,dc=com"

[admin.auth.ldap.untrusted.roles]
viewer = ["cn=staff,ou=groups,dc=example,dc=com"]
"#
    )
}

fn dex_config(lab_hosts: (&str, &str, &str)) -> String {
    let (proxy, ldap, dex) = lab_hosts;
    format!(
        r#"
issuer: https://{dex}:5556/dex
storage:
  type: memory
web:
  https: 0.0.0.0:5556
  tlsCert: /etc/dex/server.pem
  tlsKey: /etc/dex/server.key
oauth2:
  skipApprovalScreen: true
staticClients:
  - id: acme-proxy
    secret: {CLIENT_SECRET}
    name: acme-proxy
    redirectURIs:
      - https://{proxy}:3001/ui/login/oidc/dex/callback
connectors:
  - type: ldap
    id: ldap
    name: LDAP
    config:
      host: {ldap}:636
      rootCA: /etc/dex/ca.pem
      bindDN: cn=admin,dc=example,dc=com
      bindPW: admin-password
      userSearch:
        baseDN: ou=people,dc=example,dc=com
        filter: "(objectClass=inetOrgPerson)"
        username: uid
        idAttr: uid
        emailAttr: mail
        nameAttr: cn
        preferredUsernameAttr: uid
      groupSearch:
        baseDN: ou=groups,dc=example,dc=com
        filter: "(objectClass=groupOfNames)"
        userMatchers:
          - userAttr: DN
            groupAttr: member
        nameAttr: cn
"#
    )
}

impl SsoLab {
    async fn new() -> Self {
        tokio::task::spawn_blocking(ensure_images_built)
            .await
            .expect("image build task panicked");

        let uuid = uuid::Uuid::now_v7();
        let network = format!("e2e-sso-{uuid}");
        let status = Command::new(container_runtime())
            .args(["network", "create", &network])
            .status()
            .await
            .unwrap();
        assert!(status.success(), "Failed to create network");

        let ldap_host = format!("ldap-{uuid}");
        let dex_host = format!("dex-{uuid}");
        let proxy_host = format!("proxy-{uuid}");
        let browser_host = format!("browser-{uuid}");
        let hosts = (proxy_host.as_str(), ldap_host.as_str(), dex_host.as_str());
        let (ca, server_cert, server_key) = certificates(&[&ldap_host, &dex_host]);

        let ldap = GenericImage::new("openldap-e2e", "latest")
            .with_wait_for(WaitFor::message_on_stderr("slapd starting"))
            .with_network(&network)
            .with_container_name(&ldap_host)
            .with_copy_to(
                CopyTargetOptions::new("/certs/ca.pem"),
                ca.clone().into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/certs/server.pem"),
                server_cert.clone().into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/certs/server.key").with_mode(0o600),
                server_key.clone().into_bytes(),
            );
        let browser = GenericImage::new("acmesh-e2e", "latest")
            .with_entrypoint("sh")
            .with_cmd(vec!["-c", "trap 'exit 0' TERM; sleep infinity & wait"])
            .with_network(&network)
            .with_container_name(&browser_host);
        let (ldap, browser) = tokio::join!(ldap.start(), browser.start());
        let ldap = ldap.expect("Failed to start OpenLDAP");
        let browser = browser.expect("Failed to start the browser");

        let dex = GenericImage::new("dex-e2e", "latest")
            .with_wait_for(WaitFor::message_on_stderr("listening on"))
            .with_cmd(vec!["serve", "/etc/dex/lab.yaml"])
            .with_network(&network)
            .with_container_name(&dex_host)
            .with_copy_to(
                CopyTargetOptions::new("/etc/dex/lab.yaml"),
                dex_config(hosts).into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/etc/dex/ca.pem"),
                ca.clone().into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/etc/dex/server.pem"),
                server_cert.into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/etc/dex/server.key").with_mode(0o644),
                server_key.into_bytes(),
            );
        let proxy = GenericImage::new("acme-proxy-e2e", "latest")
            .with_wait_for(WaitFor::message_on_stdout("server_startup"))
            .with_network(&network)
            .with_container_name(&proxy_host)
            .with_env_var("ACME_PROXY_CONFIG", "/tmp/config.toml")
            .with_env_var("RUST_LOG", "acme_proxy=debug")
            .with_copy_to(
                CopyTargetOptions::new("/tmp/config.toml").with_mode(0o644),
                proxy_config(hosts).into_bytes(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/tmp/lab-ca.pem").with_mode(0o644),
                ca.into_bytes(),
            );
        let (dex, proxy) = tokio::join!(dex.start(), proxy.start());
        let dex = dex.expect("Failed to start Dex");
        let proxy = proxy.expect("Failed to start acme-proxy");

        Self {
            network,
            ldap,
            _dex: dex,
            proxy,
            browser,
            dex_host,
            proxy_host,
        }
    }

    async fn exec(&self, container: &ContainerAsync<GenericImage>, script: &str) -> (bool, String) {
        let output = Command::new(container_runtime())
            .args(["exec", container.id(), "sh", "-c", script])
            .output()
            .await
            .expect("Failed to execute command in container");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    }

    /// A whole OpenID Connect sign-in, in a fresh cookie jar, answering what
    /// `GET /api/session` says afterwards: the session's JSON, or an error body.
    async fn oidc_sign_in(&self, user: &str) -> String {
        let script = format!(
            r#"
            set -e
            J=/tmp/jar-$$; rm -f "$J"
            P=https://{proxy}:3001
            AUTH=$(curl -sk -c "$J" -b "$J" -o /dev/null -w '%{{redirect_url}}' "$P/ui/login/oidc/dex")
            PAGE=$(curl -sk -c "$J" -b "$J" -L "$AUTH")
            ACTION=$(printf '%s\n' "$PAGE" | sed -n 's/.*<form method="post" action="\([^"]*\)".*/\1/p' | head -1 | sed 's/&amp;/\&/g')
            [ -n "$ACTION" ] || {{ echo "no login form at $AUTH"; printf '%s' "$PAGE"; exit 1; }}
            curl -sk -c "$J" -b "$J" -L -o /dev/null \
                --data-urlencode "login={user}" --data-urlencode "password={user}-password" \
                "https://{dex}:5556$ACTION"
            curl -sk -c "$J" -b "$J" "$P/api/session"
            "#,
            proxy = self.proxy_host,
            dex = self.dex_host,
        );
        let (ok, output) = self.exec(&self.browser, &script).await;
        assert!(ok, "the browser's script failed: {output}");
        output
    }

    /// `POST /api/session` into an LDAP realm, answering the status and body.
    async fn ldap_sign_in(&self, realm: &str, user: &str) -> (String, String) {
        let script = format!(
            r#"curl -sk -o /tmp/body -w '%{{http_code}}' -H 'content-type: application/json' \
                -d '{{"username":"{user}","password":"{user}-password","provider":"{realm}"}}' \
                https://{proxy}:3001/api/session; echo; cat /tmp/body"#,
            proxy = self.proxy_host,
        );
        let (ok, output) = self.exec(&self.browser, &script).await;
        assert!(ok, "curl failed: {output}");
        let (status, body) = output.split_once('\n').unwrap_or((&output, ""));
        (status.trim().to_string(), body.to_string())
    }

    async fn proxy_logs(&self) -> String {
        let output = Command::new(container_runtime())
            .args(["logs", self.proxy.id()])
            .output()
            .await
            .unwrap();
        String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr)
    }
}

#[tokio::test]
#[ignore]
async fn oidc_login_provisions_and_maps_roles() {
    let lab = SsoLab::new().await;

    let alice = lab.oidc_sign_in("alice").await;
    assert!(
        alice.contains(r#""authProvider":"oidc:dex""#) && alice.contains(r#""role":"admin""#),
        "alice signs in as a provisioned admin: {alice}\n{}",
        lab.proxy_logs().await
    );

    let carol = lab.oidc_sign_in("carol").await;
    assert!(carol.contains(r#""role":"viewer""#), "{carol}");

    let dave = lab.oidc_sign_in("dave").await;
    assert!(
        dave.contains("session_"),
        "dave is in no mapped group and gets no session: {dave}"
    );
    assert!(lab.proxy_logs().await.contains("no_matching_group"));
}

#[tokio::test]
#[ignore]
async fn oidc_role_resyncs_on_next_login() {
    let lab = SsoLab::new().await;
    // alice holds `admin`, so demoting bob is not the last-admin case.
    lab.oidc_sign_in("alice").await;
    assert!(lab.oidc_sign_in("bob").await.contains(r#""role":"admin""#));

    let (ok, output) = lab
        .exec(
            &lab.ldap,
            r#"ldapmodify -x -H ldap://localhost -D cn=admin,dc=example,dc=com -w admin-password <<'LDIF'
dn: cn=acme-admins,ou=groups,dc=example,dc=com
changetype: modify
delete: member
member: uid=bob,ou=people,dc=example,dc=com

dn: cn=staff,ou=groups,dc=example,dc=com
changetype: modify
add: member
member: uid=bob,ou=people,dc=example,dc=com
LDIF"#,
        )
        .await;
    assert!(ok, "ldapmodify: {output}");

    let bob = lab.oidc_sign_in("bob").await;
    assert!(
        bob.contains(r#""role":"viewer""#),
        "bob follows his groups: {bob}"
    );
}

#[tokio::test]
#[ignore]
async fn ldap_starttls_and_ldaps_logins_map_groups() {
    let lab = SsoLab::new().await;
    // One person per realm: the same uid through a second realm is another
    // provider's claim on a taken name, which is refused rather than linked.
    for (realm, user) in [("corp", "alice"), ("corps", "bob")] {
        let (status, body) = lab.ldap_sign_in(realm, user).await;
        assert_eq!(status, "200", "{realm}: {body}\n{}", lab.proxy_logs().await);
        assert!(body.contains(r#""role":"admin""#), "{realm}: {body}");
        assert!(
            body.contains(&format!(r#""authProvider":"ldap:{realm}""#)),
            "{body}"
        );
    }
    let (status, _) = lab.ldap_sign_in("corps", "alice").await;
    assert_eq!(status, "401", "alice is ldap:corp's");
    assert!(lab.proxy_logs().await.contains("username_taken"));

    let (status, _) = lab.ldap_sign_in("corp", "dave").await;
    assert_eq!(status, "401");
}

#[tokio::test]
#[ignore]
async fn ldap_untrusted_certificate_is_refused() {
    let lab = SsoLab::new().await;
    let (status, body) = lab.ldap_sign_in("untrusted", "carol").await;
    assert_eq!(status, "503", "{body}");
    assert!(body.contains("provider_unavailable"), "{body}");
}

#[tokio::test]
#[ignore]
async fn admin_cli_shows_external_source() {
    let lab = SsoLab::new().await;
    lab.ldap_sign_in("corp", "carol").await;
    let (ok, output) = lab
        .exec(&lab.proxy, "acme-proxy admin user list --json")
        .await;
    assert!(ok, "{output}");
    assert!(output.contains(r#""authProvider":"ldap:corp""#), "{output}");
}
