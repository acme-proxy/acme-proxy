//! Signing in to the web admin through an LDAP directory, end to end through
//! the real `build_admin_app` and the real `ldap3` client, against a directory
//! on loopback.
//!
//! The directory ([`FakeDirectory`]) speaks just enough LDAPv3 (RFC 4511) to
//! answer what the provider sends -- simple binds, equality searches, unbind --
//! in hand-written BER, and records every bind, so a test can assert what was
//! (and was **not**) sent. It serves plain `ldap://` (loopback is the one place
//! that is allowed) and `ldaps://` under a certificate the test generates.
//!
//! What is proved here and not inline: the exchange's order (service bind,
//! search, then the person's bind), the realm selector on both front ends, an
//! LDAP operator owing the local second factor, the directory as the step-up
//! credential, and that a TLS connection uses the server's own `ring` config --
//! no process-wide crypto provider appears.

mod common;

use std::sync::{Arc, Mutex};

use acme_proxy_core::config::{LdapProviderConfig, RoleMapConfig};
use acme_proxy_store::admin_user::{AdminRole, AdminUser};
use axum::Router;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BASE: &str = "ou=people,dc=example";
const SERVICE_DN: &str = "cn=svc,dc=example";
const SERVICE_PASSWORD: &str = "service-password";
const ADMINS: &str = "cn=acme-admins,ou=groups,dc=example";
const STAFF: &str = "cn=staff,ou=groups,dc=example";

// ---------------------------------------------------------------------------
// BER, as much as this needs
// ---------------------------------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let significant: Vec<u8> = bytes
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | significant.len() as u8);
        out.extend(significant);
    }
    out.extend_from_slice(content);
    out
}

fn octets(value: &str) -> Vec<u8> {
    tlv(0x04, value.as_bytes())
}

fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    tlv(0x02, &bytes[start..])
}

/// One TLV off the front of `input`: tag, content, rest.
fn split(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, byte| acc << 8 | usize::from(*byte));
        (length, &rest[count..])
    };
    Some((tag, &rest[..length], &rest[length..]))
}

fn text(content: &[u8]) -> String {
    String::from_utf8_lossy(content).to_string()
}

/// `LDAPResult` with `code` under `tag`, for message `id`.
fn result(id: i64, tag: u8, code: u8) -> Vec<u8> {
    let body = [tlv(0x0a, &[code]), octets(""), octets("")].concat();
    tlv(0x30, &[integer(id), tlv(tag, &body)].concat())
}

fn entry(id: i64, dn: &str, attributes: &[(&str, Vec<&str>)]) -> Vec<u8> {
    let attributes: Vec<u8> = attributes
        .iter()
        .flat_map(|(name, values)| {
            let values: Vec<u8> = values.iter().flat_map(|value| octets(value)).collect();
            tlv(0x30, &[octets(name), tlv(0x31, &values)].concat())
        })
        .collect();
    let body = [octets(dn), tlv(0x30, &attributes)].concat();
    tlv(0x30, &[integer(id), tlv(0x64, &body)].concat())
}

// ---------------------------------------------------------------------------
// The directory
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Person {
    dn: String,
    uid: String,
    password: String,
    uuid: String,
    groups: Vec<String>,
}

#[derive(Default)]
struct Log {
    connections: usize,
    binds: Vec<String>,
}

#[derive(Clone)]
struct FakeDirectory {
    people: Arc<Mutex<Vec<Person>>>,
    log: Arc<Mutex<Log>>,
    url: String,
}

impl FakeDirectory {
    fn people() -> Vec<Person> {
        let person = |uid: &str, groups: &[&str]| Person {
            dn: format!("uid={uid},{BASE}"),
            uid: uid.to_string(),
            password: format!("{uid}-password"),
            uuid: format!("uuid-{uid}"),
            groups: groups.iter().map(ToString::to_string).collect(),
        };
        vec![
            person("bob", &[STAFF]),
            person("boss", &[ADMINS, STAFF]),
            person("nogroup", &[]),
        ]
    }

    /// Plain `ldap://`, on loopback.
    async fn start() -> Self {
        Self::serve(None).await
    }

    /// `ldaps://`, under `acceptor`'s certificate.
    async fn start_tls(acceptor: tokio_rustls::TlsAcceptor) -> Self {
        Self::serve(Some(acceptor)).await
    }

    async fn serve(acceptor: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let scheme = if acceptor.is_some() { "ldaps" } else { "ldap" };
        let directory = Self {
            people: Arc::new(Mutex::new(Self::people())),
            log: Arc::new(Mutex::new(Log::default())),
            url: format!("{scheme}://{}", listener.local_addr().unwrap()),
        };
        let server = directory.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                server.log.lock().unwrap().connections += 1;
                let server = server.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                server.session(stream).await;
                            }
                        }
                        None => server.session(stream).await,
                    }
                });
            }
        });
        directory
    }

    async fn session(&self, mut stream: impl AsyncRead + AsyncWrite + Unpin) {
        loop {
            let Some(message) = read_message(&mut stream).await else {
                return;
            };
            let Some((0x30, body, _)) = split(&message) else {
                return;
            };
            let Some((0x02, id, rest)) = split(body) else {
                return;
            };
            let id = id
                .iter()
                .fold(0i64, |acc, byte| acc << 8 | i64::from(*byte));
            let Some((op, content, _)) = split(rest) else {
                return;
            };
            let reply = match op {
                // BindRequest: version, name, [0] simple password.
                0x60 => {
                    let (_, _, rest) = split(content).unwrap();
                    let (_, name, rest) = split(rest).unwrap();
                    let (_, password, _) = split(rest).unwrap();
                    let (name, password) = (text(name), text(password));
                    self.log.lock().unwrap().binds.push(name.clone());
                    let ok = (name == SERVICE_DN && password == SERVICE_PASSWORD)
                        || self
                            .people
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|person| person.dn == name && person.password == password);
                    result(id, 0x61, if ok { 0 } else { 49 })
                }
                // SearchRequest: base, scope, deref, size, time, typesOnly,
                // filter (equalityMatch only), attributes.
                0x63 => {
                    let (_, base, mut rest) = split(content).unwrap();
                    for _ in 0..5 {
                        rest = split(rest).unwrap().2;
                    }
                    let (filter_tag, filter, _) = split(rest).unwrap();
                    let mut reply = Vec::new();
                    if filter_tag == 0xa3 {
                        let (_, attribute, rest) = split(filter).unwrap();
                        let (_, value, _) = split(rest).unwrap();
                        reply = self.search(id, &text(base), &text(attribute), &text(value));
                    }
                    reply.extend(result(id, 0x65, 0));
                    reply
                }
                // UnbindRequest.
                0x42 => return,
                _ => result(id, 0x78, 2),
            };
            if stream.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    fn search(&self, id: i64, base: &str, attribute: &str, value: &str) -> Vec<u8> {
        let people = self.people.lock().unwrap();
        if attribute.eq_ignore_ascii_case("uid") && base == BASE {
            people
                .iter()
                .filter(|person| person.uid.eq_ignore_ascii_case(value))
                .flat_map(|person| {
                    entry(
                        id,
                        &person.dn,
                        &[
                            ("uid", vec![person.uid.as_str()]),
                            ("entryUUID", vec![person.uuid.as_str()]),
                            (
                                "memberOf",
                                person.groups.iter().map(String::as_str).collect(),
                            ),
                        ],
                    )
                })
                .collect()
        } else if attribute.eq_ignore_ascii_case("member") {
            let Some(person) = people.iter().find(|person| person.dn == value) else {
                return Vec::new();
            };
            person
                .groups
                .iter()
                .flat_map(|group| entry(id, group, &[]))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn config(&self) -> LdapProviderConfig {
        LdapProviderConfig {
            display_name: "Corporate directory".to_string(),
            url: self.url.clone(),
            bind_dn: SERVICE_DN.to_string(),
            bind_password: SERVICE_PASSWORD.to_string(),
            user_base_dn: BASE.to_string(),
            roles: RoleMapConfig {
                admin: vec![ADMINS.to_uppercase()],
                operator: Vec::new(),
                viewer: vec![STAFF.to_string()],
            },
            ..LdapProviderConfig::default()
        }
    }

    fn binds(&self) -> Vec<String> {
        self.log.lock().unwrap().binds.clone()
    }
}

async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.ok()?;
    let mut message = head.to_vec();
    let length = if head[1] & 0x80 == 0 {
        usize::from(head[1])
    } else {
        let mut bytes = vec![0u8; usize::from(head[1] & 0x7f)];
        stream.read_exact(&mut bytes).await.ok()?;
        message.extend(&bytes);
        bytes
            .iter()
            .fold(0usize, |acc, byte| acc << 8 | usize::from(*byte))
    };
    let mut content = vec![0u8; length];
    stream.read_exact(&mut content).await.ok()?;
    message.extend(content);
    Some(message)
}

// ---------------------------------------------------------------------------
// The panel
// ---------------------------------------------------------------------------

async fn app_with(
    directory: &FakeDirectory,
    edit: impl FnOnce(&mut acme_proxy_core::config::Config, &mut LdapProviderConfig),
) -> (Router, Arc<acme_proxy_store::db::Database>) {
    let mut config = admin_config();
    let mut provider = directory.config();
    edit(&mut config, &mut provider);
    config.admin.auth.ldap.insert("corp".to_string(), provider);
    test_admin_app(config).await
}

async fn sign_in(app: &Router, username: &str, password: &str) -> axum::response::Response {
    admin_request(
        app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({"username": username, "password": password, "provider": "corp"})),
    )
    .await
}

#[tokio::test]
async fn a_directory_sign_in_provisions_at_the_groups_role() {
    let directory = FakeDirectory::start().await;
    let (app, database) = app_with(&directory, |_, _| {}).await;

    let response = sign_in(&app, "Boss", "boss-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["user"]["username"], "boss");
    assert_eq!(body["user"]["role"], "admin", "matched case-insensitively");
    assert_eq!(body["user"]["authProvider"], "ldap:corp");

    let boss = AdminUser::find_by_username("boss", &database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(boss.external_id.as_deref(), Some("uuid-boss"));
    // The order that matters: the service account first, the person last.
    assert_eq!(
        directory.binds(),
        vec![SERVICE_DN.to_string(), format!("uid=boss,{BASE}")]
    );
}

/// The same realm through the form, which carries it as the selector's value.
#[tokio::test]
async fn the_sign_in_page_offers_the_directory_as_a_realm() {
    let directory = FakeDirectory::start().await;
    let (app, _database) = app_with(&directory, |_, _| {}).await;

    let page = html_body(admin_page(&app, "/ui/login", None, false).await).await;
    assert!(
        page.contains(r#"<select id="provider" name="provider">"#),
        "{page}"
    );
    assert!(page.contains(r#"<option value="corp""#));
    assert!(page.contains("Corporate directory"));

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[
            ("provider", "corp"),
            ("username", "bob"),
            ("password", "bob-password"),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // A refusal re-renders with the realm still selected.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[
            ("provider", "corp"),
            ("username", "bob"),
            ("password", "wrong"),
        ]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(
        html_body(refused)
            .await
            .contains(r#"<option value="corp" selected>"#)
    );
}

#[tokio::test]
async fn every_refusal_answers_alike() {
    let directory = FakeDirectory::start().await;
    let (app, database) = app_with(&directory, |_, _| {}).await;
    // A second entry answering to one name: a filter that does not identify
    // people is refused, not guessed between.
    directory.people.lock().unwrap().push(Person {
        dn: format!("uid=bob,ou=other,{BASE}"),
        ..FakeDirectory::people()[0].clone()
    });

    for (username, password) in [
        ("boss", "wrong"),
        ("nobody", "anything"),
        ("bob", "bob-password"),
        ("nogroup", "nogroup-password"),
    ] {
        let response = sign_in(&app, username, password).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{username}");
        assert_eq!(json_body(response).await["error"], "invalid_credentials");
    }
    assert!(
        AdminUser::find_by_username("nogroup", &database)
            .await
            .unwrap()
            .is_none()
    );

    // A password for the directory is never tried locally, and a realm that
    // is not configured is refused like a wrong password.
    AdminUser::create("local", "unused", None, &database)
        .await
        .unwrap();
    let elsewhere = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({"username": "boss", "password": "boss-password", "provider": "elsewhere"})),
    )
    .await;
    assert_eq!(elsewhere.status(), StatusCode::UNAUTHORIZED);
}

/// An empty password would be an unauthenticated bind, which many directories
/// accept: it never leaves this server.
#[tokio::test]
async fn an_empty_password_never_reaches_the_directory() {
    let directory = FakeDirectory::start().await;
    let (app, _database) = app_with(&directory, |_, _| {}).await;

    assert_eq!(
        sign_in(&app, "bob", "").await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(directory.log.lock().unwrap().connections, 0);
}

#[tokio::test]
async fn an_unreachable_directory_is_unavailable() {
    let directory = FakeDirectory::start().await;
    let (app, _database) = app_with(&directory, |_, provider| {
        provider.url = "ldap://127.0.0.1:9".to_string();
    })
    .await;
    let response = sign_in(&app, "bob", "bob-password").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(response).await["error"], "provider_unavailable");
}

/// Groups from a search under `group_search_base` rather than `memberOf`.
#[tokio::test]
async fn groups_can_come_from_a_group_search() {
    let directory = FakeDirectory::start().await;
    let (app, _database) = app_with(&directory, |_, provider| {
        provider.group_attribute = "absent".to_string();
        provider.group_search_base = "ou=groups,dc=example".to_string();
    })
    .await;
    let response = sign_in(&app, "boss", "boss-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["user"]["role"], "admin");
}

/// A directory password is a password: `require_mfa` holds an LDAP operator
/// at enrolment like a local one.
#[tokio::test]
async fn a_directory_operator_owes_the_local_second_factor() {
    let directory = FakeDirectory::start().await;
    let (app, _database) = app_with(&directory, |config, _| config.admin.require_mfa = true).await;
    let response = sign_in(&app, "bob", "bob-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["mfaRequired"], true);
    assert_eq!(body["step"], "enrol");
}

/// The directory is the step-up credential of a directory operator: their
/// directory password, re-checked by a bind as them.
#[tokio::test]
async fn the_directory_password_is_the_step_up() {
    let directory = FakeDirectory::start().await;
    let (app, database) = app_with(&directory, |_, _| {}).await;
    let response = sign_in(&app, "boss", "boss-password").await;
    let cookie = session_cookie_token(&response).unwrap();
    let csrf = json_body(response).await["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    let boss = AdminSessionHandle { cookie, csrf };
    AdminUser::create("dave", "unused", Some(AdminRole::Viewer), &database)
        .await
        .unwrap();

    let wrong = admin_request(
        &app,
        Method::POST,
        "/api/operators/dave/disable",
        Some(&boss),
        Some(json!({"password": "wrong"})),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let right = admin_request(
        &app,
        Method::POST,
        "/api/operators/dave/disable",
        Some(&boss),
        Some(json!({"password": "boss-password"})),
    )
    .await;
    assert_eq!(right.status(), StatusCode::NO_CONTENT);
}

/// Over `ldaps://`, the server's certificate is checked against
/// `ca_cert_path`, and the connection runs on the server's own `ring` config:
/// no process-default provider is installed by it (ADR 0009).
#[tokio::test]
async fn ldaps_verifies_the_directory_and_installs_no_crypto_provider() {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = acme_proxy_core::testutil::TempDir::new("ldaps");
    let ca_path = dir.path().join("directory.pem");
    std::fs::write(&ca_path, certified.cert.pem()).unwrap();

    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
    )
    .unwrap();
    let directory =
        FakeDirectory::start_tls(tokio_rustls::TlsAcceptor::from(Arc::new(server))).await;

    // Without the CA, the certificate is a stranger's.
    let (untrusting, _database) = app_with(&directory, |_, _| {}).await;
    assert_eq!(
        sign_in(&untrusting, "bob", "bob-password").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        directory.binds().is_empty(),
        "nothing is sent to an unverified server"
    );

    let (trusting, _database) = app_with(&directory, |_, provider| {
        provider.ca_cert_path = ca_path.to_str().unwrap().to_string();
    })
    .await;
    assert_eq!(
        sign_in(&trusting, "bob", "bob-password").await.status(),
        StatusCode::OK
    );
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "an LDAP connection must not install a process-wide crypto provider"
    );
}
