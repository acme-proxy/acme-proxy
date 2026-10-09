//! Signing in to the web admin through an OpenID Connect provider, end to end
//! through the real `build_admin_app`, against a provider on loopback.
//!
//! The provider ([`MockIdp`]) is a real HTTP server the admin listener's
//! outbound client reaches over a socket -- discovery, the key set and the
//! token endpoint -- and it checks what a real one would: the client's Basic
//! credentials, the `redirect_uri`, and the PKCE verifier against the challenge
//! the browser carried. The test plays the browser: it follows the start
//! route's redirect only far enough to read `state`, `nonce` and the
//! challenge, and "authorizes" by registering a code with the provider.
//!
//! What is proved here and not inline: the cookie dance across the redirect
//! (the `SameSite=Lax` flow cookie, the `200` hand-off page that lets the
//! `Strict` session cookie ride), the single use of `state`, the refusals each
//! landing on the sign-in page, and the provider-owned surfaces (role,
//! password, step-up) on a provisioned operator. The ID-token checks
//! themselves are `core::jws::jwt`'s own tests; provisioning's rules are
//! `admin::identity`'s.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use acme_proxy_core::config::{OidcProviderConfig, RoleMapConfig};
use acme_proxy_store::admin_user::{AdminRole, AdminUser};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get as route_get, post as route_post};
use axum::{Json, Router};
use base64::prelude::*;
use common::*;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

const CLIENT_ID: &str = "acme-proxy";
const CLIENT_SECRET: &str = "s3cret:with-a-colon";

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// What the provider has been told about one authorization code.
#[derive(Clone)]
struct Grant {
    challenge: String,
    redirect_uri: String,
    claims: Value,
}

struct IdpState {
    issuer: String,
    grants: HashMap<String, Grant>,
    /// Answer the token endpoint with this status instead, when set.
    token_failure: Option<StatusCode>,
    /// Leave `id_token` out of the token response.
    omit_id_token: bool,
    /// The signing key and its `kid`; [`MockIdp::rotate`] replaces both.
    key: Arc<EcdsaKeyPair>,
    kid: String,
    /// Sign with the current key but name this `kid` instead.
    kid_override: Option<String>,
    /// How many times the key set was fetched.
    jwks_fetches: usize,
    /// What the userinfo endpoint answers a bearer of `opaque` with.
    userinfo: Value,
}

fn new_key() -> Arc<EcdsaKeyPair> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    Arc::new(
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap(),
    )
}

#[derive(Clone)]
struct MockIdp {
    state: Arc<Mutex<IdpState>>,
    issuer: String,
}

impl MockIdp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(IdpState {
            issuer: issuer.clone(),
            grants: HashMap::new(),
            token_failure: None,
            omit_id_token: false,
            key: new_key(),
            kid: "k1".to_string(),
            kid_override: None,
            jwks_fetches: 0,
            userinfo: json!({}),
        }));
        let idp = Self { state, issuer };

        let router = Router::new()
            .route("/.well-known/openid-configuration", route_get(discovery))
            .route("/jwks", route_get(jwks))
            .route("/token", route_post(token))
            .route("/userinfo", route_get(userinfo))
            .with_state(idp.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        idp
    }

    /// The `[admin.auth.oidc.corp]` section pointing at this provider.
    fn config(&self) -> OidcProviderConfig {
        OidcProviderConfig {
            display_name: "Corporate SSO".to_string(),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            groups_claim: "groups".to_string(),
            roles: RoleMapConfig {
                admin: vec!["acme-admins".to_string()],
                operator: vec!["acme-operators".to_string()],
                viewer: vec!["staff".to_string()],
            },
            ..OidcProviderConfig::default()
        }
    }

    /// "The person authenticated at the provider": a code the token endpoint
    /// will exchange for an ID token carrying `claims`.
    fn authorize(&self, code: &str, flow: &Flow, claims: Value) {
        self.state.lock().unwrap().grants.insert(
            code.to_string(),
            Grant {
                challenge: flow.challenge.clone(),
                redirect_uri: flow.redirect_uri.clone(),
                claims,
            },
        );
    }

    /// A new signing key under a new `kid`, as a provider rotating does.
    fn rotate(&self) {
        let mut state = self.state.lock().unwrap();
        state.key = new_key();
        state.kid = format!("{}-next", state.kid);
    }

    fn id_token(&self, claims: &Value) -> String {
        let (key, kid) = {
            let state = self.state.lock().unwrap();
            let kid = state
                .kid_override
                .clone()
                .unwrap_or_else(|| state.kid.clone());
            (state.key.clone(), kid)
        };
        let header = json!({"alg": "ES256", "kid": kid, "typ": "JWT"});
        let input = format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(header.to_string()),
            BASE64_URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        format!(
            "{input}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
    let issuer = idp.state.lock().unwrap().issuer.clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
    }))
}

async fn userinfo(State(idp): State<MockIdp>, headers: axum::http::HeaderMap) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some("Bearer opaque")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(idp.state.lock().unwrap().userinfo.clone()).into_response()
}

async fn jwks(State(idp): State<MockIdp>) -> Json<Value> {
    let mut state = idp.state.lock().unwrap();
    state.jwks_fetches += 1;
    let point = state.key.public_key().as_ref();
    Json(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": state.kid, "use": "sig", "alg": "ES256",
        "x": BASE64_URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": BASE64_URL_SAFE_NO_PAD.encode(&point[33..65]),
    }]}))
}

/// The token endpoint, checking what RFC 6749 §4.1.3 and RFC 7636 §4.6 make a
/// provider check -- so a client that got any of it wrong fails here.
async fn token(
    State(idp): State<MockIdp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    if let Some(status) = idp.state.lock().unwrap().token_failure {
        return (status, "the provider is having a bad day").into_response();
    }
    let expected = format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{CLIENT_ID}:{}", "s3cret%3Awith-a-colon"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&expected)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let Some(grant) = form
        .get("code")
        .and_then(|code| idp.state.lock().unwrap().grants.remove(code))
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = BASE64_URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ));
    if form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || challenge != grant.challenge
        || form.get("redirect_uri") != Some(&grant.redirect_uri)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let mut response = json!({"access_token": "opaque", "token_type": "Bearer"});
    if !idp.state.lock().unwrap().omit_id_token {
        response["id_token"] = json!(idp.id_token(&grant.claims));
    }
    Json(response).into_response()
}

// ---------------------------------------------------------------------------
// The browser
// ---------------------------------------------------------------------------

/// One sign-in, as far as the provider's authorization endpoint.
struct Flow {
    state: String,
    nonce: String,
    challenge: String,
    redirect_uri: String,
    /// The `__Host-acme_admin_oidc` value the start set.
    binding: String,
}

async fn app_with(
    idp: &MockIdp,
    edit: impl FnOnce(&mut OidcProviderConfig),
) -> (Router, Arc<acme_proxy_store::db::Database>) {
    let mut config = admin_config();
    let mut provider = idp.config();
    edit(&mut provider);
    config.admin.auth.oidc.insert("corp".to_string(), provider);
    test_admin_app(config).await
}

async fn get(app: &Router, path: &str, cookies: &[(&str, &str)]) -> Response {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if !cookies.is_empty() {
        let joined = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        builder = builder.header(header::COOKIE, joined);
    }
    send_from(app, builder.body(Body::empty()).unwrap(), "127.0.0.1:40000").await
}

fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect()
}

fn cookie_named(response: &Response, name: &str) -> Option<String> {
    set_cookies(response).iter().find_map(|cookie| {
        cookie
            .split(';')
            .next()?
            .strip_prefix(&format!("{name}="))
            .map(str::to_string)
    })
}

/// `GET /ui/login/oidc/corp`, read the way a browser would follow it.
async fn start(app: &Router) -> Flow {
    let response = get(app, "/ui/login/oidc/corp", &[]).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let flow_cookie = set_cookies(&response)
        .into_iter()
        .find(|cookie| cookie.starts_with("__Host-acme_admin_oidc="))
        .expect("the start sets the flow cookie");
    assert!(flow_cookie.contains("SameSite=Lax"), "{flow_cookie}");
    assert!(flow_cookie.contains("HttpOnly") && flow_cookie.contains("Secure"));

    let location = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert!(location.path().ends_with("/authorize"));
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(query["scope"].split(' ').any(|scope| scope == "openid"));
    Flow {
        state: query["state"].clone(),
        nonce: query["nonce"].clone(),
        challenge: query["code_challenge"].clone(),
        redirect_uri: query["redirect_uri"].clone(),
        binding: cookie_named(&response, "__Host-acme_admin_oidc").unwrap(),
    }
}

fn claims(idp: &MockIdp, flow: &Flow, username: &str, groups: &[&str]) -> Value {
    let now = acme_proxy_store::nonce::now_secs();
    json!({
        "iss": idp.issuer, "aud": CLIENT_ID, "sub": format!("sub-{username}"),
        "iat": now, "exp": now + 300, "nonce": flow.nonce,
        "preferred_username": username, "groups": groups,
    })
}

/// The provider's redirect back, carrying the flow cookie.
async fn callback(app: &Router, flow: &Flow, code: &str) -> Response {
    get(
        app,
        &format!(
            "/ui/login/oidc/corp/callback?code={code}&state={}",
            flow.state
        ),
        &[("__Host-acme_admin_oidc", &flow.binding)],
    )
    .await
}

/// A whole sign-in as `username` in `groups`, answering the callback.
async fn sign_in(app: &Router, idp: &MockIdp, username: &str, groups: &[&str]) -> Response {
    let flow = start(app).await;
    idp.authorize("code-1", &flow, claims(idp, &flow, username, groups));
    callback(app, &flow, "code-1").await
}

/// The session a successful callback established, as an API handle.
async fn session_of(app: &Router, response: &Response) -> AdminSessionHandle {
    let cookie = cookie_named(response, "__Host-acme_admin_session").expect("a session cookie");
    let whoami = admin_request(
        app,
        Method::GET,
        "/api/session",
        Some(&AdminSessionHandle {
            cookie: cookie.clone(),
            csrf: String::new(),
        }),
        None,
    )
    .await;
    assert_eq!(whoami.status(), StatusCode::OK);
    let csrf = json_body(whoami).await["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    AdminSessionHandle { cookie, csrf }
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_sign_in_page_offers_the_provider() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    let body = html_body(admin_page(&app, "/ui/login", None, false).await).await;
    assert!(body.contains(r#"href="/ui/login/oidc/corp""#), "{body}");
    assert!(body.contains("Sign in with Corporate SSO"));
    // The local realm is still there, and is the only password realm, so no
    // selector is drawn.
    assert!(body.contains(r#"name="password""#));
    assert!(!body.contains("<select"));
}

#[tokio::test]
async fn a_first_sign_in_provisions_the_operator_and_hands_over_a_session() {
    let idp = MockIdp::start().await;
    let (app, database) = app_with(&idp, |_| {}).await;

    let response = sign_in(&app, &idp, "Bob@Example.com", &["acme-operators"]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookies(&response);
    let session = cookies
        .iter()
        .find(|cookie| cookie.starts_with("__Host-acme_admin_session="))
        .expect("the session cookie");
    assert!(session.contains("SameSite=Strict"));
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-acme_admin_oidc=;")
                && cookie.contains("Max-Age=0")),
        "the flow cookie is cleared: {cookies:?}"
    );
    let handle = session_of(&app, &response).await;
    let page = html_body(response).await;
    assert!(
        page.contains(r#"http-equiv="refresh" content="0;url=/ui/""#),
        "{page}"
    );

    let whoami =
        json_body(admin_request(&app, Method::GET, "/api/session", Some(&handle), None).await)
            .await;
    assert_eq!(whoami["user"]["username"], "bob@example.com");
    assert_eq!(whoami["user"]["role"], "operator");
    assert_eq!(whoami["user"]["authProvider"], "oidc:corp");

    let user = AdminUser::find_by_username("bob@example.com", &database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user.external_id.as_deref(),
        Some(format!("{} sub-Bob@Example.com", idp.issuer).as_str())
    );
    assert!(
        user.last_login_at.is_some(),
        "a completed sign-in is stamped"
    );
}

#[tokio::test]
async fn the_role_follows_the_groups_and_no_group_is_refused() {
    let idp = MockIdp::start().await;
    let (app, database) = app_with(&idp, |_| {}).await;
    // Somebody else is admin, so bob's demotion is not the last-admin case.
    AdminUser::create("root", "unused", None, &database)
        .await
        .unwrap();

    assert_eq!(
        sign_in(&app, &idp, "bob", &["acme-admins"]).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        sign_in(&app, &idp, "bob", &["staff"]).await.status(),
        StatusCode::OK
    );
    let bob = AdminUser::find_by_username("bob", &database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob.role(), AdminRole::Viewer);

    let refused = sign_in(&app, &idp, "bob", &["contractors"]).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(cookie_named(&refused, "__Host-acme_admin_session").is_none());
    let page = html_body(refused).await;
    assert!(
        page.contains(r#"name="password""#),
        "the refusal lands on the sign-in page"
    );
}

#[tokio::test]
async fn a_name_a_local_operator_holds_is_refused_not_linked() {
    let idp = MockIdp::start().await;
    let (app, database) = app_with(&idp, |_| {}).await;
    let alice = AdminUser::create("alice", "unused", None, &database)
        .await
        .unwrap();

    let refused = sign_in(&app, &idp, "alice", &["acme-admins"]).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let still = AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still.id, alice.id);
    assert!(!still.is_external());
}

// ---------------------------------------------------------------------------
// The callback's own guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_callback_without_its_browser_cookie_is_refused() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;

    for cookies in [vec![], vec![("__Host-acme_admin_oidc", "somebody-elses")]] {
        let flow = start(&app).await;
        idp.authorize("code-1", &flow, claims(&idp, &flow, "bob", &["staff"]));
        let response = get(
            &app,
            &format!(
                "/ui/login/oidc/corp/callback?code=code-1&state={}",
                flow.state
            ),
            &cookies,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{cookies:?}");
        assert!(cookie_named(&response, "__Host-acme_admin_session").is_none());
    }
}

#[tokio::test]
async fn a_state_answers_one_callback() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    let flow = start(&app).await;
    idp.authorize("code-1", &flow, claims(&idp, &flow, "bob", &["staff"]));
    assert_eq!(
        callback(&app, &flow, "code-1").await.status(),
        StatusCode::OK
    );

    idp.authorize("code-2", &flow, claims(&idp, &flow, "bob", &["staff"]));
    assert_eq!(
        callback(&app, &flow, "code-2").await.status(),
        StatusCode::UNAUTHORIZED,
        "the row was consumed by the first callback"
    );
}

/// The provider refusing consumes the `state` too: it cannot be presented
/// again with a code.
#[tokio::test]
async fn a_provider_error_consumes_the_sign_in() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    let flow = start(&app).await;
    let denied = get(
        &app,
        &format!(
            "/ui/login/oidc/corp/callback?error=access_denied&state={}",
            flow.state
        ),
        &[("__Host-acme_admin_oidc", &flow.binding)],
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    idp.authorize("code-1", &flow, claims(&idp, &flow, "bob", &["staff"]));
    assert_eq!(
        callback(&app, &flow, "code-1").await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_token_for_another_sign_in_or_client_is_refused() {
    let idp = MockIdp::start().await;
    let (app, database) = app_with(&idp, |_| {}).await;

    for edit in [
        |claims: &mut Value| claims["nonce"] = json!("not-this-sign-ins"),
        |claims: &mut Value| claims["aud"] = json!("another-client"),
        |claims: &mut Value| claims["iss"] = json!("https://evil.example"),
    ] {
        let flow = start(&app).await;
        let mut token_claims = claims(&idp, &flow, "bob", &["staff"]);
        edit(&mut token_claims);
        idp.authorize("code-1", &flow, token_claims);
        assert_eq!(
            callback(&app, &flow, "code-1").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(
        AdminUser::find_by_username("bob", &database)
            .await
            .unwrap()
            .is_none()
    );
}

/// `required_amr` refuses a token that does not say the provider asked for a
/// second factor.
#[tokio::test]
async fn a_required_amr_is_enforced() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |provider| {
        provider.required_amr = vec!["mfa".to_string()]
    })
    .await;

    let flow = start(&app).await;
    idp.authorize("code-1", &flow, claims(&idp, &flow, "bob", &["staff"]));
    assert_eq!(
        callback(&app, &flow, "code-1").await.status(),
        StatusCode::UNAUTHORIZED
    );

    let flow = start(&app).await;
    let mut with_mfa = claims(&idp, &flow, "bob", &["staff"]);
    with_mfa["amr"] = json!(["pwd", "mfa"]);
    idp.authorize("code-1", &flow, with_mfa);
    assert_eq!(
        callback(&app, &flow, "code-1").await.status(),
        StatusCode::OK
    );
}

/// A provider that cannot be asked is this server's failure: `503`, not the
/// "wrong credentials" a person would go and reset.
#[tokio::test]
async fn an_unreachable_provider_is_unavailable_not_a_wrong_credential() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    idp.state.lock().unwrap().token_failure = Some(StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        sign_in(&app, &idp, "bob", &["staff"]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    // A provider that is not there at all fails the start the same way.
    let (down, _database) = app_with(&idp, |provider| {
        provider.issuer = "http://127.0.0.1:9".to_string()
    })
    .await;
    assert_eq!(
        get(&down, "/ui/login/oidc/corp", &[]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn an_unknown_provider_is_not_found() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    assert_eq!(
        get(&app, "/ui/login/oidc/nope", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/ui/login/oidc/nope/callback?code=x&state=y", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------
// A provisioned operator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_external_operator_has_no_password_here() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    let handle = session_of(&app, &sign_in(&app, &idp, "bob", &["acme-admins"]).await).await;

    // The local realm does not know them, whatever is typed.
    let refused = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({"username": "bob", "password": "anything-at-all"})),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    // Nor can they set one.
    let change = admin_request(
        &app,
        Method::POST,
        "/api/account/password",
        Some(&handle),
        Some(json!({"current_password": "", "new_password": "a-long-enough-password-2"})),
    )
    .await;
    assert_eq!(change.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(change).await["error"], "managed_externally");
}

/// An admin signed in through the provider manages colleagues: a fresh sign-in
/// stands in for the password they do not have here, and the provider owns a
/// provisioned colleague's role.
#[tokio::test]
async fn a_fresh_external_sign_in_steps_up_and_the_provider_owns_roles() {
    let idp = MockIdp::start().await;
    let (app, database) = app_with(&idp, |_| {}).await;
    let admin = session_of(&app, &sign_in(&app, &idp, "boss", &["acme-admins"]).await).await;
    sign_in(&app, &idp, "carol", &["staff"]).await;
    AdminUser::create("dave", "unused", Some(AdminRole::Viewer), &database)
        .await
        .unwrap();

    let role = admin_request(
        &app,
        Method::POST,
        "/api/operators/carol/role",
        Some(&admin),
        Some(json!({"role": "admin", "password": ""})),
    )
    .await;
    assert_eq!(role.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(role).await["error"], "managed_externally");

    let disable = admin_request(
        &app,
        Method::POST,
        "/api/operators/dave/disable",
        Some(&admin),
        Some(json!({"password": ""})),
    )
    .await;
    assert_eq!(disable.status(), StatusCode::NO_CONTENT);

    // Ten minutes later the sign-in is no longer fresh.
    sqlx::query("UPDATE admin_sessions SET created_at = created_at - 600;")
        .execute(database.raw_pool())
        .await
        .unwrap();
    let stale = admin_request(
        &app,
        Method::POST,
        "/api/operators/dave/enable",
        Some(&admin),
        Some(json!({"password": ""})),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(stale).await["error"], "reauthentication_required");
}

// ---------------------------------------------------------------------------
// The provider's variations
// ---------------------------------------------------------------------------

/// Groups from the userinfo endpoint, for a provider that keeps the ID token
/// small -- and only when the userinfo `sub` is the token's.
#[tokio::test]
async fn groups_can_come_from_userinfo() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |provider| provider.userinfo_groups = true).await;

    idp.state.lock().unwrap().userinfo = json!({"sub": "sub-bob", "groups": ["acme-admins"]});
    let response = sign_in(&app, &idp, "bob", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let handle = session_of(&app, &response).await;
    let whoami =
        json_body(admin_request(&app, Method::GET, "/api/session", Some(&handle), None).await)
            .await;
    assert_eq!(whoami["user"]["role"], "admin");

    idp.state.lock().unwrap().userinfo = json!({"sub": "somebody-else", "groups": ["acme-admins"]});
    assert_eq!(
        sign_in(&app, &idp, "bob", &[]).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_required_acr_is_enforced() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |provider| {
        provider.required_acr = vec!["gold".to_string()]
    })
    .await;

    for (acr, status) in [
        ("silver", StatusCode::UNAUTHORIZED),
        ("gold", StatusCode::OK),
    ] {
        let flow = start(&app).await;
        let mut token_claims = claims(&idp, &flow, "bob", &["staff"]);
        token_claims["acr"] = json!(acr);
        idp.authorize("code-1", &flow, token_claims);
        assert_eq!(
            callback(&app, &flow, "code-1").await.status(),
            status,
            "{acr}"
        );
    }
}

/// A provider that rotated its key is picked up at once -- one forced fetch --
/// while a stream of unknown `kid`s costs it at most one fetch a minute.
#[tokio::test]
async fn a_rotated_key_is_fetched_and_forged_kids_are_not_a_load_generator() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    assert_eq!(
        sign_in(&app, &idp, "bob", &["staff"]).await.status(),
        StatusCode::OK
    );
    assert_eq!(idp.state.lock().unwrap().jwks_fetches, 1);

    idp.rotate();
    assert_eq!(
        sign_in(&app, &idp, "bob", &["staff"]).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        idp.state.lock().unwrap().jwks_fetches,
        2,
        "one forced fetch"
    );

    idp.state.lock().unwrap().kid_override = Some("forged".to_string());
    for _ in 0..3 {
        assert_eq!(
            sign_in(&app, &idp, "bob", &["staff"]).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        idp.state.lock().unwrap().jwks_fetches,
        2,
        "the last forced fetch was moments ago"
    );
}

/// `openid` is requested whatever `scopes` says; `start` asserts it.
#[tokio::test]
async fn openid_is_always_requested() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |provider| {
        provider.scopes = vec!["groups".to_string()]
    })
    .await;
    start(&app).await;
}

#[tokio::test]
async fn a_token_response_without_an_id_token_is_refused() {
    let idp = MockIdp::start().await;
    let (app, _database) = app_with(&idp, |_| {}).await;
    idp.state.lock().unwrap().omit_id_token = true;
    assert_eq!(
        sign_in(&app, &idp, "bob", &["staff"]).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

/// The OpenID Connect routes share the sign-in limiter: refused callbacks
/// count, and past the budget both the start and the callback answer `429`.
#[tokio::test]
async fn refused_callbacks_spend_the_sign_in_budget() {
    let idp = MockIdp::start().await;
    let mut config = admin_config();
    config.admin.login_max_attempts = 1;
    config
        .admin
        .auth
        .oidc
        .insert("corp".to_string(), idp.config());
    let (app, _database) = test_admin_app(config).await;

    let flow = start(&app).await;
    let forged = get(
        &app,
        &format!("/ui/login/oidc/corp/callback?code=x&state={}", flow.state),
        &[],
    )
    .await;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(
        get(&app, "/ui/login/oidc/corp", &[]).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        get(&app, "/ui/login/oidc/corp/callback?code=x&state=y", &[])
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
