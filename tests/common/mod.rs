//! Shared integration-test harness: an in-memory app builder, response helpers,
//! and EC/RSA JWS signers producing bodies in the exact shape the `AcmeRequest`
//! extractor expects.
//!
//! Each `tests/*.rs` file is its own crate that includes this module, so not
//! every crate uses every helper — hence the crate-wide `dead_code` allow, and
//! the `unused_imports` one for the re-exports only some of them need.
#![allow(dead_code, unused_imports)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acme_proxy::audit::Auditor;
// Re-exported for the suites that build an `Account` directly.
pub use acme_proxy::audit::ClientContext;
use acme_proxy::{Profile, ProfileParts, build_app};

use acme_proxy::challenge::{
    ChallengeError, ChallengeRegistry, ChallengeValidator, ValidationContext,
};
use acme_proxy::config::Config;
use acme_proxy::filter::expr::Condition;
use acme_proxy::filter::policy::{Check, Effect, Mode, Rule, StageSet, Verdict};
use acme_proxy::filter::{ConnectionContext, FilterPolicy, IdentifierContext, ProxyPolicy, Stage};
use acme_proxy::notify::{NotifyBackend, NotifyDispatcher, NotifyError, NotifyEvent};
use acme_proxy::signer::local_ca::LocalCa;
use acme_proxy::signer::relay::http01::MemoryTokenStore;
use acme_proxy::signer::{
    Http01TokenStore, IssueOutcome, RenewalWindow, RequestedValidity, SignerBackend, SignerError,
};
use acme_proxy::sqlite::db::Database;
use acme_proxy::sqlite::order::Identifier;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use base64::prelude::*;
use http_body_util::BodyExt;
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
use serde_json::{Value, json};
use simple_asn1::ASN1Block;
use tower::ServiceExt;

/// Installs a `tracing` subscriber once per test binary.
///
/// Without a subscriber, `LevelFilter::current()` is `OFF` and `tracing`'s
/// `event!` short-circuits before evaluating its field expressions — they sit
/// inside its `if enabled` block. So every `error = %error` / `id = ?id` in the
/// server runs its `Display`/`Debug` impl for the first time *in production*.
/// This makes the suite exercise them instead, which is what would catch a
/// field expression that panics or is accidentally expensive.
///
/// Output goes to a sink: the point is to run the formatting, not to print it.
/// `try_init` (not `init`) because each `tests/*.rs` is its own binary but a
/// binary may call this from several tests at once.
///
/// Note this is *not* a coverage lever, though it looks like one: measured
/// before and after, it moved the line total by 0.03 points. Handlers carrying
/// `#[instrument]` report oddly under `llvm-cov` for an unrelated reason — the
/// attribute moves the body into a generated `async` block, so the visible
/// signature lines read as 0 hits and the body lines carry no region at all,
/// however thoroughly the handler is tested.
fn init_tracing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .try_init();
    });
}

/// Builds a real PKCS#10 CSR for a single `dns` SAN and returns it base64url-DER
/// encoded (the shape a finalize payload's `csr` field carries). Uses `rcgen`
/// (a normal crate dependency, available to integration tests).
pub fn make_csr(dns: &str) -> String {
    make_csr_for(&[dns])
}

/// [`make_csr`] over several names, for a multi-identifier order.
///
/// `tests/security.rs` had its own verbatim copy of this; a CSR builder is
/// exactly the sort of thing that ends up subtly different in two places (one
/// setting a common name, the other not) and then tests two different things
/// while reading as though it tests one.
pub fn make_csr_for(names: &[&str]) -> String {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let csr = params.serialize_request(&key_pair).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(csr.der())
}

/// Like [`make_csr`], but with extra subject alternative names appended — so a
/// test can build the CSR that smuggles an IP address alongside its DNS name.
pub fn make_csr_with_sans(dns: &str, extra: Vec<rcgen::SanType>) -> String {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![dns.to_string()]).unwrap();
    params.subject_alt_names.extend(extra);
    let csr = params.serialize_request(&key_pair).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(csr.der())
}

/// Builds a base64url-DER CSR for `dns` from an EC key pair a test can *also*
/// sign an ACME JWS with — the shape "revoke via the certificate's own
/// keypair" needs (RFC 8555 §7.6's second authorization case, no account
/// involved at all). The same PKCS8 document backs two independent objects:
/// a `ring` `EcdsaKeyPair` (fixed-format ES256 signing, wrapped as
/// [`EcSigner`] so [`TestSigner::sign`] can build the embedded-`jwk` revoke
/// JWS) and an `rcgen::KeyPair` (ASN.1-format signing, used only to
/// self-sign the CSR) — both derive the *same* public key, so the leaf
/// certificate later issued from this CSR carries the exact DER-SPKI
/// [`EcSigner::jwk`] encodes.
pub fn make_csr_and_keypair(dns: &str) -> (String, EcSigner) {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let signer = EcSigner::from_pkcs8(pkcs8.as_ref());

    let rcgen_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let params = rcgen::CertificateParams::new(vec![dns.to_string()]).unwrap();
    let csr = params.serialize_request(&rcgen_key).unwrap();

    (BASE64_URL_SAFE_NO_PAD.encode(csr.der()), signer)
}

/// The leaf out of a `leaf + CA` PEM chain, as DER — the first `CERTIFICATE`
/// block.
pub fn first_certificate(chain: &str) -> Vec<u8> {
    acme_proxy::cert::leaf_der_from_chain(chain).unwrap()
}

/// The server-level base URL — `server.base_url`, naming the process rather
/// than any one endpoint. Nothing ACME is served here.
pub const HOST: &str = "http://localhost:3000";

/// The profile every helper below mounts.
pub const PROFILE: &str = "default";

/// Where that profile is mounted: `/profile/<name>`, the namespace `build_app`
/// reserves for ACME endpoints.
pub const PREFIX: &str = "/profile/default";

/// The base URL for that profile — what its `directory` advertises, and what
/// every JWS `url` must name (RFC 8555 §6.4).
pub const BASE: &str = "http://localhost:3000/profile/default";

/// A route path under the test profile: `p("/newOrder")` →
/// `/profile/default/newOrder`.
///
/// An absolute URL a response handed back (a `Location` header, an
/// `authorizations` entry) becomes a request path by stripping [`HOST`], not
/// [`BASE`] — the prefix has to stay.
#[must_use]
pub fn p(path: &str) -> String {
    format!("{PREFIX}{path}")
}

/// Builds the full app backed by a throwaway in-memory database and the
/// default configuration.
pub async fn test_app() -> Router {
    test_app_with_db().await.0
}

/// Like [`test_app`], but also returns the backing database so a test can, e.g.,
/// close its pool to exercise DB-failure paths. The signer is an in-memory local
/// CA so the suite stays disk- and network-free.
pub async fn test_app_with_db() -> (Router, Arc<Database>) {
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_with_signer(signer).await
}

/// Builds the full router with a caller-supplied signer backend (and a throwaway
/// in-memory database), returning both. Lets a test inject a failing signer to
/// drive the issuance-failure path.
pub async fn test_app_with_signer(signer: Arc<dyn SignerBackend>) -> (Router, Arc<Database>) {
    test_app_full(
        Config::default(),
        signer,
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications(),
    )
    .await
}

/// Builds the full router with a caller-supplied filter chain, the default
/// config and an in-memory local CA.
pub async fn test_app_with_filter(filter: Arc<FilterPolicy>) -> (Router, Arc<Database>) {
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_full(
        Config::default(),
        signer,
        filter,
        default_challenges(),
        no_notifications(),
    )
    .await
}

/// Builds the full router with a caller-supplied challenge registry and config,
/// so a test can choose which types are offered and how they validate.
pub async fn test_app_with_challenges(
    config: Config,
    challenges: Arc<ChallengeRegistry>,
) -> (Router, Arc<Database>) {
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_full(
        config,
        signer,
        Arc::new(FilterPolicy::default()),
        challenges,
        no_notifications(),
    )
    .await
}

/// Builds the full router with a caller-supplied notify dispatcher — usually
/// wrapping a [`RecordingNotifyBackend`] — plus the default config, an
/// in-memory local CA, no filters and a bypassing `http-01` registry.
pub async fn test_app_with_notify(notify: Arc<NotifyDispatcher>) -> (Router, Arc<Database>) {
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_full(
        Config::default(),
        signer,
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        notify,
    )
    .await
}

/// The no-op dispatcher every `test_app_with_*` helper defaults to when a test
/// isn't asserting on notifications at all.
pub fn no_notifications() -> Arc<NotifyDispatcher> {
    Arc::new(NotifyDispatcher::default())
}

/// The bypassing `http-01`-only registry every other helper uses — the same
/// thing a server with no `[challenge]` section gets.
pub fn default_challenges() -> Arc<ChallengeRegistry> {
    Arc::new(ChallengeRegistry::default())
}

/// A registry offering `types` and validating them with `validator`.
pub fn challenges_with(
    types: &[&str],
    validators: Vec<Arc<dyn ChallengeValidator>>,
) -> Arc<ChallengeRegistry> {
    Arc::new(ChallengeRegistry::new(
        validators,
        types.iter().map(std::string::ToString::to_string).collect(),
        false,
        Duration::from_secs(5),
    ))
}

/// A registry offering `types` but validating nothing, as the default config does.
pub fn bypassing_challenges(types: &[&str]) -> Arc<ChallengeRegistry> {
    Arc::new(ChallengeRegistry::new(
        Vec::new(),
        types.iter().map(std::string::ToString::to_string).collect(),
        true,
        Duration::from_secs(5),
    ))
}

/// One endpoint in a multi-profile app, for `tests/profiles.rs`.
///
/// Defaults mirror [`test_app_full`]'s single profile — an in-memory local CA,
/// no filters, a bypassing `http-01` registry — so a test states only the
/// difference it is about.
pub struct TestProfile {
    pub name: &'static str,
    pub signer: Arc<dyn SignerBackend>,
    pub filter: Arc<FilterPolicy>,
    pub challenges: Arc<ChallengeRegistry>,
    pub eab: acme_proxy::config::EabConfig,
    pub meta: acme_proxy::config::MetaConfig,
    pub notify: Arc<NotifyDispatcher>,
}

impl TestProfile {
    /// A profile named `name`, with its **own** local CA — two of these issue
    /// certificates with different issuers, which is how a test proves which
    /// endpoint actually signed.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            signer: Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap()),
            filter: Arc::new(FilterPolicy::default()),
            challenges: default_challenges(),
            eab: acme_proxy::config::EabConfig::default(),
            meta: acme_proxy::config::MetaConfig::default(),
            notify: no_notifications(),
        }
    }

    #[must_use]
    pub fn requiring_eab(mut self) -> Self {
        self.eab.enabled = true;
        self
    }

    #[must_use]
    pub fn with_filter(mut self, filter: Arc<FilterPolicy>) -> Self {
        self.filter = filter;
        self
    }

    #[must_use]
    pub fn with_notify(mut self, notify: Arc<NotifyDispatcher>) -> Self {
        self.notify = notify;
        self
    }

    /// This endpoint's base URL — what its directory advertises and what every
    /// JWS `url` sent to it must name.
    #[must_use]
    pub fn base(name: &str) -> String {
        format!("{HOST}/profile/{name}")
    }

    /// A request path under this endpoint.
    #[must_use]
    pub fn path(name: &str, path: &str) -> String {
        format!("/profile/{name}{path}")
    }
}

/// Builds an app mounting several endpoints over one database — the real
/// multi-profile shape, through the real `build_app`.
pub async fn test_app_with_profiles(profiles: Vec<TestProfile>) -> (Router, Arc<Database>) {
    init_tracing();
    let config = Config::default();
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let built: Vec<_> = profiles
        .into_iter()
        .map(|profile| {
            Arc::new(Profile::new(
                profile.name,
                &config.server.base_url,
                ProfileParts {
                    signer: profile.signer,
                    filter: profile.filter,
                    challenges: profile.challenges,
                    order: config.order.clone(),
                    eab: profile.eab,
                    meta: profile.meta,
                    notify: profile.notify,
                },
            ))
        })
        .collect();
    let router = build_app(
        database.clone(),
        Arc::new(config),
        built,
        test_auditor(database.clone()),
    );
    (router, database)
}

/// The one place the app is actually constructed: every other `test_app_*`
/// helper delegates here, so a new `build_app`/`Profile` parameter is added in
/// one place rather than at each call site.
///
/// It builds the real thing — root routes plus one profile mounted under
/// [`PREFIX`] — so the suite exercises the mounting itself, not a router that
/// only exists in tests.
pub async fn test_app_full(
    config: Config,
    signer: Arc<dyn SignerBackend>,
    filter: Arc<FilterPolicy>,
    challenges: Arc<ChallengeRegistry>,
    notify: Arc<NotifyDispatcher>,
) -> (Router, Arc<Database>) {
    init_tracing();
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let profile = one_profile(&config, signer, filter, challenges, notify);
    let router = build_app(
        database.clone(),
        Arc::new(config),
        vec![profile],
        test_auditor(database.clone()),
    );
    (router, database)
}

/// The single `default` profile both app builders mount.
///
/// Factored out rather than copied so `test_admin_app` and `test_app_full`
/// cannot drift into mounting subtly different endpoints.
fn one_profile(
    config: &Config,
    signer: Arc<dyn SignerBackend>,
    filter: Arc<FilterPolicy>,
    challenges: Arc<ChallengeRegistry>,
    notify: Arc<NotifyDispatcher>,
) -> Arc<Profile> {
    Arc::new(Profile::new(
        PROFILE,
        &config.server.base_url,
        ProfileParts {
            signer,
            filter,
            challenges,
            order: config.order.clone(),
            eab: config.eab.clone(),
            meta: config.meta.clone(),
            notify,
        },
    ))
}

/// The auditor every test app is built with: **no reverse lookup**.
///
/// `audit.reverse_dns` defaults to `true` in production, and deliberately not
/// here — the suite runs with no network and `Auditor::from_config` would build
/// a resolver from `/etc/resolv.conf`, making the audit path's behaviour depend
/// on the machine the tests run on. Every audit row a test sees therefore has a
/// `client_ip` and no `client_ptr`; a test that wants the PTR half drives
/// `Auditor::with_resolver` with a stub, the way the challenge and filter
/// suites drive theirs.
pub fn test_auditor(database: Arc<Database>) -> Arc<Auditor> {
    Arc::new(Auditor::with_resolver(
        database,
        None,
        std::time::Duration::from_millis(100),
    ))
}

/// A `Config` with the web admin enabled at its defaults.
pub fn admin_config() -> Config {
    let mut config = Config::default();
    config.admin.enabled = true;
    config
}

/// Builds the **admin** router (not the ACME one) over a throwaway in-memory
/// database, plus the one `default` profile so `revoke` can resolve a signer.
pub async fn test_admin_app(config: Config) -> (Router, Arc<Database>) {
    let (router, database, _signer) = test_admin_app_with_signer(config).await;
    (router, database)
}

/// [`test_admin_app`], also handing back the signer the profile was built with.
///
/// A test that needs an order to be genuinely *issued* — so the admin API's
/// revoke path has a certificate to act on — must issue through the very same
/// backend the handler will later revoke against, or the CA-side ledger and
/// the CRL would belong to two different objects.
pub async fn test_admin_app_with_signer(
    config: Config,
) -> (Router, Arc<Database>, Arc<dyn SignerBackend>) {
    init_tracing();
    let database = Arc::new(Database::connect_in_memory().await.unwrap());
    let signer: Arc<dyn SignerBackend> =
        Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    let profile = one_profile(
        &config,
        signer.clone(),
        Arc::new(FilterPolicy::default()),
        default_challenges(),
        no_notifications(),
    );
    let router = acme_proxy::webadmin::build_admin_app(
        database.clone(),
        Arc::new(config),
        &[profile],
        test_auditor(database.clone()),
    );
    (router, database, signer)
}

/// A signed-in admin session: the cookie to send back and the CSRF token every
/// mutating request needs.
pub struct AdminSessionHandle {
    pub cookie: String,
    pub csrf: String,
}

/// The password `test_admin_app_logged_in` creates its operator with.
pub const ADMIN_PASSWORD: &str = "a-long-enough-password";

/// Builds the admin router, creates one operator, signs in, and hands back the
/// credentials the rest of a test needs.
pub async fn test_admin_app_logged_in(
    config: Config,
) -> (Router, Arc<Database>, AdminSessionHandle) {
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user("alice", ADMIN_PASSWORD, database.clone())
        .await
        .expect("the bootstrap operator must be creatable");
    let handle = admin_login(&app, "alice", ADMIN_PASSWORD).await;
    (app, database, handle)
}

/// Signs in and extracts the cookie and CSRF token, failing loudly if the
/// login did not succeed.
pub async fn admin_login(app: &Router, username: &str, password: &str) -> AdminSessionHandle {
    let response = admin_request(
        app,
        Method::POST,
        "/api/session",
        None,
        Some(serde_json::json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "login must succeed to build a session handle"
    );

    let cookie = session_cookie_token(&response).expect("login must set the session cookie");
    let body = json_body(response).await;
    let csrf = body["csrfToken"]
        .as_str()
        .expect("login must return a csrfToken")
        .to_string();
    AdminSessionHandle { cookie, csrf }
}

/// Signs in as far as the password step and asserts the login is **not**
/// complete, handing back the half-authenticated cookie.
///
/// [`admin_login`]'s sibling. The CSRF token is real -- the pending response
/// carries one so the enrolment routes can be reached -- but no ordinary route
/// will accept this session.
pub async fn admin_login_pending(app: &Router, username: &str, password: &str) -> (String, String) {
    let response = admin_request(
        app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a correct password answers 200 even when a factor is outstanding"
    );

    let cookie = session_cookie_token(&response).expect("a pending login must set the cookie");
    let body = json_body(response).await;
    assert_eq!(
        body["mfaRequired"], true,
        "this helper is for an operator who owes a second factor"
    );
    let csrf = body["csrfToken"]
        .as_str()
        .expect("a pending login must return a csrfToken")
        .to_string();
    (cookie, csrf)
}

/// Gives `username` a confirmed second factor, through the same operation layer
/// the panel uses, and returns the raw secret so the test can compute codes.
pub async fn enrol_totp(database: Arc<Database>, username: &str) -> Vec<u8> {
    let mut user = acme_proxy::sqlite::admin_user::AdminUser::find_by_username(username, &database)
        .await
        .unwrap()
        .expect("the operator must exist before enrolling them");

    let enrolment = acme_proxy::admin::mfa::begin_totp_enrolment(
        &mut user,
        "http://localhost:3001",
        database.clone(),
    )
    .await
    .unwrap();

    let code = totp_code(&enrolment.secret, 0);
    acme_proxy::admin::mfa::confirm_totp_enrolment(&mut user, &code, None, database)
        .await
        .unwrap()
        .expect("a freshly generated code must confirm its own enrolment");

    enrolment.secret
}

/// The text between two markers, for pulling a secret out of a rendered page.
///
/// Panics loudly rather than returning an `Option`: every caller is asserting
/// that the page contains it, so a miss is the test result.
pub fn between(haystack: &str, start: &str, end: &str) -> String {
    let rest = haystack
        .split_once(start)
        .unwrap_or_else(|| panic!("`{start}` not found in the rendered page"))
        .1;
    rest.split_once(end)
        .unwrap_or_else(|| panic!("`{end}` not found after `{start}`"))
        .0
        .trim()
        .to_string()
}

/// Decodes the unpadded RFC 4648 base32 the enrolment endpoint hands back.
///
/// Lives here and not in `admin::totp` on purpose: nothing in the server ever
/// reads base32 back, so a production decoder would be untested surface. The
/// tests need one because they receive the secret the way an operator does --
/// as the string they would type into an app -- and then have to compute codes
/// from it.
pub fn base32_decode(encoded: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut buffer = 0u64;
    let mut out = Vec::new();

    for character in encoded.bytes() {
        let value = ALPHABET
            .iter()
            .position(|symbol| *symbol == character)
            .unwrap_or_else(|| panic!("`{}` is not base32", character as char));
        buffer = (buffer << 5) | value as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

/// The code `secret` produces `steps` time steps from now.
///
/// **Prefer [`admin_login_mfa`] for a login that is only meant to succeed.**
/// Stepping forward by hand is fragile in this suite: a login costs several
/// PBKDF2 runs, so two of them routinely straddle a 30-second boundary and a
/// code computed as "now + 2" lands outside the ±1 window by the time it is
/// submitted. Reach for this only where the *code itself* is the subject.
pub fn totp_code(secret: &[u8], steps: i64) -> String {
    use acme_proxy::admin::totp;
    totp::totp_at(secret, totp::step_at(now_unix()) + steps, totp::DIGITS)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Signs in through both steps and hands back a usable session.
///
/// Clears `totp_last_step` first, so the code for the current step is always
/// accepted. That is the harness stepping out of the replay guard's way rather
/// than testing around it: the guard is a `WHERE` clause with its own tests
/// (`AdminUser::claim_totp_step`, `admin::mfa`, and
/// `a_code_cannot_be_spent_twice` below), and an integration test that has to
/// win a race against a 30-second clock to sign in is a flake, not a
/// regression test.
pub async fn admin_login_mfa(
    app: &Router,
    database: Arc<Database>,
    username: &str,
    password: &str,
    secret: &[u8],
) -> AdminSessionHandle {
    sqlx::query("UPDATE admin_users SET totp_last_step = NULL WHERE username = ?;")
        .bind(username)
        .execute(&database.pool)
        .await
        .unwrap();

    let (cookie, csrf) = admin_login_pending(app, username, password).await;
    let pending = AdminSessionHandle { cookie, csrf };

    let response = admin_request(
        app,
        Method::POST,
        "/api/session/mfa",
        Some(&pending),
        Some(json!({ "code": totp_code(secret, 0) })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the second step must complete the login"
    );

    let cookie = session_cookie_token(&response).expect("promotion must rotate the cookie");
    let body = json_body(response).await;
    AdminSessionHandle {
        cookie,
        csrf: body["csrfToken"]
            .as_str()
            .expect("a promoted session must return a csrfToken")
            .to_string(),
    }
}

/// The `__Host-acme_admin_session` value from a response's `Set-Cookie`, if it
/// set one to a non-empty value.
pub fn session_cookie_token(response: &Response) -> Option<String> {
    let raw = response
        .headers()
        .get(header::SET_COOKIE)?
        .to_str()
        .ok()?
        .to_string();
    let value = raw
        .split(';')
        .next()?
        .strip_prefix("__Host-acme_admin_session=")?
        .to_string();
    (!value.is_empty()).then_some(value)
}

/// Drives one admin request, optionally authenticated and optionally with a
/// JSON body.
///
/// `session` supplies both the cookie and the `X-CSRF-Token`; a test that wants
/// to omit or corrupt the token builds the request itself.
pub async fn admin_request(
    app: &Router,
    method: Method,
    path: &str,
    session: Option<&AdminSessionHandle>,
    body: Option<serde_json::Value>,
) -> Response {
    admin_request_from(app, method, path, session, body, "127.0.0.1:40000").await
}

/// [`admin_request`], with the peer address spelled out.
///
/// The address is the `LoginLimiter`'s key, so anything asserting that a bound
/// does — or deliberately does not — survive an attacker rotating addresses has
/// to choose it per request.
pub async fn admin_request_from(
    app: &Router,
    method: Method,
    path: &str,
    session: Option<&AdminSessionHandle>,
    body: Option<serde_json::Value>,
    peer: &str,
) -> Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(session) = session {
        builder = builder
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header("x-csrf-token", &session.csrf);
    }
    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    send_from(app, request, peer).await
}

/// Drives one `/ui` page request.
///
/// `hx` sets `HX-Request: true`, which is what tells a page handler to answer
/// with the bare fragment rather than the whole document — and what turns a
/// sign-in redirect into an `HX-Redirect` header. Both branches are worth
/// exercising on every route, so it is a parameter rather than two helpers.
pub async fn admin_page(
    app: &Router,
    path: &str,
    session: Option<&AdminSessionHandle>,
    hx: bool,
) -> Response {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(session) = session {
        builder = builder.header(
            header::COOKIE,
            format!("__Host-acme_admin_session={}", session.cookie),
        );
    }
    if hx {
        builder = builder.header("hx-request", "true");
    }
    send_from(app, builder.body(Body::empty()).unwrap(), "127.0.0.1:40000").await
}

/// Drives one `/ui` mutation, with a form body rather than JSON.
///
/// The CSRF token still travels as `X-CSRF-Token` — htmx puts it there from
/// `hx-headers`, which is why the page layer needed no second CSRF path.
pub async fn admin_form_request(
    app: &Router,
    method: Method,
    path: &str,
    session: Option<&AdminSessionHandle>,
    form: Option<&[(&str, &str)]>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(session) = session {
        builder = builder
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header("x-csrf-token", &session.csrf);
    }
    let request = match form {
        Some(pairs) => builder
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(encode_form(pairs)))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    send_from(app, request, "127.0.0.1:40000").await
}

/// `application/x-www-form-urlencoded`, hand-rolled so the test crate needs no
/// encoder dependency of its own.
fn encode_form(pairs: &[(&str, &str)]) -> String {
    fn encode(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for byte in raw.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                b' ' => out.push('+'),
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
        out
    }

    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Reads a response body as text, for the HTML the page layer serves.
pub async fn html_body(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).expect("an admin page must be UTF-8")
}

/// Parses a response body as JSON.
pub async fn json_body(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "expected a JSON body, got `{}`: {error}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

/// A challenge validator that blocks until the test lets it go.
///
/// `post_challenge` awaits validation inline, so this is how a test holds an
/// ACME request open for as long as it needs — which is what the admission
/// limit has to be observed against. Anything that merely *slept* would make
/// those tests races against a timer.
pub struct BlockingValidator {
    typ: &'static str,
    release: Arc<tokio::sync::Notify>,
}

impl BlockingValidator {
    pub fn new(typ: &'static str) -> Self {
        Self {
            typ,
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// A handle the test keeps, to let every blocked validation finish.
    pub fn releaser(&self) -> Arc<tokio::sync::Notify> {
        self.release.clone()
    }
}

#[async_trait]
impl ChallengeValidator for BlockingValidator {
    fn typ(&self) -> &'static str {
        self.typ
    }

    async fn validate(&self, _context: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        self.release.notified().await;
        Ok(())
    }
}

/// A challenge validator answering from a canned outcome and counting its calls,
/// so a test can assert that a decided challenge was *not* re-validated.
pub struct StubValidator {
    typ: &'static str,
    outcome: Option<String>,
    calls: Arc<AtomicUsize>,
}

impl StubValidator {
    /// Passes every challenge of `typ`.
    pub fn passing(typ: &'static str) -> Self {
        Self {
            typ,
            outcome: None,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Fails every challenge of `typ` with an `incorrectResponse`.
    pub fn failing(typ: &'static str, detail: &str) -> Self {
        Self {
            typ,
            outcome: Some(detail.to_string()),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A handle to this validator's call counter, cloneable before the validator
    /// is moved into the registry.
    pub fn counter(&self) -> Arc<AtomicUsize> {
        self.calls.clone()
    }
}

#[async_trait]
impl ChallengeValidator for StubValidator {
    fn typ(&self) -> &'static str {
        self.typ
    }

    async fn validate(&self, _ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.outcome {
            Some(detail) => Err(ChallengeError::IncorrectResponse(detail.clone())),
            None => Ok(()),
        }
    }
}

/// A validator that records the key authorization it was handed, so a test can
/// check the server derives it the way a real client would.
pub struct RecordingValidator {
    typ: &'static str,
    seen: Arc<Mutex<Vec<String>>>,
}

impl RecordingValidator {
    pub fn new(typ: &'static str) -> Self {
        Self {
            typ,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn seen(&self) -> Arc<Mutex<Vec<String>>> {
        self.seen.clone()
    }
}

#[async_trait]
impl ChallengeValidator for RecordingValidator {
    fn typ(&self) -> &'static str {
        self.typ
    }

    async fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
        self.seen.lock().unwrap().push(format!(
            "{}|{}|{}|{}",
            ctx.identifier, ctx.wildcard, ctx.token, ctx.key_authorization
        ));
        Ok(())
    }
}

/// A signer backend that always fails internally, for exercising the
/// finalize → `serverInternal` / order-`invalid` path.
pub struct FailingSigner;

#[async_trait]
impl SignerBackend for FailingSigner {
    async fn issue(
        &self,
        _order_id: &str,
        _csr_der: &[u8],
        _identifiers: &[Identifier],
        _validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        Err(SignerError::Internal("boom".to_string()))
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Err(SignerError::Internal("boom".to_string()))
    }
}

/// Issues for real, then refuses to revoke.
///
/// [`FailingSigner`] cannot reach the revocation path at all -- it fails
/// `issue` too, so no order ever gets a certificate to revoke. This one wraps a
/// real [`LocalCa`] so a test can genuinely issue, then drive the branch where
/// the CA-side action fails: `post_revoke_cert` calls `revoke` *before*
/// `Order::revoke`, precisely so a signer failure leaves the order un-revoked
/// and retryable rather than recording a revocation the CA never performed.
pub struct RevokeFailingSigner(pub Arc<LocalCa>);

impl RevokeFailingSigner {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(
            LocalCa::generate_in_memory("ecdsa-p256", 90)
                .expect("an in-memory CA is always available"),
        ))
    }
}

impl Default for RevokeFailingSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignerBackend for RevokeFailingSigner {
    async fn issue(
        &self,
        order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        self.0.issue(order_id, csr_der, identifiers, validity).await
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Err(SignerError::Internal("the CA refused".to_string()))
    }

    async fn crl_der(&self) -> Option<Vec<u8>> {
        self.0.crl_der().await
    }
}

/// A signer backend carrying nothing but an `http-01` token store.
///
/// The responder route is mounted off `SignerBackend::http01_tokens`, so this
/// is how a test gets it onto the real `build_app` without standing up an
/// upstream ACME server. Issuance is deliberately unsupported: nothing that
/// uses this backend is about certificates.
pub struct TokenStoreSigner(pub Arc<MemoryTokenStore>);

impl TokenStoreSigner {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(MemoryTokenStore::new()))
    }
}

impl Default for TokenStoreSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignerBackend for TokenStoreSigner {
    async fn issue(
        &self,
        _order_id: &str,
        _csr_der: &[u8],
        _identifiers: &[Identifier],
        _validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        Err(SignerError::Internal("not a signing backend".to_string()))
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Ok(())
    }

    fn http01_tokens(&self) -> Option<Arc<dyn Http01TokenStore>> {
        Some(self.0.clone())
    }
}

/// A signer backend that records whether `issue` was ever reached.
///
/// Exists for one property: `post_finalize` binds the CSR to its order
/// *before* handing anything to a backend. `local_ca` makes that check itself,
/// so a test using the real signer cannot tell the handler's refusal from the
/// backend's — and it is precisely the backends that do *not* check
/// (`custom` shells out to an operator script, `relay` relays to an
/// upstream that never saw the local authorizations) whose safety rests on the
/// handler getting there first. This backend refuses nothing, so if it is ever
/// called the CSR was accepted.
#[derive(Default)]
pub struct RecordingSigner {
    issued: std::sync::atomic::AtomicBool,
}

impl RecordingSigner {
    pub fn was_called(&self) -> bool {
        self.issued.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl SignerBackend for RecordingSigner {
    async fn issue(
        &self,
        _order_id: &str,
        _csr_der: &[u8],
        _identifiers: &[Identifier],
        _validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        self.issued.store(true, std::sync::atomic::Ordering::SeqCst);
        Err(SignerError::Internal("recorded".to_string()))
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Ok(())
    }
}

/// A signer backend that defers every issuance, the way a backend delegating
/// to an upstream CA does. It never finishes the work — a test using it is
/// asserting on what the *handler* does with `Processing`, not on any relay.
pub struct DelegatingSigner;

#[async_trait]
impl SignerBackend for DelegatingSigner {
    async fn issue(
        &self,
        _order_id: &str,
        _csr_der: &[u8],
        _identifiers: &[Identifier],
        _validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        Ok(IssueOutcome::Processing)
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Ok(())
    }
}

/// What a [`ScriptedAriSigner`] answers when the ARI handler asks it for a
/// renewal window.
pub enum AriAnswer {
    /// The backend has an opinion — what a backend delegating to an upstream CA
    /// returns once that CA has answered.
    Window(i64, i64),
    /// The same, plus RFC 9773 §4.2's optional `explanationURL` — the case only
    /// a delegating backend can produce, since a locally computed window has
    /// nothing to explain.
    WindowWithExplanation(i64, i64, &'static str),
    /// The backend could not reach its upstream. The handler must fall back to
    /// its local estimate rather than failing the client's request.
    Unreachable,
}

/// A signer that issues real certificates through an in-memory local CA but
/// answers `renewal_info` from a script.
///
/// `LocalCa` takes the trait's default "no opinion" (`Ok(None)`), so without
/// this the two other arms of the handler's `match` are unreachable through the
/// router — there is no test app whose signer has an ARI opinion at all.
pub struct ScriptedAriSigner {
    inner: LocalCa,
    answer: AriAnswer,
}

impl ScriptedAriSigner {
    pub fn new(answer: AriAnswer) -> Self {
        Self {
            inner: LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap(),
            answer,
        }
    }
}

#[async_trait]
impl SignerBackend for ScriptedAriSigner {
    async fn issue(
        &self,
        order_id: &str,
        csr_der: &[u8],
        identifiers: &[Identifier],
        validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        self.inner
            .issue(order_id, csr_der, identifiers, validity)
            .await
    }

    async fn revoke(&self, cert_der: &[u8], reason: Option<u32>) -> Result<(), SignerError> {
        self.inner.revoke(cert_der, reason).await
    }

    async fn renewal_info(&self, _cert_der: &[u8]) -> Result<Option<RenewalWindow>, SignerError> {
        match self.answer {
            AriAnswer::Window(start, end) => Ok(Some(RenewalWindow::new(start, end))),
            AriAnswer::WindowWithExplanation(start, end, url) => Ok(Some(RenewalWindow {
                start,
                end,
                explanation_url: Some(url.to_string()),
            })),
            AriAnswer::Unreachable => {
                Err(SignerError::Internal("upstream unreachable".to_string()))
            }
        }
    }
}

/// A signer whose `issue` succeeds but returns something that is not a PEM
/// chain — this server's own bug, since it just "issued" it. Drives the
/// finalize path's chain-parsing guards, which no real backend reaches.
pub struct GarbageChainSigner;

#[async_trait]
impl SignerBackend for GarbageChainSigner {
    async fn issue(
        &self,
        _order_id: &str,
        _csr_der: &[u8],
        _identifiers: &[Identifier],
        _validity: RequestedValidity,
    ) -> Result<IssueOutcome, SignerError> {
        Ok(IssueOutcome::Issued("not a certificate at all".to_string()))
    }

    async fn revoke(&self, _cert_der: &[u8], _reason: Option<u32>) -> Result<(), SignerError> {
        Ok(())
    }
}

/// A notify backend recording every event it receives, so a test can assert a
/// handler dispatches the right event with the right data. When built via
/// [`RecordingNotifyBackend::failing`], every `send` also returns an error —
/// used to prove a broken notify backend never affects the HTTP response.
#[derive(Default)]
pub struct RecordingNotifyBackend {
    events: Mutex<Vec<NotifyEvent>>,
    fail: bool,
}

impl RecordingNotifyBackend {
    pub fn failing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail: true,
        }
    }

    /// Every event received so far, in order.
    pub fn events(&self) -> Vec<NotifyEvent> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl NotifyBackend for RecordingNotifyBackend {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        self.events.lock().unwrap().push(event.clone());
        if self.fail {
            Err(NotifyError::new("recording backend configured to fail"))
        } else {
            Ok(())
        }
    }
}

/// A check that refuses everything, at whichever hook it is configured for.
pub struct RejectingCheck {
    pub connections: bool,
    pub identifiers: bool,
    pub internal: bool,
}

impl RejectingCheck {
    /// Refuses at the connection hook.
    pub fn connections() -> Self {
        Self {
            connections: true,
            identifiers: false,
            internal: false,
        }
    }

    /// Refuses at the identifier hook.
    pub fn identifiers() -> Self {
        Self {
            connections: false,
            identifiers: true,
            internal: false,
        }
    }

    /// Fails to reach a decision at the connection hook.
    pub fn failing() -> Self {
        Self {
            connections: true,
            identifiers: false,
            internal: true,
        }
    }

    /// Fails to reach a decision at the *identifier* hook. Distinct from
    /// [`RejectingCheck::failing`]: the two hooks are mapped to problems by
    /// different callers (the middleware vs. the handlers).
    pub fn failing_identifiers() -> Self {
        Self {
            connections: false,
            identifiers: true,
            internal: true,
        }
    }

    fn refusal(&self) -> Verdict {
        if self.internal {
            Verdict::Undecided("resolver exploded".to_string())
        } else {
            Verdict::Fail("refused by test filter".to_string())
        }
    }
}

#[async_trait]
impl Check for RejectingCheck {
    fn kind(&self) -> &'static str {
        "rejecting"
    }

    /// Both, so the stage it actually refuses at is the one its constructor
    /// chose rather than one this declaration forces.
    fn stages(&self) -> StageSet {
        StageSet::both()
    }

    async fn check_connection(&self, _context: &ConnectionContext<'_>) -> Verdict {
        if self.connections {
            return self.refusal();
        }
        Verdict::Pass
    }

    async fn check_identifiers(&self, _context: &IdentifierContext<'_>) -> Verdict {
        if self.identifiers {
            return self.refusal();
        }
        Verdict::Pass
    }
}

/// A policy where **every** named check must pass — the all-must-pass shape
/// most tests want, without writing a rule per suite.
///
/// One rule per stage, each a conjunction of the checks that can decide there,
/// which is exactly what "all of these must pass" means once checks no longer
/// all answer at both hooks. A stage with no capable check gets no rule and
/// therefore allows, which is the policy engine's own law rather than a
/// special case here.
pub fn policy_of(checks: Vec<(String, Arc<dyn Check>)>) -> Arc<FilterPolicy> {
    let mut rules = Vec::new();
    for (stage, label) in [
        (Stage::Connection, "connection"),
        (Stage::Identifiers, "identifiers"),
    ] {
        let names: Vec<&str> = checks
            .iter()
            .filter(|(_, check)| check.stages().contains(stage))
            .map(|(name, _)| name.as_str())
            .collect();
        if names.is_empty() {
            continue;
        }
        rules.push(Rule {
            name: format!("all-{label}"),
            when: Condition::parse(&names.join(" and ")).expect("test condition should parse"),
            then: Effect::Allow,
            message: None,
            mode: Mode::Enforce,
        });
    }

    Arc::new(FilterPolicy::new(
        checks,
        rules,
        Effect::Deny,
        ProxyPolicy::default(),
    ))
}

/// [`policy_of`] for the common case of a single unnamed check.
pub fn policy_with(check: Arc<dyn Check>) -> Arc<FilterPolicy> {
    policy_of(vec![("only".to_string(), check)])
}

/// Sends a request as if it arrived from `peer`, by inserting the
/// `ConnectInfo` extension that `axum::serve` would normally add.
///
/// `oneshot` drives the router without a socket, so without this the filters
/// see no client address at all.
pub async fn send_from(app: &Router, request: Request<Body>, peer: &str) -> Response {
    let addr: SocketAddr = peer.parse().expect("peer must be an ip:port");
    let mut request = request;
    request.extensions_mut().insert(ConnectInfo(addr));
    app.clone().oneshot(request).await.unwrap()
}

/// POSTs a signed ACME body as if it arrived from `peer`.
pub async fn post_from(app: &Router, path: &str, body: String, peer: &str) -> Response {
    send_from(
        app,
        Request::post(path)
            .header("content-type", "application/jose+json")
            .body(Body::from(body))
            .unwrap(),
        peer,
    )
    .await
}

/// Fetches a nonce as if from `peer`, for suites where the filter would
/// otherwise refuse an address-less request.
pub async fn fetch_nonce_from(app: &Router, peer: &str) -> String {
    let res = send_from(
        app,
        Request::get(p("/newNonce")).body(Body::empty()).unwrap(),
        peer,
    )
    .await;

    res.headers()
        .get("replay-nonce")
        .expect("newNonce response must carry a Replay-Nonce header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Reads a response body and parses it as JSON.
pub async fn body_json(response: Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Issues a real nonce by hitting the profile's `/newNonce` and returning its
/// `Replay-Nonce`
/// header value (minted and persisted by the middleware).
pub async fn fetch_nonce(app: &Router) -> String {
    let res = app
        .clone()
        .oneshot(Request::get(p("/newNonce")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    res.headers()
        .get("replay-nonce")
        .expect("newNonce response must carry a Replay-Nonce header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Assembles a flattened JWS body from an already-built `protected` header and
/// an already-encoded payload, signing the exact `protected.payload` input.
///
/// The three `build_jws*` wrappers below differ only in what goes in the header
/// (`jwk` vs `kid`) and whether the payload is encoded or empty, so the encoding
/// and signing live here once.
fn build_jws_parts(
    protected: Value,
    payload_b64: &str,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes());
    flattened_jws(&protected_b64, payload_b64, &signature)
}

/// Base64url-encodes a JSON payload the way a JWS payload segment carries it.
fn encode_payload(payload: &Value) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap())
}

/// Assembles a flattened JWS body (`{protected, payload, signature}`) with an
/// embedded `jwk` — the `newAccount` form. Public so tests can craft off-nominal
/// envelopes (e.g. a JWK whose `alg` disagrees with the key type).
pub fn build_jws(
    alg: &str,
    jwk: Value,
    url: &str,
    nonce: &str,
    payload: &Value,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let protected = json!({ "alg": alg, "jwk": jwk, "nonce": nonce, "url": url });
    build_jws_parts(protected, &encode_payload(payload), sign)
}

/// Like [`build_jws`] but uses the `kid` (account URL) form of the protected
/// header instead of an embedded `jwk` — the shape RFC 8555 §6.2 requires for
/// requests to an existing account URL (e.g. account update).
pub fn build_jws_kid(
    alg: &str,
    kid: &str,
    url: &str,
    nonce: &str,
    payload: &Value,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let protected = json!({ "alg": alg, "kid": kid, "nonce": nonce, "url": url });
    build_jws_parts(protected, &encode_payload(payload), sign)
}

/// Like [`build_jws_kid`] but with an **empty** payload, the shape RFC 8555 §6.3
/// POST-as-GET requires. The signature covers the `protected.` input (empty
/// payload segment).
pub fn build_jws_kid_empty(
    alg: &str,
    kid: &str,
    url: &str,
    nonce: &str,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let protected = json!({ "alg": alg, "kid": kid, "nonce": nonce, "url": url });
    build_jws_parts(protected, "", sign)
}

/// Like [`build_jws`] but with no `nonce` in the protected header — the shape
/// RFC 8555 §7.3.5 requires for the *inner* JWS of a `keyChange` request
/// (whose protected header MUST omit `nonce`: it is bound into a request the
/// outer JWS already replay-protects, not a second signed request in its own
/// right).
pub fn build_jws_no_nonce(
    alg: &str,
    jwk: Value,
    url: &str,
    payload: &Value,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let protected = json!({ "alg": alg, "jwk": jwk, "url": url });
    build_jws_parts(protected, &encode_payload(payload), sign)
}

/// Assembles the flattened JWS JSON string from already-encoded parts. Lets
/// tests supply a raw (possibly invalid) `payload_b64` while keeping a signature
/// that matches the exact `protected.payload` signing input.
pub fn flattened_jws(protected_b64: &str, payload_b64: &str, signature: &[u8]) -> String {
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": BASE64_URL_SAFE_NO_PAD.encode(signature),
    })
    .to_string()
}

/// Builds the inner EAB JWS object (RFC 8555 §7.3.4): protected header
/// `{alg: "HS256", kid, url}` (no nonce), payload = the account's own JWK (as
/// returned by [`TestSigner::jwk`]), HMAC-signed with `hmac_secret`. Returns
/// the JSON value to embed as `externalAccountBinding` in a `newAccount`
/// payload.
pub fn build_eab(kid: &str, hmac_secret: &[u8], url: &str, account_jwk: &Value) -> Value {
    let protected = json!({ "alg": "HS256", "kid": kid, "url": url });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(account_jwk).unwrap());
    let signing_input = format!("{protected_b64}.{payload_b64}");

    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_secret);
    let signature = hmac::sign(&key, signing_input.as_bytes());

    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
    })
}

/// What a test needs from a key to drive a signed ACME request.
///
/// `EcSigner` and `RsaSigner` differ only in their `alg`, how they expose a JWK,
/// and how they sign bytes; every envelope shape is built the same way from
/// those three. Keeping the shapes here rather than on each signer means a test
/// helper can be generic over the key type — which is what lets the order
/// lifecycle and the account-update tests run against both EC and RSA without
/// being written twice.
pub trait TestSigner {
    /// The JWS `alg` this key signs with.
    fn alg(&self) -> &'static str;
    /// The public key as a JWK, for the embedded-`jwk` (newAccount) form.
    fn jwk(&self) -> Value;
    /// Raw signature over `input`, for crafting custom JWS envelopes.
    fn sign_input(&self, input: &[u8]) -> Vec<u8>;

    /// A flattened JWS body with an embedded `jwk`.
    fn sign(&self, url: &str, nonce: &str, payload: &Value) -> String {
        build_jws(self.alg(), self.jwk(), url, nonce, payload, |input| {
            self.sign_input(input)
        })
    }

    /// A flattened JWS body in the `kid` (account URL) form.
    fn sign_kid(&self, kid: &str, url: &str, nonce: &str, payload: &Value) -> String {
        build_jws_kid(self.alg(), kid, url, nonce, payload, |input| {
            self.sign_input(input)
        })
    }

    /// A `kid`-form POST-as-GET body (empty payload).
    fn sign_kid_empty(&self, kid: &str, url: &str, nonce: &str) -> String {
        build_jws_kid_empty(self.alg(), kid, url, nonce, |input| self.sign_input(input))
    }

    /// A flattened JWS body with an embedded `jwk` and **no `nonce`** — the
    /// `keyChange` (RFC 8555 §7.3.5) inner JWS shape, self-signed by this key
    /// (the *new* account key in a rollover).
    fn sign_inner(&self, url: &str, payload: &Value) -> String {
        build_jws_no_nonce(self.alg(), self.jwk(), url, payload, |input| {
            self.sign_input(input)
        })
    }
}

/// A freshly generated EC (P-256 / ES256) signer.
pub struct EcSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl EcSigner {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Builds a signer from existing PKCS8 EC key material — used when a test
    /// needs the same key wrapped both as a JWS signer (this) and as an
    /// `rcgen::KeyPair` (to self-sign a CSR), e.g. "revoke via the
    /// certificate's own keypair". See [`make_csr_and_keypair`].
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_der, &rng)
                .unwrap();
        Self { key_pair, rng }
    }
}

impl TestSigner for EcSigner {
    fn alg(&self) -> &'static str {
        "ES256"
    }

    /// The JWK (EC public key) derived from this signer's SEC1 point `04 || x || y`.
    fn jwk(&self) -> Value {
        let sec1 = self.key_pair.public_key().as_ref();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": BASE64_URL_SAFE_NO_PAD.encode(&sec1[1..33]),
            "y": BASE64_URL_SAFE_NO_PAD.encode(&sec1[33..65]),
        })
    }

    fn sign_input(&self, input: &[u8]) -> Vec<u8> {
        self.key_pair
            .sign(&self.rng, input)
            .unwrap()
            .as_ref()
            .to_vec()
    }
}

/// An RSA (RS256) signer backed by the shared 2048-bit test key fixture.
pub struct RsaSigner {
    key_pair: RsaKeyPair,
    rng: SystemRandom,
}

impl RsaSigner {
    pub fn new() -> Self {
        let pkcs8 = include_bytes!("../fixtures/rsa_test_key.pk8");
        let key_pair = RsaKeyPair::from_pkcs8(pkcs8).unwrap();
        Self {
            key_pair,
            rng: SystemRandom::new(),
        }
    }
}

impl TestSigner for RsaSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    /// The JWK (RSA public key), deriving `n`/`e` from the PKCS#1 public key DER
    /// `SEQUENCE { INTEGER n, INTEGER e }`.
    fn jwk(&self) -> Value {
        let blocks = simple_asn1::from_der(self.key_pair.public_key().as_ref()).unwrap();
        let (n, e) = match &blocks[0] {
            ASN1Block::Sequence(_, items) => {
                let int = |block: &ASN1Block| match block {
                    ASN1Block::Integer(_, v) => v.to_bytes_be().1,
                    _ => panic!("expected INTEGER in RSA public key"),
                };
                (int(&items[0]), int(&items[1]))
            }
            _ => panic!("unexpected RSA public key DER structure"),
        };
        json!({
            "kty": "RSA",
            "n": BASE64_URL_SAFE_NO_PAD.encode(&n),
            "e": BASE64_URL_SAFE_NO_PAD.encode(&e),
        })
    }

    /// Raw RS256 signature over `input` (256-byte, 2048-bit key).
    fn sign_input(&self, input: &[u8]) -> Vec<u8> {
        let mut sig = vec![0u8; 256];
        self.key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &self.rng, input, &mut sig)
            .unwrap();
        sig
    }
}

/// A scratch directory that removes itself on drop, so a failing assertion
/// cannot leave files behind.
///
/// The library has its own copy under `src/testutil.rs`; an integration test
/// cannot see a `#[cfg(test)]` item of the crate it links against, and making
/// that one a real `pub mod` would ship test scaffolding to every consumer.
/// Two copies, deliberately — down from seven.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("acme-proxy-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes an executable script and returns its path.
///
/// See `src/testutil.rs::write_script` for why this suite must run under
/// `cargo nextest` rather than `cargo test`: every caller exec's a file it has
/// just written, which intermittently hits `ETXTBSY` when tests share one
/// process.
#[cfg(unix)]
pub fn write_script(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}
