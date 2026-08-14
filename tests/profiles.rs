//! Covers the multi-endpoint (profile) surface: several ACME endpoints served
//! by one process, over one database, under `/profile/<name>`.
//!
//! Most of this crate is about what must **not** work across endpoints. The
//! URL prefix alone is cosmetic; what makes a profile a boundary is that
//! accounts and orders are scoped to it in the database. Without that, a client
//! could register at a permissive endpoint and then use that account at a
//! stricter one — bypassing its `eab.enabled`, and carrying orders whose
//! challenges were never really validated to a signer that relays to a public
//! CA. Each test below pins one half of that boundary.

use std::sync::Arc;

use acme_proxy::filter::policy::{Check, StageSet, Verdict};
use acme_proxy::filter::{ConnectionContext, IdentifierContext};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, HOST, TestProfile, TestSigner, body_json, first_certificate, make_csr,
    make_csr_and_keypair, send_from, test_app_with_profiles,
};

/// Two endpoints: `a` issues freely, `b` demands an External Account Binding.
/// They have distinct local CAs, so the issuer of a leaf says which one signed.
async fn two_profiles() -> Router {
    test_app_with_profiles(vec![
        TestProfile::new("a"),
        TestProfile::new("b").requiring_eab(),
    ])
    .await
    .0
}

fn base(name: &str) -> String {
    TestProfile::base(name)
}

fn path(name: &str, path: &str) -> String {
    TestProfile::path(name, path)
}

async fn post(app: &Router, path: &str, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn nonce(app: &Router, profile: &str) -> String {
    get(app, &path(profile, "/newNonce"))
        .await
        .headers()
        .get("replay-nonce")
        .expect("newNonce must hand out a nonce")
        .to_str()
        .unwrap()
        .to_string()
}

/// Registers an account at `profile` and returns its account URL.
async fn register(app: &Router, profile: &str, signer: &EcSigner) -> String {
    let n = nonce(app, profile).await;
    let body = signer.sign(
        &format!("{}/newAccount", base(profile)),
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(app, &path(profile, "/newAccount"), body).await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "registering at {profile}"
    );
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// The path a returned absolute URL maps to — the host goes, the profile
/// prefix stays.
fn to_path(url: &str) -> &str {
    url.strip_prefix(HOST).expect("URL must be under the host")
}

/// Drives one order at `profile` all the way to an issued certificate chain.
async fn issue(app: &Router, profile: &str, signer: &EcSigner, account: &str, dns: &str) -> String {
    let n = nonce(app, profile).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": dns }] });
    let body = signer.sign_kid(
        account,
        &format!("{}/newOrder", base(profile)),
        &n,
        &payload,
    );
    let res = post(app, &path(profile, "/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;

    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let n = nonce(app, profile).await;
    let body = signer.sign_kid_empty(account, &authz_url, &n);
    let authz = body_json(post(app, to_path(&authz_url), body).await).await;
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let n = nonce(app, profile).await;
    let body = signer.sign_kid(account, &chall_url, &n, &json!({}));
    assert_eq!(
        post(app, to_path(&chall_url), body).await.status(),
        StatusCode::OK
    );

    let finalize_url = format!("{order_url}/finalize");
    let n = nonce(app, profile).await;
    let body = signer.sign_kid(account, &finalize_url, &n, &json!({ "csr": make_csr(dns) }));
    let res = post(app, to_path(&finalize_url), body).await;
    assert_eq!(res.status(), StatusCode::OK, "finalize at {profile}");
    let cert_url = body_json(res).await["certificate"]
        .as_str()
        .unwrap()
        .to_string();

    let n = nonce(app, profile).await;
    let body = signer.sign_kid_empty(account, &cert_url, &n);
    let res = post(app, to_path(&cert_url), body).await;
    assert_eq!(res.status(), StatusCode::OK);
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// Each endpoint advertises its own URLs, and only its own.
#[tokio::test]
async fn each_directory_advertises_its_own_prefix() {
    let app = two_profiles().await;

    for name in ["a", "b"] {
        let directory = body_json(get(&app, &path(name, "/directory")).await).await;
        for key in ["newNonce", "newAccount", "newOrder", "revokeCert"] {
            let url = directory[key].as_str().unwrap();
            assert_eq!(
                url,
                format!("{}/{key}", base(name)),
                "{name}'s directory must advertise its own {key}"
            );
        }
    }

    // Only the EAB-requiring endpoint says so.
    let a = body_json(get(&app, &path("a", "/directory")).await).await;
    let b = body_json(get(&app, &path("b", "/directory")).await).await;
    assert!(a.get("meta").is_none());
    assert_eq!(b["meta"]["externalAccountRequired"], true);
}

/// The whole lifecycle works through a nested router — the proof that
/// `Router::nest`'s path rewriting and the RFC 8555 §6.4 `url` check agree.
#[tokio::test]
async fn a_full_lifecycle_runs_under_a_profile_prefix() {
    let app = two_profiles().await;
    let signer = EcSigner::new();
    let account = register(&app, "a", &signer).await;

    assert!(
        account.starts_with(&format!("{}/acct/", base("a"))),
        "the account URL carries the endpoint's prefix: {account}"
    );

    let chain = issue(&app, "a", &signer, &account, "example.com").await;
    assert!(chain.contains("BEGIN CERTIFICATE"));
}

/// A JWS is bound to the endpoint it was signed for: the `url` it carries names
/// one profile, and replaying it at another is refused before anything else.
#[tokio::test]
async fn a_jws_signed_for_one_profile_is_refused_at_another() {
    let app = two_profiles().await;
    let signer = EcSigner::new();

    let n = nonce(&app, "a").await;
    let body = signer.sign(
        &format!("{}/newAccount", base("a")),
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );

    let res = post(&app, &path("b", "/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

/// An account URL minted at one endpoint is not an account at another, even
/// when the `kid` is rewritten to name the second one: the row itself is
/// scoped, so there is nothing to find.
#[tokio::test]
async fn an_account_from_one_profile_is_unknown_at_another() {
    let app = two_profiles().await;
    let signer = EcSigner::new();
    let account_at_a = register(&app, "a", &signer).await;

    let id = account_at_a
        .rsplit('/')
        .next()
        .expect("the account URL ends in its id");
    let kid_at_b = format!("{}/acct/{id}", base("b"));

    let n = nonce(&app, "b").await;
    let body = signer.sign_kid(&kid_at_b, &kid_at_b, &n, &json!({}));
    let res = post(&app, &path("b", &format!("/acct/{id}")), body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
}

/// The regression this whole scoping exists for: registering where no External
/// Account Binding is required must not produce an account usable where one is.
#[tokio::test]
async fn registering_without_eab_does_not_open_an_eab_protected_profile() {
    let app = two_profiles().await;
    let signer = EcSigner::new();

    // The same key, at the endpoint that demands a binding: refused.
    let n = nonce(&app, "b").await;
    let body = signer.sign(
        &format!("{}/newAccount", base("b")),
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(&app, &path("b", "/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:externalAccountRequired"
    );

    // Registering at `a` (no binding needed) and then ordering at `b` with the
    // account `a` handed out must not work either.
    let account_at_a = register(&app, "a", &signer).await;
    let id = account_at_a.rsplit('/').next().unwrap();
    let kid_at_b = format!("{}/acct/{id}", base("b"));

    let n = nonce(&app, "b").await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&kid_at_b, &format!("{}/newOrder", base("b")), &n, &payload);
    let res = post(&app, &path("b", "/newOrder"), body).await;

    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "an account created at `a` must not be usable at `b`"
    );
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
}

/// An order lives at the endpoint it was created at. Reading it through another
/// one fails at the account lookup, so a permissive endpoint's authorizations
/// can never be spent on a stricter endpoint's signer.
#[tokio::test]
async fn an_order_is_invisible_from_another_profile() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let signer = EcSigner::new();

    let account_at_a = register(&app, "a", &signer).await;
    let account_at_b = register(&app, "b", &signer).await;

    let n = nonce(&app, "a").await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(
        &account_at_a,
        &format!("{}/newOrder", base("a")),
        &n,
        &payload,
    );
    let res = post(&app, &path("a", "/newOrder"), body).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order_id = order_url.rsplit('/').next().unwrap().to_string();

    // Same client key, its own account at `b`, asking for `a`'s order.
    let url_at_b = format!("{}/order/{order_id}", base("b"));
    let n = nonce(&app, "b").await;
    let body = signer.sign_kid_empty(&account_at_b, &url_at_b, &n);
    let res = post(&app, &path("b", &format!("/order/{order_id}")), body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

/// Each endpoint signs with its own CA and publishes its own CRL.
#[tokio::test]
async fn each_profile_issues_from_its_own_ca() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let signer = EcSigner::new();

    let account_at_a = register(&app, "a", &signer).await;
    let account_at_b = register(&app, "b", &signer).await;
    let chain_a = issue(&app, "a", &signer, &account_at_a, "a.example.com").await;
    let chain_b = issue(&app, "b", &signer, &account_at_b, "b.example.com").await;

    // Both CAs carry the same subject name, so the issuer *name* proves
    // nothing: compare the issuing certificates themselves, which is what a
    // client validating the chain would actually rely on.
    let ca_a = chain_a.split("-----BEGIN CERTIFICATE-----").nth(2).unwrap();
    let ca_b = chain_b.split("-----BEGIN CERTIFICATE-----").nth(2).unwrap();
    assert_ne!(
        ca_a, ca_b,
        "two endpoints must not share a CA unless configured to"
    );

    // …and each leaf really is the name that endpoint was asked for (the
    // subject is rcgen's own default; the SAN is what a client validates).
    let leaf_a = first_certificate(&chain_a);
    let (_, parsed_a) = x509_parser::parse_x509_certificate(&leaf_a).unwrap();
    let san = parsed_a
        .subject_alternative_name()
        .unwrap()
        .expect("the leaf carries a SAN");
    assert!(
        format!("{:?}", san.value.general_names).contains("a.example.com"),
        "the leaf is the one this endpoint issued"
    );

    let crl_a = get(&app, &path("a", "/crl")).await;
    let crl_b = get(&app, &path("b", "/crl")).await;
    assert_eq!(crl_a.status(), StatusCode::OK);
    assert_eq!(crl_b.status(), StatusCode::OK);
    let body_a = crl_a.into_body().collect().await.unwrap().to_bytes();
    let body_b = crl_b.into_body().collect().await.unwrap().to_bytes();
    assert_ne!(body_a, body_b, "each CA publishes its own CRL");
}

/// Revocation carries no account (RFC 8555 §7.6 allows the certificate's own
/// key), so the endpoint the request reached is the only thing scoping it: `b`
/// must not revoke — or even recognise — a certificate `a` issued.
#[tokio::test]
async fn a_certificate_cannot_be_revoked_through_another_profile() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let account_signer = EcSigner::new();
    let account = register(&app, "a", &account_signer).await;

    // An order whose CSR key is also a JWS signer, so revocation can be
    // authorized by the certificate's own key pair.
    let (csr, cert_key) = make_csr_and_keypair("revoke.example.com");
    let n = nonce(&app, "a").await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "revoke.example.com" }] });
    let body = account_signer.sign_kid(&account, &format!("{}/newOrder", base("a")), &n, &payload);
    let res = post(&app, &path("a", "/newOrder"), body).await;
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let n = nonce(&app, "a").await;
    let body = account_signer.sign_kid_empty(&account, &authz_url, &n);
    let authz = body_json(post(&app, to_path(&authz_url), body).await).await;
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
    let n = nonce(&app, "a").await;
    let body = account_signer.sign_kid(&account, &chall_url, &n, &json!({}));
    post(&app, to_path(&chall_url), body).await;

    let finalize_url = format!("{order_url}/finalize");
    let n = nonce(&app, "a").await;
    let body = account_signer.sign_kid(&account, &finalize_url, &n, &json!({ "csr": csr }));
    let res = post(&app, to_path(&finalize_url), body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cert_url = body_json(res).await["certificate"]
        .as_str()
        .unwrap()
        .to_string();

    let n = nonce(&app, "a").await;
    let body = account_signer.sign_kid_empty(&account, &cert_url, &n);
    let chain = String::from_utf8(
        post(&app, to_path(&cert_url), body)
            .await
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let leaf = BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain));

    // The certificate's own key, at the wrong endpoint: unknown there.
    let n = nonce(&app, "b").await;
    let body = cert_key.sign(
        &format!("{}/revokeCert", base("b")),
        &n,
        &json!({ "certificate": leaf }),
    );
    let res = post(&app, &path("b", "/revokeCert"), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );

    // …and at the right one it works, so the refusal above is about the
    // endpoint, not about the request being malformed in some other way.
    let n = nonce(&app, "a").await;
    let body = cert_key.sign(
        &format!("{}/revokeCert", base("a")),
        &n,
        &json!({ "certificate": leaf }),
    );
    assert_eq!(
        post(&app, &path("a", "/revokeCert"), body).await.status(),
        StatusCode::OK
    );
}

/// ARI is unauthenticated, so it is scoped the same way revocation is.
#[tokio::test]
async fn renewal_info_does_not_answer_for_another_profiles_certificate() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let signer = EcSigner::new();
    let account = register(&app, "a", &signer).await;
    let chain = issue(&app, "a", &signer, &account, "ari.example.com").await;

    // RFC 9773 certID = base64url(AKI).base64url(serial), built from the
    // certificate exactly as a client would. Note each profile has its own CA,
    // so `b` would reject this identifier on the AKI half even if the serials
    // collided — but the isolation being tested here is the profile-scoped
    // lookup, which is why the assertion below is about `b` specifically.
    let leaf = first_certificate(&chain);
    let cert_id = acme_proxy::cert::ari_cert_id(&leaf).unwrap();

    let at_a = get(&app, &path("a", &format!("/renewalInfo/{cert_id}"))).await;
    assert_eq!(at_a.status(), StatusCode::OK);

    let at_b = get(&app, &path("b", &format!("/renewalInfo/{cert_id}"))).await;
    assert_eq!(
        at_b.status(),
        StatusCode::BAD_REQUEST,
        "`b` knows nothing about `a`'s certificates"
    );
}

/// A filter that denies every connection, for the per-profile filtering test.
struct DenyAll;

#[async_trait]
impl Check for DenyAll {
    fn kind(&self) -> &'static str {
        "deny-all"
    }

    fn stages(&self) -> StageSet {
        StageSet::both()
    }

    async fn check_connection(&self, _ctx: &ConnectionContext<'_>) -> Verdict {
        Verdict::Fail("denied by policy".to_string())
    }

    async fn check_identifiers(&self, _ctx: &IdentifierContext<'_>) -> Verdict {
        Verdict::Pass
    }
}

/// Filters are per endpoint: one profile can be closed while the other is open,
/// which is the point of running both in one process.
#[tokio::test]
async fn filters_apply_to_their_own_profile_only() {
    let closed = common::policy_with(Arc::new(DenyAll));
    let app = test_app_with_profiles(vec![
        TestProfile::new("open"),
        TestProfile::new("closed").with_filter(closed),
    ])
    .await
    .0;

    let peer = "192.168.1.5:40000";
    let open = send_from(
        &app,
        Request::get(path("open", "/directory"))
            .body(Body::empty())
            .unwrap(),
        peer,
    )
    .await;
    assert_eq!(open.status(), StatusCode::OK);

    let closed = send_from(
        &app,
        Request::get(path("closed", "/directory"))
            .body(Body::empty())
            .unwrap(),
        peer,
    )
    .await;
    assert_eq!(closed.status(), StatusCode::FORBIDDEN);
    // That a refusal still hands back a usable nonce is a POST-only property
    // now (RFC 8555 §6.5), so it is asserted where it can be — over a signed
    // POST, in `filters.rs::a_rejection_still_carries_a_replay_nonce`. What
    // this test is about is which profile the filter applied to.
}

/// Server-level routes live at the root and nowhere else; ACME lives under a
/// profile and nowhere else. Anything in between is a 404, never a surprise.
#[tokio::test]
async fn routing_separates_server_routes_from_acme_routes() {
    let app = two_profiles().await;

    assert_eq!(get(&app, "/health").await.status(), StatusCode::OK);
    assert_eq!(
        get(&app, &path("a", "/health")).await.status(),
        StatusCode::NOT_FOUND,
        "/health is a server route, not part of an endpoint"
    );
    assert_eq!(
        get(&app, "/directory").await.status(),
        StatusCode::NOT_FOUND,
        "nothing ACME is served at the root"
    );
    assert_eq!(
        get(&app, "/profile/nope/directory").await.status(),
        StatusCode::NOT_FOUND,
        "an unconfigured profile is simply not mounted"
    );
}

/// Nonces are process-wide by design. Replay protection is unaffected: the §6.4
/// `url` check is what binds a request to its endpoint, and a nonce is single
/// use wherever it is spent.
#[tokio::test]
async fn a_nonce_minted_at_one_profile_is_accepted_at_another() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let signer = EcSigner::new();

    let n = nonce(&app, "a").await;
    let body = signer.sign(
        &format!("{}/newAccount", base("b")),
        &n,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(&app, &path("b", "/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// The same client key registering at both endpoints gets two independent
/// accounts — different ids, and deactivating one leaves the other working.
#[tokio::test]
async fn one_key_yields_one_account_per_profile() {
    let app = test_app_with_profiles(vec![TestProfile::new("a"), TestProfile::new("b")])
        .await
        .0;
    let signer = EcSigner::new();

    let at_a = register(&app, "a", &signer).await;
    let at_b = register(&app, "b", &signer).await;
    assert_ne!(at_a, at_b, "one key, two endpoints, two accounts");

    // Deactivate at `a`.
    let n = nonce(&app, "a").await;
    let body = signer.sign_kid(&at_a, &at_a, &n, &json!({ "status": "deactivated" }));
    assert_eq!(
        post(&app, to_path(&at_a), body).await.status(),
        StatusCode::OK
    );

    // `b` is untouched: it still accepts an order from the same key.
    let n = nonce(&app, "b").await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&at_b, &format!("{}/newOrder", base("b")), &n, &payload);
    let res: Response = post(&app, &path("b", "/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // …while `a` refuses, as a deactivated account must.
    let n = nonce(&app, "a").await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(&at_a, &format!("{}/newOrder", base("a")), &n, &payload);
    let res = post(&app, &path("a", "/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let _: Value = body_json(res).await;
}
