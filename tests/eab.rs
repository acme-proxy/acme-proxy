//! Integration tests for External Account Binding (RFC 8555 §7.3.4), driven
//! through the real router the way `tests/new_account.rs` is. `test_app()`
//! (default config) never sets `eab.enabled`, so those tests are an implicit
//! regression guard that the feature stays off unless configured on.

use acme_proxy::config::Config;
use acme_proxy::sqlite::account::Account;
use acme_proxy::sqlite::eab::Eab;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, build_eab, default_challenges, fetch_nonce, p, test_app,
    test_app_with_challenges,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const DEFAULT_BASE: &str = common::BASE;

fn eab_enabled_config() -> Config {
    let mut config = Config::default();
    config.eab.enabled = true;
    config
}

async fn get_directory(app: &Router) -> Value {
    let res = app
        .clone()
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    body_json(res).await
}

async fn post_new_account(app: &Router, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(p("/newAccount"))
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Extracts the account id from a `Location: http://.../acct/{id}` header.
fn account_id_from_location(res: &Response) -> String {
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("response must carry a Location header")
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn directory_advertises_meta_when_eab_enabled() {
    let (app, _db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let directory = get_directory(&app).await;
    assert_eq!(directory["meta"]["externalAccountRequired"], true);
}

#[tokio::test]
async fn directory_omits_meta_when_eab_disabled() {
    let app = test_app().await;
    let directory = get_directory(&app).await;
    assert!(directory.get("meta").is_none());
}

#[tokio::test]
async fn missing_eab_is_rejected_when_required() {
    let (app, _db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:externalAccountRequired"
    );
}

#[tokio::test]
async fn valid_eab_creates_account_and_records_kid() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();
    let key = Eab::create(Some("customer-1".to_string()), None, &db)
        .await
        .unwrap();

    let nonce = fetch_nonce(&app).await;
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        NEW_ACCOUNT_URL,
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let account_id = {
        let location = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        location.rsplit('/').next().unwrap().to_string()
    };

    let account = Account::find_by_id(common::PROFILE, &account_id, &db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.eab_kid, Some(key.kid));
}

#[tokio::test]
async fn revoked_kid_is_rejected() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();
    let key = Eab::create(None, None, &db).await.unwrap();
    Eab::revoke(&key.kid.to_string(), &db).await.unwrap();

    let nonce = fetch_nonce(&app).await;
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        NEW_ACCOUNT_URL,
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

#[tokio::test]
async fn unknown_kid_is_rejected() {
    let (app, _db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let eab = build_eab(
        "never-created-kid",
        b"some-32-byte-long-secret-value!!",
        NEW_ACCOUNT_URL,
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

#[tokio::test]
async fn bad_hmac_signature_is_rejected() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();
    let key = Eab::create(None, None, &db).await.unwrap();

    let nonce = fetch_nonce(&app).await;
    // Signed with the wrong secret -- the kid is real and active, but the MAC
    // does not verify against the key's actual stored secret.
    let eab = build_eab(
        &key.kid.to_string(),
        b"wrong-secret-wrong-secret-wrong!",
        NEW_ACCOUNT_URL,
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

#[tokio::test]
async fn url_mismatch_is_rejected() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();
    let key = Eab::create(None, None, &db).await.unwrap();

    let nonce = fetch_nonce(&app).await;
    // The inner EAB JWS names a different URL than the request actually hit.
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        "http://localhost:3000/profile/default/somewhereElse",
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
}

#[tokio::test]
async fn payload_jwk_mismatch_is_rejected() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let account_signer = EcSigner::new();
    let other_signer = EcSigner::new();
    let key = Eab::create(None, None, &db).await.unwrap();

    let nonce = fetch_nonce(&app).await;
    // The EAB payload names `other_signer`'s key, but the outer JWS is signed
    // by `account_signer` -- the credential does not bind to this account.
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        NEW_ACCOUNT_URL,
        &other_signer.jwk(),
    );
    let body = account_signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
}

#[tokio::test]
async fn same_kid_binds_two_distinct_accounts() {
    let (app, db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let key = Eab::create(Some("team-a".to_string()), None, &db)
        .await
        .unwrap();

    let first_signer = EcSigner::new();
    let nonce = fetch_nonce(&app).await;
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        NEW_ACCOUNT_URL,
        &first_signer.jwk(),
    );
    let body = first_signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );
    let first_res = post_new_account(&app, body).await;
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_id = account_id_from_location(&first_res);

    let second_signer = EcSigner::new();
    let nonce = fetch_nonce(&app).await;
    let eab = build_eab(
        &key.kid.to_string(),
        &key.secret,
        NEW_ACCOUNT_URL,
        &second_signer.jwk(),
    );
    let body = second_signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab }),
    );
    let second_res = post_new_account(&app, body).await;
    assert_eq!(second_res.status(), StatusCode::CREATED);
    let second_id = account_id_from_location(&second_res);

    assert_ne!(first_id, second_id);
}

#[tokio::test]
async fn only_return_existing_is_exempt_from_eab() {
    let (app, _db) = test_app_with_challenges(eab_enabled_config(), default_challenges()).await;
    let signer = EcSigner::new();

    // No account exists, no externalAccountBinding is supplied, yet the
    // request must still be treated as a lookup -- not "EAB missing".
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "onlyReturnExisting": true }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
}

#[tokio::test]
async fn eab_field_is_ignored_when_disabled() {
    let app = test_app().await;
    let signer = EcSigner::new();

    // A well-shaped but entirely bogus externalAccountBinding: since EAB is
    // off, it must never even be looked at.
    let nonce = fetch_nonce(&app).await;
    let garbage_eab = build_eab(
        "nonexistent-kid",
        b"irrelevant-secret-irrelevant-sec",
        DEFAULT_BASE,
        &signer.jwk(),
    );
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true, "externalAccountBinding": garbage_eab }),
    );

    let res = post_new_account(&app, body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
}
