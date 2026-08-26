//! Covers reading an account object.
//!
//! There is no unauthenticated `GET /acct/{id}`: it would hand the account's
//! `contact` — normally an operator's email — to anyone holding the id, which
//! `newAccount` publishes in its `Location` header. RFC 8555 reads account
//! resources with a signed request, so a client fetches its own account by
//! `POSTing` an empty update (`{}`) to the account URL, which returns the object
//! unchanged.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{EcSigner, TestSigner, body_json, fetch_nonce, p, test_app};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const BASE: &str = common::BASE;

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

/// Registers an account and returns its full account URL.
async fn create_account(app: &Router, signer: &EcSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "contact": ["mailto:acct@example.com"], "termsOfServiceAgreed": true });
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &payload);

    let res = post(app, &p("/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// An empty update round-trips the account object to the key that owns it.
#[tokio::test]
async fn signed_read_returns_the_account_object() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let url = create_account(&app, &signer).await;
    let path = url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&url, &url, &nonce, &json!({}));
    let res = post(&app, path, body).await;

    assert_eq!(res.status(), StatusCode::OK);
    let account = body_json(res).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"][0], "mailto:acct@example.com");
}

/// The account URL is not a public read: without a signature there is no route
/// at all, so a plain GET cannot reach the contact address.
#[tokio::test]
async fn unsigned_get_is_not_routed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let url = create_account(&app, &signer).await;
    let path = url.strip_prefix(common::HOST).unwrap();

    let res = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// A signed read naming an account that does not exist.
#[tokio::test]
async fn signed_read_of_unknown_account_is_account_does_not_exist() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let url = format!("{BASE}/acct/00000000-0000-0000-0000-000000000000");

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&url, &url, &nonce, &json!({}));
    let res = post(&app, &p("/acct/00000000-0000-0000-0000-000000000000"), body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
    );
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
}

#[tokio::test]
async fn account_orders_list_returns_orders() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let url = create_account(&app, &signer).await;
    let orders_url = format!("{url}/orders");
    let path = orders_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&url, &orders_url, &nonce);
    let res = post(&app, path, body).await;

    assert_eq!(res.status(), StatusCode::OK);
    let body_val = body_json(res).await;
    assert!(body_val["orders"].is_array());
}

/// RFC 8555 §7.1.2.1: "The server SHOULD include pending orders and SHOULD NOT
/// include orders that are invalid in the array of URLs."
///
/// Expired orders go too: `load_owned_order` refuses one unless it is already
/// `valid`, so listing it would hand the client a URL that only ever answers
/// with an error. A `valid` order survives its own `expires`, because the
/// certificate it points at does.
#[tokio::test]
async fn the_orders_list_omits_invalid_and_expired_orders() {
    let (app, db) = common::test_app_with_db().await;
    let signer = EcSigner::new();
    let url = create_account(&app, &signer).await;

    // Four orders, one of each shape this test cares about.
    let mut ids = Vec::new();
    for name in ["pending", "gone-invalid", "expired", "issued"] {
        let nonce = fetch_nonce(&app).await;
        let res = post(
            &app,
            &p("/newOrder"),
            signer.sign_kid(
                &url,
                &format!("{BASE}/newOrder"),
                &nonce,
                &json!({ "identifiers": [{ "type": "dns", "value": format!("{name}.example.com") }] }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        ids.push(
            res.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string(),
        );
    }

    sqlx::query("UPDATE orders SET status = 'invalid' WHERE id = ?")
        .bind(ids[1].parse::<uuid::Uuid>().unwrap())
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE orders SET expires = 1 WHERE id = ?")
        .bind(ids[2].parse::<uuid::Uuid>().unwrap())
        .execute(&db.pool)
        .await
        .unwrap();
    // Valid *and* long expired: the certificate outlives the order object.
    sqlx::query("UPDATE orders SET status = 'valid', expires = 1 WHERE id = ?")
        .bind(ids[3].parse::<uuid::Uuid>().unwrap())
        .execute(&db.pool)
        .await
        .unwrap();

    let orders_url = format!("{url}/orders");
    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        orders_url.strip_prefix(common::HOST).unwrap(),
        signer.sign_kid_empty(&url, &orders_url, &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let listed: Vec<String> = body_json(res).await["orders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|url| {
            url.as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();

    assert!(listed.contains(&ids[0]), "a pending order is listed");
    assert!(!listed.contains(&ids[1]), "an invalid order is not");
    assert!(!listed.contains(&ids[2]), "an expired order is not");
    assert!(
        listed.contains(&ids[3]),
        "a valid order survives its own expiry: its certificate URL still works"
    );
}

#[tokio::test]
async fn account_orders_list_by_different_account_is_unauthorized() {
    let app = test_app().await;
    let signer1 = EcSigner::new();
    let url1 = create_account(&app, &signer1).await;
    let orders_url1 = format!("{url1}/orders");
    let path1 = orders_url1.strip_prefix(common::HOST).unwrap();

    let signer2 = EcSigner::new();
    let url2 = create_account(&app, &signer2).await;

    let nonce = fetch_nonce(&app).await;
    let body = signer2.sign_kid_empty(&url2, &orders_url1, &nonce);
    let res = post(&app, path1, body).await;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}
