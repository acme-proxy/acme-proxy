//! Regression tests for the security defects fixed in this pass.
//!
//! Each test names the thing that used to be possible. They run through the real
//! router so they cover the handler wiring as well as the model logic, and they
//! are grouped here rather than scattered so the set is easy to re-read as a
//! whole: this is the list of ways a client could once get more than it proved.

use std::sync::Arc;

use acme_proxy::sqlite::db::Database;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, TestSigner, body_json, fetch_nonce, first_certificate, make_csr, make_csr_for, p,
    test_app, test_app_with_db,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";

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

/// Registers an account and returns its account URL (used as `kid`).
async fn register(app: &Router, signer: &impl TestSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

async fn new_order(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    dns: &str,
) -> Response {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": dns }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    post(app, &p("/newOrder"), body).await
}

async fn post_as_get(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    url: &str,
) -> Value {
    let path = url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, url, &nonce);
    let res = post(app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

/// Creates an order for `dns` and drives every challenge so it becomes `ready`.
/// Returns the order URL.
async fn ready_order(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    dns: &str,
) -> String {
    let res = new_order(app, signer, account_url, dns).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let order = post_as_get(app, signer, account_url, &order_url).await;
    for authz_url in order["authorizations"].as_array().unwrap() {
        let authz_url = authz_url.as_str().unwrap();
        let authz = post_as_get(app, signer, account_url, authz_url).await;
        for challenge in authz["challenges"].as_array().unwrap() {
            let chall_url = challenge["url"].as_str().unwrap();
            let path = chall_url.strip_prefix(common::HOST).unwrap();
            let nonce = fetch_nonce(app).await;
            let body = signer.sign_kid(account_url, chall_url, &nonce, &json!({}));
            assert_eq!(post(app, path, body).await.status(), StatusCode::OK);
        }
    }
    order_url
}

async fn finalize(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    order_url: &str,
    csr: &str,
) -> Response {
    let url = format!("{order_url}/finalize");
    let path = url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, &url, &nonce, &json!({ "csr": csr }));
    post(app, path, body).await
}

// ---------------------------------------------------------------------------
// Deactivated accounts (RFC 8555 §7.3.6)
// ---------------------------------------------------------------------------

/// Deactivating an account used to block only further *account updates*.
/// `signer_account` never looked at `status`, so the key kept full issuance
/// rights: a client could deactivate and then keep ordering certificates.
#[tokio::test]
async fn a_deactivated_account_cannot_create_an_order() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "deactivated" }),
    );
    assert_eq!(post(&app, path, body).await.status(), StatusCode::OK);

    let res = new_order(&app, &signer, &account_url, "example.com").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
}

/// Deactivation must also stop an order that was already `ready` — otherwise a
/// client could stage its orders first and cash them in afterwards.
#[tokio::test]
async fn a_deactivated_account_cannot_finalize_a_ready_order() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let order_url = ready_order(&app, &signer, &account_url, "example.com").await;

    let path = account_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(
        &account_url,
        &account_url,
        &nonce,
        &json!({ "status": "deactivated" }),
    );
    assert_eq!(post(&app, path, body).await.status(), StatusCode::OK);

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// `newAccount` must refuse a deactivated key too — on **both** its branches.
///
/// RFC 8555 §7.3.6 makes this a MUST, and every other path already kept it
/// (`signer_account` for the order side and `keyChange`, `post_account`
/// directly). `newAccount` did not: a deactivated key got `200` + `Location` +
/// its own `contact` array back, either by asking `onlyReturnExisting` or by
/// simply re-registering. Read-only and limited to the key's own holder, but a
/// hole in a boundary that is otherwise uniform — and it let a key whose account
/// had been shut down confirm the account still existed.
#[tokio::test]
async fn a_deactivated_key_is_refused_by_new_account() {
    for only_return_existing in [true, false] {
        let app = test_app().await;
        let signer = EcSigner::new();
        let account_url = register(&app, &signer).await;
        let path = account_url.strip_prefix(common::HOST).unwrap();

        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid(
            &account_url,
            &account_url,
            &nonce,
            &json!({ "status": "deactivated" }),
        );
        assert_eq!(post(&app, path, body).await.status(), StatusCode::OK);

        // Signed with `jwk`, not `kid`: `newAccount` is how a key introduces
        // itself, so there is no account named in the header to reject on.
        let nonce = fetch_nonce(&app).await;
        let payload = if only_return_existing {
            json!({ "onlyReturnExisting": true })
        } else {
            json!({ "termsOfServiceAgreed": true })
        };
        let res = post(
            &app,
            &p("/newAccount"),
            signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
        )
        .await;

        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "onlyReturnExisting={only_return_existing}"
        );
        let problem = body_json(res).await;
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");
        // And specifically not the account object it used to hand back.
        assert!(problem.get("contact").is_none());
    }
}

// ---------------------------------------------------------------------------
// Wildcards
// ---------------------------------------------------------------------------

/// A wildcard needs `dns-01` proof over the whole zone (RFC 8555 §7.1.3), so
/// with the default configuration — which offers `http-01` alone — there is no
/// challenge that could ever satisfy it. Refused up front rather than turned
/// into an authorization nobody can complete.
#[tokio::test]
async fn a_wildcard_identifier_is_rejected_when_dns_01_is_disabled() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, "*.example.com").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    // The detail names the challenge the operator would have to enable.
    assert!(
        problem["detail"].as_str().unwrap().contains("dns-01"),
        "{problem}"
    );
}

/// RFC 8555 §6.7.1: when several identifiers are rejected, the problem document
/// "MAY contain the `subproblems` field […] each of which MAY contain an
/// `identifier` field", so the client can resubmit without the bad names
/// instead of discovering them one round trip at a time.
///
/// Also pins two constraints the same section imposes: subproblems "need not
/// all have the same type", and `identifier` "MUST NOT be present at the top
/// level in ACME problem documents".
#[tokio::test]
async fn several_bad_identifiers_are_reported_together_as_subproblems() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({
        "identifiers": [
            { "type": "dns", "value": "fine.example.com" },
            { "type": "dns", "value": "*.*.example.com" },   // malformed
            { "type": "dns", "value": "*.example.com" },     // needs dns-01
        ]
    });
    let res = post(
        &app,
        &p("/newOrder"),
        signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload),
    )
    .await;

    // The most severe part decides the status: a policy refusal (403) must not
    // be downgraded to 400 by a malformed name sitting next to it.
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:compound");
    assert!(
        problem.get("identifier").is_none(),
        "§6.7.1 forbids `identifier` at the top level: {problem}"
    );

    let subproblems = problem["subproblems"].as_array().expect("subproblems");
    assert_eq!(subproblems.len(), 2, "only the bad names: {problem}");

    let by_value: Vec<(&str, &str)> = subproblems
        .iter()
        .map(|sub| {
            (
                sub["identifier"]["value"].as_str().unwrap(),
                sub["type"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(by_value.contains(&("*.*.example.com", "urn:ietf:params:acme:error:malformed")));
    assert!(by_value.contains(&(
        "*.example.com",
        "urn:ietf:params:acme:error:rejectedIdentifier"
    )));

    // The good name is not mentioned — that is what makes the list actionable.
    assert!(
        !by_value
            .iter()
            .any(|(value, _)| *value == "fine.example.com")
    );
}

/// A lone rejection stays itself. Wrapping one problem in a `compound` would
/// bury the type a client actually switches on, for no gain — which is why the
/// two wildcard tests above still assert their specific types.
#[tokio::test]
async fn a_single_bad_identifier_is_not_wrapped_in_a_compound() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, "*.example.com").await;
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    assert!(problem.get("subproblems").is_none(), "{problem}");
}

/// A `*` anywhere but as the single leading `*.` is not a wildcard anyone could
/// prove — it is a malformed identifier, and gets a 400 rather than a policy
/// refusal (RFC 8555 §6.7 draws that line).
#[tokio::test]
async fn a_malformed_wildcard_identifier_is_rejected_as_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    for value in ["*example.com", "*.*.example.com", "a.*.example.com", "*"] {
        let res = new_order(&app, &signer, &account_url, value).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{value}");
        let problem = body_json(res).await;
        assert_eq!(
            problem["type"], "urn:ietf:params:acme:error:malformed",
            "{value}"
        );
    }
}

// ---------------------------------------------------------------------------
// Identifier normalization
// ---------------------------------------------------------------------------

/// A fully-qualified name (trailing dot) and a shouted one name the same host.
/// Storing them verbatim meant a filter's anchored pattern only matched the one
/// spelling the operator happened to write; the order now records one canonical
/// form, which is also what the CSR is compared against at finalize.
#[tokio::test]
async fn identifiers_are_normalized_before_they_are_stored() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    for spelling in ["EXAMPLE.com.", "Example.COM", "example.com."] {
        let res = new_order(&app, &signer, &account_url, spelling).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let order = body_json(res).await;
        assert_eq!(
            order["identifiers"][0]["value"], "example.com",
            "{spelling} should normalize to example.com"
        );
    }
}

/// The normalized name is what the signer compares the CSR against, so an order
/// placed in one spelling finalizes with a CSR in the canonical one.
#[tokio::test]
async fn an_order_placed_with_a_trailing_dot_finalizes_normally() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let order_url = ready_order(&app, &signer, &account_url, "EXAMPLE.com.").await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Expiry (RFC 8555 §7.1.3)
// ---------------------------------------------------------------------------

/// `expires` was written and echoed but never compared against the clock, so an
/// order stayed finalizable indefinitely.
#[tokio::test]
async fn an_expired_order_cannot_be_finalized() {
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let order_url = ready_order(&app, &signer, &account_url, "example.com").await;

    expire_orders(&db).await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("expired"),
        "the problem should say the order expired, got {problem}"
    );
}

/// An expired authorization proves nothing, so triggering its challenge must not
/// carry the order to `ready`.
#[tokio::test]
async fn an_expired_authorization_cannot_be_validated() {
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let res = new_order(&app, &signer, &account_url, "example.com").await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let authz = post_as_get(&app, &signer, &account_url, &authz_url).await;
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    // Expire the authorization (and its order) behind the client's back.
    sqlx::query("UPDATE authorizations SET expires = 1;")
        .execute(&db.pool)
        .await
        .unwrap();

    let path = chall_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &chall_url, &nonce, &json!({}));
    let res = post(&app, path, body).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
}

/// An order that already produced a certificate stays readable after it expires
/// — the client still has to fetch the chain it paid for.
#[tokio::test]
async fn an_issued_order_is_still_readable_after_it_expires() {
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let order_url = ready_order(&app, &signer, &account_url, "example.com").await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    expire_orders(&db).await;

    // Both the order and its certificate remain retrievable.
    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(order["status"], "valid");

    let path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &nonce);
    assert_eq!(post(&app, path, body).await.status(), StatusCode::OK);
}

async fn expire_orders(db: &Arc<Database>) {
    sqlx::query("UPDATE orders SET expires = 1;")
        .execute(&db.pool)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Order integrity
// ---------------------------------------------------------------------------

/// The readiness check used to be "every authorization row is valid", which is
/// only equivalent to "every identifier was authorized" while the rows and the
/// identifiers stay in step. Deleting one authorization simulates the partial
/// write a non-transactional `newOrder` could leave behind: the surviving
/// challenge must not be enough to make a two-name order `ready`.
#[tokio::test]
async fn an_order_missing_an_authorization_never_becomes_ready() {
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "identifiers": [
        { "type": "dns", "value": "a.example.com" },
        { "type": "dns", "value": "b.example.com" },
    ]});
    let body = signer.sign_kid(&account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(&app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    let authz_urls: Vec<String> = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(authz_urls.len(), 2);

    // Drop the second authorization and its challenge, leaving the order row
    // still claiming two identifiers.
    let surviving = authz_urls[0].rsplit('/').next().unwrap().to_string();
    sqlx::query("DELETE FROM challenges WHERE authz_id != ?;")
        .bind(&surviving)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM authorizations WHERE id != ?;")
        .bind(&surviving)
        .execute(&db.pool)
        .await
        .unwrap();

    // Validate the one remaining challenge.
    let authz = post_as_get(&app, &signer, &account_url, &authz_urls[0]).await;
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
    let path = chall_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, &chall_url, &nonce, &json!({}));
    assert_eq!(post(&app, path, body).await.status(), StatusCode::OK);

    // The order must stay `pending`: one authorization cannot speak for two
    // identifiers.
    let order = post_as_get(&app, &signer, &account_url, &order_url).await;
    assert_eq!(
        order["status"], "pending",
        "an order with fewer authorizations than identifiers must not be ready"
    );

    // And so it cannot be finalized.
    let csr = make_csr_for(&["a.example.com", "b.example.com"]);
    let res = finalize(&app, &signer, &account_url, &order_url, &csr).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:orderNotReady");
}

// ---------------------------------------------------------------------------
// CA escalation, end to end
// ---------------------------------------------------------------------------

/// The whole flow with a CSR that asks to be a CA. It is signed — the name
/// matches the order — but the leaf that comes back must not carry the powers
/// the CSR requested. `src/signer/local_ca.rs` tests the same thing at the unit
/// level; this one proves the wiring in between does not reintroduce it.
#[tokio::test]
async fn a_csr_requesting_ca_powers_yields_a_leaf_without_them() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let order_url = ready_order(&app, &signer, &account_url, "example.com").await;

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let csr = params.serialize_request(&key_pair).unwrap();
    let csr_b64 = BASE64_URL_SAFE_NO_PAD.encode(csr.der());

    let res = finalize(&app, &signer, &account_url, &order_url, &csr_b64).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid_empty(&account_url, &cert_url, &nonce);
    let res = post(&app, path, body).await;
    assert_eq!(res.status(), StatusCode::OK);

    let pem = String::from_utf8(
        http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let leaf_der = first_certificate(&pem);
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    // Either no `basicConstraints` at all, or one saying `cA: FALSE`. Both refuse
    // CA status per RFC 5280 §6.1.4(k); the signer omits the extension.
    assert!(
        parsed
            .basic_constraints()
            .unwrap()
            .is_none_or(|bc| !bc.value.ca),
        "the issued leaf must not be a CA"
    );
    assert!(
        !parsed.key_usage().unwrap().unwrap().value.key_cert_sign(),
        "the issued leaf must not be able to sign certificates"
    );
}
