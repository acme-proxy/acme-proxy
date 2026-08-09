//! Traceability and the CA's audit trail, through the real router.
//!
//! The unit suites cover the pieces — the enums, the model, the reverse
//! lookup, the renderers. What can only be checked here is that the pieces are
//! *reached*: that a certificate cannot be issued or withdrawn without a row
//! landing in `audit_log`, that the row carries the address the request came
//! from, and that the refusals are recorded too.
//!
//! Every request goes through `post_from`, which inserts the
//! `ConnectInfo<SocketAddr>` extension by hand — `oneshot` has no socket, so
//! without it there is no client address for any of this to record and the
//! suite would pass while asserting nothing.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

mod common;
use acme_proxy::sqlite::audit::{AuditEntry, AuditQuery};
use acme_proxy::sqlite::db::Database;
use common::{
    EcSigner, TestSigner, body_json, fetch_nonce_from, first_certificate, make_csr, p, post_from,
    test_app_with_db,
};

const CLIENT: &str = "203.0.113.7:40000";
const OTHER_CLIENT: &str = "198.51.100.4:40000";
const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";
const REVOKE_URL: &str = "http://localhost:3000/profile/default/revokeCert";

/// Every audit row, newest first.
async fn rows(database: &Arc<Database>) -> Vec<AuditEntry> {
    AuditEntry::search(
        &AuditQuery {
            limit: 100,
            ..AuditQuery::default()
        },
        database,
    )
    .await
    .unwrap()
    .0
}

async fn one_row(database: &Arc<Database>) -> AuditEntry {
    let mut rows = rows(database).await;
    assert_eq!(rows.len(), 1, "expected exactly one audit row: {rows:?}");
    rows.remove(0)
}

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Registers an account from `peer` and returns its account URL (the `kid`).
async fn register(app: &Router, signer: &impl TestSigner, peer: &str) -> String {
    let nonce = fetch_nonce_from(app, peer).await;
    let body = signer.sign(NEW_ACCOUNT_URL, &nonce, &json!({}));
    let res = post_from(app, &p("/newAccount"), body, peer).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string()
}

/// Places an order and drives it to `ready`, returning its URL.
async fn ready_order(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    peer: &str,
) -> String {
    let nonce = fetch_nonce_from(app, peer).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post_from(app, &p("/newOrder"), body, peer).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let nonce = fetch_nonce_from(app, peer).await;
    let body = signer.sign_kid_empty(account_url, &authz_url, &nonce);
    let res = post_from(
        app,
        authz_url.strip_prefix(common::HOST).unwrap(),
        body,
        peer,
    )
    .await;
    let authz = body_json(res).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let nonce = fetch_nonce_from(app, peer).await;
    let body = signer.sign_kid(account_url, &challenge_url, &nonce, &json!({}));
    let res = post_from(
        app,
        challenge_url.strip_prefix(common::HOST).unwrap(),
        body,
        peer,
    )
    .await;
    assert_eq!(body_json(res).await["status"], "valid");

    order_url
}

/// Finalizes `order_url` with `csr`, returning the response.
async fn finalize(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    order_url: &str,
    csr: &str,
    peer: &str,
) -> Response {
    let finalize_url = format!("{order_url}/finalize");
    let nonce = fetch_nonce_from(app, peer).await;
    let payload = json!({ "csr": csr });
    let body = signer.sign_kid(account_url, &finalize_url, &nonce, &payload);
    post_from(
        app,
        finalize_url.strip_prefix(common::HOST).unwrap(),
        body,
        peer,
    )
    .await
}

/// The whole lifecycle, returning the issued `leaf + CA` PEM chain.
async fn issue(app: &Router, signer: &impl TestSigner, account_url: &str, peer: &str) -> String {
    let order_url = ready_order(app, signer, account_url, peer).await;
    let res = finalize(
        app,
        signer,
        account_url,
        &order_url,
        &make_csr("example.com"),
        peer,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let nonce = fetch_nonce_from(app, peer).await;
    let body = signer.sign_kid_empty(account_url, &cert_url, &nonce);
    let res = post_from(
        app,
        cert_url.strip_prefix(common::HOST).unwrap(),
        body,
        peer,
    )
    .await;
    body_text(res).await
}

/// The account row as the database holds it — the traceability columns are
/// admin-visible only, so there is no HTTP surface to read them from.
async fn account_row(database: &Arc<Database>) -> Value {
    let row: (Option<String>, Option<i64>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT created_ip, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts LIMIT 1;",
    )
    .fetch_one(&database.pool)
    .await
    .unwrap();
    json!({
        "created_ip": row.0,
        "last_seen_at": row.1,
        "last_seen_ip": row.2,
        "last_seen_ptr": row.3,
    })
}

/// `newAccount` stamps where the account was registered from, and every later
/// signed request moves `last_seen_*` — including, and especially, when the
/// address changes.
#[tokio::test]
async fn an_account_records_where_it_was_created_and_where_it_was_last_used() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;

    let row = account_row(&database).await;
    assert_eq!(row["created_ip"], "203.0.113.7");
    // Seeded at creation rather than left NULL until the next request.
    assert_eq!(row["last_seen_ip"], "203.0.113.7");
    assert!(row["last_seen_at"].is_i64());
    // The reverse name is absent: the test harness builds an auditor with no
    // resolver, so there is nothing to look one up with. `src/audit/tests.rs`
    // drives the PTR half against a stub.
    assert_eq!(row["last_seen_ptr"], Value::Null);

    // A request from the same address inside `ACCOUNT_TOUCH_INTERVAL` is
    // throttled — this is the write that must *not* happen on every poll.
    // `POST /acct/{id}` is §7.3.2's update, so it needs a payload — an empty
    // object is the no-op form and still authenticates, which is all this
    // needs: any accepted signed request must move the mark.
    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let res = post_from(
        &app,
        account_url.strip_prefix(common::HOST).unwrap(),
        body,
        CLIENT,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(account_row(&database).await["last_seen_ip"], "203.0.113.7");

    // The same key arriving from somewhere new beats the throttle outright.
    let nonce = fetch_nonce_from(&app, OTHER_CLIENT).await;
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let res = post_from(
        &app,
        account_url.strip_prefix(common::HOST).unwrap(),
        body,
        OTHER_CLIENT,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let row = account_row(&database).await;
    assert_eq!(row["last_seen_ip"], "198.51.100.4");
    // And the creation column is untouched: it means "registered from", not
    // "last seen at".
    assert_eq!(row["created_ip"], "203.0.113.7");
}

/// A request the server refuses must not move `last_seen_*`: "last used" has to
/// mean a request that was actually accepted, or a replay from anywhere would
/// rewrite the field an operator reads to find out where a key is being used.
#[tokio::test]
async fn a_rejected_request_does_not_move_the_last_seen_columns() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;

    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    // Replaying a consumed nonce, from a different address.
    let path = account_url.strip_prefix(common::HOST).unwrap();
    let first = post_from(&app, path, body.clone(), OTHER_CLIENT).await;
    assert_eq!(first.status(), StatusCode::OK);
    // That one was accepted and did move it.
    assert_eq!(account_row(&database).await["last_seen_ip"], "198.51.100.4");

    let third = "192.0.2.9:40000";
    let replayed = post_from(&app, path, body, third).await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        account_row(&database).await["last_seen_ip"],
        "198.51.100.4",
        "a replayed nonce must not stamp the address it came from"
    );
}

/// `newOrder` freezes the address it was placed from onto the order.
#[tokio::test]
async fn an_order_records_the_address_it_was_placed_from() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    ready_order(&app, &signer, &account_url, OTHER_CLIENT).await;

    let (ip, ptr): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT created_ip, created_ptr FROM orders LIMIT 1;")
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(ip.as_deref(), Some("198.51.100.4"));
    assert_eq!(ptr, None);
}

/// The row the whole feature exists for: one per certificate signed, naming the
/// account, the profile, the address and the names covered.
#[tokio::test]
async fn issuing_a_certificate_writes_one_audit_row_with_the_requesters_address() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    assert!(
        rows(&database).await.is_empty(),
        "registering an account is not a CA action and writes no audit row"
    );

    issue(&app, &signer, &account_url, CLIENT).await;

    let row = one_row(&database).await;
    assert_eq!(row.event, "certificate_issued");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.profile, "default");
    assert_eq!(row.actor_kind, "acme");
    assert_eq!(
        row.actor_id.as_deref(),
        account_url.rsplit('/').next(),
        "the actor is the account that finalized"
    );
    assert_eq!(row.account_id, row.actor_id);
    assert!(row.order_id.is_some());
    assert!(row.cert_serial.is_some());
    assert_eq!(row.identifiers, vec!["example.com"]);
    assert_eq!(row.client_ip.as_deref(), Some("203.0.113.7"));
    // The access middleware generates one when the client sends none, so this
    // is always present and always joins the row to the tracing lines.
    assert!(row.request_id.is_some());
    assert!(row.reason.is_none());
}

/// A CSR the CA refuses is an audit row too. This is the half a
/// successes-only trail cannot answer: what was attempted and turned away.
#[tokio::test]
async fn a_refused_csr_is_recorded_as_a_failure_naming_the_problem() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    let order_url = ready_order(&app, &signer, &account_url, CLIENT).await;

    // A CSR for a name the order does not authorize.
    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        &make_csr("evil.example.net"),
        OTHER_CLIENT,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let row = one_row(&database).await;
    assert_eq!(row.event, "certificate_issue_failed");
    assert_eq!(row.outcome, "failure");
    assert_eq!(row.reason.as_deref(), Some("badCSR"));
    assert!(row.detail.is_some());
    assert!(row.cert_serial.is_none());
    // The order's *own* identifiers, not the CSR's: the row says which order
    // was being finalized, and the detail says what went wrong with it.
    assert_eq!(row.identifiers, vec!["example.com"]);
    assert_eq!(row.client_ip.as_deref(), Some("198.51.100.4"));

    // Unparsable base64 is refused earlier and recorded just the same.
    let res = finalize(
        &app,
        &signer,
        &account_url,
        &order_url,
        "not-base64!!",
        CLIENT,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rows(&database).await.len(), 2);
}

/// Revocation over ACME: the success carries the reason code, and the trail
/// ends up with one row per action rather than one per certificate.
#[tokio::test]
async fn revoking_over_acme_records_the_action_and_the_reason_code() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    let chain = issue(&app, &signer, &account_url, CLIENT).await;

    let nonce = fetch_nonce_from(&app, OTHER_CLIENT).await;
    let payload = json!({
        "certificate": BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain)),
        "reason": 1,
    });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = post_from(&app, &p("/revokeCert"), body, OTHER_CLIENT).await;
    assert_eq!(res.status(), StatusCode::OK);

    let after_revoke = rows(&database).await;
    assert_eq!(after_revoke.len(), 2, "{after_revoke:?}");
    let revoked = &after_revoke[0];
    assert_eq!(revoked.event, "certificate_revoked");
    assert_eq!(revoked.reason.as_deref(), Some("1"));
    assert_eq!(revoked.client_ip.as_deref(), Some("198.51.100.4"));
    assert_eq!(revoked.cert_serial, after_revoke[1].cert_serial);

    // A second attempt is `alreadyRevoked`, and that refusal is recorded.
    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let payload = json!({
        "certificate": BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain)),
    });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = post_from(&app, &p("/revokeCert"), body, CLIENT).await;
    // RFC 8555 gives `alreadyRevoked` a 400, not a 409 — see
    // `tests/revoke_cert.rs::double_revoke_is_already_revoked`.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let after_retry = rows(&database).await;
    assert_eq!(after_retry.len(), 3);
    assert_eq!(after_retry[0].event, "certificate_revoke_failed");
    assert_eq!(after_retry[0].reason.as_deref(), Some("alreadyRevoked"));
}

/// A revocation without a reason leaves the column **absent**: RFC 8555 §7.6
/// allows omitting it, and that is not the same as `unspecified` (0).
#[tokio::test]
async fn a_revocation_with_no_reason_records_no_reason_rather_than_zero() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    let chain = issue(&app, &signer, &account_url, CLIENT).await;

    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let payload = json!({
        "certificate": BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain)),
    });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    assert_eq!(
        post_from(&app, &p("/revokeCert"), body, CLIENT)
            .await
            .status(),
        StatusCode::OK
    );

    let written = rows(&database).await;
    assert_eq!(written[0].event, "certificate_revoked");
    assert_eq!(written[0].reason, None);
    assert!(
        !written[0]
            .to_json()
            .as_object()
            .unwrap()
            .contains_key("reason")
    );
}

/// Somebody who merely *saw* a certificate must not be able to revoke it — and
/// the attempt has to leave a trail, since a stream of these is an attack
/// rather than a client bug.
#[tokio::test]
async fn an_unauthorized_revocation_is_recorded_with_the_serial_it_targeted() {
    let (app, database) = test_app_with_db().await;
    let owner = EcSigner::new();
    let owner_url = register(&app, &owner, CLIENT).await;
    let chain = issue(&app, &owner, &owner_url, CLIENT).await;

    let stranger = EcSigner::new();
    let stranger_url = register(&app, &stranger, OTHER_CLIENT).await;

    let nonce = fetch_nonce_from(&app, OTHER_CLIENT).await;
    let payload = json!({
        "certificate": BASE64_URL_SAFE_NO_PAD.encode(first_certificate(&chain)),
    });
    let body = stranger.sign_kid(&stranger_url, REVOKE_URL, &nonce, &payload);
    let res = post_from(&app, &p("/revokeCert"), body, OTHER_CLIENT).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let written = rows(&database).await;
    assert_eq!(written[0].event, "certificate_revoke_failed");
    assert_eq!(written[0].reason.as_deref(), Some("unauthorized"));
    // The actor is the stranger who signed, not the certificate's owner.
    assert_eq!(
        written[0].actor_id.as_deref(),
        stranger_url.rsplit('/').next()
    );
    assert_eq!(written[0].client_ip.as_deref(), Some("198.51.100.4"));
    assert!(written[0].cert_serial.is_some());
}

/// A certificate this server never issued: recorded, because a run of these is
/// somebody enumerating serials.
#[tokio::test]
async fn revoking_an_unknown_certificate_is_recorded_as_a_refusal() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;

    // A syntactically valid certificate from an unrelated CA.
    let unrelated = rcgen::generate_simple_self_signed(vec!["other.example.com".to_string()])
        .unwrap()
        .cert
        .der()
        .to_vec();

    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let payload = json!({ "certificate": BASE64_URL_SAFE_NO_PAD.encode(&unrelated) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = post_from(&app, &p("/revokeCert"), body, CLIENT).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let row = one_row(&database).await;
    assert_eq!(row.event, "certificate_revoke_failed");
    assert_eq!(row.reason.as_deref(), Some("malformed"));
    assert!(row.order_id.is_none(), "there is no order to name");
    assert!(
        row.cert_serial.is_some(),
        "but the serial tried is recorded"
    );
}

/// A garbage `certificate` field never reaches an identifiable subject, so it
/// is a protocol error and not an audit row — the trail must not fill up with
/// rows naming nothing.
#[tokio::test]
async fn an_unparsable_revocation_payload_writes_no_row() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;

    for certificate in ["not-base64!!", &BASE64_URL_SAFE_NO_PAD.encode([1u8, 2, 3])] {
        let nonce = fetch_nonce_from(&app, CLIENT).await;
        let payload = json!({ "certificate": certificate });
        let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
        let res = post_from(&app, &p("/revokeCert"), body, CLIENT).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
    assert!(rows(&database).await.is_empty());
}

/// The ACME wire format is unchanged by any of this. The order and account
/// objects are defined by RFC 8555 and must not grow members naming where a
/// client connects from — those columns are admin-visible only.
#[tokio::test]
async fn the_acme_objects_expose_none_of_the_traceability_columns() {
    let (app, _database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, CLIENT).await;
    let order_url = ready_order(&app, &signer, &account_url, CLIENT).await;

    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let body = signer.sign_kid_empty(&account_url, &order_url, &nonce);
    let order = body_json(
        post_from(
            &app,
            order_url.strip_prefix(common::HOST).unwrap(),
            body,
            CLIENT,
        )
        .await,
    )
    .await;

    let nonce = fetch_nonce_from(&app, CLIENT).await;
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &json!({}));
    let account = body_json(
        post_from(
            &app,
            account_url.strip_prefix(common::HOST).unwrap(),
            body,
            CLIENT,
        )
        .await,
    )
    .await;

    for object in [&order, &account] {
        let text = object.to_string();
        assert!(!text.contains("203.0.113.7"), "{text}");
        for member in ["createdIp", "createdPtr", "lastSeenAt", "lastSeenIp"] {
            assert!(
                !object.as_object().unwrap().contains_key(member),
                "{member} leaked into {text}"
            );
        }
    }
}

/// `GET /health` and the unauthenticated surfaces write nothing: only CA
/// actions do.
#[tokio::test]
async fn the_unauthenticated_surfaces_write_no_audit_rows() {
    let (app, database) = test_app_with_db().await;
    for path in ["/health", &p("/directory"), &p("/crl")] {
        let res = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(res.status().is_success(), "{path}: {}", res.status());
    }
    assert!(rows(&database).await.is_empty());
}
