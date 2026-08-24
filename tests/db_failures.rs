//! Exercises the request-path DB-failure branches by closing the pool out from
//! under a running app.
//!
//! Two properties: a failed DB call becomes a 500 `serverInternal` rather than a
//! panic or a wrong answer, and the nonce middleware drops the `Replay-Nonce`
//! header rather than advertising a nonce it could not persist.
//!
//! The 500 cases are all the same shape — register if needed, grab a nonce, close
//! the pool, send one request — so they share a driver; only the request differs.

use std::sync::Arc;

use acme_proxy::sqlite::db::Database;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{EcSigner, PREFIX, TestSigner, body_json, fetch_nonce, p, test_app_with_db};

const BASE: &str = common::BASE;
const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";

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

/// Registers an account while the DB is still up, returning its URL.
async fn register(app: &Router, signer: &EcSigner) -> String {
    let nonce = fetch_nonce(app).await;
    let body = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true }),
    );
    let res = post(app, &p("/newAccount"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string()
}

/// Drives one case: `prepare` does whatever setup the request needs while the DB
/// is up and returns the request to send, then the pool is closed and the request
/// must come back a 500 `serverInternal`.
async fn assert_500_after_pool_close<F, Fut>(name: &str, prepare: F)
where
    F: FnOnce(Router, EcSigner, Arc<Database>) -> Fut,
    Fut: Future<Output = (Router, Arc<Database>, String, String)>,
{
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let (app, db, path, body) = prepare(app, signer, db).await;

    db.pool.close().await;

    let res = post(&app, &path, body).await;
    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "{name} should be a 500"
    );
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"], "urn:ietf:params:acme:error:serverInternal",
        "{name}"
    );
}

/// Drives one case where the failure must land **after** a successful read.
///
/// [`assert_500_after_pool_close`] closes the pool before the request, so only
/// the *first* database call in a request can fail — which is why every arm it
/// reaches is an extractor-level one, and why the handlers' own
/// `map_err(… serverInternal)` arms were unreachable from this file. `sabotage`
/// is run once the setup is done and breaks exactly one thing:
///
/// - `DROP TABLE t` makes the next **read** of `t` fail while the nonce check,
///   which runs first and needs `nonces`, still succeeds.
/// - A `BEFORE INSERT`/`BEFORE UPDATE` trigger raising `ABORT` makes the next
///   **write** to `t` fail while reads of it keep working. `PRAGMA query_only`
///   cannot serve here: consuming the nonce is itself a `DELETE`, so it would
///   fail in the extractor and prove nothing about the handler.
///
/// Foreign keys do not block the `DROP`, and nothing is restored afterwards —
/// the database is a throwaway per test.
async fn assert_500_after_sabotage<F, Fut>(name: &str, sabotage: &[&'static str], prepare: F)
where
    F: FnOnce(Router, EcSigner, Arc<Database>) -> Fut,
    Fut: Future<Output = (Router, Arc<Database>, String, String)>,
{
    let (app, db) = test_app_with_db().await;
    let signer = EcSigner::new();
    let (app, db, path, body) = prepare(app, signer, db).await;

    for statement in sabotage {
        sqlx::query(*statement)
            .execute(&db.pool)
            .await
            .unwrap_or_else(|error| panic!("{name}: sabotage `{statement}` failed: {error}"));
    }

    let res = post(&app, &path, body).await;
    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "{name} should be a 500"
    );
    let problem = body_json(res).await;
    assert_eq!(
        problem["type"], "urn:ietf:params:acme:error:serverInternal",
        "{name}"
    );
}

/// Triggers that refuse one kind of write to one table, leaving reads of it —
/// and every other table — working. Literals rather than a formatted helper:
/// `sqlx::query` takes `&'static str`, which is the point of that signature.
const REFUSE_ACCOUNT_INSERT: &str = "CREATE TRIGGER refuse_account_insert BEFORE INSERT ON \
                                     accounts BEGIN SELECT RAISE(ABORT, 'sabotage'); END;";
const REFUSE_ACCOUNT_UPDATE: &str = "CREATE TRIGGER refuse_account_update BEFORE UPDATE ON \
                                     accounts BEGIN SELECT RAISE(ABORT, 'sabotage'); END;";
const REFUSE_ORDER_INSERT: &str = "CREATE TRIGGER refuse_order_insert BEFORE INSERT ON orders \
                                   BEGIN SELECT RAISE(ABORT, 'sabotage'); END;";

/// `newAccount`'s own `INSERT`, which the pool-close driver cannot reach: the
/// nonce check fails first there, so nothing ever proved that a failed account
/// *creation* is a 500 rather than a half-registered account.
#[tokio::test]
async fn account_creation_db_error_returns_500() {
    assert_500_after_sabotage(
        "newAccount persistence",
        &[REFUSE_ACCOUNT_INSERT],
        |app, signer, db| async move {
            let nonce = fetch_nonce(&app).await;
            let body = signer.sign(
                NEW_ACCOUNT_URL,
                &nonce,
                &json!({ "termsOfServiceAgreed": true }),
            );
            (app, db, p("/newAccount"), body)
        },
    )
    .await;
}

/// §7.3.1's `onlyReturnExisting` lookup, which is a *read* and happens after
/// the nonce has already been spent.
#[tokio::test]
async fn only_return_existing_lookup_db_error_returns_500() {
    assert_500_after_sabotage(
        "newAccount onlyReturnExisting lookup",
        &["DROP TABLE accounts;"],
        |app, signer, db| async move {
            let nonce = fetch_nonce(&app).await;
            let body = signer.sign(
                NEW_ACCOUNT_URL,
                &nonce,
                &json!({ "onlyReturnExisting": true }),
            );
            (app, db, p("/newAccount"), body)
        },
    )
    .await;
}

/// `newOrder`'s own transaction, which the pool-close driver cannot reach.
///
/// `order_persistence_db_error_returns_500` above closes the pool, so its 500
/// comes from the extractor's nonce check — the first database call of the
/// request — and says nothing about `post_new_order`. This one lets the whole
/// request through and refuses only the `INSERT`, so what fails is the order
/// transaction itself.
#[tokio::test]
async fn order_transaction_db_error_returns_500() {
    assert_500_after_sabotage(
        "newOrder transaction",
        &[REFUSE_ORDER_INSERT],
        |app, signer, db| async move {
            let account_url = register(&app, &signer).await;
            let nonce = fetch_nonce(&app).await;
            let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
            let body = signer.sign_kid(&account_url, &format!("{BASE}/newOrder"), &nonce, &payload);
            (app, db, p("/newOrder"), body)
        },
    )
    .await;
}

/// `keyChange`'s `UPDATE`, after its conflict check has already read cleanly.
///
/// `key_change_db_error_returns_500` covers the extractor-level failure. This
/// covers `key_change_persist_failed`: the rollover was authorised, the new key
/// was free, and the write is what went wrong — which must be a 500 and must
/// **not** be reported as §7.3.5's `409`, since nothing else holds the key.
#[tokio::test]
async fn key_change_persist_db_error_returns_500() {
    assert_500_after_sabotage(
        "keyChange persistence",
        &[REFUSE_ACCOUNT_UPDATE],
        |app, signer, db| async move {
            let account_url = register(&app, &signer).await;
            let new_key = EcSigner::new();
            let url = format!("{BASE}/keyChange");
            let inner_payload =
                json!({ "account": account_url, "oldKey": TestSigner::jwk(&signer) });
            let inner: serde_json::Value =
                serde_json::from_str(&new_key.sign_inner(&url, &inner_payload)).unwrap();
            let nonce = fetch_nonce(&app).await;
            let body = signer.sign_kid(&account_url, &url, &nonce, &inner);
            (app, db, p("/keyChange"), body)
        },
    )
    .await;
}

/// The challenge list an authorization read builds, after the authorization
/// itself has been loaded.
///
/// `challenge_list_failed` is the last read of `post_authz`, so it is only
/// reachable once every earlier one has succeeded — dropping `challenges`
/// alone leaves the extractor, the account lookup and the authorization lookup
/// all working.
#[tokio::test]
async fn challenge_list_db_error_returns_500() {
    assert_500_after_sabotage(
        "authorization challenge list",
        &["DROP TABLE challenges;"],
        |app, signer, db| async move {
            let account_url = register(&app, &signer).await;
            let (authz_url, _challenge_url) =
                order_with_challenge(&app, &signer, &account_url).await;
            let nonce = fetch_nonce(&app).await;
            let path = authz_url.strip_prefix(common::HOST).unwrap().to_string();
            let body = signer.sign_kid_empty(&account_url, &authz_url, &nonce);
            (app, db, path, body)
        },
    )
    .await;
}

/// The extractor's own nonce verification, on the `jwk` path (`newAccount`).
#[tokio::test]
async fn nonce_verification_db_error_returns_500() {
    assert_500_after_pool_close(
        "newAccount nonce verification",
        |app, signer, db| async move {
            let nonce = fetch_nonce(&app).await;
            let body = signer.sign(
                NEW_ACCOUNT_URL,
                &nonce,
                &json!({ "termsOfServiceAgreed": true }),
            );
            (app, db, p("/newAccount"), body)
        },
    )
    .await;
}

/// The extractor's `kid` account lookup, which happens before the nonce check.
#[tokio::test]
async fn account_update_kid_lookup_db_error_returns_500() {
    assert_500_after_pool_close("kid account lookup", |app, signer, db| async move {
        let account_url = register(&app, &signer).await;
        let path = account_url.strip_prefix(common::HOST).unwrap().to_string();
        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid(
            &account_url,
            &account_url,
            &nonce,
            &json!({ "contact": [] }),
        );
        (app, db, path, body)
    })
    .await;
}

/// A `jwk`-form request to the update endpoint needs no DB in the extractor's
/// signature path, so the first failing call is the nonce verification.
#[tokio::test]
async fn account_update_nonce_db_error_returns_500() {
    assert_500_after_pool_close("account update nonce", |app, signer, db| async move {
        let id = "00000000-0000-0000-0000-000000000000";
        let account_url = format!("{BASE}/acct/{id}");
        let nonce = fetch_nonce(&app).await;
        let body = signer.sign(&account_url, &nonce, &json!({ "contact": [] }));
        (app, db, format!("{PREFIX}/acct/{id}"), body)
    })
    .await;
}

/// newOrder reaches the DB to persist the order in a transaction; a closed pool
/// there must also be a 500, not a partially written order.
#[tokio::test]
async fn order_persistence_db_error_returns_500() {
    assert_500_after_pool_close("newOrder persistence", |app, signer, db| async move {
        let account_url = register(&app, &signer).await;
        let nonce = fetch_nonce(&app).await;
        let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
        let body = signer.sign_kid(&account_url, &format!("{BASE}/newOrder"), &nonce, &payload);
        (app, db, p("/newOrder"), body)
    })
    .await;
}

/// A nonce that could not be persisted must not be advertised: the client would
/// sign its next request with something that can never verify.
///
/// Driven through `/newNonce`. This used to probe `/health`, which is a
/// server-level route *outside* the profile router and therefore outside the
/// nonce middleware entirely — so it asserted nothing about the middleware and
/// had been passing for free.
#[tokio::test]
async fn middleware_drops_replay_nonce_when_db_unavailable() {
    let (app, db) = test_app_with_db().await;
    db.pool.close().await;

    let res = app
        .clone()
        .oneshot(Request::get(p("/newNonce")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    // The handler still succeeds — §7.2's 204 for the GET form — but the nonce
    // could not be persisted, so the middleware leaves the header off rather
    // than handing out one that can never verify.
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(!res.headers().contains_key("replay-nonce"));
}

/// Creates a one-name order while the DB is up, returning `(authz_url, challenge_url)`.
async fn order_with_challenge(
    app: &Router,
    signer: &EcSigner,
    account_url: &str,
) -> (String, String) {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let res = post(
        app,
        &p("/newOrder"),
        signer.sign_kid(account_url, &format!("{BASE}/newOrder"), &nonce, &payload),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let authz_url = body_json(res).await["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();

    let nonce = fetch_nonce(app).await;
    let path = authz_url.strip_prefix(common::HOST).unwrap();
    let res = post(
        app,
        path,
        signer.sign_kid_empty(account_url, &authz_url, &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let challenge_url = body_json(res).await["challenges"][0]["url"]
        .as_str()
        .unwrap()
        .to_string();

    (authz_url, challenge_url)
}

/// Triggering a challenge with no database is a 500, not a panic.
///
/// `post_challenge` writes its outcome — challenge, authorization and order —
/// in **one** transaction, precisely so a partial write cannot park an order
/// `pending` with every authorization `valid`, a state nothing re-derives. A
/// closed pool fails at the handler's first read rather than mid-transaction,
/// so what this pins is the reachable half: the handler degrades into a problem
/// document instead of panicking, and no `Replay-Nonce` is advertised for a
/// nonce that could not be persisted.
#[tokio::test]
async fn challenge_trigger_db_error_returns_500() {
    assert_500_after_pool_close("challenge trigger", |app, signer, db| async move {
        let account_url = register(&app, &signer).await;
        let (_authz_url, challenge_url) = order_with_challenge(&app, &signer, &account_url).await;
        let nonce = fetch_nonce(&app).await;
        let path = challenge_url
            .strip_prefix(common::HOST)
            .unwrap()
            .to_string();
        let body = signer.sign_kid(&account_url, &challenge_url, &nonce, &json!({}));
        (app, db, path, body)
    })
    .await;
}

/// §7.5.2's deactivate-and-demote pair is one transaction for the same reason
/// `post_challenge`'s outcome is; same coverage caveat as above.
#[tokio::test]
async fn authorization_deactivation_db_error_returns_500() {
    assert_500_after_pool_close("authz deactivation", |app, signer, db| async move {
        let account_url = register(&app, &signer).await;
        let (authz_url, _challenge_url) = order_with_challenge(&app, &signer, &account_url).await;
        let nonce = fetch_nonce(&app).await;
        let path = authz_url.strip_prefix(common::HOST).unwrap().to_string();
        let body = signer.sign_kid(
            &account_url,
            &authz_url,
            &nonce,
            &json!({ "status": "deactivated" }),
        );
        (app, db, path, body)
    })
    .await;
}

// ---------------------------------------------------------------------------
// The write paths the suite's own docstring claimed and did not cover.
// ---------------------------------------------------------------------------

/// `keyChange` (§7.3.5): the account key swap.
///
/// A rollover that half-happened would be the worst outcome here — an account
/// whose stored key matches neither the old nor the new one is locked out for
/// good — so the failure has to be a clean `500` the client can retry.
#[tokio::test]
async fn key_change_db_error_returns_500() {
    assert_500_after_pool_close("keyChange", |app, signer, db| async move {
        let account_url = register(&app, &signer).await;
        let new_key = EcSigner::new();

        let key_change_url = format!("{BASE}/keyChange");
        let inner = new_key.sign(
            &key_change_url,
            // The inner JWS carries no nonce (§7.3.5): it proves possession,
            // it is not itself a request.
            "",
            &json!({ "account": account_url, "oldKey": signer.jwk() }),
        );
        let inner: serde_json::Value = serde_json::from_str(&inner).unwrap();

        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid(&account_url, &key_change_url, &nonce, &inner);
        (app, db, p("/keyChange"), body)
    })
    .await;
}

/// Retrieving an issued certificate by signed POST-as-GET (§7.4.2).
///
/// A read rather than a write, but it goes through the same extractor and the
/// same order lookup, and a client polling for its chain must be told to come
/// back rather than handed an empty body.
#[tokio::test]
async fn certificate_retrieval_db_error_returns_500() {
    assert_500_after_pool_close("certificate retrieval", |app, signer, db| async move {
        // One registration: `ready_order` does it, and registering again with
        // the same key is a find-or-create `200`, not a `201`.
        let (account_url, order_url, _order) =
            common::acme::ready_order(&app, &signer, &["example.com"]).await;
        let order_id = order_url.rsplit('/').next().unwrap().to_string();
        let certificate_url = format!("{BASE}/certificate/{order_id}");

        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid_empty(&account_url, &certificate_url, &nonce);
        (app, db, p(&format!("/certificate/{order_id}")), body)
    })
    .await;
}

/// `newOrder` carrying `replaces` (RFC 9773 §5): the "already replaced?" lookup
/// runs on every such order, and a database failure there must not be read as
/// "no, nothing replaces it".
#[tokio::test]
async fn replaces_lookup_db_error_returns_500() {
    assert_500_after_pool_close("newOrder replaces lookup", |app, signer, db| async move {
        let (account_url, _order_url, pem) =
            common::acme::issue_certificate(&app, &signer, &["example.com"]).await;

        let leaf = acme_proxy::cert::leaf_der_from_chain(&pem).unwrap();
        let cert_id = acme_proxy::cert::ari_cert_id(&leaf).unwrap();

        let new_order_url = format!("{BASE}/newOrder");
        let nonce = fetch_nonce(&app).await;
        let body = signer.sign_kid(
            &account_url,
            &new_order_url,
            &nonce,
            &json!({
                "identifiers": [{ "type": "dns", "value": "example.com" }],
                "replaces": cert_id,
            }),
        );
        (app, db, p("/newOrder"), body)
    })
    .await;
}
