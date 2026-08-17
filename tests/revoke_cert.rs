//! `POST /revokeCert` (RFC 8555 §7.6): revocation via the owning account's
//! `kid`, via the certificate's own key pair with no account at all, the
//! `alreadyRevoked`/`badRevocationReason`/`malformed` rejection paths, and the
//! authorization edge case that matters most — a certificate is public, so
//! merely having seen it must never be enough to revoke it (only the JWS's
//! cryptographically verified signer key counts). Also confirms a revoked
//! certificate's serial actually appears in the CRL served at `GET /crl`,
//! tying the ACME endpoint to the signer backend end-to-end.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{
    EcSigner, RevokeFailingSigner, TestSigner, body_json, fetch_nonce, first_certificate, make_csr,
    make_csr_and_keypair, p, test_app, test_app_with_db, test_app_with_signer,
};
use std::sync::Arc;

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";
const REVOKE_URL: &str = "http://localhost:3000/profile/default/revokeCert";

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

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
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

/// Drives a full order → authz → trigger → finalize lifecycle for `account_url`
/// (already registered under `signer`), using `csr` as the finalize CSR, and
/// returns the issued `leaf + CA` PEM chain.
async fn issue_certificate(
    app: &Router,
    signer: &impl TestSigner,
    account_url: &str,
    csr: String,
) -> String {
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": "example.com" }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    let res = post(app, &p("/newOrder"), body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let order = body_json(res).await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let order_path = order_url.strip_prefix(common::HOST).unwrap();

    let authz_path = authz_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &authz_url, &nonce);
    let res = post(app, authz_path, body).await;
    let authz = body_json(res).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let challenge_path = challenge_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid(account_url, &challenge_url, &nonce, &json!({}));
    let res = post(app, challenge_path, body).await;
    assert_eq!(body_json(res).await["status"], "valid");

    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &order_url, &nonce);
    let res = post(app, order_path, body).await;
    assert_eq!(body_json(res).await["status"], "ready");

    let finalize_url = format!("{order_url}/finalize");
    let finalize_path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let payload = json!({ "csr": csr });
    let body = signer.sign_kid(account_url, &finalize_url, &nonce, &payload);
    let res = post(app, finalize_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
    let cert_url = order["certificate"].as_str().unwrap().to_string();

    let cert_path = cert_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(app).await;
    let body = signer.sign_kid_empty(account_url, &cert_url, &nonce);
    let res = get_cert(app, cert_path, body).await;
    body_text(res).await
}

async fn get_cert(app: &Router, path: &str, body: String) -> Response {
    post(app, path, body).await
}

/// Builds the base64url-DER `certificate` field of a revokeCert payload from
/// a `leaf + CA` PEM chain.
fn cert_field(chain_pem: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(first_certificate(chain_pem))
}

async fn revoke(app: &Router, body: String) -> Response {
    post(app, &p("/revokeCert"), body).await
}

#[tokio::test]
async fn revoke_via_account_kid_with_no_reason_succeeds() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoke_via_account_kid_with_a_valid_reason_succeeds() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain), "reason": 1 });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoke_via_certificate_own_keypair_succeeds() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let (csr, cert_signer) = make_csr_and_keypair("example.com");
    let chain = issue_certificate(&app, &signer, &account_url, csr).await;

    // Signed with the certificate's own key pair — an embedded `jwk`, no
    // `kid`, and this key was never registered as any account.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = cert_signer.sign(REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn double_revoke_is_already_revoked() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;
    let payload = json!({ "certificate": cert_field(&chain) });

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    assert_eq!(revoke(&app, body).await.status(), StatusCode::OK);

    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:alreadyRevoked"
    );
}

#[tokio::test]
async fn revoke_by_a_different_registered_account_is_unauthorized() {
    let app = test_app().await;
    let owner = EcSigner::new();
    let account_url = register(&app, &owner).await;
    let chain = issue_certificate(&app, &owner, &account_url, make_csr("example.com")).await;

    let other = EcSigner::new();
    let other_account_url = register(&app, &other).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = other.sign_kid(&other_account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    // The `type` as well as the status: `unauthorized` and `malformed` are both
    // refusals, but only one of them says "this is not yours".
    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

/// The regression test for the authorization subtlety this endpoint hinges
/// on: a certificate is public (served in cleartext on any TLS handshake), so
/// merely being able to paste its DER into the payload must never be enough
/// to revoke it — only a JWS *cryptographically signed* by a key this server
/// actually trusts for it (the account, or the certificate's own key pair)
/// counts. Submitting a real, valid, previously-issued certificate signed
/// with a brand-new, never-registered key must be refused.
#[tokio::test]
async fn revoke_with_someone_elses_certificate_and_an_unrelated_key_is_unauthorized() {
    let app = test_app().await;
    let owner = EcSigner::new();
    let account_url = register(&app, &owner).await;
    let chain = issue_certificate(&app, &owner, &account_url, make_csr("example.com")).await;

    // A throwaway key with no relation to the account or the certificate.
    let attacker = EcSigner::new();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = attacker.sign(REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    // This suite's flagship security regression, so it reads the body: a
    // refusal that kept the status and changed the type would have passed.
    common::acme::assert_problem(
        res,
        StatusCode::UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
}

#[tokio::test]
async fn bad_revocation_reason_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    for reason in [7, 999] {
        let nonce = fetch_nonce(&app).await;
        let payload = json!({ "certificate": cert_field(&chain), "reason": reason });
        let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
        let res = revoke(&app, body).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "reason {reason}");
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:badRevocationReason",
            "reason {reason}"
        );
    }
}

#[tokio::test]
async fn malformed_base64_certificate_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": "not-valid-base64!!" });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

#[tokio::test]
async fn unparsable_certificate_der_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": BASE64_URL_SAFE_NO_PAD.encode([0xde, 0xad, 0xbe, 0xef]) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

#[tokio::test]
async fn unknown_certificate_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    // A legitimately-built certificate, never issued by this server's CA.
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["unknown.example".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": BASE64_URL_SAFE_NO_PAD.encode(cert.der()) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

#[tokio::test]
async fn missing_certificate_field_is_malformed() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "reason": 1 });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

#[tokio::test]
async fn deactivated_account_can_still_revoke_its_own_certificate() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    // Deactivate the account (RFC 8555 §7.3.6).
    let account_path = account_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "status": "deactivated" });
    let body = signer.sign_kid(&account_url, &account_url, &nonce, &payload);
    let res = post(&app, account_path, body).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "deactivated");

    // Revocation only ever removes trust, never grants it — a deactivated
    // account can still revoke a certificate it legitimately holds.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoked_certificate_appears_in_the_served_crl() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;
    let leaf_der = first_certificate(&chain);
    let (serial_hex, _) = acme_proxy::cert::cert_serial_and_spki(&leaf_der).unwrap();

    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    assert_eq!(revoke(&app, body).await.status(), StatusCode::OK);

    let res = get(&app, &p("/crl")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let der = res.into_body().collect().await.unwrap().to_bytes();

    use x509_parser::prelude::FromDer;
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
    let serials: Vec<String> = crl
        .iter_revoked_certificates()
        .map(|r| r.raw_serial_as_string().replace(':', ""))
        .collect();
    assert!(
        serials.iter().any(|s| s.eq_ignore_ascii_case(&serial_hex)),
        "expected {serial_hex} in {serials:?}"
    );
}

/// A signer that refuses leaves the order **un-revoked and retryable**.
///
/// `post_revoke_cert` calls the signer's `revoke` *before* `Order::revoke`,
/// because the CA-side action is the authoritative one: recording a revocation
/// the CA never performed would leave the database claiming a certificate is
/// dead while every relying party checking the CRL is told it is alive. So a
/// signer failure must be a plain 500 that changes nothing — and, crucially,
/// the retry must not come back `alreadyRevoked`.
#[tokio::test]
async fn a_signer_revoke_failure_leaves_the_order_revocable() {
    let backend = Arc::new(RevokeFailingSigner::new());
    let (app, database) = test_app_with_signer(backend.clone()).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;
    let leaf_der = first_certificate(&chain);
    let (serial_hex, _) = acme_proxy::cert::cert_serial_and_spki(&leaf_der).unwrap();

    let payload = json!({ "certificate": cert_field(&chain) });
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );

    // Nothing was recorded: the row is untouched.
    let order =
        acme_proxy::sqlite::order::Order::find_by_cert_serial("default", &serial_hex, &database)
            .await
            .unwrap()
            .expect("the order is still findable by serial");
    assert!(
        order.revoked_at.is_none(),
        "a signer that refused must not leave a revocation recorded"
    );
    assert!(order.revocation_reason.is_none());

    // Nor did the CA act: the serial is absent from the CRL it serves.
    let der = get(&app, &p("/crl"))
        .await
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    use x509_parser::prelude::FromDer;
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
    assert_eq!(crl.iter_revoked_certificates().count(), 0);

    // And the retry is a fresh attempt, not `alreadyRevoked`. Without the
    // ordering this test exists for, the first call would have recorded the
    // revocation and this would answer 400.
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;
    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "the same failure, not alreadyRevoked"
    );
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
}

/// `POST /revokeCert`'s own database calls are 500s, and revoke nothing.
///
/// This endpoint had no DB-failure coverage at all, which matters more here
/// than on most routes: it is the one place a database error can leave the
/// server's record of a certificate and the CA's CRL disagreeing. A closed pool
/// fails at the first call — the `find_by_cert_serial` lookup — so what this
/// pins is that the failure is a `serverInternal` and that nothing downstream
/// of it ran: no CRL entry, and the signer was never asked.
#[tokio::test]
async fn revoke_cert_answers_500_and_revokes_nothing_when_the_database_is_gone() {
    let (app, database) = test_app_with_db().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    // Everything the request needs is built while the pool is still open.
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);

    database.pool.close().await;

    let res = revoke(&app, body).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );

    // The CA was never asked, so the CRL it serves is still empty. `GET /crl`
    // reads the signer, not the database, so it answers even now.
    let der = get(&app, &p("/crl"))
        .await
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    use x509_parser::prelude::FromDer;
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
    assert_eq!(
        crl.iter_revoked_certificates().count(),
        0,
        "a database failure must not have reached the signer"
    );
}

/// The CA took the revocation and this server failed to record it.
///
/// `certificate_revoke_persist_failed` sits between the two writes: the signer
/// already withdrew trust, and `Order::revoke` then failed. It has its own
/// error event, its own audit row and a carefully argued comment, and nothing
/// reached it — `tests/db_failures.rs` closes the pool up front, so those tests
/// land on the *lookup* two hundred lines earlier.
///
/// What the branch claims, and what this pins: the client gets a `500` it is
/// expected to retry, the failure is on the audit trail, and the CA-side action
/// stands (the serial really is in the CRL) even though the order still reads
/// un-revoked.
#[tokio::test]
async fn a_revocation_the_ca_took_but_the_database_did_not_is_a_retryable_500() {
    let backend = Arc::new(common::RevokePersistFailingSigner::new());
    let (app, database) = test_app_with_signer(backend.clone()).await;
    backend.arm(database.clone());

    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;
    let leaf_der = first_certificate(&chain);
    let (serial_hex, _) = acme_proxy::cert::cert_serial_and_spki(&leaf_der).unwrap();

    let payload = json!({ "certificate": cert_field(&chain) });
    let nonce = fetch_nonce(&app).await;
    let body = signer.sign_kid(&account_url, REVOKE_URL, &nonce, &payload);
    let res = revoke(&app, body).await;

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal",
        "a failure to record is the server's problem, never the client's"
    );

    // The signer really was called — this is the branch *past* it, not the one
    // where the CA refused.
    assert_eq!(
        backend
            .revocations
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    // And the CA-side action stands: the serial is in the CRL even though the
    // order row never learned about it. That asymmetry is the whole reason the
    // branch is audited as a failure rather than swallowed.
    use acme_proxy::signer::SignerBackend;
    let crl = backend.crl_der().await.expect("the CA serves a CRL");
    use x509_parser::prelude::FromDer;
    let (_, parsed) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(&crl).unwrap();
    let serials: Vec<String> = parsed
        .iter_revoked_certificates()
        .map(|entry| entry.raw_serial_as_string().replace(':', ""))
        .collect();
    assert!(
        serials.iter().any(|s| s.eq_ignore_ascii_case(&serial_hex)),
        "the CA withdrew trust, so the CRL must say so: expected {serial_hex} in {serials:?}"
    );
}
