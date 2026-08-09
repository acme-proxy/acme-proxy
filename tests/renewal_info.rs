use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

use http_body_util::BodyExt;

mod common;
use common::{
    AriAnswer, EcSigner, PREFIX, ScriptedAriSigner, TestSigner, body_json, fetch_nonce,
    first_certificate, make_csr, p, test_app, test_app_with_db, test_app_with_signer,
};

/// An RFC3339 timestamp from the response, converted to epoch seconds — the
/// representation the server reasons in.
fn epoch(value: &Value) -> i64 {
    OffsetDateTime::parse(value.as_str().expect("timestamp is a string"), &Rfc3339)
        .expect("timestamp is RFC3339")
        .unix_timestamp()
}

async fn get(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
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

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";

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
    let res = post(app, cert_path, body).await;

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn cert_field(chain_pem: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(first_certificate(chain_pem))
}

/// The RFC 9773 §4.1 certID a real client would build from its certificate:
/// `base64url(AKI keyIdentifier) "." base64url(serial)`.
///
/// Derived from the certificate itself rather than hand-assembled, because the
/// AKI half is now checked — which also makes this the regression test for the
/// local CA actually *emitting* an Authority Key Identifier: without it,
/// `ari_cert_id` fails and every test in this file panics here.
fn cert_id(chain_pem: &str) -> String {
    acme_proxy::cert::ari_cert_id(&first_certificate(chain_pem))
        .expect("an issued leaf must carry an AKI, or no client can build a certID for it")
}

/// A syntactically valid certID naming a certificate that does not exist: a
/// well-formed AKI half, so the request reaches the serial lookup rather than
/// stopping at the decode.
fn unknown_cert_id() -> String {
    format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode([0xAAu8; 20]),
        BASE64_URL_SAFE_NO_PAD.encode([0x01u8, 0x02, 0x03])
    )
}

#[tokio::test]
async fn renewal_info_returns_window_for_valid_cert() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    let id = cert_id(&chain);
    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", id)).await;

    assert_eq!(res.status(), StatusCode::OK);

    // RFC 9773 §4.3: "it indicates the desired (i.e., both requested minimum
    // and maximum) amount of time to wait" — six hours, §4.2's own example.
    assert_eq!(
        res.headers().get("retry-after").unwrap().to_str().unwrap(),
        "21600"
    );

    let body = body_json(res).await;
    let window = &body["suggestedWindow"];
    assert!(window.get("start").is_some());
    assert!(window.get("end").is_some());
    // §4.2 makes `explanationURL` optional, and a locally computed window has
    // nothing to explain — so it must be absent, not present-and-empty.
    assert!(body.get("explanationURL").is_none());
}

/// RFC 9773 §4.1 builds the certID from *both* the issuer's key identifier and
/// the serial. Matching on the serial alone would answer for a certificate the
/// caller did not name — a different issuer's certificate that happens to share
/// a serial within this profile.
#[tokio::test]
async fn a_cert_id_whose_key_identifier_is_wrong_is_rejected() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    let real = cert_id(&chain);
    let serial_b64 = real.split_once('.').unwrap().1;

    // Same serial, an AKI that names nobody.
    let forged = format!(
        "{}.{serial_b64}",
        BASE64_URL_SAFE_NO_PAD.encode([0xFFu8; 20])
    );
    assert_ne!(forged, real, "the forged AKI must actually differ");

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{forged}")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = body_json(res).await;
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("key identifier"),
        "the refusal should name the mismatching half: {body}"
    );

    // The real one still works, so the check is discriminating rather than
    // simply broken.
    let res = get(&app, &format!("{PREFIX}/renewalInfo/{real}")).await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// §4.1: "All trailing `=` characters MUST be stripped from both parts."
/// A padded half is therefore not a certID a conformant client would send.
#[tokio::test]
async fn a_padded_cert_id_is_rejected() {
    let app = test_app().await;

    for id in [
        "qrvM3Q==.AQID",
        "qrvM3Q.AQID=",
        // Exactly one '.' — three parts is not the §4.1 grammar.
        "qrvM3Q.AQID.AQID",
        // Neither half may be empty.
        ".AQID",
        "qrvM3Q.",
    ] {
        let res = get(&app, &p(&format!("/renewalInfo/{id}"))).await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{id} should not parse as a certID"
        );
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:malformed"
        );
    }
}

#[tokio::test]
async fn renewal_info_returns_past_window_for_revoked_cert() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer).await;
    let chain = issue_certificate(&app, &signer, &account_url, make_csr("example.com")).await;

    let id = cert_id(&chain);

    // Revoke the certificate
    let nonce = fetch_nonce(&app).await;
    let payload = json!({ "certificate": cert_field(&chain) });
    let body = signer.sign_kid(
        &account_url,
        "http://localhost:3000/profile/default/revokeCert",
        &nonce,
        &payload,
    );
    let res = post(&app, &p("/revokeCert"), body).await;
    assert_eq!(res.status(), StatusCode::OK);

    // Get renewal info
    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", id)).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_json(res).await;
    let window = &body["suggestedWindow"];

    let start_str = window["start"].as_str().unwrap();
    let end_str = window["end"].as_str().unwrap();

    // Convert back to timestamps to check they are in the past
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let start_dt = OffsetDateTime::parse(start_str, &Rfc3339).unwrap();
    let end_dt = OffsetDateTime::parse(end_str, &Rfc3339).unwrap();
    let now = OffsetDateTime::now_utc();

    // Since we set end = now, it should be slightly in the past due to execution time
    assert!(start_dt < now);
    assert!(end_dt <= now);
}

#[tokio::test]
async fn renewal_info_rejects_invalid_id_format() {
    let app = test_app().await;
    let res = get(&app, &p("/renewalInfo/invalidformat")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

/// Les deux moitiés doivent être un base64url *valide* et le certificat
/// simplement inconnu, sinon le handler s'arrête un cran plus tôt, au décodage.
/// `"dummy"` fait 5 caractères et `5 % 4 == 1` n'est pas une longueur base64
/// possible : une version précédente de ce test visait donc « certID
/// illisible », pas « certificat inconnu », tout en portant le second nom —
/// les deux rendant le même 400 + `malformed`, rien ne le signalait.
#[tokio::test]
async fn renewal_info_rejects_unknown_certificate() {
    let app = test_app().await;

    let res = get(&app, &p(&format!("/renewalInfo/{}", unknown_cert_id()))).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = body_json(res).await;
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(
        body["detail"], "Unknown certificate",
        "doit atteindre la recherche par numéro de série, pas échouer au décodage"
    );
}

#[tokio::test]
async fn renewal_info_rejects_a_serial_that_is_not_base64url() {
    let app = test_app().await;

    let res = get(&app, &p("/renewalInfo/qrvM3Q.dummy")).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = body_json(res).await;
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("serial number encoding"),
        "doit nommer la moitié fautive : {body}"
    );
}

/// The window returned by a [`ScriptedAriSigner`]: a fixed date, unrelated
/// to the certificate's validity, so that no assertion can confuse the
/// upstream's opinion with the local calculation.
const START: i64 = 1_800_000_000;
const END: i64 = 1_800_086_400;

/// A backend that delegates to an upstream CA knows things that no local calculation
/// knows (its own rate limits, a planned mass revocation):
/// its window must take precedence over the local estimate.
#[tokio::test]
async fn an_upstream_window_is_preferred_over_the_local_estimate() {
    let signer = Arc::new(ScriptedAriSigner::new(AriAnswer::Window(START, END)));
    let (app, _db) = test_app_with_signer(signer).await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", cert_id(&chain))).await;

    assert_eq!(res.status(), StatusCode::OK);
    let window = body_json(res).await["suggestedWindow"].clone();
    assert_eq!(epoch(&window["start"]), START);
    assert_eq!(epoch(&window["end"]), END);
}

/// The opposite property, and the one that matters for availability: an
/// unreachable upstream CA must not fail the client's request, but only
/// make the server fall back on its local estimate.
#[tokio::test]
async fn an_unreachable_upstream_falls_back_to_the_local_window() {
    let signer = Arc::new(ScriptedAriSigner::new(AriAnswer::Unreachable));
    let (app, _db) = test_app_with_signer(signer).await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", cert_id(&chain))).await;

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "un amont muet ne doit pas se propager au client"
    );
    let window = body_json(res).await["suggestedWindow"].clone();

    // La fenêtre locale d'un certificat de 90 jours non révoqué est à venir.
    let start = OffsetDateTime::parse(window["start"].as_str().unwrap(), &Rfc3339).unwrap();
    let end = OffsetDateTime::parse(window["end"].as_str().unwrap(), &Rfc3339).unwrap();
    assert!(start < end);
    assert!(start > OffsetDateTime::now_utc());
}

/// RFC 9773 §4.2 : « `explanationURL` […] Clients SHOULD provide this URL to
/// their operator, if present. » Seul un backend qui délègue en a un, et il doit
/// traverser le proxy intact — c'est la seule information de contexte que ce
/// serveur ne peut pas reconstituer.
#[tokio::test]
async fn an_upstream_explanation_url_reaches_the_client() {
    const URL: &str = "https://ca.example/incidents/2026-08";
    let signer = Arc::new(ScriptedAriSigner::new(AriAnswer::WindowWithExplanation(
        START, END, URL,
    )));
    let (app, _db) = test_app_with_signer(signer).await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", cert_id(&chain))).await;

    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["explanationURL"], URL);
    assert_eq!(epoch(&body["suggestedWindow"]["start"]), START);
}

/// Revocation takes precedence over the upstream's opinion. An upstream that has
/// not yet learned of the revocation would return a future window and
/// deter the client from renewing — whereas this server *knows*
/// that the certificate is revoked.
#[tokio::test]
async fn revocation_beats_an_upstream_window_in_the_future() {
    let signer = Arc::new(ScriptedAriSigner::new(AriAnswer::Window(START, END)));
    let (app, _db) = test_app_with_signer(signer).await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;
    let id = cert_id(&chain);

    // Precondition: without revocation, it is indeed the upstream window.
    let res = get(&app, &format!("{PREFIX}/renewalInfo/{id}")).await;
    assert_eq!(
        epoch(&body_json(res).await["suggestedWindow"]["start"]),
        START
    );

    let nonce = fetch_nonce(&app).await;
    let body = ec.sign_kid(
        &account_url,
        "http://localhost:3000/profile/default/revokeCert",
        &nonce,
        &json!({ "certificate": cert_field(&chain) }),
    );
    assert_eq!(
        post(&app, &p("/revokeCert"), body).await.status(),
        StatusCode::OK
    );

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{id}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    // §4.3.2: a window that has already passed is not re-queried in one day.
    assert_eq!(
        res.headers().get("retry-after").unwrap().to_str().unwrap(),
        "60"
    );

    let window = body_json(res).await["suggestedWindow"].clone();
    let now = OffsetDateTime::now_utc();
    let start = OffsetDateTime::parse(window["start"].as_str().unwrap(), &Rfc3339).unwrap();
    let end = OffsetDateTime::parse(window["end"].as_str().unwrap(), &Rfc3339).unwrap();
    assert!(
        start < now && end <= now,
        "la fenêtre d'un certificat révoqué doit être entièrement passée, \
         pas celle que l'amont a proposée"
    );
}

/// Une commande retrouvée par son numéro de série mais dont la colonne
/// `certificate` est vide : la ligne existe, le certificat non.
#[tokio::test]
async fn renewal_info_rejects_an_order_whose_certificate_is_missing() {
    let (app, db) = test_app_with_db().await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;
    let id = cert_id(&chain);

    sqlx::query("UPDATE orders SET certificate = NULL")
        .execute(&db.pool)
        .await
        .unwrap();

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{id}")).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = body_json(res).await;
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(body["detail"], "Order does not have a certificate");
}

/// Un certificat émis avant que l'AC locale ne pose d'AKI n'en a aucun : la
/// vérification de la moitié AKI doit alors dire « impossible à vérifier », pas
/// « rejeté », sinon tout certificat émis par une version antérieure devient
/// définitivement inconsultable.
#[tokio::test]
async fn a_certificate_without_an_aki_still_answers_on_its_serial_alone() {
    let (app, db) = test_app_with_db().await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;

    // Un certificat auto-signé sans AKI, portant le même numéro de série que
    // celui que la commande a enregistré — c'est ce que produisait `local_ca`
    // avant que `use_authority_key_identifier_extension` ne soit posé.
    let leaf = first_certificate(&chain);
    let (serial_hex, _) = acme_proxy::cert::cert_serial_and_spki(&leaf).unwrap();
    let serial_bytes = hex::decode(&serial_hex).unwrap();

    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));
    let no_aki = params.self_signed(&key).unwrap();
    assert!(
        acme_proxy::cert::ari_cert_id(no_aki.der()).is_err(),
        "précondition : ce certificat ne porte pas d'AKI"
    );

    sqlx::query("UPDATE orders SET certificate = ?")
        .bind(no_aki.pem())
        .execute(&db.pool)
        .await
        .unwrap();

    // N'importe quelle moitié AKI syntaxiquement valide passe, faute de quoi
    // comparer contre.
    let id = format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode([0xAAu8; 20]),
        BASE64_URL_SAFE_NO_PAD.encode(&serial_bytes)
    );
    let res = get(&app, &format!("{PREFIX}/renewalInfo/{id}")).await;

    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_json(res).await["suggestedWindow"]["start"].is_string());
}

/// RFC 9773 §4.2 : « A RenewalInfo object in which the end timestamp equals or
/// precedes the start timestamp is invalid. Servers MUST NOT serve such a
/// response. » Vérifié à la sortie, quel que soit le producteur de la fenêtre —
/// ici un amont qui en renvoie une dégénérée.
#[tokio::test]
async fn a_degenerate_window_is_never_served() {
    let signer = Arc::new(ScriptedAriSigner::new(AriAnswer::Window(END, START)));
    let (app, _db) = test_app_with_signer(signer).await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{}", cert_id(&chain))).await;

    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "mieux vaut ne rien servir qu'une fenêtre que le client doit traiter \
         comme une absence de réponse"
    );
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
}

/// Une chaîne stockée illisible est un bug de ce serveur, pas du client : 500,
/// et surtout pas un 4xx qui inviterait le client à « corriger » sa requête.
#[tokio::test]
async fn renewal_info_reports_an_unparsable_stored_chain_as_internal() {
    let (app, db) = test_app_with_db().await;
    let ec = EcSigner::new();
    let account_url = register(&app, &ec).await;
    let chain = issue_certificate(&app, &ec, &account_url, make_csr("example.com")).await;
    let id = cert_id(&chain);

    sqlx::query("UPDATE orders SET certificate = ?")
        .bind("-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n")
        .execute(&db.pool)
        .await
        .unwrap();

    let res = get(&app, &format!("{PREFIX}/renewalInfo/{id}")).await;

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
}
