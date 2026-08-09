//! Account `contact` validation (RFC 8555 §7.3), through the real router.
//!
//! §7.3: "The server SHOULD validate that the contact URLs in the `contact`
//! field are valid and supported by the server. If the server validates contact
//! URLs, it MUST support the `mailto` scheme." Having opted in, this server owes
//! the rest of that paragraph too — the `hfields`/multiple-address rules — and
//! the two distinct error types the registry defines for the two kinds of
//! failure.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{EcSigner, TestSigner, body_json, fetch_nonce, p, test_app};

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

/// A `newAccount` carrying `contact`.
async fn register_with(app: &Router, signer: &impl TestSigner, contact: Value) -> Response {
    let nonce = fetch_nonce(app).await;
    post(
        app,
        &p("/newAccount"),
        signer.sign(
            NEW_ACCOUNT_URL,
            &nonce,
            &json!({ "termsOfServiceAgreed": true, "contact": contact }),
        ),
    )
    .await
}

/// §7.3 makes `mailto` the one scheme a validating server MUST support. This
/// server supports nothing else — there is no other scheme it could act on —
/// so anything else is `unsupportedContact`, the error that tells a client to
/// try a different scheme rather than a different address.
#[tokio::test]
async fn a_non_mailto_scheme_is_unsupported_contact() {
    let app = test_app().await;

    for contact in [
        "tel:+15551234567",
        "https://example.com/contact",
        "not-a-url-at-all",
    ] {
        let signer = EcSigner::new();
        let res = register_with(&app, &signer, json!([contact])).await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{contact}");
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:unsupportedContact",
            "{contact}"
        );
    }
}

/// §7.3: "Clients MUST NOT provide a `mailto` URL in the `contact` field that
/// contains `hfields` [RFC6068] or more than one `addr-spec` in the `to`
/// component. If a server encounters a `mailto` contact URL that does not meet
/// these criteria, then it SHOULD reject it as invalid."
///
/// Distinct from the case above: the scheme *is* supported, so `invalidContact`
/// is the right type — the client should fix the address, not switch schemes.
#[tokio::test]
async fn a_malformed_mailto_is_invalid_contact() {
    let app = test_app().await;

    for (name, contact) in [
        ("hfields", "mailto:admin@example.com?subject=hi"),
        ("two addresses", "mailto:a@example.com,b@example.com"),
        ("no address", "mailto:"),
        ("no domain", "mailto:admin"),
        ("no local part", "mailto:@example.com"),
        ("a domain with no dot", "mailto:admin@localhost"),
    ] {
        let signer = EcSigner::new();
        let res = register_with(&app, &signer, json!([contact])).await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(
            body_json(res).await["type"],
            "urn:ietf:params:acme:error:invalidContact",
            "{name}"
        );
    }
}

/// The other side of the line: ordinary addresses, including the unusual-looking
/// ones. Refusing a valid local part would lock an operator out of their own
/// account, and §7.3 asks for a syntax check, not a deliverability check.
#[tokio::test]
async fn ordinary_addresses_are_accepted_and_stored() {
    let app = test_app().await;

    for contact in [
        "mailto:admin@example.com",
        "mailto:cert-admin+acme@sub.example.co.uk",
        // RFC 6068 permits a good deal inside the local part.
        "mailto:weird.but-legal_name@example.org",
    ] {
        let signer = EcSigner::new();
        let res = register_with(&app, &signer, json!([contact])).await;

        assert_eq!(res.status(), StatusCode::CREATED, "{contact}");
        assert_eq!(body_json(res).await["contact"], json!([contact]));
    }

    // No contact at all is fine — the field is optional (§7.3).
    let signer = EcSigner::new();
    let res = register_with(&app, &signer, json!([])).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(body_json(res).await.get("contact").is_none());
}

/// Every address is checked, not just the first — a list is only as valid as its
/// worst member, and accepting the rest would store a contact the server has
/// already decided it cannot use.
#[tokio::test]
async fn one_bad_address_rejects_the_whole_list() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let res = register_with(
        &app,
        &signer,
        json!(["mailto:good@example.com", "tel:+15551234567"]),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:unsupportedContact"
    );
}

/// The update path (§7.3.2) is validated too — otherwise a client could put
/// anything it liked in after registering, which is the same hole one step later.
#[tokio::test]
async fn a_contact_update_is_validated_as_well() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let res = register_with(&app, &signer, json!(["mailto:admin@example.com"])).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let account_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let path = account_url.strip_prefix(common::HOST).unwrap();

    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        path,
        signer.sign_kid(
            &account_url,
            &account_url,
            &nonce,
            &json!({ "contact": ["tel:+15551234567"] }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:unsupportedContact"
    );

    // …and a good update still works.
    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        path,
        signer.sign_kid(
            &account_url,
            &account_url,
            &nonce,
            &json!({ "contact": ["mailto:new@example.com"] }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        body_json(res).await["contact"],
        json!(["mailto:new@example.com"])
    );
}
