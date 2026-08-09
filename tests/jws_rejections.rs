//! Covers the `AcmeRequest` extractor's rejection branches: malformed bodies,
//! bad base64, and payloads of the wrong shape all become 400 `malformed`
//! problem documents before any handler logic runs.
//!
//! These are all one shape — "this body is rejected as `malformed`, for this
//! reason" — so they are driven from a table. `detail` is matched on a
//! distinguishing substring rather than the whole sentence: what these tests are
//! about is *which* branch rejected the request, and pinning the full prose made
//! them fail on a reworded message that changed nothing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{EcSigner, TestSigner, body_json, build_jws, fetch_nonce, flattened_jws, p, test_app};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";

async fn post(app: &axum::Router, body: String) -> Response {
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

/// Asserts a 400 `malformed` problem+json response and returns the problem body.
async fn assert_malformed(res: Response) -> Value {
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
    );
    let problem = body_json(res).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
    problem
}

/// One rejection case: a description, the request body, and a substring the
/// `detail` must contain (empty = don't care which branch, only that it was
/// rejected).
struct Case {
    name: &'static str,
    body: String,
    detail_contains: &'static str,
}

/// Builds every case. Async because several need a real nonce and signature.
async fn cases(app: &axum::Router) -> Vec<Case> {
    let signer = EcSigner::new();
    let mut cases = Vec::new();

    cases.push(Case {
        name: "a body that is not JSON at all",
        body: "not-json".to_string(),
        detail_contains: "JWS",
    });

    // Well-formed JWS envelope, but `protected` is not valid base64url.
    cases.push(Case {
        name: "protected is not base64url",
        body: json!({ "protected": "!!!not-base64!!!", "payload": "", "signature": "" })
            .to_string(),
        detail_contains: "protected",
    });

    // `protected` is valid base64url but decodes to JSON that is not a header.
    cases.push(Case {
        name: "protected decodes to the wrong JSON shape",
        body: json!({
            "protected": BASE64_URL_SAFE_NO_PAD.encode(b"{\"not\":\"a header\"}"),
            "payload": BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
            "signature": BASE64_URL_SAFE_NO_PAD.encode(b"whatever"),
        })
        .to_string(),
        detail_contains: "protected",
    });

    // `kty` is neither EC nor RSA, so the header fails to deserialize before any
    // signature check.
    let protected = json!({
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "AAAA" },
        "nonce": "n",
        "url": NEW_ACCOUNT_URL,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    cases.push(Case {
        name: "an unknown key type",
        body: flattened_jws(
            &protected_b64,
            &BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
            b"whatever",
        ),
        detail_contains: "protected",
    });

    // A fully valid, correctly signed request that additionally names a critical
    // header extension. RFC 7515 §4.1.11: a recipient that does not understand
    // every `crit` entry MUST reject the JWS — and this server understands none,
    // so the rejection stands even though everything else about the request is
    // in order. Built by hand because `build_jws` has no `crit` knob.
    let nonce = fetch_nonce(app).await;
    let protected = json!({
        "alg": "ES256",
        "jwk": signer.jwk(),
        "nonce": nonce,
        "url": NEW_ACCOUNT_URL,
        "crit": ["urn:example:unknown-extension"],
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 =
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({ "contact": [] })).unwrap());
    let sig = signer.sign_input(format!("{protected_b64}.{payload_b64}").as_bytes());
    cases.push(Case {
        name: "an unrecognized critical header extension",
        body: flattened_jws(&protected_b64, &payload_b64, &sig),
        detail_contains: "critical",
    });

    // Signature and nonce are valid, but `contact` is a number rather than an
    // array of strings, so the payload fails to deserialize into the handler type.
    let nonce = fetch_nonce(app).await;
    cases.push(Case {
        name: "a payload of the wrong shape for this endpoint",
        body: signer.sign(
            NEW_ACCOUNT_URL,
            &nonce,
            &json!({ "contact": 123, "termsOfServiceAgreed": true }),
        ),
        detail_contains: "Payload",
    });

    // Sign the exact `protected.payload` input, but make the payload field not
    // valid base64url. The signature verifies, so the request reaches — and fails
    // at — the payload-decode step.
    let nonce = fetch_nonce(app).await;
    let protected = json!({
        "alg": "ES256",
        "jwk": signer.jwk(),
        "nonce": nonce,
        "url": NEW_ACCOUNT_URL,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = "!!!not-base64!!!";
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = signer.sign_input(signing_input.as_bytes());
    cases.push(Case {
        name: "a payload that is not base64url",
        body: flattened_jws(&protected_b64, payload_b64, &sig),
        detail_contains: "payload",
    });

    // A `kid` that is not an account URL this endpoint minted. Checked before
    // any signature work, since there is no account to check a signature
    // against — a `kid` naming another profile lands here too.
    let protected = json!({
        "alg": "ES256",
        "kid": "http://localhost:3000/profile/other/acct/1",
        "nonce": "n",
        "url": NEW_ACCOUNT_URL,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    cases.push(Case {
        name: "a kid from somewhere this endpoint never minted",
        body: flattened_jws(
            &protected_b64,
            &BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
            b"whatever",
        ),
        detail_contains: "kid",
    });

    cases
}

/// A body that is not UTF-8 cannot even be read as a string, let alone parsed
/// as a JWS. It must be the same 400 `malformed` as any other unreadable body
/// rather than a panic or a 500.
#[tokio::test]
async fn a_body_that_is_not_utf8_is_malformed() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::post(p("/newAccount"))
                .header("content-type", "application/jose+json")
                .body(Body::from(vec![0xff, 0xfe, 0xfd]))
                .unwrap(),
        )
        .await
        .unwrap();

    let problem = assert_malformed(res).await;
    assert!(
        problem["detail"].as_str().unwrap().contains("HTTP Body"),
        "{problem}"
    );
}

#[tokio::test]
async fn malformed_requests_are_rejected_before_any_handler_runs() {
    let app = test_app().await;

    for case in cases(&app).await {
        let problem = assert_malformed(post(&app, case.body).await).await;
        let detail = problem["detail"].as_str().unwrap_or_default();
        assert!(
            detail
                .to_lowercase()
                .contains(&case.detail_contains.to_lowercase()),
            "{}: detail {detail:?} should mention {:?}",
            case.name,
            case.detail_contains
        );
    }
}

/// RFC 8555 §6.2: an unsupported `alg` gets its own error type, and the
/// response "MUST include an `algorithms` field […] listing the JWS algorithms
/// the server supports" — so the client can retry with one instead of guessing.
///
/// This is a distinct classification from `malformed`: the request is
/// well-formed, it just asked for something this server does not implement.
#[tokio::test]
async fn an_unsupported_algorithm_is_bad_signature_algorithm_and_lists_the_supported_ones() {
    let app = test_app().await;
    let signer = EcSigner::new();

    for (name, alg) in [
        // An EC JWK but the header claims RS256, signed with the real EC key.
        ("an alg that disagrees with the embedded key type", "RS256"),
        // An algorithm this server implements for neither key type.
        ("an algorithm nobody here implements", "ES512"),
    ] {
        let nonce = fetch_nonce(&app).await;
        let res = post(
            &app,
            build_jws(
                alg,
                signer.jwk(),
                NEW_ACCOUNT_URL,
                &nonce,
                &json!({ "termsOfServiceAgreed": true }),
                |input| signer.sign_input(input),
            ),
        )
        .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{name}");
        let problem = body_json(res).await;
        assert_eq!(
            problem["type"], "urn:ietf:params:acme:error:badSignatureAlgorithm",
            "{name}"
        );
        assert_eq!(
            problem["algorithms"],
            json!(["ES256", "RS256"]),
            "{name}: §6.2 requires the supported list"
        );
    }
}

/// RFC 8555 §6.2: an ACME body is a flattened JWS and so "must have the
/// Content-Type header field set to `application/jose+json`. If a request does
/// not meet this requirement, then the server MUST return a response with
/// status code 415".
///
/// The check has to come *before* the nonce is consumed, or a client whose
/// proxy rewrote the header would burn a nonce per attempt — hence the last
/// case, which replays the same nonce successfully after the 415.
#[tokio::test]
async fn a_body_that_is_not_jose_json_is_unsupported_media_type() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let send = |content_type: Option<&'static str>, body: String| {
        let app = app.clone();
        async move {
            let mut request = Request::post(p("/newAccount"));
            if let Some(value) = content_type {
                request = request.header("content-type", value);
            }
            app.oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap()
        }
    };

    let nonce = fetch_nonce(&app).await;
    let signed = signer.sign(
        NEW_ACCOUNT_URL,
        &nonce,
        &json!({ "termsOfServiceAgreed": true }),
    );

    for (name, content_type) in [
        ("no Content-Type at all", None),
        ("application/json", Some("application/json")),
        ("text/plain", Some("text/plain")),
        // A near-miss that must not be accepted by a prefix comparison.
        (
            "application/jose+json-ish",
            Some("application/jose+json-but-not-really"),
        ),
    ] {
        let res = send(content_type, signed.clone()).await;
        assert_eq!(
            res.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{name} should be refused with 415"
        );
        let problem = body_json(res).await;
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
        assert_eq!(problem["status"], 415);
    }

    // Parameters are part of the media type but not part of its essence, so a
    // charset must still be accepted.
    let res = send(Some("application/jose+json; charset=utf-8"), signed).await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "a charset parameter must not disqualify the media type — and the nonce \
         must have survived every 415 above"
    );
}

/// Both `jwk` and `kid`, or neither: RFC 8555 §6.2 makes them mutually
/// exclusive, and the extractor must not pick one arbitrarily.
#[tokio::test]
async fn jwk_and_kid_must_be_exactly_one() {
    let app = test_app().await;
    let signer = EcSigner::new();

    for (name, protected) in [
        (
            "both jwk and kid",
            json!({
                "alg": "ES256",
                "jwk": signer.jwk(),
                "kid": "http://localhost:3000/profile/default/acct/whatever",
                "nonce": "n",
                "url": NEW_ACCOUNT_URL,
            }),
        ),
        (
            "neither jwk nor kid",
            json!({ "alg": "ES256", "nonce": "n", "url": NEW_ACCOUNT_URL }),
        ),
    ] {
        let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = signer.sign_input(signing_input.as_bytes());
        let body = flattened_jws(&protected_b64, &payload_b64, &sig);

        let problem = assert_malformed(post(&app, body).await).await;
        let detail = problem["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("jwk") || detail.contains("kid"),
            "{name}: detail {detail:?} should name jwk/kid"
        );
    }
}

/// §6.4's `url` check runs before the account lookup, so a JWS addressed to
/// another endpoint is refused without ever reading the database.
///
/// The visible difference is which refusal comes back: a `kid` naming an
/// account that does not exist used to answer `accountDoesNotExist` — a
/// statement about the database — even when the request was not addressed to
/// this endpoint at all and nothing about it should have been examined.
#[tokio::test]
async fn a_jws_addressed_elsewhere_is_refused_before_the_account_is_looked_up() {
    let app = test_app().await;
    let signer = EcSigner::new();
    let nonce = fetch_nonce(&app).await;

    // A `kid` for an account that certainly does not exist, and a `url` naming
    // a different endpoint than the one the request is sent to.
    let protected = json!({
        "alg": "ES256",
        "kid": "http://localhost:3000/profile/default/acct/00000000-0000-4000-8000-000000000000",
        "nonce": nonce,
        "url": "http://localhost:3000/profile/default/newOrder",
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = signer.sign_input(signing_input.as_bytes());
    let body = flattened_jws(&protected_b64, &payload_b64, &sig);

    let problem = assert_malformed(post(&app, body).await).await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("URL"),
        "expected the url check to refuse first, got {problem}"
    );
}
