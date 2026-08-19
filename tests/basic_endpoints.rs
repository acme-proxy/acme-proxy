use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{BASE, EcSigner, TestSigner, body_json, fetch_nonce, flattened_jws, p, test_app};

/// POSTs a signed body to a profile path.
async fn post(app: &axum::Router, path: &str, body: String) -> Response {
    app.clone()
        .oneshot(
            Request::post(p(path))
                .header("content-type", "application/jose+json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// A POST-as-GET body in the embedded-`jwk` form — an empty payload, which is
/// what RFC 8555 §6.3 defines the shape to be.
///
/// The harness only ships a `kid`-form equivalent (`sign_kid_empty`), and a
/// `kid` has to name a real account; the directory and `newNonce` are exactly
/// the two resources a client reads *before* it has one.
fn post_as_get(signer: &EcSigner, url: &str, nonce: &str) -> String {
    let protected = json!({
        "alg": signer.alg(),
        "jwk": signer.jwk(),
        "nonce": nonce,
        "url": url,
    });
    let protected_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
    let sig = signer.sign_input(format!("{protected_b64}.").as_bytes());
    flattened_jws(&protected_b64, "", &sig)
}

#[tokio::test]
async fn health_returns_ok_json() {
    let res = test_app()
        .await
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["healthy"], true);
}

#[tokio::test]
async fn directory_lists_only_routed_endpoints() {
    let res = test_app()
        .await
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;

    for key in [
        "newNonce",
        "newAccount",
        "newOrder",
        "revokeCert",
        "keyChange",
        "renewalInfo",
    ] {
        assert!(json.get(key).is_some(), "directory is missing `{key}`");
    }
    // `crl` and `ca.pem` are deliberately never advertised — both are CA
    // infrastructure, not ACME resources, and §7.1.1 defines no member either
    // could go under (see tests/crl.rs and tests/ca_chain.rs).
    for key in ["crl", "ca.pem", "caChain"] {
        assert!(
            json.get(key).is_none(),
            "directory should not advertise unrouted `{key}`"
        );
    }
}

/// Every path the directory advertises is a path the router actually mounts.
///
/// The two used to be written out separately — once as routes in
/// `build_router`, once as URLs in `get_directory` — and agreed only by
/// inspection. They now share `acme_proxy::routes`, and this drives each
/// advertised URL as a real request to prove the constants are wired to both
/// sides rather than merely existing.
#[tokio::test]
async fn every_advertised_endpoint_is_actually_mounted() {
    let app = test_app().await;
    let directory = body_json(
        app.clone()
            .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await;

    for (key, value) in directory.as_object().expect("the directory is an object") {
        // `meta` is a nested object of policy, not endpoints.
        let Some(url) = value.as_str() else { continue };
        let path = url
            .strip_prefix(common::HOST)
            .unwrap_or_else(|| panic!("`{key}` is not under this server: {url}"));
        // `renewalInfo` is advertised bare — RFC 9773 §4.1 has the client
        // append the certID — so it is exercised with one appended.
        let path = if key == "renewalInfo" {
            format!("{path}/aYhfVA.AAAA")
        } else {
            path.to_string()
        };

        let response = app
            .clone()
            .oneshot(Request::get(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "`{key}` is advertised at {path} but nothing is mounted there"
        );
    }
}

#[tokio::test]
async fn root_redirects_to_health() {
    let res = test_app()
        .await
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/health"),
    );
}

/// Both newNonce methods answer, and both forbid caching: RFC 8555 §7.2. A
/// cached nonce is one the server will reject as already spent, so the client
/// would see a `badNonce` it cannot explain.
#[tokio::test]
async fn new_nonce_answers_and_forbids_caching() {
    for (request, expected) in [
        (Request::get(p("/newNonce")), StatusCode::NO_CONTENT),
        (Request::head(p("/newNonce")), StatusCode::OK),
    ] {
        let method = request.method_ref().unwrap().clone();
        let res = test_app()
            .await
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), expected, "{method} /newNonce");
        assert_eq!(
            res.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "{method} /newNonce must not be cacheable"
        );
        assert!(
            res.headers().contains_key("replay-nonce"),
            "{method} /newNonce must hand out a nonce"
        );
    }
}

/// RFC 8555 §6.3: "The server MUST allow GET requests for the directory and
/// newNonce resources […] in addition to POST-as-GET requests for these
/// resources. This enables clients to bootstrap into the ACME authentication
/// system."
///
/// Both forms must therefore work, and the POST form must be a *real*
/// POST-as-GET — signed, nonce-consuming — not an unauthenticated alias.
#[tokio::test]
async fn directory_and_new_nonce_answer_post_as_get() {
    let app = test_app().await;
    let signer = EcSigner::new();

    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        "/directory",
        post_as_get(&signer, &format!("{BASE}/directory"), &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    assert_eq!(json["newOrder"], format!("{BASE}/newOrder"));

    let nonce = fetch_nonce(&app).await;
    let res = post(
        &app,
        "/newNonce",
        post_as_get(&signer, &format!("{BASE}/newNonce"), &nonce),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
    );
    assert!(res.headers().contains_key("replay-nonce"));

    // The signed form still consumes its nonce (§6.5), so replaying it fails.
    let nonce = fetch_nonce(&app).await;
    let body = post_as_get(&signer, &format!("{BASE}/newNonce"), &nonce);
    assert_eq!(
        post(&app, "/newNonce", body.clone()).await.status(),
        StatusCode::OK
    );
    let replayed = post(&app, "/newNonce", body).await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(replayed).await["type"],
        "urn:ietf:params:acme:error:badNonce"
    );
}

/// RFC 8555 §6.3: "if the server receives a GET request, it MUST return an
/// error with status code 405 (Method Not Allowed) and type `malformed`".
///
/// axum's built-in method-not-allowed response gets the status right but sends
/// an empty body, so the *type* half is what this pins.
#[tokio::test]
async fn a_get_of_a_post_only_resource_is_405_malformed() {
    let app = test_app().await;

    for path in ["/newAccount", "/newOrder", "/revokeCert", "/keyChange"] {
        let res = app
            .clone()
            .oneshot(Request::get(p(path)).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "GET {path}");
        assert_eq!(
            res.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "GET {path} must carry a problem document, not an empty body"
        );
        let problem = body_json(res).await;
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
        assert_eq!(problem["status"], 405);
    }

    // Same treatment for a path that routes nowhere, so an unknown resource is
    // never an empty-bodied 404.
    let res = app
        .oneshot(Request::get(p("/nope")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(res).await["type"],
        "urn:ietf:params:acme:error:malformed"
    );
}

/// RFC 8555 §7.1: "The `index` link relation is present on all resources other
/// than the directory and indicates the URL of the directory."
#[tokio::test]
async fn every_resource_but_the_directory_links_to_the_index() {
    let app = test_app().await;

    for path in ["/newNonce", "/newAccount", "/nope"] {
        let res = app
            .clone()
            .oneshot(Request::get(p(path)).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let links: Vec<&str> = res
            .headers()
            .get_all("link")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        assert!(
            links.contains(&format!("<{BASE}/directory>;rel=\"index\"").as_str()),
            "{path} should carry the index link, got {links:?}"
        );
    }

    // …"other than the directory": a directory pointing at itself says nothing.
    let res = app
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(
        !res.headers().contains_key("link"),
        "the directory itself must not carry an index link"
    );
}

/// RFC 8555 §6.5 asks for a `Replay-Nonce` on every response to a POST, and
/// §7.2 on `newNonce`. Not on anything else — and minting one anyway cost a
/// committed database write per unauthenticated GET, on exactly the requests
/// (directory polls, CRL fetches) that dominate a real deployment's traffic.
#[tokio::test]
async fn only_the_responses_rfc8555_asks_for_carry_a_replay_nonce() {
    let app = test_app().await;

    let has_nonce = |res: axum::response::Response| res.headers().contains_key("replay-nonce");

    // §7.2: newNonce hands one out in each of its three forms.
    for request in [
        Request::get(p("/newNonce")).body(Body::empty()).unwrap(),
        Request::head(p("/newNonce")).body(Body::empty()).unwrap(),
    ] {
        let res = app.clone().oneshot(request).await.unwrap();
        assert!(has_nonce(res), "newNonce must always mint a nonce");
    }

    // §6.5: every response to a POST, including an error — a client that has
    // just burnt a nonce needs the next one, or it round-trips `newNonce`
    // before it can even retry.
    let res = app
        .clone()
        .oneshot(
            Request::post(p("/newAccount"))
                .header("content-type", "application/jose+json")
                .body(Body::from("not a jws"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        has_nonce(res),
        "an error response to a POST must still carry a nonce (§6.5)"
    );

    // And nothing else does.
    for path in [
        p("/directory"),
        p("/crl"),
        p("/ca.pem"),
        p("/no-such-resource"),
    ] {
        let res = app
            .clone()
            .oneshot(Request::get(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            !has_nonce(res),
            "GET {path} must not mint a nonce nobody asked for"
        );
    }

    // The counterpart: server-level routes are outside the ACME router
    // entirely, so a health probe never touches the nonce table.
    let res = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(
        !has_nonce(res),
        "/health is a server route, not an ACME one: it must not mint nonces"
    );
}
