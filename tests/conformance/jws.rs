//! The request-level rules of RFC 8555 §6, checked against every route instead
//! of the one route each older test happened to use: nonces, algorithms,
//! media types, methods and the `Link` header on refusals.
//!
//! The older suites (`jws_rejections`, `new_account`, ...) pin the details of a
//! single route. A rule that holds on `newAccount` and not on `revokeCert` only
//! shows up here.

use axum::http::StatusCode;
use axum::response::Response;

use crate::common::body_json;
use crate::world::{
    FLAWS, Flaw, Payload, TARGETS, World, get, send, send_general_serialization,
    send_with_content_type, send_with_method,
};

const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
const BAD_ALGORITHM: &str = "urn:ietf:params:acme:error:badSignatureAlgorithm";

/// §6.5: "If the value of a 'nonce' header parameter is not valid, the server
/// MUST return the 'badNonce' error."
#[tokio::test]
async fn a_replayed_or_unknown_nonce_is_bad_nonce_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for flaw in [Flaw::ReplayedNonce, Flaw::UnknownNonce] {
            let response = send(&world, target, Payload::Empty, Some(flaw)).await;

            assert_problem(&format!("{target:?} {flaw:?}"), response, 400, BAD_NONCE).await;
        }
    }
}

/// §6.2: the server "MUST NOT" accept an algorithm it does not support, and a
/// `badSignatureAlgorithm` problem "SHOULD" list the ones it does (§6.2).
#[tokio::test]
async fn an_unsupported_algorithm_is_named_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for flaw in [Flaw::AlgorithmNone, Flaw::MacAlgorithm] {
            let label = format!("{target:?} {flaw:?}");
            let response = send(&world, target, Payload::Empty, Some(flaw)).await;

            let problem = assert_problem(&label, response, 400, BAD_ALGORITHM).await;
            let algorithms = problem["algorithms"].as_array();
            assert!(algorithms.is_some_and(|list| !list.is_empty()), "{label}");
        }
    }
}

/// §6.2: a POST must be `application/jose+json`; anything else is a 415.
#[tokio::test]
async fn another_media_type_is_unsupported_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for content_type in ["application/json", "text/plain"] {
            let label = format!("{target:?} as {content_type}");
            let response = send_with_content_type(&world, target, content_type).await;

            assert_problem(
                &label,
                response,
                415,
                "urn:ietf:params:acme:error:malformed",
            )
            .await;
        }
    }
}

/// §6.3 rules out an unsigned GET for these resources. Every route that only
/// takes a signed POST answers a GET with 405 and a problem document.
#[tokio::test]
async fn a_get_of_a_post_only_route_is_method_not_allowed() {
    let world = World::new().await;

    for target in TARGETS {
        let response = get(&world, target).await;

        assert_problem(
            &format!("{target:?}"),
            response,
            405,
            "urn:ietf:params:acme:error:malformed",
        )
        .await;
    }
}

/// §7.1: every resource but the directory carries `Link: <directory>;rel="index"`,
/// refusals included.
#[tokio::test]
async fn every_refusal_links_to_the_directory() {
    let world = World::new().await;

    for target in TARGETS {
        for flaw in FLAWS.into_iter().filter(|flaw| flaw.applies_to(target)) {
            let response = send(&world, target, Payload::Empty, Some(flaw)).await;

            assert!(
                has_index_link(&response),
                "{target:?} {flaw:?}: no index link on the {} response",
                response.status()
            );
        }
    }
}

fn has_index_link(response: &Response) -> bool {
    response
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|link| link.contains("rel=\"index\""))
}

/// Checks the status and the problem type, and returns the problem document.
async fn assert_problem(
    label: &str,
    response: Response,
    status: u16,
    kind: &str,
) -> serde_json::Value {
    assert_eq!(
        response.status(),
        StatusCode::from_u16(status).unwrap(),
        "{label}"
    );

    let problem = body_json(response).await;
    assert_eq!(problem["type"], kind, "{label}");

    problem
}

/// §6.2 allows only the flattened JWS JSON serialization with a single
/// signature. The general form, with a `signatures` array, is refused.
#[tokio::test]
async fn the_general_jws_serialization_is_refused_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        let response = send_general_serialization(&world, target).await;

        assert!(
            response.status().is_client_error(),
            "{target:?} answered {}",
            response.status()
        );
    }
}

/// Only GET is answered with a definite status by the RFC. For every other
/// method the server must still refuse, never serve or fail.
#[tokio::test]
async fn other_methods_are_refused_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for method in ["PUT", "DELETE", "PATCH", "HEAD"] {
            let response = send_with_method(&world, target, method).await;

            assert!(
                response.status().is_client_error(),
                "{method} {target:?} answered {}",
                response.status()
            );
        }
    }
}
