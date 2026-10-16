//! The request-level rules of RFC 8555 §6 that a flaw in the JWS cannot
//! express, checked against every route instead of the one route each older
//! test happened to use: the media type, the JWS serialization and the HTTP
//! method. Nonces, algorithms, key forms and the `Link` header are checked by
//! the flaw matrix and the invariants in `invariants.rs`.
//!
//! The older suites (`jws_rejections`, `new_account`, ...) pin the details of a
//! single route. A rule that holds on `newAccount` and not on `revokeCert` only
//! shows up here.

use axum::http::StatusCode;

use crate::invariants::{assert_invariants, assert_links_to_the_directory, assert_well_formed};
use crate::world::{
    TARGETS, World, get, send_general_serialization, send_with_content_type, send_with_method,
};

const MALFORMED: &str = "urn:ietf:params:acme:error:malformed";

/// §6.2: a POST must be `application/jose+json`; anything else is a 415.
#[tokio::test]
async fn another_media_type_is_unsupported_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for content_type in ["application/json", "text/plain"] {
            let label = format!("{target:?} as {content_type}");

            let response = send_with_content_type(&world, target, content_type).await;
            let answer = assert_invariants(&world, &label, response).await;

            assert_eq!(answer.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{label}");
            assert_eq!(answer.problem_type(), MALFORMED, "{label}");
        }
    }
}

/// §6.3 rules out an unsigned GET for these resources: the server "MUST
/// return an error with status code 405 (Method Not Allowed) and type
/// 'malformed'". A GET is not a POST, so §6.5 asks for no nonce here.
#[tokio::test]
async fn a_get_of_a_post_only_route_is_method_not_allowed() {
    let world = World::new().await;

    for target in TARGETS {
        let label = format!("GET {target:?}");

        let response = get(&world, target).await;
        let answer = assert_well_formed(&label, response).await;

        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{label}");
        assert_eq!(answer.problem_type(), MALFORMED, "{label}");
    }
}

/// §6.2 allows only the flattened JWS JSON serialization with a single
/// signature. The general form, with a `signatures` array, is refused.
#[tokio::test]
async fn the_general_jws_serialization_is_refused_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        let label = format!("{target:?}");

        let response = send_general_serialization(&world, target).await;
        let answer = assert_invariants(&world, &label, response).await;

        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(answer.problem_type(), MALFORMED, "{label}");
    }
}

/// Only GET is answered with a definite status by the RFC. Every other method
/// is refused with `405 Method Not Allowed`, whose `Allow` header names the
/// one method these routes take, so the method is shown to be the reason. A
/// `HEAD` answer has no body, so only its headers are checked; the others
/// carry a problem document.
#[tokio::test]
async fn other_methods_are_refused_on_every_route() {
    let world = World::new().await;

    for target in TARGETS {
        for method in ["PUT", "DELETE", "PATCH", "HEAD"] {
            let label = format!("{method} {target:?}");

            let response = send_with_method(&world, target, method).await;

            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{label}");
            assert_eq!(response.headers()["allow"], "POST", "{label}");
            if method == "HEAD" {
                assert_links_to_the_directory(&label, &response);
            } else {
                let answer = assert_well_formed(&label, response).await;
                assert_eq!(answer.problem_type(), MALFORMED, "{label}");
            }
        }
    }
}
