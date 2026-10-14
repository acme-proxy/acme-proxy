//! What must hold for every response, whatever was sent, and the controls that
//! keep those checks from passing without testing anything.

use axum::http::StatusCode;
use axum::response::Response;

use crate::common::body_json;
use crate::world::{
    FLAWS, PAYLOADS, Payload, READABLE, TARGETS, Target, World, send, send_well_formed,
};

/// Checks what must hold for every response, and returns its status.
async fn assert_invariants(label: &str, response: Response) -> StatusCode {
    let status = response.status();

    assert!(!status.is_server_error(), "{label}: answered {status}");
    assert!(
        response.headers().contains_key("replay-nonce"),
        "{label}: no Replay-Nonce on a {status} response"
    );

    if status.is_client_error() {
        assert_is_problem_document(label, response).await;
    }

    status
}

async fn assert_is_problem_document(label: &str, response: Response) {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("application/problem+json"),
        "{label}: refusal sent as {content_type:?}"
    );

    let problem = body_json(response).await;
    let kind = problem["type"].as_str().unwrap_or_default();
    assert!(
        kind.starts_with("urn:ietf:params:acme:error:"),
        "{label}: problem type {kind:?} is not an ACME error"
    );
}

/// The control that proves the requests built here can succeed at all.
#[tokio::test]
async fn a_well_formed_request_is_accepted() {
    let world = World::new().await;

    for target in READABLE {
        let response = send_well_formed(&world, target).await;
        let status = assert_invariants(&format!("{target:?}"), response).await;
        assert_eq!(status, StatusCode::OK, "{target:?} read");
    }

    let response = send_well_formed(&world, Target::NewAccount).await;
    assert_eq!(response.status(), StatusCode::OK, "existing account");

    let response = send_well_formed(&world, Target::NewOrder).await;
    assert_eq!(response.status(), StatusCode::CREATED, "new order");
}

#[tokio::test]
async fn every_payload_gets_a_well_formed_answer() {
    let world = World::new().await;

    for target in TARGETS {
        for payload in PAYLOADS {
            let label = format!("{target:?} with {payload:?}");
            let response = send(&world, target, payload, None).await;
            assert_invariants(&label, response).await;
        }
    }
}

#[tokio::test]
async fn every_flaw_is_refused_with_a_well_formed_problem() {
    let world = World::new().await;

    for target in TARGETS {
        for flaw in FLAWS.into_iter().filter(|flaw| flaw.applies_to(target)) {
            let label = format!("{target:?} with {flaw:?}");
            let response = send(&world, target, Payload::Empty, Some(flaw)).await;
            let status = assert_invariants(&label, response).await;

            assert!(status.is_client_error(), "{label}: answered {status}");
        }
    }
}
