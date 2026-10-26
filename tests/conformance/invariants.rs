//! What must hold for every response, whatever was sent, and the controls that
//! keep those checks from passing without testing anything.

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value;

use crate::common::acme::url;
use crate::common::body_json;
use crate::world::{
    FLAWS, PAYLOADS, READABLE, TARGETS, Target, World, problem, send, send_flawed, send_well_formed,
};

/// What a response said, once [`assert_invariants`] has checked it.
pub struct Answer {
    pub status: StatusCode,
    /// The problem document, for a refusal.
    pub problem: Option<Value>,
}

impl Answer {
    pub fn problem_type(&self) -> &str {
        self.problem
            .as_ref()
            .and_then(|problem| problem["type"].as_str())
            .unwrap_or_default()
    }
}

/// Checks what must hold for every response to a POST, and returns what the
/// response said: a fresh nonce (§6.5), and everything
/// [`assert_well_formed`] checks.
pub async fn assert_invariants(world: &World, label: &str, response: Response) -> Answer {
    assert_carries_a_fresh_nonce(world, label, &response);

    assert_well_formed(label, response).await
}

/// Checks what must hold for every response, whatever its method: no 5xx, the
/// `index` link, and a problem document for a refusal. A request that is not a
/// POST is owed no nonce, so this leaves the nonce alone.
pub async fn assert_well_formed(label: &str, response: Response) -> Answer {
    let status = response.status();

    assert!(!status.is_server_error(), "{label}: answered {status}");
    assert_links_to_the_directory(label, &response);

    let problem = if status.is_client_error() {
        Some(assert_is_problem_document(label, response).await)
    } else {
        None
    };

    Answer { status, problem }
}

/// §6.5: "The server MUST include a Replay-Nonce header field in every
/// successful response to a POST request and SHOULD provide it in error
/// responses as well." The server provides it on both, and each one must be
/// usable: a nonce no request was sent with and no earlier answer carried. A
/// server that echoed the request's nonce, or handed out the same one twice,
/// would give clients a nonce that is refused as `badNonce`.
fn assert_carries_a_fresh_nonce(world: &World, label: &str, response: &Response) {
    let status = response.status();
    let nonce = response
        .headers()
        .get("replay-nonce")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("{label}: no Replay-Nonce on a {status} response"));

    let base64url = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    assert!(
        !nonce.is_empty() && nonce.chars().all(base64url),
        "{label}: Replay-Nonce {nonce:?} is not base64url"
    );
    assert!(
        world.is_fresh(nonce),
        "{label}: Replay-Nonce {nonce:?} was handed out before"
    );
}

/// §7.1: "The 'index' link relation is present on all resources other than
/// the directory and indicates the URL of the directory." None of these
/// routes is the directory, so every answer, a refusal included, links to this
/// endpoint's directory.
pub fn assert_links_to_the_directory(label: &str, response: &Response) {
    let expected = format!("<{}>;rel=\"index\"", url("/directory"));
    let links: Vec<&str> = response
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();

    assert!(
        links.contains(&expected.as_str()),
        "{label}: no {expected} among the Link headers {links:?}"
    );
}

async fn assert_is_problem_document(label: &str, response: Response) -> Value {
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

    problem
}

/// The control that proves the requests built here can succeed at all. Its
/// answers go through the same checks as every other answer.
#[tokio::test]
async fn a_well_formed_request_is_accepted() {
    let world = World::new().await;

    for target in READABLE {
        let response = send_well_formed(&world, target).await;
        let answer = assert_invariants(&world, &format!("{target:?}"), response).await;
        assert_eq!(answer.status, StatusCode::OK, "{target:?} read");
    }

    let response = send_well_formed(&world, Target::NewAccount).await;
    let answer = assert_invariants(&world, "existing account", response).await;
    assert_eq!(answer.status, StatusCode::OK, "existing account");

    let response = send_well_formed(&world, Target::NewOrder).await;
    let answer = assert_invariants(&world, "new order", response).await;
    assert_eq!(answer.status, StatusCode::CREATED, "new order");
}

/// Answering a challenge can start its validation, which in tests passes at
/// once. So every challenge request gets a challenge nobody has answered yet,
/// and no request decides what the next one meets.
#[tokio::test]
async fn every_payload_gets_a_well_formed_answer() {
    let mut world = World::new().await;

    for target in TARGETS {
        for payload in PAYLOADS {
            if matches!(target, Target::Challenge) {
                world.replace_the_challenge().await;
            }
            let label = format!("{target:?} with {payload:?}");

            let response = send(&world, target, payload).await;

            assert_invariants(&world, &label, response).await;
        }
    }
}

/// Each flaw is answered with its own status and problem type on every route
/// (see [`Flaw::accepted_answers`], which also marks the two answers that still
/// need fixing). The request carries a payload the route would act on, so a
/// route that stopped checking the flaw would answer something else and fail
/// here.
#[tokio::test]
async fn every_flaw_is_refused_with_a_well_formed_problem() {
    let world = World::new().await;

    for target in TARGETS {
        for flaw in FLAWS.into_iter().filter(|flaw| flaw.applies_to(target)) {
            let label = format!("{target:?} with {flaw:?}");

            let response = send_flawed(&world, target, flaw).await;
            let answer = assert_invariants(&world, &label, response).await;

            let accepted = flaw.accepted_answers();
            assert!(
                accepted.contains(&(answer.status, answer.problem_type())),
                "{label}: answered {} {}, expected one of {accepted:?}",
                answer.status,
                answer.problem_type()
            );

            if answer.problem_type() == problem::BAD_SIGNATURE_ALGORITHM {
                assert_lists_the_algorithms(&label, &answer);
            }
        }
    }
}

/// §6.2: the `badSignatureAlgorithm` problem document "MUST include an
/// 'algorithms' field with an array of supported 'alg' values".
fn assert_lists_the_algorithms(label: &str, answer: &Answer) {
    let algorithms = answer
        .problem
        .as_ref()
        .and_then(|problem| problem["algorithms"].as_array());

    assert!(
        algorithms.is_some_and(|list| !list.is_empty()),
        "{label}: no algorithms listed"
    );
}
