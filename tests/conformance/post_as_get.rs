//! Reading resources with an empty payload (RFC 8555 §6.3), and the routes that
//! must refuse one. Each test names the RFC section it checks.
//!
//! The read of the account URL is not here yet. It arrives with the fix for
//! that route.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::common::acme::{self, post};
use crate::common::raw::RawJws;
use crate::common::{EcSigner, body_json, fetch_nonce, p};
use crate::world::{Payload, READABLE, Target, World, send, send_well_formed};

/// §6.3 and §7.4.2 make these reads a POST-as-GET, and a read must not
/// change what it reads.
#[tokio::test]
async fn reading_a_resource_twice_gives_the_same_answer() {
    let world = World::new().await;

    for target in READABLE {
        let first = send_well_formed(&world, target).await;
        assert_eq!(first.status(), StatusCode::OK, "{target:?}");
        let first = acme::body_text(first).await;

        let second = send_well_formed(&world, target).await;
        assert_eq!(second.status(), StatusCode::OK, "{target:?}");

        assert_eq!(first, acme::body_text(second).await, "{target:?}");
    }
}

/// §7.4 requires a CSR in the body, so an empty payload is refused and
/// the order stays as it was.
#[tokio::test]
async fn finalize_refuses_an_empty_payload_and_leaves_the_order_ready() {
    let app = crate::common::test_app().await;
    let signer = EcSigner::new();
    let (account, order_url, order) =
        acme::ready_order(&app, &signer, &["ready.example.com"]).await;
    let finalize_url = order["finalize"].as_str().unwrap();

    let nonce = fetch_nonce(&app).await;
    let request = RawJws::with_kid(&signer, &account, finalize_url, &nonce);
    let response = post(&app, &acme::path_of(finalize_url), request.signed()).await;

    assert!(response.status().is_client_error(), "{}", response.status());

    let order = acme::post_as_get(&app, &signer, &account, &order_url).await;
    assert_eq!(order["status"], "ready");
}

/// §7.6 puts the certificate in the payload, so an empty one is refused.
#[tokio::test]
async fn revoke_cert_refuses_an_empty_payload() {
    let world = World::new().await;

    let response = send(&world, Target::RevokeCert, Payload::Empty, None).await;

    assert!(response.status().is_client_error(), "{}", response.status());
}

/// §6.3 defines a POST-as-GET only with a zero-length payload, so a
/// resource that can only be read refuses any other payload.
#[tokio::test]
async fn a_read_only_resource_refuses_a_payload() {
    let world = World::new().await;
    let read_only = [Target::Order, Target::Certificate, Target::OrdersList];

    for target in read_only {
        let response = send(&world, target, Payload::EmptyObject, None).await;

        assert!(
            response.status().is_client_error(),
            "{target:?} answered {}",
            response.status()
        );
    }
}

/// Pre-authorization (§7.4.1) is optional. The server offers none, so
/// the directory does not advertise it and the route does not exist.
#[tokio::test]
async fn pre_authorization_is_neither_advertised_nor_served() {
    let world = World::new().await;

    let directory = world
        .app
        .clone()
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(body_json(directory).await.get("newAuthz").is_none());

    let response = post_to(&world, "/newAuthz").await;
    assert!(response.status().is_client_error(), "{}", response.status());
}

/// RFC 9773 §4.1 defines renewal information as an unauthenticated GET.
/// There is no POST form, so a signed POST is refused.
#[tokio::test]
async fn renewal_information_cannot_be_posted() {
    let world = World::new().await;

    let response = post_to(&world, "/renewalInfo/not-a-real-certificate-id").await;

    assert!(response.status().is_client_error(), "{}", response.status());
}

/// A correctly signed POST-as-GET to a path under the test profile.
async fn post_to(world: &World, path: &str) -> axum::response::Response {
    let nonce = fetch_nonce(&world.app).await;
    let url = acme::url(path);
    let request = RawJws::with_kid(&world.signer, &world.account, &url, &nonce);

    post(&world.app, &p(path), request.signed()).await
}
