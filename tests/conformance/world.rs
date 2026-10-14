//! The server under test and the requests sent to it: one account holding an
//! issued certificate and a pending order, the routes a signed request can
//! target, and the ways a request can be shaped or deliberately broken.

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::common::acme::{self, path_of, post, url};
use crate::common::raw::RawJws;
use crate::common::{EcSigner, TestSigner, fetch_nonce, test_app};

/// An account with an issued certificate and a second, still pending, order,
/// so every kind of resource has a real URL to be requested.
pub struct World {
    pub app: Router,
    pub signer: EcSigner,
    pub account: String,
    pub resources: Resources,
}

pub struct Resources {
    pub order: String,
    pub authorization: String,
    pub challenge: String,
    pub finalize: String,
    pub certificate: String,
    pub orders_list: String,
}

impl World {
    pub async fn new() -> Self {
        let app = test_app().await;
        let signer = EcSigner::new();

        let (account, issued_order_url, _) =
            acme::issue_certificate(&app, &signer, &["issued.example.com"]).await;
        let issued = acme::post_as_get(&app, &signer, &account, &issued_order_url).await;

        let (order_url, pending) =
            acme::new_order(&app, &signer, &account, &["pending.example.com"]).await;
        let authorization = text(&pending["authorizations"][0]);
        let authz = acme::post_as_get(&app, &signer, &account, &authorization).await;

        let resources = Resources {
            order: order_url,
            authorization,
            challenge: text(&authz["challenges"][0]["url"]),
            finalize: text(&pending["finalize"]),
            certificate: text(&issued["certificate"]),
            orders_list: format!("{account}/orders"),
        };

        Self {
            app,
            signer,
            account,
            resources,
        }
    }
}

pub fn text(value: &Value) -> String {
    value.as_str().expect("expected a string").to_string()
}

/// A route a signed request can be sent to.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    NewAccount,
    NewOrder,
    RevokeCert,
    KeyChange,
    Account,
    Order,
    Authorization,
    Challenge,
    Finalize,
    Certificate,
    OrdersList,
}

pub const TARGETS: [Target; 11] = [
    Target::NewAccount,
    Target::NewOrder,
    Target::RevokeCert,
    Target::KeyChange,
    Target::Account,
    Target::Order,
    Target::Authorization,
    Target::Challenge,
    Target::Finalize,
    Target::Certificate,
    Target::OrdersList,
];

/// Resources the well-formed control reads with a POST-as-GET. The account read
/// joins once its handler accepts an empty payload.
pub const READABLE: [Target; 5] = [
    Target::Order,
    Target::Authorization,
    Target::Challenge,
    Target::Certificate,
    Target::OrdersList,
];

impl Target {
    pub fn url(self, world: &World) -> String {
        let resources = &world.resources;

        match self {
            Target::NewAccount => url("/newAccount"),
            Target::NewOrder => url("/newOrder"),
            Target::RevokeCert => url("/revokeCert"),
            Target::KeyChange => url("/keyChange"),
            Target::Account => world.account.clone(),
            Target::Order => resources.order.clone(),
            Target::Authorization => resources.authorization.clone(),
            Target::Challenge => resources.challenge.clone(),
            Target::Finalize => resources.finalize.clone(),
            Target::Certificate => resources.certificate.clone(),
            Target::OrdersList => resources.orders_list.clone(),
        }
    }

    /// `newAccount` is the one route where the request carries its key. Every
    /// other route names an existing account instead.
    pub fn carries_its_key(self) -> bool {
        matches!(self, Target::NewAccount)
    }

    pub fn request<'a>(self, world: &'a World, nonce: &str) -> RawJws<'a> {
        let url = self.url(world);

        if self.carries_its_key() {
            RawJws::with_jwk(&world.signer, &url, nonce)
        } else {
            RawJws::with_kid(&world.signer, &world.account, &url, nonce)
        }
    }

    /// A payload this route accepts, where one is easy to build.
    pub fn valid_payload(self) -> Option<Value> {
        match self {
            Target::NewAccount => Some(json!({ "termsOfServiceAgreed": true })),
            Target::NewOrder => Some(json!({
                "identifiers": [{ "type": "dns", "value": "control.example.com" }]
            })),
            _ => None,
        }
    }
}

/// What the request carries as its payload.
#[derive(Clone, Copy, Debug)]
pub enum Payload {
    Empty,
    EmptyObject,
    Null,
    Array,
    Text,
    NotJson,
    NotBase64,
}

pub const PAYLOADS: [Payload; 7] = [
    Payload::Empty,
    Payload::EmptyObject,
    Payload::Null,
    Payload::Array,
    Payload::Text,
    Payload::NotJson,
    Payload::NotBase64,
];

impl Payload {
    pub fn apply(self, request: RawJws) -> RawJws {
        match self {
            Payload::Empty => request,
            Payload::EmptyObject => request.json_payload(&json!({})),
            Payload::Null => request.json_payload(&Value::Null),
            Payload::Array => request.json_payload(&json!([])),
            Payload::Text => request.json_payload(&json!("text")),
            Payload::NotJson => request.bytes_payload(b"{"),
            Payload::NotBase64 => request.payload_segment("***"),
        }
    }
}

/// One deliberate violation of a requirement in RFC 8555 §6.
#[derive(Clone, Copy, Debug)]
pub enum Flaw {
    BadSignature,
    SignedByAnotherKey,
    MissingNonce,
    ReplayedNonce,
    UnknownNonce,
    WrongUrl,
    MissingUrl,
    UnknownAccount,
    AlgorithmNone,
    MacAlgorithm,
    BothKeyForms,
    NoKeyForm,
}

pub const FLAWS: [Flaw; 12] = [
    Flaw::BadSignature,
    Flaw::SignedByAnotherKey,
    Flaw::MissingNonce,
    Flaw::ReplayedNonce,
    Flaw::UnknownNonce,
    Flaw::WrongUrl,
    Flaw::MissingUrl,
    Flaw::UnknownAccount,
    Flaw::AlgorithmNone,
    Flaw::MacAlgorithm,
    Flaw::BothKeyForms,
    Flaw::NoKeyForm,
];

impl Flaw {
    /// Naming a wrong account only means something where the request names one.
    pub fn applies_to(self, target: Target) -> bool {
        !(target.carries_its_key() && matches!(self, Flaw::UnknownAccount))
    }

    /// The nonce the flawed request sends.
    pub async fn nonce(self, world: &World) -> String {
        match self {
            Flaw::ReplayedNonce => spend_a_nonce(world).await,
            Flaw::UnknownNonce => "a-nonce-the-server-never-issued".to_string(),
            _ => fetch_nonce(&world.app).await,
        }
    }

    /// The request body with the flaw applied.
    pub fn body(self, request: RawJws, world: &World) -> String {
        match self {
            Flaw::BadSignature => request.with_bad_signature(),
            Flaw::SignedByAnotherKey => request.signed_by(&EcSigner::new()),
            Flaw::MissingNonce => request.without_header("nonce").signed(),
            Flaw::ReplayedNonce | Flaw::UnknownNonce => request.signed(),
            Flaw::WrongUrl => request.header("url", json!(url("/directory"))).signed(),
            Flaw::MissingUrl => request.without_header("url").signed(),
            Flaw::UnknownAccount => request
                .header("kid", json!(unknown_account(world)))
                .signed(),
            Flaw::AlgorithmNone => request.header("alg", json!("none")).signed(),
            Flaw::MacAlgorithm => request.header("alg", json!("HS256")).signed(),
            Flaw::BothKeyForms => request
                .header("kid", json!(world.account))
                .header("jwk", world.signer.jwk())
                .signed(),
            Flaw::NoKeyForm => request.without_header("kid").without_header("jwk").signed(),
        }
    }
}

/// Uses up a nonce in a harmless request and returns it, so the caller can
/// send it a second time.
pub async fn spend_a_nonce(world: &World) -> String {
    let nonce = fetch_nonce(&world.app).await;
    let request = RawJws::with_kid(&world.signer, &world.account, &world.account, &nonce);
    post(&world.app, &path_of(&world.account), request.signed()).await;

    nonce
}

/// The URL of an account that does not exist.
pub fn unknown_account(world: &World) -> String {
    let (prefix, _) = world.account.rsplit_once('/').unwrap();

    format!("{prefix}/{}", uuid::Uuid::nil())
}

pub async fn send(world: &World, target: Target, payload: Payload, flaw: Option<Flaw>) -> Response {
    let nonce = match flaw {
        Some(flaw) => flaw.nonce(world).await,
        None => fetch_nonce(&world.app).await,
    };
    let request = payload.apply(target.request(world, &nonce));
    let body = match flaw {
        Some(flaw) => flaw.body(request, world),
        None => request.signed(),
    };

    post(&world.app, &path_of(&target.url(world)), body).await
}

/// Sends a request with a payload the route accepts (or an empty one where
/// there is no easy valid payload) and no flaw.
pub async fn send_well_formed(world: &World, target: Target) -> Response {
    let nonce = fetch_nonce(&world.app).await;
    let mut request = target.request(world, &nonce);

    if let Some(payload) = target.valid_payload() {
        request = request.json_payload(&payload);
    }

    post(&world.app, &path_of(&target.url(world)), request.signed()).await
}

/// A well-formed request sent with a different `Content-Type` than the one
/// RFC 8555 §6.2 requires.
pub async fn send_with_content_type(world: &World, target: Target, content_type: &str) -> Response {
    let nonce = fetch_nonce(&world.app).await;
    let body = target.request(world, &nonce).signed();

    world
        .app
        .clone()
        .oneshot(
            Request::post(path_of(&target.url(world)))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// An unsigned GET of a target's URL.
pub async fn get(world: &World, target: Target) -> Response {
    world
        .app
        .clone()
        .oneshot(
            Request::get(path_of(&target.url(world)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// A correctly signed body in the *general* JWS serialization, with a
/// `signatures` array instead of the flattened `protected`/`signature` pair.
pub async fn send_general_serialization(world: &World, target: Target) -> Response {
    let nonce = fetch_nonce(&world.app).await;
    let flattened: Value = serde_json::from_str(&target.request(world, &nonce).signed()).unwrap();
    let body = json!({
        "payload": flattened["payload"],
        "signatures": [{
            "protected": flattened["protected"],
            "signature": flattened["signature"],
        }],
    });

    post(&world.app, &path_of(&target.url(world)), body.to_string()).await
}

/// An unsigned request with the given method to a target's URL.
pub async fn send_with_method(world: &World, target: Target, method: &str) -> Response {
    world
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path_of(&target.url(world)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
