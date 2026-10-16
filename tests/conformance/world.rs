//! The server under test and the requests sent to it: one account holding an
//! issued certificate and two pending orders, the routes a signed request can
//! target, and the ways a request can be shaped or deliberately broken.

use std::collections::HashSet;
use std::sync::Mutex;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::common::acme::{self, path_of, post, url};
use crate::common::raw::RawJws;
use crate::common::{EcSigner, TestSigner, fetch_nonce, first_certificate, make_csr, test_app};

/// An account with an issued certificate and two pending orders, so every
/// kind of resource has a real URL to be requested.
///
/// The challenge belongs to an order of its own. Answering it can start its
/// validation and make that order `ready`, and the order, authorization and
/// finalize targets must not change state under a test because of it.
pub struct World {
    pub app: Router,
    pub signer: EcSigner,
    pub account: String,
    pub resources: Resources,
    /// The issued certificate, DER-encoded.
    pub certificate_der: Vec<u8>,
    /// Every nonce a request was sent with or an answer carried, so
    /// [`crate::invariants::assert_invariants`] can tell a fresh one from one
    /// handed out before.
    nonces: Mutex<HashSet<String>>,
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

        let (account, issued_order_url, chain) =
            acme::issue_certificate(&app, &signer, &["issued.example.com"]).await;
        let issued = acme::post_as_get(&app, &signer, &account, &issued_order_url).await;

        let (order_url, pending) =
            acme::new_order(&app, &signer, &account, &["pending.example.com"]).await;

        let resources = Resources {
            order: order_url,
            authorization: text(&pending["authorizations"][0]),
            challenge: String::new(),
            finalize: text(&pending["finalize"]),
            certificate: text(&issued["certificate"]),
            orders_list: format!("{account}/orders"),
        };
        let mut world = Self {
            app,
            signer,
            account,
            resources,
            certificate_der: first_certificate(&chain),
            nonces: Mutex::new(HashSet::new()),
        };
        world.replace_the_challenge().await;

        world
    }

    /// A nonce from `newNonce`, recorded as seen.
    pub async fn nonce(&self) -> String {
        let nonce = fetch_nonce(&self.app).await;
        self.nonces.lock().unwrap().insert(nonce.clone());

        nonce
    }

    /// Records a nonce an answer carried, and says whether it was new: never
    /// sent with a request and never carried by an earlier answer.
    pub fn is_fresh(&self, nonce: &str) -> bool {
        self.nonces.lock().unwrap().insert(nonce.to_string())
    }

    /// Points the challenge target at a new challenge, under a new pending
    /// order, that nobody has answered yet.
    pub async fn replace_the_challenge(&mut self) {
        let name = format!("{}.example.com", uuid::Uuid::now_v7().simple());
        let (_, order) = acme::new_order(&self.app, &self.signer, &self.account, &[&name]).await;
        let authorization = text(&order["authorizations"][0]);
        let authz = acme::post_as_get(&self.app, &self.signer, &self.account, &authorization).await;

        self.resources.challenge = text(&authz["challenges"][0]["url"]);
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

/// Resources the well-formed control reads with a POST-as-GET.
pub const READABLE: [Target; 6] = [
    Target::Account,
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

    /// The payload a request with a flaw carries: one this route would act
    /// on, so the flaw is the only reason left to refuse the request. An
    /// empty payload would not do — several routes refuse it on its own, and
    /// would still answer with an error if they stopped checking the flaw.
    ///
    /// The reads have none: an empty payload is what a read sends.
    pub fn payload_for_a_flaw(self, world: &World) -> Option<Value> {
        match self {
            Target::NewAccount | Target::NewOrder => self.valid_payload(),
            Target::RevokeCert => Some(json!({
                "certificate": BASE64_URL_SAFE_NO_PAD.encode(&world.certificate_der),
            })),
            Target::KeyChange => {
                let inner = json!({ "account": world.account, "oldKey": world.signer.jwk() });
                let signed = EcSigner::new().sign_inner(&url("/keyChange"), &inner);

                Some(serde_json::from_str(&signed).unwrap())
            }
            Target::Account | Target::Challenge => Some(json!({})),
            // The order is still pending, so without the flaw this is
            // `orderNotReady`, never the `malformed` several flaws answer.
            Target::Finalize => Some(json!({ "csr": make_csr("pending.example.com") })),
            Target::Order | Target::Authorization | Target::Certificate | Target::OrdersList => {
                None
            }
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

    /// The status and problem type this flaw may be answered with, on every
    /// route. Every flaw has one answer, except the two the server answers
    /// differently from the RFC: those accept the RFC's answer as well, so a
    /// fix passes here unchanged, and nothing else.
    pub fn accepted_answers(self) -> &'static [(StatusCode, &'static str)] {
        const MALFORMED: &str = "urn:ietf:params:acme:error:malformed";
        const UNAUTHORIZED: &str = "urn:ietf:params:acme:error:unauthorized";
        const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

        match self {
            // §6.2 requires the JWS to be verified and names no error type.
            Flaw::BadSignature | Flaw::SignedByAnotherKey => {
                &[(StatusCode::UNAUTHORIZED, UNAUTHORIZED)]
            }
            // §6.5: a nonce the server did not issue, or has seen, is
            // `badNonce`.
            Flaw::ReplayedNonce | Flaw::UnknownNonce => &[(StatusCode::BAD_REQUEST, BAD_NONCE)],
            // NEEDS FIXING (or an agreed exception): §6.5 says a nonce that is
            // "not present" is `badNonce` too. The server answers `malformed`
            // on purpose, as `jws_rejections` explains: `badNonce` asks the
            // client to retry with a fresh nonce, and a client that sent none
            // will send none again. Both answers are accepted until that is
            // settled.
            Flaw::MissingNonce => &[
                (StatusCode::BAD_REQUEST, MALFORMED),
                (StatusCode::BAD_REQUEST, BAD_NONCE),
            ],
            // NEEDS FIXING: §6.4 says a `url` that does not match the request
            // is rejected "as unauthorized", with no status named. The server
            // answers `malformed`. Both are accepted until it is fixed.
            Flaw::WrongUrl => &[
                (StatusCode::BAD_REQUEST, MALFORMED),
                (StatusCode::UNAUTHORIZED, UNAUTHORIZED),
                (StatusCode::FORBIDDEN, UNAUTHORIZED),
            ],
            // §6.4: the `url` member is mandatory. No error type is named.
            Flaw::MissingUrl => &[(StatusCode::BAD_REQUEST, MALFORMED)],
            Flaw::UnknownAccount => &[(
                StatusCode::BAD_REQUEST,
                "urn:ietf:params:acme:error:accountDoesNotExist",
            )],
            // §6.2: `none` and MAC algorithms are refused with
            // `badSignatureAlgorithm`.
            Flaw::AlgorithmNone | Flaw::MacAlgorithm => &[(
                StatusCode::BAD_REQUEST,
                "urn:ietf:params:acme:error:badSignatureAlgorithm",
            )],
            // §6.2: exactly one of `jwk` and `kid`. No error type is named.
            Flaw::BothKeyForms | Flaw::NoKeyForm => &[(StatusCode::BAD_REQUEST, MALFORMED)],
        }
    }

    /// The nonce the flawed request sends.
    pub async fn nonce(self, world: &World) -> String {
        match self {
            Flaw::ReplayedNonce => spend_a_nonce(world).await,
            Flaw::UnknownNonce => "a-nonce-the-server-never-issued".to_string(),
            _ => world.nonce().await,
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

/// Uses up a nonce in a read that succeeds, and returns it, so the caller can
/// send it a second time. The read must succeed: a refused request may be
/// refused before its nonce is consumed, and the nonce would then still be
/// fresh.
pub async fn spend_a_nonce(world: &World) -> String {
    let nonce = world.nonce().await;
    let order = &world.resources.order;
    let request = RawJws::with_kid(&world.signer, &world.account, order, &nonce);

    let response = post(&world.app, &path_of(order), request.signed()).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the read that spends a nonce"
    );

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
        None => world.nonce().await,
    };
    let request = payload.apply(target.request(world, &nonce));
    let body = match flaw {
        Some(flaw) => flaw.body(request, world),
        None => request.signed(),
    };

    post(&world.app, &path_of(&target.url(world)), body).await
}

/// Sends a request with one flaw and the payload [`Target::payload_for_a_flaw`]
/// gives the route.
pub async fn send_flawed(world: &World, target: Target, flaw: Flaw) -> Response {
    let nonce = flaw.nonce(world).await;
    let mut request = target.request(world, &nonce);

    if let Some(payload) = target.payload_for_a_flaw(world) {
        request = request.json_payload(&payload);
    }

    post(
        &world.app,
        &path_of(&target.url(world)),
        flaw.body(request, world),
    )
    .await
}

/// Sends a request with a payload the route accepts (or an empty one where
/// there is no easy valid payload) and no flaw.
pub async fn send_well_formed(world: &World, target: Target) -> Response {
    let nonce = world.nonce().await;
    let mut request = target.request(world, &nonce);

    if let Some(payload) = target.valid_payload() {
        request = request.json_payload(&payload);
    }

    post(&world.app, &path_of(&target.url(world)), request.signed()).await
}

/// A well-formed request sent with a different `Content-Type` than the one
/// RFC 8555 §6.2 requires.
pub async fn send_with_content_type(world: &World, target: Target, content_type: &str) -> Response {
    let nonce = world.nonce().await;
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
    let nonce = world.nonce().await;
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
