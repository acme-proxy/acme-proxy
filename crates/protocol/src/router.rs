//! The ACME listener's routers — the whole service and one profile's — the
//! metrics listener's, and the response layers shared with the admin listener.

use std::any::Any;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, header};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{Span, info};

use crate::{handlers, middlewares};
use acme_proxy_core::config::Config;
use acme_proxy_core::error::Problem;
use acme_proxy_core::routes;
use acme_proxy_jobs::metrics;
use acme_proxy_net::challenge;
use acme_proxy_signer as signer;
use acme_proxy_store::db::Database;

use crate::profile::Profile;

/// Shared application state handed to every route via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub database: Arc<Database>,
    /// Process-wide configuration only — `server`, `nonce`, `dns`, `logging`.
    /// Anything an endpoint can differ on is on [`AppState::profile`].
    pub config: Arc<Config>,
    pub profile: Arc<Profile>,
    /// The CA's audit trail. Beside `config` rather than on the profile,
    /// because `[audit]` is process-wide: the trail describes the CA, and the
    /// web admin writes to the same one across every endpoint it can revoke on.
    pub audit: Arc<acme_proxy_jobs::auditor::Auditor>,
    /// The durable queue, for the work a request starts and does not finish.
    ///
    /// Here for `audit`'s reason — one queue, one table, one runner for the
    /// process — rather than on the profile. `post_challenge` is its only
    /// caller on this listener: it claims a challenge and queues the outbound
    /// check rather than awaiting it, so a probe of a client-chosen host no
    /// longer holds an admission permit.
    pub jobs: acme_proxy_jobs::jobs::JobQueue,
}

/// Every distinct `http-01` token store across the mounted profiles.
///
/// Deduplicated by pointer: [`signer::build_backends`] already shares one
/// backend instance between profiles with identical `[signer]` sections, so
/// several profiles usually contribute the *same* store. Two profiles relaying
/// to two different upstreams contribute two, and the route consults both —
/// there is nothing to isolate, because the token is the upstream's own random
/// value and is itself the secret (RFC 8555 §8.3), so one merged view cannot
/// answer the wrong challenge.
fn http01_stores(profiles: &[Arc<Profile>]) -> Vec<Arc<dyn signer::Http01TokenStore>> {
    let mut stores: Vec<Arc<dyn signer::Http01TokenStore>> = Vec::new();
    for profile in profiles {
        if let Some(store) = profile.signer_info.http01_tokens()
            && !stores.iter().any(|existing| Arc::ptr_eq(existing, &store))
        {
            stores.push(store);
        }
    }
    stores
}

/// The three response-hardening headers **both** listeners apply.
///
/// A shared constructor rather than two copies: the admin router is not nested
/// inside [`build_app`] and so inherits none of its layers, but these three are
/// a security control, and two hand-written copies of one are a control that
/// drifts. Everything genuinely per-listener — the admin's `Cache-Control`,
/// `Referrer-Policy` and CSP, this one's admission and nonce layers — stays at
/// its own call site.
///
/// A tuple because `tower` implements [`Layer`](tower::Layer) for one, so the
/// three still apply as three separate layers rather than being collapsed into
/// a wrapper type. They set distinct headers, so their order among themselves
/// carries no meaning.
pub fn security_headers() -> (
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
) {
    (
        SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ),
    )
}

/// The human-readable message a panic payload carries, or a fixed fallback.
///
/// `std::panic::panic_any` can carry any `'static` type; the two shapes that
/// actually occur are `panic!("literal")` (`&'static str`) and `panic!("{x}")`
/// (`String`). Anything else is reported as the fallback — the message only
/// reaches the log, never a response body (ASVS V16.5.1).
pub fn panic_message(err: &(dyn Any + Send)) -> &str {
    err.downcast_ref::<&'static str>()
        .copied()
        .or_else(|| err.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a handler panicked")
}

/// The response a caught panic produces on the ACME listener.
///
/// Without this a panic in a handler aborts the connection with no reply, where
/// every other refusal this server makes is an `application/problem+json`
/// document — the reason [`middlewares::admission`]'s deadline is a hand-written
/// `from_fn` returning [`Problem`] rather than `tower_http`'s timeout layer. The
/// panic message goes to the log only, never the body.
///
/// Relies on `panic = "unwind"`: [`CatchPanicLayer`] is inert under
/// `panic = "abort"`, which `Cargo.toml` deliberately does not set.
fn acme_panic_response(err: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!(
        event = "request_handler_panicked",
        outcome = "failure",
        listener = "acme",
        error = %panic_message(err.as_ref()),
    );
    Problem::server_internal("Internal server error").into_response()
}

/// The last-resort panic layer for the ACME listener — see [`acme_panic_response`].
///
/// `pub` on the same terms as [`build_app`]: the library exists so the tests and
/// `main.rs` can reach it, and `tests/security.rs` drives this layer over a
/// deliberately panicking route.
pub fn catch_panic_acme() -> CatchPanicLayer<fn(Box<dyn Any + Send + 'static>) -> Response> {
    CatchPanicLayer::custom(acme_panic_response as fn(Box<dyn Any + Send + 'static>) -> Response)
}

/// Builds the whole HTTP service: the server-level routes at the root, and one
/// ACME router per profile under `/profile/<name>`.
pub fn build_app(
    database: Arc<Database>,
    config: Arc<Config>,
    profiles: Vec<Arc<Profile>>,
    audit: Arc<acme_proxy_jobs::auditor::Auditor>,
    metrics: Arc<metrics::Metrics>,
    jobs: acme_proxy_jobs::jobs::JobQueue,
) -> Router {
    // Server-level routes. Deliberately *outside* the admission limit below: a
    // health probe is asked for precisely when the server is saturated, and
    // inside the limit it was starved exactly when it mattered — a load
    // balancer would go on reporting the server healthy right up to the point
    // where the probe itself could no longer get a slot.
    let mut root = Router::new()
        .route("/", get(|| async { Redirect::temporary("/health") }))
        .route("/health", get(handlers::get_health_check));

    // The `http-01` responder for the *upstream's* challenge, mounted only when
    // a signer backend has tokens to serve — which today means `relay`
    // with `challenge_strategy = "http01"`. Here beside `/health` rather than
    // inside a profile: RFC 8555 §8.3 fixes this path at the root of the name
    // being certified, and the CA fetching it holds no account at this server,
    // so it must not meet a filter chain, a nonce or an ACME 404.
    let stores = http01_stores(&profiles);
    if !stores.is_empty() {
        info!(
            event = "http_01_responder_mounted",
            outcome = "advisory",
            path = challenge::http_01::WELL_KNOWN_PREFIX,
            stores = stores.len(),
            "a reverse proxy must forward or redirect \
             http://<identifier>:80/.well-known/acme-challenge/ here for the upstream to reach it"
        );
        root = root.merge(
            Router::new()
                .route(
                    &format!("{}{{token}}", challenge::http_01::WELL_KNOWN_PREFIX),
                    get(handlers::get_challenge_file),
                )
                .with_state(handlers::Http01Stores(Arc::new(stores))),
        );
    }

    let mut acme = Router::new();
    for profile in &profiles {
        let path = profile.path.clone();
        acme = acme.nest(
            &path,
            build_router(
                database.clone(),
                config.clone(),
                profile.clone(),
                audit.clone(),
                jobs.clone(),
            ),
        );
    }

    let server = &config.server;
    let acme = acme
        .layer(middleware::from_fn_with_state(
            middlewares::admission::Admission::new(
                server.max_concurrent_requests,
                server.admission_wait_ms,
                server.request_timeout_ms,
            ),
            middlewares::admission::admission_middleware,
        ))
        // Innermost of the two, so it is in force by the time
        // `String::from_request` reads the JWS body in `verify_jws`. Without it
        // the ceiling is axum's implicit 2 MiB, which every concurrent request
        // may buffer and then hand to `serde_json` — for a body that is a JWS
        // carrying at most a CSR.
        .layer(DefaultBodyLimit::max(server.max_body_bytes));

    // Server-wide layers, applied once rather than once per profile. The
    // filter and nonce layers are deliberately *not* here: both are ACME
    // concerns and live inside each profile's own router.
    let app = root.merge(acme);

    // Innermost of the server-wide stack: a panic anywhere below here — a
    // handler, the admission layer, a nested profile router — is turned into a
    // 500 problem document instead of an aborted connection. Under the metrics
    // and access layers on purpose, so the counter still sees `status = "500"`
    // and the access line still emits (`request_completed`, with the profile
    // span field already recorded). ASVS V16.5.4.
    let app = app.layer(catch_panic_acme());

    // Counting sits here even though the exposition is served on a *different*
    // socket (see `metrics_app`): this is the only router that sees an ACME
    // request, and the registry both share is an `Arc`. On the merged router
    // rather than inside a profile, because `Router::layer` applies per route
    // *and* to the fallback — so a request that matched nothing is counted too,
    // under `ROUTE_UNMATCHED`. It also runs after routing, which is what makes
    // `MatchedPath` present: the label has to be the route *pattern*
    // (`/order/{id}`), never the URI, or every order ever finalized would be
    // its own series for as long as the scraper retained it.
    //
    // Added only when the listener exists, so an operator who has not asked for
    // metrics pays neither the lock nor the allocation per request.
    let app = if config.metrics.enabled {
        app.layer(middleware::from_fn_with_state(
            metrics,
            middlewares::metrics::record_request,
        ))
    } else {
        app
    };

    app.layer(security_headers())
        // Outermost of everything, so the `request` span it opens — and the
        // `x-request-id` it echoes — covers every route, the admission layer
        // and the two hardening layers alike. Nothing below it is allowed to
        // log without an id.
        .layer(middleware::from_fn(
            middlewares::access::add_access_middleware,
        ))
}

/// Builds the metrics listener's router: `GET /metrics` and nothing else.
///
/// A **third socket**, not a route on either of the other two. The port is the
/// access control — see [`acme_proxy_core::config::MetricsConfig`] — which is why there
/// is no session extractor here and no filter chain, and why the exposition can
/// name every profile without that being a decision about the public listener.
///
/// Deliberately none of `build_app`'s layers. There is no admission control (a
/// scrape is wanted *most* when the server is saturated, the reason `/health`
/// sits outside it too), no `Replay-Nonce`, no `Link: rel="index"`, no
/// `DefaultBodyLimit` (a `GET` with no body), and no security headers — those
/// exist for a browser, and nothing renders this. It keeps only the access
/// middleware, so a scrape is a `request_completed` line like everything else
/// and its `x-request-id` correlates with whatever it was measuring.
///
/// This router is **not** behind a `reload` swap cell, unlike
/// the other two. It has one route, and its only state is the registry — which
/// by design is carried across generations rather than rebuilt (see
/// `Assembly`), so there is nothing a reload could put in a
/// new one. `metrics.enabled` and `metrics.bind_address` are frozen for the
/// reason every bind address is: the socket cannot move under a running
/// listener.
pub fn metrics_app(metrics: Arc<metrics::Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(handlers::get_metrics))
        .with_state(handlers::MetricsState(metrics))
        .layer(middleware::from_fn(
            middlewares::access::add_access_middleware,
        ))
}

/// Builds one profile's ACME router: every RFC 8555 resource, plus the two
/// layers that are per-endpoint (its filter chain) or ACME-specific (the
/// `Replay-Nonce` minting).
///
/// Paths here are relative to the mount point — `axum::Router::nest` strips
/// the prefix before this router sees a request, which is also what makes
/// `verify_jws`'s `base_url + path` reconstruction correct.
pub fn build_router(
    database: Arc<Database>,
    config: Arc<Config>,
    profile: Arc<Profile>,
    audit: Arc<acme_proxy_jobs::auditor::Auditor>,
    jobs: acme_proxy_jobs::jobs::JobQueue,
) -> Router {
    let filter = profile.filter.clone();
    let state = AppState {
        database: database.clone(),
        config,
        profile: profile.clone(),
        audit,
        jobs,
    };

    let profile_name = profile.name.clone();

    // RFC 8555 §7.1 — the `index` link every resource but the directory carries.
    // Built once here rather than per response; an invalid header value is
    // impossible for a URL that already passed config validation, but falling
    // back to skipping the layer beats panicking a whole endpoint over it.
    let index_link =
        HeaderValue::from_str(&format!("<{}/directory>;rel=\"index\"", profile.base_url));

    let router = Router::<AppState>::new()
        // §6.3: the directory and newNonce MUST answer a plain GET *and* a
        // POST-as-GET. The extra methods chain onto one `MethodRouter` —
        // registering the same path twice would replace the first route.
        .route(
            routes::DIRECTORY,
            get(handlers::get_directory).post(handlers::post_directory),
        )
        .route(
            routes::NEW_NONCE,
            get(handlers::get_new_nonce)
                .head(handlers::head_new_nonce)
                .post(handlers::post_new_nonce),
        )
        .route(routes::NEW_ACCOUNT, post(handlers::post_new_account))
        .route("/acct/{id}", post(handlers::post_account))
        .route("/acct/{id}/orders", post(handlers::post_account_orders))
        .route(routes::KEY_CHANGE, post(handlers::post_key_change))
        .route(routes::NEW_ORDER, post(handlers::post_new_order))
        .route("/order/{id}", post(handlers::post_order))
        .route("/order/{id}/finalize", post(handlers::post_finalize))
        .route("/authz/{id}", post(handlers::post_authz))
        .route("/chall/{id}", post(handlers::post_challenge))
        .route("/certificate/{id}", post(handlers::post_certificate))
        .route(routes::REVOKE_CERT, post(handlers::post_revoke_cert))
        .route(
            &format!("{}/{{id}}", routes::RENEWAL_INFO),
            get(handlers::get_renewal_info),
        )
        .route(routes::CRL, get(handlers::get_crl))
        .route(routes::CA_CHAIN, get(handlers::get_ca_chain))
        // §6.3: "if the server receives a GET request, it MUST return an error
        // with status code 405 (Method Not Allowed) and type `malformed`".
        // axum's own default gets the status right but sends an empty body, so
        // these two fallbacks supply the problem document — for a wrong method
        // and, in the same spirit, for a path that routes nowhere.
        .method_not_allowed_fallback(|| async {
            Problem::method_not_allowed("This resource must be read with POST-as-GET")
        })
        .fallback(|| async { Problem::not_found("No such resource") })
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            filter,
            middlewares::filter::add_filter_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            database.clone(),
            middlewares::nonce::add_nonce_middleware,
        ));

    // Outermost of the profile's layers that touch a response, so the link
    // reaches every one of them — including the two fallbacks above and
    // anything a filter refuses. (The `profile` recorder below wraps this, but
    // only writes to the tracing span.)
    let router = match index_link {
        Ok(value) => router.layer(middleware::from_fn_with_state(
            value,
            middlewares::index_link::add_index_link_middleware,
        )),
        Err(error) => {
            tracing::error!(
                event = "request_index_link_header_invalid",
                outcome = "failure",
                base_url = %profile.base_url,
                error = %error,
            );
            router
        }
    };

    // `profile` is declared `field::Empty` on the server-wide `request` span
    // (`middlewares::access`) and filled in here — the first layer that knows
    // which endpoint the request landed on, since the name comes from the
    // `/profile/<name>` mount point `Router::nest` has already stripped.
    // Ahead of every other layer of this router so a request a filter refuses
    // still says *which* endpoint refused it.
    router.layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let name = profile_name.clone();
            async move {
                Span::current().record("profile", &*name);
                next.run(request).await
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;

    /// Every panic-payload shape resolves to a message; an odd one falls
    /// back rather than panicking the panic handler.
    #[test]
    fn panic_message_covers_every_payload_shape() {
        assert_eq!(panic_message(&"boom"), "boom");
        assert_eq!(panic_message(&String::from("boom")), "boom");
        assert_eq!(panic_message(&0u8), "a handler panicked");
    }

    /// `acme_panic_response` is a 500 problem document whatever the payload,
    /// and the panic text never reaches the body.
    #[tokio::test]
    async fn acme_panic_response_is_a_problem_document() {
        let response = acme_panic_response(Box::new("secret internal detail"));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(problem["status"], 500);
        assert!(
            !body_contains(&body, "secret internal detail"),
            "the panic message must not reach the client",
        );
    }

    fn body_contains(bytes: &[u8], needle: &str) -> bool {
        std::str::from_utf8(bytes)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    }

    async fn boom() -> &'static str {
        panic!("this handler panics on purpose")
    }

    fn app() -> Router {
        Router::new()
            .route("/ok", get(|| async { "ok" }))
            .route("/boom", get(boom))
            .layer(catch_panic_acme())
    }

    #[tokio::test]
    async fn a_panicking_route_answers_a_problem_document() {
        let response = app()
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
        );
    }

    #[tokio::test]
    async fn the_layer_is_transparent_on_the_happy_path() {
        let response = app()
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
