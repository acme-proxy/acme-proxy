//! Counts one request into the Prometheus registry.
//!
//! Mounted only when `metrics.enabled` is on (see [`crate::build_app`]), so the
//! lock and the two allocations below cost nothing to a deployment that has not
//! asked for metrics.
//!
//! ## Why the labels come from `MatchedPath`
//!
//! [`MatchedPath`] is the route *pattern* axum matched — `/profile/le/order/{id}`
//! — rather than the URI the client sent. That distinction is the whole
//! cardinality argument: a `route` label taken from the URI would mint a series
//! per order id, per account id and per challenge id, and a Prometheus series
//! is memory in this process and in the scraper for as long as it is retained.
//!
//! Two consequences worth knowing:
//!
//! - The extension is populated by routing, and `Router::layer` applies this
//!   middleware to each route rather than wrapping the router as a whole, so it
//!   really is present here. A middleware that ran *before* routing — the
//!   access layer, for instance — would see `None` on every request.
//! - It is absent for a request that matched no route, which is the fallback's
//!   own case. [`split_matched_path`] answers [`ROUTE_UNMATCHED`](crate::metrics::ROUTE_UNMATCHED) there, so a
//!   scanner probing ten thousand paths adds one series rather than ten
//!   thousand.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::metrics::{Metrics, split_matched_path};

pub async fn record_request(
    State(metrics): State<Arc<Metrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string());

    let response = next.run(request).await;

    let (profile, route) = split_matched_path(matched.as_deref());
    metrics.record_request(&profile, &route, response.status().as_u16());

    response.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::ROUTE_UNMATCHED;
    use axum::{Router, http::StatusCode, middleware, routing::get};
    use tower::ServiceExt;

    async fn app(metrics: Arc<Metrics>) -> Router {
        let inner = Router::new()
            .route("/order/{id}", get(|| async { "ok" }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }));

        Router::new()
            .route("/health", get(|| async { "ok" }))
            .nest(&format!("{}/le", crate::PROFILE_PREFIX), inner)
            .layer(middleware::from_fn_with_state(metrics, record_request))
    }

    async fn registry() -> Arc<Metrics> {
        Arc::new(Metrics::new(Arc::new(
            crate::sqlite::db::Database::connect_in_memory()
                .await
                .unwrap(),
        )))
    }

    /// The regression that matters: two different order ids are **one** series,
    /// because the label is the pattern. Getting this wrong is not a wrong
    /// number, it is an unbounded memory leak in the scraper.
    #[tokio::test]
    async fn two_ids_on_one_route_are_one_series() {
        let metrics = registry().await;
        let app = app(metrics.clone()).await;

        for id in ["aaaa-1111", "bbbb-2222", "cccc-3333"] {
            let request = Request::get(format!("/profile/le/order/{id}"))
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(request).await.unwrap();
        }

        let rendered = metrics.render();
        assert!(
            rendered.contains(
                "acme_proxy_requests_total{profile=\"le\",route=\"/order/{id}\",status=\"200\"} 3\n"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("aaaa-1111"), "{rendered}");
    }

    /// A root route belongs to no endpoint, and the status is the response's
    /// own rather than a guess.
    #[tokio::test]
    async fn root_routes_and_statuses_are_labelled() {
        let metrics = registry().await;
        let app = app(metrics.clone()).await;

        app.clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        app.clone()
            .oneshot(
                Request::get("/profile/le/boom")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let rendered = metrics.render();
        assert!(
            rendered.contains(
                "acme_proxy_requests_total{profile=\"none\",route=\"/health\",status=\"200\"} 1\n"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "acme_proxy_requests_total{profile=\"le\",route=\"/boom\",status=\"500\"} 1\n"
            ),
            "{rendered}"
        );
    }

    /// The fallback's case. An unmatched path is attacker-chosen, so every one
    /// of them has to collapse into a single series.
    #[tokio::test]
    async fn unmatched_paths_collapse_to_one_series() {
        let metrics = registry().await;
        let app = app(metrics.clone()).await;

        for path in ["/nope", "/also-nope", "/../etc/passwd"] {
            let request = Request::get(path).body(Body::empty()).unwrap();
            app.clone().oneshot(request).await.unwrap();
        }

        let rendered = metrics.render();
        assert!(
            rendered.contains(&format!(
                "acme_proxy_requests_total{{profile=\"none\",route=\"{ROUTE_UNMATCHED}\",status=\"404\"}} 3\n"
            )),
            "{rendered}"
        );
        assert!(!rendered.contains("also-nope"), "{rendered}");
    }
}
