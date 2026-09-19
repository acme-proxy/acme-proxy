//! `GET /metrics` — the Prometheus exposition endpoint.
//!
//! Not an ACME resource, and mounted on the root router beside `/health`: it
//! carries no nonce, no `Link: rel="index"` and no filter chain, and it is
//! deliberately absent from the directory. See [`acme_proxy_jobs::metrics`] for what it
//! exposes and [`acme_proxy_core::config::MetricsConfig`] for why it is off by default.

use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse};

use acme_proxy_jobs::metrics::Metrics;

/// The handler's own state.
///
/// A newtype rather than `AppState`, which holds exactly one `Profile` — the
/// registry is the *process's*, and a scrape reporting one endpoint's requests
/// would be a worse answer than no scrape at all.
#[derive(Clone)]
pub struct MetricsState(pub Arc<Metrics>);

pub async fn get_metrics(State(MetricsState(metrics)): State<MetricsState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, acme_proxy_jobs::metrics::CONTENT_TYPE)],
        metrics.render(),
    )
}
