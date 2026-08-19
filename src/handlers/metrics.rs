//! `GET /metrics` — the Prometheus exposition endpoint.
//!
//! Not an ACME resource, and mounted on the root router beside `/health`: it
//! carries no nonce, no `Link: rel="index"` and no filter chain, and it is
//! deliberately absent from the directory. See [`crate::metrics`] for what it
//! exposes and [`crate::config::MetricsConfig`] for why it is off by default.

use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse};

use crate::metrics::Metrics;

/// The handler's own state.
///
/// A newtype rather than `AppState`, which holds exactly one `Profile` — the
/// registry is the *process's*, and a scrape reporting one endpoint's requests
/// would be a worse answer than no scrape at all.
#[derive(Clone)]
pub struct MetricsState(pub Arc<Metrics>);

pub async fn get_metrics(State(MetricsState(metrics)): State<MetricsState>) -> impl IntoResponse {
    (
        // The text exposition format's own media type, version parameter
        // included: a collector reading `text/plain` with no `version` falls
        // back to guessing, and the guess is right today only by luck.
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics.render(),
    )
}
