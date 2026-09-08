//! `/api/jobs` — the background queue across every kind, plus the two
//! operator mutations.
//!
//! `list` and `get` take [`Authenticated`]; `cancel` and `run` take
//! [`AuthenticatedWrite`], exactly like order revoke/delete — cancelling or
//! re-scheduling a queued job is shared/CA-adjacent state, so `operator` is the
//! floor and a `viewer` is refused. Both mutations appear in
//! `tests/admin_api.rs::mutating_endpoints()`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use crate::admin::{self, CancelJobOutcome, RunJobNowOutcome};
use crate::sqlite::job::{Job, JobQuery};
use crate::sqlite::status::{JobStatus, UnknownStatus};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};

/// The window fields are inline, not `#[serde(flatten)]` — see the note on
/// [`super::accounts::AccountListParams`].
#[derive(Debug, Deserialize, Default)]
pub struct JobListParams {
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl JobListParams {
    /// The `status=` filter, parsed. Refused by name so `/api/jobs?status=typo`
    /// and `/ui/jobs?status=typo` answer identically — the
    /// [`super::orders::OrderListParams::parsed_status`] rule. `kind` is **not**
    /// validated: kinds are an open set, so an unknown one matches nothing.
    pub fn parsed_status(&self) -> Result<Option<JobStatus>, UnknownStatus> {
        self.status.as_deref().map(str::parse).transpose()
    }
}

/// Turns an unparseable `status=` into a `400`, for either front end.
pub(crate) fn bad_status(error: UnknownStatus) -> AdminError {
    AdminError::with_code(StatusCode::BAD_REQUEST, "invalid_status", error.to_string())
}

/// `GET /api/jobs?kind=&status=&limit=&offset=`
pub async fn list_jobs(
    State(state): State<AdminState>,
    Query(params): Query<JobListParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let status = params.parsed_status().map_err(bad_status)?;
    let query = JobQuery {
        kind: params.kind,
        status,
        limit: page.limit,
        offset: page.offset,
    };
    let (jobs, total) = Job::search(&query, &state.database).await?;
    let items = jobs.iter().map(admin::render_job_json).collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/jobs/{id}` — the job plus, for a relay issuance, its upstream
/// order.
pub async fn get_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let detail = admin::load_job_detail(&id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(admin::render_job_detail_json(&detail)))
}

/// `POST /api/jobs/{id}/cancel`
///
/// For a `signer_relay_issue` job this also marks the ACME order invalid and
/// abandons the upstream mapping, with an audit row attributed to the operator
/// — see [`admin::cancel_job`].
pub async fn cancel_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    request_context: crate::audit::RequestContext,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<Json<Value>, AdminError> {
    let outcome = admin::cancel_job(
        &id,
        crate::audit::Actor::admin(&auth.user.username),
        state.audit.client(&request_context).await,
        state.audit.metrics(),
        state.database.clone(),
    )
    .await
    .map_err(|admin::CancelJobError::Database(error)| AdminError::from(error))?;

    match outcome {
        CancelJobOutcome::NotFound => Err(not_found(&id)),
        CancelJobOutcome::NotCancellable(status) => Err(AdminError::conflict(
            "job_not_cancellable",
            format!("job {id} is {status}; only ready or failed jobs can be cancelled"),
        )),
        CancelJobOutcome::Cancelled(job) => {
            tracing::info!(event = "admin_job_cancelled",
                           outcome = "success",
                           surface = "api",
                           job_id = %id,
                           job_kind = %job.kind,
                           order_abandoned = false,
                           username = %auth.user.username);
            Ok(Json(admin::render_job_json(&job)))
        }
        CancelJobOutcome::CancelledAndOrderAbandoned { job, order_id } => {
            tracing::info!(event = "admin_job_cancelled",
                           outcome = "success",
                           surface = "api",
                           job_id = %id,
                           job_kind = %job.kind,
                           order_id = %order_id,
                           order_abandoned = true,
                           username = %auth.user.username);
            Ok(Json(admin::render_job_json(&job)))
        }
    }
}

/// `POST /api/jobs/{id}/run` — nudge a `ready` job forward, or revive a
/// `failed` one for exactly one more attempt.
pub async fn run_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    request_context: crate::audit::RequestContext,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<Json<Value>, AdminError> {
    match admin::run_job_now(
        &id,
        crate::audit::Actor::admin(&auth.user.username),
        state.audit.client(&request_context).await,
        state.database.clone(),
    )
    .await?
    {
        RunJobNowOutcome::NotFound => Err(not_found(&id)),
        RunJobNowOutcome::Refused(status) => Err(AdminError::conflict(
            "job_not_runnable",
            format!("job {id} is {status}; run-now applies to ready or failed jobs"),
        )),
        RunJobNowOutcome::Nudged(job) => {
            tracing::info!(event = "admin_job_advanced",
                           outcome = "success",
                           surface = "api",
                           job_id = %id,
                           username = %auth.user.username);
            Ok(Json(admin::render_job_json(&job)))
        }
        RunJobNowOutcome::Revived(job) => {
            tracing::info!(event = "admin_job_revived",
                           outcome = "success",
                           surface = "api",
                           job_id = %id,
                           attempts = job.attempts,
                           username = %auth.user.username);
            Ok(Json(admin::render_job_json(&job)))
        }
    }
}

fn not_found(id: &str) -> AdminError {
    AdminError::not_found(format!("no such job: {id}"))
}
