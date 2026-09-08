//! `/ui/jobs` — the queue list, one job with its upstream cross-link, and the
//! two things an operator can do to it.

use axum::extract::{Path, Query, State};
use axum::response::Html;
use serde_json::{Map, Value};

use crate::admin::{self, CancelJobOutcome, RunJobNowOutcome};
use crate::sqlite::job::{Job, JobQuery};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::jobs::JobListParams;
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, flash, flash_error, pager, respond, respond_fragment};

/// The kinds the filter `<select>` offers. A free-typed `?kind=` still filters
/// — this is only the dropdown, and a job row's kind is a closed code set.
///
/// The **constants**, not their spellings: written out as literals this list
/// agreed with `admin::ops::PERIODIC_JOB_KINDS` only until somebody renamed a
/// kind, at which point the dropdown would silently stop matching anything
/// while every test still passed. Nothing else in the crate spells a job kind
/// twice.
const KNOWN_KINDS: &[&str] = &[
    crate::signer::relay::RELAY_JOB_KIND,
    crate::notify::job::NOTIFY_JOB_KIND,
    crate::notify::expiry::EXPIRY_JOB_KIND,
    crate::signer::local_ca::sweep::CRL_SWEEP_KIND,
    crate::jobs::sweep::NONCE_SWEEP_KIND,
    crate::jobs::sweep::AUDIT_SWEEP_KIND,
    crate::jobs::sweep::ADMIN_SESSION_SWEEP_KIND,
    crate::jobs::sweep::ORDER_SWEEP_KIND,
    crate::jobs::sweep::RETENTION_JOB_KIND,
];

/// `GET /ui/jobs?kind=&status=&limit=&offset=`
pub async fn list_jobs(
    State(state): State<AdminState>,
    Query(params): Query<JobListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let kind = params.kind.clone().unwrap_or_default();
    let status = params.status.clone().unwrap_or_default();
    let parsed = params
        .parsed_status()
        .map_err(|error| PageError::bad_request(error.to_string()))?;

    let (jobs, total) = Job::search(
        &JobQuery {
            kind: params.kind.clone(),
            status: parsed,
            limit: page.limit,
            offset: page.offset,
        },
        &state.database,
    )
    .await?;
    let items: Vec<Value> = jobs.iter().map(admin::render_job_json).collect();

    let mut context = chrome(&session, "jobs", "Jobs");
    context.insert(
        "page".to_string(),
        serde_json::json!({ "items": items, "total": total }),
    );
    context.insert(
        "pager".to_string(),
        pager(
            page,
            total,
            "/ui/jobs",
            &[("kind", &kind), ("status", &status)],
            "#jobs-table",
        ),
    );
    context.insert(
        "filters".to_string(),
        serde_json::json!({ "kind": kind, "status": status }),
    );
    context.insert(
        "kinds".to_string(),
        Value::Array(KNOWN_KINDS.iter().map(|k| Value::from(*k)).collect()),
    );

    respond(
        &state,
        session.hx,
        "jobs/list.html",
        "jobs/_table.html",
        context,
    )
}

/// `GET /ui/jobs/{id}`
pub async fn get_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let detail = load(&id, &state).await?;
    let mut context = chrome(&session, "jobs", "Job");
    context.insert("detail".to_string(), detail);
    respond(
        &state,
        session.hx,
        "jobs/detail.html",
        "jobs/_card.html",
        context,
    )
}

/// `POST /ui/jobs/{id}/cancel`
///
/// Refusal split, the [`crate::webadmin::pages::orders::revoke_order`] rule: a
/// `409` (`job_not_cancellable`) is a banner beside the still-rendered card; a
/// `5xx` replaces the page.
pub async fn cancel_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    request_context: crate::audit::RequestContext,
    session: PageSessionWrite,
) -> Result<Html<String>, PageError> {
    let banner = match admin::cancel_job(
        &id,
        crate::audit::Actor::admin(&session.auth.user.username),
        state.audit.client(&request_context).await,
        state.audit.metrics(),
        state.database.clone(),
    )
    .await
    .map_err(|admin::CancelJobError::Database(error)| PageError::from(AdminError::from(error)))?
    {
        CancelJobOutcome::NotFound => return Err(not_found(&id)),
        CancelJobOutcome::NotCancellable(status) => flash_error(
            "job_not_cancellable",
            format!("Job {id} is {status}; only ready or failed jobs can be cancelled."),
        ),
        CancelJobOutcome::Cancelled(job) => {
            tracing::info!(event = "admin_job_cancelled",
                           outcome = "success",
                           surface = "ui",
                           job_id = %id,
                           job_kind = %job.kind,
                           order_abandoned = false,
                           username = %session.auth.user.username);
            flash("ok", "Job cancelled.")
        }
        CancelJobOutcome::CancelledAndOrderAbandoned { job, order_id } => {
            tracing::info!(event = "admin_job_cancelled",
                           outcome = "success",
                           surface = "ui",
                           job_id = %id,
                           job_kind = %job.kind,
                           order_id = %order_id,
                           order_abandoned = true,
                           username = %session.auth.user.username);
            flash(
                "ok",
                format!("Job cancelled. Order {order_id} was marked invalid."),
            )
        }
    };

    fragment(&state, &session, &id, banner).await
}

/// `POST /ui/jobs/{id}/run`
pub async fn run_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    request_context: crate::audit::RequestContext,
) -> Result<Html<String>, PageError> {
    let banner = match admin::run_job_now(
        &id,
        crate::audit::Actor::admin(&session.auth.user.username),
        state.audit.client(&request_context).await,
        state.database.clone(),
    )
    .await?
    {
        RunJobNowOutcome::NotFound => return Err(not_found(&id)),
        RunJobNowOutcome::Refused(status) => flash_error(
            "job_not_runnable",
            format!("Job {id} is {status}; run-now applies to ready or failed jobs."),
        ),
        RunJobNowOutcome::Nudged(_) => {
            tracing::info!(event = "admin_job_advanced",
                           outcome = "success",
                           surface = "ui",
                           job_id = %id,
                           username = %session.auth.user.username);
            flash("ok", "Job will run at the next queue poll.")
        }
        RunJobNowOutcome::Revived(job) => {
            tracing::info!(event = "admin_job_revived",
                           outcome = "success",
                           surface = "ui",
                           job_id = %id,
                           attempts = job.attempts,
                           username = %session.auth.user.username);
            flash(
                "ok",
                format!(
                    "Job revived: status ready, attempts {}/{} (one more attempt).",
                    job.attempts, job.max_attempts
                ),
            )
        }
    };

    fragment(&state, &session, &id, banner).await
}

/// Re-reads the job and re-renders `jobs/_card.html` with a banner.
async fn fragment(
    state: &AdminState,
    session: &PageSessionWrite,
    id: &str,
    banner: Value,
) -> Result<Html<String>, PageError> {
    let detail = load(id, state).await?;
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("detail".to_string(), detail);
    context.insert("flash".to_string(), banner);
    respond_fragment(state, "jobs/_card.html", context)
}

async fn load(id: &str, state: &AdminState) -> Result<Value, PageError> {
    let detail = admin::load_job_detail(id, state.database.clone())
        .await?
        .ok_or_else(|| not_found(id))?;
    Ok(admin::render_job_detail_json(&detail))
}

fn not_found(id: &str) -> PageError {
    PageError::not_found(format!("no such job: {id}"))
}
