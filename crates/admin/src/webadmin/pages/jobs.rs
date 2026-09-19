//! `/ui/jobs` — the queue list, one job with its upstream cross-link, and the
//! two things an operator can do to it.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde_json::Value;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::Caller;
use crate::webadmin::handlers::jobs::{
    Cancelled, JobListParams, Ran, apply_cancel_job, apply_run_job,
};
use crate::webadmin::handlers::paging::PageParams;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{
    ListFilters, chrome, flash, flash_error, pager, respond, respond_fragment,
};
use acme_proxy_store::job::Job;
use acme_proxy_store::job::JobQuery;

/// The kinds the filter `<select>` offers. A free-typed `?kind=` still filters
/// — this is only the dropdown, and a job row's kind is a closed code set.
///
/// The **constants**, not their spellings: written out as literals this list
/// agreed with `admin::ops::PERIODIC_JOB_KINDS` only until somebody renamed a
/// kind, at which point the dropdown would silently stop matching anything
/// while every test still passed. Nothing else in the crate spells a job kind
/// twice.
const KNOWN_KINDS: &[&str] = &[
    acme_proxy_signer::relay::RELAY_JOB_KIND,
    acme_proxy_jobs::notify::job::NOTIFY_JOB_KIND,
    acme_proxy_jobs::notify::expiry::EXPIRY_JOB_KIND,
    acme_proxy_signer::local_ca::sweep::CRL_SWEEP_KIND,
    acme_proxy_signer::local_ca::sweep::CRL_REGENERATE_KIND,
    acme_proxy_protocol::acme::issue::SIGNER_ISSUE_KIND,
    acme_proxy_protocol::acme::revoke::SIGNER_REVOKE_KIND,
    acme_proxy_protocol::acme::validate::CHALLENGE_VALIDATE_KIND,
    acme_proxy_jobs::jobs::sweep::NONCE_SWEEP_KIND,
    acme_proxy_jobs::jobs::sweep::AUDIT_SWEEP_KIND,
    acme_proxy_jobs::jobs::sweep::ADMIN_SESSION_SWEEP_KIND,
    acme_proxy_jobs::jobs::sweep::ORDER_SWEEP_KIND,
    acme_proxy_jobs::jobs::sweep::RETENTION_JOB_KIND,
];

/// `GET /ui/jobs?kind=&status=&limit=&offset=`
pub async fn list_jobs(
    State(state): State<AdminState>,
    Query(params): Query<JobListParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let filters = ListFilters::new()
        .with("kind", params.kind.as_deref())
        .with("status", params.status.as_deref());
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
        pager(page, total, "/ui/jobs", &filters.pairs(), "#jobs-table"),
    );
    context.insert("filters".to_string(), filters.to_value());
    // From the enum `?status=` is parsed against, so a status added there is
    // offered here rather than being filterable only by hand-typed URL.
    context.insert(
        "statuses".to_string(),
        Value::Array(
            acme_proxy_store::status::JobStatus::ALL
                .iter()
                .map(|status| Value::from(status.as_str()))
                .collect(),
        ),
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
    request_context: acme_proxy_core::audit::RequestContext,
    session: PageSessionWrite,
) -> Result<Html<String>, PageError> {
    let banner =
        match apply_cancel_job(&state, &Caller::ui(&session.auth, &request_context), &id).await {
            Ok(Cancelled {
                abandoned_order: None,
                ..
            }) => flash("ok", "Job cancelled."),
            Ok(Cancelled {
                abandoned_order: Some(order_id),
                ..
            }) => flash(
                "ok",
                format!("Job cancelled. Order {order_id} was marked invalid."),
            ),
            Err(error) if error.status == StatusCode::CONFLICT => {
                flash_error(error.code, error.message)
            }
            Err(error) => return Err(error.into()),
        };

    fragment(&state, &session, &id, banner).await
}

/// `POST /ui/jobs/{id}/run`
pub async fn run_job(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    session: PageSessionWrite,
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Html<String>, PageError> {
    let banner =
        match apply_run_job(&state, &Caller::ui(&session.auth, &request_context), &id).await {
            Ok(Ran::Nudged(_)) => flash("ok", "Job will run at the next queue poll."),
            Ok(Ran::Revived(job)) => flash(
                "ok",
                format!(
                    "Job revived: status ready, attempts {}/{} (one more attempt).",
                    job.attempts, job.max_attempts
                ),
            ),
            Err(error) if error.status == StatusCode::CONFLICT => {
                flash_error(error.code, error.message)
            }
            Err(error) => return Err(error.into()),
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
    let mut context = super::fragment_context(&session.auth);
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
