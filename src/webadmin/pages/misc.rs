//! `/ui/`, `/ui/profiles` and `/ui/nonces` — the overview and the two small
//! surfaces.

use axum::extract::State;
use axum::response::Html;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

use crate::admin;
use crate::sqlite::account::Account;
use crate::sqlite::audit::{AuditEntry, AuditQuery};
use crate::sqlite::eab::Eab;
use crate::sqlite::job::{Job, JobQuery};
use crate::sqlite::nonce::Nonce;
use crate::sqlite::order::{Order, OrderQuery};
use crate::sqlite::status::JobStatus;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::misc::profile_rows;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, flash, respond, respond_fragment};

#[derive(Debug, Deserialize, Default)]
pub struct CleanupForm {
    /// Blank means `nonce.ttl_seconds`, matching the JSON API's absent member.
    #[serde(default, rename = "ttlSeconds")]
    pub ttl_seconds: String,
}

/// How far ahead the overview's "expiring" tile looks. The expiry page's own
/// "urgent" badge threshold, so the tile and the red rows it opens agree.
const ATTENTION_EXPIRY_DAYS: u64 = 7;

/// `GET /ui/` — the overview.
///
/// What needs attention, then the totals, then the endpoint list. Every number
/// comes from the same query its list page runs, asked for a single row: the
/// totals are computed by the database, so this is a handful of `COUNT(*)`s
/// rather than as many full reads.
pub async fn get_index(
    State(state): State<AdminState>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let (_, accounts) = Account::search(None, 1, 0, &state.database).await?;
    let (_, orders) = Order::search(
        &OrderQuery {
            limit: 1,
            ..OrderQuery::default()
        },
        &state.database,
    )
    .await?;
    let (_, eab) = Eab::search(1, 0, &state.database).await?;
    let nonces = Nonce::count(&state.database).await?;

    // What needs somebody, before what merely exists. Each is the total of a
    // query a list page already runs, asked for one row, and each tile links
    // to that list -- so a number here is never one the operator cannot open.
    let (_, failed_jobs) = Job::search(
        &JobQuery {
            kind: None,
            status: Some(JobStatus::Failed),
            limit: 1,
            offset: 0,
        },
        &state.database,
    )
    .await?;
    // The whole window, replaced certificates included, so the number agrees
    // with the list the tile opens rather than with a filter it does not set.
    let (_, expiring_soon, _) = admin::list_expiring(
        &admin::ExpiringQuery {
            profile: None,
            before: admin::expiring_horizon(ATTENTION_EXPIRY_DAYS),
            include_superseded: true,
            limit: 1,
            offset: 0,
        },
        state.database.clone(),
    )
    .await?;
    let (_, refusals) = AuditEntry::search(
        &AuditQuery {
            outcome: Some("failure".to_string()),
            since: Some(crate::sqlite::nonce::now_secs().saturating_sub(24 * 60 * 60)),
            limit: 1,
            ..AuditQuery::default()
        },
        &state.database,
    )
    .await?;
    let profiles = profile_rows(&state);
    let any_bypass = profiles
        .iter()
        .any(|profile| profile["challengeBypass"] == Value::Bool(true));

    let mut context = chrome(&session, "index", "Overview");
    context.insert(
        "stats".to_string(),
        serde_json::json!({
            "accounts": accounts,
            "orders": orders,
            "eab": eab,
            "nonces": nonces,
            "failedJobs": failed_jobs,
            "expiringSoon": expiring_soon,
            "expiryDays": ATTENTION_EXPIRY_DAYS,
            "refusals": refusals,
        }),
    );
    context.insert("any_bypass".to_string(), Value::Bool(any_bypass));
    context.insert("profiles".to_string(), Value::Array(profiles));

    // The overview is a whole page or nothing: there is no fragment of it worth
    // swapping on its own.
    respond(&state, false, "index.html", "index.html", context)
}

/// `GET /ui/profiles` — the endpoints this process is serving.
pub async fn list_profiles(
    State(state): State<AdminState>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let profiles = profile_rows(&state);
    // Computed here rather than filtered in the template: a warning this
    // load-bearing should be a value a Rust test can assert on.
    let any_bypass = profiles
        .iter()
        .any(|profile| profile["challengeBypass"] == Value::Bool(true));

    let mut context = chrome(&session, "profiles", "Profiles");
    context.insert("profiles".to_string(), Value::Array(profiles));
    context.insert("any_bypass".to_string(), Value::Bool(any_bypass));

    respond(
        &state,
        false,
        "profiles/list.html",
        "profiles/_table.html",
        context,
    )
}

/// `GET /ui/nonces` — how many rows the table holds.
pub async fn get_nonces(
    State(state): State<AdminState>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let count = Nonce::count(&state.database).await?;

    let mut context = chrome(&session, "nonces", "Nonces");
    context.insert("count".to_string(), Value::from(count));
    context.insert(
        "ttl_seconds".to_string(),
        Value::from(state.config.nonce.ttl_seconds),
    );

    respond(
        &state,
        session.hx,
        "nonces/index.html",
        "nonces/_panel.html",
        context,
    )
}

/// `POST /ui/nonces/cleanup` — sweep now, rather than waiting for the reaper.
pub async fn cleanup_nonces(
    State(state): State<AdminState>,
    session: PageSessionWrite,
    request_context: crate::audit::RequestContext,
    axum::Form(form): axum::Form<CleanupForm>,
) -> Result<Html<String>, PageError> {
    let seconds = match form.ttl_seconds.trim() {
        "" => state.config.nonce.ttl_seconds,
        raw => raw.parse::<u64>().map_err(|_| {
            PageError::from(crate::webadmin::error::AdminError::bad_request(format!(
                "`{raw}` is not a number of seconds"
            )))
        })?,
    };

    let removed =
        admin::cleanup_nonces(Duration::from_secs(seconds), state.database.clone()).await?;
    // See the `/api` twin: a sweep that removed nothing writes no row.
    if removed > 0 {
        state
            .record_admin_action(
                &request_context,
                &session.auth.user.username,
                |actor, client| {
                    crate::audit::admin::nonce_cleanup_completed(actor, client, removed)
                },
            )
            .await;
    }
    tracing::info!(event = "admin_nonces_cleaned",
                   outcome = "success",
                   surface = "ui",
                   rows_removed = removed,
                   ttl_seconds = seconds,
                   username = %session.auth.user.username);

    let count = Nonce::count(&state.database).await?;
    let mut context = super::fragment_context(&session.auth);
    context.insert("count".to_string(), Value::from(count));
    context.insert(
        "ttl_seconds".to_string(),
        Value::from(state.config.nonce.ttl_seconds),
    );
    context.insert(
        "flash".to_string(),
        flash("ok", format!("Swept {removed} nonce(s).")),
    );

    respond_fragment(&state, "nonces/_panel.html", context)
}
