//! `/ui/`, `/ui/profiles` and `/ui/nonces` — the overview and the two small
//! surfaces.

use axum::extract::State;
use axum::response::Html;
use serde::Deserialize;
use serde_json::Value;

use crate::webadmin::AdminState;
use crate::webadmin::handlers::Caller;
use crate::webadmin::handlers::misc::{apply_cleanup_nonces, profile_rows};
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, flash, respond, respond_fragment};
use acme_proxy_store::account::Account;
use acme_proxy_store::audit::AuditEntry;
use acme_proxy_store::audit::AuditQuery;
use acme_proxy_store::eab::Eab;
use acme_proxy_store::job::Job;
use acme_proxy_store::job::JobQuery;
use acme_proxy_store::nonce::Nonce;
use acme_proxy_store::order::Order;
use acme_proxy_store::order::OrderQuery;
use acme_proxy_store::status::JobStatus;

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
    let (_, accounts) = Account::search(None, None, 1, 0, &state.database).await?;
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
    let (_, expiring_soon, _) = acme_proxy_store::expiring::list_expiring(
        &acme_proxy_store::expiring::ExpiringQuery {
            profile: None,
            before: acme_proxy_store::expiring::expiring_horizon(ATTENTION_EXPIRY_DAYS),
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
            since: Some(acme_proxy_store::nonce::now_secs().saturating_sub(24 * 60 * 60)),
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
    request_context: acme_proxy_core::audit::RequestContext,
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

    let removed = apply_cleanup_nonces(
        &state,
        &Caller::ui(&session.auth, &request_context),
        seconds,
    )
    .await?;

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
