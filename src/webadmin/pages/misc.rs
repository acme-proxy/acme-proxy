//! `/ui/`, `/ui/profiles` and `/ui/nonces` — the overview and the two small
//! surfaces.

use axum::extract::State;
use axum::response::Html;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::time::Duration;

use crate::admin;
use crate::sqlite::account::Account;
use crate::sqlite::eab::Eab;
use crate::sqlite::nonce::Nonce;
use crate::sqlite::order::{Order, OrderQuery};
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

/// `GET /ui/` — the overview.
///
/// Four counts and the endpoint list. The counts come from the same `search`
/// calls the lists use, asked for a single row: the totals are computed by the
/// database, so this is four `COUNT(*)`s rather than four full reads.
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

    let mut context = chrome(&session, "index", "Overview");
    context.insert(
        "stats".to_string(),
        serde_json::json!({
            "accounts": accounts,
            "orders": orders,
            "eab": eab,
            "nonces": nonces,
        }),
    );
    context.insert("profiles".to_string(), Value::Array(profile_rows(&state)));

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
    tracing::info!(event = "admin_nonces_cleaned",
                   outcome = "success",
                   surface = "ui",
                   rows_removed = removed,
                   ttl_seconds = seconds,
                   username = %session.auth.user.username);

    let count = Nonce::count(&state.database).await?;
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
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
