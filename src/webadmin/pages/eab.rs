//! `/ui/eab` — External Account Binding credentials.
//!
//! The one page in this tree that ever renders a secret, and it renders it
//! exactly once: `render_eab_created_json` is the only renderer carrying
//! `hmacKey`, the list and the detail read the same row through
//! `render_eab_json`, and `Eab::to_json` has no such member. A lost credential
//! is replaced, never recovered.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::sqlite::eab::Eab;
use crate::webadmin::AdminState;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, flash, respond, respond_fragment};

#[derive(Debug, Deserialize, Default)]
pub struct CreateForm {
    /// A human label, free text. Rendered into the list and the detail, which
    /// is why every page template is `.html` and auto-escaped.
    #[serde(default)]
    pub label: String,
    /// Empty means the credential is valid at every endpoint — the `NULL` the
    /// column stores, not a profile named "".
    #[serde(default)]
    pub profile: String,
}

/// `GET /ui/eab`
///
/// Unpaginated, over `Eab::list_all`: an operator mints these by hand, a few at
/// a time, so the whole table is a page. `GET /api/eab` is the one that windows
/// -- it answers the envelope every list endpoint in that API answers, and a
/// script has no scroll bar to reach the rest with. Both read the table in the
/// same order (oldest first), which is what keeps the two surfaces describing
/// one listing.
pub async fn list_eab(
    State(state): State<AdminState>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let mut context = chrome(&session, "eab", "External Account Binding");
    context.insert("items".to_string(), Value::Array(rows(&state).await?));
    context.insert(
        "profiles".to_string(),
        Value::Array(crate::webadmin::handlers::misc::profile_rows(&state)),
    );

    respond(
        &state,
        session.hx,
        "eab/list.html",
        "eab/_table.html",
        context,
    )
}

/// `GET /ui/eab/{kid}`
pub async fn get_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let eab = load(&kid, &state).await?;

    let mut context = chrome(&session, "eab", "Credential");
    context.insert("eab".to_string(), eab);

    respond(
        &state,
        session.hx,
        "eab/detail.html",
        "eab/_card.html",
        context,
    )
}

/// `POST /ui/eab`
///
/// Answers `201` with the one-time secret, and refreshes the list underneath
/// out of band — the new row would otherwise only appear on a reload, which is
/// exactly when the secret would be gone.
pub async fn create_eab(
    State(state): State<AdminState>,
    session: PageSessionWrite,
    // See `pages::orders::revoke_order`: `Option<Form<_>>` is not an axum
    // extractor, and this is only ever reached from a browser form.
    axum::Form(form): axum::Form<CreateForm>,
) -> Result<Response, PageError> {
    let label = non_empty(&form.label);
    let profile = non_empty(&form.profile);

    super::super::handlers::eab::require_mounted_profile(
        &state,
        profile.as_deref(),
        "leave it unset",
    )?;

    let eab = Eab::create(label, profile, &state.database).await?;
    tracing::info!(event = "admin_eab_created",
                   outcome = "success",
                   surface = "ui",
                   kid = %eab.kid,
                   username = %session.auth.user.username);

    let mut context = Map::new();
    context.insert("eab".to_string(), admin::render_eab_created_json(&eab));
    context.insert("items".to_string(), Value::Array(rows(&state).await?));
    // Read by `eab/_table.html`'s root element: this response carries the table
    // as well as the new credential, and htmx matches an out-of-band swap on
    // the id of the element carrying the attribute.
    context.insert("oob".to_string(), Value::Bool(true));

    let body = respond_fragment(&state, "eab/_created.html", context)?;
    Ok((StatusCode::CREATED, body).into_response())
}

/// `POST /ui/eab/{kid}/revoke`
pub async fn revoke_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    session: PageSessionWrite,
) -> Result<Html<String>, PageError> {
    // Idempotent, so a second revoke is not an error — but the row still has to
    // exist, or the operator is being told something happened to nothing.
    if !Eab::revoke(&kid, &state.database).await? {
        return Err(not_found(&kid));
    }

    tracing::info!(event = "admin_eab_revoked",
                   outcome = "success",
                   surface = "ui",
                   kid = %kid,
                   username = %session.auth.user.username);

    let eab = load(&kid, &state).await?;
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert("eab".to_string(), eab);
    context.insert(
        "flash".to_string(),
        flash(
            "ok",
            "Credential revoked. Registrations using it fail from now on.",
        ),
    );
    respond_fragment(&state, "eab/_card.html", context)
}

async fn rows(state: &AdminState) -> Result<Vec<Value>, PageError> {
    Ok(Eab::list_all(&state.database)
        .await?
        .iter()
        .map(admin::render_eab_json)
        .collect())
}

async fn load(kid: &str, state: &AdminState) -> Result<Value, PageError> {
    let eab = Eab::find_any_by_kid(kid, &state.database)
        .await?
        .ok_or_else(|| not_found(kid))?;
    Ok(admin::render_eab_json(&eab))
}

/// A form field left blank is absent, not the empty string.
fn non_empty(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn not_found(kid: &str) -> PageError {
    PageError::not_found(format!("no such EAB credential: {kid}"))
}
