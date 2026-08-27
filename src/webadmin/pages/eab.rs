//! `/ui/eab` — External Account Binding credentials.
//!
//! The one page in this tree that ever renders a secret, and it renders it
//! exactly once: `render_eab_created_json` is the only renderer carrying
//! `hmacKey`, the list and the detail read the same row through
//! `render_eab_json`, and `Eab::to_json` has no such member. A lost credential
//! is replaced, never recovered.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::admin;
use crate::sqlite::eab::Eab;
use crate::webadmin::AdminState;
use crate::webadmin::handlers::paging::{Page, PageParams};
use crate::webadmin::handlers::params::non_empty;
use crate::webadmin::pages::auth::{PageSession, PageSessionWrite};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::{chrome, flash, page_value, pager, respond, respond_fragment};

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

/// `GET /ui/eab?limit=&offset=`
///
/// Paged over `Eab::search`, the same query `GET /api/eab` and `eab list` read
/// -- one listing, three surfaces, so none of them can come to describe the
/// credential set differently. It was unpaged over an `Eab::list_all` that no
/// longer exists, on the argument that an operator mints these by hand a few at
/// a time; that is true of how the table fills and says nothing about how long
/// it has been filling.
pub async fn list_eab(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    session: PageSession,
) -> Result<Html<String>, PageError> {
    let page = params.resolve(&state.config);
    let (items, total) = rows(page, &state).await?;

    let mut context = chrome(&session, "eab", "External Account Binding");
    context.insert("page".to_string(), page_value(items, total));
    context.insert(
        "pager".to_string(),
        pager(page, total, "/ui/eab", &[], "#eab-table"),
    );
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

    // The **first** page, whatever page the form was posted from, and the
    // reason `Eab::search` is newest first: a credential minted a moment ago is
    // its first row, so the refreshed table below the form is guaranteed to
    // contain the row the secret above it belongs to. Re-rendering the
    // operator's current page instead would show the new credential only when
    // they happened to be on the right one.
    let page = PageParams::default().resolve(&state.config);
    let (items, total) = rows(page, &state).await?;

    let mut context = Map::new();
    context.insert("eab".to_string(), admin::render_eab_created_json(&eab));
    context.insert("page".to_string(), page_value(items, total));
    context.insert(
        "pager".to_string(),
        pager(page, total, "/ui/eab", &[], "#eab-table"),
    );
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

async fn rows(page: Page, state: &AdminState) -> Result<(Vec<Value>, i64), PageError> {
    let (keys, total) = Eab::search(page.limit, page.offset, &state.database).await?;
    Ok((keys.iter().map(admin::render_eab_json).collect(), total))
}

async fn load(kid: &str, state: &AdminState) -> Result<Value, PageError> {
    let eab = Eab::find_any_by_kid(kid, &state.database)
        .await?
        .ok_or_else(|| not_found(kid))?;
    Ok(admin::render_eab_json(&eab))
}

fn not_found(kid: &str) -> PageError {
    PageError::not_found(format!("no such EAB credential: {kid}"))
}
