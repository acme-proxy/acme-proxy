//! `/api/eab` — External Account Binding credentials.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::sqlite::eab::Eab;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};

#[derive(Debug, Deserialize, Default)]
pub struct CreateEab {
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub label: Option<String>,
    /// Bind the credential to one endpoint. Absent means every profile.
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub profile: Option<String>,
}

/// `GET /api/eab?limit=&offset=` — one page of credentials. Never the secret.
///
/// Takes `Query<PageParams>` directly rather than declaring the window inline:
/// the `#[serde(flatten)]` trap documented on `AccountListParams` needs a
/// filter to flatten *around*, and this listing has none. `oldest first` here,
/// where the other lists are newest first — see [`Eab::search`].
pub async fn list_eab(
    State(state): State<AdminState>,
    Query(params): Query<PageParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = params.resolve(&state.config);
    let (keys, total) = Eab::search(page.limit, page.offset, &state.database).await?;
    let items: Vec<Value> = keys.iter().map(admin::render_eab_json).collect();
    Ok(Json(page_envelope(items, total, page)))
}

/// `GET /api/eab/{kid}` — one credential. Never the secret.
pub async fn get_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let eab = Eab::find_any_by_kid(&kid, &state.database)
        .await?
        .ok_or_else(|| not_found(&kid))?;
    Ok(Json(admin::render_eab_json(&eab)))
}

/// `POST /api/eab` — mint a credential.
///
/// **The only response in this API that carries a secret.** It is shown once
/// and is not recoverable afterwards, exactly as `acme-proxy eab create`
/// behaves — a lost credential is replaced, never read back. The log records
/// the kid and never the secret.
pub async fn create_eab(
    State(state): State<AdminState>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    body: Option<Json<CreateEab>>,
) -> Result<Response, AdminError> {
    let Json(body) = body.unwrap_or_default();

    require_mounted_profile(&state, body.profile.as_deref(), "omit `profile`")?;

    let eab = Eab::create(body.label, body.profile, &state.database).await?;
    tracing::info!(event = "admin_eab_created",
                   outcome = "success",
                   surface = "api",
                   kid = %eab.kid,
                   profile = ?eab.profile,
                   username = %auth.user.username);

    Ok((
        StatusCode::CREATED,
        Json(admin::render_eab_created_json(&eab)),
    )
        .into_response())
}

/// `POST /api/eab/{kid}/revoke`
///
/// Spelled `revoke` rather than `DELETE`, because the row survives: the model
/// moves it to `revoked` and the CLI calls it the same thing. Accounts already
/// bound under it are deliberately unaffected.
pub async fn revoke_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
) -> Result<StatusCode, AdminError> {
    if !Eab::revoke(&kid, &state.database).await? {
        return Err(not_found(&kid));
    }
    tracing::info!(event = "admin_eab_revoked", outcome = "success", surface = "api", kid = %kid, username = %auth.user.username);
    Ok(StatusCode::NO_CONTENT)
}

/// Refuses a credential scoped to an endpoint this process does not serve.
///
/// Shared by both front ends, because the *condition* is one rule and two
/// copies of it drift: such a credential would be accepted and then never be
/// usable, which is worth catching while the operator is still looking at what
/// they typed. `hint` is the one part that is legitimately per-front-end — a
/// JSON caller omits a field, someone at a form leaves an input blank.
pub(crate) fn require_mounted_profile(
    state: &AdminState,
    profile: Option<&str>,
    hint: &str,
) -> Result<(), AdminError> {
    if let Some(name) = profile
        && !state.profiles.contains_key(name)
    {
        return Err(AdminError::bad_request(format!(
            "no profile named `{name}` is mounted; {hint} for a credential valid at \
             every endpoint"
        )));
    }
    Ok(())
}

fn not_found(kid: &str) -> AdminError {
    AdminError::not_found(format!("no such EAB credential: {kid}"))
}
