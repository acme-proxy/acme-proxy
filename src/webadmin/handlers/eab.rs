//! `/api/eab` — External Account Binding credentials.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::sqlite::eab::{BoundAccounts, DeletedEab, Eab, EabDeletion};
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

/// The query of `DELETE /api/eab/{kid}` and `DELETE /ui/eab/{kid}`.
#[derive(Debug, Deserialize, Default)]
pub struct DeleteEabParams {
    /// `keep` (the default), `deactivate` or `delete`: what happens to the
    /// accounts the credential bound. See [`BoundAccounts`].
    #[serde(default, deserialize_with = "empty_is_absent")]
    pub accounts: Option<String>,
}

impl DeleteEabParams {
    /// The mode, refusing an unknown one **by name** and listing the
    /// alternatives, as `order list --status` does: guessing `keep` for a typo
    /// of `delete` would answer a destructive request with a different one.
    pub(crate) fn resolve(&self) -> Result<BoundAccounts, AdminError> {
        let Some(value) = self.accounts.as_deref() else {
            return Ok(BoundAccounts::Keep);
        };
        BoundAccounts::parse(value).ok_or_else(|| {
            let known: Vec<&str> = BoundAccounts::ALL
                .iter()
                .map(|mode| mode.as_str())
                .collect();
            AdminError::bad_request(format!(
                "unknown accounts mode `{value}`; expected one of: {}",
                known.join(", ")
            ))
        })
    }
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
    request_context: crate::audit::RequestContext,
    body: Option<Json<CreateEab>>,
) -> Result<Response, AdminError> {
    let Json(body) = body.unwrap_or_default();

    require_mounted_profile(&state, body.profile.as_deref(), "omit `profile`")?;

    let eab = Eab::create(body.label, body.profile, &state.database).await?;
    state
        .record_admin_action(&request_context, &auth.user.username, |actor, client| {
            crate::audit::admin::eab_created(
                actor,
                client,
                &eab.kid.to_string(),
                eab.profile.as_deref(),
                eab.label.as_deref(),
            )
        })
        .await;
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
/// A `POST` to `revoke` rather than a `DELETE`, because the row survives: the
/// model moves it to `revoked` and the CLI calls it the same thing. Accounts
/// already bound under it are deliberately unaffected, and keep resolving to it
/// — which is what separates this from [`delete_eab`].
pub async fn revoke_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    request_context: crate::audit::RequestContext,
) -> Result<StatusCode, AdminError> {
    let subject = Eab::find_any_by_kid(&kid, &state.database).await?;
    if !Eab::revoke(&kid, &state.database).await? {
        return Err(not_found(&kid));
    }
    // A repeat revoke changes nothing, so it records nothing.
    if subject.as_ref().is_some_and(|eab| eab.status == "active") {
        let profile = subject.as_ref().and_then(|eab| eab.profile.as_deref());
        state
            .record_admin_action(&request_context, &auth.user.username, |actor, client| {
                crate::audit::admin::eab_revoked(actor, client, &kid, profile)
            })
            .await;
    }
    tracing::info!(event = "admin_eab_revoked", outcome = "success", surface = "api", kid = %kid, username = %auth.user.username);
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/eab/{kid}?accounts=keep|deactivate|delete`
///
/// Removes the row, where [`revoke_eab`] keeps it. Answers `200` with what it
/// did to the accounts rather than a bare `204`, the `DELETE
/// /api/accounts/{id}` shape: `deleted` counts accounts and the orders that
/// cascaded with them, `deactivatedAccounts` those moved to `deactivated`, and
/// `keptAccounts` those still in the table naming a credential that is now
/// gone. `409 live_certificates` when `accounts=delete` would take a live
/// certificate's order with it; nothing changes then.
pub async fn delete_eab(
    State(state): State<AdminState>,
    Path(kid): Path<String>,
    Query(params): Query<DeleteEabParams>,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    request_context: crate::audit::RequestContext,
) -> Result<Json<Value>, AdminError> {
    let accounts = params.resolve()?;
    let deleted = deleted_or_refused(
        &kid,
        admin::delete_eab(&kid, accounts, state.database.clone()).await?,
    )?;

    state
        .record_admin_actions(&request_context, &auth.user.username, |actor, client| {
            crate::audit::admin::eab_deleted_records(actor, client, &deleted)
        })
        .await;
    tracing::info!(event = "admin_eab_deleted",
                   outcome = "success",
                   surface = "api",
                   kid = %kid,
                   accounts = accounts.as_str(),
                   username = %auth.user.username);

    let orders: u64 = deleted.deleted.iter().map(|(_, orders)| orders).sum();
    Ok(Json(serde_json::json!({
        "deleted": { "accounts": deleted.deleted.len(), "orders": orders },
        "deactivatedAccounts": deleted.deactivated.len(),
        "keptAccounts": deleted.remaining,
    })))
}

/// An [`EabDeletion`] as either what was deleted or the refusal both front ends
/// answer with.
pub(crate) fn deleted_or_refused(
    kid: &str,
    deletion: EabDeletion,
) -> Result<DeletedEab, AdminError> {
    match deletion {
        EabDeletion::NotFound => Err(not_found(kid)),
        EabDeletion::LiveCertificates {
            accounts,
            certificates,
        } => Err(AdminError::conflict(
            "live_certificates",
            admin::eab_live_certificates_refusal(kid, accounts, certificates),
        )),
        EabDeletion::Deleted(deleted) => Ok(deleted),
    }
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
