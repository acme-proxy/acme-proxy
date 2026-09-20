//! `/api/eab` — External Account Binding credentials.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::Caller;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::handlers::params::empty_is_absent;
use crate::webadmin::session::{Authenticated, AuthenticatedWrite};
use acme_proxy_store::eab::BoundAccounts;
use acme_proxy_store::eab::DeletedEab;
use acme_proxy_store::eab::Eab;
use acme_proxy_store::eab::EabDeletion;

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
/// filter to flatten *around*, and this listing has none. Newest first, like
/// every other listing — see [`Eab::search`] for why its tiebreak runs the
/// same way as its primary key rather than against it.
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
    request_context: acme_proxy_core::audit::RequestContext,
    body: Option<Json<CreateEab>>,
) -> Result<Response, AdminError> {
    let Json(body) = body.unwrap_or_default();
    let eab = apply_create_eab(
        &state,
        &Caller::api(&auth, &request_context),
        body.label,
        body.profile,
        "omit `profile`",
    )
    .await?;

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
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<StatusCode, AdminError> {
    apply_revoke_eab(&state, &Caller::api(&auth, &request_context), &kid).await?;
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
    request_context: acme_proxy_core::audit::RequestContext,
) -> Result<Json<Value>, AdminError> {
    let accounts = params.resolve()?;
    let deleted = apply_delete_eab(
        &state,
        &Caller::api(&auth, &request_context),
        &kid,
        accounts,
    )
    .await?;

    let orders: u64 = deleted.deleted.iter().map(|(_, orders)| orders).sum();
    Ok(Json(serde_json::json!({
        "deleted": { "accounts": deleted.deleted.len(), "orders": orders },
        "deactivatedAccounts": deleted.deactivated.len(),
        "keptAccounts": deleted.remaining,
    })))
}

/// Mints a credential: the mounted-profile check, the row, its audit row and
/// the log line. `hint` is the front end's wording of "leave the profile out"
/// (see [`require_mounted_profile`]).
pub(crate) async fn apply_create_eab(
    state: &AdminState,
    caller: &Caller<'_>,
    label: Option<String>,
    profile: Option<String>,
    hint: &str,
) -> Result<Eab, AdminError> {
    require_mounted_profile(state, profile.as_deref(), hint)?;

    let eab = Eab::create(label, profile, &state.database).await?;
    state
        .record_admin_action(caller.request, caller.username(), |actor, client| {
            acme_proxy_jobs::auditor::admin::eab_created(
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
                   surface = caller.surface,
                   kid = %eab.kid,
                   profile = ?eab.profile,
                   username = %caller.username());
    Ok(eab)
}

/// Revokes a credential, keeping its row. Idempotent, but the row has to
/// exist, or the operator is being told something happened to nothing. Only
/// the revoke that changed something records a row.
pub(crate) async fn apply_revoke_eab(
    state: &AdminState,
    caller: &Caller<'_>,
    kid: &str,
) -> Result<(), AdminError> {
    let subject = Eab::find_any_by_kid(kid, &state.database).await?;
    if !Eab::revoke(kid, &state.database).await? {
        return Err(not_found(kid));
    }
    if let Some(eab) = subject.as_ref().filter(|eab| eab.status == "active") {
        state
            .record_admin_action(caller.request, caller.username(), |actor, client| {
                acme_proxy_jobs::auditor::admin::eab_revoked(
                    actor,
                    client,
                    kid,
                    eab.profile.as_deref(),
                )
            })
            .await;
    }
    tracing::info!(event = "admin_eab_revoked",
                   outcome = "success",
                   surface = caller.surface,
                   kid = %kid,
                   username = %caller.username());
    Ok(())
}

/// Deletes a credential, doing `accounts` to the accounts it bound. `404` for
/// no such credential, `409 live_certificates` when `accounts=delete` would
/// take a live certificate's order with it; nothing changes then.
pub(crate) async fn apply_delete_eab(
    state: &AdminState,
    caller: &Caller<'_>,
    kid: &str,
    accounts: BoundAccounts,
) -> Result<DeletedEab, AdminError> {
    let deleted = deleted_or_refused(
        kid,
        admin::delete_eab(kid, accounts, state.database.clone()).await?,
    )?;

    state
        .record_admin_actions(caller.request, caller.username(), |actor, client| {
            acme_proxy_jobs::auditor::admin::eab_deleted_records(actor, client, &deleted)
        })
        .await;
    tracing::info!(event = "admin_eab_deleted",
                   outcome = "success",
                   surface = caller.surface,
                   kid = %kid,
                   accounts = accounts.as_str(),
                   username = %caller.username());
    Ok(deleted)
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

/// Refuses a credential scoped to an endpoint this process does not serve, in
/// this state's terms; the rule itself is
/// [`ops::unmounted_profile_refusal`](crate::admin::ops::unmounted_profile_refusal),
/// which `eab create` on the host CLI asks too.
pub(crate) fn require_mounted_profile(
    state: &AdminState,
    profile: Option<&str>,
    hint: &str,
) -> Result<(), AdminError> {
    match crate::admin::ops::unmounted_profile_refusal(
        |name| state.profiles.contains_key(name),
        profile,
        hint,
    ) {
        Some(message) => Err(AdminError::bad_request(message)),
        None => Ok(()),
    }
}

fn not_found(kid: &str) -> AdminError {
    AdminError::not_found(format!("no such EAB credential: {kid}"))
}
