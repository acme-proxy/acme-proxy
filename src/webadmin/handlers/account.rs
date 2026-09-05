//! `/api/account` — the operator's own account, distinct from `/api/mfa`'s
//! second factor: currently just the password.
//!
//! No id in the one route here either, for the same reason `/api/mfa` has
//! none: there is exactly one account this session can be about.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::admin::password::PasswordContext;
use crate::admin::users::{self, UserError};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::mfa::verify_current_password;
use crate::webadmin::session::{AdminClientIp, AuthenticatedWrite};

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// `POST /api/account/password` — change this operator's own password.
///
/// ASVS V6.2.3: takes the *current* password and verifies it
/// ([`verify_current_password`]) before writing a new hash, unlike
/// `acme-proxy admin user passwd` on the host, which already runs as the
/// process trusted to rewrite the row. Every other session this operator
/// holds is revoked ([`users::change_own_password`]); the one making this
/// request survives, or the panel would sign its own operator out mid-edit.
pub async fn change_password(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    AuthenticatedWrite(auth): AuthenticatedWrite,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, AdminError> {
    let mut user = auth.user;
    verify_current_password(&user, &body.current_password, client, &state.logins)?;

    let context = PasswordContext::from_config(&state.config, &user.username);
    users::change_own_password(
        &mut user,
        &body.new_password,
        &context,
        &auth.session.token_hash,
        state.database.clone(),
    )
    .await
    .map_err(|error| match error {
        UserError::Policy(message) => AdminError::bad_request(message),
        UserError::Database(_) | UserError::DuplicateUsername(_) => AdminError::internal(),
    })?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
