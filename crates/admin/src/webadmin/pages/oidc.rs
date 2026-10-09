//! `/ui/login/oidc/{provider}` and its `/callback` -- signing in through an
//! OpenID Connect provider (authorization code flow, PKCE `S256`).
//!
//! Two unauthenticated `GET`s, and deliberately **without** `check_origin`:
//! the start is a link on the sign-in page, and the callback is a navigation
//! the *provider's* site begins, which a browser reports as `cross-site` on
//! every hop. What stands in for the origin gate:
//!
//! - **`state` is single-use and server-side.** The start writes an
//!   `admin_oidc_logins` row keyed by `hex(SHA-256(state))`; the callback
//!   deletes it in the same statement that reads it, so a replayed callback
//!   finds nothing.
//! - **The browser is bound to its own sign-in** by the
//!   `__Host-acme_admin_oidc` cookie (`SameSite=Lax`, so it survives the
//!   provider's redirect back), whose hash the row holds. A callback carried to
//!   another browser -- login CSRF, an attacker's code planted in a victim's
//!   session -- has a `state` that browser never received the cookie for.
//! - **The `nonce` binds the ID token to the row**, and the PKCE verifier the
//!   code to the browser that started it.
//!
//! The callback answers `200` with a page that refreshes to the panel, not a
//! `303` -- see `login_complete.html` for the `SameSite=Strict` reason.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::identity::oidc::Callback;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::session::{Refusal, refusal, start_session};
use crate::webadmin::pages::error::PageError;
use crate::webadmin::pages::session::page;
use crate::webadmin::pages::templates;
use crate::webadmin::session::{
    AdminClientIp, hash_token, log_login, mint_token, named_cookie_value,
};
use acme_proxy_store::admin_oidc_login::AdminOidcLogin;

/// The browser-binding cookie of a sign-in in flight.
pub const FLOW_COOKIE: &str = "__Host-acme_admin_oidc";

/// How long a sign-in may spend at the provider. Long enough for a person to
/// complete a second factor there; short enough that an abandoned row is
/// swept within the hour.
pub const FLOW_TTL_SECONDS: i64 = 600;

/// The query a provider calls back with (RFC 6749 §4.1.2, §4.1.2.1).
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Set instead of `code` when the provider refused (`access_denied`, ...).
    #[serde(default)]
    pub error: Option<String>,
}

/// `GET /ui/login/oidc/{provider}` -- send the browser to the provider.
pub async fn start(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    Path(name): Path<String>,
) -> Result<Response, PageError> {
    let Some(provider) = state.providers.oidc.get(&name) else {
        return Err(PageError::not_found("no such sign-in provider"));
    };
    let realm = provider.key();

    // Not a credential, but each start writes a row: the limiter bounds that
    // the way it bounds password attempts. The slot is given back uncounted.
    if let Err(retry_after) = state.logins.begin(client) {
        log_login(false, "", &realm, client, "rate_limited");
        return refused(&state, &AdminError::rate_limited(retry_after));
    }

    let flow_state = mint_token();
    let binding = mint_token();
    let nonce = mint_token().token;
    let verifier = mint_token().token;
    let redirect_uri = redirect_uri(&state, &name);

    let authorize = match provider
        .authorization_url(&redirect_uri, &flow_state.token, &nonce, &verifier)
        .await
    {
        Ok(url) => url,
        Err(error) => {
            if let Refusal::Unreachable(detail) = refusal(error) {
                tracing::warn!(event = "admin_login_provider_failed",
                               outcome = "failure",
                               realm = %realm,
                               error = %detail);
            }
            log_login(false, "", &realm, client, "provider_unreachable");
            return refused(&state, &AdminError::provider_unavailable());
        }
    };

    let now = acme_proxy_store::nonce::now_secs();
    AdminOidcLogin {
        state_hash: flow_state.token_hash,
        provider: name,
        binding_hash: binding.token_hash,
        nonce,
        pkce_verifier: verifier,
        created_at: now,
        expires_at: now + FLOW_TTL_SECONDS,
    }
    .create(&state.database)
    .await
    .map_err(AdminError::from)?;

    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, authorize.to_string()),
            (header::SET_COOKIE, flow_cookie(&binding.token)),
        ],
    )
        .into_response())
}

/// `GET /ui/login/oidc/{provider}/callback` -- finish the sign-in.
pub async fn callback(
    State(state): State<AdminState>,
    AdminClientIp(client): AdminClientIp,
    Path(name): Path<String>,
    headers: HeaderMap,
    request_context: acme_proxy_core::audit::RequestContext,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, PageError> {
    let Some(provider) = state.providers.oidc.get(&name) else {
        return Err(PageError::not_found("no such sign-in provider"));
    };
    let realm = provider.key();

    let attempt = match state.logins.begin(client) {
        Ok(attempt) => attempt,
        Err(retry_after) => {
            log_login(false, "", &realm, client, "rate_limited");
            return refused(&state, &AdminError::rate_limited(retry_after));
        }
    };

    // The row first, whatever else the query says: an error callback still
    // consumes its `state`, so it cannot be presented again with a code.
    let login = match &query.state {
        Some(flow_state) => AdminOidcLogin::take(
            &hash_token(flow_state),
            acme_proxy_store::nonce::now_secs(),
            &state.database,
        )
        .await
        .map_err(AdminError::from)?,
        None => None,
    };
    let bound = login.as_ref().is_some_and(|login| {
        login.provider == name
            && named_cookie_value(&headers, FLOW_COOKIE).is_some_and(|binding| {
                subtle::ConstantTimeEq::ct_eq(
                    hash_token(&binding).as_bytes(),
                    login.binding_hash.as_bytes(),
                )
                .into()
            })
    });
    let (Some(login), true, Some(code), None) = (login, bound, &query.code, &query.error) else {
        attempt.failed();
        let reason = if query.error.is_some() {
            "provider_refused"
        } else {
            "flow_invalid"
        };
        log_login(false, "", &realm, client, reason);
        return refused(&state, &AdminError::invalid_credentials());
    };

    let completed = provider
        .complete(&Callback {
            code,
            pkce_verifier: &login.pkce_verifier,
            nonce: &login.nonce,
            redirect_uri: &redirect_uri(&state, &name),
            now: acme_proxy_store::nonce::now_secs(),
        })
        .await;
    let provisioned = match completed {
        Ok(identity) => {
            let trail = crate::webadmin::ProviderTrail {
                state: &state,
                request_context: &request_context,
                provider: &identity.provider,
            };
            crate::identity::provision(&identity, &provider.roles, state.database.clone(), &trail)
                .await
                .map_err(|error| (identity.username.clone(), refusal(error)))
        }
        Err(error) => Err((String::new(), refusal(error))),
    };

    let user = match provisioned {
        Ok(user) => user,
        Err((username, Refusal::Unreachable(detail))) => {
            tracing::warn!(event = "admin_login_provider_failed",
                           outcome = "failure",
                           realm = %realm,
                           error = %detail);
            log_login(false, &username, &realm, client, "provider_unreachable");
            return refused(&state, &AdminError::provider_unavailable());
        }
        Err((username, Refusal::Refused(reason))) => {
            attempt.failed();
            log_login(false, &username, &realm, client, reason);
            return refused(&state, &AdminError::invalid_credentials());
        }
    };

    // The provider owns this person's authentication, second factor included
    // (`required_amr` is how an operator insists on one): no local step.
    let signed_in = start_session(&state, client, &headers, user, &realm, None).await?;
    let body = templates::render(
        &state.templates,
        "login_complete.html",
        minijinja::Value::from_serialize(Value::Object(Map::new())),
    )?;
    let mut response = (StatusCode::OK, body).into_response();
    for cookie in [signed_in.cookie, clearing_flow_cookie()] {
        if let Ok(value) = header::HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    Ok(response)
}

/// Where the provider is told to send the browser back: under
/// `admin.base_url`, the origin the panel is reached at -- the same value the
/// provider's client registration must list.
fn redirect_uri(state: &AdminState, name: &str) -> String {
    format!(
        "{}/ui/login/oidc/{name}/callback",
        state.config.admin.base_url.trim_end_matches('/')
    )
}

/// The sign-in page with the refusal's banner, at the refusal's status, and
/// the flow cookie cleared: whatever this sign-in was, it is over.
fn refused(state: &AdminState, error: &AdminError) -> Result<Response, PageError> {
    let flash = super::flash_error(error.code, error.message.clone());
    let mut response = (error.status, page(state, Some(flash), None)?).into_response();
    if let Ok(value) = header::HeaderValue::from_str(&clearing_flow_cookie()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

/// `SameSite=Lax`, unlike the session cookie: it has to come back on the
/// provider's top-level redirect, which `Strict` would withhold.
fn flow_cookie(binding: &str) -> String {
    format!(
        "{FLOW_COOKIE}={binding}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={FLOW_TTL_SECONDS}"
    )
}

fn clearing_flow_cookie() -> String {
    format!("{FLOW_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}
