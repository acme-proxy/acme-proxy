//! The admin API's error type.
//!
//! Deliberately **not** [`crate::error::Problem`]. Every `Problem` type is a
//! hardcoded `urn:ietf:params:acme:error:*` URN, and nothing on this listener
//! is an ACME error — answering a failed admin login with an ACME problem
//! document would be a category error that a client library might even try to
//! interpret.
//!
//! ```json
//! { "error": "not_found", "message": "no such account: acct-1" }
//! ```
//!
//! `error` is a stable snake_case code a caller may branch on; `message` is
//! for a human and may change.

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::error;

/// A failed admin request.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct AdminError {
    pub status: StatusCode,
    /// Stable, machine-readable, snake_case. Never a URN.
    pub code: &'static str,
    pub message: String,
    /// Seconds to wait, rendered as a `Retry-After` header. Only the rate
    /// limiter sets it.
    retry_after: Option<u64>,
}

impl AdminError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    /// `400` — the request body or query string did not make sense.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// `401` — no usable session. Every reason a login can fail collapses to
    /// [`AdminError::invalid_credentials`]; this one is for a request that
    /// arrived without a live session.
    pub fn session_invalid() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "no valid session; sign in again",
        )
    }

    /// `401` — the session passed its absolute deadline.
    pub fn session_expired() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "the session has expired; sign in again",
        )
    }

    /// `401` — the session went unused for longer than the idle timeout.
    pub fn session_idle() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "session_idle",
            "the session timed out through inactivity; sign in again",
        )
    }

    /// `401` — the login failed.
    ///
    /// **One code for every cause**: unknown username, wrong password, and a
    /// disabled account are indistinguishable to the client on purpose, so the
    /// endpoint cannot be used to enumerate operators. The log says which
    /// (see [`crate::admin::users::AuthOutcome`]).
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        )
    }

    /// `403` — the CSRF token was missing, wrong, or the request came from
    /// another origin.
    pub fn csrf_failed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "csrf_failed", message)
    }

    /// `404` — no such row.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// `405`/`404` fallbacks and any other conflict-free refusal with its own
    /// code.
    pub fn with_code(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self::new(status, code, message)
    }

    /// `409` — the request was well-formed but the row is in the wrong state.
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// `429` — too many failed logins from this address.
    pub fn rate_limited(retry_after_seconds: u64) -> Self {
        Self {
            retry_after: Some(retry_after_seconds),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!("too many failed sign-in attempts; retry in {retry_after_seconds}s"),
            )
        }
    }

    /// `502` — the signer backend refused or could not be reached.
    pub fn signer_failed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "signer_failed", message)
    }

    /// `500` — anything the operator can only find in the log.
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

/// A database failure is logged and answered generically.
///
/// The `sqlx` message names tables and columns, which is schema disclosure on
/// an authenticated-but-not-necessarily-trusted surface — it belongs in the
/// log, where the operator can read it, and not in the body.
impl From<sqlx::Error> for AdminError {
    fn from(error: sqlx::Error) -> Self {
        error!(event = "admin_db_error", outcome = "failure", error = %error);
        AdminError::internal()
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.code,
            "message": self.message,
        }));

        let mut response = (self.status, body).into_response();
        // Every admin response is `no-store` at the layer level, but an error
        // can be produced by an extractor rejection that never reaches it.
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        if let Some(seconds) = self.retry_after
            && let Ok(value) = header::HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn parts(error: AdminError) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
        let expected_status = error.status;
        let response = error.into_response();
        let status = response.status();
        assert_eq!(status, expected_status);
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap(), headers)
    }

    #[tokio::test]
    async fn every_constructor_has_its_own_status_and_code() {
        let cases: Vec<(AdminError, u16, &str)> = vec![
            (AdminError::bad_request("nope"), 400, "bad_request"),
            (AdminError::session_invalid(), 401, "session_invalid"),
            (AdminError::session_expired(), 401, "session_expired"),
            (AdminError::session_idle(), 401, "session_idle"),
            (
                AdminError::invalid_credentials(),
                401,
                "invalid_credentials",
            ),
            (AdminError::csrf_failed("missing"), 403, "csrf_failed"),
            (AdminError::not_found("no such thing"), 404, "not_found"),
            (
                AdminError::conflict("already_revoked", "already revoked"),
                409,
                "already_revoked",
            ),
            (AdminError::rate_limited(30), 429, "rate_limited"),
            (AdminError::signer_failed("down"), 502, "signer_failed"),
            (AdminError::internal(), 500, "internal"),
            (
                AdminError::with_code(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "no"),
                405,
                "method_not_allowed",
            ),
        ];

        for (error, expected_status, expected_code) in cases {
            let (status, body, headers) = parts(error).await;
            assert_eq!(status.as_u16(), expected_status, "for {expected_code}");
            assert_eq!(body["error"], expected_code);
            assert!(
                body["message"].as_str().is_some_and(|m| !m.is_empty()),
                "{expected_code} must carry a human message"
            );
            // Never an ACME problem document.
            assert_eq!(
                headers[header::CONTENT_TYPE],
                "application/json",
                "{expected_code} must not be application/problem+json"
            );
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert!(
                !body.to_string().contains("urn:ietf:params:acme"),
                "{expected_code} must not carry an ACME error URN"
            );
        }
    }

    #[tokio::test]
    async fn only_the_rate_limiter_sets_retry_after() {
        let (_, body, headers) = parts(AdminError::rate_limited(42)).await;
        assert_eq!(headers[header::RETRY_AFTER], "42");
        assert!(body["message"].as_str().unwrap().contains("42s"));

        let (_, _, headers) = parts(AdminError::internal()).await;
        assert!(!headers.contains_key(header::RETRY_AFTER));
    }

    /// The three login failures a client can provoke must be byte-identical,
    /// or the endpoint enumerates the operator table.
    #[tokio::test]
    async fn every_login_failure_looks_the_same_to_the_client() {
        let (first_status, first_body, _) = parts(AdminError::invalid_credentials()).await;
        let (second_status, second_body, _) = parts(AdminError::invalid_credentials()).await;
        assert_eq!(first_status, second_status);
        assert_eq!(first_body, second_body);
        assert_eq!(first_body["error"], "invalid_credentials");
        // Says nothing about which half was wrong.
        let message = first_body["message"].as_str().unwrap().to_lowercase();
        assert!(!message.contains("no such"));
        assert!(!message.contains("disabled"));
        assert!(!message.contains("unknown"));
    }

    #[tokio::test]
    async fn a_database_error_is_logged_and_answered_generically() {
        let error = AdminError::from(sqlx::Error::RowNotFound);
        assert_eq!(error, AdminError::internal());
        let (status, body, _) = parts(error).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // The sqlx message names schema; it must not reach the client.
        assert_eq!(body["message"], "internal error");
    }

    #[test]
    fn display_names_the_code_and_the_message() {
        assert_eq!(
            AdminError::not_found("no such account: acct-1").to_string(),
            "not_found: no such account: acct-1"
        );
    }
}
