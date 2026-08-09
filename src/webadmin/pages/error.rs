//! The page layer's error type.
//!
//! Deliberately **not** [`AdminError`], for the same reason `AdminError` is not
//! [`crate::error::Problem`]: its `IntoResponse` is hardcoded to
//! `application/json`, and a browser navigating to `/ui/accounts` without a
//! session must land on the sign-in page, not on a JSON document.
//!
//! ## Why the shape is chosen at construction
//!
//! There are two kinds of caller and they need two different answers to a `401`:
//!
//! - a **browser** following a link wants `303 See Other` and a `Location`;
//! - an **htmx** request wants an `HX-Redirect` header, which makes htmx do a
//!   real navigation rather than swapping the sign-in page into a `<div>`.
//!
//! A `303` cannot serve both: `fetch` follows a redirect transparently, so htmx
//! would only ever see the *final* response's headers and would swap the
//! sign-in page's markup wherever the click came from. The page extractors have
//! `parts.headers` in hand and read `HX-Request` there, which is why the
//! decision lives at construction rather than in `into_response`.
//!
//! ## Why it renders no template
//!
//! The error document is a `const` with two holes, not a `minijinja` render.
//! An error path that can itself fail is not an error path — the same reasoning
//! that keeps `AdminError`'s body a `serde_json::json!` literal.

use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use crate::webadmin::error::AdminError;

/// A failed page request.
#[derive(Debug, PartialEq, Eq)]
pub enum PageError {
    /// Sign-in is needed: `303` + `Location` for a browser, `HX-Redirect` for
    /// htmx.
    Redirect { location: String, hx: bool },
    /// Anything else: the real status, plus a standalone HTML document.
    Rendered {
        status: StatusCode,
        /// The same stable snake_case code the JSON API uses, so an operator
        /// reporting a problem quotes one string whichever front end they were
        /// on.
        code: &'static str,
        message: String,
    },
}

/// Where an unauthenticated request is sent.
pub const LOGIN_PATH: &str = "/ui/login";

impl PageError {
    /// The redirect an expired or absent session produces.
    #[must_use]
    pub fn login_required(hx: bool) -> Self {
        Self::Redirect {
            location: LOGIN_PATH.to_string(),
            hx,
        }
    }

    /// `404` — no such row.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::Rendered {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    /// `500` — anything the operator can only find in the log.
    #[must_use]
    pub fn internal() -> Self {
        Self::Rendered {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "internal error".to_string(),
        }
    }

    /// The status this will answer with, which for a redirect is the redirect's
    /// own — useful mostly to tests.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            // 204 rather than 200: htmx must not swap anything, it must
            // navigate.
            Self::Redirect { hx: true, .. } => StatusCode::NO_CONTENT,
            Self::Redirect { hx: false, .. } => StatusCode::SEE_OTHER,
            Self::Rendered { status, .. } => *status,
        }
    }
}

/// A `401` from the API layer means "sign in"; everything else keeps its status.
///
/// This is the one place the two error vocabularies meet, and it is a
/// conversion rather than a shared type on purpose: `AdminError` answers a
/// script, `PageError` answers a browser, and the day one grows a member the
/// other should not have, nothing has to be untangled.
impl From<AdminError> for PageError {
    fn from(error: AdminError) -> Self {
        Self::Rendered {
            status: error.status,
            code: error.code,
            message: error.message,
        }
    }
}

/// Routed through [`AdminError`] so the `admin_db_error` log line — which
/// carries the table and column names the body must not — still happens exactly
/// once.
impl From<sqlx::Error> for PageError {
    fn from(error: sqlx::Error) -> Self {
        AdminError::from(error).into()
    }
}

impl std::fmt::Display for PageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redirect { location, .. } => write!(formatter, "redirect: {location}"),
            Self::Rendered { code, message, .. } => write!(formatter, "{code}: {message}"),
        }
    }
}

impl std::error::Error for PageError {}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut response = match self {
            Self::Redirect { location, hx } => redirect(&location, hx),
            Self::Rendered { code, message, .. } => {
                (status, Html(document(status, code, &message))).into_response()
            }
        };

        // Every admin response is `no-store` at the layer level, but an
        // extractor rejection never reaches it.
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}

/// A navigation the browser should perform, expressed the way the caller can
/// actually obey.
///
/// Shared by the failure path above and by the successes that end somewhere
/// else — signing in, signing out, deleting the row whose page you were on. The
/// `hx` branch is the whole reason this is a function: see the module docs.
pub(crate) fn redirect(location: &str, hx: bool) -> Response {
    let Ok(value) = header::HeaderValue::from_str(location) else {
        // Every caller passes a constant or a path this crate built; an
        // unencodable one is a bug, and a `500` beats a panic in a handler.
        tracing::error!(event = "admin_redirect_unencodable", location = location);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if hx {
        // `204` so htmx swaps nothing and navigates instead.
        (StatusCode::NO_CONTENT, [("hx-redirect", value)]).into_response()
    } else {
        (StatusCode::SEE_OTHER, [(header::LOCATION, value)]).into_response()
    }
}

/// The error page: no template engine, no context, no way to fail.
fn document(status: StatusCode, code: &str, message: &str) -> String {
    format!(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head><meta charset=\"utf-8\"><title>{status} — acme-proxy admin</title>\
         <link rel=\"stylesheet\" href=\"/ui/static/admin.css\"></head>\n\
         <body><main><h1>{status}</h1>\
         <div class=\"panel\"><p>{}</p>\
         <p class=\"muted small\">Error code: <code>{}</code></p></div>\
         <p class=\"small\"><a href=\"/ui/\">← Back to the panel</a></p>\
         </main></body></html>\n",
        escape_html(message),
        escape_html(code),
    )
}

/// Minimal HTML escaping for the error document.
///
/// Not decoration: an error message interpolates the id from the path
/// (`no such account: {id}`), and a path segment is attacker-controlled. The
/// templates get this from minijinja; this document has no template.
fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_of(error: PageError) -> String {
        let response = error.into_response();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn a_browser_redirect_is_a_see_other_with_a_location() {
        let response = PageError::login_required(false).into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], LOGIN_PATH);
        assert!(!response.headers().contains_key("hx-redirect"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    /// The pair the whole type exists for: htmx must navigate, not swap.
    ///
    /// A `303` here would be followed by `fetch` before htmx ever saw a header,
    /// and the sign-in page would be swapped into whatever element the click
    /// came from.
    #[test]
    fn an_htmx_redirect_is_a_header_and_no_body() {
        let response = PageError::login_required(true).into_response();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["hx-redirect"], LOGIN_PATH);
        assert!(!response.headers().contains_key("location"));
    }

    #[tokio::test]
    async fn a_rendered_error_is_an_html_document_carrying_its_code() {
        let error = PageError::not_found("no such account: acct-1");
        assert_eq!(error.status(), StatusCode::NOT_FOUND);

        let body = body_of(error).await;
        assert!(body.starts_with("<!doctype html>"));
        assert!(body.contains("no such account: acct-1"));
        assert!(body.contains("<code>not_found</code>"));
    }

    #[tokio::test]
    async fn a_message_carrying_markup_is_escaped() {
        // The id comes from the path, so this is reachable by anyone who can
        // reach the panel at all.
        let body = body_of(PageError::not_found(
            "no such account: <script>alert(1)</script>",
        ))
        .await;
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn escape_html_covers_every_delimiter() {
        assert_eq!(
            escape_html(r#"<a href="x" id='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; id=&#x27;y&#x27;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(escape_html("plain"), "plain");
    }

    #[test]
    fn an_admin_error_keeps_its_status_and_code() {
        let error: PageError = AdminError::conflict("already_revoked", "already revoked").into();
        assert_eq!(error.status(), StatusCode::CONFLICT);
        assert_eq!(
            error,
            PageError::Rendered {
                status: StatusCode::CONFLICT,
                code: "already_revoked",
                message: "already revoked".to_string(),
            }
        );
    }

    #[test]
    fn internal_says_nothing_a_log_should_have_said() {
        let error = PageError::internal();
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.to_string(), "internal: internal error");
    }

    #[test]
    fn display_names_the_redirect_target() {
        assert_eq!(
            PageError::login_required(true).to_string(),
            "redirect: /ui/login"
        );
    }
}
