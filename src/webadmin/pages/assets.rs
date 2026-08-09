//! `GET /ui/static/{file}` — the two vendored assets, out of the binary.
//!
//! Embedded rather than served from disk: a deployment stays one executable,
//! and `tower-http`'s `fs` feature — with the path-traversal surface that comes
//! with it — stays off. The match below is the entire allowlist, so there is no
//! traversal to defend against in the first place.
//!
//! **Outside the session requirement.** The sign-in page needs the stylesheet
//! before anyone has a session, and neither file says anything about this
//! deployment: `htmx.min.js` is a public release (see `static/README.md` for
//! its provenance) and `admin.css` is a stylesheet.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const HTMX_JS: &str = include_str!("../static/htmx.min.js");
const ADMIN_CSS: &str = include_str!("../static/admin.css");

/// `GET /ui/static/{file}`.
pub async fn get_asset(Path(file): Path<String>) -> Response {
    let (content_type, body) = match file.as_str() {
        "htmx.min.js" => ("text/javascript; charset=utf-8", HTMX_JS),
        "admin.css" => ("text/css; charset=utf-8", ADMIN_CSS),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    (
        [(header::CONTENT_TYPE, content_type)],
        // Not `Html`/`Json`: these are served verbatim, and the response
        // hardening layers (`nosniff` in particular) are applied at the router
        // root and reach here unchanged.
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn each_known_asset_is_served_with_its_own_type() {
        for (file, content_type, marker) in [
            ("htmx.min.js", "text/javascript; charset=utf-8", "htmx"),
            ("admin.css", "text/css; charset=utf-8", ".htmx-indicator"),
        ] {
            let response = get_asset(Path(file.to_string())).await;
            assert_eq!(response.status(), StatusCode::OK, "{file}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);

            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(body.contains(marker), "{file} looks like the wrong file");
        }
    }

    /// The allowlist is the whole security model here, so a name outside it —
    /// including anything that looks like traversal — is a plain `404`.
    #[tokio::test]
    async fn an_unknown_name_is_not_found() {
        for file in ["../Cargo.toml", "htmx.js", "", "admin.css/"] {
            let response = get_asset(Path(file.to_string())).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{file}");
        }
    }

    /// The htmx-config settings in `layout.html` are only half of the pair;
    /// these rules are the other half, and dropping them leaves every htmx
    /// indicator permanently visible.
    #[test]
    fn the_stylesheet_carries_the_indicator_rules_htmx_is_told_not_to_inject() {
        assert!(ADMIN_CSS.contains(".htmx-indicator"));
        assert!(ADMIN_CSS.contains(".htmx-request .htmx-indicator"));
    }

    #[test]
    fn the_vendored_htmx_is_the_version_the_readme_records() {
        assert!(HTMX_JS.contains(r#"version:"2.0.10""#));
    }
}
