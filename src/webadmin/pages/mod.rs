//! `/ui` — the HTML the operator actually looks at.
//!
//! ## Why this is separate from `handlers/`
//!
//! `handlers/` answers JSON at `/api`; this answers HTML at `/ui`. Both are
//! thin layers over the same `src/admin/` operations, which is the whole point:
//! neither re-derives data, and neither is where a rule lives. Two small
//! handlers over one operation beat one handler content-negotiating itself into
//! two representations — htmx swaps markup, and a `text/html` branch inside a
//! JSON handler is where the two would start disagreeing.
//!
//! ## Pages and fragments
//!
//! Every list and detail route serves both. A normal navigation gets the full
//! document — the layout, the navigation, the page's content — and an htmx
//! request gets the bare partial it is going to swap in. The choice is made off
//! the `HX-Request` header ([`auth::is_htmx`]), not off the route, so there is
//! one URL per resource and it is bookmarkable.
//!
//! ## What makes a write safe here
//!
//! Exactly what makes it safe on the API: [`PageSessionWrite`] wraps
//! [`crate::webadmin::session::AuthenticatedWrite`], so the origin gate, the
//! session lookup and the CSRF check all run before a mutating handler can see
//! a session. The token reaches the browser through `hx-headers` on `<body>` in
//! `layout.html` and comes back as `X-CSRF-Token` — the same header the JSON
//! API uses, and the reason `check_csrf` needed no second code path.

pub mod account;
pub mod accounts;
pub mod assets;
pub mod audit;
pub mod auth;
pub mod eab;
pub mod error;
pub mod expiring;
pub mod filter;
pub mod misc;
pub mod orders;
pub mod session;
pub mod templates;

pub use auth::{PageSession, PageSessionWrite};
pub use error::PageError;

use axum::Router;
use axum::response::Html;
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::webadmin::AdminState;
use crate::webadmin::handlers::paging::Page;

/// Everything under `/ui`, including the assets and the two unauthenticated
/// sign-in routes.
///
/// Full paths rather than a `nest`: the admin listener's fallback is HTML (a
/// browser-facing listener should answer a browser), and the JSON fallback the
/// API needs is already scoped inside its own nest. One fewer nesting level is
/// one fewer place for a path to be assembled twice.
pub(crate) fn pages_router() -> Router<AdminState> {
    Router::new()
        // No session: the sign-in page, and the assets it needs to render.
        .route(
            "/ui/login",
            get(session::get_login).post(session::post_login),
        )
        // The second half of signing in. It takes a `pending_mfa` cookie, which
        // is the one thing `PageSession` refuses -- so it belongs here, above
        // the line, and not below it.
        .route(
            "/ui/login/mfa",
            get(session::get_login_mfa).post(session::post_login_mfa),
        )
        .route("/ui/static/{file}", get(assets::get_asset))
        // Everything below needs one.
        .route("/ui/", get(misc::get_index))
        // The operator's own page. No id in any of these paths: there is
        // exactly one account they can be about, and the session names it.
        .route("/ui/account", get(account::get_account))
        .route("/ui/account/mfa/totp", post(account::begin_totp))
        .route("/ui/account/mfa/totp/confirm", post(account::confirm_totp))
        .route("/ui/account/mfa/totp/disable", post(account::disable_totp))
        .route(
            "/ui/account/mfa/recovery-codes",
            post(account::regenerate_recovery_codes),
        )
        .route("/ui/logout", post(session::post_logout))
        .route("/ui/accounts", get(accounts::list_accounts))
        .route(
            "/ui/accounts/{id}",
            get(accounts::get_account).delete(accounts::delete_account),
        )
        .route(
            "/ui/accounts/{id}/contact",
            post(accounts::post_account_contact),
        )
        .route(
            "/ui/accounts/{id}/deactivate",
            post(accounts::deactivate_account),
        )
        // Read-only, and the only list here with no control in its rows.
        .route("/ui/expiring", get(expiring::list_expiring))
        .route("/ui/audit", get(audit::list_audit))
        .route("/ui/audit/{id}", get(audit::get_audit))
        .route("/ui/orders", get(orders::list_orders))
        .route(
            "/ui/orders/{id}",
            get(orders::get_order).delete(orders::delete_order),
        )
        .route("/ui/orders/{id}/revoke", post(orders::revoke_order))
        // A `GET`, so it is absent from `mutating_page_endpoints()` by right
        // rather than by omission.
        .route("/ui/orders/{id}/chain.pem", get(orders::download_chain))
        .route("/ui/eab", get(eab::list_eab).post(eab::create_eab))
        .route("/ui/eab/{kid}", get(eab::get_eab))
        .route("/ui/eab/{kid}/revoke", post(eab::revoke_eab))
        .route("/ui/nonces", get(misc::get_nonces))
        .route("/ui/nonces/cleanup", post(misc::cleanup_nonces))
        .route("/ui/profiles", get(misc::list_profiles))
        // Read-only: a policy is configuration, and `filter explain` -- the
        // one that would need a form -- has no web surface at all. Absent from
        // `mutating_page_endpoints()` accordingly.
        .route(
            "/ui/profiles/{name}/filter",
            get(filter::get_profile_filter),
        )
}

/// The context every full page needs on top of its own data.
///
/// `csrf_token` is the load-bearing member: `layout.html` puts it on `<body>`
/// as an `hx-headers` attribute, and every mutating request htmx issues carries
/// it back. A page rendered without it loses every write at once, which is the
/// intended failure mode — a partial loss would be worse.
pub(crate) fn chrome(session: &PageSession, nav: &'static str, title: &str) -> Map<String, Value> {
    let mut context = Map::new();
    context.insert(
        "csrf_token".to_string(),
        Value::String(session.auth.session.csrf_token.clone()),
    );
    context.insert(
        "user".to_string(),
        crate::admin::render_admin_user_json(&session.auth.user),
    );
    context.insert("nav".to_string(), Value::String(nav.to_string()));
    context.insert("title".to_string(), Value::String(title.to_string()));
    context
}

/// Renders `page` for a navigation and `fragment` for an htmx swap.
///
/// The single place the page/fragment choice is expressed, so a route cannot
/// accidentally serve a bare partial to the address bar (a document with no
/// `<html>`) or a whole document into a `<div>`.
pub(crate) fn respond(
    state: &AdminState,
    hx: bool,
    page: &str,
    fragment: &str,
    context: Map<String, Value>,
) -> Result<Html<String>, PageError> {
    let name = if hx { fragment } else { page };
    templates::render(
        &state.templates,
        name,
        minijinja::Value::from_serialize(Value::Object(context)),
    )
}

/// Renders a fragment only — the answer to every mutation, which is always a
/// swap and never a navigation.
pub(crate) fn respond_fragment(
    state: &AdminState,
    fragment: &str,
    context: Map<String, Value>,
) -> Result<Html<String>, PageError> {
    templates::render(
        &state.templates,
        fragment,
        minijinja::Value::from_serialize(Value::Object(context)),
    )
}

/// A banner for a partial to render: `kind` is `ok`, `error` or `warn`.
#[must_use]
pub(crate) fn flash(kind: &str, message: impl Into<String>) -> Value {
    json!({ "kind": kind, "message": message.into() })
}

/// The banner form of a refusal that is worth showing rather than replacing the
/// page with.
///
/// A `409 already_revoked` is the motivating case: the operator asked for
/// something the row's state does not allow, the answer belongs next to the
/// button they pressed, and the code is the same string the JSON API returns.
#[must_use]
pub(crate) fn flash_error(code: &str, message: impl Into<String>) -> Value {
    json!({ "kind": "error", "message": message.into(), "code": code })
}

/// The offset-pagination controls for a list fragment.
///
/// Built here rather than in the template because the previous and next URLs
/// have to carry whatever filters the list was already showing — assembling a
/// query string is not a template's job, and getting it wrong silently drops a
/// filter on the second page.
pub(crate) fn pager(
    page: Page,
    total: i64,
    path: &str,
    filters: &[(&str, &str)],
    target: &str,
) -> Value {
    let url = |offset: i64| {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("limit", &page.limit.to_string());
        query.append_pair("offset", &offset.to_string());
        for (key, value) in filters {
            if !value.is_empty() {
                query.append_pair(key, value);
            }
        }
        format!("{path}?{}", query.finish())
    };

    // Saturating throughout. `PageParams::resolve` already clamps `offset` so
    // this cannot overflow from the query string, but `limit`'s ceiling is
    // `admin.page_size_max`, an operator-set `i64` with no upper bound of its
    // own — and a page control is not worth a panicking arithmetic path.
    let next = page.offset.saturating_add(page.limit);
    json!({
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        // Human numbering: "1–50 of 312", and an empty page says 0–0.
        "from": if total == 0 { 0 } else { page.offset.saturating_add(1) },
        "to": next.min(total).max(0),
        "prev": (page.offset > 0).then(|| url(page.offset.saturating_sub(page.limit).max(0))),
        "next": (next < total).then(|| url(next)),
        "target": target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(limit: i64, offset: i64) -> Page {
        Page { limit, offset }
    }

    #[test]
    fn the_first_page_of_several_offers_next_and_not_previous() {
        let value = pager(page(50, 0), 312, "/ui/accounts", &[], "#accounts-table");
        assert_eq!(value["from"], 1);
        assert_eq!(value["to"], 50);
        assert_eq!(value["total"], 312);
        assert!(value["prev"].is_null());
        assert_eq!(value["next"], "/ui/accounts?limit=50&offset=50");
    }

    #[test]
    fn the_last_page_offers_previous_and_not_next() {
        let value = pager(page(50, 300), 312, "/ui/accounts", &[], "#accounts-table");
        assert_eq!(value["from"], 301);
        // The final page is short, and the count must say so rather than
        // running past the total.
        assert_eq!(value["to"], 312);
        assert_eq!(value["prev"], "/ui/accounts?limit=50&offset=250");
        assert!(value["next"].is_null());
    }

    /// The bug this function exists to prevent: paging away from page one must
    /// not drop the filter the operator was looking through.
    #[test]
    fn the_filters_survive_a_page_step_and_are_encoded() {
        let value = pager(
            page(10, 0),
            40,
            "/ui/orders",
            &[("profile", "le"), ("status", ""), ("accountId", "a b&c")],
            "#orders-table",
        );
        let next = value["next"].as_str().unwrap();
        assert!(next.contains("profile=le"));
        // An empty filter is absent, not `status=`.
        assert!(!next.contains("status="));
        assert!(next.contains("accountId=a+b%26c"));
    }

    #[test]
    fn an_empty_result_set_renders_no_controls() {
        let value = pager(page(50, 0), 0, "/ui/eab", &[], "#eab-table");
        assert_eq!(value["total"], 0);
        assert_eq!(value["from"], 0);
        assert_eq!(value["to"], 0);
        assert!(value["prev"].is_null());
        assert!(value["next"].is_null());
    }

    /// `PageParams::resolve` clamps the offset, but `limit`'s own ceiling is
    /// `admin.page_size_max`, an operator-set `i64`. Neither end may panic.
    #[test]
    fn an_extreme_window_saturates_instead_of_overflowing() {
        let value = pager(page(i64::MAX, i64::MAX / 2), 10, "/ui/orders", &[], "#t");
        assert_eq!(value["to"], 10);
        assert!(value["next"].is_null());
        assert!(value["prev"].is_string());
    }

    #[test]
    fn a_single_full_page_offers_neither_control() {
        let value = pager(page(50, 0), 50, "/ui/accounts", &[], "#accounts-table");
        assert!(value["prev"].is_null());
        assert!(value["next"].is_null());
    }

    #[test]
    fn flashes_carry_their_kind_and_a_code_only_when_there_was_one() {
        let ok = flash("ok", "saved");
        assert_eq!(ok["kind"], "ok");
        assert!(ok.get("code").is_none());

        let error = flash_error("already_revoked", "already revoked");
        assert_eq!(error["kind"], "error");
        assert_eq!(error["code"], "already_revoked");
    }
}
