//! The page templates: embedded defaults, the on-disk override, and rendering.
//!
//! Deliberately the same mechanism as [`crate::notify`]'s, down to the loader
//! closure — an operator who has already overridden a notification template
//! should not have to learn a second scheme to override a page.
//!
//! ## Why every name ends in `.html`
//!
//! minijinja picks its auto-escaping off the template *name*: `.html` escapes,
//! and the notify templates are named `.j2` precisely so that they do not (an
//! email body is not markup). Rendering an account contact or an EAB label into
//! an unescaped template is stored XSS, so the extension here is a security
//! control rather than a filing convention, and
//! `auto_escaping_is_on_for_pages_and_off_for_notify` pins it.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::response::Html;

use crate::webadmin::pages::error::PageError;

/// Every template, embedded so the server needs no `templates/` directory on
/// disk to serve a page.
///
/// Keyed exactly as the templates refer to each other in `{% extends %}` and
/// `{% include %}`, since that is what reaches the loader.
static EMBEDDED_TEMPLATES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("layout.html", include_str!("../templates/layout.html")),
        ("login.html", include_str!("../templates/login.html")),
        (
            "mfa/challenge.html",
            include_str!("../templates/mfa/challenge.html"),
        ),
        ("index.html", include_str!("../templates/index.html")),
        (
            "audit/list.html",
            include_str!("../templates/audit/list.html"),
        ),
        (
            "audit/_table.html",
            include_str!("../templates/audit/_table.html"),
        ),
        (
            "audit/detail.html",
            include_str!("../templates/audit/detail.html"),
        ),
        (
            "audit/_card.html",
            include_str!("../templates/audit/_card.html"),
        ),
        (
            "mfa/_setup.html",
            include_str!("../templates/mfa/_setup.html"),
        ),
        (
            "mfa/_codes.html",
            include_str!("../templates/mfa/_codes.html"),
        ),
        (
            "mfa/enrolled.html",
            include_str!("../templates/mfa/enrolled.html"),
        ),
        (
            "account/index.html",
            include_str!("../templates/account/index.html"),
        ),
        (
            "account/_mfa.html",
            include_str!("../templates/account/_mfa.html"),
        ),
        (
            "account/_card.html",
            include_str!("../templates/account/_card.html"),
        ),
        (
            "account/_enrol.html",
            include_str!("../templates/account/_enrol.html"),
        ),
        (
            "account/_codes.html",
            include_str!("../templates/account/_codes.html"),
        ),
        (
            "partials/_flash.html",
            include_str!("../templates/partials/_flash.html"),
        ),
        (
            "partials/_pager.html",
            include_str!("../templates/partials/_pager.html"),
        ),
        (
            "profiles/list.html",
            include_str!("../templates/profiles/list.html"),
        ),
        (
            "profiles/_table.html",
            include_str!("../templates/profiles/_table.html"),
        ),
        (
            "accounts/list.html",
            include_str!("../templates/accounts/list.html"),
        ),
        (
            "accounts/_table.html",
            include_str!("../templates/accounts/_table.html"),
        ),
        (
            "accounts/detail.html",
            include_str!("../templates/accounts/detail.html"),
        ),
        (
            "accounts/_card.html",
            include_str!("../templates/accounts/_card.html"),
        ),
        (
            "orders/list.html",
            include_str!("../templates/orders/list.html"),
        ),
        (
            "orders/_table.html",
            include_str!("../templates/orders/_table.html"),
        ),
        (
            "orders/detail.html",
            include_str!("../templates/orders/detail.html"),
        ),
        (
            "orders/_card.html",
            include_str!("../templates/orders/_card.html"),
        ),
        ("eab/list.html", include_str!("../templates/eab/list.html")),
        (
            "eab/_table.html",
            include_str!("../templates/eab/_table.html"),
        ),
        (
            "eab/detail.html",
            include_str!("../templates/eab/detail.html"),
        ),
        (
            "eab/_card.html",
            include_str!("../templates/eab/_card.html"),
        ),
        (
            "eab/_created.html",
            include_str!("../templates/eab/_created.html"),
        ),
        (
            "nonces/index.html",
            include_str!("../templates/nonces/index.html"),
        ),
        (
            "nonces/_panel.html",
            include_str!("../templates/nonces/_panel.html"),
        ),
    ])
});

/// Every embedded template name, for the startup compile in
/// [`crate::webadmin::check_config`].
///
/// A `HashMap` iteration would do the same job, but a startup check that
/// silently covers nothing if the map is empty is not a check — this is the
/// list a test can also assert the map against.
#[must_use]
pub(crate) fn template_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = EMBEDDED_TEMPLATES.keys().copied().collect();
    names.sort_unstable();
    names
}

/// Builds a template environment: `template_dir` (if set) is checked for each
/// named template before falling back to the compiled-in default, so an
/// operator can restyle one page and leave every other at its default.
///
/// The override is per *file*, not per directory: a `template_dir` holding only
/// `layout.html` changes the chrome of every page and nothing else.
#[must_use]
pub(crate) fn build_environment(template_dir: &str) -> minijinja::Environment<'static> {
    let dir = (!template_dir.is_empty()).then(|| std::path::PathBuf::from(template_dir));
    let mut env = minijinja::Environment::new();
    env.set_loader(move |name| {
        if let Some(dir) = &dir
            && let Ok(contents) = std::fs::read_to_string(dir.join(name))
        {
            return Ok(Some(contents));
        }
        Ok(EMBEDDED_TEMPLATES.get(name).map(|body| (*body).to_string()))
    });
    env
}

/// Renders one named template against `context`.
///
/// A failure here is a `500`: the templates are compiled at startup
/// (`check_config`), so by the time a request reaches this the only remaining
/// causes are a bug in the context shape or a `template_dir` file that changed
/// underneath a running process.
pub(crate) fn render(
    env: &minijinja::Environment<'static>,
    name: &str,
    context: minijinja::Value,
) -> Result<Html<String>, PageError> {
    let template = env.get_template(name).map_err(|error| {
        tracing::error!(event = "admin_template_missing", outcome = "failure", template = name, error = %error);
        PageError::internal()
    })?;
    let body = template.render(context).map_err(|error| {
        tracing::error!(event = "admin_template_render_failed", outcome = "failure", template = name, error = %error);
        PageError::internal()
    })?;
    Ok(Html(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn every_embedded_template_compiles() {
        let env = build_environment("");
        for name in template_names() {
            assert!(
                env.get_template(name).is_ok(),
                "`{name}` must compile: it is what `check_config` refuses to start without"
            );
        }
    }

    /// The reason every page template is named `.html` and every notify
    /// template is named `.j2`.
    ///
    /// minijinja picks auto-escaping off the name, so this is the whole
    /// defence against a stored `<script>` in an account contact or an EAB
    /// label. Asserted in both directions: turning it *on* for notify would
    /// quietly corrupt every email body.
    #[test]
    fn auto_escaping_is_on_for_pages_and_off_for_notify() {
        let mut env = minijinja::Environment::new();
        env.add_template("page.html", "{{ value }}").unwrap();
        env.add_template("mail.body.j2", "{{ value }}").unwrap();

        let hostile = minijinja::context! { value => "<script>alert(1)</script>" };

        // minijinja escapes `/` as well, so the closing tag comes back as
        // `&lt;&#x2f;script&gt;` rather than `&lt;/script&gt;`.
        let page = env
            .get_template("page.html")
            .unwrap()
            .render(hostile.clone())
            .unwrap();
        assert!(!page.contains("<script>"));
        assert_eq!(page, "&lt;script&gt;alert(1)&lt;&#x2f;script&gt;");

        let mail = env
            .get_template("mail.body.j2")
            .unwrap()
            .render(hostile)
            .unwrap();
        assert_eq!(mail, "<script>alert(1)</script>");
    }

    #[test]
    fn a_template_dir_file_wins_over_the_embedded_default() {
        let dir = TempDir::new("admin-templates");
        dir.write("index.html", "overridden");

        let env = build_environment(dir.path().to_str().unwrap());
        let rendered = env
            .get_template("index.html")
            .unwrap()
            .render(minijinja::context! {})
            .unwrap();
        assert_eq!(rendered, "overridden");

        // Every other template still comes from the binary: the override is
        // per file, not "the directory replaces the set".
        assert!(env.get_template("layout.html").is_ok());
    }

    #[test]
    fn an_empty_template_dir_touches_no_disk() {
        let env = build_environment("");
        assert!(env.get_template("layout.html").is_ok());
        assert!(env.get_template("no-such-template.html").is_err());
    }

    #[test]
    fn render_reports_a_missing_template_as_internal() {
        let env = build_environment("");
        let error = render(&env, "no-such-template.html", minijinja::context! {}).unwrap_err();
        assert_eq!(
            error.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn render_produces_the_login_page() {
        let env = build_environment("");
        let Html(body) = render(&env, "login.html", minijinja::context! {}).unwrap();
        assert!(body.starts_with("<!doctype html>"));
        assert!(body.contains("name=\"password\""));
        // No htmx on the sign-in page: it must work before a byte of
        // JavaScript has loaded.
        assert!(!body.contains("htmx.min.js"));
    }
}
