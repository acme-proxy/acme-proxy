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

/// One embedded template: the name it is known by *is* the path it lives at.
///
/// See `notify::embed!` — the same rule, and the same reason.
macro_rules! embed {
    ($name:literal) => {
        ($name, include_str!(concat!("../templates/", $name)))
    };
}

/// Every template, embedded so the server needs no `templates/` directory on
/// disk to serve a page.
///
/// Keyed exactly as the templates refer to each other in `{% extends %}` and
/// `{% include %}`, since that is what reaches the loader.
static EMBEDDED_TEMPLATES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        embed!("layout.html"),
        embed!("login.html"),
        embed!("mfa/challenge.html"),
        embed!("index.html"),
        embed!("audit/list.html"),
        embed!("audit/_table.html"),
        embed!("audit/detail.html"),
        embed!("audit/_card.html"),
        embed!("mfa/_setup.html"),
        embed!("mfa/_codes.html"),
        embed!("mfa/enrolled.html"),
        embed!("account/index.html"),
        embed!("account/_mfa.html"),
        embed!("account/_card.html"),
        embed!("account/_enrol.html"),
        embed!("account/_codes.html"),
        embed!("partials/_flash.html"),
        embed!("partials/_pager.html"),
        embed!("profiles/list.html"),
        embed!("profiles/_table.html"),
        embed!("accounts/list.html"),
        embed!("accounts/_table.html"),
        embed!("accounts/detail.html"),
        embed!("accounts/_card.html"),
        embed!("orders/list.html"),
        embed!("orders/_table.html"),
        embed!("orders/detail.html"),
        embed!("orders/_card.html"),
        embed!("eab/list.html"),
        embed!("eab/_table.html"),
        embed!("eab/detail.html"),
        embed!("eab/_card.html"),
        embed!("eab/_created.html"),
        embed!("nonces/index.html"),
        embed!("nonces/_panel.html"),
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
    crate::templating::loader_env(template_dir, &EMBEDDED_TEMPLATES)
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
