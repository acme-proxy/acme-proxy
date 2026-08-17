//! The one thing the two `minijinja` environments in this crate share: how a
//! template is *found*.
//!
//! [`notify`](crate::notify) renders `.j2` messages and
//! [`webadmin::pages`](crate::webadmin::pages) renders `.html` pages, and the
//! two had byte-identical loader closures — check `template_dir` for a file of
//! this name, fall back to the compiled-in default — differing only in which
//! table they closed over.
//!
//! **Sharing the loader cannot weaken the escaping rule**, which is worth
//! stating because it is a security control: minijinja picks auto-escaping off
//! the template *name*, so `account/_card.html` escapes and
//! `webhook/certificate_issued.j2` does not. That decision is made by the
//! extension in the name, never by the loader, and
//! `auto_escaping_is_on_for_pages_and_off_for_notify` pins both directions. A
//! page template renamed `.j2` would turn an account contact or an EAB label
//! into stored XSS — which is a rule about naming, and this function cannot
//! affect it either way.

use std::collections::HashMap;

/// An environment that resolves a template name to a `template_dir` file first
/// and the compiled-in default second.
///
/// The override is per *file*, not per directory: a `template_dir` holding only
/// `layout.html` changes the chrome of every page and leaves everything else at
/// its default.
pub(crate) fn loader_env(
    template_dir: &str,
    embedded: &'static HashMap<&'static str, &'static str>,
) -> minijinja::Environment<'static> {
    let dir = (!template_dir.is_empty()).then(|| std::path::PathBuf::from(template_dir));
    let mut env = minijinja::Environment::new();
    env.set_loader(move |name| {
        if let Some(dir) = &dir
            && let Ok(contents) = std::fs::read_to_string(dir.join(name))
        {
            return Ok(Some(contents));
        }
        Ok(embedded.get(name).map(|body| (*body).to_string()))
    });
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static TABLE: LazyLock<HashMap<&'static str, &'static str>> =
        LazyLock::new(|| HashMap::from([("a.j2", "embedded a"), ("b.j2", "embedded b")]));

    #[test]
    fn an_empty_directory_uses_the_embedded_default() {
        let env = loader_env("", &TABLE);
        assert_eq!(
            env.get_template("a.j2").unwrap().render(()).unwrap(),
            "embedded a"
        );
    }

    /// The override is per file: overriding `a.j2` must leave `b.j2` alone.
    #[test]
    fn a_directory_file_beats_the_default_for_that_name_only() {
        let dir = crate::testutil::TempDir::new("templating-loader");
        std::fs::write(dir.as_ref().join("a.j2"), "from disk").unwrap();

        let env = loader_env(dir.as_ref().to_str().unwrap(), &TABLE);
        assert_eq!(
            env.get_template("a.j2").unwrap().render(()).unwrap(),
            "from disk"
        );
        assert_eq!(
            env.get_template("b.j2").unwrap().render(()).unwrap(),
            "embedded b"
        );
    }

    /// A name in neither place is absent, not an error at load time — the
    /// caller decides what a missing template means (permanent for a notify
    /// delivery, a `500` for a page).
    #[test]
    fn an_unknown_name_is_simply_not_found() {
        let env = loader_env("", &TABLE);
        assert!(env.get_template("nope.j2").is_err());
    }

    /// A `template_dir` that does not exist is not a panic: `check_config`
    /// refuses one at startup, and this layer degrades to the defaults.
    #[test]
    fn a_missing_directory_falls_through_to_the_defaults() {
        let env = loader_env("/nonexistent/acme-proxy-templates", &TABLE);
        assert_eq!(
            env.get_template("a.j2").unwrap().render(()).unwrap(),
            "embedded a"
        );
    }
}
