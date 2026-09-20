//! Typed helpers for structured log fields, so a field has one spelling and
//! one wire type wherever it is logged.

/// A duration in milliseconds, as a log field.
///
/// `Duration::as_millis` returns `u128`, which `tracing` has no primitive
/// visitor for and so records through `Display` — landing in the JSON output as
/// a quoted `"42"` rather than the number `42`. That output exists to be
/// aggregated by machines, and a latency field a collector has to re-parse (or
/// silently indexes as a string) is a defect in it. Every duration logged
/// anywhere in this crate goes through here.
///
/// The saturation is unreachable — `u64::MAX` milliseconds is some 584 million
/// years — and is written out only to avoid a silent truncating cast.
#[must_use]
pub fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A connection URL with any password replaced, for a log line or an error.
///
/// `database.url` is the one configuration value that is both logged verbatim
/// at startup and rendered into [`reload`]'s refusal message, and a PostgreSQL
/// DSN carries `user:password@` where a SQLite path carries nothing. The rule
/// it follows is already written down in `server::reload`: a projection must be
/// opaque if any field it reaches can hold a credential.
///
/// Deliberately string-based rather than parsed. This runs on whatever an
/// operator put in the configuration, including a value that is not a URL at
/// all, and a redactor that only works on input it can parse is the wrong shape
/// — an unparseable DSN must still not have its password logged. Anything
/// without a `://` or without credentials is returned as it stands.
///
/// `net::proxy` has a `Url`-typed twin for the case where the value has already
/// been parsed, which also keeps the trailing slash `Url` adds.
///
/// [`reload`]: https://docs.rs/acme-proxy-server
#[must_use]
pub fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return std::borrow::Cow::Borrowed(url);
    };
    // Only the authority may carry credentials, and it ends at the first `/`.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let Some((credential, host)) = authority.rsplit_once('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    let user = credential.split_once(':').map_or(credential, |(u, _)| u);
    std::borrow::Cow::Owned(format!("{scheme}://{user}:***@{host}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_never_survives() {
        assert_eq!(
            redact_url("postgres://acme:hunter2@db.internal:5432/acme"),
            "postgres://acme:***@db.internal:5432/acme"
        );
    }

    /// The default, and every SQLite spelling: nothing to hide, nothing changed.
    #[test]
    fn a_url_without_credentials_is_returned_as_it_stands() {
        for url in [
            "sqlite://sqlite.db",
            "sqlite:///var/lib/acme-proxy/acme.db",
            "postgres://db.internal/acme",
            "not a url at all",
            "",
        ] {
            assert_eq!(redact_url(url), url, "{url}");
        }
    }

    /// A user with no password still has its name kept: an operator reading the
    /// log needs to know *which* role failed to connect.
    #[test]
    fn a_bare_user_is_kept_and_still_marked() {
        assert_eq!(
            redact_url("postgres://acme@db.internal/acme"),
            "postgres://acme:***@db.internal/acme"
        );
    }

    /// An `@` in the password must not be mistaken for the authority's own.
    #[test]
    fn the_last_at_sign_separates_the_credential() {
        assert_eq!(
            redact_url("postgres://acme:p@ss@db.internal/acme"),
            "postgres://acme:***@db.internal/acme"
        );
    }

    /// A `@` after the authority is part of the path and decides nothing.
    #[test]
    fn an_at_sign_in_the_path_is_not_a_credential() {
        assert_eq!(
            redact_url("postgres://db.internal/acme@weird"),
            "postgres://db.internal/acme@weird"
        );
    }
}
