//! The `--limit`/`--offset` window every paged listing takes.
//!
//! Four commands page — `account list`, `order list` (both queries) and
//! `audit list` — and every one of them wants the same default, the same two
//! clamps and the same envelope under `--json`. That envelope is
//! [`crate::cli::render::json_page`]; this is the window that produced it.

/// Default rows per page.
///
/// There is deliberately no "everything" spelling, and `--limit 0` is not a way
/// around it: `orders` and `audit_log` each grow a row per issuance for the
/// life of the deployment, so on a year-old CA an unwindowed listing is a
/// terminal full of scrollback and a table loaded into memory. Page with
/// `--offset`; the `N of M row(s)` footer is what says there is more.
pub const DEFAULT_LIMIT: i64 = 50;

/// A resolved window, clamped into something a query can be handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub limit: i64,
    pub offset: i64,
}

impl Window {
    /// Clamps a caller's window rather than refusing it.
    ///
    /// A `--limit 0` or a negative offset is nonsense rather than an attack, and
    /// answering with the smallest usable page is more useful than an error;
    /// passed through to SQL, `LIMIT -1` means *no limit* in SQLite, which is
    /// the one answer a window must never accidentally give.
    ///
    /// Deliberately **not** clamped to `admin.page_size_max`: that key is a
    /// ceiling on what an HTTP caller may ask the server for, and this front end
    /// answers to a shell on the host. There is no upper bound on the offset
    /// either, unlike `webadmin::handlers::paging`, because nothing here
    /// computes `offset + limit` — a terminal has no "next page" link to place.
    #[must_use]
    pub fn resolve(limit: i64, offset: i64) -> Self {
        Self {
            limit: limit.max(1),
            offset: offset.max(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonsense_window_is_clamped_rather_than_refused() {
        for (limit, expected) in [(50, 50), (1, 1), (0, 1), (-5, 1)] {
            assert_eq!(Window::resolve(limit, 0).limit, expected, "limit={limit}");
        }
        for (offset, expected) in [(0, 0), (7, 7), (-7, 0)] {
            assert_eq!(
                Window::resolve(50, offset).offset,
                expected,
                "offset={offset}"
            );
        }
    }
}
