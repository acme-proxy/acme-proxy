//! The shared `?limit=&offset=` window and the envelope every list returns.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;

/// Rows per page when the caller does not say.
const DEFAULT_PAGE_SIZE: i64 = 50;

/// The furthest a caller may page in. Far beyond any real table, and low
/// enough that `offset + limit` cannot overflow — see [`PageParams::resolve`].
const MAX_OFFSET: i64 = i64::MAX / 2;

/// The page window a list endpoint accepts.
#[derive(Debug, Deserialize, Default)]
pub struct PageParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// A resolved, clamped window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub limit: i64,
    pub offset: i64,
}

impl PageParams {
    /// Builds a window from fields a caller declared inline.
    #[must_use]
    pub fn from(limit: Option<i64>, offset: Option<i64>) -> Self {
        Self { limit, offset }
    }

    /// Clamps the caller's window into something the database can be handed.
    ///
    /// Clamped rather than refused: a `?limit=100000` is far more likely to be
    /// a client that does not know the ceiling than an attack, and answering
    /// with the largest allowed page is more useful than a 400. A negative
    /// offset is nonsense, so it becomes 0 rather than a SQL error.
    ///
    /// The *upper* clamp is not cosmetic: `pages::pager` computes
    /// `offset + limit` to place the "next" link, and `?offset=` arrives
    /// straight off the query string as an `i64`. At `i64::MAX` that addition
    /// overflows — a panic in a debug build, a silent wrap to a negative page
    /// window in release, which sets no `overflow-checks`. [`MAX_OFFSET`]
    /// leaves headroom for the addition no matter what `limit` resolved to.
    #[must_use]
    pub fn resolve(&self, config: &Config) -> Page {
        let max = config.admin.page_size_max.max(1);
        Page {
            limit: self.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, max),
            offset: self.offset.unwrap_or(0).clamp(0, MAX_OFFSET),
        }
    }
}

/// The envelope every list endpoint returns.
///
/// `total` is the count the same filters match *unpaged*, which is what a page
/// control needs and what a bare array cannot express.
#[must_use]
pub fn page_envelope(items: Vec<Value>, total: i64, page: Page) -> Value {
    json!({
        "items": items,
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_max(max: i64) -> Config {
        let mut config = Config::default();
        config.admin.page_size_max = max;
        config
    }

    #[test]
    fn an_absent_window_is_the_default_page() {
        let page = PageParams::default().resolve(&Config::default());
        assert_eq!(
            page,
            Page {
                limit: 50,
                offset: 0
            }
        );
    }

    #[test]
    fn a_limit_is_clamped_into_range_rather_than_refused() {
        let config = config_with_max(200);
        let cases = [
            (Some(10), 10),
            (Some(200), 200),
            // Over the ceiling: answered with the largest allowed page.
            (Some(100_000), 200),
            // Nonsense: one row, not zero and not a SQL error.
            (Some(0), 1),
            (Some(-5), 1),
        ];
        for (requested, expected) in cases {
            let page = PageParams {
                limit: requested,
                offset: None,
            }
            .resolve(&config);
            assert_eq!(page.limit, expected, "limit={requested:?}");
        }
    }

    #[test]
    fn a_negative_offset_becomes_zero() {
        let page = PageParams {
            limit: None,
            offset: Some(-7),
        }
        .resolve(&Config::default());
        assert_eq!(page.offset, 0);
    }

    /// `?offset=9223372036854775807` reaches `pager`, which computes
    /// `offset + limit`. Unclamped that overflows: a panic in debug, a wrapped
    /// negative window in release, which sets no `overflow-checks`.
    #[test]
    fn an_offset_at_the_top_of_the_range_is_clamped_below_an_overflow() {
        let page = PageParams {
            limit: None,
            offset: Some(i64::MAX),
        }
        .resolve(&Config::default());
        assert_eq!(page.offset, MAX_OFFSET);
        assert!(page.offset.checked_add(page.limit).is_some());
    }

    /// A misconfigured ceiling must not make every page empty.
    #[test]
    fn a_page_size_max_of_zero_still_yields_a_usable_page() {
        let page = PageParams {
            limit: Some(50),
            offset: None,
        }
        .resolve(&config_with_max(0));
        assert_eq!(page.limit, 1);
    }

    #[test]
    fn the_envelope_reports_the_window_it_was_given() {
        let page = Page {
            limit: 2,
            offset: 4,
        };
        let envelope = page_envelope(vec![json!({"id": "a"})], 17, page);
        assert_eq!(envelope["total"], 17);
        assert_eq!(envelope["limit"], 2);
        assert_eq!(envelope["offset"], 4);
        assert_eq!(envelope["items"].as_array().unwrap().len(), 1);
    }
}
