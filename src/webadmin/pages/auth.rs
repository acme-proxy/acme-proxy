//! The page layer's session extractors.
//!
//! Thin wrappers over [`Authenticated`] and [`AuthenticatedWrite`], and
//! deliberately nothing more. `resolve_session`, `check_csrf` and
//! `check_origin` stay the single implementation in
//! [`crate::webadmin::session`]: a second copy written "for pages" is how the
//! two front ends would drift into disagreeing about what a live session is.
//!
//! All these add is the answer to a failure. The API says `401`; a browser
//! needs to *arrive* at the sign-in page, and htmx needs to be told to navigate
//! rather than swap — see [`super::error::PageError`].

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::pages::error::PageError;
use crate::webadmin::session::{
    AdminWrite, Authenticated, AuthenticatedWrite, EnrolWrite, PendingMfa, PendingMfaSubmit,
    SelfServiceWrite,
};

/// The header htmx sets on every request it issues.
const HX_REQUEST: &str = "hx-request";

/// Whether this request came from htmx rather than from the address bar.
///
/// Decides both how a redirect is expressed and whether a handler answers with
/// a whole page or the bare fragment htmx will swap.
#[must_use]
pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get(HX_REQUEST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

/// A signed-in operator, on a page that only reads.
pub struct PageSession {
    pub auth: Authenticated,
    /// Carried through so the handler can pick the page or the fragment
    /// without re-reading the headers it has already given up ownership of.
    pub hx: bool,
}

/// A signed-in operator on a page that writes, with the origin and CSRF gates
/// already passed.
///
/// The wrapped [`AuthenticatedWrite`] is what makes that structural: a page
/// handler cannot reach a session for a mutation by any other route.
pub struct PageSessionWrite {
    pub auth: Authenticated,
    pub hx: bool,
}

impl FromRequestParts<AdminState> for PageSession {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match Authenticated::from_request_parts(parts, state).await {
            Ok(auth) => Ok(Self { auth, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

impl FromRequestParts<AdminState> for PageSessionWrite {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match AuthenticatedWrite::from_request_parts(parts, state).await {
            Ok(AuthenticatedWrite(auth)) => Ok(Self { auth, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

/// A signed-in **admin** on a page that manages other operators, with the
/// origin and CSRF gates passed. Wraps [`AdminWrite`].
pub struct PageAdminWrite {
    pub auth: Authenticated,
    pub hx: bool,
}

/// A signed-in operator of **any** role, on a page that only touches their own
/// account. Wraps [`SelfServiceWrite`].
pub struct PageSelfServiceWrite {
    pub auth: Authenticated,
    pub hx: bool,
}

impl FromRequestParts<AdminState> for PageAdminWrite {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match AdminWrite::from_request_parts(parts, state).await {
            Ok(AdminWrite(auth)) => Ok(Self { auth, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

impl FromRequestParts<AdminState> for PageSelfServiceWrite {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match SelfServiceWrite::from_request_parts(parts, state).await {
            Ok(SelfServiceWrite(auth)) => Ok(Self { auth, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

/// A half-authenticated session, on the page that shows the challenge.
pub struct PageMfaPending {
    pub pending: PendingMfa,
    pub hx: bool,
}

/// A half-authenticated session, on the form that submits a code.
///
/// The origin gate ran and the CSRF check did not -- see [`PendingMfaSubmit`],
/// which is where that trade is argued.
pub struct PageMfaSubmit {
    pub pending: PendingMfa,
    pub hx: bool,
}

/// A session allowed to set up a factor, on a page that writes.
pub struct PageEnrolWrite {
    pub enrol: EnrolWrite,
    pub hx: bool,
}

impl FromRequestParts<AdminState> for PageMfaPending {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match PendingMfa::from_request_parts(parts, state).await {
            Ok(pending) => Ok(Self { pending, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

impl FromRequestParts<AdminState> for PageMfaSubmit {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match PendingMfaSubmit::from_request_parts(parts, state).await {
            Ok(PendingMfaSubmit(pending)) => Ok(Self { pending, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

impl FromRequestParts<AdminState> for PageEnrolWrite {
    type Rejection = PageError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let hx = is_htmx(&parts.headers);
        match EnrolWrite::from_request_parts(parts, state).await {
            Ok(enrol) => Ok(Self { enrol, hx }),
            Err(error) => Err(to_page_error(error, hx)),
        }
    }
}

/// A `401` becomes "go and sign in"; anything else keeps its own status.
///
/// The distinction matters: a `403 csrf_failed` must *not* bounce the operator
/// to the sign-in page, because their session is fine and the page would just
/// send them back — the useful answer is the error, visible where they clicked.
fn to_page_error(error: AdminError, hx: bool) -> PageError {
    if error.status == axum::http::StatusCode::UNAUTHORIZED {
        PageError::login_required(hx)
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn is_htmx_reads_the_header_case_insensitively() {
        assert!(is_htmx(&headers(&[("hx-request", "true")])));
        assert!(is_htmx(&headers(&[("HX-Request", "True")])));
        assert!(!is_htmx(&headers(&[("hx-request", "false")])));
        // htmx sets it on the boosted-navigation path too, but anything else
        // in that header is not htmx and must get a real page.
        assert!(!is_htmx(&headers(&[("hx-request", "yes")])));
        assert!(!is_htmx(&HeaderMap::new()));
    }

    #[test]
    fn an_unauthorized_rejection_becomes_a_sign_in_redirect() {
        assert_eq!(
            to_page_error(AdminError::session_expired(), false),
            PageError::login_required(false)
        );
        assert_eq!(
            to_page_error(AdminError::session_invalid(), true),
            PageError::login_required(true)
        );
    }

    /// A failed CSRF check is not a reason to sign in again — the session is
    /// live, and bouncing to the sign-in page would send the operator straight
    /// back with nothing explained.
    #[test]
    fn a_csrf_failure_keeps_its_own_status() {
        let error = to_page_error(AdminError::csrf_failed("no token"), true);
        assert_eq!(error.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            error,
            PageError::Rendered {
                status: StatusCode::FORBIDDEN,
                code: "csrf_failed",
                message: "no token".to_string(),
            }
        );
    }
}
