//! Session tokens, the cookie they travel in, the extractors that resolve
//! them, the CSRF check, and the login rate limiter.
//!
//! ## The token
//!
//! 32 bytes from the system CSPRNG, base64url-unpadded (43 characters, cookie-
//! safe unquoted). Stored as `hex(SHA-256(token))` and never in plaintext, so
//! a read of the database — a backup, a `.dump`, an injection — yields nothing
//! replayable. Not the password KDF: the token has 256 bits of entropy, so
//! there is no dictionary to slow down and a slow hash would buy nothing but
//! latency on every request. Lookup is by the hash, and the value looked up
//! *is* the secret, so that path needs no constant-time comparison — unlike
//! the CSRF token, which is compared against a caller-supplied string.
//!
//! ## CSRF, and why `SameSite=Strict` is not enough
//!
//! The usual answer is that SameSite covers it. It does not, here, and the
//! reason is specific: **SameSite is scoped to the registrable domain, not the
//! origin — different ports of the same host are same-site.** A panel on
//! `:3001` beside anything else on `:8080` of the same box is exactly the
//! configuration it does not protect. So there is a per-session token as well,
//! plus an origin gate that also covers login (which by definition carries no
//! session token yet).
//!
//! Enforcement is **structural**: one of [`AuthenticatedWrite`],
//! [`AdminWrite`] or [`SelfServiceWrite`] is the only way for a mutating
//! handler to reach a session, and constructing any of them runs the origin
//! and CSRF checks. The three differ only in the privilege tier they demand —
//! `operator`+, `admin`, and none (own-account routes) — so a handler that
//! forgets the role check cannot compile. Same reasoning as hoisting the
//! media-type/`crit`/`url`/nonce checks into `AcmeRequest` — a new endpoint
//! cannot forget what it cannot express.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use acme_proxy_store::admin_login_bucket::{AdminLoginBucket, Reservation};
use acme_proxy_store::admin_session::AdminSession;
use acme_proxy_store::admin_user::AdminRole;
use acme_proxy_store::admin_user::AdminUser;
use acme_proxy_store::db::Database;
use acme_proxy_store::nonce::fingerprint;
use acme_proxy_store::nonce::now_secs;

/// The session cookie's name.
///
/// The `__Host-` prefix is free, browser-enforced hardening: it *requires*
/// `Secure`, `Path=/` and no `Domain`, which is exactly the spec chosen below.
/// A future edit that drops `Secure` therefore breaks the cookie visibly
/// instead of silently widening it.
pub const COOKIE_NAME: &str = "__Host-acme_admin_session";

/// The header carrying the per-session CSRF token on unsafe methods.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Session token length in bytes. 256 bits — the same size
/// `acme_proxy_store::eab::generate_secret` chooses, and for the same reason.
const TOKEN_LEN: usize = 32;

/// How stale `last_seen_at` may get before a request bothers to advance it.
///
/// Without this, a page polling every few seconds would take the WAL writer
/// lock on every request just to move a timestamp by a second.
const SESSION_TOUCH_INTERVAL: i64 = 60;

/// How long a half-authenticated session may sit unfinished.
///
/// Deliberately **not** `admin.session_ttl_seconds` and deliberately not a
/// configuration key. A `pending_mfa` row is a password that has been accepted
/// and nothing more; it should not outlive the tab that created it. Five
/// minutes is longer than reading a code off a phone and shorter than walking
/// away from the keyboard -- a UI timing constant, not a policy an operator
/// tunes.
///
/// It is also the only per-session bound on code guessing: within it an
/// attacker holding a correct password gets `admin.login_max_attempts` tries
/// from one address, and then the row is gone regardless.
pub const PENDING_MFA_TTL: Duration = Duration::from_secs(300);

/// A freshly minted session token, and the hash to store for it.
pub struct MintedToken {
    /// Goes in the `Set-Cookie` and is never written down.
    pub token: String,
    /// Goes in `admin_sessions.token_hash`.
    pub token_hash: String,
}

/// Mints a session token. RNG failure is unrecoverable, as elsewhere in this
/// crate.
#[must_use]
pub fn mint_token() -> MintedToken {
    let mut bytes = [0u8; TOKEN_LEN];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG unavailable");
    let token = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    let token_hash = hash_token(&token);
    MintedToken { token, token_hash }
}

/// Mints a CSRF token. Same entropy as a session token — it is stored in
/// plaintext, but it still has to be unguessable.
#[must_use]
pub fn mint_csrf_token() -> String {
    let mut bytes = [0u8; TOKEN_LEN];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG unavailable");
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// `hex(SHA-256(token))` — the `admin_sessions` primary key.
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    hex::encode(digest.as_ref())
}

/// The `Set-Cookie` value that establishes a session.
#[must_use]
pub fn session_cookie(token: &str, ttl: Duration) -> String {
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        ttl.as_secs()
    )
}

/// The `Set-Cookie` value that clears one.
#[must_use]
pub fn clearing_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

/// Reads the session token out of a `Cookie` header set.
///
/// Hand-rolled rather than pulling in `axum-extra` or `cookie` for twenty
/// lines. Takes the **first** match, across all `Cookie` headers: a crafted
/// request carrying the name twice must not let the second one win, which is a
/// session-fixation vector.
#[must_use]
pub fn cookie_value(headers: &HeaderMap) -> Option<String> {
    named_cookie_value(headers, COOKIE_NAME)
}

/// [`cookie_value`] for any cookie of this listener, first match winning for
/// the same reason.
#[must_use]
pub fn named_cookie_value(headers: &HeaderMap, cookie: &str) -> Option<String> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for pair in raw.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == cookie {
                // A cookie value may be quoted (RFC 6265 §4.1.1).
                let value = value.trim();
                let value = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(value);
                return Some(value.to_string());
            }
        }
    }
    None
}

/// The client address of an admin request, if the socket carried one.
///
/// Its own extractor rather than [`acme_proxy_core::client::ClientIp`], so a
/// router built without the `[admin.filter]` layer (a test driving one handler)
/// still gets the socket peer rather than `None`.
///
/// **Forwarded headers only from `admin.filter.trusted_proxies`.** That layer
/// resolves the address and records a `ClientIp`, which this prefers; its
/// absence falls back to the peer. Honouring `X-Forwarded-For` from anyone else
/// would let a caller spoof the key the login limiter counts on — and with no
/// trusted proxy listed, the limiter behind a reverse proxy counts the proxy.
#[derive(Debug, Clone, Copy)]
pub struct AdminClientIp(pub Option<IpAddr>);

impl<S: Sync> FromRequestParts<S> for AdminClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(acme_proxy_core::client::ClientIp(resolved)) = parts
            .extensions
            .get::<acme_proxy_core::client::ClientIp>()
            .copied()
        {
            return Ok(AdminClientIp(resolved));
        }
        let address = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            // Canonicalized for the same reason `ProxyPolicy::resolve` does it:
            // a dual-stack listener sees an IPv4 client as `::ffff:…`, and two
            // spellings of one address would be two buckets.
            .map(|info| info.0.ip().to_canonical());
        Ok(AdminClientIp(address))
    }
}

/// What still stands between a `pending_mfa` cookie and a usable session.
///
/// Not derivable from the session row alone, which is why it is carried rather
/// than recomputed: both states are one `pending_mfa` row, and the difference
/// is `user.has_totp()`. Making each caller re-derive it is exactly the drift
/// this codebase avoids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaStep {
    /// A confirmed factor exists: prove a code, or spend a recovery code.
    Verify,
    /// `admin.require_mfa` is on and this operator has none: enrol first.
    Enrol,
}

impl MfaStep {
    /// The wire and template spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MfaStep::Verify => "verify",
            MfaStep::Enrol => "enrol",
        }
    }
}

/// A live session and the operator it belongs to. Read-only handlers take this.
#[derive(Debug)]
pub struct Authenticated {
    pub session: AdminSession,
    pub user: AdminUser,
}

/// [`Authenticated`], the origin gate and the CSRF check, **plus a privilege
/// tier of at least [`AdminRole::Operator`]**.
///
/// Every mutating handler that touches shared or CA state takes this. None of
/// the three checks can be forgotten, because this type is the only way such a
/// handler can reach a session at all. A `viewer` is refused here; the
/// own-account routes a `viewer` may still use take [`SelfServiceWrite`]
/// instead, and the colleague-management routes take [`AdminWrite`].
#[derive(Debug)]
pub struct AuthenticatedWrite(pub Authenticated);

/// [`AuthenticatedWrite`], but requiring the full [`AdminRole::Admin`] tier.
///
/// The four `/operators/*` routes take this: disabling or re-enabling a
/// colleague, resetting their second factor, revoking one of their sessions.
#[derive(Debug)]
pub struct AdminWrite(pub Authenticated);

/// The origin gate, a live `active` session and the CSRF check -- **no
/// privilege check**, so any role including `viewer` passes.
///
/// The own-account routes take this: change your own password, revoke your own
/// sessions, manage your own second factor, log out. A `viewer` has to be able
/// to do these or `admin.require_mfa` enrolment would be unreachable for them.
#[derive(Debug)]
pub struct SelfServiceWrite(pub Authenticated);

/// [`Authenticated`] **plus a privilege tier of [`AdminRole::Admin`]** -- the
/// read-side sibling of [`AdminWrite`], with no CSRF or origin gate, since a
/// `GET` changes nothing.
///
/// The `/operators` read routes take this. What they render is every
/// colleague's role and contact address, the last addresses each signed in
/// from, and every live session's fingerprint, address and last-seen time --
/// "who else is an admin here, and from where do they work" is exactly the
/// reconnaissance a `viewer` tier exists to withhold, so the reads are gated to
/// the same tier as the writes rather than to a live session alone.
///
/// Nothing else on this listener needs it: every other read is either the
/// caller's own (`/account/*`) or CA state a `viewer` is meant to see.
#[derive(Debug)]
pub struct AdminRead(pub Authenticated);

impl FromRequestParts<AdminState> for Authenticated {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        resolve_session(parts, state).await
    }
}

/// The origin gate + live `active` session + CSRF check the three write
/// extractors share. Each then adds (or omits) its own privilege check.
async fn resolve_write(parts: &Parts, state: &AdminState) -> Result<Authenticated, AdminError> {
    // The origin gate first: it is free, and it refuses a cross-origin
    // request before a database lookup happens on its behalf.
    check_origin(&parts.headers, &state.config.admin.base_url)?;
    let authenticated = resolve_session(parts, state).await?;
    check_csrf(&parts.headers, &authenticated.session.csrf_token)?;
    Ok(authenticated)
}

/// The privilege gate. `role()` resolves a `NULL` column to
/// [`AdminRole::Admin`], so an operator that predates the `role` column is
/// unaffected.
fn require_role(user: &AdminUser, minimum: AdminRole) -> Result<(), AdminError> {
    if user.role() >= minimum {
        Ok(())
    } else {
        Err(AdminError::insufficient_role())
    }
}

impl FromRequestParts<AdminState> for AdminRead {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        // No `resolve_write`: there is no body to forge and no state change to
        // ride, so the origin and CSRF gates buy nothing on a read. The tier is
        // the whole of what this adds over `Authenticated`.
        let authenticated = resolve_session(parts, state).await?;
        require_role(&authenticated.user, AdminRole::Admin)?;
        Ok(AdminRead(authenticated))
    }
}

impl FromRequestParts<AdminState> for AuthenticatedWrite {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let authenticated = resolve_write(parts, state).await?;
        require_role(&authenticated.user, AdminRole::Operator)?;
        Ok(AuthenticatedWrite(authenticated))
    }
}

impl FromRequestParts<AdminState> for AdminWrite {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let authenticated = resolve_write(parts, state).await?;
        require_role(&authenticated.user, AdminRole::Admin)?;
        Ok(AdminWrite(authenticated))
    }
}

impl FromRequestParts<AdminState> for SelfServiceWrite {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        Ok(SelfServiceWrite(resolve_write(parts, state).await?))
    }
}

/// A session with a verified password and nothing more.
///
/// Its own extractor with its own resolver, because [`resolve_session`] hard-
/// refuses a non-`active` session -- deliberately, so no ordinary route can
/// accept a half-authenticated one. This is its exact mirror image: it refuses
/// an `active` one.
#[derive(Debug)]
pub struct PendingMfa {
    pub session: AdminSession,
    pub user: AdminUser,
    pub step: MfaStep,
}

/// [`PendingMfa`] with the **origin gate only, and no CSRF check.**
///
/// The omission is deliberate, and is the same one `POST /ui/login` already
/// makes one step earlier: the challenge page is a plain form -- sign-in must
/// work with JavaScript off, which `tests/admin_pages.rs` pins for `login.html`
/// -- and [`check_csrf`] reads a header a form cannot set. Teaching it to read a
/// form field instead would be a second CSRF path, which is what
/// `pages::auth`'s whole shape exists to prevent.
///
/// What covers the route is [`check_origin`], and the residual risk is nil: a
/// cross-site forger would need a valid code for a session they cannot read,
/// and success would only complete the victim's own login.
#[derive(Debug)]
pub struct PendingMfaSubmit(pub PendingMfa);

/// A session allowed to *set up* a factor.
///
/// Either an `active` session -- voluntary enrolment, or moving to a new phone
/// -- or a `pending_mfa` one that exists precisely because the operator has none
/// and `admin.require_mfa` is on.
///
/// **The `pending_mfa` case requires `!user.has_totp()`, and that condition is
/// the whole security of this type.** A session that owes a *code* must never
/// reach an enrolment route, or the second factor is bypassable by enrolling a
/// new one over it.
///
/// Runs [`check_origin`] and [`check_csrf`] exactly as [`AuthenticatedWrite`]
/// does: unlike the challenge form, these routes are htmx calls from a page
/// that was handed a token.
#[derive(Debug)]
pub struct EnrolWrite {
    pub session: AdminSession,
    pub user: AdminUser,
    /// `true` when this session is still `pending_mfa`, so the handler knows to
    /// promote it once the enrolment confirms.
    pub pending: bool,
}

impl FromRequestParts<AdminState> for PendingMfa {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        resolve_pending(parts, state).await
    }
}

impl FromRequestParts<AdminState> for PendingMfaSubmit {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        check_origin(&parts.headers, &state.config.admin.base_url)?;
        Ok(PendingMfaSubmit(resolve_pending(parts, state).await?))
    }
}

impl FromRequestParts<AdminState> for EnrolWrite {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        check_origin(&parts.headers, &state.config.admin.base_url)?;
        let (_, session, user) = resolve_live(parts, state).await?;

        // The refusal this type exists for. A `pending_mfa` session whose owner
        // already *has* a factor owes a code, and letting it enrol a second one
        // would make the first optional.
        if !session.is_active() && user.has_totp() {
            return Err(AdminError::session_invalid());
        }

        check_csrf(&parts.headers, &session.csrf_token)?;
        let pending = !session.is_active();
        Ok(EnrolWrite {
            session,
            user,
            pending,
        })
    }
}

/// Cookie → live row → live user.
///
/// Judges *liveness* only -- expiry, idleness, the orphan case, a disabled owner
/// -- and never `state`. That is what lets two extractors sit over one lookup
/// without either being a widening of the other: each adds its own opposite
/// state check on top.
async fn resolve_live(
    parts: &Parts,
    state: &AdminState,
) -> Result<(String, AdminSession, AdminUser), AdminError> {
    let token = cookie_value(&parts.headers).ok_or_else(AdminError::session_invalid)?;
    let token_hash = hash_token(&token);

    let Some(session) = AdminSession::find_by_token_hash(&token_hash, &state.database).await?
    else {
        return Err(AdminError::session_invalid());
    };

    let now = now_secs();
    if session.is_expired(now) {
        AdminSession::delete(&token_hash, &state.database).await?;
        return Err(AdminError::session_expired());
    }
    let idle_timeout = Duration::from_secs(state.config.admin.session_idle_timeout_seconds);
    if session.is_idle(now, idle_timeout) {
        AdminSession::delete(&token_hash, &state.database).await?;
        return Err(AdminError::session_idle());
    }

    let Some(user) = AdminUser::find_by_id(session.user_id, &state.database).await? else {
        // The FK cascade should make this impossible; if it happens, the
        // session is orphaned and must not authenticate anybody.
        warn!(event = "admin_session_orphaned", outcome = "failure", session_fp = %fingerprint(&token_hash));
        AdminSession::delete(&token_hash, &state.database).await?;
        return Err(AdminError::session_invalid());
    };
    if !user.is_active() {
        return Err(AdminError::session_invalid());
    }

    Ok((token_hash, session, user))
}

/// Resolves the cookie to a live, **fully authenticated** session, refusing each
/// way it can be dead with its own code — the client is told to sign in again
/// either way, but the operator reading a log can tell an expiry from a
/// revocation.
async fn resolve_session(parts: &Parts, state: &AdminState) -> Result<Authenticated, AdminError> {
    let (_, mut session, user) = resolve_live(parts, state).await?;

    // `pending_mfa`: a password was accepted and nothing more. Only the routes
    // that finish the login may see such a session, and they go through
    // `resolve_pending` instead.
    if !session.is_active() {
        return Err(AdminError::session_invalid());
    }

    if now_secs() - session.last_seen_at >= SESSION_TOUCH_INTERVAL {
        session.touch(&state.database).await?;
    }

    Ok(Authenticated { session, user })
}

/// [`resolve_session`]'s mirror image: a live session that is **not** yet
/// active.
///
/// Does not touch `last_seen_at`. A pending row has a five-minute absolute
/// deadline, so advancing an idle deadline it will never reach would be pure
/// cost on the login path.
async fn resolve_pending(parts: &Parts, state: &AdminState) -> Result<PendingMfa, AdminError> {
    let (_, session, user) = resolve_live(parts, state).await?;

    if session.is_active() {
        return Err(AdminError::session_invalid());
    }

    let step = if user.has_totp() {
        MfaStep::Verify
    } else {
        MfaStep::Enrol
    };
    Ok(PendingMfa {
        session,
        user,
        step,
    })
}

/// Compares the request's `X-CSRF-Token` against the session's, in constant
/// time.
pub fn check_csrf(headers: &HeaderMap, expected: &str) -> Result<(), AdminError> {
    let Some(supplied) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return Err(AdminError::csrf_failed(format!(
            "this request needs an {CSRF_HEADER} header carrying the session's csrfToken"
        )));
    };

    // `ct_eq` is only constant-time across equal lengths; comparing the
    // lengths first leaks nothing a token's own encoding does not already fix.
    let matches = supplied.len() == expected.len()
        && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()));
    if !matches {
        return Err(AdminError::csrf_failed(
            "the CSRF token does not match this session",
        ));
    }
    Ok(())
}

/// Refuses a request whose `Origin` or `Sec-Fetch-Site` says it came from
/// somewhere else.
///
/// Both headers are checked only when *present*: a non-browser client (curl,
/// a script) sends neither and is not the threat this addresses. Its value is
/// covering the login request, which carries no session and therefore no CSRF
/// token to check.
pub fn check_origin(headers: &HeaderMap, base_url: &str) -> Result<(), AdminError> {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && site != "same-origin"
        && site != "none"
    {
        return Err(AdminError::csrf_failed(format!(
            "cross-origin request refused (Sec-Fetch-Site: {site})"
        )));
    }

    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let expected = url::Url::parse(base_url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default();
        if origin != expected {
            return Err(AdminError::csrf_failed(format!(
                "cross-origin request refused (Origin: {origin}, expected {expected})"
            )));
        }
    }
    Ok(())
}

/// Fixed-window failed-login counter, keyed by client address, **in the
/// database** (`acme_proxy_store::admin_login_bucket`).
///
/// It was in process memory, and correct only while exactly one admin process
/// existed: two behind one load balancer gave an attacker two budgets, and a
/// restart a fresh one. In the table every admin process shares one budget per
/// address, and a configuration reload has nothing to carry — the counters
/// were never the generation's. The price is a write on the path being
/// flooded, one indexed `UPDATE` per attempt: still a small fraction of the
/// 600 000 KDF iterations a refusal saves.
///
/// **An attempt is counted when it starts, not when it fails.** [`begin`]
/// reserves a slot and refuses once failures *plus attempts still in flight*
/// reach the limit, in one conditional statement. Counting only finished
/// failures was a check-then-act race: a burst of parallel requests from one
/// address all passed the check before the first of them had paid its KDF and
/// recorded anything, so the burst bought as many guesses — and as much KDF
/// time — as it had requests. The slot is a [`LoginAttempt`] guard, so every
/// early return (a database error included) gives it back.
///
/// Two instances share the table under different scopes: `password` for
/// credentials and `oidc_start` for the OpenID Connect starts that each write a
/// row (`AdminState::oidc_starts`).
///
/// [`begin`]: LoginLimiter::begin
#[derive(Clone)]
pub struct LoginLimiter {
    scope: &'static str,
    max_attempts: u32,
    window_seconds: u64,
    database: Arc<Database>,
}

impl std::fmt::Debug for LoginLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginLimiter")
            .field("scope", &self.scope)
            .field("max_attempts", &self.max_attempts)
            .field("window_seconds", &self.window_seconds)
            .finish_non_exhaustive()
    }
}

/// Why [`LoginLimiter::begin`] refused an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRefusal {
    /// The address has spent its budget: retry after this many seconds.
    RateLimited(u64),
    /// The counter could not be read. Fails **closed**: a limiter that waved
    /// attempts through whenever its table was unreachable would be a bypass
    /// for anyone able to make it so.
    Unavailable,
}

impl LoginRefusal {
    /// The `reason` a refused sign-in is logged with.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::RateLimited(_) => "rate_limited",
            Self::Unavailable => "limiter_unavailable",
        }
    }
}

impl From<LoginRefusal> for AdminError {
    fn from(refusal: LoginRefusal) -> Self {
        match refusal {
            LoginRefusal::RateLimited(retry_after) => AdminError::rate_limited(retry_after),
            LoginRefusal::Unavailable => AdminError::internal(),
        }
    }
}

/// The bucket an address counts against.
///
/// An IPv6 client is keyed by its /64. A single subscriber routinely holds a
/// whole /64 and can rotate through it at will, so keying the full /128 gave
/// one attacker 2^64 fresh budgets. An IPv4-mapped address is its IPv4 self.
fn bucket_key(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(std::net::Ipv6Addr::from(prefix))
        }
    }
}

impl LoginLimiter {
    /// The credential limiter: at most `max_attempts` failures per client
    /// address (an IPv6 address by its /64) within `window_seconds`.
    #[must_use]
    pub fn new(database: Arc<Database>, max_attempts: u32, window_seconds: u64) -> Self {
        Self::scoped(PASSWORD_SCOPE, database, max_attempts, window_seconds)
    }

    /// The same limits over a budget of its own, named by `scope`.
    #[must_use]
    pub fn scoped(
        scope: &'static str,
        database: Arc<Database>,
        max_attempts: u32,
        window_seconds: u64,
    ) -> Self {
        Self {
            scope,
            max_attempts,
            window_seconds,
            database,
        }
    }

    /// Starts a login attempt from this address, or refuses it.
    ///
    /// Called **before** the password hash runs: 600 000 iterations is a
    /// denial-of-service lever, so a limited caller must not pay it — nor make
    /// the server pay it. The returned guard holds the slot until it is
    /// [`failed`](LoginAttempt::failed), [`released`](LoginAttempt::release)
    /// or dropped.
    pub async fn begin(&self, client: Option<IpAddr>) -> Result<LoginAttempt<'_>, LoginRefusal> {
        // No address means no key. This is not a bypass: the limiter is a
        // convenience over the bind address and the session, and an admin
        // listener always has a peer address in practice (`TapIo` carries it
        // through TLS). Failing closed here would lock out every request
        // rather than every attacker.
        let Some(key) = client.map(|client| bucket_key(client).to_string()) else {
            return Ok(LoginAttempt {
                limiter: self,
                key: None,
            });
        };
        let reservation = AdminLoginBucket::begin(
            self.scope,
            &key,
            self.max_attempts,
            self.window_seconds,
            now_secs(),
            &self.database,
        )
        .await
        .map_err(|error| {
            warn!(event = "admin_login_limiter_failed",
                  outcome = "failure",
                  scope = self.scope,
                  error = %error);
            LoginRefusal::Unavailable
        })?;
        match reservation {
            Reservation::Reserved => Ok(LoginAttempt {
                limiter: self,
                key: Some(key),
            }),
            Reservation::Refused { retry_after } => Err(LoginRefusal::RateLimited(retry_after)),
        }
    }

    /// Clears an address's failures after a completed login, so one operator
    /// fumbling their password does not spend the window for the next.
    ///
    /// Best effort: the sign-in has already succeeded, and failing it because
    /// the counter could not be cleared would punish the one request that
    /// proved itself.
    pub async fn record_success(&self, client: Option<IpAddr>) {
        let Some(client) = client else {
            return;
        };
        let key = bucket_key(client).to_string();
        if let Err(error) = AdminLoginBucket::clear_failures(self.scope, &key, &self.database).await
        {
            warn!(event = "admin_login_limiter_failed",
                  outcome = "failure",
                  scope = self.scope,
                  error = %error);
        }
    }

    /// Gives back an in-flight slot, and turns it into a failure if `failed`.
    async fn settle(scope: &str, key: &str, failed: bool, database: &Database) {
        if let Err(error) = AdminLoginBucket::settle(scope, key, failed, database).await {
            // A slot not given back is spent until the window runs out, which
            // is the bound the table documents; a failure not counted is one
            // guess more. Neither is worth failing the request over.
            warn!(event = "admin_login_limiter_failed",
                  outcome = "failure",
                  scope = scope,
                  error = %error);
        }
    }
}

/// The scope [`LoginLimiter::new`] counts credentials under.
pub const PASSWORD_SCOPE: &str = "password";

/// The scope `AdminState::oidc_starts` counts OpenID Connect starts under.
pub const OIDC_START_SCOPE: &str = "oidc_start";

/// One login attempt's slot in the [`LoginLimiter`].
///
/// Dropping it releases the slot without counting anything: a correct password
/// waiting on its second factor, a refused origin, a database error. Only
/// [`failed`](Self::failed) spends the budget.
///
/// A drop cannot await, so the release it triggers is spawned and lands a
/// moment later; [`release`](Self::release) is the same, awaited.
#[derive(Debug)]
#[must_use = "dropping the attempt releases its slot"]
pub struct LoginAttempt<'a> {
    limiter: &'a LoginLimiter,
    key: Option<String>,
}

impl LoginAttempt<'_> {
    /// Counts this attempt as a failure against its address.
    pub async fn failed(mut self) {
        if let Some(key) = self.key.take() {
            LoginLimiter::settle(self.limiter.scope, &key, true, &self.limiter.database).await;
        }
    }

    /// Gives the slot back uncounted, and waits until it is.
    pub async fn release(mut self) {
        if let Some(key) = self.key.take() {
            LoginLimiter::settle(self.limiter.scope, &key, false, &self.limiter.database).await;
        }
    }
}

impl Drop for LoginAttempt<'_> {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        // Outside a runtime there is nothing to spawn on; the window running
        // out gives the slot back instead.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let scope = self.limiter.scope;
            let database = self.limiter.database.clone();
            runtime.spawn(async move {
                LoginLimiter::settle(scope, &key, false, &database).await;
            });
        }
    }
}

/// Logs a completed login attempt. One place, so the events cannot drift.
pub fn log_login(
    succeeded: bool,
    username: &str,
    realm: &str,
    client: Option<IpAddr>,
    reason: &'static str,
) {
    if succeeded {
        info!(event = "admin_login_succeeded",
              outcome = "success",
              username = %username,
              realm = %realm,
              client_ip = ?client);
    } else {
        warn!(event = "admin_login_failed",
              outcome = "failure",
              username = %username,
              realm = %realm,
              client_ip = ?client,
              reason = reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    async fn client_ip_of(request: axum::http::Request<()>) -> Option<IpAddr> {
        let (mut parts, ()) = request.into_parts();
        let AdminClientIp(ip) = AdminClientIp::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        ip
    }

    /// Behind a trusted proxy the `[admin.filter]` layer has resolved the real
    /// client, and that — not the proxy — is what the login limiter must count.
    #[tokio::test]
    async fn the_resolved_client_is_preferred_to_the_peer() {
        let mut request = axum::http::Request::new(());
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [172, 18, 0, 2],
                4711,
            ))));
        request
            .extensions_mut()
            .insert(acme_proxy_core::client::ClientIp(Some(
                "198.51.100.9".parse().unwrap(),
            )));
        assert_eq!(
            client_ip_of(request).await,
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn without_the_filter_layer_the_peer_is_the_client() {
        let mut request = axum::http::Request::new(());
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "[::ffff:192.0.2.7]:4711"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));
        assert_eq!(
            client_ip_of(request).await,
            Some("192.0.2.7".parse().unwrap())
        );
    }

    #[test]
    fn a_minted_token_is_43_url_safe_characters_and_hashes_stably() {
        let minted = mint_token();
        assert_eq!(minted.token.len(), 43, "32 bytes, base64url unpadded");
        assert!(!minted.token.contains('='));
        assert!(!minted.token.contains('+'));
        assert!(!minted.token.contains('/'));
        assert_eq!(minted.token_hash, hash_token(&minted.token));
        assert_eq!(minted.token_hash.len(), 64, "SHA-256 as hex");

        // Distinct per call, and the hash never contains the token.
        assert_ne!(mint_token().token, minted.token);
        assert!(!minted.token_hash.contains(&minted.token));
    }

    #[test]
    fn hash_token_matches_a_known_vector() {
        // sha256("") — pins the encoding (hex, lowercase) as well as the digest.
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn csrf_tokens_are_unguessable_and_distinct() {
        let first = mint_csrf_token();
        assert_eq!(first.len(), 43);
        assert_ne!(first, mint_csrf_token());
    }

    #[test]
    fn the_session_cookie_carries_every_required_attribute() {
        let cookie = session_cookie("the-token", Duration::from_secs(43_200));
        assert!(cookie.starts_with("__Host-acme_admin_session=the-token;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=43200"));
        // `__Host-` forbids it, and setting one would widen the cookie to
        // every subdomain.
        assert!(!cookie.contains("Domain"));
    }

    #[test]
    fn the_clearing_cookie_expires_immediately_and_keeps_the_same_attributes() {
        let cookie = clearing_cookie();
        assert!(cookie.starts_with("__Host-acme_admin_session=;"));
        assert!(cookie.contains("Max-Age=0"));
        // A browser matches on name+path+domain, so a clear that dropped these
        // would leave the original cookie in place.
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
    }

    /// A parser case: a label, the `Cookie` headers to send, and the value the
    /// parser must pick out.
    type CookieCase = (
        &'static str,
        Vec<(&'static str, String)>,
        Option<&'static str>,
    );

    #[test]
    fn cookie_parsing_is_table_driven() {
        let name = COOKIE_NAME;
        let cases: Vec<CookieCase> = vec![
            ("absent entirely", vec![], None),
            (
                "the only cookie",
                vec![("cookie", format!("{name}=abc"))],
                Some("abc"),
            ),
            (
                "among others",
                vec![("cookie", format!("theme=dark; {name}=abc; lang=en"))],
                Some("abc"),
            ),
            (
                "leading whitespace",
                vec![("cookie", format!("theme=dark;   {name}=abc"))],
                Some("abc"),
            ),
            (
                "a quoted value",
                vec![("cookie", format!("{name}=\"abc\""))],
                Some("abc"),
            ),
            (
                "a segment with no equals sign",
                vec![("cookie", format!("broken; {name}=abc"))],
                Some("abc"),
            ),
            (
                "present but empty",
                vec![("cookie", format!("{name}="))],
                Some(""),
            ),
            (
                "a different cookie only",
                vec![("cookie", "other=abc".to_string())],
                None,
            ),
            (
                // The fixation vector: a crafted header repeating the name
                // must not let the *second* value win.
                "duplicated in one header",
                vec![("cookie", format!("{name}=first; {name}=second"))],
                Some("first"),
            ),
            (
                "duplicated across two headers",
                vec![
                    ("cookie", format!("{name}=first")),
                    ("cookie", format!("{name}=second")),
                ],
                Some("first"),
            ),
            (
                "a name that merely contains ours",
                vec![("cookie", format!("x{name}=nope"))],
                None,
            ),
        ];

        for (label, pairs, expected) in cases {
            let owned: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
            assert_eq!(
                cookie_value(&headers(&owned)).as_deref(),
                expected,
                "case `{label}`"
            );
        }
    }

    #[test]
    fn the_csrf_check_accepts_only_an_exact_match() {
        let expected = "the-expected-token";
        assert!(check_csrf(&headers(&[(CSRF_HEADER, expected)]), expected).is_ok());

        // Missing.
        let error = check_csrf(&HeaderMap::new(), expected).unwrap_err();
        assert_eq!(error.code, "csrf_failed");
        assert!(error.message.contains(CSRF_HEADER));

        // Wrong, and wrong-length (the branch that short-circuits `ct_eq`).
        for supplied in [
            "",
            "wrong",
            "the-expected-token-but-longer",
            "the-expected-toke",
        ] {
            let error = check_csrf(&headers(&[(CSRF_HEADER, supplied)]), expected).unwrap_err();
            assert_eq!(error.code, "csrf_failed", "for `{supplied}`");
        }
    }

    #[test]
    fn the_origin_gate_covers_the_cases_a_browser_produces() {
        let base = "http://localhost:3001";

        // Neither header: a script or curl. Not the threat this addresses.
        assert!(check_origin(&HeaderMap::new(), base).is_ok());

        // Same-origin, both spellings a browser uses.
        assert!(check_origin(&headers(&[("sec-fetch-site", "same-origin")]), base).is_ok());
        assert!(check_origin(&headers(&[("sec-fetch-site", "none")]), base).is_ok());
        assert!(check_origin(&headers(&[("origin", base)]), base).is_ok());

        for site in ["cross-site", "same-site"] {
            let error = check_origin(&headers(&[("sec-fetch-site", site)]), base).unwrap_err();
            assert_eq!(error.code, "csrf_failed", "for {site}");
            // `same-site` is the one SameSite=Strict would have let through:
            // a different port of the same host.
            assert!(error.message.contains(site));
        }

        let error = check_origin(&headers(&[("origin", "http://evil.example")]), base).unwrap_err();
        assert!(error.message.contains("evil.example"));

        // A different port of the same host is a different origin.
        let error =
            check_origin(&headers(&[("origin", "http://localhost:8080")]), base).unwrap_err();
        assert_eq!(error.code, "csrf_failed");
    }

    fn ip(last: u8) -> Option<IpAddr> {
        Some(IpAddr::from([192, 0, 2, last]))
    }

    async fn limiter(max_attempts: u32, window_seconds: u64) -> LoginLimiter {
        let database = Database::connect_for_test().await.expect("a test database");
        LoginLimiter::new(Arc::new(database), max_attempts, window_seconds)
    }

    /// One failed attempt, start to finish.
    async fn fail(limiter: &LoginLimiter, client: Option<IpAddr>) {
        limiter.begin(client).await.unwrap().failed().await;
    }

    #[tokio::test]
    async fn the_limiter_permits_up_to_the_limit_then_refuses() {
        let limiter = limiter(3, 300).await;

        for attempt in 0..3 {
            let slot = limiter.begin(ip(1)).await;
            assert!(slot.is_ok(), "attempt {attempt} must pass");
            slot.unwrap().failed().await;
        }

        let Err(LoginRefusal::RateLimited(retry_after)) = limiter.begin(ip(1)).await else {
            panic!("the fourth attempt must be rate limited");
        };
        assert!(retry_after > 0 && retry_after <= 300, "got {retry_after}");

        // Scoped to the address that failed.
        assert!(limiter.begin(ip(2)).await.is_ok());
    }

    /// The race this type exists to close: a burst whose attempts are all in
    /// flight at once must not each find the budget untouched.
    #[tokio::test]
    async fn attempts_in_flight_count_against_the_limit() {
        let limiter = limiter(3, 300).await;
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(limiter.begin(ip(1)).await.unwrap());
        }
        assert!(
            limiter.begin(ip(1)).await.is_err(),
            "a fourth concurrent attempt must be refused before any has failed"
        );

        // Settled without failing — a right password awaiting its second
        // factor — the slots come back.
        for attempt in held {
            attempt.release().await;
        }
        assert!(limiter.begin(ip(1)).await.is_ok());
    }

    /// A dropped guard cannot await, so its release is spawned: the slot comes
    /// back a moment later rather than at the drop.
    #[tokio::test]
    async fn a_dropped_attempt_gives_its_slot_back() {
        let limiter = limiter(1, 300).await;
        drop(limiter.begin(ip(1)).await.unwrap());

        let mut freed = false;
        for _ in 0..100 {
            if let Ok(attempt) = limiter.begin(ip(1)).await {
                attempt.release().await;
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(freed, "the spawned release must land");
    }

    #[tokio::test]
    async fn a_success_clears_the_counter() {
        let limiter = limiter(2, 300).await;
        fail(&limiter, ip(1)).await;
        limiter.record_success(ip(1)).await;
        fail(&limiter, ip(1)).await;
        assert!(
            limiter.begin(ip(1)).await.is_ok(),
            "the pre-success failure must not still count"
        );
    }

    /// A success while another attempt is in flight keeps that attempt's slot,
    /// so it is still released when it settles.
    #[tokio::test]
    async fn a_success_beside_an_attempt_in_flight_keeps_its_slot() {
        let limiter = limiter(1, 300).await;
        let other = limiter.begin(ip(1)).await.unwrap();
        limiter.record_success(ip(1)).await;
        assert!(
            limiter.begin(ip(1)).await.is_err(),
            "the slot is still taken"
        );
        other.release().await;
        assert!(limiter.begin(ip(1)).await.is_ok());
    }

    #[tokio::test]
    async fn the_window_rolls_over() {
        // A short window, so the rollover is observable after a sleep rather
        // than by reaching into the table. Two seconds, not one: the window is
        // counted in whole seconds, so a one-second window can roll over
        // between two calls milliseconds apart (a `fail` at x.99, a `begin`
        // at x+1.00), and the refusal below would then flake.
        let limiter = limiter(1, 2).await;
        fail(&limiter, ip(1)).await;
        assert!(limiter.begin(ip(1)).await.is_err());

        tokio::time::sleep(Duration::from_millis(2_100)).await;
        assert!(
            limiter.begin(ip(1)).await.is_ok(),
            "the window must roll over"
        );
    }

    #[tokio::test]
    async fn a_missing_client_address_is_not_limited() {
        let limiter = limiter(1, 300).await;
        fail(&limiter, None).await;
        limiter.record_success(None).await;
        assert!(
            limiter.begin(None).await.is_ok(),
            "failing closed here would lock out every request, not every attacker"
        );
    }

    /// Rotating through one /64 is one budget; a different /64 is another, and
    /// an IPv4-mapped address is its IPv4 self.
    #[tokio::test]
    async fn an_ipv6_client_is_limited_by_its_slash_64() {
        let limiter = limiter(1, 300).await;
        let v6 = |s: &str| Some(s.parse::<IpAddr>().unwrap());

        fail(&limiter, v6("2001:db8:1:2::1")).await;
        assert!(limiter.begin(v6("2001:db8:1:2:ffff::9")).await.is_err());
        assert!(limiter.begin(v6("2001:db8:1:3::1")).await.is_ok());

        fail(&limiter, ip(7)).await;
        assert!(limiter.begin(v6("::ffff:192.0.2.7")).await.is_err());
    }

    /// The property moving the counter into the database bought: two limiters
    /// over one database — two admin processes, or two configuration
    /// generations — spend one budget.
    #[tokio::test]
    async fn two_limiters_over_one_database_share_one_budget() {
        let database = Arc::new(Database::connect_for_test().await.unwrap());
        let first = LoginLimiter::new(database.clone(), 2, 300);
        let second = LoginLimiter::new(database.clone(), 2, 300);

        fail(&first, ip(1)).await;
        fail(&second, ip(1)).await;
        assert!(first.begin(ip(1)).await.is_err());
        assert!(second.begin(ip(1)).await.is_err());

        // A scope of its own is a budget of its own.
        let starts = LoginLimiter::scoped(OIDC_START_SCOPE, database, 2, 300);
        assert!(starts.begin(ip(1)).await.is_ok());
    }

    /// An unreachable table refuses rather than waving the attempt through.
    #[tokio::test]
    async fn a_failing_counter_fails_closed() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        crate::webadmin::session::tests::drop_buckets(&database).await;
        let limiter = LoginLimiter::new(database, 2, 300);

        let refusal = limiter.begin(ip(1)).await.unwrap_err();
        assert_eq!(refusal, LoginRefusal::Unavailable);
        assert_eq!(refusal.reason(), "limiter_unavailable");
        assert_eq!(AdminError::from(refusal).code, "internal");
        // Clearing is best effort, and does not fail the sign-in it follows.
        limiter.record_success(ip(1)).await;
    }

    async fn drop_buckets(database: &Database) {
        acme_proxy_store::sql::query("DROP TABLE admin_login_buckets;")
            .execute(database)
            .await
            .expect("the table drops");
    }

    #[test]
    fn log_login_renders_both_outcomes() {
        // The `tracing` field expressions only execute when something is
        // subscribed; `tests/common` installs a sink, and here the call is
        // simply exercised for its branches.
        log_login(true, "alice", "local", ip(1), "");
        log_login(false, "alice", "local", ip(1), "wrong_password");
        log_login(false, "alice", "ldap:ad", None, "unknown_user");
    }
}
