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
//! Enforcement is **structural**: [`AuthenticatedWrite`] is the only way for a
//! mutating handler to reach a session, and constructing it runs the check.
//! Same reasoning as hoisting the media-type/`crit`/`url`/nonce checks into
//! `AcmeRequest` — a new endpoint cannot forget what it cannot express.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::db::Database;
use crate::sqlite::nonce::{fingerprint, now_secs};
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;

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
/// `sqlite::eab::generate_secret` chooses, and for the same reason.
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
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for pair in raw.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == COOKIE_NAME {
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

/// The peer address of an admin request, if the socket carried one.
///
/// Its own extractor rather than [`crate::filter::client_ip::ClientIp`],
/// because that one is populated by the ACME filter middleware and this
/// listener deliberately runs none (see `build_admin_app`).
///
/// **No forwarded-header handling.** `filter.trusted_proxies` governs the ACME
/// listener, and honouring `X-Forwarded-For` here without an equivalent
/// allowlist would let any caller spoof the key the login limiter counts on.
/// Behind a reverse proxy the limiter therefore counts the proxy — which is a
/// real limitation, and the reason the recommended way to reach this listener
/// remotely is an SSH tunnel rather than a proxy.
#[derive(Debug, Clone, Copy)]
pub struct AdminClientIp(pub Option<IpAddr>);

impl<S: Sync> FromRequestParts<S> for AdminClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
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

/// [`Authenticated`], plus the CSRF token and the origin gate.
///
/// Every mutating handler takes this. The check cannot be forgotten, because
/// this type is the only way a `POST`/`PATCH`/`DELETE` handler can reach a
/// session at all.
#[derive(Debug)]
pub struct AuthenticatedWrite(pub Authenticated);

impl FromRequestParts<AdminState> for Authenticated {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        resolve_session(parts, state).await
    }
}

impl FromRequestParts<AdminState> for AuthenticatedWrite {
    type Rejection = AdminError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        // The origin gate first: it is free, and it refuses a cross-origin
        // request before a database lookup happens on its behalf.
        check_origin(&parts.headers, &state.config.admin.base_url)?;
        let authenticated = resolve_session(parts, state).await?;
        check_csrf(&parts.headers, &authenticated.session.csrf_token)?;
        Ok(AuthenticatedWrite(authenticated))
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

    let Some(user) = AdminUser::find_by_id(&session.user_id, &state.database).await? else {
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

/// Fixed-window failed-login counter, keyed by client address.
///
/// In-process on purpose: it protects a listener that defaults to loopback and
/// holds a handful of accounts, and a database-backed counter would add a
/// write to the very path being flooded.
#[derive(Debug)]
pub struct LoginLimiter {
    max_attempts: u32,
    window: Duration,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    failures: u32,
    window_started: i64,
}

impl LoginLimiter {
    #[must_use]
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            max_attempts,
            window: Duration::from_secs(window_seconds),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this address may attempt a login now. `Err` carries the seconds
    /// left in the window.
    ///
    /// Called **before** the password hash runs: 600 000 iterations is a
    /// denial-of-service lever, so a limited caller must not pay it — nor make
    /// the server pay it.
    pub fn check(&self, client: Option<IpAddr>) -> Result<(), u64> {
        // No address means no key. This is not a bypass: the limiter is a
        // convenience over the bind address and the session, and an admin
        // listener always has a peer address in practice (`TapIo` carries it
        // through TLS). Failing closed here would lock out every request
        // rather than every attacker.
        let Some(client) = client else { return Ok(()) };
        let now = now_secs();
        let window = self.window.as_secs() as i64;

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        // Pruned under the same lock, so the map cannot grow without bound.
        buckets.retain(|_, bucket| now - bucket.window_started < window);

        match buckets.get(&client) {
            Some(bucket) if bucket.failures >= self.max_attempts => {
                Err((window - (now - bucket.window_started)).max(1) as u64)
            }
            _ => Ok(()),
        }
    }

    /// Records a failed attempt.
    pub fn record_failure(&self, client: Option<IpAddr>) {
        let Some(client) = client else { return };
        let now = now_secs();
        let window = self.window.as_secs() as i64;

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = buckets.entry(client).or_insert(Bucket {
            failures: 0,
            window_started: now,
        });
        if now - bucket.window_started >= window {
            *bucket = Bucket {
                failures: 0,
                window_started: now,
            };
        }
        bucket.failures += 1;
    }

    /// Clears an address's counter after a successful login, so one operator
    /// fumbling their password does not spend the window for the next.
    pub fn record_success(&self, client: Option<IpAddr>) {
        let Some(client) = client else { return };
        self.buckets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&client);
    }
}

/// Sweeps expired and idle sessions for the life of the process.
///
/// Modelled on `cli::spawn_nonce_reaper`, and needed for the same reason with
/// one difference: sessions **outlive a restart**, so a startup-only sweep
/// would leak every session an operator never explicitly logged out of.
pub fn spawn_session_reaper(
    database: Arc<Database>,
    idle_timeout: Duration,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // A missed tick means the last sweep ran long; running the backlog
        // immediately would just queue more of the same.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick completes immediately; the startup sweep is the
        // caller's, so skip it here rather than sweeping twice.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match AdminSession::cleanup(idle_timeout, &database).await {
                Ok(removed) => {
                    debug!(
                        event = "admin_session_reaper_swept",
                        outcome = "success",
                        rows_removed = removed
                    );
                }
                Err(error) => {
                    error!(event = "admin_session_reaper_failed", outcome = "failure", error = %error);
                }
            }
        }
    })
}

/// Logs a completed login attempt. One place, so the events cannot drift.
pub fn log_login(succeeded: bool, username: &str, client: Option<IpAddr>, reason: &'static str) {
    if succeeded {
        info!(event = "admin_login_succeeded",
              outcome = "success",
              username = %username,
              client_ip = ?client);
    } else {
        warn!(event = "admin_login_failed",
              outcome = "failure",
              username = %username,
              client_ip = ?client,
              reason = reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::admin_session::NewSession;
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

    #[test]
    fn the_limiter_permits_up_to_the_limit_then_refuses() {
        let limiter = LoginLimiter::new(3, 300);

        for attempt in 0..3 {
            assert!(limiter.check(ip(1)).is_ok(), "attempt {attempt} must pass");
            limiter.record_failure(ip(1));
        }

        let retry_after = limiter.check(ip(1)).unwrap_err();
        assert!(retry_after > 0 && retry_after <= 300, "got {retry_after}");

        // Scoped to the address that failed.
        assert!(limiter.check(ip(2)).is_ok());
    }

    #[test]
    fn a_success_clears_the_counter() {
        let limiter = LoginLimiter::new(2, 300);
        limiter.record_failure(ip(1));
        limiter.record_success(ip(1));
        limiter.record_failure(ip(1));
        assert!(
            limiter.check(ip(1)).is_ok(),
            "the pre-success failure must not still count"
        );
    }

    #[test]
    fn the_window_rolls_over_and_prunes() {
        // A one-second window, so the rollover is observable without sleeping
        // on a wall clock the test does not control.
        let limiter = LoginLimiter::new(1, 1);
        limiter.record_failure(ip(1));
        assert!(limiter.check(ip(1)).is_err());

        // Backdate the bucket past the window.
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            buckets.get_mut(&ip(1).unwrap()).unwrap().window_started -= 5;
        }
        assert!(limiter.check(ip(1)).is_ok(), "the window must roll over");
        assert!(
            limiter.buckets.lock().unwrap().is_empty(),
            "a stale bucket must be pruned, or the map grows without bound"
        );
    }

    #[test]
    fn a_missing_client_address_is_not_limited() {
        let limiter = LoginLimiter::new(1, 300);
        limiter.record_failure(None);
        limiter.record_success(None);
        assert!(
            limiter.check(None).is_ok(),
            "failing closed here would lock out every request, not every attacker"
        );
    }

    /// A real short sleep rather than paused time: `tokio`'s `test-util`
    /// feature is not enabled here, and the existing `spawn_nonce_reaper` test
    /// makes the same trade.
    #[tokio::test]
    async fn the_reaper_sweeps_on_its_interval() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let user = AdminUser::create("alice", "hash", &database).await.unwrap();
        AdminSession::create(
            NewSession {
                user_id: &user.id,
                token_hash: "expired",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            Duration::from_secs(1),
            &database,
        )
        .await
        .unwrap();
        // Backdate it past its own deadline.
        sqlx::query("UPDATE admin_sessions SET expires_at = ? WHERE token_hash = 'expired';")
            .bind(now_secs() - 1)
            .execute(&database.pool)
            .await
            .unwrap();

        let handle = spawn_session_reaper(
            database.clone(),
            Duration::from_secs(3_600),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        handle.abort();

        assert!(
            AdminSession::find_by_token_hash("expired", &database)
                .await
                .unwrap()
                .is_none(),
            "the reaper must remove a session past its absolute deadline"
        );
    }

    #[test]
    fn log_login_renders_both_outcomes() {
        // The `tracing` field expressions only execute when something is
        // subscribed; `tests/common` installs a sink, and here the call is
        // simply exercised for its branches.
        log_login(true, "alice", ip(1), "");
        log_login(false, "alice", ip(1), "wrong_password");
        log_login(false, "alice", None, "unknown_user");
    }
}
