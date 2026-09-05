//! The web admin interface: a second HTTP listener, serving no ACME.
//!
//! ## Where this sits
//!
//! `src/cli/` and `src/webadmin/` are the two **front ends**; `src/admin/` is
//! the operation layer both dispatch to and neither owns. A handler here is a
//! few lines over an `admin::ops` call and an `admin::render_*_json`, the same
//! way a `src/cli/` command body is a few lines over the same call and a
//! `render_*_line`.
//!
//! ## Why a second listener
//!
//! The ACME listener is public, unauthenticated and often internet-facing.
//! This one defaults to loopback, requires a session on every route but login,
//! and carries no admission control or filter chain because neither fits it
//! (see `build_admin_app`). Keeping them on one socket would have meant one
//! set of defaults for two very different threat models.

pub mod error;
pub mod handlers;
pub mod pages;
pub mod session;

pub use error::AdminError;
pub use pages::PageError;
pub use session::LoginLimiter;

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::bail;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};

use crate::Profile;
use crate::config::Config;
use crate::middlewares;
use crate::sqlite::db::Database;

/// Shared state for every admin route.
///
/// Not [`crate::AppState`]: that one holds exactly one `Profile`, and this
/// listener is cross-profile by nature — an operator lists accounts from every
/// endpoint at once, and revoking an order needs *that order's own* profile's
/// signer, which may be a different CA from the one the request arrived
/// through.
#[derive(Clone)]
pub struct AdminState {
    pub database: Arc<Database>,
    pub config: Arc<Config>,
    /// Keyed by profile name — the lookup `orders.profile` needs.
    pub profiles: Arc<HashMap<String, Arc<Profile>>>,
    pub logins: Arc<LoginLimiter>,
    /// The `/ui` templates, embedded defaults overlaid by
    /// `admin.template_dir`. Built once: the loader reads a file per template
    /// on first use, and rebuilding it per request would mean a disk read per
    /// page.
    pub templates: Arc<minijinja::Environment<'static>>,
    /// The same process-wide auditor the ACME listener holds. Shared rather
    /// than a second instance: an operator revoking through the panel writes
    /// into the one trail, and the reverse-lookup cache is worth sharing.
    pub audit: Arc<crate::audit::Auditor>,
}

impl AdminState {
    /// Builds the state from what `serve_on` already has in hand.
    ///
    /// Takes a **slice**, not the `Vec`: `build_app` consumes that vec, so the
    /// admin side has to be built first, and expressing it in the signature is
    /// what stops the ordering being rediscovered as a borrow error.
    #[must_use]
    pub fn new(
        database: Arc<Database>,
        config: Arc<Config>,
        profiles: &[Arc<Profile>],
        audit: Arc<crate::audit::Auditor>,
    ) -> Self {
        Self::with_logins(database, config, profiles, audit, None)
    }

    /// [`new`](Self::new), carrying the previous generation's login counters.
    ///
    /// Only a configuration reload passes `Some`: every other caller is building
    /// the first generation, where there is nothing to carry. See
    /// [`LoginLimiter::rebuilt`] for why the counters move but the limits do not.
    #[must_use]
    pub fn with_logins(
        database: Arc<Database>,
        config: Arc<Config>,
        profiles: &[Arc<Profile>],
        audit: Arc<crate::audit::Auditor>,
        previous_logins: Option<&LoginLimiter>,
    ) -> Self {
        let by_name = profiles
            .iter()
            .map(|profile| (profile.name.clone(), profile.clone()))
            .collect();
        let max_attempts = config.admin.login_max_attempts;
        let window = config.admin.login_window_seconds;
        let logins = match previous_logins {
            Some(previous) => previous.rebuilt(max_attempts, window),
            None => LoginLimiter::new(max_attempts, window),
        };
        let templates = pages::templates::build_environment(&config.admin.template_dir);
        Self {
            database,
            config,
            profiles: Arc::new(by_name),
            logins: Arc::new(logins),
            templates: Arc::new(templates),
            audit,
        }
    }
}

/// Builds the whole admin service: `/health`, then the JSON API under `/api`.
///
/// Takes `profiles` as a **slice** so it can be called before `build_app`
/// consumes the `Vec` in `cli::serve_on` — the ordering is a real constraint
/// and the signature is where it is stated.
///
/// ## What this router deliberately does *not* have
///
/// - **No admission control.** `Admission` exists because the ACME surface is
///   public and unauthenticated. This one defaults to loopback and needs a
///   session on every route but login; the real availability concern is
///   credential brute force, which admission control would not touch and the
///   login limiter does.
/// - **No filter chain.** Filters are a per-profile ACME concern, and
///   `filter.exempt_paths` matches profile-stripped paths. Wiring them here
///   would be a category error. Access control on this listener is the bind
///   address, TLS, and the session.
pub fn build_admin_app(
    database: Arc<Database>,
    config: Arc<Config>,
    profiles: &[Arc<Profile>],
    audit: Arc<crate::audit::Auditor>,
) -> Router {
    build_admin_app_with_logins(database, config, profiles, audit, None).0
}

/// [`build_admin_app`], carrying login counters across a configuration reload.
///
/// Returns the limiter it ended up with as well as the router, because the
/// generation after this one has to carry it in turn — an `Arc<LoginLimiter>`
/// that only ever moved forward is the whole point.
pub fn build_admin_app_with_logins(
    database: Arc<Database>,
    config: Arc<Config>,
    profiles: &[Arc<Profile>],
    audit: Arc<crate::audit::Auditor>,
    previous_logins: Option<&LoginLimiter>,
) -> (Router, Arc<LoginLimiter>) {
    let state = AdminState::with_logins(database, config.clone(), profiles, audit, previous_logins);
    let logins = state.logins.clone();

    let api = Router::new()
        .route(
            "/session",
            post(handlers::post_session)
                .get(handlers::get_session)
                .delete(handlers::delete_session),
        )
        // The second half of signing in: reachable only with a `pending_mfa`
        // cookie, which every other route here refuses.
        .route(
            "/session/mfa",
            get(handlers::get_session_mfa).post(handlers::post_session_mfa),
        )
        // The operator's own second factor. Not a server resource like the ones
        // below — it is about whoever is holding this cookie, which is why
        // there is no id in any of these paths.
        .route("/mfa", get(handlers::get_mfa))
        .route(
            "/mfa/totp",
            post(handlers::begin_totp).delete(handlers::disable_totp),
        )
        .route("/mfa/totp/confirm", post(handlers::confirm_totp))
        .route(
            "/mfa/recovery-codes",
            post(handlers::regenerate_recovery_codes),
        )
        .route("/account/password", post(handlers::change_password))
        .route("/account/sessions", get(handlers::list_own_sessions))
        .route(
            "/account/sessions/{id}/revoke",
            post(handlers::revoke_own_session),
        )
        // The operators surface: every operator this process has, and acting
        // on one *other* than the caller — see `handlers::operators`. Every
        // mutating route here sits behind `check_step_up`, unlike the
        // `/account/*` routes just above.
        .route("/operators", get(handlers::list_operators))
        .route("/operators/{username}", get(handlers::get_operator))
        .route(
            "/operators/{username}/sessions",
            get(handlers::list_operator_sessions),
        )
        .route(
            "/operators/{username}/disable",
            post(handlers::disable_operator),
        )
        .route(
            "/operators/{username}/enable",
            post(handlers::enable_operator),
        )
        .route(
            "/operators/{username}/totp/reset",
            post(handlers::reset_operator_totp),
        )
        .route(
            "/operators/{username}/sessions/{id}/revoke",
            post(handlers::revoke_operator_session),
        )
        .route("/accounts", get(handlers::list_accounts))
        .route(
            "/accounts/{id}",
            get(handlers::get_account)
                .patch(handlers::patch_account)
                .delete(handlers::delete_account),
        )
        .route("/accounts/{id}/orders", get(handlers::list_account_orders))
        .route(
            "/accounts/{id}/deactivate",
            post(handlers::deactivate_account),
        )
        .route("/orders", get(handlers::list_orders))
        .route(
            "/orders/{id}",
            get(handlers::get_order).delete(handlers::delete_order),
        )
        .route("/orders/{id}/revoke", post(handlers::revoke_order))
        .route("/eab", get(handlers::list_eab).post(handlers::create_eab))
        .route("/eab/{kid}", get(handlers::get_eab))
        .route("/eab/{kid}/revoke", post(handlers::revoke_eab))
        // Read-only, and therefore absent from `mutating_endpoints()`: there
        // is no route here that writes an audit row, by design. The trail is
        // pruned from the host (`acme-proxy audit cleanup`) or by
        // `audit.retention_days`, never through a browser session — a panel
        // that can delete its own audit history is a panel whose audit history
        // proves nothing.
        .route("/audit", get(handlers::list_audit))
        .route("/audit/{id}", get(handlers::get_audit))
        // Read-only for its own reason rather than the audit trail's: renewing
        // is the *client's* action, driven by its own ACME flow, so there is
        // nothing here for a route to write. Absent from `mutating_endpoints()`
        // accordingly.
        .route("/expiring", get(handlers::list_expiring))
        .route("/nonces", get(handlers::get_nonces))
        .route("/nonces/cleanup", post(handlers::cleanup_nonces))
        .route("/profiles", get(handlers::list_profiles))
        // Read-only for a third reason again: a policy is *configuration*,
        // edited in `config.toml` and reloaded, so there is nothing here for a
        // route to write — hence its absence from `mutating_endpoints()`. Note
        // this is `filter show` and never `filter explain`: the latter runs the
        // operator's scripts and queries the inventory against caller-chosen
        // inputs, and has no web surface at all.
        .route("/profiles/{name}/filter", get(handlers::get_profile_filter));

    let router = Router::new()
        // Unauthenticated and touching no database: an orchestrator probing
        // this port should not need a session to learn the process is alive.
        .route("/health", get(crate::handlers::get_health_check))
        // The panel is what somebody opening this port in a browser wants.
        .route("/", get(|| async { Redirect::to("/ui/") }))
        .merge(api_with_fallbacks(api))
        .merge(pages::pages_router())
        // HTML, because this listener is browser-facing and every path that
        // reaches here is one a person typed. `/api`'s own JSON fallback is
        // scoped inside its nest and is unaffected, so a script still gets the
        // admin error shape on the paths a script uses.
        .fallback(|| async { PageError::not_found("no such page") })
        .with_state(state)
        // Innermost layer: a panic in any page handler (or the `/api` nest, if
        // its own catch layer somehow did not fire) becomes an HTML 500 rather
        // than an aborted connection, and the header layers and the access line
        // above still see a real response. ASVS V16.5.4.
        .layer(catch_panic_admin_pages())
        .layer(DefaultBodyLimit::max(config.admin.max_body_bytes))
        // `no-store` is not decoration: account contacts and a freshly minted
        // EAB secret must not sit in a disk cache after the operator closes
        // the tab.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ))
        // The same three the ACME app applies. This router is not nested
        // inside `build_app` and inherits none of its layers, so they have to
        // be applied again here — but from the one constructor, since two
        // hand-written copies of a security control are a control that drifts.
        .layer(crate::security_headers())
        // Strict, and affordable only because of how the pages are built:
        // htmx is served from this origin (`script-src 'self'`) and drives
        // everything through `hx-*` attributes rather than inline handlers, so
        // no `'unsafe-inline'` and no `'unsafe-eval'` are needed. `style-src
        // 'self'` is why `layout.html` sets htmx's `includeIndicatorStyles` to
        // false -- htmx would otherwise inject a <style> element this refuses.
        // `default-src 'none'` means anything added later has to be allowed
        // deliberately rather than inherited by accident.
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; \
                 img-src 'self' data:; connect-src 'self'; form-action 'self'; \
                 frame-ancestors 'none'; base-uri 'none'",
            ),
        ))
        // Outermost, and the same middleware the ACME listener uses: an admin
        // request gets an `x-request-id` and an access line on identical
        // terms. Its `profile` field stays `field::Empty` and renders as
        // absent, which is correct — an admin request belongs to no profile.
        .layer(middleware::from_fn(
            middlewares::access::add_access_middleware,
        ));

    (router, logins)
}

/// Mounts the API at `/api` with fallbacks that answer in the admin error
/// shape.
///
/// Without these, a typo'd path would fall through to an empty body — the same
/// reasoning the profile routers already encode, except that there the fallback
/// has to be an ACME problem document and here it must not be.
fn api_with_fallbacks(api: Router<AdminState>) -> Router<AdminState> {
    Router::new().nest(
        "/api",
        api.method_not_allowed_fallback(|| async {
            AdminError::with_code(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "that method is not allowed on this resource",
            )
        })
        .fallback(|| async { AdminError::not_found("no such admin API resource") })
        // A panic below here answers a script in the JSON admin error shape,
        // not the HTML page the outer router's own catch layer produces —
        // the same split `AdminError` and `PageError` exist for. ASVS V16.5.4.
        .layer(catch_panic_admin_api()),
    )
}

/// The response a caught panic produces on the admin **API** surface: the JSON
/// `{"error":"internal", ...}` shape a script gets everywhere else on `/api`,
/// never the HTML document a browser gets. The panic message goes to the log
/// only (ASVS V16.5.1). Relies on `panic = "unwind"`.
fn admin_api_panic_response(err: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!(
        event = "request_handler_panicked",
        outcome = "failure",
        listener = "admin",
        surface = "api",
        error = %crate::panic_message(err.as_ref()),
    );
    AdminError::internal().into_response()
}

/// The response a caught panic produces on every other admin surface (`/ui`,
/// `/`, the HTML fallback): a standalone HTML error document, matching the outer
/// router's own `.fallback()`. The panic message goes to the log only.
fn admin_page_panic_response(err: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!(
        event = "request_handler_panicked",
        outcome = "failure",
        listener = "admin",
        surface = "page",
        error = %crate::panic_message(err.as_ref()),
    );
    PageError::internal().into_response()
}

/// The last-resort panic layer for the admin `/api` nest — see
/// [`admin_api_panic_response`].
pub fn catch_panic_admin_api() -> CatchPanicLayer<fn(Box<dyn Any + Send + 'static>) -> Response> {
    CatchPanicLayer::custom(
        admin_api_panic_response as fn(Box<dyn Any + Send + 'static>) -> Response,
    )
}

/// The last-resort panic layer for the admin pages and the HTML fallback — see
/// [`admin_page_panic_response`]. `pub` on the same terms as [`build_admin_app`].
pub fn catch_panic_admin_pages() -> CatchPanicLayer<fn(Box<dyn Any + Send + 'static>) -> Response> {
    CatchPanicLayer::custom(
        admin_page_panic_response as fn(Box<dyn Any + Send + 'static>) -> Response,
    )
}

/// Rejects an `[admin]` section that cannot work, before anything binds.
///
/// Runs only when the panel is enabled: an operator who has not turned it on
/// must never be stopped from starting by a section they never edited.
pub fn check_config(config: &Config) -> anyhow::Result<()> {
    let admin = &config.admin;
    if !admin.enabled {
        return Ok(());
    }

    if admin.bind_address == config.server.bind_address {
        bail!(
            "admin.bind_address and server.bind_address are both `{}`: the web admin is a \
             second listener on its own socket, not a path on the ACME one",
            admin.bind_address
        );
    }

    let url = url::Url::parse(&admin.base_url).map_err(|error| {
        anyhow::anyhow!("admin.base_url `{}` is not a URL: {error}", admin.base_url)
    })?;
    if url.host_str().is_none_or(str::is_empty) {
        bail!(
            "admin.base_url `{}` has no host: it names the origin the panel is reached at, \
             and a generated certificate takes its name from it",
            admin.base_url
        );
    }

    // A hard error, not a warning, and the reasoning is worth keeping: the
    // session cookie is always sent `Secure` (never conditionally -- that is
    // how a session cookie leaks). Browsers accept a `Secure` cookie on
    // `http://localhost` and silently refuse it on `http://192.0.2.10:3001`.
    // The operator would see "login succeeds, then I am immediately logged
    // out" with nothing in any log to explain it. Refuse, and name both keys.
    // Same reasoning as `filter.allowed_ip` with two empty lists being a
    // startup error rather than an accept-everything default.
    if !admin.tls.enabled && !binds_loopback_only(&admin.bind_address) {
        bail!(
            "admin.bind_address `{}` is not loopback while admin.tls.enabled is false: the \
             session cookie is sent `Secure`, which a browser will not store over plain HTTP \
             on anything but localhost, so signing in would appear to succeed and then fail \
             silently. Set admin.tls.enabled = true, or bind 127.0.0.1 and reach it through \
             an SSH tunnel",
            admin.bind_address
        );
    }

    // The `tls_base_url_mismatch` treatment: a warning, because the reverse
    // proxy case (https:// in the URL, TLS terminated in front) is legitimate.
    if admin.tls.enabled && url.scheme() == "http" {
        warn!(event = "admin_base_url_mismatch",
              outcome = "advisory",
              base_url = %admin.base_url,
              "admin.base_url names http:// while admin.tls.enabled is true: the CSRF origin \
               check compares against it, so browser requests will be refused until it names \
               https://");
    }

    // `admin.base_url` is load-bearing in three unrelated ways -- the CSRF
    // origin check, the generated certificate's name, and later the WebAuthn
    // relying-party id -- and is easy to leave at its default while binding
    // somewhere else. Logging the resolved origin makes the mismatch visible
    // at startup rather than at the first refused request.
    info!(event = "admin_origin_resolved",
          outcome = "success",
          origin = %url.origin().ascii_serialization(),
          bind_address = %admin.bind_address);

    check_templates(&admin.template_dir)?;

    Ok(())
}

/// Compiles every page template, so a broken override stops the process here
/// rather than serving a `500` at three in the morning.
///
/// The same posture as the rest of startup: a path that can fail fast should.
/// The cost is one compile of ~20 small templates, once.
fn check_templates(template_dir: &str) -> anyhow::Result<()> {
    if !template_dir.is_empty() {
        let path = std::path::Path::new(template_dir);
        if !path.is_dir() {
            bail!(
                "admin.template_dir `{template_dir}` is not a directory: it holds per-file \
                 overrides of the compiled-in page templates, checked by name before the \
                 default. Leave it empty to use the defaults"
            );
        }
    }

    let env = pages::templates::build_environment(template_dir);
    for name in pages::templates::template_names() {
        env.get_template(name).map_err(|error| {
            anyhow::anyhow!(
                "admin page template `{name}` does not compile: {error}. \
                 It was loaded from admin.template_dir `{template_dir}`"
            )
        })?;
    }

    if !template_dir.is_empty() {
        info!(event = "admin_templates_overridden", outcome = "success", template_dir = %template_dir);
    }

    Ok(())
}

/// Whether every address `bind` can accept on is a loopback address.
///
/// Deliberately conservative: an address that does not parse, or a hostname
/// this does not resolve, counts as *not* loopback. Being wrong in that
/// direction costs an operator one explicit `admin.tls.enabled = true`; being
/// wrong in the other silently ships a panel whose login does not work.
fn binds_loopback_only(bind: &str) -> bool {
    let Ok(addr) = bind.parse::<std::net::SocketAddr>() else {
        // Not a bare socket address -- e.g. `localhost:3001`, which the
        // listener resolves later. Accept the two spellings that can only
        // ever be loopback, and refuse everything else.
        return matches!(
            bind.rsplit_once(':').map(|(host, _)| host),
            Some("localhost" | "ip6-localhost")
        );
    };
    addr.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AdminConfig, Config};

    /// `[admin]` enabled, with everything else at its default.
    ///
    /// Built by mutation rather than struct-update syntax: `Config` keeps a
    /// private `raw` field, so `..Config::default()` is not available outside
    /// `crate::config`.
    fn enabled() -> Config {
        let mut config = Config::default();
        config.admin = AdminConfig {
            enabled: true,
            ..AdminConfig::default()
        };
        config
    }

    #[test]
    fn a_disabled_panel_is_never_checked() {
        // Every one of these would be refused if the panel were on.
        let mut config = Config::default();
        config.admin = AdminConfig {
            enabled: false,
            bind_address: "0.0.0.0:3001".to_string(),
            base_url: "not a url".to_string(),
            ..AdminConfig::default()
        };
        assert!(check_config(&config).is_ok());
    }

    #[test]
    fn the_defaults_are_a_working_configuration() {
        check_config(&enabled()).expect("loopback + the default base_url must start");
    }

    /// The compiled-in templates are checked on every start, so a page that
    /// stopped compiling fails the build's own test suite rather than the first
    /// operator to open it.
    #[test]
    fn the_embedded_templates_all_compile_at_startup() {
        check_templates("").expect("the shipped templates must compile");
    }

    #[test]
    fn a_template_dir_that_is_not_a_directory_is_refused() {
        let dir = crate::testutil::TempDir::new("admin-template-dir");
        let file = dir.write("not-a-directory", "");

        let error = check_templates(file.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("is not a directory"));
    }

    /// A broken override should stop the process, not serve a `500` at three in
    /// the morning — the same fail-fast posture as the rest of startup.
    #[test]
    fn an_override_that_does_not_compile_is_refused_at_startup() {
        let dir = crate::testutil::TempDir::new("admin-bad-template");
        dir.write("index.html", "{% for x in %}");

        let error = check_templates(dir.path().to_str().unwrap()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("index.html"));
        assert!(message.contains("does not compile"));
    }

    #[test]
    fn a_valid_override_directory_starts() {
        let dir = crate::testutil::TempDir::new("admin-good-template");
        dir.write("login.html", "<p>{{ flash }}</p>");

        check_templates(dir.path().to_str().unwrap())
            .expect("one overridden template must not stop the other twenty");
    }

    #[test]
    fn a_bind_shared_with_the_acme_listener_is_refused() {
        let mut config = enabled();
        config.admin.bind_address = config.server.bind_address.clone();
        let error = check_config(&config).unwrap_err().to_string();
        assert!(error.contains("second listener"), "got: {error}");
        assert!(error.contains(&config.server.bind_address));
    }

    #[test]
    fn a_base_url_that_is_not_a_url_or_has_no_host_is_refused() {
        let mut config = enabled();
        config.admin.base_url = "not a url".to_string();
        assert!(
            check_config(&config)
                .unwrap_err()
                .to_string()
                .contains("is not a URL")
        );

        // Parses, but names no host.
        config.admin.base_url = "unix:/run/admin.sock".to_string();
        let error = check_config(&config).unwrap_err().to_string();
        assert!(error.contains("has no host"), "got: {error}");
    }

    #[test]
    fn a_non_loopback_bind_without_tls_is_a_startup_error_not_a_warning() {
        for bind in [
            "0.0.0.0:3001",
            "192.0.2.10:3001",
            "[::]:3001",
            "[2001:db8::1]:3001",
        ] {
            let mut config = enabled();
            config.admin.bind_address = bind.to_string();
            let error = check_config(&config).unwrap_err().to_string();
            assert!(
                error.contains("is not loopback"),
                "`{bind}` must be refused without TLS, got: {error}"
            );
        }
    }

    #[test]
    fn a_non_loopback_bind_is_allowed_once_tls_is_on() {
        let mut config = enabled();
        config.admin.bind_address = "0.0.0.0:3001".to_string();
        config.admin.tls.enabled = true;
        config.admin.base_url = "https://admin.example.com".to_string();
        check_config(&config).expect("TLS is what the loopback rule was standing in for");
    }

    #[test]
    fn every_loopback_spelling_is_accepted_without_tls() {
        for bind in [
            "127.0.0.1:3001",
            "127.0.0.53:3001",
            "[::1]:3001",
            "localhost:3001",
        ] {
            let mut config = enabled();
            config.admin.bind_address = bind.to_string();
            check_config(&config).unwrap_or_else(|error| panic!("`{bind}` must start: {error}"));
        }
    }

    #[test]
    fn an_unparseable_bind_is_treated_as_non_loopback() {
        // Conservative on purpose: the cost of being wrong this way is one
        // explicit config key, the other way is a panel nobody can log in to.
        let mut config = enabled();
        config.admin.bind_address = "not-a-socket-address".to_string();
        assert!(
            check_config(&config)
                .unwrap_err()
                .to_string()
                .contains("is not loopback")
        );
    }

    #[test]
    fn tls_with_an_http_base_url_warns_but_starts() {
        let mut config = enabled();
        config.admin.tls.enabled = true;
        // Still http://, which the CSRF origin check will compare against.
        check_config(&config).expect("a scheme mismatch is a warning, not a refusal");
    }

    mod catch_panic {
        use super::*;
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        async fn boom() -> &'static str {
            panic!("this handler panics on purpose")
        }

        /// An `/api` panic keeps the JSON admin error shape a script gets
        /// everywhere else — never the HTML document, never an ACME URN.
        #[tokio::test]
        async fn an_api_panic_is_the_json_admin_error() {
            let response = admin_api_panic_response(Box::new("secret internal detail"));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json"),
            );
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"], "internal");
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(!text.contains("urn:ietf:params:acme"));
            assert!(
                !text.contains("secret internal detail"),
                "the panic message must not reach the client",
            );
        }

        /// A page panic is a standalone HTML document, matching the outer
        /// router's own `.fallback()`.
        #[tokio::test]
        async fn a_page_panic_is_an_html_document() {
            let response = admin_page_panic_response(Box::new(String::from("boom")));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(text.starts_with("<!doctype html>"), "got: {text}");
            assert!(text.contains("internal"));
        }

        #[tokio::test]
        async fn each_layer_catches_a_panicking_route() {
            for layer_name in ["api", "pages"] {
                let router: Router = if layer_name == "api" {
                    Router::new()
                        .route("/boom", get(boom))
                        .layer(catch_panic_admin_api())
                } else {
                    Router::new()
                        .route("/boom", get(boom))
                        .layer(catch_panic_admin_pages())
                };
                let response = router
                    .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the {layer_name} layer must catch the panic",
                );
            }
        }
    }
}
