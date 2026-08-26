//! The web admin's JSON API, driven through the real `build_admin_app`.
//!
//! Every case enters through the router, so the extractors, the layers and the
//! error shape are all exercised together — the same way `tests/orders.rs`
//! drives the ACME side.

mod common;

use acme_proxy::admin::password::PasswordContext;
use acme_proxy::audit::{Actor, AuditEvent, AuditRecord, ClientContext};
use acme_proxy::sqlite::admin_session::AdminSession;
use acme_proxy::sqlite::audit::AuditEntry;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_sets_a_hardened_cookie_and_returns_a_csrf_token() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // The cookie attributes, asserted one by one: each is load-bearing and a
    // future edit dropping any of them must fail here rather than in the wild.
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("__Host-acme_admin_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Path=/"));
    assert!(!set_cookie.contains("Domain"));

    let body = json_body(response).await;
    assert_eq!(body["user"]["username"], "alice");
    assert!(body["csrfToken"].as_str().is_some_and(|t| t.len() > 20));
    assert!(body["expiresAt"].as_str().is_some());
    // The response must never echo anything derived from the password.
    assert!(!body.to_string().contains("pbkdf2"));
}

#[tokio::test]
async fn every_login_failure_is_indistinguishable_to_the_client() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    acme_proxy::admin::users::create_user(
        "bob",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    acme_proxy::admin::users::set_status("bob", "disabled", database)
        .await
        .unwrap();

    let mut bodies = Vec::new();
    for (username, password) in [
        ("alice", "the-wrong-password"),
        ("nobody-at-all", ADMIN_PASSWORD),
        ("bob", ADMIN_PASSWORD),
    ] {
        let response = admin_request(
            &app,
            Method::POST,
            "/api/session",
            None,
            Some(json!({ "username": username, "password": password })),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "for {username}"
        );
        assert!(
            session_cookie_token(&response).is_none(),
            "a failed login must not set a session cookie"
        );
        bodies.push(json_body(response).await);
    }

    // Wrong password, unknown user and disabled account: one answer.
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[1], bodies[2]);
    assert_eq!(bodies[0]["error"], "invalid_credentials");
}

#[tokio::test]
async fn login_is_rate_limited_before_the_password_hash_runs() {
    let mut config = admin_config();
    config.admin.login_max_attempts = 2;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let attempt = |password: &'static str| {
        let app = app.clone();
        async move {
            admin_request(
                &app,
                Method::POST,
                "/api/session",
                None,
                Some(json!({ "username": "alice", "password": password })),
            )
            .await
        }
    };

    for _ in 0..2 {
        assert_eq!(attempt("wrong").await.status(), StatusCode::UNAUTHORIZED);
    }

    let limited = attempt("wrong").await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(json_body(limited).await["error"], "rate_limited");

    // Even the *correct* password is refused while the window holds: the
    // limiter is what stops the expensive hash running at all.
    assert_eq!(
        attempt(ADMIN_PASSWORD).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// Two sign-ins from two browsers are two independent sessions. Signing in on
/// a second machine must not log you out on the first.
#[tokio::test]
async fn a_second_login_without_a_cookie_is_a_second_independent_session() {
    let (app, _database, first) = test_admin_app_logged_in(admin_config()).await;
    let second = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    assert_ne!(
        first.cookie, second.cookie,
        "each login mints its own token"
    );
    assert_ne!(first.csrf, second.csrf, "and its own CSRF token");
    for session in [&first, &second] {
        assert_eq!(
            admin_request(&app, Method::GET, "/api/session", Some(session), None)
                .await
                .status(),
            StatusCode::OK
        );
    }
}

/// Session fixation: a login that *carries* a session replaces it, so a cookie
/// planted in the victim's browser before they sign in is dead afterwards
/// rather than promoted to an authenticated one.
#[tokio::test]
async fn logging_in_with_a_cookie_already_set_destroys_that_session() {
    let (app, _database, planted) = test_admin_app_logged_in(admin_config()).await;

    // Log in again, this time presenting the existing cookie.
    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        Some(&planted),
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let fresh_cookie = session_cookie_token(&response).expect("a new cookie must be set");
    assert_ne!(fresh_cookie, planted.cookie, "the token must rotate");

    // The presented session is gone.
    let refused = admin_request(&app, Method::GET, "/api/session", Some(&planted), None).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(refused).await["error"], "session_invalid");
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_needs_a_session_and_reports_the_operator() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let anonymous = admin_request(&app, Method::GET, "/api/session", None, None).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(anonymous).await["error"], "session_invalid");

    let body =
        json_body(admin_request(&app, Method::GET, "/api/session", Some(&session), None).await)
            .await;
    assert_eq!(body["user"]["username"], "alice");
    assert_eq!(body["csrfToken"], session.csrf);
}

#[tokio::test]
async fn logout_clears_the_cookie_and_the_session_stops_working() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_request(&app, Method::DELETE, "/api/session", Some(&session), None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("Max-Age=0"));

    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&session), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_session_deleted_out_from_under_the_request_stops_authenticating() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let user = acme_proxy::sqlite::admin_user::AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    acme_proxy::sqlite::admin_session::AdminSession::delete_for_user(user.id, &database)
        .await
        .unwrap();

    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&session), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_expired_session_is_refused_and_swept() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let hash = acme_proxy::webadmin::session::hash_token(&session.cookie);
    sqlx::query("UPDATE admin_sessions SET expires_at = 1 WHERE token_hash = ?;")
        .bind(&hash)
        .execute(&database.pool)
        .await
        .unwrap();

    let response = admin_request(&app, Method::GET, "/api/session", Some(&session), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["error"], "session_expired");

    // Refusing it also removed it, rather than leaving a dead row behind.
    assert!(
        acme_proxy::sqlite::admin_session::AdminSession::find_by_token_hash(&hash, &database)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_idle_session_is_refused_with_its_own_code() {
    let mut config = admin_config();
    config.admin.session_idle_timeout_seconds = 60;
    let (app, database, session) = test_admin_app_logged_in(config).await;

    let hash = acme_proxy::webadmin::session::hash_token(&session.cookie);
    sqlx::query(
        "UPDATE admin_sessions SET last_seen_at = last_seen_at - 600 WHERE token_hash = ?;",
    )
    .bind(&hash)
    .execute(&database.pool)
    .await
    .unwrap();

    let response = admin_request(&app, Method::GET, "/api/session", Some(&session), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["error"], "session_idle");
}

#[tokio::test]
async fn disabling_an_operator_stops_their_live_session() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&session), None)
            .await
            .status(),
        StatusCode::OK
    );

    acme_proxy::admin::users::set_status("alice", "disabled", database)
        .await
        .unwrap();
    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&session), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

// ---------------------------------------------------------------------------
// Second factor
// ---------------------------------------------------------------------------

/// The guard on every other admin test in this repository.
///
/// `test_admin_app_logged_in` and `admin_login` are the choke point ~40 cases go
/// through, and adding a second login step must not have moved what an operator
/// with no factor sees. Deliberately first in this section.
#[tokio::test]
async fn a_factorless_login_is_completely_unchanged() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let cookie = session_cookie_token(&response).expect("login must set the session cookie");
    let body = json_body(response).await;
    assert_eq!(body["user"]["username"], "alice");
    assert!(body["csrfToken"].as_str().is_some());
    assert!(
        body.get("mfaRequired").is_none(),
        "an operator with no factor must see the pre-MFA response shape: {body}"
    );

    // And the cookie works immediately, with no second step.
    let session = AdminSessionHandle {
        cookie,
        csrf: body["csrfToken"].as_str().unwrap().to_string(),
    };
    assert_eq!(
        admin_request(&app, Method::GET, "/api/accounts", Some(&session), None)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_factor_bearing_login_stops_half_way_and_says_so() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database, "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    // The pending body carries no operator metadata: a half-authenticated
    // session must not read who it belongs to.
    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    let body = json_body(response).await;
    assert_eq!(body["mfaRequired"], true);
    assert_eq!(body["step"], "verify");
    assert!(
        body.get("user").is_none(),
        "a pending session must not read operator metadata: {body}"
    );

    // And the cookie opens nothing.
    for path in ["/api/session", "/api/accounts", "/api/orders", "/api/eab"] {
        assert_eq!(
            admin_request(&app, Method::GET, path, Some(&pending), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "{path} must refuse a half-authenticated session"
        );
    }

    // The one route it does open says what it owes.
    let step = admin_request(&app, Method::GET, "/api/session/mfa", Some(&pending), None).await;
    assert_eq!(step.status(), StatusCode::OK);
    assert_eq!(json_body(step).await["step"], "verify");
}

#[tokio::test]
async fn a_valid_code_promotes_the_session_onto_a_brand_new_token() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;
    sqlx::query("UPDATE admin_users SET totp_last_step = NULL WHERE username = 'alice';")
        .execute(&database.pool)
        .await
        .unwrap();

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle {
        cookie: cookie.clone(),
        csrf,
    };

    let response = admin_request(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&pending),
        Some(json!({ "code": totp_code(&secret, 0) })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let promoted = session_cookie_token(&response).expect("promotion must set a new cookie");
    assert_ne!(
        promoted, cookie,
        "the pending token crossed the wire before authentication finished; \
         its privilege level changing means its value changes"
    );

    let body = json_body(response).await;
    assert_eq!(body["user"]["username"], "alice");
    let active = AdminSessionHandle {
        cookie: promoted,
        csrf: body["csrfToken"].as_str().unwrap().to_string(),
    };
    assert_ne!(active.csrf, pending.csrf, "the CSRF token rotates with it");

    // The new token works everywhere; the old one nowhere.
    assert_eq!(
        admin_request(&app, Method::GET, "/api/accounts", Some(&active), None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&pending), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// RFC 6238 §5.2. A code observed in flight must not be replayable inside its
/// own thirty-second window.
///
/// Accept-then-replay rather than "the enrolment code is already spent", which
/// would be the same assertion in a form that loses whenever the two requests
/// straddle a step boundary. This shape is correct either way: cross one
/// boundary and the code is still in the ±1 window but the guard refuses it;
/// cross two and it falls out of the window. Both answer `401`.
#[tokio::test]
async fn a_code_cannot_be_spent_twice() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;

    sqlx::query("UPDATE admin_users SET totp_last_step = NULL WHERE username = 'alice';")
        .execute(&database.pool)
        .await
        .unwrap();

    let code = totp_code(&secret, 0);

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let first = AdminSessionHandle { cookie, csrf };
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&first),
            Some(json!({ "code": code.clone() })),
        )
        .await
        .status(),
        StatusCode::OK
    );

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let second = AdminSessionHandle { cookie, csrf };
    let replayed = admin_request(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&second),
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(replayed).await["error"], "invalid_credentials");
}

/// A wrong code, a spent recovery code and a replayed one are one refusal to
/// the client — byte-identical to a wrong password, exactly as the three
/// password failures already are.
#[tokio::test]
async fn a_wrong_code_is_indistinguishable_from_a_wrong_password() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database, "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    let wrong_password = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": "not-the-password" })),
    )
    .await;
    let password_status = wrong_password.status();
    let password_body = json_body(wrong_password).await;

    for code in ["000000", "12345", "abcdef", "ZZZZZZZZZZ"] {
        let response = admin_request(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&pending),
            Some(json!({ "code": code })),
        )
        .await;
        assert_eq!(response.status(), password_status, "code {code:?}");
        assert_eq!(json_body(response).await, password_body, "code {code:?}");
    }
}

/// The limiter's second call site. Without it, an attacker holding a correct
/// password would guess six-digit codes without limit.
///
/// Spread across **two** pending sessions on purpose. The per-session cap
/// (`the_code_step_is_bounded_per_session_and_not_only_per_address`) would
/// otherwise fire at the same count and destroy the row, so the response would
/// be a `401` for a missing session rather than the `429` this test is about.
/// Two sessions of two and one failure make three against the address while
/// leaving each session's own counter under the cap.
#[tokio::test]
async fn the_code_step_shares_the_login_limiter() {
    let mut config = admin_config();
    config.admin.login_max_attempts = 3;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database, "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let first = AdminSessionHandle { cookie, csrf };
    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let second = AdminSessionHandle { cookie, csrf };

    for pending in [&first, &first, &second] {
        assert_eq!(
            admin_request(
                &app,
                Method::POST,
                "/api/session/mfa",
                Some(pending),
                Some(json!({ "code": "000000" })),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // Over the limit, and a *correct* code on a session with attempts to spare
    // is refused too: the budget is per address, not per guess.
    let refused = admin_request(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&second),
        Some(json!({ "code": totp_code(&secret, 1) })),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.headers().contains_key(header::RETRY_AFTER));

    // One address, one budget: the password step is locked out as well.
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/session",
            None,
            Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// The bound the address-keyed limiter cannot provide.
///
/// A `pending_mfa` cookie is valid from any address by design — `created_ip` is
/// forensics, never compared — so an attacker holding a correct password could
/// otherwise mint one pending session and spend `login_max_attempts` guesses
/// per source address, of which a single IPv6 /64 supplies 2^64. The counter
/// lives on the session row, so rotating addresses buys nothing, and past the
/// cap the row is **deleted**: getting back to a pending session means
/// producing the password again, which `sign_in`'s limiter bounds.
#[tokio::test]
async fn the_code_step_is_bounded_per_session_and_not_only_per_address() {
    let mut config = admin_config();
    config.admin.login_max_attempts = 3;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };
    let token_hash = acme_proxy::webadmin::session::hash_token(&pending.cookie);

    // Each guess arrives from a *different* address, so the address-keyed
    // limiter never accumulates anything. Only the session counter does.
    for attempt in 0..3 {
        let response = admin_request_from(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&pending),
            Some(json!({ "code": "000000" })),
            &format!("203.0.113.{}:40000", attempt + 1),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} must be a plain refusal, never a rate-limit"
        );
    }

    assert!(
        AdminSession::find_by_token_hash(&token_hash, &database)
            .await
            .unwrap()
            .is_none(),
        "past the cap the half-authenticated row is gone, not merely refused"
    );

    // And a correct code from a fourth fresh address gets nowhere: there is no
    // session left to finish, and the answer says only that.
    let response = admin_request_from(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&pending),
        Some(json!({ "code": totp_code(&secret, 1) })),
        "203.0.113.9:40000",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The password step must **not** clear the limiter bucket. If it did, an
/// attacker with a correct password would reset their own budget on every
/// attempt.
#[tokio::test]
async fn the_password_step_does_not_clear_the_limiter_while_a_factor_is_outstanding() {
    let mut config = admin_config();
    config.admin.login_max_attempts = 3;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database, "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    for _ in 0..3 {
        admin_request(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&pending),
            Some(json!({ "code": "000000" })),
        )
        .await;

        // Re-authenticating with the correct password between guesses must not
        // buy another three tries.
        admin_request(
            &app,
            Method::POST,
            "/api/session",
            None,
            Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
        )
        .await;
    }

    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/session",
            None,
            Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// `last_login_at` means "completed a login", not "typed the right password".
#[tokio::test]
async fn last_login_is_stamped_at_promotion_not_at_the_password() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;
    sqlx::query("UPDATE admin_users SET totp_last_step = NULL WHERE username = 'alice';")
        .execute(&database.pool)
        .await
        .unwrap();

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    let halfway = acme_proxy::sqlite::admin_user::AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    assert!(
        halfway.last_login_at.is_none(),
        "a password accepted is not a login completed"
    );

    admin_request(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&pending),
        Some(json!({ "code": totp_code(&secret, 0) })),
    )
    .await;

    let after = acme_proxy::sqlite::admin_user::AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    assert!(after.last_login_at.is_some());
}

/// A recovery code finishes a login just as a TOTP code does, once.
#[tokio::test]
async fn a_recovery_code_finishes_a_login_and_is_then_spent() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database.clone(), "alice").await;

    let user = acme_proxy::sqlite::admin_user::AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    let codes = acme_proxy::admin::mfa::regenerate_recovery_codes(&user, database.clone())
        .await
        .unwrap();

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };
    let response = admin_request(
        &app,
        Method::POST,
        "/api/session/mfa",
        Some(&pending),
        Some(json!({ "code": codes[0].clone() })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        acme_proxy::admin::mfa::recovery_codes_remaining(user.id, database.clone())
            .await
            .unwrap(),
        9
    );

    // Single-use: the same code again is worth nothing.
    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let second = AdminSessionHandle { cookie, csrf };
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&second),
            Some(json!({ "code": codes[0].clone() })),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        acme_proxy::admin::mfa::recovery_codes_remaining(user.id, database)
            .await
            .unwrap(),
        9
    );
}

#[tokio::test]
async fn enrolment_shows_the_secret_once_and_the_codes_once() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let status =
        json_body(admin_request(&app, Method::GET, "/api/mfa", Some(&session), None).await).await;
    assert_eq!(status["totpEnabled"], false);
    assert_eq!(status["enrolmentPending"], false);
    assert_eq!(status["recoveryCodesRemaining"], 0);

    let begun = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(begun.status(), StatusCode::CREATED);
    let enrolment = json_body(begun).await;
    let secret_base32 = enrolment["secret"].as_str().unwrap().to_string();
    assert_eq!(secret_base32.len(), 32);
    assert!(!secret_base32.contains('='));
    assert!(
        enrolment["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/acme-proxy:alice@")
    );
    assert_eq!(enrolment["algorithm"], "SHA1");
    assert_eq!(enrolment["digits"], 6);
    assert_eq!(enrolment["period"], 30);

    // Pending is not enrolled, and the secret is not readable again.
    let status =
        json_body(admin_request(&app, Method::GET, "/api/mfa", Some(&session), None).await).await;
    assert_eq!(status["totpEnabled"], false);
    assert_eq!(status["enrolmentPending"], true);
    assert!(
        !status.to_string().contains(&secret_base32),
        "the secret is shown exactly once: {status}"
    );

    // A wrong code confirms nothing.
    let refused = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp/confirm",
        Some(&session),
        Some(json!({ "code": "000000" })),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let secret = base32_decode(&secret_base32);
    let confirmed = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp/confirm",
        Some(&session),
        Some(json!({ "code": totp_code(&secret, 0) })),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert!(
        session_cookie_token(&confirmed).is_none(),
        "an already-active session has nothing to promote"
    );

    let body = json_body(confirmed).await;
    let codes = body["recoveryCodes"].as_array().unwrap().clone();
    assert_eq!(codes.len(), 10);

    let status =
        json_body(admin_request(&app, Method::GET, "/api/mfa", Some(&session), None).await).await;
    assert_eq!(status["totpEnabled"], true);
    assert_eq!(status["enrolmentPending"], false);
    assert_eq!(status["recoveryCodesRemaining"], 10);
    for code in &codes {
        assert!(
            !status.to_string().contains(code.as_str().unwrap()),
            "recovery codes are shown exactly once"
        );
    }
}

/// The step-up password is bounded by the same budget sign-in is, and by the
/// *same bucket* — so guessing it cannot buy a second budget.
///
/// The third call site of the login limiter, after the password step and the
/// code step. Until it ran here, somebody holding a stolen cookie could
/// brute-force the account password at unlimited rate, and a correct guess
/// converts that cookie into a factor takeover: enrol their own authenticator,
/// revoke every other session, void the recovery codes.
#[tokio::test]
async fn a_step_up_password_is_rate_limited_and_shares_the_sign_in_budget() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;
    let session = admin_login_mfa(&app, database, "alice", ADMIN_PASSWORD, &secret).await;

    // A distinct address, so the bucket under test is not the one `admin_login`
    // already touched.
    let peer = "203.0.113.9:1234";
    for _ in 0..5 {
        let refused = admin_request_from(
            &app,
            Method::POST,
            "/api/mfa/totp",
            Some(&session),
            Some(json!({ "password": "not the password" })),
            peer,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(refused).await["error"], "invalid_credentials");
    }

    // Past the budget the **correct** password is refused too — which is what
    // proves the limiter runs ahead of the KDF rather than behind it.
    let limited = admin_request_from(
        &app,
        Method::POST,
        "/api/mfa/totp",
        Some(&session),
        Some(json!({ "password": ADMIN_PASSWORD })),
        peer,
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key("retry-after"));

    // And the bucket is shared with sign-in: a second budget here would hand an
    // attacker twice the guesses against one password.
    let login = send_from(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/api/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "username": "alice", "password": ADMIN_PASSWORD }).to_string(),
            ))
            .unwrap(),
        peer,
    )
    .await;
    assert_eq!(login.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn recovery_codes_can_be_reissued_and_supersede_the_previous_set() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();

    // No factor: there is nothing for the codes to recover access to.
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;
    let refused = admin_request(
        &app,
        Method::POST,
        "/api/mfa/recovery-codes",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(refused).await["error"], "mfa_not_enabled");

    let secret = enrol_totp(database.clone(), "alice").await;
    let session = admin_login_mfa(&app, database, "alice", ADMIN_PASSWORD, &secret).await;

    let first = json_body(
        admin_request(
            &app,
            Method::POST,
            "/api/mfa/recovery-codes",
            Some(&session),
            Some(json!({ "password": ADMIN_PASSWORD })),
        )
        .await,
    )
    .await;
    let second = json_body(
        admin_request(
            &app,
            Method::POST,
            "/api/mfa/recovery-codes",
            Some(&session),
            Some(json!({ "password": ADMIN_PASSWORD })),
        )
        .await,
    )
    .await;
    assert_ne!(first["recoveryCodes"], second["recoveryCodes"]);

    // A code from the superseded set no longer finishes a login.
    let stale = first["recoveryCodes"][0].as_str().unwrap().to_string();
    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/session/mfa",
            Some(&pending),
            Some(json!({ "code": stale })),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// `require_mfa` forces enrolment rather than refusing the login — which is
/// what stops it bricking the panel, since enrolling needs a session.
#[tokio::test]
async fn require_mfa_makes_a_factorless_operator_enrol_before_the_session_works() {
    let mut config = admin_config();
    config.admin.require_mfa = true;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    let step =
        json_body(admin_request(&app, Method::GET, "/api/session/mfa", Some(&pending), None).await)
            .await;
    assert_eq!(step["step"], "enrol");

    // Ordinary routes are still shut.
    assert_eq!(
        admin_request(&app, Method::GET, "/api/accounts", Some(&pending), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // But the enrolment routes are open, and finishing enrolment finishes the
    // login: the answer carries a rotated cookie.
    let begun = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp",
        Some(&pending),
        Some(json!({})),
    )
    .await;
    assert_eq!(begun.status(), StatusCode::CREATED);
    let secret = base32_decode(json_body(begun).await["secret"].as_str().unwrap());

    let confirmed = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp/confirm",
        Some(&pending),
        Some(json!({ "code": totp_code(&secret, 0) })),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let promoted = session_cookie_token(&confirmed)
        .expect("finishing enrolment finishes the login, so the token rotates");
    assert_ne!(promoted, pending.cookie);

    let body = json_body(confirmed).await;
    assert_eq!(body["recoveryCodes"].as_array().unwrap().len(), 10);

    // The rotated cookie is a full session: a read works, and it carries the
    // CSRF token every write from here on needs.
    let active = AdminSessionHandle {
        cookie: promoted,
        csrf: String::new(),
    };
    let whoami = admin_request(&app, Method::GET, "/api/session", Some(&active), None).await;
    assert_eq!(whoami.status(), StatusCode::OK);
    let whoami = json_body(whoami).await;
    assert_eq!(whoami["user"]["username"], "alice");
    assert_eq!(whoami["user"]["totpEnabled"], true);
}

/// **The refusal this whole feature turns on.** A `pending_mfa` session that
/// owes a *code* must never reach an enrolment route — otherwise the second
/// factor is bypassable by enrolling a new one over it.
#[tokio::test]
async fn a_session_that_owes_a_code_cannot_enrol_its_way_past_it() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database, "alice").await;

    let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
    let pending = AdminSessionHandle { cookie, csrf };

    for (method, path) in [
        (Method::POST, "/api/mfa/totp"),
        (Method::POST, "/api/mfa/totp/confirm"),
        (Method::POST, "/api/mfa/recovery-codes"),
        (Method::DELETE, "/api/mfa/totp"),
        (Method::GET, "/api/mfa"),
    ] {
        let response = admin_request(
            &app,
            method.clone(),
            path,
            Some(&pending),
            Some(json!({ "code": "123456" })),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must refuse a session that owes a code"
        );
    }
}

#[tokio::test]
async fn disabling_the_factor_is_refused_while_require_mfa_is_on() {
    let mut config = admin_config();
    config.admin.require_mfa = true;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;
    let session = admin_login_mfa(&app, database, "alice", ADMIN_PASSWORD, &secret).await;

    let refused = admin_request(
        &app,
        Method::DELETE,
        "/api/mfa/totp",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(refused).await["error"], "mfa_required");
}

#[tokio::test]
async fn disabling_the_factor_clears_the_codes_and_the_other_sessions() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;

    let other = admin_login_mfa(&app, database.clone(), "alice", ADMIN_PASSWORD, &secret).await;
    let session = admin_login_mfa(&app, database, "alice", ADMIN_PASSWORD, &secret).await;

    assert_eq!(
        admin_request(
            &app,
            Method::DELETE,
            "/api/mfa/totp",
            Some(&session),
            Some(json!({ "password": ADMIN_PASSWORD })),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );

    let status =
        json_body(admin_request(&app, Method::GET, "/api/mfa", Some(&session), None).await).await;
    assert_eq!(status["totpEnabled"], false);
    assert_eq!(status["recoveryCodesRemaining"], 0);

    // The session doing the change survives; every other browser does not.
    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&other), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED,
        "a factor removed that left another session alive is a change in name only"
    );

    // And the next login needs no code.
    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert!(json_body(response).await.get("mfaRequired").is_none());
}

/// An `active` session is not a pending one, and the mirror-image extractors
/// must each refuse the other's.
#[tokio::test]
async fn the_mfa_step_routes_refuse_a_completed_session() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for method in [Method::GET, Method::POST] {
        let response = admin_request(
            &app,
            method.clone(),
            "/api/session/mfa",
            Some(&session),
            Some(json!({ "code": "123456" })),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} /api/session/mfa must refuse a session that has nothing outstanding"
        );
    }
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/// The two routes that finish a login: origin-gated, deliberately **not**
/// CSRF-checked.
///
/// They cannot join [`mutating_endpoints`], because with an *active* session
/// they answer `401`/`303` rather than the `403` that table asserts. Keeping
/// them in their own table, with their own tests below, is what stops the
/// exclusion from reading as an oversight.
///
/// The omission is argued in `webadmin::session::PendingMfaSubmit`: the
/// challenge page is a plain form (sign-in must work with JavaScript off) and
/// `check_csrf` reads a header a form cannot set. A cross-site forger would
/// need a valid code for a session they cannot read, and success would only
/// complete the victim's own login.
fn mfa_step_endpoints() -> Vec<(Method, &'static str)> {
    vec![
        (Method::POST, "/api/session/mfa"),
        (Method::POST, "/ui/login/mfa"),
    ]
}

#[tokio::test]
async fn the_mfa_step_endpoints_need_a_pending_session_and_the_origin_gate() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    enrol_totp(database, "alice").await;

    for (method, path) in mfa_step_endpoints() {
        // No session at all.
        let anonymous = admin_request(&app, method.clone(), path, None, Some(json!({}))).await;
        assert!(
            anonymous.status().is_client_error() || anonymous.status().is_redirection(),
            "{method} {path} must refuse an anonymous caller, got {}",
            anonymous.status()
        );

        // A pending session from somewhere else entirely.
        let (cookie, csrf) = admin_login_pending(&app, "alice", ADMIN_PASSWORD).await;
        let pending = AdminSessionHandle { cookie, csrf };
        let cross_origin = send_from(
            &app,
            Request::builder()
                .method(method.clone())
                .uri(path)
                .header(
                    header::COOKIE,
                    format!("__Host-acme_admin_session={}", pending.cookie),
                )
                .header(header::ORIGIN, "https://evil.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "code": "123456" }).to_string()))
                .unwrap(),
            "127.0.0.1:40000",
        )
        .await;
        assert_eq!(
            cross_origin.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must be covered by the origin gate, which is what \
             stands in for the CSRF token it cannot have"
        );
    }
}

/// Every mutating endpoint, in one table.
///
/// **This list is the regression suite.** `AuthenticatedWrite` makes the check
/// structural — a mutating handler cannot reach a session without it — but the
/// residual risk is a new handler taking `Authenticated` by mistake, and that
/// is what this catches. An endpoint added below `/api` and not added here is
/// a review catch.
///
/// The `/ui` pages have their own table, `mutating_page_endpoints()` in
/// `tests/admin_pages.rs`, asserted HTML-shaped: a page answering in this
/// suite's JSON error shape would be the bug, not the expectation.
fn mutating_endpoints() -> Vec<(Method, &'static str)> {
    vec![
        (Method::PATCH, "/api/accounts/some-id"),
        (Method::POST, "/api/accounts/some-id/deactivate"),
        (Method::DELETE, "/api/accounts/some-id"),
        (Method::POST, "/api/orders/some-id/revoke"),
        (Method::DELETE, "/api/orders/some-id"),
        (Method::POST, "/api/eab"),
        (Method::POST, "/api/eab/some-kid/revoke"),
        (Method::POST, "/api/nonces/cleanup"),
        (Method::DELETE, "/api/session"),
        (Method::POST, "/api/mfa/totp"),
        (Method::POST, "/api/mfa/totp/confirm"),
        (Method::DELETE, "/api/mfa/totp"),
        (Method::POST, "/api/mfa/recovery-codes"),
    ]
}

#[tokio::test]
async fn every_mutating_endpoint_refuses_a_missing_csrf_token() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for (method, path) in mutating_endpoints() {
        // The cookie, but no `X-CSRF-Token`.
        let request = axum::http::Request::builder()
            .method(method.clone())
            .uri(path)
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let response = send_from(&app, request, "127.0.0.1:40000").await;

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must refuse a request with no CSRF token"
        );
        assert_eq!(json_body(response).await["error"], "csrf_failed");
    }
}

#[tokio::test]
async fn every_mutating_endpoint_refuses_a_wrong_or_foreign_csrf_token() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;
    // A second, legitimate session — its token must not work here either.
    let other = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    for (method, path) in mutating_endpoints() {
        for (label, token) in [
            ("wrong", "not-the-token"),
            ("another session's", &*other.csrf),
        ] {
            let request = axum::http::Request::builder()
                .method(method.clone())
                .uri(path)
                .header(
                    header::COOKIE,
                    format!("__Host-acme_admin_session={}", session.cookie),
                )
                .header("x-csrf-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap();
            let response = send_from(&app, request, "127.0.0.1:40000").await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} must refuse a {label} CSRF token"
            );
        }
    }
}

#[tokio::test]
async fn a_cross_origin_write_is_refused_before_anything_else() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for (name, value) in [
        ("origin", "http://evil.example"),
        ("sec-fetch-site", "cross-site"),
        // A different port of the same host — the case `SameSite=Strict`
        // does not cover, which is the whole reason the gate exists.
        ("origin", "http://localhost:8080"),
    ] {
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/eab")
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header("x-csrf-token", &session.csrf)
            .header(name, value)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let response = send_from(&app, request, "127.0.0.1:40000").await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{name}: {value} must be refused even with a valid CSRF token"
        );
    }
}

#[tokio::test]
async fn a_same_origin_write_with_the_right_token_is_allowed() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/api/eab")
        .header(
            header::COOKIE,
            format!("__Host-acme_admin_session={}", session.cookie),
        )
        .header("x-csrf-token", &session.csrf)
        .header("origin", "http://localhost:3001")
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap();
    let response = send_from(&app, request, "127.0.0.1:40000").await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn reads_need_no_csrf_token() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for path in [
        "/api/session",
        "/api/accounts",
        "/api/orders",
        "/api/audit",
        "/api/eab",
        "/api/nonces",
        "/api/profiles",
    ] {
        let request = axum::http::Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let response = send_from(&app, request, "127.0.0.1:40000").await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    }
}

#[tokio::test]
async fn every_api_route_needs_a_session() {
    let (app, _database, _session) = test_admin_app_logged_in(admin_config()).await;

    let mut routes: Vec<(Method, &'static str)> = vec![
        (Method::GET, "/api/session"),
        (Method::GET, "/api/accounts"),
        (Method::GET, "/api/accounts/some-id"),
        (Method::GET, "/api/accounts/some-id/orders"),
        (Method::GET, "/api/orders"),
        (Method::GET, "/api/orders/some-id"),
        (Method::GET, "/api/audit"),
        (Method::GET, "/api/audit/1"),
        (Method::GET, "/api/eab"),
        (Method::GET, "/api/eab/some-kid"),
        (Method::GET, "/api/nonces"),
        (Method::GET, "/api/profiles"),
        // Refuses a *missing* session for the same reason as the rest, and an
        // `active` one besides — see `the_mfa_step_routes_refuse_a_completed_session`.
        (Method::GET, "/api/session/mfa"),
        (Method::GET, "/api/mfa"),
    ];
    routes.extend(mutating_endpoints());

    for (method, path) in routes {
        let response = admin_request(&app, method.clone(), path, None, Some(json!({}))).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must require a session"
        );
    }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// Seeds `count` accounts, each with one order, and returns their ids.
///
/// Each is created from a real address with a reverse name, so the traceability
/// members the admin renderer adds have something to carry.
async fn seed(
    database: &std::sync::Arc<acme_proxy::sqlite::db::Database>,
    count: u8,
) -> Vec<String> {
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let mut ids = Vec::new();
    for index in 0..count {
        let (account, _) = Account::find_or_create(
            PROFILE,
            &[1u8, index],
            vec![format!("mailto:user{index}@example.com")],
            &ClientContext {
                ip: Some(format!("203.0.113.{index}")),
                ptr: Some(format!("client{index}.example.net")),
                ..ClientContext::default()
            },
            database,
        )
        .await
        .unwrap();
        Order::create(
            PROFILE,
            account.id,
            vec![Identifier::dns(format!("host{index}.example.com"))],
            2_000_000_000,
            None,
            None,
            database,
        )
        .await
        .unwrap();
        ids.push(account.id.to_string());
    }
    ids
}

#[tokio::test]
async fn accounts_list_pages_and_reports_the_total() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 5).await;

    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/accounts?limit=2",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    // The renderer's admin-only augmentation is present.
    assert!(body["items"][0]["id"].as_str().is_some());
    assert_eq!(body["items"][0]["profile"], PROFILE);

    let paged = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/accounts?limit=2&offset=4",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(paged["items"].as_array().unwrap().len(), 1);
    assert_eq!(paged["total"], 5);
}

/// The one list endpoint that used to answer a bare array. The book says lists
/// return an envelope, without qualification, so this pins that `/api/eab` is
/// one of them.
#[tokio::test]
async fn the_eab_list_pages_and_reports_the_total() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    for _ in 0..5 {
        acme_proxy::sqlite::eab::Eab::create(None, None, &database)
            .await
            .unwrap();
    }

    let body =
        json_body(admin_request(&app, Method::GET, "/api/eab?limit=2", Some(&session), None).await)
            .await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert!(body["items"][0]["kid"].as_str().is_some());
    // Never the secret, whatever the shape around it.
    assert!(body["items"][0].get("hmacKey").is_none());

    let paged = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/eab?limit=2&offset=4",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(paged["items"].as_array().unwrap().len(), 1);
    assert_eq!(paged["total"], 5, "the total is the table, not the page");

    // An absent window is the default page, not the whole table by another
    // spelling.
    let bare =
        json_body(admin_request(&app, Method::GET, "/api/eab", Some(&session), None).await).await;
    assert_eq!(bare["limit"], 50);
    assert_eq!(bare["offset"], 0);
    assert_eq!(bare["total"], 5);
}

#[tokio::test]
async fn a_limit_over_the_ceiling_is_clamped_rather_than_refused() {
    let mut config = admin_config();
    config.admin.page_size_max = 3;
    let (app, database, session) = test_admin_app_logged_in(config).await;
    seed(&database, 5).await;

    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/accounts?limit=1000",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["limit"], 3, "clamped to admin.page_size_max");
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
    assert_eq!(body["total"], 5);
}

#[tokio::test]
async fn an_account_can_be_read_updated_deactivated_and_deleted() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let id = &ids[0];

    // Read.
    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/accounts/{id}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["id"], *id);
    assert_eq!(body["status"], "valid");
    // The traceability columns, admin-only: `Account::to_json` carries none of
    // them, so their presence here is the renderer's augmentation and the API
    // is an accurate description of what the `/ui` card holds.
    assert_eq!(body["createdIp"], "203.0.113.0");
    assert_eq!(body["createdPtr"], "client0.example.net");
    assert_eq!(body["lastSeenIp"], "203.0.113.0");
    assert_eq!(body["lastSeenPtr"], "client0.example.net");
    assert!(body["lastSeenAt"].as_str().unwrap().ends_with('Z'));

    // Its orders.
    let orders = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/accounts/{id}/orders"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(orders["total"], 1);

    // Update the contacts.
    let updated = json_body(
        admin_request(
            &app,
            Method::PATCH,
            &format!("/api/accounts/{id}"),
            Some(&session),
            Some(json!({ "contact": ["mailto:new@example.com"] })),
        )
        .await,
    )
    .await;
    assert_eq!(updated["contact"][0], "mailto:new@example.com");

    // Deactivate.
    let deactivated = json_body(
        admin_request(
            &app,
            Method::POST,
            &format!("/api/accounts/{id}/deactivate"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(deactivated["status"], "deactivated");

    // Delete, and the response names what cascaded.
    let deleted = json_body(
        admin_request(
            &app,
            Method::DELETE,
            &format!("/api/accounts/{id}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(deleted["deleted"]["orders"], 1);

    assert_eq!(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/accounts/{id}"),
            Some(&session),
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
}

/// The gap the shared `contact_shape_error` closes: the admin API must not
/// write a contact `newAccount` would have refused.
#[tokio::test]
async fn patching_an_account_validates_contacts_the_way_new_account_does() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let id = &ids[0];

    for bad in [
        "https://example.com",                // wrong scheme
        "mailto:a@example.com?subject=hi",    // hfields
        "mailto:a@example.com,b@example.com", // two addresses
        "mailto:not-an-address",
    ] {
        let response = admin_request(
            &app,
            Method::PATCH,
            &format!("/api/accounts/{id}"),
            Some(&session),
            Some(json!({ "contact": [bad] })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for `{bad}`");
        let body = json_body(response).await;
        assert_eq!(body["error"], "bad_request");
        assert!(body["message"].as_str().unwrap().contains(bad));
    }
}

#[tokio::test]
async fn unknown_ids_are_json_404s_and_never_acme_problem_documents() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for (method, path) in [
        (Method::GET, "/api/accounts/nope"),
        (Method::GET, "/api/accounts/nope/orders"),
        (Method::GET, "/api/orders/nope"),
        (Method::GET, "/api/eab/nope"),
        (Method::DELETE, "/api/accounts/nope"),
        (Method::DELETE, "/api/orders/nope"),
        (Method::POST, "/api/eab/nope/revoke"),
    ] {
        let response = admin_request(&app, method.clone(), path, Some(&session), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json",
            "{method} {path} must not answer application/problem+json"
        );
        let body = json_body(response).await;
        assert_eq!(body["error"], "not_found");
        assert!(!body.to_string().contains("urn:ietf:params:acme"));
    }
}

#[tokio::test]
async fn an_unrouted_path_and_a_wrong_method_answer_in_the_admin_error_shape() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let missing = admin_request(&app, Method::GET, "/api/nothing-here", Some(&session), None).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(missing).await["error"], "not_found");

    let wrong_method = admin_request(
        &app,
        Method::PUT,
        "/api/accounts",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json_body(wrong_method).await["error"], "method_not_allowed");
}

#[tokio::test]
async fn orders_list_filters_by_account_and_status() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 3).await;

    let all =
        json_body(admin_request(&app, Method::GET, "/api/orders", Some(&session), None).await)
            .await;
    assert_eq!(all["total"], 3);

    let mine = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/orders?accountId={}", ids[0]),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(mine["total"], 1);

    let pending = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/orders?status=pending",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(pending["total"], 3);

    let ready = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/orders?status=ready",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(ready["total"], 0);
    assert!(ready["items"].as_array().unwrap().is_empty());
}

/// An unknown `status=` is a `400`, not an empty page.
///
/// The two answers are indistinguishable to a caller — `ready` above really
/// does match nothing — so a typo'd filter has to say so itself rather than
/// looking like a true negative. The CLI's `--status` refuses the same way.
#[tokio::test]
async fn an_unknown_order_status_filter_is_refused_rather_than_matching_nothing() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 2).await;

    let response = admin_request(
        &app,
        Method::GET,
        "/api/orders?status=readyy",
        Some(&session),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = json_body(response).await;
    assert_eq!(body["error"], "invalid_status");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("`readyy`"), "{message}");
    assert!(
        message.contains("pending, ready, processing, valid, invalid"),
        "{message}"
    );
}

#[tokio::test]
async fn an_order_detail_carries_its_authorizations() {
    use acme_proxy::sqlite::authz::{Authorization, Challenge};
    use acme_proxy::sqlite::order::{Identifier, Order};

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let orders = Order::find_by_account(ids[0].parse().unwrap(), &database)
        .await
        .unwrap();
    let order_id = orders[0].id;

    let authz = Authorization::create(
        order_id,
        Identifier::dns("host0.example.com"),
        2_000_000_000,
        &database,
    )
    .await
    .unwrap();
    Challenge::create(authz.id, "http-01", &database)
        .await
        .unwrap();

    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/orders/{order_id}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["order"]["id"], order_id.to_string());
    assert_eq!(body["authorizations"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["authorizations"][0]["challenges"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn revoking_an_order_covers_every_outcome() {
    use acme_proxy::sqlite::order::Order;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let orders = Order::find_by_account(ids[0].parse().unwrap(), &database)
        .await
        .unwrap();
    let order_id = orders[0].id;

    // Never issued.
    let response = admin_request(
        &app,
        Method::POST,
        &format!("/api/orders/{order_id}/revoke"),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response).await["error"], "order_not_issued");

    // Unknown order.
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/orders/nope/revoke",
            Some(&session),
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    // An out-of-range reason code is refused before anything is attempted.
    let bad_reason = admin_request(
        &app,
        Method::POST,
        &format!("/api/orders/{order_id}/revoke"),
        Some(&session),
        Some(json!({ "reason": 99 })),
    )
    .await;
    assert_eq!(bad_reason.status(), StatusCode::CONFLICT);
}

/// An order from a profile this process does not mount cannot be revoked here,
/// and says so rather than reaching for whatever signer is at hand.
#[tokio::test]
async fn revoking_an_order_from_an_unmounted_profile_is_a_conflict() {
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let (account, _) = Account::find_or_create(
        "retired",
        &[7u8, 7],
        vec![],
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();
    let order = Order::create(
        "retired",
        account.id,
        vec![Identifier::dns("old.example.com")],
        2_000_000_000,
        None,
        None,
        &database,
    )
    .await
    .unwrap();

    let response = admin_request(
        &app,
        Method::POST,
        &format!("/api/orders/{}/revoke", order.id),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["error"], "profile_not_mounted");
    assert!(body["message"].as_str().unwrap().contains("retired"));
}

#[tokio::test]
async fn an_order_can_be_deleted_and_names_its_cascade() {
    use acme_proxy::sqlite::order::Order;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let orders = Order::find_by_account(ids[0].parse().unwrap(), &database)
        .await
        .unwrap();
    let order_id = orders[0].id;

    let body = json_body(
        admin_request(
            &app,
            Method::DELETE,
            &format!("/api/orders/{order_id}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["deleted"]["authorizations"], 0);
    assert!(
        Order::find_by_id(&order_id.to_string(), &database)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_eab_secret_is_returned_once_and_never_again() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let created = admin_request(
        &app,
        Method::POST,
        "/api/eab",
        Some(&session),
        Some(json!({ "label": "team-a" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = json_body(created).await;
    let kid = body["kid"].as_str().unwrap().to_string();
    let secret = body["hmacKey"].as_str().unwrap().to_string();
    assert!(!secret.is_empty());
    assert_eq!(body["label"], "team-a");

    // Neither the detail nor the list ever shows it again.
    let shown = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/eab/{kid}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert!(shown.get("hmacKey").is_none());
    assert!(!shown.to_string().contains(&secret));

    let listed =
        json_body(admin_request(&app, Method::GET, "/api/eab", Some(&session), None).await).await;
    assert!(!listed.to_string().contains(&secret));

    // Revoke keeps the row, moving it to `revoked`.
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            &format!("/api/eab/{kid}/revoke"),
            Some(&session),
            None
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let after = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/eab/{kid}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(after["status"], "revoked");
}

#[tokio::test]
async fn creating_an_eab_for_an_unmounted_profile_is_refused() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_request(
        &app,
        Method::POST,
        "/api/eab",
        Some(&session),
        Some(json!({ "profile": "no-such-profile" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        json_body(response).await["message"]
            .as_str()
            .unwrap()
            .contains("no-such-profile")
    );
}

#[tokio::test]
async fn nonces_can_be_counted_and_swept() {
    use acme_proxy::sqlite::nonce::Nonce;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    for _ in 0..3 {
        Nonce::new().save(&database).await.unwrap();
    }

    let counted =
        json_body(admin_request(&app, Method::GET, "/api/nonces", Some(&session), None).await)
            .await;
    assert_eq!(counted["count"], 3);
    assert_eq!(counted["ttlSeconds"], 300);

    // A zero TTL sweeps everything.
    let swept = json_body(
        admin_request(
            &app,
            Method::POST,
            "/api/nonces/cleanup",
            Some(&session),
            Some(json!({ "ttlSeconds": 0 })),
        )
        .await,
    )
    .await;
    assert_eq!(swept["removed"], 3);
    assert_eq!(Nonce::count(&database).await.unwrap(), 0);
}

#[tokio::test]
async fn profiles_reports_the_endpoints_actually_mounted() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let body =
        json_body(admin_request(&app, Method::GET, "/api/profiles", Some(&session), None).await)
            .await;
    let profiles = body.as_array().unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0]["name"], PROFILE);
    assert_eq!(profiles[0]["baseUrl"], BASE);
    assert_eq!(profiles[0]["directory"], format!("{BASE}/directory"));
}

/// `filter show`, behind a session — and the live policy rather than a rebuilt
/// one, since this listener reads the profiles the process actually mounted.
#[tokio::test]
async fn the_filter_policy_api_serves_the_resolved_policy() {
    let (app, _database, session) =
        test_admin_app_logged_in_with_filter(admin_config(), test_filter_policy()).await;

    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/profiles/{PROFILE}/filter"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;

    assert_eq!(body["profile"], PROFILE);
    assert_eq!(body["active"], true);
    assert_eq!(body["defaultEffect"], "deny");
    assert!(body["warning"].is_null());

    let checks = body["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 2);
    assert_eq!(checks[0]["name"], "mgmt-net");
    assert_eq!(checks[0]["type"], "allowed_ip");
    assert_eq!(checks[0]["stages"], "connection and identifiers");
    assert_eq!(checks[1]["name"], "names");
    assert_eq!(checks[1]["type"], "identifiers");

    // Evaluation order, and the condition re-parenthesized -- the member this
    // whole surface exists for.
    let rules = body["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["name"], "mgmt-bypass");
    assert_eq!(rules[0]["then"], "allow");
    assert_eq!(rules[0]["mode"], "enforce");
    assert_eq!(rules[1]["when"], "names or (mgmt-net and names)");
    assert_eq!(rules[1]["then"], "deny");
    assert_eq!(rules[1]["mode"], "warn");
    assert_eq!(rules[1]["stages"], "identifiers only");

    // The operator's own refusal wording is not here: `filter show` does not
    // print it, and the two front ends describe a policy identically.
    assert!(rules[0].get("message").is_none());

    let unknown = admin_request(
        &app,
        Method::GET,
        "/api/profiles/nope/filter",
        Some(&session),
        None,
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(unknown).await["error"], "not_found");

    assert_eq!(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/profiles/{PROFILE}/filter"),
            None,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // Nothing writes: every other verb on the path is unroutable, which is why
    // this route contributes no entry to `mutating_endpoints()`.
    for method in [Method::POST, Method::DELETE, Method::PATCH, Method::PUT] {
        let response = admin_request(
            &app,
            method.clone(),
            &format!("/api/profiles/{PROFILE}/filter"),
            Some(&session),
            Some(json!({})),
        )
        .await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} /api/profiles/{PROFILE}/filter answered {}",
            response.status()
        );
    }
}

/// An endpoint that filters nothing is a **state**, not an error: answering
/// `404` would be the tempting bug, and it would hide the one policy an
/// operator most needs to be told about.
#[tokio::test]
async fn an_endpoint_with_no_rules_says_so_rather_than_answering_404() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let body = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/profiles/{PROFILE}/filter"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;

    assert_eq!(body["active"], false);
    // Never consulted where no rule is applicable, so not a fact about this
    // endpoint at all.
    assert!(body["defaultEffect"].is_null());
    assert!(
        body["warning"]
            .as_str()
            .unwrap()
            .contains("filters nothing")
    );
    assert!(body["checks"].as_array().unwrap().is_empty());
    assert!(body["rules"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_the_hardening_headers() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_request(&app, Method::GET, "/api/profiles", Some(&session), None).await;
    let headers = response.headers();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
    // The access middleware runs here too.
    assert!(headers.contains_key("x-request-id"));
}

/// `/health` is on this listener as well, and needs no session: an
/// orchestrator probing the admin port should not have to hold one.
#[tokio::test]
async fn health_is_served_unauthenticated() {
    let (app, _database) = test_admin_app(admin_config()).await;

    let response = admin_request(&app, Method::GET, "/health", None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["healthy"], true);
}

/// This listener serves no ACME. A client that pointed certbot at it must get
/// nothing, not a half-working directory.
#[tokio::test]
async fn the_admin_listener_serves_no_acme() {
    let (app, _database) = test_admin_app(admin_config()).await;

    for path in [
        "/directory",
        "/newNonce",
        "/profile/default/directory",
        "/profile/default/newNonce",
    ] {
        let response = admin_request(&app, Method::GET, path, None, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "GET {path}");
        // And no `Replay-Nonce` was minted on the way out.
        assert!(
            !response.headers().contains_key("replay-nonce"),
            "GET {path}"
        );
    }
}

/// The revoke path with a certificate that genuinely exists: the outcome the
/// other revoke test cannot reach, and the one that actually touches the CA.
#[tokio::test]
async fn revoking_an_issued_order_succeeds_once_and_then_conflicts() {
    use acme_proxy::signer::RequestedValidity;
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let mut config = admin_config();
    config.admin.enabled = true;
    let (app, database, signer) = test_admin_app_with_signer(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    // An order, issued through the very backend the handler will revoke
    // against.
    let (account, _) = Account::find_or_create(
        PROFILE,
        &[4u8, 2],
        vec![],
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();
    let identifier = Identifier::dns("revoke-me.example.com");
    let mut order = Order::create(
        PROFILE,
        account.id,
        vec![identifier.clone()],
        2_000_000_000,
        None,
        None,
        &database,
    )
    .await
    .unwrap();

    let csr_der = {
        let csr = make_csr("revoke-me.example.com");
        use base64::prelude::*;
        BASE64_URL_SAFE_NO_PAD.decode(csr).unwrap()
    };
    let issued = signer
        .issue(
            &order.id.to_string(),
            &csr_der,
            &[identifier],
            RequestedValidity::default(),
        )
        .await
        .expect("the in-memory CA must issue");
    let chain = match issued {
        acme_proxy::signer::IssueOutcome::Issued(chain) => chain,
        other => panic!("expected an inline issuance, got {other:?}"),
    };
    // The leaf's DER out of the PEM chain: `cert_serial_and_spki` parses one
    // certificate, not a chain.
    let (serial, spki) =
        acme_proxy::cert::cert_serial_and_spki(&first_certificate(&chain)).unwrap();
    let expected_serial = serial.clone();
    order
        .finalize(chain, serial, spki, None, &database)
        .await
        .unwrap();

    // First revocation succeeds and returns the order.
    let response = admin_request(
        &app,
        Method::POST,
        &format!("/api/orders/{}/revoke", order.id),
        Some(&session),
        Some(json!({ "reason": 1 })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["id"], order.id.to_string());
    // `render_order_json` surfaces the admin-only revocation columns that
    // `Order::to_json` deliberately omits.
    assert_eq!(body["revocationReason"], 1);
    assert!(body["revokedAt"].as_str().is_some());
    // And the serial beside them: it is what an abuse report names and what
    // `/api/audit?certSerial=` filters on, so the order shape had to stop being
    // the one surface that would not say it.
    assert_eq!(body["certSerial"], expected_serial);

    // The CA acted, not just the database: the CRL now names the serial.
    let crl = signer.crl_der().await.expect("a local CA always has a CRL");
    assert!(!crl.is_empty());

    // A repeat is a conflict, not a second revocation.
    let repeat = admin_request(
        &app,
        Method::POST,
        &format!("/api/orders/{}/revoke", order.id),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(repeat.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(repeat).await["error"], "already_revoked");
}

/// Replacing or removing a live second factor takes the account password, not
/// just the cookie.
///
/// The blast radius is what makes a session insufficient authority here: each
/// of these three also calls `revoke_other_sessions` and supersedes the
/// recovery codes. Without the gate, somebody holding one stolen cookie enrols
/// *their* authenticator over the operator's, signs the operator out
/// everywhere, and voids the codes that would let them back — leaving
/// `acme-proxy admin user totp reset` on the host as the only way in.
#[tokio::test]
async fn changing_a_live_factor_requires_the_password_again() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let secret = enrol_totp(database.clone(), "alice").await;
    let session = admin_login_mfa(&app, database.clone(), "alice", ADMIN_PASSWORD, &secret).await;

    // A fresh address per attempt, because `check_step_up` now spends the login
    // limiter's budget and six guesses from one address would be refused as
    // `rate_limited` — a different refusal from the one under test here, which
    // is that a cookie alone is not authority. Rotating addresses is also
    // exactly the residual the address-keyed bound does not close, so spelling
    // it out here keeps that visible rather than incidental.
    let mut attempt = 0;
    for (method, path) in [
        (Method::POST, "/api/mfa/totp"),
        (Method::POST, "/api/mfa/recovery-codes"),
        (Method::DELETE, "/api/mfa/totp"),
    ] {
        // Absent, then wrong: both are the same refusal a wrong password gets
        // at sign-in, so this is not a second oracle for the password.
        for body in [json!({}), json!({ "password": "not-the-password" })] {
            attempt += 1;
            let refused = admin_request_from(
                &app,
                method.clone(),
                path,
                Some(&session),
                Some(body),
                &format!("192.0.2.{attempt}:1234"),
            )
            .await;
            assert_eq!(
                refused.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} must not act on a cookie alone"
            );
            assert_eq!(
                json_body(refused).await["error"],
                "invalid_credentials",
                "{method} {path}"
            );
        }
    }

    // Nothing was changed by any of those six attempts.
    let status =
        json_body(admin_request(&app, Method::GET, "/api/mfa", Some(&session), None).await).await;
    assert_eq!(status["totpEnabled"], true);
    assert_eq!(status["enrolmentPending"], false);
    assert_eq!(status["recoveryCodesRemaining"], 10);

    // With the password, the same call goes through.
    assert_eq!(
        admin_request(
            &app,
            Method::POST,
            "/api/mfa/totp",
            Some(&session),
            Some(json!({ "password": ADMIN_PASSWORD })),
        )
        .await
        .status(),
        StatusCode::CREATED
    );
}

/// The gate applies only where there is a factor to protect.
///
/// A first enrolment protects nothing, and demanding a password there would
/// put one in front of the `require_mfa` bootstrap — whose entire design is
/// that enrolling stays reachable, since a session is needed to enrol and a
/// factor would then be needed for a session.
#[tokio::test]
async fn a_first_enrolment_asks_for_no_password() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    let begun = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(begun.status(), StatusCode::CREATED);

    let secret = json_body(begun).await["secret"]
        .as_str()
        .expect("the secret is readable exactly once")
        .to_string();

    // And confirming is not gated either: it can only ever confirm the secret
    // `POST /api/mfa/totp` already handed out, which is the call that carries
    // the gate once a factor exists.
    let confirmed = admin_request(
        &app,
        Method::POST,
        "/api/mfa/totp/confirm",
        Some(&session),
        Some(json!({ "code": totp_code(&base32_decode(&secret), 0) })),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
}

/// With the database gone, the admin listener fails **closed**.
///
/// The whole listener had no DB-failure coverage — `pool.close()` appeared only
/// in `tests/db_failures.rs`, which is ACME-only. The class of bug this guards
/// against is the worst one an auth layer can have: `resolve_session` cannot
/// read the session row, and *treats that as no constraint* rather than as no
/// session. Every route below is one an unauthenticated caller must never
/// reach, so a `200` from any of them is the finding.
///
/// The limiter is checked too. It is deliberately in-memory and so survives the
/// outage, but `authenticate` reads the user table, so a login must refuse
/// rather than let a caller through on an unreadable password hash.
#[tokio::test]
async fn the_admin_listener_fails_closed_when_the_database_is_gone() {
    // Asserted as an exact status, not `is_client_error() || is_server_error()`.
    // That pair accepts a `404`, a `400` and — most importantly — a `403`, which
    // is precisely the answer a session check that silently treated an
    // unreadable table as "no constraint" would eventually stop giving. A range
    // this wide cannot tell "refused because nothing could be read" from "this
    // route stopped existing", which is the whole thing the test is named for.
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    database.pool.close().await;

    for (method, path) in [
        (Method::GET, "/api/session"),
        (Method::GET, "/api/accounts"),
        (Method::GET, "/api/orders"),
        (Method::GET, "/api/eab"),
        (Method::GET, "/api/mfa"),
        (Method::GET, "/api/profiles"),
    ] {
        let response = admin_request(&app, method.clone(), path, Some(&session), None).await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{method} {path} must say it could not authorise, not answer something \
             that reads like an ordinary refusal"
        );
    }

    // Signing in cannot succeed either, and must not set a cookie.
    let response = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "a login answered {} against an unreadable user table",
        response.status()
    );
    assert!(
        session_cookie_token(&response).is_none(),
        "a failed login must not hand out a session cookie"
    );

    // And a mutation is refused before it can half-apply.
    let response = admin_request(
        &app,
        Method::DELETE,
        "/api/accounts/00000000-0000-0000-0000-000000000000",
        Some(&session),
        None,
    )
    .await;
    assert!(response.status().is_client_error() || response.status().is_server_error());
}

/// `admin.max_body_bytes`, the admin twin of `tests/admission.rs`'s ACME check.
///
/// This listener deliberately carries no admission control — the availability
/// concern here is credential brute force, which the limiter handles — so the
/// body limit is the only thing bounding what one request can make the process
/// allocate.
#[tokio::test]
async fn an_oversized_admin_request_body_is_refused() {
    let mut config = admin_config();
    config.admin.max_body_bytes = 1024;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    let oversized = json!({ "contact": ["mailto:a@b.test"], "padding": "x".repeat(4096) });
    let response = admin_request(
        &app,
        Method::PATCH,
        "/api/accounts/00000000-0000-0000-0000-000000000000",
        Some(&session),
        Some(oversized),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // The limit is a ceiling, not a refusal of every body: the same request
    // under it reaches the handler, which then answers on its own merits.
    let response = admin_request(
        &app,
        Method::PATCH,
        "/api/accounts/00000000-0000-0000-0000-000000000000",
        Some(&session),
        Some(json!({ "contact": ["mailto:a@b.test"] })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The audit surface is **read-only**, and that is a security property rather
/// than a missing feature: a panel session that could delete audit history
/// would make the history prove nothing, since a stolen session's first act
/// would be to use it. Pruning is `acme-proxy audit cleanup` on the host, or
/// `audit.retention_days`.
///
/// This is also why `/api/audit` contributes nothing to `mutating_endpoints()`
/// — there is no mutating route to list.
#[tokio::test]
async fn the_audit_api_lists_pages_and_refuses_every_way_of_writing_to_it() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;

    for _ in 0..3 {
        AuditEntry::insert(
            AuditRecord::new(AuditEvent::CertificateIssued, PROFILE, Actor::admin("root"))
                .with_account("acct-1")
                .with_serial("0a0b")
                .with_client(ClientContext {
                    ip: Some("203.0.113.7".to_string()),
                    ptr: Some("host.example.com".to_string()),
                    ..ClientContext::default()
                }),
            &database,
        )
        .await
        .unwrap();
    }
    AuditEntry::insert(
        AuditRecord::new(
            AuditEvent::CertificateRevokeFailed,
            PROFILE,
            Actor::acme_certificate_key(),
        )
        .with_reason("unauthorized"),
        &database,
    )
    .await
    .unwrap();

    let body =
        json_body(admin_request(&app, Method::GET, "/api/audit", Some(&session), None).await).await;
    assert_eq!(body["total"], 4);
    assert_eq!(body["items"].as_array().unwrap().len(), 4);
    // Newest first, and the row carries the address it was written with.
    assert_eq!(body["items"][0]["event"], "certificate_revoke_failed");
    assert_eq!(body["items"][3]["clientIp"], "203.0.113.7");
    assert_eq!(body["items"][3]["clientPtr"], "host.example.com");
    // Absent, not null, for a row that had none.
    assert!(
        !body["items"][0]
            .as_object()
            .unwrap()
            .contains_key("clientIp")
    );

    // Filters and the page window.
    let filtered = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/audit?outcome=failure",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(filtered["total"], 1);

    let paged = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/audit?limit=2",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(paged["total"], 4);
    assert_eq!(paged["items"].as_array().unwrap().len(), 2);
    assert_eq!(paged["limit"], 2);

    // One row by id, and an unknown one.
    let id = body["items"][0]["id"].as_i64().unwrap();
    let one = json_body(
        admin_request(
            &app,
            Method::GET,
            &format!("/api/audit/{id}"),
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(one["id"], id);
    let missing = admin_request(&app, Method::GET, "/api/audit/999999", Some(&session), None).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // Nothing writes: every other verb on both paths is unroutable.
    for (method, path) in [
        (Method::POST, "/api/audit"),
        (Method::DELETE, "/api/audit"),
        (Method::DELETE, "/api/audit/1"),
        (Method::PATCH, "/api/audit/1"),
        (Method::POST, "/api/audit/cleanup"),
    ] {
        let response =
            admin_request(&app, method.clone(), path, Some(&session), Some(json!({}))).await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} {path} answered {}",
            response.status()
        );
    }
    // And the rows are all still there.
    assert_eq!(
        json_body(admin_request(&app, Method::GET, "/api/audit", Some(&session), None).await).await
            ["total"],
        4
    );
}

/// One issued order on `PROFILE` whose leaf expires at `not_after`.
///
/// The chain is a placeholder rather than a real signature: the identifier
/// signal reads the stored `identifiers` and `cert_not_after`, and the
/// `replaces` signal answers `None` on a chain it cannot parse, which is the
/// fall-through this fixture wants. The suite for the annotation itself lives
/// in `src/admin/ops.rs`, over really-signed rows.
async fn expiring(
    database: &std::sync::Arc<acme_proxy::sqlite::db::Database>,
    account: uuid::Uuid,
    names: &[&str],
    not_after: i64,
) -> String {
    use acme_proxy::sqlite::order::{Identifier, Order};

    let mut order = Order::create(
        PROFILE,
        account,
        names.iter().map(|name| Identifier::dns(*name)).collect(),
        2_000_000_000,
        None,
        None,
        database,
    )
    .await
    .unwrap();
    order
        .finalize(
            "-----BEGIN CERTIFICATE-----\nplaceholder\n".to_string(),
            format!("serial-{}", &order.id.to_string()[..8]),
            vec![1],
            Some(not_after),
            database,
        )
        .await
        .unwrap();
    order.id.to_string()
}

/// The expiry surface is **read-only**, and for a different reason than the
/// audit trail's: renewal is the *client's* action, driven by its own ACME
/// flow. A panel button that placed an order on a subscriber's behalf would be
/// this server signing for a key it does not hold. That is why `/api/expiring`
/// contributes nothing to `mutating_endpoints()` — there is no mutating route
/// to list.
#[tokio::test]
async fn the_expiring_api_lists_annotates_filters_and_refuses_every_way_of_writing_to_it() {
    use acme_proxy::sqlite::account::Account;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let (account, _) = Account::find_or_create(
        PROFILE,
        b"expiry-key",
        Vec::new(),
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();

    let now = now_unix();
    const DAY: i64 = 24 * 60 * 60;
    // Half a day past the three, so the day count below distinguishes a floor
    // from a round without racing the clock at the boundary.
    let soon = expiring(
        &database,
        account.id,
        &["soon.example.com"],
        now + 3 * DAY + DAY / 2,
    )
    .await;
    let mid = expiring(&database, account.id, &["mid.example.com"], now + 20 * DAY).await;
    // Renews `soon`, and is itself outside the window: the annotation is about
    // the row it replaces, not about being listed alongside it.
    let renewal = expiring(
        &database,
        account.id,
        &["soon.example.com"],
        now + 300 * DAY,
    )
    .await;
    // Withdrawn, so not something to go and renew.
    let mut revoked = acme_proxy::sqlite::order::Order::find_by_id(
        &expiring(&database, account.id, &["gone.example.com"], now + 2 * DAY).await,
        &database,
    )
    .await
    .unwrap()
    .unwrap();
    revoked.revoke(Some(1), &database).await.unwrap();

    let body =
        json_body(admin_request(&app, Method::GET, "/api/expiring", Some(&session), None).await)
            .await;
    assert_eq!(body["total"], 2, "the revoked row is not expiring");
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["hidden"], 0, "nothing hidden by default");
    // The default window is the configured lead time, or 30 days where the
    // digest is off — which `admin_config()` leaves it.
    assert_eq!(body["days"], 30);

    // Soonest first, which is the query's ordering and not the page's.
    assert_eq!(body["items"][0]["orderId"], soon);
    assert_eq!(body["items"][1]["orderId"], mid);
    assert_eq!(body["items"][0]["daysRemaining"], 3, "floored, not rounded");
    assert_eq!(body["items"][0]["identifiers"][0], "soon.example.com");
    assert_eq!(body["items"][0]["supersededBy"]["orderId"], renewal);
    assert_eq!(body["items"][0]["supersededBy"]["via"], "identifiers");
    // Absent, not null, on the row nothing has replaced — the presence of this
    // member is exactly what an operator scans the list for.
    assert!(
        !body["items"][1]
            .as_object()
            .unwrap()
            .contains_key("supersededBy"),
        "{body}"
    );

    // The window is a filter, and it is the `days` the answer reports back.
    let narrow = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/expiring?days=7",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(narrow["total"], 1);
    assert_eq!(narrow["days"], 7);
    assert_eq!(narrow["items"][0]["orderId"], soon);

    // Hiding the replaced rows drops them from the page and says how many —
    // and deliberately leaves `total` counting the window, because the
    // annotation is not a SQL predicate. See `admin::list_expiring`.
    let hidden = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/expiring?superseded=hide",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(hidden["items"].as_array().unwrap().len(), 1);
    assert_eq!(hidden["items"][0]["orderId"], mid);
    assert_eq!(hidden["hidden"], 1);
    assert_eq!(hidden["total"], 2, "the total counts the window");
    // Anything but `hide` shows them, rather than being refused: a row wrongly
    // hidden is a certificate an operator stops watching.
    let typo = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/expiring?superseded=hde",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(typo["items"].as_array().unwrap().len(), 2);

    // A profile that issued none of this answers with none of it.
    let other = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/expiring?profile=nothing-here",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(other["total"], 0);

    // A *blank* profile is not that: it is the "every profile" option of the
    // panel's own `<select>`, which submits `profile=` rather than omitting the
    // key. Asserted against the unfiltered total rather than against a bare
    // non-zero, so this cannot start passing again by accident.
    for query in [
        "/api/expiring?profile=",
        "/api/expiring?profile=&days=30&superseded=",
    ] {
        let blank =
            json_body(admin_request(&app, Method::GET, query, Some(&session), None).await).await;
        assert_eq!(blank["total"], 2, "{query} filtered on the empty string");
        assert_eq!(blank["items"].as_array().unwrap().len(), 2, "{query}");
    }

    // The page window is the shared one, clamped like every other listing.
    let paged = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/expiring?limit=1&offset=1",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(paged["total"], 2);
    assert_eq!(paged["limit"], 1);
    assert_eq!(paged["offset"], 1);
    assert_eq!(paged["items"][0]["orderId"], mid);

    // A session is required, like every other resource on this listener.
    assert_eq!(
        admin_request(&app, Method::GET, "/api/expiring", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Nothing writes: every other verb on the path is unroutable.
    for method in [Method::POST, Method::DELETE, Method::PATCH, Method::PUT] {
        let response = admin_request(
            &app,
            method.clone(),
            "/api/expiring",
            Some(&session),
            Some(json!({})),
        )
        .await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} /api/expiring answered {}",
            response.status()
        );
    }
}

/// A list control left at its "any"/"every" option is **not** a filter for the
/// empty string.
///
/// An HTML `<select>` inside a submitted form always contributes its `name`, so
/// `<option value="">` arrives as `profile=` rather than as an omitted key, and
/// `serde_urlencoded` reads that as `Some("")`. Every predicate builder below
/// then honoured it — `AND profile = ''` matches no row — so the panel's own
/// filter form emptied each list the moment an operator touched it. The CLI
/// never saw the shape at all, clap giving `None` for an omitted `--profile`,
/// which is why `order list` was right where `/ui/orders` was empty.
///
/// `status=` was the worst of them: it reached `OrderStatus::from_str`, which
/// refuses an unknown spelling **by name**, so "any status" was a `400` rather
/// than merely an empty page. Pinned here beside the rest.
///
/// Every assertion is against the *unfiltered* answer rather than a bare
/// non-zero, so none of them can start passing again by accident.
#[tokio::test]
async fn a_blank_filter_is_absent_on_every_list() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 3).await;
    for _ in 0..2 {
        AuditEntry::insert(
            AuditRecord::new(AuditEvent::CertificateIssued, PROFILE, Actor::admin("root"))
                .with_account("acct-1")
                .with_serial("0a0b"),
            &database,
        )
        .await
        .unwrap();
    }

    // Each pair is (the unfiltered listing, the same listing with every filter
    // control left blank — the exact query string the panel's form submits).
    for (bare, blank, expected) in [
        ("/api/accounts", "/api/accounts?profile=", 3),
        ("/api/orders", "/api/orders?profile=&accountId=&status=", 3),
        (
            "/api/audit",
            "/api/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=",
            2,
        ),
    ] {
        let response = admin_request(&app, Method::GET, blank, Some(&session), None).await;
        assert_eq!(response.status(), StatusCode::OK, "{blank}");
        let filtered = json_body(response).await;
        let unfiltered =
            json_body(admin_request(&app, Method::GET, bare, Some(&session), None).await).await;

        assert_eq!(unfiltered["total"], expected, "{bare} seeded wrong");
        assert_eq!(
            filtered["total"], unfiltered["total"],
            "{blank} filtered on the empty string"
        );
        assert_eq!(
            filtered["items"].as_array().unwrap().len(),
            unfiltered["items"].as_array().unwrap().len(),
            "{blank}"
        );
    }

    // A named filter still filters — the fix must not have turned the controls
    // into decoration.
    let named = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/orders?status=pending",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(named["total"], 3);
    let elsewhere = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/accounts?profile=nothing-here",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(elsewhere["total"], 0);

    // And a filter that is only whitespace is still blank: a text input can
    // carry a space the operator cannot see.
    let padded = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/orders?accountId=%20%20",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(padded["total"], 3);
}
