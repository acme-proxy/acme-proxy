//! The web admin's HTML pages, through the real `build_admin_app`.
//!
//! The twin of `admin_api.rs`, and split from it for the same reason `/ui` is
//! split from `/api`: the assertions are HTML-shaped, and folding them into a
//! suite whose every helper parses JSON would have meant `json_body` panicking
//! on half of them.
//!
//! Sections, mirroring that file: **Sign-in** → **Auth redirects** → **CSRF**
//! → **Escaping** → **Fragments** → **Resources** → **Layers**.

mod common;

use acme_proxy::admin::password::PasswordContext;
use acme_proxy::audit::{Actor, AuditEvent, AuditRecord, ClientContext};
use acme_proxy::sqlite::audit::AuditEntry;
use axum::http::{Method, StatusCode, header};
use common::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_sign_in_page_renders_without_a_session_and_carries_no_htmx() {
    let (app, _database) = test_admin_app(admin_config()).await;

    let response = admin_page(&app, "/ui/login", None, false).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    let body = html_body(response).await;
    assert!(body.starts_with("<!doctype html>"));
    assert!(body.contains(r#"name="username""#));
    assert!(body.contains(r#"name="password""#));
    // A plain form, deliberately: there is no CSRF token to send before a
    // session exists, and signing in must work with JavaScript off.
    assert!(!body.contains("htmx.min.js"));
    assert!(body.contains(r#"action="/ui/login""#));
}

#[tokio::test]
async fn a_form_login_sets_the_same_hardened_cookie_and_redirects_to_the_panel() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/ui/");

    // The cookie is the API's, byte for byte: one `session_cookie`, one set of
    // attributes, whichever front end minted it.
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.starts_with("__Host-acme_admin_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(!set_cookie.contains("Domain"));
    assert!(session_cookie_token(&response).is_some());
}

#[tokio::test]
async fn a_failed_form_login_re_renders_the_page_with_its_real_status() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", "wrong-password")]),
    )
    .await;

    // Not a `200`: a sign-in page answering OK to a refused credential is a
    // lie a script would believe.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(session_cookie_token(&response).is_none());

    let body = html_body(response).await;
    assert!(body.contains("invalid username or password"));
    assert!(body.contains("invalid_credentials"));
    // The typed username survives, so a mistyped password is one field to fix.
    assert!(body.contains(r#"value="alice""#));
}

#[tokio::test]
async fn the_sign_in_page_is_rate_limited_like_the_api() {
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

    for _ in 0..2 {
        admin_form_request(
            &app,
            Method::POST,
            "/ui/login",
            None,
            Some(&[("username", "alice"), ("password", "wrong-password")]),
        )
        .await;
    }

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(html_body(response).await.contains("rate_limited"));
}

/// The challenge page's twin of `the_sign_in_page_renders_without_a_session_and_carries_no_htmx`.
///
/// Finishing a sign-in must work with JavaScript off, exactly as starting one
/// does — which is also why the form carries no CSRF token and the origin gate
/// covers it instead.
#[tokio::test]
async fn the_challenge_page_renders_for_a_pending_session_and_carries_no_htmx() {
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

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/ui/login/mfa",
        "a factor-bearing operator goes to the challenge, not the panel"
    );
    let cookie = session_cookie_token(&response).expect("the pending cookie is still set");
    let pending = AdminSessionHandle {
        cookie,
        csrf: String::new(),
    };

    let page = admin_page(&app, "/ui/login/mfa", Some(&pending), false).await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = html_body(page).await;
    assert!(body.starts_with("<!doctype html>"));
    assert!(body.contains(r#"name="code""#));
    assert!(body.contains(r#"action="/ui/login/mfa""#));
    assert!(
        !body.contains("htmx.min.js"),
        "finishing a sign-in must work with JavaScript off, like starting one"
    );
    // No navigation and no operator metadata: this session is not signed in.
    assert!(!body.contains(r#"href="/ui/accounts""#));
    assert!(!body.contains("alice"));
}

#[tokio::test]
async fn a_form_second_step_completes_the_sign_in_and_rotates_the_cookie() {
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

    let started = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;
    let cookie = session_cookie_token(&started).unwrap();
    let pending = AdminSessionHandle {
        cookie: cookie.clone(),
        csrf: String::new(),
    };

    // A wrong code re-renders the page at its real status, the `post_login`
    // shape.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/login/mfa",
        Some(&pending),
        Some(&[("code", "000000")]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = html_body(refused).await;
    assert!(body.contains("invalid_credentials"));
    assert!(body.contains(r#"name="code""#));

    let done = admin_form_request(
        &app,
        Method::POST,
        "/ui/login/mfa",
        Some(&pending),
        Some(&[("code", &totp_code(&secret, 0))]),
    )
    .await;
    assert_eq!(done.status(), StatusCode::SEE_OTHER);
    assert_eq!(done.headers()[header::LOCATION], "/ui/");

    let promoted = session_cookie_token(&done).expect("promotion must set the rotated cookie");
    assert_ne!(promoted, cookie);

    // The rotated cookie opens the panel; the pending one does not.
    let session = AdminSessionHandle {
        cookie: promoted,
        csrf: String::new(),
    };
    assert_eq!(
        admin_page(&app, "/ui/", Some(&session), false)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        admin_page(&app, "/ui/", Some(&pending), false)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
}

/// A `pending_mfa` cookie is not a session: every page below the sign-in line
/// must bounce it back, exactly as no cookie at all does.
#[tokio::test]
async fn a_half_authenticated_cookie_reaches_no_page() {
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

    let started = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;
    let pending = AdminSessionHandle {
        cookie: session_cookie_token(&started).unwrap(),
        csrf: String::new(),
    };

    for path in authenticated_pages() {
        let response = admin_page(&app, path, Some(&pending), false).await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "GET {path} must bounce a half-authenticated cookie"
        );
        assert_eq!(response.headers()[header::LOCATION], "/ui/login");
    }
}

/// Under `require_mfa`, an operator with no factor finishes their login by
/// *setting one up* — the whole reason the flag forces enrolment rather than
/// refusing the login.
#[tokio::test]
async fn require_mfa_turns_the_challenge_page_into_an_enrolment_page() {
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

    let started = admin_form_request(
        &app,
        Method::POST,
        "/ui/login",
        None,
        Some(&[("username", "alice"), ("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(started.headers()[header::LOCATION], "/ui/login/mfa");
    let pending = AdminSessionHandle {
        cookie: session_cookie_token(&started).unwrap(),
        csrf: String::new(),
    };

    let page = admin_page(&app, "/ui/login/mfa", Some(&pending), false).await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = html_body(page).await;
    assert!(body.contains("Set up a second factor"));
    // Escaped, because these are `.html` templates and minijinja escapes `/`
    // as well as the five delimiters — the same property that makes a stored
    // `<script>` in a username inert. The browser decodes it back on the way in.
    assert!(
        body.contains("otpauth:&#x2f;&#x2f;totp&#x2f;acme-proxy:alice@"),
        "the provisioning URI must be present and auto-escaped"
    );

    let secret_base32 = between(&body, r#"<pre class="secret">"#, "</pre>");
    let secret = base32_decode(&secret_base32);

    // A reload must show the *same* secret: an operator who has just scanned it
    // into an app cannot be handed a different one.
    let again = html_body(admin_page(&app, "/ui/login/mfa", Some(&pending), false).await).await;
    assert!(again.contains(&secret_base32), "the enrolment must resume");

    let confirmed = admin_form_request(
        &app,
        Method::POST,
        "/ui/login/mfa",
        Some(&pending),
        Some(&[("code", &totp_code(&secret, 0))]),
    )
    .await;
    assert_eq!(
        confirmed.status(),
        StatusCode::OK,
        "the recovery codes exist for one moment; a 303 would spend it"
    );
    let promoted =
        session_cookie_token(&confirmed).expect("finishing enrolment finishes the login");
    let body = html_body(confirmed).await;
    assert!(body.contains("Store these recovery codes now"));
    assert!(body.contains(r#"href="/ui/""#));

    let session = AdminSessionHandle {
        cookie: promoted,
        csrf: String::new(),
    };
    assert_eq!(
        admin_page(&app, "/ui/", Some(&session), false)
            .await
            .status(),
        StatusCode::OK
    );
}

/// The account page, end to end: enrol, see the codes once, reissue them, turn
/// it off.
#[tokio::test]
async fn the_account_page_runs_the_whole_enrolment_lifecycle() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;

    let body = html_body(admin_page(&app, "/ui/account", Some(&session), false).await).await;
    assert!(body.contains("Two-factor authentication"));
    assert!(body.contains("Set one up"));

    // Begin: the secret, exactly once.
    let begun = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp",
        Some(&session),
        Some(&[]),
    )
    .await;
    assert_eq!(begun.status(), StatusCode::OK);
    let body = html_body(begun).await;
    assert!(
        body.contains(r#"id="account-mfa""#),
        "the swap target survives"
    );
    let secret_base32 = between(&body, r#"<pre class="secret">"#, "</pre>");
    let secret = base32_decode(&secret_base32);

    // A wrong code is a banner on the same step, not an error page.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp/confirm",
        Some(&session),
        Some(&[("code", "000000")]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = html_body(refused).await;
    assert!(body.contains("That code did not match"));
    assert!(
        body.contains(&secret_base32),
        "the pending secret survives a wrong code, so the next one can be tried"
    );

    let confirmed = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp/confirm",
        Some(&session),
        Some(&[("code", &totp_code(&secret, 0))]),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let body = html_body(confirmed).await;
    assert!(body.contains("Store these recovery codes now"));
    assert!(body.contains("10 unused"));
    let codes = between(&body, r#"<pre class="secret">"#, "</pre>");
    assert_eq!(codes.lines().count(), 10);

    // And they are never shown again.
    let body = html_body(admin_page(&app, "/ui/account", Some(&session), false).await).await;
    for code in codes.lines() {
        assert!(!body.contains(code.trim()), "a recovery code is shown once");
    }
    assert!(!body.contains(&secret_base32), "so is the secret");

    // Reissue. Every control on the card that changes a live factor asks for
    // the password again -- superseding the recovery set is a lockout in a
    // stolen session's hands, so a cookie alone is not authority for it.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/recovery-codes",
        Some(&session),
        Some(&[("password", "not-the-password")]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = html_body(refused).await;
    assert!(body.contains("That password is not correct"));
    assert!(
        body.contains(r#"id="account-mfa""#),
        "a wrong password is this card's own banner, not an error page"
    );

    let reissued = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/recovery-codes",
        Some(&session),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(reissued.status(), StatusCode::OK);
    let body = html_body(reissued).await;
    let fresh = between(&body, r#"<pre class="secret">"#, "</pre>");
    assert_ne!(fresh, codes, "the previous set is superseded");

    // Re-enrolling over a live factor is gated too — the case that turns a
    // stolen cookie into a lockout, since confirming would revoke every other
    // session and void the recovery codes.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp",
        Some(&session),
        Some(&[("password", "not-the-password")]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(
        html_body(refused)
            .await
            .contains("That password is not correct"),
        "the refusal is this card's banner"
    );

    // Turn it off — the same gate, and the one the whole step-up exists for.
    assert_eq!(
        admin_form_request(
            &app,
            Method::POST,
            "/ui/account/mfa/totp/disable",
            Some(&session),
            Some(&[("password", "not-the-password")]),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let off = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp/disable",
        Some(&session),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(off.status(), StatusCode::OK);
    assert!(
        html_body(off)
            .await
            .contains("Two-factor authentication is off")
    );

    let after = acme_proxy::sqlite::admin_user::AdminUser::find_by_username("alice", &database)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.has_totp());
}

/// Refusals that are about this card's own state are banners, not pages — the
/// same split the order page's revoke already makes.
#[tokio::test]
async fn the_account_page_reports_its_refusals_as_banners() {
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

    let body = html_body(admin_page(&app, "/ui/account", Some(&session), false).await).await;
    assert!(
        !body.contains("Turn off"),
        "the button is not dangled when the server refuses the action"
    );

    // And the endpoint refuses it regardless of what the page offered.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp/disable",
        Some(&session),
        Some(&[]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let body = html_body(refused).await;
    assert!(body.contains("requires a second factor"));
    assert!(body.contains(r#"id="account-mfa""#));
}

/// Guessing the step-up password on the card is bounded, and the lockout is a
/// banner on the card at its real status — not an error page and not a 401.
///
/// The `/ui` half of the limiter's third call site. The status is what a
/// browser sees, so it has to be the error's own rather than this card's fixed
/// 401, and the message has to be the error's own too: only it can say how long
/// the wait is.
#[tokio::test]
async fn a_rate_limited_step_up_is_a_banner_at_its_own_status() {
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

    // The default budget, spent on this card rather than on the sign-in form.
    for _ in 0..5 {
        let refused = admin_form_request(
            &app,
            Method::POST,
            "/ui/account/mfa/totp",
            Some(&session),
            Some(&[("password", "not-the-password")]),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    }

    // Past it, the correct password is refused too — the limiter runs ahead of
    // the KDF, so there is nothing left to spend.
    let limited = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/totp",
        Some(&session),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = html_body(limited).await;
    assert!(
        body.contains(r#"id="account-mfa""#),
        "a lockout is this card's own banner, not an error page"
    );
    assert!(
        body.contains("too many"),
        "the banner has to say what happened, and how long to wait"
    );
}

/// The `/ui` twin of `admin_api.rs`'s password-change suite: current password
/// checked -- even with no second factor enrolled, unlike the MFA cards'
/// step-up -- new one through the policy, the calling session survives and
/// every other one does not.
#[tokio::test]
async fn the_password_card_changes_the_password_keeps_the_session_and_revokes_every_other() {
    let (app, database) = test_admin_app(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();

    let other = admin_login(&app, "alice", ADMIN_PASSWORD).await;
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    const NEW_PASSWORD: &str = "a-different-long-password";
    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/password",
        Some(&session),
        Some(&[
            ("current_password", ADMIN_PASSWORD),
            ("new_password", NEW_PASSWORD),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains("Your password was changed"));
    assert!(
        body.contains(r#"id="account-password""#),
        "the success message is this card's own banner, not a redirect"
    );

    assert_eq!(
        admin_page(&app, "/ui/account", Some(&session), false)
            .await
            .status(),
        StatusCode::OK,
        "the session that made the change must not sign itself out"
    );
    assert_eq!(
        admin_page(&app, "/ui/account", Some(&other), false)
            .await
            .status(),
        StatusCode::SEE_OTHER,
        "a password changed that left another session alive is a change in name only"
    );

    let login = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": NEW_PASSWORD })),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
}

/// A wrong current password is this card's own banner, not an error page —
/// the same rule the MFA step-up cards follow.
#[tokio::test]
async fn the_password_card_reports_a_wrong_current_password_as_a_banner() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/password",
        Some(&session),
        Some(&[
            ("current_password", "not the password"),
            ("new_password", "a-different-long-password"),
        ]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = html_body(refused).await;
    assert!(body.contains("That password is not correct"));
    assert!(body.contains(r#"id="account-password""#));

    // Nothing was written: the old password still signs in.
    let login = admin_request(
        &app,
        Method::POST,
        "/api/session",
        None,
        Some(json!({ "username": "alice", "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
}

/// The policy failure reaches the same card, with the same code the JSON API
/// answers (`bad_request`) so the two front ends never describe one refusal
/// differently.
#[tokio::test]
async fn the_password_card_reports_a_weak_new_password_as_a_banner() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/password",
        Some(&session),
        Some(&[
            ("current_password", ADMIN_PASSWORD),
            ("new_password", "short"),
        ]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = html_body(refused).await;
    assert!(body.contains("at least 12"));
    assert!(body.contains(r#"id="account-password""#));
    assert!(body.contains("(bad_request)"));
}

/// The sign-out button is `hx-post`, so the htmx branch is the one a browser
/// takes — but the route has to answer a plain client too, and the cookie must
/// be cleared either way.
#[tokio::test]
async fn signing_out_clears_the_cookie_and_redirects_both_kinds_of_caller() {
    for hx in [false, true] {
        let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

        let mut builder = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/ui/logout")
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header("x-csrf-token", &session.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if hx {
            builder = builder.header("hx-request", "true");
        }
        let response = send_from(
            &app,
            builder.body(axum::body::Body::empty()).unwrap(),
            "127.0.0.1:40000",
        )
        .await;

        if hx {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(response.headers()["hx-redirect"], "/ui/login");
        } else {
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::LOCATION], "/ui/login");
        }

        // Leaving the cookie behind would send the browser to the sign-in page
        // still carrying a token the server has already forgotten.
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0"),
            "hx={hx}"
        );

        // And the session really is gone, not merely un-cookied.
        let after = admin_page(&app, "/ui/accounts", Some(&session), false).await;
        assert_eq!(after.status(), StatusCode::SEE_OTHER, "hx={hx}");
    }
}

// ---------------------------------------------------------------------------
// Auth redirects
// ---------------------------------------------------------------------------

/// Every page route, so a new one cannot quietly ship without a session check.
fn authenticated_pages() -> Vec<&'static str> {
    vec![
        "/ui/",
        "/ui/accounts",
        "/ui/accounts/some-id",
        "/ui/orders",
        "/ui/orders/some-id",
        // A download, but still a page route behind the session: a certificate
        // is public once issued, *which orders exist* is not.
        "/ui/orders/some-id/chain.pem",
        "/ui/expiring",
        "/ui/audit",
        "/ui/audit/1",
        "/ui/eab",
        "/ui/eab/some-kid",
        "/ui/nonces",
        "/ui/profiles",
        "/ui/profiles/default/filter",
        "/ui/account",
    ]
}

/// The pair `PageError` exists for.
///
/// A browser must *arrive* at the sign-in page; htmx must be told to navigate,
/// because a `303` is followed by `fetch` before htmx sees a header and the
/// sign-in page would be swapped into whatever element was clicked.
#[tokio::test]
async fn every_page_without_a_session_redirects_the_way_its_caller_understands() {
    let (app, _database) = test_admin_app(admin_config()).await;

    for path in authenticated_pages() {
        let browser = admin_page(&app, path, None, false).await;
        assert_eq!(browser.status(), StatusCode::SEE_OTHER, "GET {path}");
        assert_eq!(browser.headers()[header::LOCATION], "/ui/login", "{path}");
        assert!(!browser.headers().contains_key("hx-redirect"), "{path}");

        let htmx = admin_page(&app, path, None, true).await;
        assert_eq!(htmx.status(), StatusCode::NO_CONTENT, "htmx GET {path}");
        assert_eq!(htmx.headers()["hx-redirect"], "/ui/login", "{path}");
        assert!(!htmx.headers().contains_key(header::LOCATION), "{path}");
    }
}

#[tokio::test]
async fn an_expired_session_redirects_rather_than_answering_json() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;

    // Age the session past its absolute deadline.
    let hash = acme_proxy::webadmin::session::hash_token(&session.cookie);
    sqlx::query("UPDATE admin_sessions SET expires_at = 1 WHERE token_hash = ?")
        .bind(&hash)
        .execute(&database.pool)
        .await
        .unwrap();

    let response = admin_page(&app, "/ui/accounts", Some(&session), false).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/ui/login");
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/// Every mutating `/ui` route, in one table.
///
/// The twin of `admin_api.rs`'s `mutating_endpoints()`, and it carries the same
/// warning: `PageSessionWrite` makes the check structural — a mutating page
/// handler cannot reach a session without it — but a new handler taking
/// `PageSession` by mistake is exactly what this catches. **A `/ui` route added
/// and not added here is a review catch.**
fn mutating_page_endpoints() -> Vec<(Method, &'static str)> {
    vec![
        (Method::POST, "/ui/accounts/some-id/contact"),
        (Method::POST, "/ui/accounts/some-id/deactivate"),
        (Method::DELETE, "/ui/accounts/some-id"),
        (Method::POST, "/ui/orders/some-id/revoke"),
        (Method::DELETE, "/ui/orders/some-id"),
        (Method::POST, "/ui/eab"),
        (Method::POST, "/ui/eab/some-kid/revoke"),
        (Method::POST, "/ui/nonces/cleanup"),
        (Method::POST, "/ui/logout"),
        (Method::POST, "/ui/account/mfa/totp"),
        (Method::POST, "/ui/account/mfa/totp/confirm"),
        (Method::POST, "/ui/account/mfa/totp/disable"),
        (Method::POST, "/ui/account/mfa/recovery-codes"),
        (Method::POST, "/ui/account/password"),
        (Method::POST, "/ui/account/sessions/some-id/revoke"),
        (Method::POST, "/ui/operators/some-username/disable"),
        (Method::POST, "/ui/operators/some-username/enable"),
        (Method::POST, "/ui/operators/some-username/totp/reset"),
        (
            Method::POST,
            "/ui/operators/some-username/sessions/some-id/revoke",
        ),
        // `POST /ui/login/mfa` is deliberately absent. It is a plain form on a
        // page that has no CSRF token — the same trade `POST /ui/login` makes,
        // argued on `webadmin::session::PendingMfaSubmit` — so with an active
        // session it answers `401`, not the `403` this table asserts. It is
        // covered, origin gate and all, by `mfa_step_endpoints()` in
        // `tests/admin_api.rs`.
    ]
}

#[tokio::test]
async fn every_mutating_page_endpoint_refuses_a_missing_csrf_token() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for (method, path) in mutating_page_endpoints() {
        // The cookie, but no `X-CSRF-Token`: `admin_page` sends exactly that.
        let request = axum::http::Request::builder()
            .method(method.clone())
            .uri(path)
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = send_from(&app, request, "127.0.0.1:40000").await;

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must refuse a request with no CSRF token"
        );
        // And it must *not* bounce to the sign-in page: the session is live,
        // and a redirect would send the operator back with nothing explained.
        assert!(!response.headers().contains_key("hx-redirect"), "{path}");
        assert!(html_body(response).await.contains("csrf_failed"), "{path}");
    }
}

#[tokio::test]
async fn every_mutating_page_endpoint_refuses_another_sessions_csrf_token() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "bob",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database,
    )
    .await
    .unwrap();
    let other = admin_login(&app, "bob", ADMIN_PASSWORD).await;

    for (method, path) in mutating_page_endpoints() {
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
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::empty())
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
async fn a_cross_origin_page_write_is_refused_before_anything_else() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/ui/eab")
        .header(
            header::COOKIE,
            format!("__Host-acme_admin_session={}", session.cookie),
        )
        .header("x-csrf-token", &session.csrf)
        .header(header::ORIGIN, "http://evil.example.com")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = send_from(&app, request, "127.0.0.1:40000").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn page_reads_need_no_csrf_token() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    for path in authenticated_pages() {
        // `admin_page` sends the cookie and no token at all.
        let response = admin_page(&app, path, Some(&session), false).await;
        assert!(
            response.status() == StatusCode::OK || response.status() == StatusCode::NOT_FOUND,
            "GET {path} answered {}",
            response.status()
        );
    }
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// The whole reason every page template is named `.html`.
///
/// An EAB label is free operator text that reaches three pages, so it is the
/// natural vector: stored once, rendered on the list, the detail and the
/// creation banner.
#[tokio::test]
async fn a_stored_script_tag_is_escaped_everywhere_it_is_rendered() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;
    const HOSTILE: &str = "<script>alert(1)</script>";

    let created = admin_form_request(
        &app,
        Method::POST,
        "/ui/eab",
        Some(&session),
        Some(&[("label", HOSTILE), ("profile", "")]),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = html_body(created).await;
    assert!(!created_body.contains(HOSTILE));
    assert!(created_body.contains("&lt;script&gt;"));

    // The kid, so the detail page can be reached.
    let listed = html_body(admin_page(&app, "/ui/eab", Some(&session), false).await).await;
    assert!(
        !listed.contains(HOSTILE),
        "the list rendered a raw <script> tag"
    );
    assert!(listed.contains("&lt;script&gt;"));
}

/// The same vector from the other direction: a reverse name is not operator
/// text but *remote* text — whoever controls the PTR record for the address a
/// client connects from writes it — and it now reaches the account list and the
/// account card.
#[tokio::test]
async fn a_hostile_reverse_name_is_escaped_on_both_account_surfaces() {
    use acme_proxy::sqlite::account::Account;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    const HOSTILE: &str = "<script>alert(1)</script>";

    let (account, _) = Account::find_or_create(
        PROFILE,
        &[7u8, 7],
        vec![],
        &ClientContext {
            ip: Some("198.51.100.9".to_string()),
            ptr: Some(HOSTILE.to_string()),
            ..ClientContext::default()
        },
        &database,
    )
    .await
    .unwrap();

    for path in [
        "/ui/accounts".to_string(),
        format!("/ui/accounts/{}", account.id),
    ] {
        let body = html_body(admin_page(&app, &path, Some(&session), false).await).await;
        assert!(body.contains("198.51.100.9"), "{path}: {body}");
        assert!(
            !body.contains(HOSTILE),
            "{path} rendered a raw <script> tag"
        );
        assert!(body.contains("&lt;script&gt;"), "{path}: {body}");
    }
}

/// The other vector: a path segment, echoed into a `404` message by a document
/// that has no template engine behind it.
#[tokio::test]
async fn an_id_echoed_into_a_not_found_page_is_escaped() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    // Two shapes of caller-supplied path segment: an account id, and a profile
    // name. Both are interpolated into a message the `PageError` document
    // renders with no template, so both go through `escape_html` or neither.
    for path in [
        "/ui/accounts/%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/ui/profiles/%3Cscript%3Ealert(1)%3C%2Fscript%3E/filter",
    ] {
        let response = admin_page(&app, path, Some(&session), false).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");

        let body = html_body(response).await;
        assert!(!body.contains("<script>alert"), "{path}");
        assert!(body.contains("&lt;script&gt;"), "{path}");
        assert!(body.contains("<code>not_found</code>"), "{path}");
    }
}

// ---------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------

/// One URL per resource, two representations, chosen by `HX-Request`.
#[tokio::test]
async fn a_list_route_serves_a_document_or_a_bare_fragment() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 2).await;

    for (path, marker) in [
        ("/ui/accounts", "accounts-table"),
        ("/ui/orders", "orders-table"),
        ("/ui/expiring", "expiring-table"),
        ("/ui/eab", "eab-table"),
        ("/ui/nonces", "nonces-panel"),
    ] {
        let page = html_body(admin_page(&app, path, Some(&session), false).await).await;
        assert!(page.starts_with("<!doctype html>"), "{path}");
        assert!(page.contains("htmx.min.js"), "{path}");
        assert!(page.contains(marker), "{path}");

        let fragment = html_body(admin_page(&app, path, Some(&session), true).await).await;
        assert!(
            !fragment.contains("<!doctype html>"),
            "{path} served a whole document into an htmx swap"
        );
        assert!(!fragment.contains("<body"), "{path}");
        assert!(fragment.contains(marker), "{path}");
    }
}

#[tokio::test]
async fn the_layout_carries_the_csrf_token_every_write_depends_on() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let body = html_body(admin_page(&app, "/ui/", Some(&session), false).await).await;
    // `hx-headers` on <body> is the only way the token reaches a mutation.
    assert!(body.contains(&format!(
        r#"hx-headers='{{"X-CSRF-Token": "{}"}}'"#,
        session.csrf
    )));
    assert!(body.contains("alice"));
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// Seeds `count` accounts, each with one order, and returns their ids.
///
/// Every account is created from a real address with a reverse name, since that
/// is what the pages render — a `ClientContext::default()` would leave the
/// traceability columns `NULL` and every assertion about them vacuous.
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
            vec![],
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
async fn the_overview_counts_every_resource() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 3).await;

    let body = html_body(admin_page(&app, "/ui/", Some(&session), false).await).await;
    assert!(body.contains("Overview"));
    // Three accounts and three orders, and the endpoint the harness mounts.
    assert!(body.contains(r#"<div class="value">3</div>"#));
    assert!(body.contains(PROFILE));
}

#[tokio::test]
async fn an_account_page_shows_the_account_and_its_orders() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;

    let body = html_body(
        admin_page(
            &app,
            &format!("/ui/accounts/{}", ids[0]),
            Some(&session),
            false,
        )
        .await,
    )
    .await;
    assert!(body.contains(&ids[0]));
    assert!(body.contains("host0.example.com"));
    assert!(body.contains("account-card"));
    // Traceability: where the account was registered from, and where the key
    // was last seen. Both pairs, both with their reverse name.
    assert!(body.contains("Created from"), "{body}");
    assert!(body.contains("Last seen from"), "{body}");
    assert!(body.contains("203.0.113.0"), "{body}");
    assert!(body.contains("client0.example.net"), "{body}");
}

/// A reverse lookup that found nothing leaves the address alone, which is a
/// normal state rather than a broken row — the label must still appear and must
/// not be followed by a blank line where a name would go.
#[tokio::test]
async fn an_account_page_shows_an_address_that_never_resolved() {
    use acme_proxy::sqlite::account::Account;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let (account, _) = Account::find_or_create(
        PROFILE,
        &[9u8, 9],
        vec![],
        &ClientContext {
            ip: Some("198.51.100.4".to_string()),
            ptr: None,
            ..ClientContext::default()
        },
        &database,
    )
    .await
    .unwrap();

    let body = html_body(
        admin_page(
            &app,
            &format!("/ui/accounts/{}", account.id),
            Some(&session),
            false,
        )
        .await,
    )
    .await;
    assert!(body.contains("Created from"), "{body}");
    assert!(body.contains("198.51.100.4"), "{body}");
    assert!(body.contains("Last seen from"), "{body}");
}

/// The listing gave the public-key fingerprint's column to the address the key
/// was last seen from; the fingerprint stays on the detail card.
#[tokio::test]
async fn the_account_list_shows_where_each_key_was_last_seen() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 2).await;

    let body = html_body(admin_page(&app, "/ui/accounts", Some(&session), false).await).await;
    assert!(body.contains("Last seen from"), "{body}");
    assert!(body.contains("203.0.113.1"), "{body}");
    assert!(body.contains("client1.example.net"), "{body}");
    assert!(!body.contains("<th>Key</th>"), "{body}");

    // And the detail page is where the key still is.
    let card = html_body(
        admin_page(
            &app,
            &format!("/ui/accounts/{}", ids[0]),
            Some(&session),
            false,
        )
        .await,
    )
    .await;
    assert!(card.contains("Public key"), "{card}");
}

#[tokio::test]
async fn editing_a_contact_accepts_a_textarea_and_refuses_what_new_account_refuses() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let path = format!("/ui/accounts/{}/contact", ids[0]);

    let good = admin_form_request(
        &app,
        Method::POST,
        &path,
        Some(&session),
        Some(&[("contact", "mailto:a@example.com\nmailto:b@example.com")]),
    )
    .await;
    assert_eq!(good.status(), StatusCode::OK);
    let body = html_body(good).await;
    assert!(body.contains("Contact updated."));
    assert!(body.contains("mailto:a@example.com"));

    // The same refusal `newAccount` and `PATCH /api/accounts/{id}` give, shown
    // as a banner beside the box rather than as an error page.
    let bad = admin_form_request(
        &app,
        Method::POST,
        &path,
        Some(&session),
        Some(&[("contact", "tel:+15551234")]),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::OK);
    let body = html_body(bad).await;
    assert!(body.contains("unsupported scheme"));
    assert!(body.contains("bad_request"));
}

#[tokio::test]
async fn deactivating_an_account_swaps_the_card_and_deleting_it_redirects() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 2).await;

    let deactivated = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/accounts/{}/deactivate", ids[0]),
        Some(&session),
        Some(&[]),
    )
    .await;
    assert_eq!(deactivated.status(), StatusCode::OK);
    let body = html_body(deactivated).await;
    assert!(body.contains("Account deactivated"));
    assert!(body.contains(r#"<span class="badge deactivated">deactivated</span>"#));

    // A delete has no card to swap back, so it navigates.
    let deleted = admin_form_request(
        &app,
        Method::DELETE,
        &format!("/ui/accounts/{}", ids[1]),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(deleted.headers()[header::LOCATION], "/ui/accounts");

    assert_eq!(
        admin_page(
            &app,
            &format!("/ui/accounts/{}", ids[1]),
            Some(&session),
            false
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
}

/// The page grew a window when `Eab::list_all` went, so all three surfaces
/// read one query. The regression that matters is the pairing at the end: the
/// mint form re-renders the **first** page out of band, and the ordering is
/// what puts the credential just minted on it.
#[tokio::test]
async fn the_eab_list_pages_and_a_new_credential_lands_on_the_refreshed_page() {
    let mut config = admin_config();
    config.admin.page_size_max = 200;
    let (app, database, session) = test_admin_app_logged_in(config).await;

    let mut minted = Vec::new();
    for _ in 0..3 {
        minted.push(
            acme_proxy::sqlite::eab::Eab::create(None, None, &database)
                .await
                .unwrap()
                .kid
                .to_string(),
        );
    }

    // Newest first, so the first page of one holds the credential minted last.
    let first = html_body(admin_page(&app, "/ui/eab?limit=1", Some(&session), false).await).await;
    assert!(first.contains(minted[2].as_str()), "{first}");
    assert!(!first.contains(minted[0].as_str()), "{first}");
    assert!(first.contains("1–1 of 3"), "{first}");
    // The pager's links carry the window forward, and it is a page step rather
    // than a reload: `#eab-table` is the swap target, so the form above it and
    // the secret beside it survive.
    // The path is HTML-escaped by minijinja (`&#x2f;`), so the window is what
    // this asserts on -- the part a dropped filter or a miscomputed offset
    // would break.
    assert!(first.contains("?limit=1&amp;offset=1"), "{first}");
    assert!(first.contains(r##"hx-target="#eab-table""##), "{first}");

    let last =
        html_body(admin_page(&app, "/ui/eab?limit=1&offset=2", Some(&session), false).await).await;
    assert!(last.contains(minted[0].as_str()), "{last}");
    assert!(last.contains("3–3 of 3"), "{last}");

    // The fragment form, chosen off `HX-Request` like every other list route.
    let fragment = html_body(admin_page(&app, "/ui/eab", Some(&session), true).await).await;
    assert!(
        fragment.trim_start().starts_with("<div id=\"eab-table\""),
        "{fragment}"
    );

    // Minting from the *last* page still refreshes a table holding the new row:
    // the response renders page one whatever page the form was posted from,
    // which is only the right answer because the listing is newest first.
    let created = admin_form_request(
        &app,
        Method::POST,
        "/ui/eab",
        Some(&session),
        Some(&[("label", "fresh"), ("profile", "")]),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = html_body(created).await;
    let kid = body
        .split("<dt>Key ID</dt><dd><code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("the created panel must name the kid")
        .to_string();
    assert!(
        body.contains(&format!(r#"href="/ui/eab/{kid}""#)),
        "the refreshed table must hold the row the secret above it belongs to"
    );
    assert!(body.contains("1–4 of 4"), "{body}");
}

#[tokio::test]
async fn an_eab_secret_is_shown_once_and_the_list_refreshes_out_of_band() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let created = admin_form_request(
        &app,
        Method::POST,
        "/ui/eab",
        Some(&session),
        Some(&[("label", "team-a"), ("profile", "")]),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = html_body(created).await;
    assert!(body.contains("Copy the HMAC key now"));
    // The out-of-band table, so the new row appears without a reload -- which
    // is exactly when the secret would be gone.
    assert!(body.contains(r#"id="eab-table" hx-swap-oob="true""#));

    let kid = body
        .split("<dt>Key ID</dt><dd><code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("the created panel must name the kid")
        .to_string();

    // Nowhere else, ever.
    let listed = html_body(admin_page(&app, "/ui/eab", Some(&session), false).await).await;
    assert!(!listed.contains("hmacKey"));
    assert!(!listed.contains("Copy the HMAC key"));

    let detail =
        html_body(admin_page(&app, &format!("/ui/eab/{kid}"), Some(&session), false).await).await;
    assert!(detail.contains(&kid));
    assert!(!detail.contains("HMAC key"));

    let revoked = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/eab/{kid}/revoke"),
        Some(&session),
        Some(&[]),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let body = html_body(revoked).await;
    assert!(body.contains("Credential revoked"));
    assert!(body.contains(r#"<span class="badge revoked">revoked</span>"#));
}

#[tokio::test]
async fn creating_an_eab_for_an_unmounted_profile_is_refused() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/eab",
        Some(&session),
        Some(&[("label", ""), ("profile", "not-mounted")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(html_body(response).await.contains("no profile named"));
}

/// The one test that genuinely issues, so the revoke path has a certificate to
/// act on and the CA-side ledger belongs to the same object that serves the CRL.
#[tokio::test]
async fn revoking_an_issued_order_shows_a_banner_and_then_a_conflict() {
    use acme_proxy::signer::RequestedValidity;
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let (app, database, signer) = test_admin_app_with_signer(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    let (account, _) = Account::find_or_create(
        PROFILE,
        &[7u8, 7],
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
        use base64::prelude::*;
        BASE64_URL_SAFE_NO_PAD
            .decode(make_csr("revoke-me.example.com"))
            .unwrap()
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
    let (serial, spki) =
        acme_proxy::cert::cert_serial_and_spki(&first_certificate(&chain)).unwrap();
    order
        .finalize(chain, serial, spki, None, &database)
        .await
        .unwrap();

    let path = format!("/ui/orders/{}/revoke", order.id);
    let response = admin_form_request(
        &app,
        Method::POST,
        &path,
        Some(&session),
        Some(&[("reason", "1")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains("Certificate revoked"));
    assert!(body.contains(r#"<span class="badge revoked">revoked</span>"#));
    assert!(body.contains("reason 1"));
    assert!(
        !signer
            .crl_der()
            .await
            .expect("a local CA always has a CRL")
            .is_empty()
    );

    // A second attempt is the row's state, so it is a banner and the order
    // stays on screen -- not an error page.
    let again = admin_form_request(
        &app,
        Method::POST,
        &path,
        Some(&session),
        Some(&[("reason", "")]),
    )
    .await;
    assert_eq!(again.status(), StatusCode::OK);
    let body = html_body(again).await;
    assert!(body.contains("already_revoked"));
    assert!(body.contains("order-card"));
}

/// Issues a real certificate against the in-memory CA and returns the order id
/// with the PEM chain it was finalized with.
///
/// The whole `Order::create` → `signer.issue` → `Order::finalize` sequence,
/// because an order carrying a chain is not something `seed` can produce: the
/// column is only ever written by finalize.
async fn issue_into_an_order(
    database: &std::sync::Arc<acme_proxy::sqlite::db::Database>,
    signer: &std::sync::Arc<dyn acme_proxy::signer::SignerBackend>,
    name: &str,
) -> (String, String) {
    use acme_proxy::signer::RequestedValidity;
    use acme_proxy::sqlite::account::Account;
    use acme_proxy::sqlite::order::{Identifier, Order};

    let (account, _) = Account::find_or_create(
        PROFILE,
        &[9u8, 9],
        vec![],
        &ClientContext::default(),
        database,
    )
    .await
    .unwrap();
    let identifier = Identifier::dns(name);
    let mut order = Order::create(
        PROFILE,
        account.id,
        vec![identifier.clone()],
        2_000_000_000,
        None,
        None,
        database,
    )
    .await
    .unwrap();

    let csr_der = {
        use base64::prelude::*;
        BASE64_URL_SAFE_NO_PAD.decode(make_csr(name)).unwrap()
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
    let leaf_der = first_certificate(&chain);
    let (serial, spki) = acme_proxy::cert::cert_serial_and_spki(&leaf_der).unwrap();
    // The leaf's own `notAfter`, exactly as `post_finalize` stamps it — the
    // helper is only useful to the extent it produces the row production does,
    // and the card now renders this column.
    let cert_not_after = acme_proxy::cert::cert_validity(&leaf_der)
        .ok()
        .map(|(_, not_after)| not_after);
    order
        .finalize(chain.clone(), serial, spki, cert_not_after, database)
        .await
        .unwrap();

    (order.id.to_string(), chain)
}

/// The card shows the certificate itself, not the ACME URL.
///
/// That URL is reachable only by signed POST-as-GET, so a browser handed it
/// gets nothing — it was a dead string on the page, and the PEM it should have
/// been showing was already in the row.
#[tokio::test]
async fn an_issued_order_card_shows_the_chain_and_offers_it_for_download() {
    let (app, database, signer) = test_admin_app_with_signer(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    let (order_id, chain) = issue_into_an_order(&database, &signer, "chain.example.com").await;

    let response = admin_page(
        &app,
        &format!("/ui/orders/{order_id}"),
        Some(&session),
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;

    assert!(
        body.contains("-----BEGIN CERTIFICATE-----"),
        "the card must render the PEM itself"
    );
    assert!(
        body.contains(&format!("/ui/orders/{order_id}/chain.pem")),
        "and offer the download route"
    );
    // The dead string is gone. The ACME certificate URL lives under the
    // profile prefix, so this is what it would have looked like.
    assert!(
        !body.contains("/profile/default/certificate/"),
        "the ACME certificate URL is unreachable from a browser and must not \
         be presented as if it were a link"
    );
    // The leaf described three ways, not one. The serial is what an abuse
    // report or `/api/audit?certSerial=` is keyed on, and until the order
    // renderings were made to agree, no surface would tell an operator what it
    // was for an order they were looking at.
    let (serial, _) = acme_proxy::cert::cert_serial_and_spki(&first_certificate(&chain)).unwrap();
    assert!(
        body.contains("<dt>Serial</dt>"),
        "the card must name the serial"
    );
    assert!(
        body.contains(&serial),
        "and it must be this order's: {serial}"
    );
    assert!(
        body.contains("<dt>Certificate expires</dt>"),
        "the leaf's own expiry is a different date from the requested window \
         above it, and the card carried neither"
    );

    let download = admin_page(
        &app,
        &format!("/ui/orders/{order_id}/chain.pem"),
        Some(&session),
        false,
    )
    .await;
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        download.headers()[header::CONTENT_TYPE],
        "application/pem-certificate-chain"
    );
    assert_eq!(
        download.headers()[header::CONTENT_DISPOSITION],
        format!("attachment; filename=\"{order_id}.pem\"")
    );
    assert_eq!(
        html_body(download).await,
        chain,
        "the download must be the stored chain byte for byte"
    );
}

/// An order that never reached issuance has no chain, so the route is a `404`
/// rather than a zero-byte `.pem` — an empty file reads as a broken
/// certificate, not an absent one.
#[tokio::test]
async fn downloading_a_chain_from_an_unissued_order_is_a_404() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();
    let order_id = orders[0].id;

    let response = admin_page(
        &app,
        &format!("/ui/orders/{order_id}/chain.pem"),
        Some(&session),
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // And an order that does not exist at all is the same answer, so the route
    // never distinguishes "no certificate" from "no order" to a caller
    // guessing ids.
    let missing = admin_page(
        &app,
        "/ui/orders/no-such-order/chain.pem",
        Some(&session),
        false,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoking_an_order_with_no_certificate_is_a_banner_not_a_page() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();

    let response = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/orders/{}/revoke", orders[0].id),
        Some(&session),
        Some(&[("reason", "")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains("order_not_issued"));
    assert!(body.contains("order-card"));
}

/// The three refusals the revoke control can produce that are not about the
/// order's own state, and the one that is not a number at all.
#[tokio::test]
async fn revoking_covers_the_refusals_that_are_not_the_rows_state() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();
    let path = format!("/ui/orders/{}/revoke", orders[0].id);

    // A reason that is not a number replaces the page: the form could not have
    // produced it, so it is a bad request rather than a banner.
    let bad = admin_form_request(
        &app,
        Method::POST,
        &path,
        Some(&session),
        Some(&[("reason", "not-a-number")]),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert!(html_body(bad).await.contains("is not a number"));

    // An order that does not exist at all.
    let missing = admin_form_request(
        &app,
        Method::POST,
        "/ui/orders/no-such-order/revoke",
        Some(&session),
        Some(&[("reason", "")]),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(html_body(missing).await.contains("no such order"));
}

/// An order whose profile this process no longer mounts cannot be revoked
/// here, and saying so beats revoking against whatever backend came first.
#[tokio::test]
async fn revoking_an_order_from_an_unmounted_profile_is_a_banner() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();

    // Move the row to a profile the harness does not mount.
    sqlx::query("UPDATE orders SET profile = 'gone' WHERE id = ?")
        .bind(orders[0].id)
        .execute(&database.pool)
        .await
        .unwrap();

    let response = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/orders/{}/revoke", orders[0].id),
        Some(&session),
        Some(&[("reason", "")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains("profile_not_mounted"));
    assert!(body.contains("order-card"));
}

#[tokio::test]
async fn deleting_an_order_redirects_to_the_list() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 1).await;
    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();
    let path = format!("/ui/orders/{}", orders[0].id);

    let deleted = admin_form_request(&app, Method::DELETE, &path, Some(&session), None).await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(deleted.headers()[header::LOCATION], "/ui/orders");

    assert_eq!(
        admin_page(&app, &path, Some(&session), false)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // And a second delete has nothing left to act on.
    assert_eq!(
        admin_form_request(&app, Method::DELETE, &path, Some(&session), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_order_list_filters_and_the_detail_links_back_to_its_account() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let ids = seed(&database, 3).await;

    let all = html_body(admin_page(&app, "/ui/orders", Some(&session), false).await).await;
    assert!(all.contains("host0.example.com"));
    assert!(all.contains("host2.example.com"));

    let filtered = html_body(
        admin_page(
            &app,
            &format!("/ui/orders?accountId={}", ids[0]),
            Some(&session),
            true,
        )
        .await,
    )
    .await;
    assert!(filtered.contains("host0.example.com"));
    assert!(!filtered.contains("host2.example.com"));

    let (orders, _) = acme_proxy::sqlite::order::Order::search(
        &acme_proxy::sqlite::order::OrderQuery {
            account_id: Some(ids[0].clone()),
            limit: 10,
            ..Default::default()
        },
        &database,
    )
    .await
    .unwrap();
    let detail = html_body(
        admin_page(
            &app,
            &format!("/ui/orders/{}", orders[0].id),
            Some(&session),
            false,
        )
        .await,
    )
    .await;
    // `accountId` is admin-only and absent from the ACME order object; without
    // it this link could not exist.
    assert!(detail.contains(&format!(r#"href="/ui/accounts/{}""#, ids[0])));
}

#[tokio::test]
async fn a_page_limit_over_the_ceiling_is_clamped_rather_than_refused() {
    let mut config = admin_config();
    config.admin.page_size_max = 2;
    let (app, database) = test_admin_app(config).await;
    acme_proxy::admin::users::create_user(
        "alice",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let session = admin_login(&app, "alice", ADMIN_PASSWORD).await;
    seed(&database, 5).await;

    let body =
        html_body(admin_page(&app, "/ui/accounts?limit=500", Some(&session), true).await).await;
    // Two rows shown, five in total, and a next page offered.
    assert!(body.contains("1–2 of 5"));
    assert!(body.contains("offset=2"));
}

#[tokio::test]
async fn sweeping_the_nonce_table_reports_what_it_removed() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_form_request(
        &app,
        Method::POST,
        "/ui/nonces/cleanup",
        Some(&session),
        Some(&[("ttlSeconds", "0")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains("Swept"));
    assert!(body.contains("nonces-panel"));
}

#[tokio::test]
async fn the_profiles_page_warns_when_an_endpoint_bypasses_validation() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let body = html_body(admin_page(&app, "/ui/profiles", Some(&session), false).await).await;
    assert!(body.contains(PROFILE));
    // The harness registry bypasses, which is what makes this assertable at
    // all -- and the warning is the whole point of the page.
    assert!(body.contains("challenge.bypass"));
    assert!(body.contains(r#"<span class="badge invalid">bypassed</span>"#));
    // The gap this page used to leave: it warns that `[filter]` is all such an
    // endpoint has, and now says where to read it.
    assert!(body.contains(&format!(r#"href="/ui/profiles/{PROFILE}/filter""#)));
}

/// The answer to "and what does that policy say?", which `/ui/profiles` warns
/// about and used to leave to an SSH session.
#[tokio::test]
async fn the_filter_policy_page_shows_what_the_process_is_enforcing() {
    let (app, _database, session) =
        test_admin_app_logged_in_with_filter(admin_config(), test_filter_policy()).await;

    let path = format!("/ui/profiles/{PROFILE}/filter");
    let body = html_body(admin_page(&app, &path, Some(&session), false).await).await;

    assert!(body.starts_with("<!doctype html>"), "{body}");
    assert!(body.contains("mgmt-net"), "{body}");
    assert!(body.contains("allowed_ip"), "{body}");
    assert!(body.contains("connection and identifiers"), "{body}");
    assert!(body.contains("identifiers only"), "{body}");

    // The re-parenthesized condition, end to end: configuration -> `build` ->
    // `policy_json` -> template. The operator wrote it without parentheses.
    assert!(body.contains("names or (mgmt-net and names)"), "{body}");

    // The default effect, and the warn rule that matches without deciding.
    assert!(
        body.contains(r#"<span class="badge deny">deny</span>"#),
        "{body}"
    );
    assert!(
        body.contains(r#"<span class="badge allow">allow</span>"#),
        "{body}"
    );
    assert!(
        body.contains(r#"<span class="badge warn">does not decide</span>"#),
        "{body}"
    );

    // Urgency and effect are classes, never inline styles -- `style-src 'self'`
    // blocks those.
    assert!(!body.contains("style="), "{body}");

    // Read-only: no form and no htmx target of its own. The layout's own
    // sign-out button is the only `hx-post` a page ever carries, so the
    // assertion that means anything is the unroutable-verb loop at the end.
    assert!(!body.contains("<form"), "{body}");
    assert!(!body.contains("hx-target"), "{body}");

    // A sub-page of Profiles, not a nav entry of its own.
    assert!(
        body.contains(r#"<a href="/ui/profiles" class="active">Profiles</a>"#),
        "{body}"
    );

    // No fragment: there is nothing on this page for htmx to swap, so an
    // `HX-Request` still gets the whole document rather than a bare partial.
    let htmx = html_body(admin_page(&app, &path, Some(&session), true).await).await;
    assert!(htmx.starts_with("<!doctype html>"), "{htmx}");

    // An unmounted endpoint is a `404`, not an empty policy.
    assert_eq!(
        admin_page(&app, "/ui/profiles/nope/filter", Some(&session), false)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // Nothing writes: every other verb on the path is unroutable, which is why
    // this route contributes no entry to `mutating_page_endpoints()`.
    for method in [Method::POST, Method::DELETE, Method::PATCH] {
        let response = admin_form_request(&app, method.clone(), &path, Some(&session), None).await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} {path} answered {}",
            response.status()
        );
    }
}

/// An endpoint that filters nothing says so, and says nothing else -- the
/// page's parity with `render_policy`, which returns before it prints a
/// default or a table.
#[tokio::test]
async fn the_filter_policy_page_says_plainly_when_nothing_is_configured() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let body = html_body(
        admin_page(
            &app,
            &format!("/ui/profiles/{PROFILE}/filter"),
            Some(&session),
            false,
        )
        .await,
    )
    .await;

    assert!(body.contains("filters nothing"), "{body}");
    assert!(!body.contains("Evaluated at"), "{body}");
    assert!(!body.contains("first match decides"), "{body}");
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_pages_carry_a_content_security_policy_strict_enough_to_matter() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response = admin_page(&app, "/ui/", Some(&session), false).await;
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string();

    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    // The two that would quietly undo the whole policy.
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("unsafe-eval"));

    // And the page really does live within it: no inline script, no inline
    // style attribute, no remote origin.
    let body = html_body(response).await;
    assert!(!body.contains("<script>"));
    assert!(!body.contains(" style=\""));
    assert!(!body.contains("//cdn."));
}

#[tokio::test]
async fn the_assets_are_served_from_this_origin_with_their_own_types() {
    let (app, _database) = test_admin_app(admin_config()).await;

    for (path, content_type, marker) in [
        (
            "/ui/static/htmx.min.js",
            "text/javascript; charset=utf-8",
            "htmx",
        ),
        (
            "/ui/static/admin.css",
            "text/css; charset=utf-8",
            ".htmx-indicator",
        ),
    ] {
        // No session: the sign-in page needs the stylesheet before there is one.
        let response = admin_page(&app, path, None, false).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(html_body(response).await.contains(marker), "{path}");
    }

    assert_eq!(
        admin_page(&app, "/ui/static/../Cargo.toml", None, false)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_root_redirects_to_the_panel_and_an_unknown_page_is_html() {
    let (app, _database) = test_admin_app(admin_config()).await;

    let root = admin_page(&app, "/", None, false).await;
    assert_eq!(root.status(), StatusCode::SEE_OTHER);
    assert_eq!(root.headers()[header::LOCATION], "/ui/");

    let missing = admin_page(&app, "/ui/nothing-here", None, false).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let body = html_body(missing).await;
    assert!(body.starts_with("<!doctype html>"));
    assert!(body.contains("no such page"));
}

/// The HTML fallback must not reach into `/api`, whose callers are scripts.
#[tokio::test]
async fn the_api_keeps_its_json_shape_beside_the_html_fallback() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let response =
        admin_request(&app, Method::GET, "/api/nothing-here", Some(&session), None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(response).await["error"], "not_found");
}

/// Asking for recovery codes with no factor is a banner, not a page.
///
/// The `/api` twin of this is covered; the page branch that renders it was not,
/// and it is the one an operator actually sees.
#[tokio::test]
async fn recovery_codes_without_a_factor_are_refused_on_the_card() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;

    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/account/mfa/recovery-codes",
        Some(&session),
        Some(&[]),
    )
    .await;

    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let body = html_body(refused).await;
    assert!(body.contains("no second factor"));
    assert!(
        body.contains(r#"id="account-mfa""#),
        "the card's own state is a banner, not an error page"
    );
}

/// The `/ui` twin of `the_audit_api_lists_pages_and_refuses_every_way_of_writing_to_it`.
///
/// Read-only, so it adds nothing to `mutating_page_endpoints()` — there is no
/// control in the table and no route behind one. What is asserted here instead
/// is the escaping: an audit row carries a `User-Agent` and a `detail` straight
/// off the wire, which is the same stored-XSS shape as an EAB label.
#[tokio::test]
async fn the_audit_page_lists_rows_escapes_them_and_offers_nothing_to_write() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;

    let id = AuditEntry::insert(
        AuditRecord::new(AuditEvent::CertificateIssued, PROFILE, Actor::admin("root"))
            .with_account("acct-1")
            .with_serial("0a0b")
            .with_client(ClientContext {
                ip: Some("203.0.113.7".to_string()),
                ptr: Some("host.example.com".to_string()),
                user_agent: Some("<script>alert(1)</script>".to_string()),
                request_id: Some("req-1".to_string()),
            }),
        &database,
    )
    .await
    .unwrap();
    AuditEntry::insert(
        AuditRecord::new(
            AuditEvent::CertificateRevokeFailed,
            PROFILE,
            Actor::system(),
        )
        .with_reason("unauthorized"),
        &database,
    )
    .await
    .unwrap();

    let body = html_body(admin_page(&app, "/ui/audit", Some(&session), false).await).await;
    assert!(body.contains("certificate_issued"), "{body}");
    assert!(body.contains("certificate_revoke_failed"), "{body}");
    assert!(body.contains("203.0.113.7"), "{body}");
    assert!(body.contains("host.example.com"), "{body}");
    // A row with no client renders the dash, not a blank cell.
    assert!(body.contains('—'), "{body}");
    // The filter form is an `hx-get`, which is a read.
    assert!(body.contains(r#"hx-get="/ui/audit""#), "{body}");

    // One row in full, with the attacker-controlled header escaped.
    let detail =
        html_body(admin_page(&app, &format!("/ui/audit/{id}"), Some(&session), false).await).await;
    assert!(detail.contains("req-1"), "{detail}");
    assert!(
        !detail.contains("<script>alert(1)</script>"),
        "the User-Agent must be escaped: {detail}"
    );
    assert!(detail.contains("&lt;script&gt;"), "{detail}");

    // The fragment form of the list, chosen off `HX-Request` like every other
    // list route here.
    let fragment = html_body(admin_page(&app, "/ui/audit", Some(&session), true).await).await;
    assert!(
        fragment.trim_start().starts_with("<div id=\"audit-table\""),
        "{fragment}"
    );
    assert!(!fragment.contains("<nav>"), "{fragment}");
    // Read-only: the table itself offers nothing that writes. Asserted on the
    // fragment rather than the document, because `layout.html` carries the
    // sign-out control and would make the whole page fail this.
    assert!(!fragment.contains("hx-delete"), "{fragment}");
    assert!(!fragment.contains("hx-post"), "{fragment}");

    // An unknown row is a 404 page, not a blank one.
    let missing = admin_page(&app, "/ui/audit/999999", Some(&session), false).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // Writing is unroutable in every spelling.
    for method in [Method::POST, Method::DELETE] {
        let response = admin_request(&app, method.clone(), "/ui/audit", Some(&session), None).await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} /ui/audit answered {}",
            response.status()
        );
    }
}

/// The `/ui` surface fails closed too — and is never mistaken for signed out.
///
/// `admin_api.rs`'s twin covers the JSON API. The page layer is the half that
/// had no DB-failure coverage at all, and it is the more dangerous of the two:
/// an API route answers a problem document, but a page route's refusal is a
/// *redirect to the sign-in page*, which is indistinguishable from "your
/// session ended" — and a session check that read an unreadable table as "no
/// constraint" would instead render the page. So both are asserted: no `200`,
/// and no redirect that would tell a browser it merely needs to sign in again.
#[tokio::test]
async fn the_page_surface_fails_closed_when_the_database_is_gone() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    database.pool.close().await;

    for path in authenticated_pages() {
        for hx in [false, true] {
            let response = common::admin_page(&app, path, Some(&session), hx).await;
            let status = response.status();
            assert_ne!(
                status,
                StatusCode::OK,
                "GET {path} (hx={hx}) rendered a page with no database to authorise against"
            );
            assert!(
                !status.is_redirection(),
                "GET {path} (hx={hx}) answered {status}: a database that cannot be read \
                 is a server fault, not an expired session, and sending the operator \
                 back to sign in hides an outage behind a login form"
            );
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "GET {path} (hx={hx}) must say it could not authorise"
            );
        }
    }
}

/// One issued order whose leaf expires at `not_after`, with a placeholder
/// chain — `tests/admin_api.rs`'s `expiring` and for its reason.
async fn expiring_row(
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

/// The `/ui` twin of
/// `the_expiring_api_lists_annotates_filters_and_refuses_every_way_of_writing_to_it`.
///
/// Read-only, so it adds nothing to `mutating_page_endpoints()` — there is no
/// control in the table and no route behind one, because renewal is the
/// client's own ACME flow. What is asserted here instead is the rendering an
/// operator actually reads: the annotation's presence and *absence*, the
/// urgency class, the hidden-count line that keeps the pager honest, and the
/// escaping of an identifier, which is text a client chose.
#[tokio::test]
async fn the_expiring_page_annotates_rows_escapes_them_and_offers_nothing_to_write() {
    use acme_proxy::sqlite::account::Account;

    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    let (account, _) = Account::find_or_create(
        PROFILE,
        b"expiry-key",
        vec![],
        &ClientContext::default(),
        &database,
    )
    .await
    .unwrap();

    const DAY: i64 = 24 * 60 * 60;
    let now = now_unix();
    let soon = expiring_row(&database, account.id, &["soon.example.com"], now + 3 * DAY).await;
    let mid = expiring_row(&database, account.id, &["mid.example.com"], now + 20 * DAY).await;
    let renewal = expiring_row(
        &database,
        account.id,
        &["soon.example.com"],
        now + 300 * DAY,
    )
    .await;
    // An identifier is text a client typed: the same stored-XSS shape as an
    // EAB label, on a page that renders it into a table cell.
    expiring_row(
        &database,
        account.id,
        &["<script>alert(1)</script>"],
        now + 5 * DAY,
    )
    .await;

    let body = html_body(admin_page(&app, "/ui/expiring", Some(&session), false).await).await;
    assert!(body.contains("soon.example.com"), "{body}");
    assert!(
        body.contains(&format!(r#"href="/ui/orders/{mid}""#)),
        "{body}"
    );
    // The annotation links to the successor, and says which signal produced it.
    assert!(
        body.contains(&format!(r#"href="/ui/orders/{renewal}""#)),
        "{body}"
    );
    assert!(body.contains("identifiers"), "{body}");
    // And a row nothing has replaced renders the dash, not a blank cell.
    assert!(body.contains('—'), "{body}");
    // Urgency is a class, never an inline `style` — `style-src 'self'` blocks
    // the attribute outright.
    assert!(body.contains("badge urgent"), "{body}");
    assert!(body.contains("badge soon"), "{body}");
    assert!(!body.contains("style="), "{body}");
    // Both rows link through to the order and the account behind them.
    assert!(
        body.contains(&format!(r#"href="/ui/orders/{soon}""#)),
        "{body}"
    );
    assert!(
        body.contains(&format!(r#"href="/ui/accounts/{}""#, account.id)),
        "{body}"
    );
    // The attacker-controlled identifier is escaped.
    assert!(!body.contains("<script>alert(1)</script>"), "{body}");
    assert!(body.contains("&lt;script&gt;"), "{body}");
    // The filter form is an `hx-get`, which is a read.
    assert!(body.contains(r#"hx-get="/ui/expiring""#), "{body}");

    // ...and the form's "every profile" option submits `profile=`, not an
    // omitted key, so the exact URL htmx pushes must still list everything.
    // This is the reported bug: the page was right until an operator touched
    // the filter, and empty from then on.
    let blank = html_body(
        admin_page(
            &app,
            "/ui/expiring?profile=&days=30&superseded=",
            Some(&session),
            true,
        )
        .await,
    )
    .await;
    assert!(blank.contains("soon.example.com"), "{blank}");
    assert!(blank.contains("mid.example.com"), "{blank}");
    assert!(!blank.contains("Nothing is expiring"), "{blank}");
    // Nothing is hidden by default, so the count line is absent.
    assert!(!body.contains("hidden as already replaced"), "{body}");

    // Hiding the replaced rows drops them and says how many, leaving `total`
    // counting the window — the limit documented on `admin::list_expiring`,
    // and the reason the page says it out loud.
    let hidden =
        html_body(admin_page(&app, "/ui/expiring?superseded=hide", Some(&session), false).await)
            .await;
    assert!(!hidden.contains("soon.example.com"), "{hidden}");
    assert!(hidden.contains("mid.example.com"), "{hidden}");
    assert!(hidden.contains("1 row on this page"), "{hidden}");
    assert!(hidden.contains("hidden as already replaced"), "{hidden}");

    // The window narrows, and the pager's links carry it forward.
    let narrow =
        html_body(admin_page(&app, "/ui/expiring?days=4", Some(&session), false).await).await;
    assert!(narrow.contains("soon.example.com"), "{narrow}");
    assert!(!narrow.contains("mid.example.com"), "{narrow}");

    // An empty window says so rather than rendering a bare table.
    let empty =
        html_body(admin_page(&app, "/ui/expiring?days=1", Some(&session), false).await).await;
    assert!(
        empty.contains("Nothing is expiring in this window."),
        "{empty}"
    );

    // The fragment form, chosen off `HX-Request` like every other list route,
    // and carrying no control of its own.
    let fragment = html_body(admin_page(&app, "/ui/expiring", Some(&session), true).await).await;
    assert!(
        fragment
            .trim_start()
            .starts_with("<div id=\"expiring-table\""),
        "{fragment}"
    );
    assert!(!fragment.contains("hx-post"), "{fragment}");
    assert!(!fragment.contains("hx-delete"), "{fragment}");

    // The nav entry is on every page, not only this one.
    let elsewhere = html_body(admin_page(&app, "/ui/", Some(&session), false).await).await;
    assert!(elsewhere.contains(r#"href="/ui/expiring""#), "{elsewhere}");

    // Nothing writes: every other verb on the path is unroutable.
    for method in [Method::POST, Method::DELETE, Method::PATCH] {
        let response = admin_form_request(
            &app,
            method.clone(),
            "/ui/expiring",
            Some(&session),
            Some(&[]),
        )
        .await;
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} /ui/expiring answered {}",
            response.status()
        );
    }
}

/// The same rule as `admin_api::a_blank_filter_is_absent_on_every_list`, on the
/// front end that actually produces the shape.
///
/// A `<select>` inside a submitted form always contributes its `name`, so the
/// panel's "every profile" / "any status" options arrive as `profile=` and
/// `status=` rather than as omitted keys — and every list emptied itself the
/// moment an operator touched its filter form. `/ui/orders` was worse than
/// empty: `status=` reached `OrderStatus::from_str`, which refuses an unknown
/// spelling by name, so "any status" answered `400`.
///
/// Each URL below is what htmx pushes with every control left at its default.
#[tokio::test]
async fn a_blank_filter_leaves_every_list_page_unfiltered() {
    let (app, database, session) = test_admin_app_logged_in(admin_config()).await;
    seed(&database, 3).await;

    for (path, blank) in [
        ("/ui/accounts", "/ui/accounts?profile="),
        ("/ui/orders", "/ui/orders?profile=&status=&accountId="),
        (
            "/ui/audit",
            "/ui/audit?profile=&event=&outcome=&accountId=&certSerial=",
        ),
    ] {
        let response = admin_page(&app, blank, Some(&session), true).await;
        assert_eq!(response.status(), StatusCode::OK, "{blank}");
        let filtered = html_body(response).await;
        let unfiltered = html_body(admin_page(&app, path, Some(&session), true).await).await;
        assert_eq!(
            filtered.matches("<tr").count(),
            unfiltered.matches("<tr").count(),
            "{blank} filtered on the empty string:\n{filtered}"
        );
    }

    // The identifiers are on the page, not merely a matching row count.
    let orders = html_body(
        admin_page(
            &app,
            "/ui/orders?profile=&status=&accountId=",
            Some(&session),
            true,
        )
        .await,
    )
    .await;
    for index in 0..3 {
        assert!(
            orders.contains(&format!("host{index}.example.com")),
            "{orders}"
        );
    }

    // A named filter still filters.
    let named = html_body(
        admin_page(
            &app,
            "/ui/orders?profile=nothing-here",
            Some(&session),
            true,
        )
        .await,
    )
    .await;
    assert!(!named.contains("host0.example.com"), "{named}");

    // And a genuinely unknown status is still refused by name, since that
    // refusal is what tells an operator a typo from an empty state.
    assert_eq!(
        admin_page(&app, "/ui/orders?status=typo", Some(&session), true)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

// ---------------------------------------------------------------------------
// Own sessions -- the sessions card on `/ui/account`
// ---------------------------------------------------------------------------

/// The card `account/index.html` gained: every one of the caller's own live
/// sessions, the current one labelled, and a working "Revoke" on the others.
#[tokio::test]
async fn the_account_page_lists_sessions_and_can_revoke_a_non_current_one() {
    let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;
    let _other = admin_login(&app, "alice", ADMIN_PASSWORD).await;

    let body = html_body(admin_page(&app, "/ui/account", Some(&session), false).await).await;
    assert!(body.contains("Sessions"));
    assert!(body.contains("this session"));
    // Two rows: the header's own `<tr>` plus one per session, so count the
    // per-row action button instead.
    assert_eq!(body.matches(r#"class="danger""#).count(), 2, "{body}");

    let listed = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/account/sessions",
            Some(&session),
            None,
        )
        .await,
    )
    .await;
    let other_id = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/account/sessions/{other_id}/revoke"),
        Some(&session),
        Some(&[]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = html_body(response).await;
    assert!(body.contains(r#"id="account-sessions""#), "{body}");
    assert!(body.contains("Session revoked"));
    // One row left: the current session.
    assert_eq!(body.matches(r#"class="danger""#).count(), 1, "{body}");

    // The revoking session is still perfectly usable.
    assert_eq!(
        admin_page(&app, "/ui/account", Some(&session), false)
            .await
            .status(),
        StatusCode::OK
    );
}

/// Revoking the session making the request behaves exactly like
/// `POST /ui/logout` without `?all=true` — the
/// `signing_out_clears_the_cookie_and_redirects_both_kinds_of_caller` shape,
/// reached through the sessions card instead of the sign-out button.
#[tokio::test]
async fn revoking_the_current_session_from_the_account_page_signs_out() {
    for hx in [false, true] {
        let (app, _database, session) = test_admin_app_logged_in(admin_config()).await;
        let listed = json_body(
            admin_request(
                &app,
                Method::GET,
                "/api/account/sessions",
                Some(&session),
                None,
            )
            .await,
        )
        .await;
        let own_id = listed["items"][0]["id"].as_str().unwrap().to_string();

        let mut builder = axum::http::Request::builder()
            .method(Method::POST)
            .uri(format!("/ui/account/sessions/{own_id}/revoke"))
            .header(
                header::COOKIE,
                format!("__Host-acme_admin_session={}", session.cookie),
            )
            .header("x-csrf-token", &session.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if hx {
            builder = builder.header("hx-request", "true");
        }
        let response = send_from(
            &app,
            builder.body(axum::body::Body::empty()).unwrap(),
            "127.0.0.1:40000",
        )
        .await;

        if hx {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(response.headers()["hx-redirect"], "/ui/login");
        } else {
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::LOCATION], "/ui/login");
        }
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0"),
            "hx={hx}"
        );

        let after = admin_page(&app, "/ui/accounts", Some(&session), false).await;
        assert_eq!(after.status(), StatusCode::SEE_OTHER, "hx={hx}");
    }
}

// ---------------------------------------------------------------------------
// The operators surface -- `/ui/operators`
// ---------------------------------------------------------------------------

async fn app_with_bob() -> (axum::Router, AdminSessionHandle, AdminSessionHandle) {
    let (app, database, alice) = test_admin_app_logged_in(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "bob",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let bob = admin_login(&app, "bob", ADMIN_PASSWORD).await;
    (app, alice, bob)
}

#[tokio::test]
async fn the_operators_page_lists_every_operator_and_badges_the_callers_own_row() {
    let (app, alice, _bob) = app_with_bob().await;
    let body = html_body(admin_page(&app, "/ui/operators", Some(&alice), false).await).await;
    assert!(body.contains("alice"));
    assert!(body.contains("bob"));
    assert!(body.contains(">you<"), "{body}");
    assert!(body.contains(r#"href="/ui/account""#));
    assert!(body.contains(r#"href="/ui/operators/bob""#));
}

/// Managing yourself stays on `/ui/account` — this is what stops the
/// operators page from growing a half-disabled copy of it.
#[tokio::test]
async fn the_operator_detail_page_redirects_the_caller_to_their_own_account_page() {
    for hx in [false, true] {
        let (app, alice, _bob) = app_with_bob().await;
        let response = admin_page(&app, "/ui/operators/alice", Some(&alice), hx).await;
        if hx {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(response.headers()["hx-redirect"], "/ui/account");
        } else {
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::LOCATION], "/ui/account");
        }
    }
}

/// The whole feature, end to end, through the page: disable, enable, reset a
/// second factor, and revoke one session — all on a colleague's account, all
/// re-rendering the one `#operator-detail` fragment, and all refused with a
/// banner rather than a page when the step-up password is missing or wrong.
#[tokio::test]
async fn the_operator_detail_page_manages_another_operator_end_to_end() {
    let (app, database, alice_seed) = test_admin_app_logged_in(admin_config()).await;
    acme_proxy::admin::users::create_user(
        "bob",
        ADMIN_PASSWORD,
        &PasswordContext::empty(),
        database.clone(),
    )
    .await
    .unwrap();
    let _bob_seed = admin_login(&app, "bob", ADMIN_PASSWORD).await;
    // Give bob a second live session so the revoke case has something to leave
    // behind.
    let bob_second = admin_login(&app, "bob", ADMIN_PASSWORD).await;

    // Alice enrols a factor, so every mutation below is genuinely gated.
    let secret = enrol_totp(database.clone(), "alice").await;
    let alice = admin_login_mfa(&app, database.clone(), "alice", ADMIN_PASSWORD, &secret).await;
    let _ = alice_seed; // superseded by the MFA-promoted session above

    let body = html_body(admin_page(&app, "/ui/operators/bob", Some(&alice), false).await).await;
    assert!(body.contains("bob"));
    assert!(body.contains(r#"id="operator-detail""#));
    assert!(body.contains(r#"id="operator-step-up-password""#));

    // Missing the step-up password: a banner on the same fragment, not an
    // error page.
    let refused = admin_form_request(
        &app,
        Method::POST,
        "/ui/operators/bob/disable",
        Some(&alice),
        Some(&[]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = html_body(refused).await;
    assert!(body.contains("That password is not correct"));
    assert!(body.contains(r#"id="operator-detail""#));

    // With it, disable really disables and revokes bob's sessions.
    let disabled = admin_form_request(
        &app,
        Method::POST,
        "/ui/operators/bob/disable",
        Some(&alice),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let body = html_body(disabled).await;
    assert!(body.contains("Operator disabled"));
    assert!(body.contains("badge disabled"));
    assert_eq!(
        admin_request(&app, Method::GET, "/api/session", Some(&bob_second), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Enable, the other direction.
    let enabled = admin_form_request(
        &app,
        Method::POST,
        "/ui/operators/bob/enable",
        Some(&alice),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    assert!(html_body(enabled).await.contains("badge active"));

    // A fresh session to revoke individually, and one to prove untouched.
    let bob_a = admin_login(&app, "bob", ADMIN_PASSWORD).await;
    let bob_b = admin_login(&app, "bob", ADMIN_PASSWORD).await;
    let sessions = json_body(
        admin_request(
            &app,
            Method::GET,
            "/api/operators/bob/sessions",
            Some(&alice),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(sessions["total"], 2);
    let target_id = sessions["items"][0]["id"].as_str().unwrap().to_string();

    let revoked = admin_form_request(
        &app,
        Method::POST,
        &format!("/ui/operators/bob/sessions/{target_id}/revoke"),
        Some(&alice),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert!(html_body(revoked).await.contains("Session revoked"));
    let remaining = [
        admin_request(&app, Method::GET, "/api/session", Some(&bob_a), None)
            .await
            .status(),
        admin_request(&app, Method::GET, "/api/session", Some(&bob_b), None)
            .await
            .status(),
    ];
    assert_eq!(
        remaining.iter().filter(|s| **s == StatusCode::OK).count(),
        1,
        "exactly one of bob's two sessions must survive"
    );

    // Second factor reset, on bob's own factor.
    enrol_totp(database.clone(), "bob").await;
    let reset = admin_form_request(
        &app,
        Method::POST,
        "/ui/operators/bob/totp/reset",
        Some(&alice),
        Some(&[("password", ADMIN_PASSWORD)]),
    )
    .await;
    assert_eq!(reset.status(), StatusCode::OK);
    assert!(
        html_body(reset)
            .await
            .contains("second factor and recovery codes were removed")
    );
}

/// The route exists and is refused, even though nothing in the panel's own
/// navigation would ever construct this URL for the caller's own username —
/// `get_operator` redirects self away before any button could be rendered.
#[tokio::test]
async fn the_operators_page_refuses_to_target_the_caller() {
    let (app, alice, _bob) = app_with_bob().await;

    for (method, path) in [
        (Method::POST, "/ui/operators/alice/disable"),
        (Method::POST, "/ui/operators/alice/enable"),
        (Method::POST, "/ui/operators/alice/totp/reset"),
    ] {
        let response =
            admin_form_request(&app, method.clone(), path, Some(&alice), Some(&[])).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{method} {path}"
        );
    }

    assert_eq!(
        admin_page(&app, "/ui/account", Some(&alice), false)
            .await
            .status(),
        StatusCode::OK,
        "alice's own account must be untouched"
    );
}
