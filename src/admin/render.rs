//! The JSON renderings, shared by both front ends.
//!
//! One shape per admin resource, and **the boundary this module exists to
//! hold**: everything here is read by the CLI's `--json` branches *and* by
//! `src/webadmin/`, so a change is a change to a wire format two callers parse.
//! The human-readable renderings are the CLI's alone and live in
//! [`crate::cli::render`], which is where colour is woven in — none of it can
//! reach this file, so `--json` output stays byte-identical whatever the
//! terminal is.
//!
//! Each surfaces the admin-only fields the ACME wire format deliberately does
//! not carry (an order's revocation, an account's traceability columns), and
//! each **omits** rather than nulls an absent one, so a template asking
//! `{% if account.createdIp %}` is asking the question it looks like it is
//! asking.

use base64::prelude::*;
use serde_json::Value;
use uuid::Uuid;

use crate::admin::ops::{ExpiringEntry, OrderDetail};
use crate::sqlite::account::{Account, pubkey_fingerprint};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::eab::Eab;
use crate::sqlite::order::{Order, rfc3339};

/// The public base URL of one endpoint, as the server itself derives it.
///
/// Admin output is rendered from `server.base_url`, which names the process,
/// not an endpoint — every URL a client was ever handed carries the owning
/// profile's prefix, so this puts it back.
#[must_use]
pub fn profile_base_url(base_url: &str, profile: &str) -> String {
    format!(
        "{}{}/{profile}",
        base_url.trim_end_matches('/'),
        crate::PROFILE_PREFIX
    )
}

/// JSON representation for account admin display.
///
/// The traceability members are admin-only: [`Account::to_json`] is the RFC 8555
/// object and deliberately carries none of them. Each is **omitted** rather than
/// rendered as `null` when the column is unset, so a template asking `{% if
/// account.createdIp %}` is asking the question it looks like it is asking.
#[must_use]
pub fn render_account_json(account: &Account, base_url: &str) -> Value {
    let mut object = account
        .to_json(&profile_base_url(base_url, &account.profile))
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert("id".to_string(), Value::String(account.id.to_string()));
    object.insert(
        "profile".to_string(),
        Value::String(account.profile.clone()),
    );
    object.insert(
        "createdAt".to_string(),
        Value::String(rfc3339(account.created_at)),
    );
    object.insert(
        "pubkeyFingerprint".to_string(),
        Value::String(pubkey_fingerprint(&account.pubkey)),
    );
    if let Some(seen) = account.last_seen_at {
        object.insert("lastSeenAt".to_string(), Value::String(rfc3339(seen)));
    }
    for (key, value) in [
        ("createdIp", account.created_ip.as_ref()),
        ("createdPtr", account.created_ptr.as_ref()),
        ("lastSeenIp", account.last_seen_ip.as_ref()),
        ("lastSeenPtr", account.last_seen_ptr.as_ref()),
    ] {
        if let Some(value) = value {
            object.insert(key.to_string(), Value::String(value.clone()));
        }
    }
    Value::Object(object)
}

/// JSON representation for order admin display.
#[must_use]
pub fn render_order_json(order: &Order, base_url: &str, authz_ids: &[Uuid]) -> Value {
    let mut object = order
        .to_json(&profile_base_url(base_url, &order.profile), authz_ids)
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert("id".to_string(), Value::String(order.id.to_string()));
    object.insert("profile".to_string(), Value::String(order.profile.clone()));
    // Admin-only, like `id` and `profile`: the ACME order object deliberately
    // never names its account, but an operator looking at an order almost
    // always wants to get to the account behind it, and without this neither
    // front end can offer that link.
    object.insert(
        "accountId".to_string(),
        Value::String(order.account_id.to_string()),
    );
    object.insert(
        "createdAt".to_string(),
        Value::String(rfc3339(order.created_at)),
    );
    // The leaf's serial, admin-only for `accountId`'s reason and absent from
    // every rendering until now — while `audit list --cert-serial` and
    // `GET /api/audit?certSerial=` both filter on it, so an operator could
    // search the trail by a value nothing would tell them. Omitted rather than
    // nulled: an unissued order has no serial, which is a different statement
    // from an empty one. `render_expiring_json` below deliberately keeps its
    // `unwrap_or_default()` — that shape is the digest's own, member for
    // member, and is not this one.
    if let Some(serial) = order.cert_serial.as_ref() {
        object.insert("certSerial".to_string(), Value::String(serial.clone()));
    }
    // The leaf's own expiry, and admin-only for `accountId`'s reason: RFC 8555
    // gives the order object no member for it, and the `notAfter` already in
    // there from `to_json` is the *requested* §7.4 window, which is a different
    // question with a confusingly similar name. Omitted rather than nulled,
    // like every other member here — a row issued before the column existed has
    // nothing to say yet, and the negative sentinel means the chain would not
    // parse, which is not a date to render.
    if let Some(not_after) = order.cert_not_after.filter(|value| *value >= 0) {
        object.insert(
            "certNotAfter".to_string(),
            Value::String(rfc3339(not_after)),
        );
    }
    if let Some(revoked_at) = order.revoked_at {
        object.insert("revokedAt".to_string(), Value::String(rfc3339(revoked_at)));
        if let Some(reason) = order.revocation_reason {
            object.insert("revocationReason".to_string(), Value::from(reason));
        }
    }
    Value::Object(object)
}

/// `order show --json` JSON output.
#[must_use]
pub fn render_order_detail_json(detail: &OrderDetail, base_url: &str) -> Value {
    let authz_ids: Vec<Uuid> = detail.authorizations.iter().map(|(a, _)| a.id).collect();
    let profile_base = profile_base_url(base_url, &detail.order.profile);
    let authorizations: Vec<Value> = detail
        .authorizations
        .iter()
        .map(|(a, c)| a.to_json(&profile_base, c))
        .collect();
    let mut order = render_order_json(&detail.order, base_url, &authz_ids);
    // The issued chain itself, admin-only and **detail-only**.
    //
    // `certificate` beside it is the ACME *URL*, reachable only by signed
    // POST-as-GET — a browser following it gets nothing, so on its own it is a
    // dead string on the order card. The PEM is the thing an operator actually
    // wants, and it is already in the row.
    //
    // Deliberately not in `render_order_json`, which also renders every row of
    // every listing: a page of fifty orders would carry fifty chains for a
    // field no list can show.
    if let (Some(object), Some(pem)) = (order.as_object_mut(), detail.order.certificate.as_ref()) {
        object.insert("certificatePem".to_string(), Value::String(pem.clone()));
    }

    let mut root = serde_json::Map::new();
    root.insert("order".to_string(), order);
    root.insert("authorizations".to_string(), Value::Array(authorizations));
    Value::Object(root)
}

/// One row of the expiry list: `GET /api/expiring`, `/ui/expiring` and
/// `order list --expiring-in --json`.
///
/// A shape of its own rather than [`render_order_json`] plus two members, for
/// two reasons. That renderer takes `authz_ids`, which no expiry view shows and
/// which would be a query per row to supply; and this shape is deliberately the
/// digest's own (`crate::notify::ExpiringCertificate`), so the mail, the page,
/// the API and the terminal all describe an expiring certificate the same way.
///
/// `supersededBy` is **omitted** when nothing has replaced this certificate,
/// like every other absent member here — and an operator scanning the list is
/// looking for exactly the rows where it is absent, so `null` would be a value
/// where the question is presence.
#[must_use]
pub fn render_expiring_json(entry: &ExpiringEntry) -> Value {
    let order = &entry.order;
    let mut object = serde_json::Map::new();
    object.insert("orderId".to_string(), Value::String(order.id.to_string()));
    object.insert("profile".to_string(), Value::String(order.profile.clone()));
    object.insert(
        "accountId".to_string(),
        Value::String(order.account_id.to_string()),
    );
    object.insert(
        "certSerial".to_string(),
        Value::String(order.cert_serial.clone().unwrap_or_default()),
    );
    object.insert(
        "identifiers".to_string(),
        Value::Array(
            order
                .identifiers
                .iter()
                .map(|identifier| Value::String(identifier.value.clone()))
                .collect(),
        ),
    );
    object.insert(
        "notAfter".to_string(),
        Value::String(rfc3339(order.cert_not_after.unwrap_or_default())),
    );
    object.insert(
        "daysRemaining".to_string(),
        Value::from(entry.days_remaining),
    );
    if let Some(superseded) = &entry.superseded_by {
        object.insert(
            "supersededBy".to_string(),
            serde_json::json!({
                "orderId": superseded.order_id,
                "certSerial": superseded.cert_serial,
                "notAfter": rfc3339(superseded.not_after),
                "via": superseded.via,
            }),
        );
    }
    Value::Object(object)
}

/// `eab list --json` / `eab show --json`.
#[must_use]
pub fn render_eab_json(eab: &Eab) -> Value {
    eab.to_json()
}

/// `eab create` JSON output (includes secret).
#[must_use]
pub fn render_eab_created_json(eab: &Eab) -> Value {
    let mut object = eab.to_json().as_object().cloned().unwrap_or_default();
    object.insert(
        "hmacKey".to_string(),
        Value::String(BASE64_URL_SAFE_NO_PAD.encode(&eab.secret)),
    );
    Value::Object(object)
}

/// `admin user list --json`.
///
/// A straight pass-through: unlike an account or an order, an operator has no
/// ACME wire form to augment -- [`AdminUser::to_json`] is already the only
/// representation, and it is the one that omits the password hash.
#[must_use]
pub fn render_admin_user_json(user: &AdminUser) -> Value {
    user.to_json()
}

/// `admin user show --json`: the listing shape plus the two members that cost a
/// query.
///
/// [`render_order_detail_json`]'s arrangement, and for its reason.
/// `enrolmentPending` distinguishes the state a listing cannot show --
/// "enrolment started, never confirmed" behaves exactly like "no factor" at the
/// login prompt, so an operator who believes they enrolled has no other way to
/// find out -- and `recoveryCodesRemaining` is a `COUNT` on a second table,
/// which a page of fifty operators should not pay fifty times.
#[must_use]
pub fn render_admin_user_detail_json(user: &AdminUser, recovery_codes_remaining: i64) -> Value {
    let mut object = render_admin_user_json(user)
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert(
        "enrolmentPending".to_string(),
        Value::Bool(user.has_pending_totp()),
    );
    object.insert(
        "recoveryCodesRemaining".to_string(),
        Value::from(recovery_codes_remaining),
    );
    Value::Object(object)
}

/// `admin session list --json`.
#[must_use]
pub fn render_admin_session_json(session: &AdminSession) -> Value {
    session.to_json()
}

/// A session listing plus one member no CLI rendering needed: whether this row
/// *is* the caller's own live session.
///
/// [`render_admin_user_detail_json`]'s arrangement -- the listing shape, cloned
/// and extended, never the reverse. `current_token_hash` is the caller's own
/// session (never a session being looked *at*, which never has this member's
/// answer be true of itself in a useful way), so the web panel's own sessions
/// card can badge or relabel the row that revoking would sign the viewer out
/// of, without teaching [`AdminSession`] anything about who is asking.
#[must_use]
pub fn render_admin_session_detail_json(session: &AdminSession, current_token_hash: &str) -> Value {
    let mut object = render_admin_session_json(session)
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert(
        "current".to_string(),
        Value::Bool(session.token_hash == current_token_hash),
    );
    Value::Object(object)
}

/// `nonce count --json` and `GET /api/nonces`.
///
/// A count and nothing else: a nonce is a bearer credential until it is
/// consumed, so listing values would put live ones on a screen. The count is
/// the useful part -- it should sit near the request rate times the TTL, and a
/// number far above that says the reaper is not running, which is why the TTL
/// travels beside it rather than leaving the reader to go and look it up.
#[must_use]
pub fn render_nonce_stats_json(count: i64, ttl_seconds: u64) -> Value {
    serde_json::json!({
        "count": count,
        "ttlSeconds": ttl_seconds,
    })
}

/// One ACME endpoint, as every surface describes it.
///
/// The two front ends reach this from opposite directions, and the difference
/// is real rather than an implementation detail. `GET /api/profiles` and
/// `/ui/profiles` build it from a **mounted** [`crate::Profile`], so they
/// describe what this process is actually serving; `acme-proxy profile list`
/// builds it from the configuration, because the alternative is
/// `Profile::build_all`, which constructs signer backends -- generating a CA
/// key and contacting a relay upstream for a read-only listing. That is
/// `filter show`'s split exactly: the panel serves the live thing, the terminal
/// rebuilds one, and between an edit and its `SIGHUP` the two legitimately
/// disagree.
pub struct ProfileSummary {
    pub name: String,
    pub base_url: String,
    pub challenge_bypass: bool,
    pub eab_enabled: bool,
}

impl ProfileSummary {
    /// An endpoint this process is serving.
    #[must_use]
    pub fn mounted(profile: &crate::Profile) -> Self {
        Self {
            name: profile.name.clone(),
            base_url: profile.base_url.clone(),
            challenge_bypass: profile.challenges.is_bypassed(),
            eab_enabled: profile.eab.enabled,
        }
    }

    /// An endpoint this configuration would mount.
    ///
    /// `Config::resolve_profiles` has already dropped anything `enabled = false`
    /// on the caller's behalf, so this needs no filter of its own -- the list it
    /// is mapped over is already the mounted set, minus the fact of being
    /// mounted.
    #[must_use]
    pub fn configured(base_url: &str, profile: &crate::config::ProfileConfig) -> Self {
        Self {
            name: profile.name.clone(),
            base_url: profile_base_url(base_url, &profile.name),
            challenge_bypass: profile.sections.challenge.bypass,
            eab_enabled: profile.sections.eab.enabled,
        }
    }

    /// Where a client fetches this endpoint's directory (RFC 8555 §7.1.1).
    #[must_use]
    pub fn directory_url(&self) -> String {
        format!("{}{}", self.base_url, crate::routes::DIRECTORY)
    }
}

/// `profile list --json`, `GET /api/profiles` and `/ui/profiles`.
#[must_use]
pub fn render_profile_json(profile: &ProfileSummary) -> Value {
    serde_json::json!({
        "name": profile.name,
        "baseUrl": profile.base_url,
        "directory": profile.directory_url(),
        "challengeBypass": profile.challenge_bypass,
        "eabEnabled": profile.eab_enabled,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::admin::ops::load_order_detail;
    use crate::audit::ClientContext;
    use crate::sqlite::authz::{Authorization, Challenge};
    use crate::sqlite::db::Database;
    use crate::sqlite::order::Identifier;
    use crate::sqlite::status::OrderStatus;
    use crate::testutil::{
        account_id, account_seen_from, admin_session_fixture, admin_user_fixture, client_context,
        order_fixture,
    };

    #[tokio::test]
    async fn render_account_json_includes_id_and_base_fields() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account_seen_from(
            &[1u8, 2, 3],
            &client_context(Some("203.0.113.7"), Some("host.example.com")),
            &db,
        )
        .await;

        let json = render_account_json(&account, "http://localhost:3000");
        assert_eq!(json["id"], account.id.to_string());
        assert_eq!(json["status"], "valid");
        assert!(
            json["orders"]
                .as_str()
                .unwrap()
                .contains(&account.id.to_string())
        );
        assert!(json["pubkeyFingerprint"].is_string());
        assert_eq!(json["createdIp"], "203.0.113.7");
        assert_eq!(json["createdPtr"], "host.example.com");
        assert_eq!(json["lastSeenIp"], "203.0.113.7");
        assert_eq!(json["lastSeenPtr"], "host.example.com");
        assert!(json["lastSeenAt"].as_str().unwrap().contains('T'));
    }

    /// Absent, not `null`: a template asking `{% if account.createdIp %}` must
    /// be asking the question it looks like it is asking.
    #[tokio::test]
    async fn render_account_json_omits_the_traceability_members_it_has_no_value_for() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account_seen_from(&[1u8, 2, 3], &ClientContext::default(), &db).await;

        let json = render_account_json(&account, "http://localhost:3000");
        let object = json.as_object().unwrap();
        for key in ["createdIp", "createdPtr", "lastSeenIp", "lastSeenPtr"] {
            assert!(!object.contains_key(key), "{key} in {json}");
        }
    }

    #[test]
    fn render_order_json_includes_id_and_authorizations() {
        let account = crate::sqlite::id::mint();
        let authz = crate::sqlite::id::mint();
        let order = order_fixture(account, OrderStatus::Pending);
        let json = render_order_json(&order, "http://localhost:3000", &[authz]);
        assert_eq!(json["id"], order.id.to_string());
        // Admin output is rendered against the *profile's* base URL, not the
        // server's: that is the URL the client was handed.
        assert_eq!(json["profile"], "default");
        // Admin-only, and absent from the ACME order object: without it
        // neither front end could link an order back to its account.
        assert_eq!(json["accountId"], account.to_string());
        assert_eq!(
            json["authorizations"],
            serde_json::json!([format!(
                "http://localhost:3000/profile/default/authz/{authz}"
            )])
        );
    }

    #[tokio::test]
    async fn render_order_detail_json_nests_authorizations_and_challenges() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let order = Order::create(
            "default",
            acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        let authz = Authorization::create(
            order.id,
            Identifier::dns("example.com"),
            crate::sqlite::nonce::now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();
        Challenge::create(authz.id, "http-01", &db).await.unwrap();

        let detail = load_order_detail(order.id.to_string().as_str(), db)
            .await
            .unwrap()
            .unwrap();
        let json = render_order_detail_json(&detail, "http://localhost:3000");
        assert_eq!(json["order"]["id"], order.id.to_string());
        assert_eq!(json["authorizations"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["authorizations"][0]["challenges"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn render_eab_created_json_includes_the_hmac_key_and_line_json_does_not() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();

        let created = render_eab_created_json(&eab);
        assert!(created["hmacKey"].is_string());

        let listed = render_eab_json(&eab);
        assert!(listed.get("hmacKey").is_none());
    }

    #[test]
    fn render_order_json_revoked_includes_reason_and_time() {
        let mut order = order_fixture(crate::sqlite::id::mint(), OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(1);
        let json = render_order_json(&order, "http://localhost:3000", &[]);
        assert_eq!(json["revokedAt"].as_str().unwrap().len(), 20);
        assert_eq!(json["revocationReason"], 1);
    }

    #[test]
    fn render_order_json_carries_the_cert_serial_and_omits_it_when_unissued() {
        // The complaint this member answers: `audit list --cert-serial` and
        // `GET /api/audit?certSerial=` both filter on this value, and until now
        // no order rendering would tell an operator what it was.
        let mut order = order_fixture(crate::sqlite::id::mint(), OrderStatus::Valid);
        order.cert_serial = Some("03a7f1c9".to_string());
        let json = render_order_json(&order, "http://localhost:3000", &[]);
        assert_eq!(json["certSerial"], "03a7f1c9");

        // Omitted, not nulled: an order that never issued has no serial, which
        // is a different statement from an empty one.
        let unissued = order_fixture(crate::sqlite::id::mint(), OrderStatus::Pending);
        let json = render_order_json(&unissued, "http://localhost:3000", &[]);
        assert!(json.get("certSerial").is_none());
    }

    #[test]
    fn render_admin_user_json_omits_every_secret() {
        let mut user = admin_user_fixture();
        user.totp_secret = Some(vec![9, 9, 9]);
        let json = render_admin_user_json(&user);
        let rendered = json.to_string();
        assert!(!rendered.contains("pbkdf2"));
        assert!(!rendered.contains("totpSecret"));
        assert_eq!(json["username"], "alice");
        assert_eq!(json["totpEnabled"], true);
    }

    #[test]
    fn render_admin_session_json_omits_the_hash_and_the_csrf_token() {
        let json = render_admin_session_json(&admin_session_fixture());
        let rendered = json.to_string();
        assert!(!rendered.contains("0123456789abcdef0123456789abcdef"));
        assert!(!rendered.contains("the-csrf-token"));
        assert_eq!(json["id"], "01234567");
        assert_eq!(json["state"], "active");
    }

    #[test]
    fn render_admin_session_detail_json_marks_only_the_matching_hash() {
        let session = admin_session_fixture();
        let mine = render_admin_session_detail_json(&session, &session.token_hash);
        assert_eq!(mine["current"], true);
        // Everything the listing shape carries is still there.
        assert_eq!(mine["id"], "01234567");

        let someone_elses = render_admin_session_detail_json(&session, "a-different-hash");
        assert_eq!(someone_elses["current"], false);
    }
}
