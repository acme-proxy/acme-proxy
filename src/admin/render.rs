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

use crate::admin::ops::OrderDetail;
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
    object.insert("id".to_string(), Value::String(account.id.clone()));
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
pub fn render_order_json(order: &Order, base_url: &str, authz_ids: &[String]) -> Value {
    let mut object = order
        .to_json(&profile_base_url(base_url, &order.profile), authz_ids)
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert("id".to_string(), Value::String(order.id.clone()));
    object.insert("profile".to_string(), Value::String(order.profile.clone()));
    // Admin-only, like `id` and `profile`: the ACME order object deliberately
    // never names its account, but an operator looking at an order almost
    // always wants to get to the account behind it, and without this neither
    // front end can offer that link.
    object.insert(
        "accountId".to_string(),
        Value::String(order.account_id.clone()),
    );
    object.insert(
        "createdAt".to_string(),
        Value::String(rfc3339(order.created_at)),
    );
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
    let authz_ids: Vec<String> = detail
        .authorizations
        .iter()
        .map(|(a, _)| a.id.clone())
        .collect();
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

/// `admin user list --json` / `admin user show --json`.
///
/// A straight pass-through: unlike an account or an order, an operator has no
/// ACME wire form to augment -- [`AdminUser::to_json`] is already the only
/// representation, and it is the one that omits the password hash.
#[must_use]
pub fn render_admin_user_json(user: &AdminUser) -> Value {
    user.to_json()
}

/// `admin session list --json`.
#[must_use]
pub fn render_admin_session_json(session: &AdminSession) -> Value {
    session.to_json()
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
        assert_eq!(json["id"], account.id);
        assert_eq!(json["status"], "valid");
        assert!(json["orders"].as_str().unwrap().contains(&account.id));
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
        let order = order_fixture("acct", OrderStatus::Pending);
        let authz_ids = vec!["authz-1".to_string()];
        let json = render_order_json(&order, "http://localhost:3000", &authz_ids);
        assert_eq!(json["id"], order.id);
        // Admin output is rendered against the *profile's* base URL, not the
        // server's: that is the URL the client was handed.
        assert_eq!(json["profile"], "default");
        // Admin-only, and absent from the ACME order object: without it
        // neither front end could link an order back to its account.
        assert_eq!(json["accountId"], "acct");
        assert_eq!(
            json["authorizations"],
            serde_json::json!(["http://localhost:3000/profile/default/authz/authz-1"])
        );
    }

    #[tokio::test]
    async fn render_order_detail_json_nests_authorizations_and_challenges() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        let authz = Authorization::create(
            &order.id,
            Identifier::dns("example.com"),
            crate::sqlite::nonce::now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();
        Challenge::create(&authz.id, "http-01", &db).await.unwrap();

        let detail = load_order_detail(&order.id, db).await.unwrap().unwrap();
        let json = render_order_detail_json(&detail, "http://localhost:3000");
        assert_eq!(json["order"]["id"], order.id);
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
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(1);
        let json = render_order_json(&order, "http://localhost:3000", &[]);
        assert_eq!(json["revokedAt"].as_str().unwrap().len(), 20);
        assert_eq!(json["revocationReason"], 1);
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
}
