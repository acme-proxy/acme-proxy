use base64::prelude::*;
use serde_json::Value;

use crate::admin::ops::OrderDetail;
use crate::sqlite::account::{Account, pubkey_fingerprint};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::audit::AuditEntry;
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

/// An address and the reverse name it had, as `ip (ptr)`.
///
/// Collapses to the address alone when there is no name, and to `-` when there
/// was no address at all. Three states in one column rather than two columns
/// that are empty together, which is what a `-` under a `PTR` heading would have
/// been. A name without an address is not a state that exists, so the pair is
/// only ever read in this order.
fn render_client(ip: Option<&String>, ptr: Option<&String>) -> String {
    match (ip, ptr) {
        (Some(ip), Some(ptr)) => format!("{ip} ({ptr})"),
        (Some(ip), None) => ip.clone(),
        _ => "-".to_string(),
    }
}

/// One line: `id  profile  status  last_seen_from  contact  created_at`.
///
/// The address where the key was last seen takes the column a public-key
/// fingerprint used to hold: a fingerprint identifies nothing an operator
/// scanning a list is looking for, and it is one `account show` away.
#[must_use]
pub fn render_account_line(account: &Account) -> String {
    format!(
        "{}  {:<12}  {:<11}  {:<40}  {}  {}",
        account.id,
        account.profile,
        account.status,
        render_client(
            account.last_seen_ip.as_ref(),
            account.last_seen_ptr.as_ref()
        ),
        if account.contact.is_empty() {
            "-".to_string()
        } else {
            account.contact.join(",")
        },
        rfc3339(account.created_at),
    )
}

/// `account show <id>`, one field per line.
///
/// The traceability columns take the line count past what
/// [`render_account_line`] can carry, which is the same split `audit` makes
/// between its listing and [`render_audit_detail_text`].
#[must_use]
pub fn render_account_detail_text(account: &Account) -> String {
    // One column wider than `render_audit_detail_text`'s, because
    // `last_seen_ptr` is thirteen characters and would otherwise be the one
    // label that pushes its value out of line.
    let mut out = format!(
        "id            {}\nprofile       {}\nstatus        {}\npubkey        {}\ncreated       {}\n",
        account.id,
        account.profile,
        account.status,
        pubkey_fingerprint(&account.pubkey),
        rfc3339(account.created_at),
    );
    if !account.contact.is_empty() {
        out.push_str(&format!("contact       {}\n", account.contact.join(",")));
    }
    if let Some(agreed) = account.terms_of_service_agreed {
        out.push_str(&format!("terms         {agreed}\n"));
    }
    if let Some(seen) = account.last_seen_at {
        out.push_str(&format!("last_seen     {}\n", rfc3339(seen)));
    }
    for (label, value) in [
        ("eab_kid", account.eab_kid.as_ref()),
        ("created_ip", account.created_ip.as_ref()),
        ("created_ptr", account.created_ptr.as_ref()),
        ("last_seen_ip", account.last_seen_ip.as_ref()),
        ("last_seen_ptr", account.last_seen_ptr.as_ref()),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{label:<13} {value}\n"));
        }
    }
    out
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

/// One line: `id  created_at  event  profile  actor  client  identifiers`.
///
/// The client column is [`render_client`]'s three shapes; a row with neither
/// address nor name is a CLI or relay action, and reads as `-`.
#[must_use]
pub fn render_audit_line(entry: &AuditEntry) -> String {
    let actor = match &entry.actor_id {
        Some(id) => format!("{}:{id}", entry.actor_kind),
        None => entry.actor_kind.clone(),
    };
    let client = render_client(entry.client_ip.as_ref(), entry.client_ptr.as_ref());
    let mut line = format!(
        "{:<8}  {}  {:<26}  {:<12}  {:<24}  {:<40}  {}",
        entry.id,
        rfc3339(entry.created_at),
        entry.event,
        entry.profile,
        actor,
        client,
        entry.identifiers.join(","),
    );
    if let Some(reason) = &entry.reason {
        line.push_str(&format!("  reason={reason}"));
    }
    line
}

/// `audit show <id>`, one field per line — the row carries thirteen possible
/// fields and a single line of them would wrap on any terminal.
#[must_use]
pub fn render_audit_detail_text(entry: &AuditEntry) -> String {
    let mut out = format!(
        "id           {}\ncreated      {}\nevent        {}\noutcome      {}\nprofile      {}\nactor        {}\n",
        entry.id,
        rfc3339(entry.created_at),
        entry.event,
        entry.outcome,
        entry.profile,
        match &entry.actor_id {
            Some(id) => format!("{}:{id}", entry.actor_kind),
            None => entry.actor_kind.clone(),
        },
    );
    for (label, value) in [
        ("account", entry.account_id.as_ref()),
        ("order", entry.order_id.as_ref()),
        ("serial", entry.cert_serial.as_ref()),
        ("client_ip", entry.client_ip.as_ref()),
        ("client_ptr", entry.client_ptr.as_ref()),
        ("user_agent", entry.user_agent.as_ref()),
        ("request_id", entry.request_id.as_ref()),
        ("reason", entry.reason.as_ref()),
        ("detail", entry.detail.as_ref()),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{label:<12} {value}\n"));
        }
    }
    if !entry.identifiers.is_empty() {
        out.push_str(&format!("identifiers  {}\n", entry.identifiers.join(",")));
    }
    out
}

/// One line: `id  status  identifiers (comma-joined)  created_at`.
#[must_use]
pub fn render_order_line(order: &Order) -> String {
    let identifiers = order
        .identifiers
        .iter()
        .map(|i| i.value.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let mut line = format!(
        "{}  {:<12}  {:<9}  {}  {}",
        order.id,
        order.profile,
        order.status,
        identifiers,
        rfc3339(order.created_at)
    );
    if let Some(revoked_at) = order.revoked_at {
        line.push_str(&format!(
            "  revoked={}{}",
            rfc3339(revoked_at),
            order
                .revocation_reason
                .map(|r| format!(" reason={r}"))
                .unwrap_or_default()
        ));
    }
    line
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

/// `order show` text output.
#[must_use]
pub fn render_order_detail_text(detail: &OrderDetail) -> String {
    let mut out = format!(
        "id: {}\nprofile: {}\naccount_id: {}\nstatus: {}\nidentifiers: {}\nexpires: {}\n",
        detail.order.id,
        detail.order.profile,
        detail.order.account_id,
        detail.order.status,
        detail
            .order
            .identifiers
            .iter()
            .map(|i| i.value.as_str())
            .collect::<Vec<_>>()
            .join(","),
        rfc3339(detail.order.expires),
    );
    for (authz, challenges) in &detail.authorizations {
        out.push_str(&format!(
            "  authz {} [{}] {}\n",
            authz.id, authz.status, authz.identifier.value
        ));
        for challenge in challenges {
            out.push_str(&format!(
                "    challenge {} [{}] type={}\n",
                challenge.id, challenge.status, challenge.typ
            ));
        }
    }
    out
}

/// One line: `kid  status  label  created_at (RFC3339)`.
#[must_use]
pub fn render_eab_line(eab: &Eab) -> String {
    format!(
        "{}  {:<8}  {}  {}",
        eab.kid,
        eab.status,
        eab.label.as_deref().unwrap_or("-"),
        rfc3339(eab.created_at),
    )
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

/// `eab create` text output.
#[must_use]
pub fn render_eab_created_text(eab: &Eab) -> String {
    format!(
        "kid: {}\nhmacKey: {}\nlabel: {}\n\nStore the hmacKey now: it is shown only this once.\n",
        eab.kid,
        BASE64_URL_SAFE_NO_PAD.encode(&eab.secret),
        eab.label.as_deref().unwrap_or("-"),
    )
}

/// One line: `username  status  totp  created_at  last_login`.
#[must_use]
pub fn render_admin_user_line(user: &AdminUser) -> String {
    format!(
        "{:<20}  {:<8}  totp={:<3}  {}  {}",
        user.username,
        user.status,
        if user.has_totp() { "on" } else { "off" },
        rfc3339(user.created_at),
        user.last_login_at.map_or("never".to_string(), rfc3339),
    )
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

/// `admin user totp status`, in words.
///
/// Says which of the three states the operator is in, since "enrolment pending"
/// and "no factor" behave identically at the login prompt and only this line
/// tells them apart -- an operator who believes they enrolled and did not
/// confirm has no other way to find out.
#[must_use]
pub fn render_admin_totp_line(user: &AdminUser, recovery_codes_remaining: i64) -> String {
    let state = if user.has_totp() {
        "enabled"
    } else if user.has_pending_totp() {
        "pending (enrolment started, never confirmed)"
    } else {
        "off"
    };

    format!(
        "{:<20}  totp={}  recovery-codes={}",
        user.username, state, recovery_codes_remaining
    )
}

/// One line: `id  user  state  created_at  expires_at  ip`.
///
/// `id` is a fingerprint of the token hash, not the hash: see
/// [`AdminSession::to_json`].
#[must_use]
pub fn render_admin_session_line(session: &AdminSession) -> String {
    format!(
        "{}  {}  {:<11}  {}  expires={}  {}",
        crate::sqlite::nonce::fingerprint(&session.token_hash),
        session.user_id,
        session.state,
        rfc3339(session.created_at),
        rfc3339(session.expires_at),
        session.created_ip.as_deref().unwrap_or("-"),
    )
}

/// `admin session list --json`.
#[must_use]
pub fn render_admin_session_json(session: &AdminSession) -> Value {
    session.to_json()
}

/// Prints a listing the way every `--json`-capable list command prints one:
/// one JSON array, or one human-readable line per row.
///
/// Six commands had written out the same `if json { … map(to_json).collect()
/// … } else { for row in rows { println!(to_line) } }`. The shape is the
/// contract — a JSON listing is an *array*, never a stream of objects, so a
/// caller can pipe it into `jq` — and it should exist once.
pub fn print_rows<T>(
    rows: &[T],
    json: bool,
    to_json: impl Fn(&T) -> serde_json::Value,
    to_line: impl Fn(&T) -> String,
) {
    if json {
        let rendered: Vec<_> = rows.iter().map(to_json).collect();
        println!("{}", serde_json::Value::Array(rendered));
    } else {
        for row in rows {
            println!("{}", to_line(row));
        }
    }
}

#[cfg(test)]
mod tests {

    fn audit_entry() -> AuditEntry {
        AuditEntry {
            id: 41_812,
            created_at: 1_700_000_000,
            event: "certificate_issued".to_string(),
            outcome: "success".to_string(),
            profile: "le".to_string(),
            actor_kind: "acme".to_string(),
            actor_id: Some("acct-1".to_string()),
            account_id: Some("acct-1".to_string()),
            order_id: Some("order-1".to_string()),
            cert_serial: Some("0a0b".to_string()),
            identifiers: vec!["a.example.com".to_string(), "b.example.com".to_string()],
            client_ip: Some("203.0.113.7".to_string()),
            client_ptr: Some("host.example.com".to_string()),
            user_agent: Some("certbot/2.9.0".to_string()),
            request_id: Some("req-1".to_string()),
            reason: None,
            detail: None,
        }
    }

    /// The client column has three states in one place — address with a name,
    /// address alone, and no client at all — because the two fields are empty
    /// together and a second column would just be a second blank.
    #[test]
    fn the_audit_line_renders_all_three_shapes_of_client() {
        let entry = audit_entry();
        let line = render_audit_line(&entry);
        assert!(line.contains("41812"), "{line}");
        assert!(line.contains("certificate_issued"), "{line}");
        assert!(line.contains("acme:acct-1"), "{line}");
        assert!(line.contains("203.0.113.7 (host.example.com)"), "{line}");
        assert!(line.contains("a.example.com,b.example.com"), "{line}");
        // No reason on a plain issuance, so no trailing `reason=`.
        assert!(!line.contains("reason="), "{line}");

        let mut no_ptr = audit_entry();
        no_ptr.client_ptr = None;
        let line = render_audit_line(&no_ptr);
        assert!(line.contains("203.0.113.7"), "{line}");
        assert!(!line.contains('('), "{line}");

        // A CLI row: no actor id, no client, and a reason that does show.
        let mut cli = audit_entry();
        cli.actor_kind = "cli".to_string();
        cli.actor_id = None;
        cli.client_ip = None;
        cli.client_ptr = None;
        cli.event = "certificate_revoked".to_string();
        cli.reason = Some("1".to_string());
        let line = render_audit_line(&cli);
        assert!(line.contains(" cli "), "{line}");
        assert!(
            !line.contains("cli:"),
            "an actor with no id must not render a trailing colon: {line}"
        );
        assert!(line.contains(" - "), "{line}");
        assert!(line.ends_with("reason=1"), "{line}");
    }

    /// The detail view renders one field per line and **omits** the absent
    /// ones, so a blank never reads as "unknown".
    #[test]
    fn the_audit_detail_omits_every_field_that_has_no_value() {
        let full = render_audit_detail_text(&audit_entry());
        for expected in [
            "id           41812",
            "event        certificate_issued",
            "outcome      success",
            "profile      le",
            "actor        acme:acct-1",
            "order        order-1",
            "serial       0a0b",
            "client_ip    203.0.113.7",
            "client_ptr   host.example.com",
            "user_agent   certbot/2.9.0",
            "request_id   req-1",
            "identifiers  a.example.com,b.example.com",
        ] {
            assert!(full.contains(expected), "missing `{expected}` in:\n{full}");
        }
        assert!(!full.contains("reason"), "{full}");
        assert!(!full.contains("detail"), "{full}");

        let bare = AuditEntry {
            actor_id: None,
            account_id: None,
            order_id: None,
            cert_serial: None,
            identifiers: vec![],
            client_ip: None,
            client_ptr: None,
            user_agent: None,
            request_id: None,
            ..audit_entry()
        };
        let text = render_audit_detail_text(&bare);
        assert!(text.contains("actor        acme\n"), "{text}");
        for absent in ["account", "order", "serial", "client_ip", "identifiers"] {
            assert!(
                !text.contains(absent),
                "`{absent}` should be absent from:\n{text}"
            );
        }
    }

    use crate::audit::ClientContext;
    use std::sync::Arc;

    use super::*;
    use crate::admin::ops::load_order_detail;
    use crate::sqlite::authz::{Authorization, Challenge};
    use crate::sqlite::db::Database;
    use crate::sqlite::order::Identifier;
    use crate::sqlite::status::OrderStatus;
    use crate::testutil::account_id;

    fn order_fixture(account_id: &str, status: OrderStatus) -> Order {
        let mut order = Order::new(
            "default",
            account_id,
            vec![Identifier::dns("example.com")],
            0,
            None,
            None,
        );
        order.status = status;
        order
    }

    /// An account created from `client`, whose traceability columns are
    /// therefore whatever that context carried.
    ///
    /// `pubkey` is a parameter because `find_or_create` dedupes on it: two calls
    /// sharing one would hand back the *first* account, contexts and all.
    async fn account_seen_from(
        pubkey: &[u8],
        client: &ClientContext,
        db: &Arc<Database>,
    ) -> Account {
        Account::find_or_create(
            "default",
            pubkey,
            vec!["mailto:a@example.com".to_string()],
            client,
            db,
        )
        .await
        .unwrap()
        .0
    }

    fn client_context(ip: Option<&str>, ptr: Option<&str>) -> ClientContext {
        ClientContext {
            ip: ip.map(str::to_string),
            ptr: ptr.map(str::to_string),
            ..ClientContext::default()
        }
    }

    /// The listing's client column has the same three states as the audit
    /// line's, and for the same reason — it is the same renderer.
    #[tokio::test]
    async fn render_account_line_renders_all_three_shapes_of_client() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());

        let both = account_seen_from(
            &[1u8, 2, 3],
            &client_context(Some("203.0.113.7"), Some("host.example.com")),
            &db,
        )
        .await;
        let line = render_account_line(&both);
        assert!(line.contains(&both.id), "{line}");
        assert!(line.contains("valid"), "{line}");
        assert!(line.contains("mailto:a@example.com"), "{line}");
        assert!(line.contains("203.0.113.7 (host.example.com)"), "{line}");
        // The fingerprint gave this column up; the detail view still has it.
        assert!(!line.contains(&pubkey_fingerprint(&both.pubkey)), "{line}");

        let address_only = account_seen_from(
            &[4u8, 5, 6],
            &client_context(Some("203.0.113.7"), None),
            &db,
        )
        .await;
        let line = render_account_line(&address_only);
        assert!(line.contains("203.0.113.7"), "{line}");
        assert!(!line.contains('('), "{line}");

        let neither = account_seen_from(&[7u8, 8, 9], &ClientContext::default(), &db).await;
        assert!(render_account_line(&neither).contains("  -  "));
    }

    #[tokio::test]
    async fn render_account_detail_text_omits_every_absent_field() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());

        let seen = account_seen_from(
            &[1u8, 2, 3],
            &client_context(Some("203.0.113.7"), Some("host.example.com")),
            &db,
        )
        .await;
        let text = render_account_detail_text(&seen);
        assert!(
            text.contains(&format!("id            {}", seen.id)),
            "{text}"
        );
        assert!(text.contains("profile       default"), "{text}");
        assert!(text.contains("status        valid"), "{text}");
        assert!(
            text.contains(&pubkey_fingerprint(&seen.pubkey)),
            "the fingerprint the listing gave up must be here: {text}"
        );
        assert!(
            text.contains("contact       mailto:a@example.com"),
            "{text}"
        );
        assert!(text.contains("created_ip    203.0.113.7"), "{text}");
        assert!(text.contains("created_ptr   host.example.com"), "{text}");
        assert!(text.contains("last_seen     "), "{text}");
        assert!(text.contains("last_seen_ip  203.0.113.7"), "{text}");
        assert!(text.contains("last_seen_ptr host.example.com"), "{text}");
        // Every label lands its value in the same column, `last_seen_ptr`
        // included — it is thirteen characters, and the field is wide for it.
        for line in text.lines() {
            assert_eq!(&line[13..14], " ", "misaligned: {line:?}");
            assert_ne!(&line[14..15], " ", "misaligned: {line:?}");
        }
        // Never recorded, so never a line — not a line reading "none".
        assert!(!text.contains("eab_kid"), "{text}");
        assert!(!text.contains("terms"), "{text}");

        let bare =
            Account::find_or_create("default", &[9u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap()
                .0;
        let text = render_account_detail_text(&bare);
        for absent in ["contact", "created_ip", "created_ptr", "last_seen_ip"] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
        // Seeded at creation, so this one is present even on a fresh account.
        assert!(text.contains("last_seen     "), "{text}");
    }

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
    fn render_order_line_includes_expected_fields() {
        let order = order_fixture("acct", OrderStatus::Pending);
        let line = render_order_line(&order);
        assert!(line.contains(&order.id));
        assert!(line.contains("pending"));
        assert!(line.contains("example.com"));
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
    async fn render_order_detail_text_surfaces_authorizations_and_challenges() {
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
        let text = render_order_detail_text(&detail);
        assert!(text.contains(&order.id));
        assert!(text.contains(&authz.id));
        assert!(text.contains("http-01"));
    }

    #[tokio::test]
    async fn render_eab_line_includes_expected_fields() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("team-a".to_string()), None, &db)
            .await
            .unwrap();
        let line = render_eab_line(&eab);
        assert!(line.contains(&eab.kid));
        assert!(line.contains("active"));
        assert!(line.contains("team-a"));
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

    #[tokio::test]
    async fn render_eab_created_text_includes_kid_and_hmac_key() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        let text = render_eab_created_text(&eab);
        assert!(text.contains(&eab.kid));
        assert!(text.contains(&BASE64_URL_SAFE_NO_PAD.encode(&eab.secret)));
    }

    #[test]
    fn render_order_line_revoked_includes_reason_and_time() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(1);
        let line = render_order_line(&order);
        assert!(line.contains("revoked="));
        assert!(line.contains("reason=1"));
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

    fn admin_user_fixture() -> AdminUser {
        AdminUser {
            id: "11111111-2222-3333-4444-555555555555".to_string(),
            username: "alice".to_string(),
            password_hash: "pbkdf2-sha256$600000$c2FsdA$aGFzaA".to_string(),
            status: "active".to_string(),
            totp_secret: None,
            totp_pending_secret: None,
            totp_last_step: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            last_login_at: None,
        }
    }

    #[test]
    fn render_admin_user_line_never_shows_the_hash_and_says_never_for_no_login() {
        let user = admin_user_fixture();
        let line = render_admin_user_line(&user);
        assert!(line.contains("alice"));
        assert!(line.contains("active"));
        assert!(line.contains("totp=off"));
        assert!(line.contains("never"));
        assert!(
            !line.contains("pbkdf2"),
            "the stored hash must never reach a terminal: {line}"
        );
    }

    #[test]
    fn render_admin_user_line_reflects_totp_and_a_real_last_login() {
        let mut user = admin_user_fixture();
        user.totp_secret = Some(vec![1, 2, 3]);
        user.last_login_at = Some(1_700_000_500);
        let line = render_admin_user_line(&user);
        assert!(line.contains("totp=on"));
        assert!(!line.contains("never"));
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

    fn admin_session_fixture() -> AdminSession {
        AdminSession {
            token_hash: "0123456789abcdef0123456789abcdef".to_string(),
            user_id: "11111111-2222-3333-4444-555555555555".to_string(),
            csrf_token: "the-csrf-token".to_string(),
            state: "active".to_string(),
            mfa_attempts: 0,
            created_at: 1_700_000_000,
            expires_at: 1_700_043_200,
            last_seen_at: 1_700_000_000,
            created_ip: Some("192.0.2.1".to_string()),
            user_agent: Some("curl/8".to_string()),
        }
    }

    #[test]
    fn render_admin_session_line_shows_a_fingerprint_not_the_token_hash() {
        let line = render_admin_session_line(&admin_session_fixture());
        assert!(line.contains("01234567"));
        assert!(
            !line.contains("0123456789abcdef0123456789abcdef"),
            "printing the hash would put every live session's lookup key on a terminal: {line}"
        );
        assert!(!line.contains("the-csrf-token"));
        assert!(line.contains("192.0.2.1"));
        assert!(line.contains("expires="));
    }

    #[test]
    fn render_admin_session_line_dashes_a_missing_address() {
        let mut session = admin_session_fixture();
        session.created_ip = None;
        assert!(render_admin_session_line(&session).contains(" -"));
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
