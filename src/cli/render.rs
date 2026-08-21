//! The human-readable renderings, and the only place colour is woven in.
//!
//! These lived in [`crate::admin::render`] beside the JSON ones until colour
//! arrived. The split is where the sharing actually is: every `render_*_json`
//! is read by both front ends (`src/webadmin/pages/`, `src/webadmin/handlers/`)
//! and must stay byte-identical for a script parsing `--json`, while **every
//! renderer here has exactly one consumer, the terminal**. Keeping them
//! together would have meant either a [`Palette`] argument threaded through
//! `src/admin/`, which is the front-end-agnostic layer, or colouring whole
//! lines from the print site, which is all a finished padded string allows.
//!
//! Two conventions hold throughout:
//!
//! - **Pad first, then colour** — `palette.status(&format!("{:<11}", status))`.
//!   A format width counts bytes, so wrapping before padding counts the escape
//!   and collapses the column. See [`super::style`].
//! - **Colour is semantic, never decorative.** Statuses, refusals and standing
//!   warnings; not labels, not timestamps, not identifiers. A listing should
//!   read as data with a few things standing out, and `Palette::plain()` must
//!   stay the shape an operator's `awk` was written against.

use base64::prelude::*;

use super::style::Palette;
use crate::admin::ops::OrderDetail;
use crate::sqlite::account::{Account, pubkey_fingerprint};
use crate::sqlite::admin_session::AdminSession;
use crate::sqlite::admin_user::AdminUser;
use crate::sqlite::audit::AuditEntry;
use crate::sqlite::eab::Eab;
use crate::sqlite::order::{Order, rfc3339};

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
pub fn render_account_line(account: &Account, palette: Palette) -> String {
    format!(
        "{}  {:<12}  {}  {:<40}  {}  {}",
        account.id,
        account.profile,
        palette.status(&format!("{:<11}", account.status)),
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
pub fn render_account_detail_text(account: &Account, palette: Palette) -> String {
    // One column wider than `render_audit_detail_text`'s, because
    // `last_seen_ptr` is thirteen characters and would otherwise be the one
    // label that pushes its value out of line.
    let mut out = format!(
        "id            {}\nprofile       {}\nstatus        {}\npubkey        {}\ncreated       {}\n",
        account.id,
        account.profile,
        palette.status(&account.status),
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

/// The event name padded to `width`, painted when it names a refusal.
///
/// Driven off the `_failed` suffix rather than off `AuditEntry::outcome`,
/// because the listing does not carry `outcome` and the two are derived from
/// one definition (`AuditEvent::outcome`) anyway. An event this build has never
/// seen still renders — the column is a stored string on purpose.
///
/// Takes the width rather than a padded string, because the suffix test has to
/// run on the *unpadded* name and the escape has to wrap the *padded* one.
fn paint_event(event: &str, width: usize, palette: Palette) -> String {
    let padded = format!("{event:<width$}");
    if event.ends_with("_failed") {
        palette.bad(&padded)
    } else {
        padded
    }
}

/// One line: `id  created_at  event  profile  actor  client  identifiers`.
///
/// The client column is [`render_client`]'s three shapes; a row with neither
/// address nor name is a CLI or relay action, and reads as `-`.
#[must_use]
pub fn render_audit_line(entry: &AuditEntry, palette: Palette) -> String {
    let actor = match &entry.actor_id {
        Some(id) => format!("{}:{id}", entry.actor_kind),
        None => entry.actor_kind.clone(),
    };
    let client = render_client(entry.client_ip.as_ref(), entry.client_ptr.as_ref());
    let mut line = format!(
        "{:<8}  {}  {}  {:<12}  {:<24}  {:<40}  {}",
        entry.id,
        rfc3339(entry.created_at),
        paint_event(&entry.event, 26, palette),
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
pub fn render_audit_detail_text(entry: &AuditEntry, palette: Palette) -> String {
    let mut out = format!(
        "id           {}\ncreated      {}\nevent        {}\noutcome      {}\nprofile      {}\nactor        {}\n",
        entry.id,
        rfc3339(entry.created_at),
        paint_event(&entry.event, 0, palette),
        palette.status(&entry.outcome),
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
pub fn render_order_line(order: &Order, palette: Palette) -> String {
    let identifiers = order
        .identifiers
        .iter()
        .map(|i| i.value.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let mut line = format!(
        "{}  {:<12}  {}  {}  {}",
        order.id,
        order.profile,
        palette.status(&format!("{:<9}", order.status)),
        identifiers,
        rfc3339(order.created_at)
    );
    if let Some(revoked_at) = order.revoked_at {
        // Painted whole: an order's `status` stays `valid` after revocation
        // (RFC 8555 defines no revoked status), so this suffix is the only
        // thing on the line that says the certificate is withdrawn.
        line.push_str(&palette.bad(&format!(
            "  revoked={}{}",
            rfc3339(revoked_at),
            order
                .revocation_reason
                .map(|r| format!(" reason={r}"))
                .unwrap_or_default()
        )));
    }
    line
}

/// `order show` text output.
#[must_use]
pub fn render_order_detail_text(detail: &OrderDetail, palette: Palette) -> String {
    let mut out = format!(
        "id: {}\nprofile: {}\naccount_id: {}\nstatus: {}\nidentifiers: {}\nexpires: {}\n",
        detail.order.id,
        detail.order.profile,
        detail.order.account_id,
        palette.status(&detail.order.status.to_string()),
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
            authz.id,
            palette.status(&authz.status.to_string()),
            authz.identifier.value
        ));
        for challenge in challenges {
            out.push_str(&format!(
                "    challenge {} [{}] type={}\n",
                challenge.id,
                palette.status(&challenge.status.to_string()),
                challenge.typ
            ));
        }
    }
    out
}

/// One line: `kid  status  label  created_at (RFC3339)`.
#[must_use]
pub fn render_eab_line(eab: &Eab, palette: Palette) -> String {
    format!(
        "{}  {}  {}  {}",
        eab.kid,
        palette.status(&format!("{:<8}", eab.status)),
        eab.label.as_deref().unwrap_or("-"),
        rfc3339(eab.created_at),
    )
}

/// `eab create` text output.
#[must_use]
pub fn render_eab_created_text(eab: &Eab, palette: Palette) -> String {
    format!(
        "kid: {}\nhmacKey: {}\nlabel: {}\n\n{}\n",
        eab.kid,
        BASE64_URL_SAFE_NO_PAD.encode(&eab.secret),
        eab.label.as_deref().unwrap_or("-"),
        palette.warn("Store the hmacKey now: it is shown only this once."),
    )
}

/// One line: `username  status  totp  created_at  last_login`.
#[must_use]
pub fn render_admin_user_line(user: &AdminUser, palette: Palette) -> String {
    format!(
        "{:<20}  {}  totp={}  {}  {}",
        user.username,
        palette.status(&format!("{:<8}", user.status)),
        palette.status(&format!(
            "{:<3}",
            if user.has_totp() { "on" } else { "off" }
        )),
        rfc3339(user.created_at),
        user.last_login_at.map_or("never".to_string(), rfc3339),
    )
}

/// `admin user totp status`, in words.
///
/// Says which of the three states the operator is in, since "enrolment pending"
/// and "no factor" behave identically at the login prompt and only this line
/// tells them apart -- an operator who believes they enrolled and did not
/// confirm has no other way to find out.
#[must_use]
pub fn render_admin_totp_line(
    user: &AdminUser,
    recovery_codes_remaining: i64,
    palette: Palette,
) -> String {
    // The pending word carries its explanation, so it is painted whole rather
    // than through `status` -- which would leave the parenthetical plain and
    // read as two different pieces of information.
    let state = if user.has_totp() {
        palette.status("enabled")
    } else if user.has_pending_totp() {
        palette.warn("pending (enrolment started, never confirmed)")
    } else {
        palette.status("off")
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
pub fn render_admin_session_line(session: &AdminSession, palette: Palette) -> String {
    format!(
        "{}  {}  {}  {}  expires={}  {}",
        crate::sqlite::nonce::fingerprint(&session.token_hash),
        session.user_id,
        palette.status(&format!("{:<11}", session.state)),
        rfc3339(session.created_at),
        rfc3339(session.expires_at),
        session.created_ip.as_deref().unwrap_or("-"),
    )
}

/// Prints a listing the way every `--json`-capable list command prints one:
/// one JSON array, or one human-readable line per row.
///
/// Six commands had written out the same `if json { … map(to_json).collect()
/// … } else { for row in rows { println!(to_line) } }`. The shape is the
/// contract — a JSON listing is an *array*, never a stream of objects, so a
/// caller can pipe it into `jq` — and it should exist once.
///
/// Takes no [`Palette`]: the `to_line` closure captures one at the call site,
/// which is also what keeps the `json` branch structurally unable to reach it.
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
    use std::sync::Arc;

    use super::*;
    use crate::admin::ops::load_order_detail;
    use crate::audit::ClientContext;
    use crate::cli::style::ColorChoice;
    use crate::sqlite::authz::{Authorization, Challenge};
    use crate::sqlite::db::Database;
    use crate::sqlite::order::Identifier;
    use crate::sqlite::status::OrderStatus;
    use crate::testutil::{
        account_id, account_seen_from, admin_session_fixture, admin_user_fixture, audit_entry,
        client_context, order_fixture,
    };

    /// Colour forced on, whatever the stream — the only way these assertions
    /// can see an escape at all, since a test binary's stdout is not a
    /// terminal.
    fn colour() -> Palette {
        Palette::resolve(ColorChoice::Always, false, None)
    }

    /// What a coloured rendering must reduce to: strip every SGR sequence and
    /// the plain rendering has to come back byte for byte. This is what pins
    /// "colour never changes the layout" for every renderer below.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('\x1b') {
            out.push_str(&rest[..start]);
            let Some(end) = rest[start..].find('m') else {
                break;
            };
            rest = &rest[start + end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// The client column has three states in one place — address with a name,
    /// address alone, and no client at all — because the two fields are empty
    /// together and a second column would just be a second blank.
    #[test]
    fn the_audit_line_renders_all_three_shapes_of_client() {
        let entry = audit_entry();
        let line = render_audit_line(&entry, Palette::plain());
        assert!(line.contains("41812"), "{line}");
        assert!(line.contains("certificate_issued"), "{line}");
        assert!(line.contains("acme:acct-1"), "{line}");
        assert!(line.contains("203.0.113.7 (host.example.com)"), "{line}");
        assert!(line.contains("a.example.com,b.example.com"), "{line}");
        // No reason on a plain issuance, so no trailing `reason=`.
        assert!(!line.contains("reason="), "{line}");

        let mut no_ptr = audit_entry();
        no_ptr.client_ptr = None;
        let line = render_audit_line(&no_ptr, Palette::plain());
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
        let line = render_audit_line(&cli, Palette::plain());
        assert!(line.contains(" cli "), "{line}");
        assert!(
            !line.contains("cli:"),
            "an actor with no id must not render a trailing colon: {line}"
        );
        assert!(line.contains(" - "), "{line}");
        assert!(line.ends_with("reason=1"), "{line}");
    }

    /// A refusal is the row an operator is scanning for, and the `_failed`
    /// suffix is the only thing on the listing that says so — `outcome` is a
    /// detail-view field.
    #[test]
    fn only_a_failed_audit_event_is_painted() {
        let succeeded = render_audit_line(&audit_entry(), colour());
        assert!(!succeeded.contains('\x1b'), "{succeeded}");

        let mut refused = audit_entry();
        refused.event = "certificate_issue_failed".to_string();
        refused.outcome = "failure".to_string();
        let line = render_audit_line(&refused, colour());
        assert!(line.contains("\x1b[31mcertificate_issue_failed"), "{line}");
        assert_eq!(
            strip_ansi(&line),
            render_audit_line(&refused, Palette::plain()),
            "colour must not move a column"
        );
    }

    /// The detail view renders one field per line and **omits** the absent
    /// ones, so a blank never reads as "unknown".
    #[test]
    fn the_audit_detail_omits_every_field_that_has_no_value() {
        let full = render_audit_detail_text(&audit_entry(), Palette::plain());
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
        let text = render_audit_detail_text(&bare, Palette::plain());
        assert!(text.contains("actor        acme\n"), "{text}");
        for absent in ["account", "order", "serial", "client_ip", "identifiers"] {
            assert!(
                !text.contains(absent),
                "`{absent}` should be absent from:\n{text}"
            );
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
        let line = render_account_line(&both, Palette::plain());
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
        let line = render_account_line(&address_only, Palette::plain());
        assert!(line.contains("203.0.113.7"), "{line}");
        assert!(!line.contains('('), "{line}");

        let neither = account_seen_from(&[7u8, 8, 9], &ClientContext::default(), &db).await;
        assert!(render_account_line(&neither, Palette::plain()).contains("  -  "));
    }

    /// The status column keeps its eleven characters under colour — the
    /// regression for wrapping a field before padding it.
    #[tokio::test]
    async fn colour_never_moves_the_account_listings_columns() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account_seen_from(&[1u8, 2, 3], &ClientContext::default(), &db).await;

        let painted = render_account_line(&account, colour());
        assert!(painted.contains("\x1b[32mvalid      \x1b[0m"), "{painted}");
        assert_eq!(
            strip_ansi(&painted),
            render_account_line(&account, Palette::plain())
        );
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
        let text = render_account_detail_text(&seen, Palette::plain());
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
        let text = render_account_detail_text(&bare, Palette::plain());
        for absent in ["contact", "created_ip", "created_ptr", "last_seen_ip"] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
        // Seeded at creation, so this one is present even on a fresh account.
        assert!(text.contains("last_seen     "), "{text}");
    }

    #[test]
    fn render_order_line_includes_expected_fields() {
        let order = order_fixture("acct", OrderStatus::Pending);
        let line = render_order_line(&order, Palette::plain());
        assert!(line.contains(&order.id));
        assert!(line.contains("pending"));
        assert!(line.contains("example.com"));
    }

    /// Three states, three colours, and the layout unchanged in each.
    ///
    /// The `{:<9}` this column is built with has **never** padded anything:
    /// `OrderStatus`'s `Display` is a bare `write_str`, which ignores the
    /// width, so the field arrives here already ragged. That is pre-existing
    /// and deliberately left alone — the contract colour has to keep is
    /// "identical bytes with the palette off", not "the layout the format
    /// string looks like it asks for".
    #[test]
    fn the_order_status_column_is_painted_by_what_it_means() {
        for (status, code) in [
            (OrderStatus::Valid, "32"),
            (OrderStatus::Pending, "33"),
            (OrderStatus::Invalid, "31"),
        ] {
            let order = order_fixture("acct", status);
            let painted = render_order_line(&order, colour());
            assert!(
                painted.contains(&format!("\x1b[{code}m{}\x1b[0m", status.as_str())),
                "{painted}"
            );
            assert_eq!(
                strip_ansi(&painted),
                render_order_line(&order, Palette::plain())
            );
        }
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
        let text = render_order_detail_text(&detail, Palette::plain());
        assert!(text.contains(&order.id));
        assert!(text.contains(&authz.id));
        assert!(text.contains("http-01"));

        // The nested statuses are painted too: an order is read here precisely
        // when one of its authorizations is not what it should be.
        let painted = render_order_detail_text(&detail, colour());
        assert_eq!(painted.matches("\x1b[33m").count(), 3, "{painted}");
        assert_eq!(strip_ansi(&painted), text);
    }

    #[test]
    fn render_order_line_revoked_includes_reason_and_time() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(1);
        let line = render_order_line(&order, Palette::plain());
        assert!(line.contains("revoked="));
        assert!(line.contains("reason=1"));
    }

    /// A revoked order's `status` stays `valid`, so the suffix is the only
    /// thing that can carry the news — and it is painted whole.
    #[test]
    fn a_revoked_order_paints_its_suffix_even_though_its_status_is_valid() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(1);
        let painted = render_order_line(&order, colour());
        assert!(painted.contains("\x1b[32mvalid"), "{painted}");
        assert!(painted.contains("\x1b[31m  revoked="), "{painted}");
        assert!(painted.ends_with("reason=1\x1b[0m"), "{painted}");
        assert_eq!(
            strip_ansi(&painted),
            render_order_line(&order, Palette::plain())
        );
    }

    #[tokio::test]
    async fn render_eab_line_includes_expected_fields() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("team-a".to_string()), None, &db)
            .await
            .unwrap();
        let line = render_eab_line(&eab, Palette::plain());
        assert!(line.contains(&eab.kid));
        assert!(line.contains("active"));
        assert!(line.contains("team-a"));

        let painted = render_eab_line(&eab, colour());
        assert!(painted.contains("\x1b[32mactive  \x1b[0m"), "{painted}");
        assert_eq!(strip_ansi(&painted), line);
    }

    #[tokio::test]
    async fn render_eab_created_text_includes_kid_and_hmac_key() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        let text = render_eab_created_text(&eab, Palette::plain());
        assert!(text.contains(&eab.kid));
        assert!(text.contains(&BASE64_URL_SAFE_NO_PAD.encode(&eab.secret)));
        assert!(text.contains("Store the hmacKey now"));
    }

    /// The one line an operator must not scroll past — a lost secret is
    /// replaced, never recovered.
    #[tokio::test]
    async fn the_eab_secret_warning_is_the_only_thing_painted() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        let painted = render_eab_created_text(&eab, colour());
        assert!(
            painted.contains("\x1b[33mStore the hmacKey now: it is shown only this once.\x1b[0m"),
            "{painted}"
        );
        assert_eq!(painted.matches('\x1b').count(), 2, "{painted}");
        assert_eq!(
            strip_ansi(&painted),
            render_eab_created_text(&eab, Palette::plain())
        );
    }

    #[test]
    fn render_admin_user_line_never_shows_the_hash_and_says_never_for_no_login() {
        let user = admin_user_fixture();
        let line = render_admin_user_line(&user, Palette::plain());
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
        let line = render_admin_user_line(&user, Palette::plain());
        assert!(line.contains("totp=on"));
        assert!(!line.contains("never"));
    }

    /// An operator with no second factor is a state worth noticing in a
    /// listing, which is why `off` is painted like any other bad status.
    #[test]
    fn an_operator_without_a_second_factor_stands_out() {
        let without = render_admin_user_line(&admin_user_fixture(), colour());
        assert!(without.contains("totp=\x1b[31moff\x1b[0m"), "{without}");

        let mut user = admin_user_fixture();
        user.totp_secret = Some(vec![1, 2, 3]);
        user.status = "disabled".to_string();
        let with = render_admin_user_line(&user, colour());
        assert!(with.contains("totp=\x1b[32mon \x1b[0m"), "{with}");
        assert!(with.contains("\x1b[31mdisabled\x1b[0m"), "{with}");
        assert_eq!(
            strip_ansi(&with),
            render_admin_user_line(&user, Palette::plain())
        );
    }

    /// The three TOTP states, the middle one painted whole because its
    /// parenthetical is the half that explains it.
    #[test]
    fn the_totp_line_paints_each_of_its_three_states() {
        let plain = Palette::plain();
        let off = admin_user_fixture();
        assert!(
            render_admin_totp_line(&off, 0, plain).contains("totp=off"),
            "plain output unchanged"
        );
        assert!(render_admin_totp_line(&off, 0, colour()).contains("totp=\x1b[31moff\x1b[0m"));

        let mut pending = admin_user_fixture();
        pending.totp_pending_secret = Some(vec![1, 2, 3]);
        let line = render_admin_totp_line(&pending, 0, colour());
        assert!(
            line.contains("\x1b[33mpending (enrolment started, never confirmed)\x1b[0m"),
            "{line}"
        );
        assert_eq!(
            strip_ansi(&line),
            render_admin_totp_line(&pending, 0, plain)
        );

        let mut enabled = admin_user_fixture();
        enabled.totp_secret = Some(vec![1, 2, 3]);
        let line = render_admin_totp_line(&enabled, 7, colour());
        assert!(line.contains("totp=\x1b[32menabled\x1b[0m"), "{line}");
        assert!(line.contains("recovery-codes=7"), "{line}");
    }

    #[test]
    fn render_admin_session_line_shows_a_fingerprint_not_the_token_hash() {
        let line = render_admin_session_line(&admin_session_fixture(), Palette::plain());
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
        assert!(render_admin_session_line(&session, Palette::plain()).contains(" -"));
    }

    /// A session still owing its second factor is the one an operator is
    /// looking for in `admin session list`.
    #[test]
    fn a_pending_mfa_session_is_painted_apart_from_an_active_one() {
        let active = render_admin_session_line(&admin_session_fixture(), colour());
        assert!(active.contains("\x1b[32mactive     \x1b[0m"), "{active}");

        let mut session = admin_session_fixture();
        session.state = "pending_mfa".to_string();
        let painted = render_admin_session_line(&session, colour());
        assert!(painted.contains("\x1b[33mpending_mfa\x1b[0m"), "{painted}");
        assert_eq!(
            strip_ansi(&painted),
            render_admin_session_line(&session, Palette::plain())
        );
    }
}
