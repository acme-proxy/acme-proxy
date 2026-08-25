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
use super::window::Window;
use crate::admin::ops::{ExpiringEntry, OrderDetail};
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

/// One line of `order list --expiring-in`: `order_id  profile  Nd  not_after
/// identifiers`, plus a `replaced-by=` suffix where something has.
///
/// Two things are painted, both semantic. The days-left column, because "act
/// now" versus "soon" is the one thing an operator scans this listing for; and
/// the supersession suffix, because its *presence* is the good news — which is
/// also why the rows with no suffix are the ones left plain. The thresholds are
/// the terminal's own and match `/ui/expiring`'s badges.
#[must_use]
pub fn render_expiring_line(entry: &ExpiringEntry, palette: Palette) -> String {
    let order = &entry.order;
    let identifiers = order
        .identifiers
        .iter()
        .map(|i| i.value.as_str())
        .collect::<Vec<_>>()
        .join(",");
    // Padded first, then painted: a format width counts bytes.
    let days = format!("{:>5}", format!("{}d", entry.days_remaining));
    let days = match entry.days_remaining {
        0..=7 => palette.bad(&days),
        8..=30 => palette.warn(&days),
        _ => days,
    };
    let mut line = format!(
        "{}  {:<12}  {}  {}  {}",
        order.id,
        order.profile,
        days,
        rfc3339(order.cert_not_after.unwrap_or_default()),
        identifiers
    );
    if let Some(superseded) = &entry.superseded_by {
        line.push_str(&palette.ok(&format!(
            "  replaced-by={} via={}",
            superseded.order_id, superseded.via
        )));
    }
    line
}

/// The one-line summary of an order's stored problem document: its `detail`,
/// else its `type`, else the document itself. The same fallback the order card
/// renders (`orders/_card.html`), so the two never describe one failure
/// differently.
fn problem_summary(error: &serde_json::Value) -> String {
    for member in ["detail", "type"] {
        if let Some(text) = error.get(member).and_then(serde_json::Value::as_str) {
            return text.to_string();
        }
    }
    error.to_string()
}

/// `order show`, one field per line, then the authorization tree.
///
/// Tracks [`crate::admin::render::render_order_detail_json`] member for member,
/// omitting every field that was not recorded rather than rendering it empty —
/// the shape [`render_account_detail_text`] and [`render_audit_detail_text`]
/// already have. It printed six fields until now, while its own `--json`
/// carried the serial, the leaf's expiry and the revocation state, and the book
/// documented the *JSON* spelling of the last two as something `order show`
/// surfaced.
///
/// Four JSON members are deliberately not here:
///
/// - `authorizations` and `finalize` are **URLs**. The indented tree below
///   answers the same question for a terminal, and carries the ids.
/// - `certificate` is the ACME URL, reachable only by signed POST-as-GET, so
///   printing it is a dead string — the reason the order card refuses it too.
/// - `certificatePem` is the chain itself, several KB of it, and this is a
///   command an operator runs to orient themselves. `--json` and the panel's
///   `chain.pem` download are where the bytes live; `cli.md` says so.
#[must_use]
pub fn render_order_detail_text(detail: &OrderDetail, palette: Palette) -> String {
    let order = &detail.order;
    // Two columns wider than `render_account_detail_text`'s, because
    // `cert_not_after` is fourteen characters — and it keeps that spelling
    // rather than a shorter one precisely because `not_after` is a *different*
    // field one line above it (the requested §7.4 window, not the leaf's).
    let mut out = format!(
        "id             {}\nprofile        {}\naccount_id     {}\nstatus         {}\nidentifiers    {}\ncreated        {}\nexpires        {}\n",
        order.id,
        order.profile,
        order.account_id,
        palette.status(&order.status.to_string()),
        order
            .identifiers
            .iter()
            .map(|i| i.value.as_str())
            .collect::<Vec<_>>()
            .join(","),
        rfc3339(order.created_at),
        rfc3339(order.expires),
    );
    for (label, value) in [
        ("not_before", order.not_before.map(rfc3339)),
        ("not_after", order.not_after.map(rfc3339)),
        ("replaces", order.replaces.clone()),
        ("serial", order.cert_serial.clone()),
        // The negative sentinel means the chain would not parse, which is not a
        // date to render — `render_order_json`'s guard, for its reason.
        (
            "cert_not_after",
            order
                .cert_not_after
                .filter(|value| *value >= 0)
                .map(rfc3339),
        ),
        // Painted whole, like `render_order_line`'s suffix: an order's `status`
        // stays `valid` after revocation (RFC 8555 defines no revoked status),
        // so these two lines are the only thing saying the certificate is
        // withdrawn. `reason` hangs off `revoked_at` as it does in the JSON — a
        // reason with no revocation would be a column read out of context.
        (
            "revoked",
            order.revoked_at.map(|at| palette.bad(&rfc3339(at))),
        ),
        (
            "reason",
            order
                .revoked_at
                .and(order.revocation_reason)
                .map(|reason| reason.to_string()),
        ),
        ("error", order.error.as_ref().map(problem_summary)),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{label:<14} {value}\n"));
        }
    }
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

/// The envelope a paged `--json` listing answers with.
///
/// Deliberately the same four members, spelled the same way, as
/// [`crate::webadmin::handlers::paging::page_envelope`]: `total` is what the
/// same filters match **unpaged**, which is the whole difference between having
/// read the table and having read a page of it, and a script should not have to
/// learn one shape for the API and another for the shell.
///
/// The unpaged listings beside this one — `eab list`, `admin user list`,
/// `admin session list` — stay bare arrays through [`print_rows`]. Those are
/// tables an operator mints by hand, a few rows at a time; nothing there is a
/// page, so nothing there has a total to report.
#[must_use]
pub fn json_page(items: Vec<serde_json::Value>, total: i64, window: Window) -> serde_json::Value {
    serde_json::json!({
        "items": items,
        "total": total,
        "limit": window.limit,
        "offset": window.offset,
    })
}

/// The line under a paged listing.
///
/// Printed **always**, not only when the page is short: "42 of 1877" is the
/// difference between having read the trail and having read a page of it, and
/// the count is already computed. Carries no [`Palette`] — a count is data, and
/// colour here is decorative.
fn footer_line(shown: usize, total: i64) -> String {
    format!("{shown} of {total} row(s).")
}

/// The same line where supersession has dropped rows from the page.
///
/// `total` counts the **window**, not the rows below it: `admin::list_expiring`
/// filters superseded certificates in Rust, because the annotation cannot
/// become a SQL predicate. A bare "1 of 4" over a page that quietly dropped two
/// is arithmetic an operator cannot reproduce, so the third number is said out
/// loud — the terminal's spelling of the `hidden` member `GET /api/expiring`
/// adds to its envelope for the same reason.
fn expiring_footer_line(shown: usize, total: i64, hidden: i64) -> String {
    if hidden > 0 {
        format!("{shown} of {total} row(s), {hidden} superseded hidden.")
    } else {
        footer_line(shown, total)
    }
}

/// Prints [`footer_line`].
pub fn print_footer(shown: usize, total: i64) {
    println!("{}", footer_line(shown, total));
}

/// Prints [`expiring_footer_line`].
pub fn print_expiring_footer(shown: usize, total: i64, hidden: i64) {
    println!("{}", expiring_footer_line(shown, total, hidden));
}

/// Prints one page, in whichever of the two shapes was asked for.
///
/// [`print_rows`]'s paged twin, and the same division of labour: the `to_line`
/// closure carries the [`Palette`], so the `json` branch stays structurally
/// unable to reach one. `order list --json` is the one caller that does not go
/// through here — it batches an authorization lookup its `to_json` needs, and
/// folding that in would make the text path pay for a query it never reads —
/// so it calls [`json_page`] and [`print_footer`] directly instead.
pub fn print_page<T>(
    rows: &[T],
    total: i64,
    window: Window,
    json: bool,
    to_json: impl Fn(&T) -> serde_json::Value,
    to_line: impl Fn(&T) -> String,
) {
    if json {
        let rendered: Vec<_> = rows.iter().map(to_json).collect();
        println!("{}", json_page(rendered, total, window));
    } else {
        for row in rows {
            println!("{}", to_line(row));
        }
        print_footer(rows.len(), total);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::admin::ops::SupersededBy;
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

    /// The footer under every paged listing, asserted on its exact bytes: four
    /// commands print it now, and an operator's `awk` counts on the shape.
    #[test]
    fn the_footer_reports_the_page_against_the_unpaged_total() {
        assert_eq!(footer_line(2, 137), "2 of 137 row(s).");
        // A short page and an empty one are still a page, and still say so.
        assert_eq!(footer_line(0, 0), "0 of 0 row(s).");
    }

    /// The expiry footer says the third number out loud, and is byte-identical
    /// to the ordinary one when there is nothing to say.
    #[test]
    fn the_expiry_footer_names_the_rows_supersession_removed() {
        assert_eq!(
            expiring_footer_line(1, 4, 2),
            "1 of 4 row(s), 2 superseded hidden."
        );
        assert_eq!(expiring_footer_line(4, 4, 0), footer_line(4, 4));
    }

    /// The CLI envelope is the API's, member for member — the whole point of
    /// having it. A caller should not learn one shape for `--json` and another
    /// for `/api`.
    #[test]
    fn the_json_envelope_matches_the_apis() {
        let window = Window::resolve(2, 4);
        let envelope = json_page(vec![serde_json::json!({"id": "a"})], 17, window);

        assert_eq!(envelope["total"], 17);
        assert_eq!(envelope["limit"], 2);
        assert_eq!(envelope["offset"], 4);
        assert_eq!(envelope["items"].as_array().unwrap().len(), 1);

        let page = crate::webadmin::handlers::paging::Page {
            limit: 2,
            offset: 4,
        };
        assert_eq!(
            envelope,
            crate::webadmin::handlers::paging::page_envelope(
                vec![serde_json::json!({"id": "a"})],
                17,
                page
            )
        );
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
        assert_eq!(
            painted.matches("\x1b[33mpending\x1b[0m").count(),
            3,
            "the order's, the authorization's and the challenge's: {painted}"
        );
        assert_eq!(strip_ansi(&painted), text);
    }

    /// The field set `order show` prints, and the shape it prints it in.
    ///
    /// It carried six fields until now while its own `--json` carried the
    /// serial, the leaf's expiry and the revocation state — so this is the
    /// assertion that the two describe one order. The absent half matters as
    /// much: a field that was never recorded gets no line at all, rather than
    /// a label with nothing after it, which is `render_account_detail_text`'s
    /// contract and `audit show`'s.
    #[test]
    fn render_order_detail_text_omits_every_absent_field() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.not_before = Some(1700000000);
        order.not_after = Some(1700003600);
        order.replaces = Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".to_string());
        order.cert_serial = Some("03a7f1c9".to_string());
        order.cert_not_after = Some(1700007200);
        order.revoked_at = Some(1700010800);
        order.revocation_reason = Some(1);
        order.error = Some(serde_json::json!({
            "type": "urn:ietf:params:acme:error:badCSR",
            "detail": "CSR names do not match the order",
        }));
        let detail = OrderDetail {
            order,
            authorizations: vec![],
        };

        let text = render_order_detail_text(&detail, Palette::plain());
        assert!(
            text.contains(&format!("id             {}", detail.order.id)),
            "{text}"
        );
        assert!(text.contains("profile        default"), "{text}");
        assert!(text.contains("account_id     acct"), "{text}");
        assert!(text.contains("status         valid"), "{text}");
        assert!(text.contains("identifiers    example.com"), "{text}");
        assert!(text.contains("created        "), "{text}");
        assert!(text.contains("expires        "), "{text}");
        assert!(
            text.contains("not_before     2023-11-14T22:13:20Z"),
            "{text}"
        );
        assert!(
            text.contains("not_after      2023-11-14T23:13:20Z"),
            "{text}"
        );
        assert!(
            text.contains("replaces       aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"),
            "{text}"
        );
        assert!(text.contains("serial         03a7f1c9"), "{text}");
        assert!(
            text.contains("cert_not_after 2023-11-15T00:13:20Z"),
            "{text}"
        );
        assert!(
            text.contains("revoked        2023-11-15T01:13:20Z"),
            "{text}"
        );
        assert!(text.contains("reason         1"), "{text}");
        // The problem document's `detail`, the one line of it an operator
        // wants — the same fallback the order card renders.
        assert!(
            text.contains("error          CSR names do not match the order"),
            "{text}"
        );
        // Every label lands its value in the same column, `cert_not_after`
        // included — it is fourteen characters, and the field is wide for it.
        for line in text.lines() {
            assert_eq!(&line[14..15], " ", "misaligned: {line:?}");
            assert_ne!(&line[15..16], " ", "misaligned: {line:?}");
        }

        // Never recorded, so never a line.
        let bare = OrderDetail {
            order: order_fixture("acct", OrderStatus::Pending),
            authorizations: vec![],
        };
        let text = render_order_detail_text(&bare, Palette::plain());
        for absent in [
            "not_before",
            "not_after",
            "replaces",
            "serial",
            "cert_not_after",
            "revoked",
            "reason",
            "error",
        ] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
    }

    /// The whole point of the change, asserted as a set: `order show` and
    /// `order show --json` describe the same order.
    ///
    /// The table below is the mapping, and it is checked in **both**
    /// directions — a JSON member gaining no text line fails here, and so does
    /// a text line naming nothing in the JSON. Four members are excluded by
    /// name and the exclusion is the decision, not an oversight: three URLs a
    /// terminal cannot use (the authorization list and `finalize` are answered
    /// by the indented tree below the fields; the ACME `certificate` URL is
    /// reachable only by signed POST-as-GET) and `certificatePem`, the chain
    /// itself, which `cli.md` documents as `--json`'s alone.
    #[test]
    fn the_text_and_json_order_renderings_describe_the_same_order() {
        /// `(text label, JSON member)`.
        const FIELDS: &[(&str, &str)] = &[
            ("id", "id"),
            ("profile", "profile"),
            ("account_id", "accountId"),
            ("status", "status"),
            ("identifiers", "identifiers"),
            ("created", "createdAt"),
            ("expires", "expires"),
            ("not_before", "notBefore"),
            ("not_after", "notAfter"),
            ("replaces", "replaces"),
            ("serial", "certSerial"),
            ("cert_not_after", "certNotAfter"),
            ("revoked", "revokedAt"),
            ("reason", "revocationReason"),
            ("error", "error"),
        ];
        /// Carried by `--json` and deliberately not printed.
        const JSON_ONLY: &[&str] = &[
            "authorizations",
            "finalize",
            "certificate",
            "certificatePem",
        ];

        // Every optional column populated, or an absent one would read as an
        // agreed omission rather than as a member nobody renders.
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.not_before = Some(1700000000);
        order.not_after = Some(1700003600);
        order.replaces = Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".to_string());
        order.cert_serial = Some("03a7f1c9".to_string());
        order.cert_not_after = Some(1700007200);
        order.revoked_at = Some(1700010800);
        order.revocation_reason = Some(1);
        order.error = Some(serde_json::json!({ "detail": "unreachable" }));
        order.certificate = Some("-----BEGIN CERTIFICATE-----\n".to_string());
        let detail = OrderDetail {
            order,
            authorizations: vec![],
        };

        let json = crate::admin::render::render_order_detail_json(&detail, "http://localhost:3000");
        let members: std::collections::BTreeSet<&str> = json["order"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|member| !JSON_ONLY.contains(member))
            .collect();
        assert_eq!(
            members,
            FIELDS.iter().map(|(_, member)| *member).collect(),
            "a JSON member the text rendering does not print, or the reverse"
        );

        // A field line is one that starts in column zero; the tree below is
        // indented, and no value here wraps.
        let text = render_order_detail_text(&detail, Palette::plain());
        let labels: std::collections::BTreeSet<&str> = text
            .lines()
            .filter(|line| !line.starts_with(' '))
            .map(|line| line[..14].trim_end())
            .collect();
        assert_eq!(labels, FIELDS.iter().map(|(label, _)| *label).collect());
    }

    /// The negative sentinel is not a date. A row the expiry backfill looked at
    /// and could not parse prints no `cert_not_after` line, exactly as
    /// `render_order_json` emits no member for it.
    #[test]
    fn an_unparsable_leaf_expiry_prints_no_line() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.cert_not_after = Some(crate::sqlite::order::UNPARSABLE_NOT_AFTER);
        let detail = OrderDetail {
            order,
            authorizations: vec![],
        };
        assert!(!render_order_detail_text(&detail, Palette::plain()).contains("cert_not_after"),);
    }

    /// A revoked order's `status` stays `valid` here too, so the two revocation
    /// lines are the only news — and the timestamp is painted, like the
    /// listing's suffix.
    #[test]
    fn the_order_detail_paints_its_revocation_and_nothing_else_moves() {
        let mut order = order_fixture("acct", OrderStatus::Valid);
        order.revoked_at = Some(1700000000);
        order.revocation_reason = Some(4);
        let detail = OrderDetail {
            order,
            authorizations: vec![],
        };
        let painted = render_order_detail_text(&detail, colour());
        assert!(
            painted.contains("\x1b[31m2023-11-14T22:13:20Z\x1b[0m"),
            "{painted}"
        );
        assert_eq!(
            strip_ansi(&painted),
            render_order_detail_text(&detail, Palette::plain())
        );
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

    /// The expiry line's own shape, its three urgency bands, and the suffix
    /// that only appears where something has replaced the certificate.
    #[test]
    fn the_expiring_line_bands_the_days_and_annotates_only_what_was_replaced() {
        let entry = |days: i64, superseded: Option<SupersededBy>| {
            let mut order = order_fixture("acct-1", OrderStatus::Valid);
            order.id = "ord-1".to_string();
            order.cert_not_after = Some(1_700_000_000);
            ExpiringEntry {
                order,
                days_remaining: days,
                superseded_by: superseded,
            }
        };

        let plain = render_expiring_line(&entry(40, None), Palette::plain());
        assert!(plain.starts_with("ord-1  default     "), "{plain}");
        assert!(plain.contains("  40d  "), "{plain}");
        assert!(plain.contains("2023-11-14"), "{plain}");
        assert!(plain.ends_with("example.com"), "{plain}");
        assert!(
            !plain.contains("replaced-by"),
            "the absent annotation is what an operator scans for: {plain}"
        );

        // Inside a week is red, inside a month amber, beyond that plain.
        assert!(render_expiring_line(&entry(3, None), colour()).contains("\x1b[31m"));
        assert!(render_expiring_line(&entry(20, None), colour()).contains("\x1b[33m"));
        let far = render_expiring_line(&entry(40, None), colour());
        assert_eq!(
            far,
            render_expiring_line(&entry(40, None), Palette::plain())
        );

        let replaced = entry(
            3,
            Some(SupersededBy {
                order_id: "ord-2".to_string(),
                cert_serial: "0a0b".to_string(),
                not_after: 1_800_000_000,
                via: "replaces".to_string(),
            }),
        );
        let line = render_expiring_line(&replaced, Palette::plain());
        assert!(line.ends_with("  replaced-by=ord-2 via=replaces"), "{line}");
    }

    /// The days column keeps its width under colour — the same regression the
    /// account listing pins, for a field this renderer pads itself.
    #[test]
    fn colour_never_moves_the_expiring_listings_columns() {
        let mut order = order_fixture("acct-1", OrderStatus::Valid);
        order.cert_not_after = Some(1_700_000_000);
        let entry = ExpiringEntry {
            order,
            days_remaining: 3,
            superseded_by: Some(SupersededBy {
                order_id: "ord-2".to_string(),
                cert_serial: "0a0b".to_string(),
                not_after: 1_800_000_000,
                via: "identifiers".to_string(),
            }),
        };

        let painted = render_expiring_line(&entry, colour());
        assert!(painted.contains("\x1b[31m   3d\x1b[0m"), "{painted}");
        assert_eq!(
            strip_ansi(&painted),
            render_expiring_line(&entry, Palette::plain())
        );
    }
}
