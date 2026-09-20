//! The expiry list: one query ([`Order::find_expiring`]), one annotator
//! ([`annotate_expiring`]) and three consumers — the `[notify.expiry]` digest,
//! the panel (`GET /api/expiring` and `/ui/expiring`) and
//! `order list --expiring-in`. The annotation used to live inside the digest's
//! job type, where the panel could not reach it — two answers to "has this been
//! replaced?" was exactly one too many.
//!
//! Here, over the storage it reads, rather than in the operation layer: the
//! digest is below that layer and the panel and the terminal above it, so this
//! is the one place all three can reach.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use uuid::Uuid;

use crate::db::Database;
use crate::nonce::now_secs;
use crate::order::{Order, UNPARSABLE_NOT_AFTER};
use acme_proxy_core::config::Config;

/// The window the panel opens on when the caller names no `days`.
///
/// Only reached when `[notify.expiry]` is off (`lead_days = 0`): a deployment
/// that has chosen a lead time gets that one, since the operator reading the
/// page is the operator who set it.
const DEFAULT_LEAD_DAYS: u64 = 30;

/// The certificate that has taken an expiring one's place, and how that was
/// established.
///
/// `via` is carried rather than inferred because the two signals do not mean
/// the same thing to an operator: `replaces` is the client *saying* it renewed
/// (RFC 9773 §5, exact but only from clients that send one), where
/// `identifiers` is this server noticing a later certificate covering the same
/// names — a good inference, and still an inference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SupersededBy {
    pub order_id: String,
    pub cert_serial: String,
    pub not_after: i64,
    /// `"replaces"` or `"identifiers"`.
    pub via: String,
}

/// One expiring certificate, annotated: the order row, how long it has left,
/// and whether anything has replaced it.
#[derive(Debug)]
pub struct ExpiringEntry {
    pub order: Order,
    pub days_remaining: i64,
    pub superseded_by: Option<SupersededBy>,
}

/// The window [`list_expiring`] answers.
pub struct ExpiringQuery {
    /// `None` is every endpoint, the panel's default. The digest names one.
    pub profile: Option<String>,
    /// The `cert_not_after` at or below which a row is expiring — build it with
    /// [`expiring_horizon`], or [`horizon_from`] where the caller has its own
    /// `now`, rather than computing it a second time.
    pub before: i64,
    /// Whether rows something has already replaced stay in the answer. They do
    /// by default, and the digest never turns them off: see [`list_expiring`]
    /// for what this cannot do to `total`.
    pub include_superseded: bool,
    pub limit: i64,
    pub offset: i64,
}

/// The `cert_not_after` at or below which a certificate counts as expiring.
///
/// [`audit_cutoff`](crate::audit::audit_cutoff)'s twin, and for its
/// reason: one function so the digest, the panel and
/// `order list --expiring-in` cannot come to disagree by a rounding rule.
#[must_use]
pub fn expiring_horizon(days: u64) -> i64 {
    horizon_from(now_secs(), days.saturating_mul(24 * 60 * 60))
}

/// [`expiring_horizon`] for a caller that already has its own `now` and a lead
/// time in seconds — the expiry digest, whose `notify.expiry.lead` is a
/// duration and whose `now` is the instant the whole digest is built against.
#[must_use]
pub fn horizon_from(now: i64, lead_seconds: u64) -> i64 {
    now.saturating_add(i64::try_from(lead_seconds).unwrap_or(i64::MAX))
}

/// Whole days from `now` to `not_after`, floored, and never negative — a
/// certificate that lapsed between the query and here is "0 days", not "-1".
///
/// Hoisted out of the digest so the mail, the page and the terminal round the
/// same way; computing it in a Jinja template from two epoch seconds is
/// arithmetic no template should carry.
#[must_use]
pub fn days_remaining(not_after: i64, now: i64) -> i64 {
    not_after.saturating_sub(now).max(0) / (24 * 60 * 60)
}

/// The lead time a surface should default to: the configured one, or
/// [`DEFAULT_LEAD_DAYS`] when the digest is switched off.
#[must_use]
pub fn default_lead_days(config: &Config) -> u64 {
    match config.notify.expiry.lead_days {
        0 => DEFAULT_LEAD_DAYS,
        days => days,
    }
}

/// Whether something has taken `order`'s certificate's place, and how that was
/// established.
///
/// Two signals, tried strongest first, and both deliberately narrow. The
/// annotation errs towards `None` throughout: a wrong "already renewed" is an
/// operator ignoring a certificate that really is about to lapse, where a
/// missing one is only noise. `notify::expiry`'s module docs carry that
/// argument in full.
///
/// `candidates` is the account's own orders, passed in rather than fetched, so
/// [`annotate_expiring`] can read them once for a whole listing. A caller with
/// one order and no cache hands it [`Order::find_by_account`]'s result.
pub async fn superseded_by(
    order: &Order,
    candidates: &[Order],
    database: &Database,
) -> Result<Option<SupersededBy>, sqlx::Error> {
    // 1. The client said so (RFC 9773 §5). Exact when it is there at all,
    //    but only clients that send `replaces` produce it.
    //
    //    `find_by_replaces` excludes only `invalid`, because its own
    //    question is "has this predecessor been claimed" — a *pending*
    //    claim still holds the claim. That is the wrong answer here: an
    //    order that has not issued anything has replaced nothing, and
    //    reporting its predecessor as renewed would silence the one
    //    certificate still doing the work.
    if let Some(chain) = order.certificate.as_deref()
        && let Some(cert_id) = ari_cert_id(chain)
        && let Some(successor) = Order::find_by_replaces(&order.profile, &cert_id, database).await?
        && successor.certificate.is_some()
        && successor.revoked_at.is_none()
    {
        return Ok(Some(SupersededBy {
            order_id: successor.id.to_string(),
            cert_serial: successor.cert_serial.unwrap_or_default(),
            not_after: successor.cert_not_after.unwrap_or_default(),
            via: "replaces".to_string(),
        }));
    }

    // 2. This server noticed a later certificate covering the same names.
    //    Scoped to the *same account*, and requiring a superset rather than
    //    an intersection: a certificate held by somebody else is not this
    //    subscriber's renewal, and one covering only some of these names
    //    leaves the rest uncovered.
    let names: BTreeSet<&str> = order
        .identifiers
        .iter()
        .map(|identifier| identifier.value.as_str())
        .collect();
    let expires = order.cert_not_after.unwrap_or_default();
    for candidate in candidates {
        if candidate.id == order.id
            || candidate.certificate.is_none()
            || candidate.revoked_at.is_some()
            || candidate.cert_not_after.unwrap_or(UNPARSABLE_NOT_AFTER) <= expires
        {
            continue;
        }
        let covered: BTreeSet<&str> = candidate
            .identifiers
            .iter()
            .map(|identifier| identifier.value.as_str())
            .collect();
        if names.is_subset(&covered) {
            return Ok(Some(SupersededBy {
                order_id: candidate.id.to_string(),
                cert_serial: candidate.cert_serial.clone().unwrap_or_default(),
                not_after: candidate.cert_not_after.unwrap_or_default(),
                via: "identifiers".to_string(),
            }));
        }
    }

    Ok(None)
}

/// Annotates a whole listing with [`days_remaining`] and [`superseded_by`].
///
/// The per-account cache is load-bearing rather than an optimisation.
/// [`Order::find_by_account`] is unbounded, and the identifier signal needs it
/// per row: a fifty-row page over one account read that account's entire order
/// history fifty times, and `order list --expiring-in` is unpaged, so the same
/// shape over a year-old CA is arbitrarily worse. One read per *distinct*
/// account is the same answer for a bounded amount of work.
///
/// The `replaces` signal stays per row: it is a keyed lookup and a chain parse,
/// and there is nothing to share between two rows.
pub async fn annotate_expiring(
    orders: Vec<Order>,
    database: &Database,
) -> Result<Vec<ExpiringEntry>, sqlx::Error> {
    let now = now_secs();
    let mut by_account: HashMap<Uuid, Vec<Order>> = HashMap::new();
    let mut entries = Vec::with_capacity(orders.len());

    for order in orders {
        if let std::collections::hash_map::Entry::Vacant(slot) = by_account.entry(order.account_id)
        {
            slot.insert(Order::find_by_account(order.account_id, database).await?);
        }
        // Present by construction — inserted directly above when absent, so
        // the empty slice is unreachable rather than a fallback.
        let candidates = by_account
            .get(&order.account_id)
            .map_or(&[][..], Vec::as_slice);
        let superseded = superseded_by(&order, candidates, database).await?;
        entries.push(ExpiringEntry {
            days_remaining: days_remaining(order.cert_not_after.unwrap_or_default(), now),
            superseded_by: superseded,
            order,
        });
    }

    Ok(entries)
}

/// One page of expiring certificates, annotated, with the unpaged total and
/// the number of rows this page suppressed.
///
/// **`total` counts the window, not the answer, and that is a limit worth
/// stating rather than papering over.** Supersession is computed in Rust — two
/// queries and an X.509 parse per row — so `include_superseded = false` cannot
/// become a SQL predicate and the `COUNT(*)` beside the page cannot shrink to
/// match it. The third member is therefore how many rows *this page* hid, and
/// both front ends show both numbers. The alternative was a pager whose
/// arithmetic quietly disagreed with the rows under it, which is the one bug a
/// page control makes visible and nothing else does.
pub async fn list_expiring(
    query: &ExpiringQuery,
    database: Arc<Database>,
) -> Result<(Vec<ExpiringEntry>, i64, i64), sqlx::Error> {
    let (orders, total) = Order::find_expiring(
        query.profile.as_deref(),
        query.before,
        query.limit,
        query.offset,
        &database,
    )
    .await?;
    let entries = annotate_expiring(orders, &database).await?;

    if query.include_superseded {
        return Ok((entries, total, 0));
    }
    // Named for what it counts, not for `query.before`, which is the horizon.
    let annotated = i64::try_from(entries.len()).unwrap_or(i64::MAX);
    let kept: Vec<ExpiringEntry> = entries
        .into_iter()
        .filter(|entry| entry.superseded_by.is_none())
        .collect();
    let hidden = annotated.saturating_sub(i64::try_from(kept.len()).unwrap_or(i64::MAX));
    Ok((kept, total, hidden))
}

/// The RFC 9773 certID of a stored chain's leaf, for the `replaces` lookup.
fn ari_cert_id(chain: &str) -> Option<String> {
    acme_proxy_core::cert::leaf_der_from_chain(chain)
        .ok()
        .and_then(|der| acme_proxy_core::cert::ari_cert_id(&der).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{account_id, issued_order};
    use acme_proxy_core::identifier::Identifier;

    const DAY: i64 = 24 * 60 * 60;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// An order with a chain a certID can be derived from, on `default`.
    async fn issued(
        db: &Database,
        account: uuid::Uuid,
        names: &[&str],
        not_after_days: i64,
    ) -> Order {
        issued_order(db, "default", account, names, not_after_days).await
    }

    /// [`superseded_by`] with the candidate list it would fetch for itself —
    /// what a caller holding one order and no cache does.
    async fn annotation(order: &Order, db: &Database) -> Option<SupersededBy> {
        let candidates = Order::find_by_account(order.account_id, db).await.unwrap();
        superseded_by(order, &candidates, db).await.unwrap()
    }

    /// The client said it renewed (RFC 9773 §5).
    #[tokio::test]
    async fn a_replaces_claim_marks_the_predecessor_superseded() {
        let db = db().await;
        let acct = account_id(&db).await;
        let old = issued(&db, acct, &["a.example.com"], 3).await;

        let cert_id = ari_cert_id(old.certificate.as_deref().unwrap()).unwrap();
        let successor = issued(&db, acct, &["a.example.com"], 90).await;
        sqlx::query("UPDATE orders SET replaces = ? WHERE id = ?;")
            .bind(&cert_id)
            .bind(successor.id)
            .execute(db.raw_pool())
            .await
            .unwrap();

        let reloaded = Order::find_by_id(old.id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        let superseded = annotation(&reloaded, &db).await.unwrap();
        assert_eq!(superseded.order_id, successor.id.to_string());
        assert_eq!(superseded.via, "replaces");
    }

    /// **A `replaces` claim from an order that never issued anything replaces
    /// nothing.** `find_by_replaces` excludes only `invalid`, because its own
    /// question is whether the claim is held; here a pending claim would
    /// silence the one certificate still doing the work.
    #[tokio::test]
    async fn a_pending_replaces_claim_supersedes_nothing() {
        let db = db().await;
        let acct = account_id(&db).await;
        let old = issued(&db, acct, &["a.example.com"], 3).await;
        let cert_id = ari_cert_id(old.certificate.as_deref().unwrap()).unwrap();

        // A claim on the predecessor, from an order with no certificate.
        let pending = Order::create(
            "default",
            acct,
            vec![Identifier::dns("a.example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE orders SET replaces = ? WHERE id = ?;")
            .bind(&cert_id)
            .bind(pending.id)
            .execute(db.raw_pool())
            .await
            .unwrap();

        let reloaded = Order::find_by_id(old.id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert!(annotation(&reloaded, &db).await.is_none());
    }

    /// The inference: a later certificate covering the same names.
    #[tokio::test]
    async fn a_later_certificate_over_the_same_names_supersedes() {
        let db = db().await;
        let acct = account_id(&db).await;
        let old = issued(&db, acct, &["a.example.com"], 3).await;
        let new = issued(&db, acct, &["a.example.com", "b.example.com"], 90).await;

        let superseded = annotation(&old, &db).await.unwrap();
        assert_eq!(superseded.order_id, new.id.to_string());
        assert_eq!(
            superseded.via, "identifiers",
            "a superset covers these names, so it is a renewal"
        );
    }

    /// The three the inference must **not** draw. Each would silence a
    /// certificate that really is about to lapse, which is the failure this
    /// whole annotation is written conservatively to avoid.
    #[tokio::test]
    async fn a_partial_a_revoked_and_another_accounts_certificate_supersede_nothing() {
        let db = db().await;
        let acct = account_id(&db).await;
        let old = issued(&db, acct, &["a.example.com", "b.example.com"], 3).await;

        // Covers only some of the names: the rest would go uncovered.
        issued(&db, acct, &["a.example.com"], 90).await;
        assert!(
            annotation(&old, &db).await.is_none(),
            "a subset is not a renewal"
        );

        // Covers them all, but has itself been withdrawn.
        let mut revoked = issued(&db, acct, &["a.example.com", "b.example.com"], 90).await;
        revoked.revoke(Some(1), &db).await.unwrap();
        assert!(
            annotation(&old, &db).await.is_none(),
            "a revoked certificate covers nothing"
        );

        // Covers them all and is live, but belongs to somebody else.
        let (other, _created) = crate::account::Account::find_or_create(
            "default",
            b"other-key",
            Vec::new(),
            &acme_proxy_core::audit::ClientContext::default(),
            &db,
        )
        .await
        .unwrap();
        issued(&db, other.id, &["a.example.com", "b.example.com"], 90).await;
        assert!(
            annotation(&old, &db).await.is_none(),
            "another subscriber's certificate is not this one's renewal"
        );
    }

    /// The two boundaries the three surfaces share. Computed once, here, so
    /// the digest, the panel and the terminal cannot disagree about what
    /// "within 7 days" means.
    #[test]
    fn the_horizon_and_the_day_count_agree_on_a_whole_day() {
        let now = now_secs();
        assert!((expiring_horizon(7) - now - 7 * DAY).abs() <= 1);
        // Saturating rather than overflowing: `--expiring-in` takes a `u64`
        // and nothing bounds what an operator types.
        assert_eq!(expiring_horizon(u64::MAX), i64::MAX);

        // Floored, never rounded: an operator told "4 days" about a
        // certificate that lapses in three and a half has been told the wrong
        // week.
        assert_eq!(days_remaining(1_000 + 3 * DAY + DAY / 2, 1_000), 3);
        assert_eq!(days_remaining(1_000 + DAY - 1, 1_000), 0);
        // Never negative: one that lapsed between the query and here is "0
        // days", not "-1".
        assert_eq!(days_remaining(1_000, 1_000 + 5 * DAY), 0);
        assert_eq!(days_remaining(i64::MIN, i64::MAX), 0);
    }

    /// The panel needs a window even where the digest is switched off, which
    /// `lead_days = 0` is.
    #[test]
    fn the_default_window_falls_back_only_when_the_digest_is_off() {
        let mut config = Config::default();
        assert_eq!(config.notify.expiry.lead_days, 0, "off by default");
        assert_eq!(default_lead_days(&config), DEFAULT_LEAD_DAYS);

        config.notify.expiry.lead_days = 3;
        assert_eq!(
            default_lead_days(&config),
            3,
            "a deployment that chose a lead time gets it"
        );
    }

    /// One `find_by_account` per *distinct* account, not per row.
    ///
    /// The listing is unpaged from `order list --expiring-in`, and that query
    /// is unbounded, so the un-cached shape reads a busy account's whole order
    /// history once per certificate it holds. Asserted through the annotation
    /// staying correct across a page where one account holds several rows —
    /// the cache is only safe if a candidate list is the same answer for every
    /// row of the account it belongs to.
    #[tokio::test]
    async fn a_listing_reads_each_accounts_orders_once_and_still_annotates_each_row() {
        let db = db().await;
        let acct = account_id(&db).await;

        let a = issued(&db, acct, &["a.example.com"], 3).await;
        let b = issued(&db, acct, &["b.example.com"], 5).await;
        // Renews `a` only. `b` must stay un-annotated even though it shares
        // the cached candidate list that contains this row.
        let renewal = issued(&db, acct, &["a.example.com"], 90).await;

        let (orders, _total) = Order::find_expiring(None, expiring_horizon(30), 50, 0, &db)
            .await
            .unwrap();
        let entries = annotate_expiring(orders, &db).await.unwrap();

        let annotated = |id: &str| -> Option<SupersededBy> {
            entries
                .iter()
                .find(|entry| entry.order.id.to_string() == id)
                .and_then(|entry| entry.superseded_by.clone())
        };
        assert_eq!(
            annotated(a.id.to_string().as_str()).unwrap().order_id,
            renewal.id.to_string()
        );
        assert!(
            annotated(b.id.to_string().as_str()).is_none(),
            "a shared candidate list must not leak one row's renewal onto another"
        );
        // And the days came out of the same helper the digest uses. Stamped
        // half a day past the three so the assertion distinguishes a floor
        // from a round without racing the clock at the boundary.
        Order::set_cert_not_after(a.id, now_secs() + 3 * DAY + DAY / 2, &db)
            .await
            .unwrap();
        let (orders, _total) = Order::find_expiring(None, expiring_horizon(30), 50, 0, &db)
            .await
            .unwrap();
        let entries = annotate_expiring(orders, &db).await.unwrap();
        let a_entry = entries.iter().find(|e| e.order.id == a.id).unwrap();
        assert_eq!(a_entry.days_remaining, 3, "floored, not rounded");
    }

    /// `include_superseded` hides rows from the *page* and says how many, and
    /// deliberately leaves `total` alone — the annotation is not a SQL
    /// predicate, so the count beside the page cannot follow it down.
    #[tokio::test]
    async fn hiding_superseded_rows_reports_the_count_rather_than_shrinking_the_total() {
        let db = db().await;
        let acct = account_id(&db).await;
        let a = issued(&db, acct, &["a.example.com"], 3).await;
        issued(&db, acct, &["b.example.com"], 5).await;
        issued(&db, acct, &["a.example.com"], 90).await;

        let query = |include: bool| ExpiringQuery {
            profile: None,
            before: expiring_horizon(30),
            include_superseded: include,
            limit: 50,
            offset: 0,
        };

        let (shown, total, hidden) = list_expiring(&query(true), db.clone()).await.unwrap();
        assert_eq!(shown.len(), 2, "both expiring rows, annotated");
        assert_eq!(total, 2);
        assert_eq!(hidden, 0);

        let (kept, total, hidden) = list_expiring(&query(false), db.clone()).await.unwrap();
        assert_eq!(kept.len(), 1);
        assert!(kept.iter().all(|entry| entry.superseded_by.is_none()));
        assert_ne!(kept[0].order.id, a.id, "the replaced row is the one hidden");
        assert_eq!(hidden, 1);
        assert_eq!(
            total, 2,
            "the total counts the window, not the answer -- documented on list_expiring"
        );
    }

    /// The profile filter reaches through the operation layer, and the ordering
    /// is the query's: soonest first.
    #[tokio::test]
    async fn the_listing_scopes_by_profile_and_answers_soonest_first() {
        let db = db().await;
        let acct = account_id(&db).await;
        let here = issued_order(&db, "default", acct, &["a.example.com"], 5).await;
        let sooner = issued_order(&db, "default", acct, &["b.example.com"], 2).await;
        issued_order(&db, "other", acct, &["c.example.com"], 1).await;

        let scoped = ExpiringQuery {
            profile: Some("default".to_string()),
            before: expiring_horizon(30),
            include_superseded: true,
            limit: 50,
            offset: 0,
        };
        let (entries, total, _) = list_expiring(&scoped, db.clone()).await.unwrap();
        let ids: Vec<String> = entries
            .iter()
            .map(|entry| entry.order.id.to_string())
            .collect();
        assert_eq!(ids, vec![sooner.id.to_string(), here.id.to_string()]);
        assert_eq!(total, 2);

        let unscoped = ExpiringQuery {
            profile: None,
            ..scoped
        };
        let (entries, total, _) = list_expiring(&unscoped, db).await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(total, 3);
    }
}
