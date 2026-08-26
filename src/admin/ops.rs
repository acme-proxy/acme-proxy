use std::collections::{BTreeSet, HashMap};
use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::admin::prompt::confirm;
use crate::audit::{Actor, AuditEvent, AuditRecord, ClientContext};
use crate::config::Config;
use crate::signer::{SignerBackend, SignerError};
use crate::sqlite::account::Account;
use crate::sqlite::audit::{AuditEntry, AuditQuery};
use crate::sqlite::authz::{Authorization, Challenge};
use crate::sqlite::db::Database;
use crate::sqlite::nonce::{Nonce, now_secs};
use crate::sqlite::order::{Order, UNPARSABLE_NOT_AFTER};

/// Outcome of a confirm-gated hard delete.
///
/// `Cancelled` only exists on the `confirm_*` wrappers: a caller with nobody
/// to ask -- the web admin -- uses the bare function below, whose return type
/// has no such variant to leave unhandled.
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    NotFound,
    Cancelled,
    Deleted,
}

/// What a hard delete took with it.
///
/// The count is already computed to word the confirmation prompt, so returning
/// it costs nothing and lets an API caller report what it removed rather than
/// answering a bare `204`.
#[derive(Debug, PartialEq, Eq)]
pub struct Deleted {
    /// Rows the schema's `ON DELETE CASCADE` removed along with the row named:
    /// orders for an account, authorizations for an order.
    pub cascaded: u64,
}

/// An order plus every authorization (each with its challenges).
#[derive(Debug)]
pub struct OrderDetail {
    pub order: Order,
    pub authorizations: Vec<(Authorization, Vec<Challenge>)>,
}

/// Outcome of [`revoke_order`].
#[derive(Debug)]
pub enum RevokeOutcome {
    NotFound,
    NotIssued,
    AlreadyRevoked,
    Revoked(Box<Order>),
}

/// How a [`SignerError`] reads inside a [`RevokeError`].
///
/// `BadCsr` is not a thing `revoke` can legitimately answer — the hook takes a
/// certificate, not a CSR — so it is reported as the contract violation it is
/// rather than passed through as if it meant something here.
fn signer_detail(error: &SignerError) -> String {
    match error {
        SignerError::Internal(detail) => detail.clone(),
        SignerError::BadCsr => "unexpected badCsr from revoke".to_string(),
    }
}

/// Why [`revoke_order`] failed.
#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    #[error("database error: {0}")]
    Database(sqlx::Error),
    #[error("signer error: {}", signer_detail(.0))]
    Signer(SignerError),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("unsupported revocation reason code {0}")]
    BadReason(u32),
}

impl From<sqlx::Error> for RevokeError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<SignerError> for RevokeError {
    fn from(error: SignerError) -> Self {
        Self::Signer(error)
    }
}

// Each of the three destructive operations comes in two forms: a bare one that
// simply does the thing, and a `confirm_*` wrapper that asks first. The split
// exists because the wrapper's `assume_yes: bool` + `reader: &mut impl BufRead`
// are a terminal's concerns, and a caller with no terminal -- the web admin --
// had to pass `true` and an empty reader, asserting a confirmation that never
// happened. The generic also makes the wrapper non-object-safe for no benefit
// on that path. The CLI calls the wrapper; everything else calls the bare form.

/// Hard-deletes an account. `None` when there is no such account; otherwise
/// how many orders cascaded with it.
pub async fn delete_account(
    id: &str,
    database: Arc<Database>,
) -> Result<Option<Deleted>, sqlx::Error> {
    let Some(cascaded) = account_cascade(id, database.clone()).await? else {
        return Ok(None);
    };
    Account::delete(id, &database).await?;
    Ok(Some(Deleted { cascaded }))
}

/// Looks up the account, shows what will cascade, confirms, then hard-deletes it.
pub async fn confirm_delete_account(
    id: &str,
    assume_yes: bool,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<DeleteOutcome, sqlx::Error> {
    let Some(account) = Account::find_any_by_id(id, &database).await? else {
        return Ok(DeleteOutcome::NotFound);
    };
    let order_count = Order::count_by_account(account.id, &database).await?;
    let prompt = format!(
        "Delete account {id} (status: {}, {order_count} order(s) will cascade)?",
        account.status
    );
    if !confirm(&prompt, assume_yes, reader) {
        return Ok(DeleteOutcome::Cancelled);
    }
    Account::delete(id, &database).await?;
    Ok(DeleteOutcome::Deleted)
}

/// Hard-deletes an order. `None` when there is no such order; otherwise how
/// many authorizations cascaded with it.
pub async fn delete_order(
    id: &str,
    database: Arc<Database>,
) -> Result<Option<Deleted>, sqlx::Error> {
    let Some(cascaded) = order_cascade(id, database.clone()).await? else {
        return Ok(None);
    };
    Order::delete(id, &database).await?;
    Ok(Some(Deleted { cascaded }))
}

/// Same shape as [`confirm_delete_account`], for an order.
pub async fn confirm_delete_order(
    id: &str,
    assume_yes: bool,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<DeleteOutcome, sqlx::Error> {
    let Some(order) = Order::find_by_id(id, &database).await? else {
        return Ok(DeleteOutcome::NotFound);
    };
    let authz_count = Authorization::count_by_order(order.id, &database).await?;
    let prompt = format!(
        "Delete order {id} (status: {}, {authz_count} authorization(s) will cascade)?",
        order.status
    );
    if !confirm(&prompt, assume_yes, reader) {
        return Ok(DeleteOutcome::Cancelled);
    }
    Order::delete(id, &database).await?;
    Ok(DeleteOutcome::Deleted)
}

/// Runs [`Nonce::cleanup`], returning how many were removed.
pub async fn cleanup_nonces(ttl: Duration, database: Arc<Database>) -> Result<u64, sqlx::Error> {
    Nonce::cleanup(&database, ttl).await
}

/// Confirms, then runs [`cleanup_nonces`]. `None` when the operator declined.
pub async fn confirm_cleanup_nonces(
    ttl: Duration,
    assume_yes: bool,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<Option<u64>, sqlx::Error> {
    let prompt = format!("Delete all nonces older than {}s?", ttl.as_secs());
    if !confirm(&prompt, assume_yes, reader) {
        return Ok(None);
    }
    Ok(Some(cleanup_nonces(ttl, database).await?))
}

/// How many orders an account delete would cascade, or `None` if there is no
/// such account. Shared so the prompt and the bare delete agree on the count.
async fn account_cascade(id: &str, database: Arc<Database>) -> Result<Option<u64>, sqlx::Error> {
    let Some(account) = Account::find_any_by_id(id, &database).await? else {
        return Ok(None);
    };
    Ok(Some(
        Order::count_by_account(account.id, &database).await? as u64,
    ))
}

/// The [`account_cascade`] counterpart for an order's authorizations.
async fn order_cascade(id: &str, database: Arc<Database>) -> Result<Option<u64>, sqlx::Error> {
    let Some(order) = Order::find_by_id(id, &database).await? else {
        return Ok(None);
    };
    Ok(Some(
        Authorization::count_by_order(order.id, &database).await? as u64,
    ))
}

/// Updates an account's contact list.
pub async fn update_account_contact(
    id: &str,
    contact: Vec<String>,
    database: Arc<Database>,
) -> Result<Option<Account>, sqlx::Error> {
    let Some(mut account) = Account::find_any_by_id(id, &database).await? else {
        return Ok(None);
    };
    account.update_contact(contact, &database).await?;
    Ok(Some(account))
}

/// Deactivates an account.
pub async fn deactivate_account(
    id: &str,
    database: Arc<Database>,
) -> Result<Option<Account>, sqlx::Error> {
    let Some(mut account) = Account::find_any_by_id(id, &database).await? else {
        return Ok(None);
    };
    account.deactivate(&database).await?;
    Ok(Some(account))
}

/// Revokes an order's issued certificate at the signer backend and records it on the order.
///
/// `actor`/`client` say who asked and from where. Both front ends supply their
/// own: [`Actor::cli`] with an empty [`ClientContext`] from the command line,
/// [`Actor::admin`] with the operator's address from the web admin. Passed in
/// rather than derived here because this layer is deliberately front-end
/// agnostic — it is the same reason the destructive operations come in a bare
/// and a `confirm_*` form.
///
/// The four outcomes that are *not* a revocation (`NotFound`, `NotIssued`,
/// `AlreadyRevoked`, a bad reason code) write no audit row. They are the
/// operator being told the state of things, not the CA refusing something it
/// might have done — unlike `POST /revokeCert`'s refusals, which are a remote
/// party being turned away and are audited for exactly that reason.
pub async fn revoke_order(
    id: &str,
    reason: Option<u32>,
    actor: Actor,
    client: ClientContext,
    database: Arc<Database>,
    signer: Arc<dyn SignerBackend>,
) -> Result<RevokeOutcome, RevokeError> {
    let Some(mut order) = Order::find_by_id(id, &database).await? else {
        return Ok(RevokeOutcome::NotFound);
    };
    let Some(chain) = order.certificate.clone() else {
        return Ok(RevokeOutcome::NotIssued);
    };
    if order.revoked_at.is_some() {
        return Ok(RevokeOutcome::AlreadyRevoked);
    }
    if let Some(r) = reason
        && !crate::cert::is_valid_revocation_reason(r)
    {
        return Err(RevokeError::BadReason(r));
    }

    let cert_der = crate::cert::leaf_der_from_chain(&chain).map_err(|error| {
        RevokeError::Internal(format!("stored certificate chain is unparsable: {error}"))
    })?;
    let mut record = AuditRecord::new(
        AuditEvent::CertificateRevoked,
        &order.profile,
        actor.clone(),
    )
    .with_order(&order)
    .with_client(client.clone());
    if let Some(serial) = order.cert_serial.clone() {
        record = record.with_serial(serial);
    }
    // Absent rather than empty when no reason was given — see the same rule in
    // `post_revoke_cert`.
    if let Some(reason) = reason {
        record = record.with_reason(reason.to_string());
    }

    // The signer first, as on the ACME path: the CA-side action is
    // authoritative, so a failure there must leave the order un-revoked for a
    // retry — and must be audited as the attempt it was.
    if let Err(error) = signer.revoke(&cert_der, reason).await {
        crate::audit::write(
            AuditRecord::new(AuditEvent::CertificateRevokeFailed, &order.profile, actor)
                .with_order(&order)
                .with_client(client)
                .with_reason("serverInternal")
                .with_detail(error.to_string()),
            &database,
        )
        .await;
        return Err(error.into());
    }
    order.revoke(reason.map(i64::from), &database).await?;
    crate::audit::write(record, &database).await;
    Ok(RevokeOutcome::Revoked(Box::new(order)))
}

/// The `created_at` below which an audit row is past `retention_days`.
///
/// One function so `acme-proxy audit cleanup --older-than` and the
/// `audit.retention_days` sweep delete the identical set — a CLI that computed
/// its own cutoff would eventually disagree with the timer by a rounding rule.
#[must_use]
pub fn audit_cutoff(days: u64) -> i64 {
    let seconds = i64::try_from(days.saturating_mul(24 * 60 * 60)).unwrap_or(i64::MAX);
    crate::sqlite::nonce::now_secs().saturating_sub(seconds)
}

/// One page of audit rows, plus the unpaged total the same filters match.
pub async fn list_audit(
    query: &AuditQuery,
    database: Arc<Database>,
) -> Result<(Vec<AuditEntry>, i64), sqlx::Error> {
    AuditEntry::search(query, &database).await
}

/// One audit row by id.
pub async fn find_audit(
    id: i64,
    database: Arc<Database>,
) -> Result<Option<AuditEntry>, sqlx::Error> {
    AuditEntry::find_by_id(id, &database).await
}

/// Deletes audit rows older than `days`, returning how many went.
pub async fn cleanup_audit(days: u64, database: Arc<Database>) -> Result<u64, sqlx::Error> {
    AuditEntry::cleanup(audit_cutoff(days), &database).await
}

/// Confirms, then runs [`cleanup_audit`]. `None` when the operator declined.
///
/// Confirm-gated, unlike `revoke_order`: this is the one operation in the crate
/// that destroys audit history, and the prompt names how many rows are about to
/// go — a number the operator usually did not expect.
pub async fn confirm_cleanup_audit(
    days: u64,
    assume_yes: bool,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<Option<u64>, sqlx::Error> {
    let cutoff = audit_cutoff(days);
    let doomed = AuditEntry::count_older_than(cutoff, &database).await?;
    let prompt =
        format!("Delete {doomed} audit row(s) older than {days} day(s)? This cannot be undone.");
    if !confirm(&prompt, assume_yes, reader) {
        return Ok(None);
    }
    Ok(Some(AuditEntry::cleanup(cutoff, &database).await?))
}

/// Loads order detail.
pub async fn load_order_detail(
    id: &str,
    database: Arc<Database>,
) -> Result<Option<OrderDetail>, sqlx::Error> {
    let Some(order) = Order::find_by_id(id, &database).await? else {
        return Ok(None);
    };
    let authzs = Authorization::find_by_order(order.id, &database).await?;
    let mut authorizations = Vec::with_capacity(authzs.len());
    for authz in authzs {
        let challenges = Challenge::find_by_authz(authz.id, &database).await?;
        authorizations.push((authz, challenges));
    }
    Ok(Some(OrderDetail {
        order,
        authorizations,
    }))
}

// ---------------------------------------------------------------------------
// The expiry list
//
// One query (`Order::find_expiring`), one annotator (`annotate_expiring`) and
// three consumers: the `[notify.expiry]` digest, the panel (`GET /api/expiring`
// and `/ui/expiring`) and `order list --expiring-in`. The annotation used to
// live inside the digest's job type, where the panel could not reach it — two
// answers to "has this been replaced?" was exactly one too many.
// ---------------------------------------------------------------------------

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
    /// [`expiring_horizon`] rather than computing it a second time.
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
/// [`audit_cutoff`]'s twin, and for its reason: one function so the digest,
/// the panel and `order list --expiring-in` cannot come to disagree by a
/// rounding rule.
#[must_use]
pub fn expiring_horizon(days: u64) -> i64 {
    let seconds = i64::try_from(days.saturating_mul(24 * 60 * 60)).unwrap_or(i64::MAX);
    now_secs().saturating_add(seconds)
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
/// missing one is only noise. `crate::notify::expiry`'s module docs carry that
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
    crate::cert::leaf_der_from_chain(chain)
        .ok()
        .and_then(|der| crate::cert::ari_cert_id(&der).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::order::Identifier;
    use crate::testutil::{account_id, issued_order};

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

    /// The actor the CLI supplies, which is what these tests stand in for.
    /// `Actor::cli` reads `$USER`, so it is called rather than hard-coded — the
    /// point of the tests below is the revocation, not the name on the row.
    fn cli_actor() -> Actor {
        Actor::cli()
    }

    async fn audit_rows(db: &Arc<Database>) -> Vec<AuditEntry> {
        AuditEntry::search(
            &AuditQuery {
                limit: 50,
                ..AuditQuery::default()
            },
            db,
        )
        .await
        .unwrap()
        .0
    }

    /// One cutoff function, so `audit cleanup --older-than` and the
    /// `audit.retention_days` sweep delete the identical set.
    #[test]
    fn the_audit_cutoff_is_days_before_now_and_saturates_rather_than_overflowing() {
        let now = crate::sqlite::nonce::now_secs();
        assert!((audit_cutoff(0) - now).abs() <= 1);
        let week = audit_cutoff(7);
        assert!((now - week - 7 * 24 * 60 * 60).abs() <= 1, "{week}");
        // A nonsense retention must not panic in a debug build.
        assert!(audit_cutoff(u64::MAX) <= now);
    }

    /// The confirm gate: declined leaves the trail intact, accepted prunes by
    /// age and nothing else.
    #[tokio::test]
    async fn cleaning_the_audit_trail_is_confirm_gated_and_bounded_by_age() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        AuditEntry::insert(
            AuditRecord::new(AuditEvent::CertificateIssued, "default", Actor::system()),
            &db,
        )
        .await
        .unwrap();

        let mut declined: &[u8] = b"n\n";
        assert_eq!(
            confirm_cleanup_audit(0, false, &mut declined, db.clone())
                .await
                .unwrap(),
            None
        );
        assert_eq!(audit_rows(&db).await.len(), 1);

        // Nothing is a week old yet.
        let mut reader: &[u8] = &[];
        assert_eq!(
            confirm_cleanup_audit(7, true, &mut reader, db.clone())
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(audit_rows(&db).await.len(), 1);

        assert_eq!(cleanup_audit(0, db.clone()).await.unwrap(), 0);

        // A cutoff in the future takes it.
        assert_eq!(
            AuditEntry::cleanup(audit_cutoff(0) + 3600, &db)
                .await
                .unwrap(),
            1
        );
        assert!(audit_rows(&db).await.is_empty());
    }

    /// `list_audit`/`find_audit` are the thin pass-throughs both front ends
    /// share; this pins that they page and look up rather than doing anything
    /// of their own.
    #[tokio::test]
    async fn listing_and_finding_audit_rows_pages_and_resolves() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                AuditEntry::insert(
                    AuditRecord::new(AuditEvent::CertificateIssued, "default", Actor::system()),
                    &db,
                )
                .await
                .unwrap(),
            );
        }

        let (page, total) = list_audit(
            &AuditQuery {
                limit: 2,
                ..AuditQuery::default()
            },
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);

        assert!(find_audit(ids[0], db.clone()).await.unwrap().is_some());
        assert!(find_audit(9_999, db).await.unwrap().is_none());
    }

    /// A revocation through this layer writes exactly one row, naming the
    /// actor the caller supplied rather than the order's own account — which
    /// is the whole point of the parameter.
    #[tokio::test]
    async fn revoking_writes_one_audit_row_naming_the_caller() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let signer = in_memory_ca();
        let order = finalized_order(db.clone(), &signer).await;

        let outcome = revoke_order(
            order.id.to_string().as_str(),
            Some(1),
            Actor::admin("root"),
            ClientContext {
                ip: Some("203.0.113.7".to_string()),
                ptr: Some("desk.example.com".to_string()),
                ..ClientContext::default()
            },
            db.clone(),
            signer.clone(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RevokeOutcome::Revoked(_)));

        let rows = audit_rows(&db).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(row.event, "certificate_revoked");
        assert_eq!(row.outcome, "success");
        assert_eq!(row.actor_kind, "admin");
        assert_eq!(row.actor_id.as_deref(), Some("root"));
        assert_eq!(row.account_id, Some(order.account_id.to_string()));
        assert_eq!(row.order_id, Some(order.id.to_string()));
        assert_eq!(row.cert_serial, order.cert_serial);
        assert_eq!(row.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(row.client_ptr.as_deref(), Some("desk.example.com"));
        assert_eq!(row.reason.as_deref(), Some("1"));

        // Revoking again is `AlreadyRevoked` and writes nothing: the operator
        // is being told the state of things, not refused a CA action.
        let outcome = revoke_order(
            order.id.to_string().as_str(),
            None,
            Actor::admin("root"),
            ClientContext::default(),
            db.clone(),
            signer,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RevokeOutcome::AlreadyRevoked));
        assert_eq!(audit_rows(&db).await.len(), 1);
    }

    /// No reason given is an **absent** `reason`, not an empty one: RFC 8555
    /// §7.6 allows omitting it, and that is not the same as `unspecified` (0).
    #[tokio::test]
    async fn a_revocation_with_no_reason_leaves_the_column_absent() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let signer = in_memory_ca();
        let order = finalized_order(db.clone(), &signer).await;

        revoke_order(
            order.id.to_string().as_str(),
            None,
            cli_actor(),
            ClientContext::default(),
            db.clone(),
            signer,
        )
        .await
        .unwrap();

        let rows = audit_rows(&db).await;
        assert_eq!(rows[0].reason, None);
        assert_eq!(rows[0].actor_kind, "cli");
        // A CLI revocation genuinely has no client, and says so.
        assert_eq!(rows[0].client_ip, None);
        assert_eq!(rows[0].client_ptr, None);
    }

    #[tokio::test]
    async fn delete_account_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut reader: &[u8] = &[];
        let outcome = confirm_delete_account("nope", true, &mut reader, db)
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::NotFound);
    }

    #[tokio::test]
    async fn delete_account_cancelled_leaves_row() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let mut reader = b"n\n".as_slice();
        let outcome =
            confirm_delete_account(acct.to_string().as_str(), false, &mut reader, db.clone())
                .await
                .unwrap();
        assert_eq!(outcome, DeleteOutcome::Cancelled);
        assert!(
            Account::find_by_id("default", acct.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_account_confirmed_deletes_and_cascades() {
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

        let mut reader: &[u8] = &[];
        let outcome =
            confirm_delete_account(acct.to_string().as_str(), true, &mut reader, db.clone())
                .await
                .unwrap();
        assert_eq!(outcome, DeleteOutcome::Deleted);
        assert!(
            Account::find_by_id("default", acct.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_order_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut reader: &[u8] = &[];
        let outcome = confirm_delete_order("nope", true, &mut reader, db)
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::NotFound);
    }

    #[tokio::test]
    async fn delete_order_cancelled_leaves_row() {
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

        let mut reader = b"no\n".as_slice();
        let outcome = confirm_delete_order(
            order.id.to_string().as_str(),
            false,
            &mut reader,
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, DeleteOutcome::Cancelled);
        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_order_confirmed_deletes_and_cascades() {
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

        let mut reader: &[u8] = &[];
        let outcome =
            confirm_delete_order(order.id.to_string().as_str(), true, &mut reader, db.clone())
                .await
                .unwrap();
        assert_eq!(outcome, DeleteOutcome::Deleted);
        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Authorization::find_by_id(authz.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    // The bare forms below are what the web admin calls: no prompt, no reader,
    // and a cascade count to report back instead of a bare acknowledgement.

    #[tokio::test]
    async fn bare_delete_account_reports_none_for_an_unknown_id() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert_eq!(delete_account("nope", db).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bare_delete_account_deletes_and_counts_the_cascade() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        for _ in 0..2 {
            Order::create(
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
        }

        assert_eq!(
            delete_account(acct.to_string().as_str(), db.clone())
                .await
                .unwrap(),
            Some(Deleted { cascaded: 2 })
        );
        assert!(
            Account::find_by_id("default", acct.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn bare_delete_order_reports_none_for_an_unknown_id() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert_eq!(delete_order("nope", db).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bare_delete_order_deletes_and_counts_the_cascade() {
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
        Authorization::create(
            order.id,
            Identifier::dns("example.com"),
            crate::sqlite::nonce::now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();

        assert_eq!(
            delete_order(order.id.to_string().as_str(), db.clone())
                .await
                .unwrap(),
            Some(Deleted { cascaded: 1 })
        );
        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn bare_cleanup_nonces_removes_stale_rows_without_asking() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let stale = Nonce {
            value: "stale".to_string(),
            created_at: crate::sqlite::nonce::now_secs() - 10_000,
        };
        stale.save(&db).await.unwrap();
        Nonce::new().save(&db).await.unwrap();

        assert_eq!(
            cleanup_nonces(Duration::from_secs(300), db.clone())
                .await
                .unwrap(),
            1
        );
        assert!(
            !Nonce::verify("stale", &db, Duration::from_secs(300))
                .await
                .unwrap()
        );
    }

    fn in_memory_ca() -> Arc<dyn SignerBackend> {
        Arc::new(
            crate::signer::local_ca::LocalCa::generate_in_memory("ecdsa-p256", 90)
                .expect("in-memory CA"),
        )
    }

    async fn finalized_order(db: Arc<Database>, signer: &Arc<dyn SignerBackend>) -> Order {
        let acct = account_id(&db).await;
        let mut order = Order::create(
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

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let chain = match signer
            .issue(
                order.id.to_string().as_str(),
                csr.der(),
                &order.identifiers,
                crate::signer::RequestedValidity::default(),
            )
            .await
            .unwrap()
        {
            crate::signer::IssueOutcome::Issued(chain) => chain,
            crate::signer::IssueOutcome::Processing => {
                panic!("the in-memory local CA issues synchronously")
            }
        };
        let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (serial, pubkey) = crate::cert::cert_serial_and_spki(&leaf).unwrap();
        let not_after = crate::cert::cert_validity(&leaf).ok().map(|(_, na)| na);
        order
            .finalize(chain, serial, pubkey, not_after, &db)
            .await
            .unwrap();
        order
    }

    #[tokio::test]
    async fn revoke_order_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let outcome = revoke_order(
            "nope",
            None,
            cli_actor(),
            ClientContext::default(),
            db,
            in_memory_ca(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RevokeOutcome::NotFound));
    }

    #[tokio::test]
    async fn revoke_order_without_a_certificate_is_refused() {
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

        let outcome = revoke_order(
            order.id.to_string().as_str(),
            None,
            cli_actor(),
            ClientContext::default(),
            db,
            in_memory_ca(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RevokeOutcome::NotIssued));
    }

    #[tokio::test]
    async fn revoke_order_persists() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let signer = in_memory_ca();
        let order = finalized_order(db.clone(), &signer).await;

        let outcome = revoke_order(
            order.id.to_string().as_str(),
            Some(1),
            cli_actor(),
            ClientContext::default(),
            db.clone(),
            signer.clone(),
        )
        .await
        .unwrap();
        let RevokeOutcome::Revoked(revoked) = outcome else {
            panic!("expected Revoked, got {outcome:?}");
        };
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoked.revocation_reason, Some(1));

        let reloaded = Order::find_by_id(order.id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert!(reloaded.revoked_at.is_some());

        use x509_parser::prelude::FromDer;
        let der = signer.crl_der().await.unwrap();
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
        assert_eq!(crl.iter_revoked_certificates().count(), 1);
    }

    #[tokio::test]
    async fn revoke_order_already_revoked() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let signer = in_memory_ca();
        let order = finalized_order(db.clone(), &signer).await;

        revoke_order(
            order.id.to_string().as_str(),
            None,
            cli_actor(),
            ClientContext::default(),
            db.clone(),
            signer.clone(),
        )
        .await
        .unwrap();
        let outcome = revoke_order(
            order.id.to_string().as_str(),
            None,
            cli_actor(),
            ClientContext::default(),
            db,
            signer,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RevokeOutcome::AlreadyRevoked));
    }

    #[tokio::test]
    async fn revoke_order_bad_reason_is_refused() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let signer = in_memory_ca();
        let order = finalized_order(db.clone(), &signer).await;

        let error = revoke_order(
            order.id.to_string().as_str(),
            Some(999),
            cli_actor(),
            ClientContext::default(),
            db,
            signer,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RevokeError::BadReason(999)));
    }

    #[tokio::test]
    async fn cleanup_nonces_cancelled_leaves_nonces() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        Nonce {
            value: "stale".to_string(),
            created_at: crate::sqlite::nonce::now_secs() - 600,
        }
        .save(&db)
        .await
        .unwrap();

        let mut reader = b"n\n".as_slice();
        let outcome =
            confirm_cleanup_nonces(Duration::from_secs(300), false, &mut reader, db.clone())
                .await
                .unwrap();
        assert_eq!(outcome, None);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nonces;")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn cleanup_nonces_confirmed_removes_stale_and_reports_count() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        Nonce {
            value: "stale".to_string(),
            created_at: crate::sqlite::nonce::now_secs() - 600,
        }
        .save(&db)
        .await
        .unwrap();

        let mut reader: &[u8] = &[];
        let outcome =
            confirm_cleanup_nonces(Duration::from_secs(300), true, &mut reader, db.clone())
                .await
                .unwrap();
        assert_eq!(outcome, Some(1));

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nonces;")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn update_account_contact_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(
            update_account_contact("nope", vec![], db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn update_account_contact_persists() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let contact = vec!["mailto:a@example.com".to_string()];
        let updated =
            update_account_contact(acct.to_string().as_str(), contact.clone(), db.clone())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(updated.contact, contact);

        let reloaded = Account::find_by_id("default", acct.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.contact, contact);
    }

    #[tokio::test]
    async fn deactivate_account_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(deactivate_account("nope", db).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deactivate_account_persists() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let updated = deactivate_account(acct.to_string().as_str(), db.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "deactivated");

        let reloaded = Account::find_by_id("default", acct.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "deactivated");
    }

    #[tokio::test]
    async fn load_order_detail_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(load_order_detail("nope", db).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn load_order_detail_nests_authorizations_and_challenges() {
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
        assert_eq!(detail.order.id, order.id);
        assert_eq!(detail.authorizations.len(), 1);
        assert_eq!(detail.authorizations[0].0.id, authz.id);
        assert_eq!(detail.authorizations[0].1.len(), 1);
        assert_eq!(detail.authorizations[0].1[0].typ, "http-01");
    }

    #[test]
    fn revoke_error_display_formatting() {
        let db_err: RevokeError = sqlx::Error::RowNotFound.into();
        assert!(format!("{db_err}").contains("database error"));

        let signer_internal: RevokeError = SignerError::Internal("test".to_string()).into();
        assert!(format!("{signer_internal}").contains("signer error: test"));

        let signer_bad_csr: RevokeError = SignerError::BadCsr.into();
        assert!(format!("{signer_bad_csr}").contains("unexpected badCsr"));

        let internal = RevokeError::Internal("detail".to_string());
        assert!(format!("{internal}").contains("internal error: detail"));

        let bad_reason = RevokeError::BadReason(7);
        assert!(format!("{bad_reason}").contains("unsupported revocation reason code 7"));
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
            .execute(&db.pool)
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
            .execute(&db.pool)
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
        let (other, _created) = crate::sqlite::account::Account::find_or_create(
            "default",
            b"other-key",
            Vec::new(),
            &crate::audit::ClientContext::default(),
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
