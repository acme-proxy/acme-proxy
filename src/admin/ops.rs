use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;

use crate::admin::prompt::confirm;
use crate::audit::{Actor, AuditEvent, AuditRecord, ClientContext};
use crate::signer::{SignerBackend, SignerError};
use crate::sqlite::account::Account;
use crate::sqlite::audit::{AuditEntry, AuditQuery};
use crate::sqlite::authz::{Authorization, Challenge};
use crate::sqlite::db::Database;
use crate::sqlite::nonce::Nonce;
use crate::sqlite::order::Order;

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

/// Why [`revoke_order`] failed.
#[derive(Debug)]
pub enum RevokeError {
    Database(sqlx::Error),
    Signer(SignerError),
    Internal(String),
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

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::Signer(SignerError::Internal(detail)) => write!(f, "signer error: {detail}"),
            Self::Signer(SignerError::BadCsr) => {
                write!(f, "signer error: unexpected badCsr from revoke")
            }
            Self::Internal(detail) => write!(f, "internal error: {detail}"),
            Self::BadReason(reason) => write!(f, "unsupported revocation reason code {reason}"),
        }
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
    let order_count = Order::count_by_account(id, &database).await?;
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
    let authz_count = Authorization::count_by_order(id, &database).await?;
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
    if Account::find_any_by_id(id, &database).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(Order::count_by_account(id, &database).await? as u64))
}

/// The [`account_cascade`] counterpart for an order's authorizations.
async fn order_cascade(id: &str, database: Arc<Database>) -> Result<Option<u64>, sqlx::Error> {
    if Order::find_by_id(id, &database).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(
        Authorization::count_by_order(id, &database).await? as u64,
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
    let authzs = Authorization::find_by_order(&order.id, &database).await?;
    let mut authorizations = Vec::with_capacity(authzs.len());
    for authz in authzs {
        let challenges = Challenge::find_by_authz(&authz.id, &database).await?;
        authorizations.push((authz, challenges));
    }
    Ok(Some(OrderDetail {
        order,
        authorizations,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::order::Identifier;
    use crate::testutil::account_id;

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
            &order.id,
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
        assert_eq!(row.account_id.as_deref(), Some(order.account_id.as_str()));
        assert_eq!(row.order_id.as_deref(), Some(order.id.as_str()));
        assert_eq!(row.cert_serial, order.cert_serial);
        assert_eq!(row.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(row.client_ptr.as_deref(), Some("desk.example.com"));
        assert_eq!(row.reason.as_deref(), Some("1"));

        // Revoking again is `AlreadyRevoked` and writes nothing: the operator
        // is being told the state of things, not refused a CA action.
        let outcome = revoke_order(
            &order.id,
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
            &order.id,
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
        let outcome = confirm_delete_account(&acct, false, &mut reader, db.clone())
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::Cancelled);
        assert!(
            Account::find_by_id("default", &acct, &db)
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
            &acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let mut reader: &[u8] = &[];
        let outcome = confirm_delete_account(&acct, true, &mut reader, db.clone())
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::Deleted);
        assert!(
            Account::find_by_id("default", &acct, &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(Order::find_by_id(&order.id, &db).await.unwrap().is_none());
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
            &acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let mut reader = b"no\n".as_slice();
        let outcome = confirm_delete_order(&order.id, false, &mut reader, db.clone())
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::Cancelled);
        assert!(Order::find_by_id(&order.id, &db).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_order_confirmed_deletes_and_cascades() {
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

        let mut reader: &[u8] = &[];
        let outcome = confirm_delete_order(&order.id, true, &mut reader, db.clone())
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::Deleted);
        assert!(Order::find_by_id(&order.id, &db).await.unwrap().is_none());
        assert!(
            Authorization::find_by_id(&authz.id, &db)
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
                &acct,
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
            delete_account(&acct, db.clone()).await.unwrap(),
            Some(Deleted { cascaded: 2 })
        );
        assert!(
            Account::find_by_id("default", &acct, &db)
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
            &acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        Authorization::create(
            &order.id,
            Identifier::dns("example.com"),
            crate::sqlite::nonce::now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();

        assert_eq!(
            delete_order(&order.id, db.clone()).await.unwrap(),
            Some(Deleted { cascaded: 1 })
        );
        assert!(Order::find_by_id(&order.id, &db).await.unwrap().is_none());
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
            &acct,
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
                &order.id,
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
        order.finalize(chain, serial, pubkey, &db).await.unwrap();
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
            &acct,
            vec![Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let outcome = revoke_order(
            &order.id,
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
            &order.id,
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

        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
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
            &order.id,
            None,
            cli_actor(),
            ClientContext::default(),
            db.clone(),
            signer.clone(),
        )
        .await
        .unwrap();
        let outcome = revoke_order(
            &order.id,
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
            &order.id,
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
        let updated = update_account_contact(&acct, contact.clone(), db.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.contact, contact);

        let reloaded = Account::find_by_id("default", &acct, &db)
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

        let updated = deactivate_account(&acct, db.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "deactivated");

        let reloaded = Account::find_by_id("default", &acct, &db)
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
}
