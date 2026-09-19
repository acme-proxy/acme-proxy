use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::account::Account;
use crate::db::Database;
use crate::nonce::now_secs;
use crate::order::rfc3339;
use acme_proxy_core::random::random_bytes;

/// An External Account Binding credential (RFC 8555 §7.3.4): a pre-shared
/// `kid` + HMAC secret an operator issues out-of-band, presented by a client
/// at `newAccount` to prove it was authorized to register.
///
/// Reusable: the same key can bind more than one account, until revoked (see
/// the migration). There is therefore no "used" status, only
/// `active`/`revoked`.
///
/// ## Methods
///
/// - `create`: generate a fresh key and persist it, `active`
/// - `find_by_kid`: lookup by kid (the request-time verification path)
/// - `search`: one page of the listing, newest first, plus the unpaged total --
///   the only listing of this table, read by `eab list`, `/ui/eab` and
///   `GET /api/eab` alike
/// - `revoke`: move to the terminal `revoked` state, keeping the row
/// - `delete`: remove the row, and with it deactivate, delete or leave the
///   accounts it bound (see [`BoundAccounts`])
/// - `to_json`: admin-facing rendering (never includes the secret)
#[derive(Debug)]
pub struct Eab {
    pub kid: Uuid,
    pub secret: Vec<u8>,
    pub label: Option<String>,
    /// Which ACME endpoint the credential is good for. `None` means every
    /// profile -- the default, for an operator who does not care to scope it.
    pub profile: Option<String>,
    pub status: String,
    pub created_at: i64,
}

/// What `eab delete` does to the accounts a credential bound.
///
/// `Keep` is the default because it is the only one that changes nothing
/// beyond the credential — but it is not free: an account whose kid names a
/// deleted row resolves to no credential at all, so every `type = "eab"` filter
/// check refuses it from then on (`acme::policy` finds nothing to build an
/// `EabIdentity` from).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BoundAccounts {
    /// Leave them as they are.
    #[default]
    Keep,
    /// Move them to `deactivated` (RFC 8555 §7.3.6), keeping their orders — so
    /// every certificate they hold stays revocable, in the expiry digest and in
    /// renewal information until it expires.
    Deactivate,
    /// Hard-delete them and everything under them. Refused while any of their
    /// orders holds a live certificate.
    Delete,
}

impl BoundAccounts {
    /// Every spelling [`BoundAccounts::parse`] accepts, for a refusal to list.
    pub const ALL: [BoundAccounts; 3] = [Self::Keep, Self::Deactivate, Self::Delete];

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Deactivate => "deactivate",
            Self::Delete => "delete",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }
}

/// What [`Eab::delete`] did.
#[derive(Debug)]
pub enum EabDeletion {
    NotFound,
    /// Refused, and nothing changed: [`BoundAccounts::Delete`] was asked of a
    /// credential whose accounts still hold live certificates.
    LiveCertificates {
        accounts: u64,
        certificates: u64,
    },
    Deleted(DeletedEab),
}

/// A credential [`Eab::delete`] removed, and what became of its accounts.
#[derive(Debug)]
pub struct DeletedEab {
    /// The row as it was — its label and profile name the audit row.
    pub eab: Eab,
    pub accounts: BoundAccounts,
    /// The accounts [`BoundAccounts::Deactivate`] changed, as they now are.
    /// Those already deactivated are not here: nothing happened to them.
    pub deactivated: Vec<Account>,
    /// The accounts [`BoundAccounts::Delete`] removed, each with the number of
    /// orders that cascaded with it.
    pub deleted: Vec<(Account, u64)>,
    /// Accounts still in the table naming the deleted kid.
    pub remaining: u64,
}

/// Length, in bytes, of a freshly generated HMAC secret: 32 (256 bits),
/// matching HS256's key size.
const SECRET_LEN: usize = 32;

impl Eab {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Eab {
            kid: row.try_get("kid")?,
            secret: row.try_get("secret")?,
            label: row.try_get("label")?,
            profile: row.try_get("profile")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Generates a fresh key (random UUID `kid` + random 32-byte secret) and
    /// persists it `active`. Returns the created row so the caller (the
    /// `eab create` admin command) can print the secret **once** -- this is
    /// the only time it is meant to leave the database in plaintext form.
    pub async fn create(
        label: Option<String>,
        profile: Option<String>,
        database: &Database,
    ) -> Result<Eab, sqlx::Error> {
        let eab = Eab {
            kid: crate::id::mint(),
            secret: random_bytes::<SECRET_LEN>().to_vec(),
            label,
            profile,
            status: "active".to_string(),
            created_at: now_secs(),
        };

        debug!(event = "db_eab_create_started", outcome = "progress", kid = ?eab.kid, profile = ?eab.profile);
        sqlx::query(
            "INSERT INTO eab_keys (kid, secret, label, profile, status, created_at) \
             VALUES (?, ?, ?, ?, ?, ?);",
        )
        .bind(eab.kid)
        .bind(&eab.secret)
        .bind(&eab.label)
        .bind(&eab.profile)
        .bind(&eab.status)
        .bind(eab.created_at)
        .execute(&database.pool)
        .await?;

        info!(event = "db_eab_created", outcome = "success", kid = ?eab.kid);
        Ok(eab)
    }

    /// Looks a credential up for use at `profile`. A row scoped to another
    /// profile is *not* returned: to the endpoint asking, it does not exist.
    /// A row with no profile at all matches everywhere.
    pub async fn find_by_kid(
        kid: &str,
        profile: &str,
        database: &Database,
    ) -> Result<Option<Eab>, sqlx::Error> {
        debug!(event = "db_eab_find_by_kid_started", outcome = "progress", kid = ?kid, profile = %profile);
        let Some(kid) = crate::id::parse(kid) else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys \
             WHERE kid = ? AND (profile IS NULL OR profile = ?);",
        )
        .bind(kid)
        .bind(profile)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Eab::from_row).transpose()
    }

    /// Looks a credential up by kid regardless of the profile it is scoped to
    /// -- the admin CLI's `eab show`/`eab revoke`, where the operator holds the
    /// kid and wants to see it whatever it is bound to. Never the request path,
    /// which must use [`Eab::find_by_kid`].
    pub async fn find_any_by_kid(
        kid: &str,
        database: &Database,
    ) -> Result<Option<Eab>, sqlx::Error> {
        debug!(event = "db_eab_find_any_by_kid_started", outcome = "progress", kid = ?kid);
        let Some(kid) = crate::id::parse(kid) else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys WHERE kid = ?;",
        )
        .bind(kid)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Eab::from_row).transpose()
    }

    /// One page of the listing, plus the total the table holds unpaged.
    ///
    /// The **only** listing of this table: `GET /api/eab`, `/ui/eab` and
    /// `eab list` all read it, which is what stops the three describing one
    /// credential set differently.
    ///
    /// **Newest first**, like `Account::search` and `Order::search`. It was
    /// oldest first while the page and the command still read an unpaged
    /// `list_all` — the reason recorded here was that flipping it would make
    /// the API disagree with them — and that reason expired when both moved
    /// onto this query. What settles the direction now is the mint form:
    /// `pages::eab::create_eab` re-renders the table out of band so a new
    /// credential appears without a reload, and the only page it can sensibly
    /// render is the first, so the new row has to be on it. `kid` breaks the
    /// `created_at` tie for `Account::search`'s reason — whole-second
    /// timestamps would otherwise let two rows swap between pages, and one of
    /// them would never be seen — and it breaks it **`DESC`**, following the
    /// primary key rather than opposing it: a `kid` is a UUID v7, so an `ASC`
    /// tiebreak would hand back the *oldest* of the credentials minted inside
    /// one second, which is exactly the second the mint form re-renders in.
    pub async fn search(
        limit: i64,
        offset: i64,
        database: &Database,
    ) -> Result<(Vec<Eab>, i64), sqlx::Error> {
        debug!(
            event = "db_eab_search_started",
            outcome = "progress",
            limit = limit,
            offset = offset
        );
        let rows = sqlx::query(
            "SELECT kid, secret, label, profile, status, created_at FROM eab_keys \
             ORDER BY created_at DESC, kid DESC LIMIT ? OFFSET ?;",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&database.pool)
        .await?;
        let total: i64 = sqlx::query("SELECT COUNT(*) FROM eab_keys;")
            .fetch_one(&database.pool)
            .await?
            .try_get(0)?;

        let keys = rows
            .into_iter()
            .map(Eab::from_row)
            .collect::<Result<_, _>>()?;
        Ok((keys, total))
    }

    /// Moves the key to the terminal-for-new-use `revoked` state. Existing
    /// accounts bound under it are unaffected (see the migration's note on
    /// `accounts.eab_kid`), and — unlike [`Eab::delete`] — they still resolve to
    /// this row, so a `type = "eab"` filter check keeps matching them by label
    /// (or refuses them, under `require_active`). Idempotent: revoking an already-revoked key still
    /// matches the row and reports `true`. Returns whether a row existed.
    pub async fn revoke(kid: &str, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "db_eab_revoke_started", outcome = "progress", kid = ?kid);
        let Some(kid) = crate::id::parse(kid) else {
            return Ok(false);
        };
        let result = sqlx::query("UPDATE eab_keys SET status = 'revoked' WHERE kid = ?;")
            .bind(kid)
            .execute(&database.pool)
            .await?;

        let updated = result.rows_affected() > 0;
        if updated {
            info!(event = "db_eab_revoked", outcome = "success", kid = ?kid);
        } else {
            debug!(event = "db_eab_revoke_missing", outcome = "success", kid = ?kid);
        }
        Ok(updated)
    }

    /// Deletes the credential, doing `accounts` to the accounts it bound, all in
    /// one transaction.
    ///
    /// The credential's `DELETE` is the transaction's first statement, so the
    /// write lock is held from the start: nothing can issue under one of its
    /// accounts between [`Account::live_certificates_by_eab_kid`] answering
    /// "none" and the accounts going. A refusal rolls the credential back with
    /// everything else, which is why it is not checked up front instead.
    pub async fn delete(
        kid: &str,
        accounts: BoundAccounts,
        database: &Database,
    ) -> Result<EabDeletion, sqlx::Error> {
        debug!(event = "db_eab_delete_started", outcome = "progress", kid = ?kid, accounts = accounts.as_str());
        let Some(kid) = crate::id::parse(kid) else {
            return Ok(EabDeletion::NotFound);
        };

        let mut tx = database.pool.begin().await?;
        let Some(row) = sqlx::query(
            "DELETE FROM eab_keys WHERE kid = ? \
             RETURNING kid, secret, label, profile, status, created_at;",
        )
        .bind(kid)
        .fetch_optional(&mut *tx)
        .await?
        else {
            debug!(event = "db_eab_delete_missing", outcome = "success", kid = ?kid);
            return Ok(EabDeletion::NotFound);
        };
        let eab = Eab::from_row(row)?;

        let mut deactivated = Vec::new();
        let mut deleted = Vec::new();
        match accounts {
            BoundAccounts::Keep => {}
            BoundAccounts::Deactivate => {
                deactivated = Account::deactivate_by_eab_kid(kid, &mut tx).await?;
            }
            BoundAccounts::Delete => {
                let (holders, certificates) =
                    Account::live_certificates_by_eab_kid(kid, &mut tx).await?;
                if certificates > 0 {
                    tx.rollback().await?;
                    info!(event = "db_eab_delete_blocked", outcome = "failure", kid = ?kid, accounts = holders, live_certificates = certificates);
                    return Ok(EabDeletion::LiveCertificates {
                        accounts: holders,
                        certificates,
                    });
                }
                deleted = Account::delete_by_eab_kid(kid, &mut tx).await?;
            }
        }

        let remaining: i64 = sqlx::query("SELECT COUNT(*) FROM accounts WHERE eab_kid = ?;")
            .bind(kid)
            .fetch_one(&mut *tx)
            .await?
            .try_get(0)?;
        tx.commit().await?;

        info!(event = "db_eab_deleted",
              outcome = "success",
              kid = ?kid,
              accounts = accounts.as_str(),
              accounts_deactivated = deactivated.len(),
              rows_removed = deleted.len());
        Ok(EabDeletion::Deleted(DeletedEab {
            eab,
            accounts,
            deactivated,
            deleted,
            remaining: remaining as u64,
        }))
    }

    /// Whether this key may still be used to bind a new account.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// The admin-facing rendering: `kid`, `label`, `profile`, `status`,
    /// `createdAt`.
    /// **Never** includes the secret -- that is shown once, by `eab create`,
    /// via `admin::render_eab_created_json`/`render_eab_created_text`, never
    /// again from `show`/`list`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "kid": self.kid,
            "label": self.label,
            "profile": self.profile,
            "status": self.status,
            "createdAt": rfc3339(self.created_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn create_persists_an_active_key_with_a_32_byte_secret() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("team-a".to_string()), None, &db)
            .await
            .unwrap();
        assert_eq!(eab.status, "active");
        assert_eq!(eab.secret.len(), 32);
        assert_eq!(eab.label.as_deref(), Some("team-a"));
    }

    #[tokio::test]
    async fn find_by_kid_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let created = Eab::create(None, None, &db).await.unwrap();
        let found = Eab::find_by_kid(created.kid.to_string().as_str(), "default", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.secret, created.secret);
        assert!(found.label.is_none());
    }

    #[tokio::test]
    async fn find_by_kid_of_unknown_returns_none() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(
            Eab::find_by_kid("nope", "default", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Every key comes back, newest first, and an empty table is empty rather
    /// than an error.
    ///
    /// `created_at` is a whole second, so two keys minted in one test share it
    /// and the `kid` tie-break decides. That used to be a random uuid, and this
    /// test could say nothing about which came first; a `kid` is now a UUID v7
    /// (`sqlite::id::mint`), so the tie-break is insertion order -- the same
    /// observable `list_all_returns_every_user_and_empty_is_empty`
    /// (`sqlite::admin_user`) asserts, and for the same reason. It holds only
    /// for rows minted since that change, nothing having been backfilled.
    ///
    /// The direction is what `pages::eab::create_eab` rests on: it re-renders
    /// the first page out of band, so a credential minted a moment ago has to
    /// be its first row.
    #[tokio::test]
    async fn search_returns_every_key_newest_first_and_empty_is_empty() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Eab::search(50, 0, &db).await.unwrap().0.is_empty());

        let first = Eab::create(None, None, &db).await.unwrap();
        let second = Eab::create(None, None, &db).await.unwrap();
        let (all, total) = Eab::search(50, 0, &db).await.unwrap();
        assert_eq!((all.len(), total), (2, 2));
        let kids: Vec<String> = all.iter().map(|eab| eab.kid.to_string()).collect();
        assert_eq!(kids, [second.kid.to_string(), first.kid.to_string()]);
    }

    /// The window `GET /api/eab` hands down. Every row created inside one
    /// second here, which is exactly the case the `kid` tie-break exists for:
    /// without it two rows could swap between pages and one would never be
    /// seen.
    #[tokio::test]
    async fn search_pages_without_overlap_and_reports_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert_eq!(Eab::search(50, 0, &db).await.unwrap().1, 0);

        let created: Vec<String> = {
            let mut kids = Vec::new();
            for _ in 0..5 {
                kids.push(Eab::create(None, None, &db).await.unwrap().kid);
            }
            kids.into_iter().map(|v| v.to_string()).collect()
        };

        let (first, total) = Eab::search(2, 0, &db).await.unwrap();
        let (second, also_total) = Eab::search(2, 2, &db).await.unwrap();
        let (third, _) = Eab::search(2, 4, &db).await.unwrap();

        assert_eq!(total, 5);
        assert_eq!(also_total, 5, "the total is the table, not the page");
        assert_eq!((first.len(), second.len(), third.len()), (2, 2, 1));

        // Walked end to end, the pages are the table exactly once — which is
        // both "no overlap" and "nothing skipped" in one assertion.
        let walked: Vec<String> = first
            .iter()
            .chain(second.iter())
            .chain(third.iter())
            .map(|eab| eab.kid.to_string())
            .collect();
        assert_eq!(walked.len(), created.len());
        for kid in &created {
            assert_eq!(
                walked.iter().filter(|seen| *seen == kid).count(),
                1,
                "{kid} was not on exactly one page"
            );
        }
    }

    #[tokio::test]
    async fn revoke_marks_revoked_reports_true_and_is_idempotent() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(None, None, &db).await.unwrap();
        assert!(
            Eab::revoke(eab.kid.to_string().as_str(), &db)
                .await
                .unwrap()
        );
        assert!(
            !Eab::find_by_kid(eab.kid.to_string().as_str(), "default", &db)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        // Revoking again still matches the row.
        assert!(
            Eab::revoke(eab.kid.to_string().as_str(), &db)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn revoke_of_unknown_kid_reports_false() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(!Eab::revoke("nope", &db).await.unwrap());
    }

    /// A credential, and `count` accounts registered with it, each holding
    /// one certificate expiring at `not_after`.
    async fn bound(
        db: &Arc<Database>,
        count: u8,
        not_after: Option<i64>,
    ) -> (Eab, Vec<crate::account::Account>) {
        use acme_proxy_core::audit::ClientContext;

        let eab = Eab::create(Some("tenant".to_string()), None, db)
            .await
            .unwrap();
        let mut accounts = Vec::new();
        for index in 0..count {
            let (mut account, _) = Account::find_or_create(
                "default",
                &[eab.kid.as_bytes()[15], index],
                vec![],
                &ClientContext::default(),
                db,
            )
            .await
            .unwrap();
            account.set_eab_kid(eab.kid, db).await.unwrap();
            crate::testutil::certified_order(db, account.id, not_after).await;
            accounts.push(account);
        }
        (eab, accounts)
    }

    async fn account_exists(id: uuid::Uuid, db: &Database) -> bool {
        Account::find_any_by_id(id.to_string().as_str(), db)
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn delete_of_an_unknown_kid_is_not_found() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        for kid in ["nope".to_string(), crate::id::mint().to_string()] {
            assert!(matches!(
                Eab::delete(&kid, BoundAccounts::Delete, &db).await.unwrap(),
                EabDeletion::NotFound
            ));
        }
    }

    /// `Keep` removes the credential and nothing else: the accounts stay,
    /// still naming a kid that now resolves to nothing.
    #[tokio::test]
    async fn delete_keeping_accounts_removes_only_the_credential() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, accounts) = bound(&db, 2, Some(now_secs() + 86_400)).await;
        let kid = eab.kid.to_string();

        let EabDeletion::Deleted(deleted) =
            Eab::delete(&kid, BoundAccounts::Keep, &db).await.unwrap()
        else {
            panic!("keeping the accounts cannot be refused");
        };
        assert_eq!(deleted.eab.label.as_deref(), Some("tenant"));
        assert!(deleted.deactivated.is_empty() && deleted.deleted.is_empty());
        assert_eq!(deleted.remaining, 2);

        assert!(Eab::find_any_by_kid(&kid, &db).await.unwrap().is_none());
        for account in &accounts {
            let kept = Account::find_any_by_id(account.id.to_string().as_str(), &db)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (kept.status.as_str(), kept.eab_kid),
                ("valid", Some(eab.kid))
            );
        }
    }

    /// `Deactivate` moves the accounts to `deactivated` and keeps their orders
    /// — live certificates included, which is the point. An account already
    /// deactivated changed nothing and is not reported.
    #[tokio::test]
    async fn delete_deactivating_accounts_keeps_their_orders() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, mut accounts) = bound(&db, 3, Some(now_secs() + 86_400)).await;
        accounts[2].deactivate(&db).await.unwrap();

        let EabDeletion::Deleted(deleted) =
            Eab::delete(&eab.kid.to_string(), BoundAccounts::Deactivate, &db)
                .await
                .unwrap()
        else {
            panic!("deactivating is never refused");
        };
        assert_eq!(deleted.deactivated.len(), 2);
        assert!(
            deleted
                .deactivated
                .iter()
                .all(|account| account.status == "deactivated")
        );
        assert_eq!(deleted.remaining, 3);

        for account in &accounts {
            assert_eq!(
                crate::order::Order::find_by_account(account.id, &db)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    /// `Delete` is refused while any bound account holds a live certificate,
    /// and the refusal rolls back everything — the credential included.
    #[tokio::test]
    async fn delete_with_accounts_is_refused_by_a_live_certificate_and_changes_nothing() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, accounts) = bound(&db, 2, Some(now_secs() - 86_400)).await;
        crate::testutil::certified_order(&db, accounts[1].id, None).await;
        let kid = eab.kid.to_string();

        assert!(matches!(
            Eab::delete(&kid, BoundAccounts::Delete, &db).await.unwrap(),
            EabDeletion::LiveCertificates {
                accounts: 1,
                certificates: 1
            }
        ));
        assert!(Eab::find_any_by_kid(&kid, &db).await.unwrap().is_some());
        for account in &accounts {
            assert!(account_exists(account.id, &db).await);
        }
    }

    /// With no live certificate, `Delete` takes the credential, its accounts
    /// and their orders, reports each account's own cascade, and leaves
    /// another credential's accounts alone.
    #[tokio::test]
    async fn delete_with_accounts_removes_them_and_their_orders() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (eab, accounts) = bound(&db, 2, Some(now_secs() - 86_400)).await;
        crate::testutil::certified_order(&db, accounts[0].id, Some(now_secs() - 1)).await;
        let (_, others) = bound(&db, 1, Some(now_secs() + 86_400)).await;

        let EabDeletion::Deleted(deleted) =
            Eab::delete(&eab.kid.to_string(), BoundAccounts::Delete, &db)
                .await
                .unwrap()
        else {
            panic!("no live certificate, so nothing refuses");
        };
        let mut cascades: Vec<(uuid::Uuid, u64)> = deleted
            .deleted
            .iter()
            .map(|(account, orders)| (account.id, *orders))
            .collect();
        cascades.sort();
        let mut expected = vec![(accounts[0].id, 2), (accounts[1].id, 1)];
        expected.sort();
        assert_eq!(cascades, expected);
        assert_eq!(deleted.remaining, 0);

        for account in &accounts {
            assert!(!account_exists(account.id, &db).await);
            assert!(
                crate::order::Order::find_by_account(account.id, &db)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(account_exists(others[0].id, &db).await);
    }

    #[test]
    fn bound_accounts_parses_every_spelling_it_renders_and_nothing_else() {
        for mode in BoundAccounts::ALL {
            assert_eq!(BoundAccounts::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(BoundAccounts::parse("Delete"), None);
        assert_eq!(BoundAccounts::default(), BoundAccounts::Keep);
    }

    #[tokio::test]
    async fn to_json_never_includes_the_secret() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("x".to_string()), None, &db).await.unwrap();
        let json = eab.to_json();
        assert!(json.get("secret").is_none());
        assert!(json.get("hmacKey").is_none());
        assert_eq!(json["kid"], eab.kid.to_string());
        assert_eq!(json["status"], "active");
        assert_eq!(json["label"], "x");
    }
}
