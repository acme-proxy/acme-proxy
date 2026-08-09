use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{debug, info};
use uuid::Uuid;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;

/// An ACME identifier (RFC 8555 §7.1.4). Only `dns` is supported here, but the
/// type is kept generic so the JSON round-trips whatever a client sent.
///
/// Stored inside the order's `identifiers` JSON array and echoed verbatim in the
/// order object. Reused by the signer to check a finalize CSR's SANs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub typ: String,
    pub value: String,
}

impl Identifier {
    /// A `dns` identifier, which is every identifier this server issues for.
    ///
    /// Here rather than in a test helper because the struct had no constructor
    /// at all, and twelve modules had each grown their own `fn dns(&str)` to
    /// avoid writing the literal — the same accumulation that put `TempDir` in
    /// `testutil`, except these are one line each and belong in production,
    /// where the handlers building identifiers benefit too.
    #[must_use]
    pub fn dns(value: impl Into<String>) -> Self {
        Self::new("dns", value)
    }

    /// An identifier of any type. `typ` is kept a free string because RFC 8555
    /// §9.7.7 leaves the registry open and the order object echoes back
    /// whatever a client sent.
    #[must_use]
    pub fn new(typ: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            typ: typ.into(),
            value: value.into(),
        }
    }
}

/// An ACME order (RFC 8555 §7.1.3). A new order is created in the `pending`
/// state with one authorization per identifier; once every authorization is
/// `valid` (its `http-01` challenge triggered) the order moves to `ready` and is
/// finalizable.
///
/// ## Storage Details
///
/// - `identifiers` is persisted as a JSON array of `{type, value}` objects.
/// - `error` is a nullable JSON problem document (set if issuance fails).
/// - `certificate` holds the issued PEM chain, null until finalized.
/// - `cert_serial`/`cert_pubkey` are populated alongside `certificate` (by
///   [`Order::finalize`]) from the leaf's own serial (hex) and DER-SPKI public
///   key — the former is how a `POST /revokeCert` request is looked up
///   ([`Order::find_by_cert_serial`]), the latter is how it can be authorized
///   by the certificate's own key pair (RFC 8555 §7.6's accountless case).
/// - `revoked_at`/`revocation_reason` are this order's own revocation
///   bookkeeping ([`Order::revoke`]), orthogonal to `status`: RFC 8555 defines
///   no "revoked" order status, so a revoked order's `status` stays `valid`.
/// - Timestamps are epoch seconds, matching accounts/nonces, and rendered as
///   RFC3339 datetime strings in [`Order::to_json`].
/// - The `authorizations` URLs are derived from the order's authorization ids
///   (looked up separately and passed into [`Order::to_json`]); the `finalize`/
///   `certificate` URLs are derived from the id + base URL, never stored (like
///   `Account`'s `orders` URL).
#[derive(Debug)]
pub struct Order {
    pub id: String,
    /// The ACME endpoint (`[profiles.<name>]`) this order was placed at. It
    /// always matches the owning account's own `profile` — the redundancy is
    /// what lets the two lookups that take no account (`find_by_cert_serial`,
    /// for revocation, and ARI) stay scoped to one endpoint.
    pub profile: String,
    pub account_id: String,
    pub status: String,
    pub identifiers: Vec<Identifier>,
    pub expires: i64,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub error: Option<Value>,
    pub certificate: Option<String>,
    /// The RFC 9773 §5 certID of the certificate this order is meant to
    /// replace, when the client named one. Reflected back in [`Order::to_json`]
    /// because §5 requires it: "If the server accepts a newOrder request with a
    /// `replaces` field, it MUST reflect that field in the response and in
    /// subsequent requests for the corresponding Order object."
    pub replaces: Option<String>,
    pub cert_serial: Option<String>,
    pub cert_pubkey: Option<Vec<u8>>,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
    pub created_at: i64,
    /// Where `newOrder` was called from, and the reverse name that address had
    /// at the time. Traceability only, never compared, and deliberately never
    /// rendered by [`Order::to_json`] — see the schema comment in
    /// `migrations/20260725120000_add_orders.sql`. There is no update-side
    /// pair: the moment that matters after creation is issuance, which is an
    /// `audit_log` row carrying its own address.
    pub created_ip: Option<String>,
    pub created_ptr: Option<String>,
}

/// The filters and page window [`Order::search`] applies.
///
/// Every field is optional except the window, and an absent filter imposes no
/// constraint — so `OrderQuery { limit, offset, .. }` alone is "the newest
/// page across every endpoint".
#[derive(Debug, Clone, Default)]
pub struct OrderQuery {
    pub profile: Option<String>,
    pub account_id: Option<String>,
    pub status: Option<String>,
    /// Rows per page. The caller clamps this (`admin.page_size_max`); this
    /// layer takes what it is given.
    pub limit: i64,
    pub offset: i64,
}

impl OrderQuery {
    /// Appends the `WHERE` clause shared by the page query and the count.
    ///
    /// One function rather than two copies: a filter applied to only one of
    /// them would report a total that does not match the rows returned, which
    /// is the kind of bug a page control shows and nothing else does.
    fn push_predicates(&self, builder: &mut sqlx::QueryBuilder<sqlx::Sqlite>) {
        let mut separator = " WHERE ";
        for (column, value) in [
            ("profile = ", self.profile.as_ref()),
            ("account_id = ", self.account_id.as_ref()),
            ("status = ", self.status.as_ref()),
        ] {
            if let Some(value) = value {
                builder
                    .push(separator)
                    .push(column)
                    .push_bind(value.clone());
                separator = " AND ";
            }
        }
    }
}

/// Renders epoch `secs` as an RFC3339 datetime string (the shape RFC 8555 uses
/// for order datetime fields), falling back to an empty string for the
/// out-of-range timestamps that should never occur in practice. Shared with the
/// authorization/challenge model, which renders datetimes the same way.
pub(crate) fn rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_default()
}

impl Order {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let identifiers_json: String = row.try_get("identifiers")?;
        let identifiers: Vec<Identifier> = serde_json::from_str(&identifiers_json)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let error_json: Option<String> = row.try_get("error")?;
        let error: Option<Value> = match error_json {
            Some(text) => {
                Some(serde_json::from_str(&text).map_err(|e| sqlx::Error::Decode(Box::new(e)))?)
            }
            None => None,
        };

        Ok(Order {
            id: row.try_get("id")?,
            profile: row.try_get("profile")?,
            account_id: row.try_get("account_id")?,
            status: row.try_get("status")?,
            identifiers,
            expires: row.try_get("expires")?,
            not_before: row.try_get("not_before")?,
            not_after: row.try_get("not_after")?,
            error,
            certificate: row.try_get("certificate")?,
            replaces: row.try_get("replaces")?,
            cert_serial: row.try_get("cert_serial")?,
            cert_pubkey: row.try_get("cert_pubkey")?,
            revoked_at: row.try_get("revoked_at")?,
            revocation_reason: row.try_get("revocation_reason")?,
            created_at: row.try_get("created_at")?,
            created_ip: row.try_get("created_ip")?,
            created_ptr: row.try_get("created_ptr")?,
        })
    }

    /// Builds a new order in the `pending` state. Pure — nothing is persisted
    /// until [`Order::insert`] runs.
    pub(crate) fn new(
        profile: &str,
        account_id: &str,
        identifiers: Vec<Identifier>,
        expires: i64,
        not_before: Option<i64>,
        not_after: Option<i64>,
    ) -> Order {
        Order {
            id: Uuid::new_v4().to_string(),
            profile: profile.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            identifiers,
            expires,
            not_before,
            not_after,
            error: None,
            certificate: None,
            // Set by `post_new_order` between here and `insert`, when the
            // client sent one and it passed RFC 9773 §5's checks.
            replaces: None,
            cert_serial: None,
            cert_pubkey: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now_secs(),
            // Filled in by `Order::with_client` between here and `insert`,
            // exactly as `replaces` is and for the same reason: `new` already
            // takes six positional arguments, and a seventh and eighth would
            // put `Order::create` past the point where a reader can tell them
            // apart without counting commas.
            created_ip: None,
            created_ptr: None,
        }
    }

    /// Records where the order was placed from.
    ///
    /// Consuming rather than `&mut self` so it chains off [`Order::new`] at the
    /// one call site that has a request behind it. An order created without it
    /// — every test fixture, and any future path with no client — simply keeps
    /// two `NULL`s, which is the honest answer.
    #[must_use]
    pub(crate) fn with_client(mut self, client: &crate::audit::ClientContext) -> Order {
        self.created_ip = client.ip.clone();
        self.created_ptr = client.ptr.clone();
        self
    }

    /// Inserts the order using any executor — a pool, or a transaction.
    ///
    /// Split from [`Order::new`] so `post_new_order` can write the order and its
    /// authorizations inside one transaction: a half-built order (fewer
    /// authorizations than identifiers) would otherwise be finalizable for names
    /// that were never authorized.
    pub(crate) async fn insert<'e, E>(&self, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        // `Identifier` derives `Serialize`, so this never fails in practice.
        let identifiers_json = serde_json::to_string(&self.identifiers)
            .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

        debug!(event = "order_create_started", order_id = ?self.id, profile = %self.profile, account_id = ?self.account_id);
        sqlx::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, created_at, created_ip, created_ptr) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?);",
        )
        .bind(&self.id)
        .bind(&self.profile)
        .bind(&self.account_id)
        .bind(&self.status)
        .bind(identifiers_json)
        .bind(self.expires)
        .bind(self.not_before)
        .bind(self.not_after)
        .bind(&self.replaces)
        .bind(self.created_at)
        .bind(&self.created_ip)
        .bind(&self.created_ptr)
        .execute(executor)
        .await?;

        debug!(event = "db_order_created", order_id = ?self.id, account_id = ?self.account_id);
        Ok(())
    }

    /// Creates a new order in the `pending` state (its authorizations are created
    /// separately by the caller) and returns it.
    pub async fn create(
        profile: &str,
        account_id: &str,
        identifiers: Vec<Identifier>,
        expires: i64,
        not_before: Option<i64>,
        not_after: Option<i64>,
        database: &Database,
    ) -> Result<Order, sqlx::Error> {
        let order = Order::new(
            profile,
            account_id,
            identifiers,
            expires,
            not_before,
            not_after,
        );
        order.insert(&database.pool).await?;
        Ok(order)
    }

    pub async fn find_by_id(id: &str, database: &Database) -> Result<Option<Order>, sqlx::Error> {
        debug!(event = "order_find_by_id_started", order_id = ?id);
        let row = sqlx::query("SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
             FROM orders WHERE id = ?;")
            .bind(id)
            .fetch_optional(&database.pool)
            .await?;

        let result = row.map(Order::from_row).transpose()?;
        if result.is_some() {
            info!(event = "order_found_by_id", order_id = ?id);
        } else {
            debug!(event = "order_not_found_by_id", order_id = ?id);
        }
        Ok(result)
    }

    /// Every order belonging to an account, newest first.
    ///
    /// Unfiltered on purpose: the admin CLI counts these to tell an operator
    /// what a `DELETE` will cascade, and a filtered count would understate it.
    /// The client-facing order-list URL wants
    /// [`Order::find_active_by_account`] instead.
    pub async fn find_by_account(
        account_id: &str,
        database: &Database,
    ) -> Result<Vec<Order>, sqlx::Error> {
        debug!(event = "order_find_by_account_started", account_id = ?account_id);
        let rows =
            sqlx::query("SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
             FROM orders WHERE account_id = ? ORDER BY created_at DESC;")
                .bind(account_id)
                .fetch_all(&database.pool)
                .await?;

        rows.into_iter().map(Order::from_row).collect()
    }

    /// An account's orders that are still worth a client's attention, newest
    /// first — what the RFC 8555 §7.1.2.1 order-list URL serves.
    ///
    /// §7.1.2.1: "The server SHOULD include pending orders and SHOULD NOT
    /// include orders that are invalid in the array of URLs." Expired orders go
    /// too: `load_owned_order` refuses one unless it is already `valid`, so
    /// listing it would hand the client a URL that only ever answers with an
    /// error.
    ///
    /// `valid` orders are kept whatever their `expires`, since the order
    /// object's expiry is housekeeping (`order.validity_seconds`) and the
    /// certificate it points at outlives it — that URL still works.
    pub async fn find_active_by_account(
        account_id: &str,
        database: &Database,
    ) -> Result<Vec<Order>, sqlx::Error> {
        debug!(event = "order_find_active_by_account_started", account_id = ?account_id);
        let rows =
            sqlx::query("SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
             FROM orders WHERE account_id = ? AND status != 'invalid' AND (status = 'valid' OR expires > ?) \
             ORDER BY created_at DESC;")
                .bind(account_id)
                .bind(now_secs())
                .fetch_all(&database.pool)
                .await?;

        rows.into_iter().map(Order::from_row).collect()
    }

    /// Lists orders across every account, oldest first — the admin CLI's
    /// listing. `profile` filters to one endpoint (`None` lists all of them);
    /// unlike [`Order::find_by_account`] (one account, newest-first, for the
    /// order-list URL) there is no account filter — callers filter by
    /// account/status client-side rather than building dynamic SQL for what is
    /// expected to be a small, locally-run admin table.
    pub async fn list_all(
        profile: Option<&str>,
        database: &Database,
    ) -> Result<Vec<Order>, sqlx::Error> {
        debug!(event = "order_list_all_started", profile = ?profile);
        let rows = match profile {
            Some(profile) => sqlx::query("SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
                 FROM orders WHERE profile = ? ORDER BY created_at ASC;")
                .bind(profile)
                .fetch_all(&database.pool)
                .await?,
            None => sqlx::query("SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
                 FROM orders ORDER BY created_at ASC;")
                .fetch_all(&database.pool)
                .await?,
        };

        rows.into_iter().map(Order::from_row).collect()
    }

    /// One page of orders matching `query`, plus the total the same predicate
    /// matches unpaged.
    ///
    /// Additive: [`Order::list_all`] is untouched, because the admin CLI counts
    /// on getting everything. This exists because `orders` grows a row per
    /// issuance forever — the first operator to open the web admin on a
    /// year-old deployment would otherwise pull the whole table into memory and
    /// JSON-encode it.
    ///
    /// The filters are in SQL rather than applied afterwards for the same
    /// reason they have to be: filtering a page in memory would make the page
    /// size wrong. It is also the *only* implementation of that policy — the
    /// CLI's `order list` used to hold a second one in Rust over `list_all`,
    /// which meant one meaning of `--status` written twice and a whole table
    /// loaded to filter three fields.
    ///
    /// Built with a [`sqlx::QueryBuilder`]: `sqlx::query` takes only
    /// `&'static str`, and every value below goes through `push_bind`, so
    /// nothing operator- or client-supplied is ever interpolated into the SQL.
    pub async fn search(
        query: &OrderQuery,
        database: &Database,
    ) -> Result<(Vec<Order>, i64), sqlx::Error> {
        debug!(event = "order_search_started",
               profile = ?query.profile,
               account_id = ?query.account_id,
               status = ?query.status,
               limit = query.limit,
               offset = query.offset);

        let mut page = sqlx::QueryBuilder::new(
            "SELECT id, profile, account_id, status, identifiers, expires, not_before, \
             not_after, error, certificate, replaces, cert_serial, cert_pubkey, revoked_at, \
             revocation_reason, created_at, created_ip, created_ptr FROM orders",
        );
        query.push_predicates(&mut page);
        // Newest first, and `id` breaks the tie: `created_at` is whole seconds,
        // so without it two orders placed in the same second could swap between
        // pages and one of them would never be seen.
        page.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        page.push_bind(query.limit);
        page.push(" OFFSET ");
        page.push_bind(query.offset);

        let rows = page.build().fetch_all(&database.pool).await?;
        let orders: Vec<Order> = rows
            .into_iter()
            .map(Order::from_row)
            .collect::<Result<_, _>>()?;

        let mut count = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM orders");
        query.push_predicates(&mut count);
        let total: i64 = count
            .build()
            .fetch_one(&database.pool)
            .await?
            .try_get::<i64, _>(0)?;

        Ok((orders, total))
    }

    /// How many orders an account has.
    ///
    /// `COUNT(*)`, not `find_by_account(..).len()`: the only two callers want a
    /// number, and loading every row means deserializing each one's
    /// `identifiers` JSON to throw it away.
    pub async fn count_by_account(
        account_id: &str,
        database: &Database,
    ) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) FROM orders WHERE account_id = ?;")
            .bind(account_id)
            .fetch_one(&database.pool)
            .await?;
        row.try_get::<i64, _>(0)
    }

    /// Hard-deletes the order row — cascading, via `ON DELETE CASCADE`, to its
    /// authorizations and challenges. Returns whether a row existed to delete.
    pub async fn delete(id: &str, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "order_delete_started", order_id = ?id);
        let result = sqlx::query("DELETE FROM orders WHERE id = ?;")
            .bind(id)
            .execute(&database.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            info!(event = "order_deleted", order_id = ?id);
        } else {
            debug!(event = "order_delete_missing", order_id = ?id);
        }
        Ok(deleted)
    }

    /// Records a successful issuance: stores the PEM `chain` plus the leaf's
    /// `cert_serial` (hex) and `cert_pubkey` (DER SPKI) — populated by the
    /// caller from that same chain via [`crate::cert::cert_serial_and_spki`],
    /// since parsing needs error handling the DB layer doesn't otherwise deal
    /// in — moves the order to the terminal `valid` state, and keeps `self`
    /// in sync so a following [`Order::to_json`] reflects the change without
    /// a re-read.
    pub async fn finalize(
        &mut self,
        chain: String,
        cert_serial: String,
        cert_pubkey: Vec<u8>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "order_finalize_started", order_id = ?self.id);
        sqlx::query(
            "UPDATE orders SET certificate = ?, cert_serial = ?, cert_pubkey = ?, status = 'valid' WHERE id = ?;",
        )
        .bind(&chain)
        .bind(&cert_serial)
        .bind(&cert_pubkey)
        .bind(&self.id)
        .execute(&database.pool)
        .await?;

        self.certificate = Some(chain);
        self.cert_serial = Some(cert_serial);
        self.cert_pubkey = Some(cert_pubkey);
        self.status = "valid".to_string();
        debug!(event = "db_order_finalized", order_id = ?self.id);
        Ok(())
    }

    /// Looks up the order whose stored certificate carries `serial` (hex,
    /// matching `cert_serial`'s format) — indexed, so a `POST /revokeCert`
    /// request is not a full table scan across every issued order. **Not**
    /// proof of identity on its own: the caller must additionally compare the
    /// submitted certificate's DER against the returned order's stored chain
    /// byte-for-byte (a random-serial collision, or a crafted certificate
    /// reusing a real serial, are not ruled out by the serial alone).
    ///
    /// Scoped to `profile`: revocation and ARI carry no account, so the
    /// endpoint the request arrived at is the only thing that keeps one
    /// profile from answering for — or revoking — another's certificate.
    pub async fn find_by_cert_serial(
        profile: &str,
        serial: &str,
        database: &Database,
    ) -> Result<Option<Order>, sqlx::Error> {
        debug!(event = "order_find_by_cert_serial_started", profile = %profile, cert_serial = ?serial);
        let row = sqlx::query(
            "SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, \
             cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
             FROM orders WHERE profile = ? AND cert_serial = ?;",
        )
        .bind(profile)
        .bind(serial)
        .fetch_optional(&database.pool)
        .await?;

        let result = row.map(Order::from_row).transpose()?;
        if result.is_some() {
            info!(event = "order_found_by_cert_serial", cert_serial = ?serial);
        } else {
            debug!(event = "order_not_found_by_cert_serial", cert_serial = ?serial);
        }
        Ok(result)
    }

    /// Finds any order that already claims to replace `cert_id` and is not
    /// `invalid` — RFC 9773 §5's "the identified certificate has not already
    /// been marked as replaced by a different Order that is not `invalid`".
    ///
    /// The `invalid` exclusion is what makes a retry work: an order that failed
    /// validation never produced a replacement, so it must not hold the
    /// predecessor hostage. Scoped by profile like every other request-path
    /// lookup — a certID is only meaningful at the endpoint that issued it.
    pub async fn find_by_replaces(
        profile: &str,
        cert_id: &str,
        database: &Database,
    ) -> Result<Option<Order>, sqlx::Error> {
        debug!(event = "order_find_by_replaces_started", profile = %profile, replaces = %cert_id);
        let row = sqlx::query(
            "SELECT id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, \
             cert_serial, cert_pubkey, revoked_at, revocation_reason, created_at, created_ip, created_ptr \
             FROM orders WHERE profile = ? AND replaces = ? AND status != 'invalid' LIMIT 1;",
        )
        .bind(profile)
        .bind(cert_id)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Order::from_row).transpose()
    }

    /// Records a certificate revocation (RFC 8555 §7.6): stamps `revoked_at`
    /// (now) and the optional `CRLReason` `reason`, and keeps `self` in sync
    /// (like [`Order::finalize`]). Deliberately does **not** touch `status`:
    /// revocation is orthogonal to the order state machine (RFC 8555 defines
    /// no "revoked" order status), so a revoked order stays `valid`.
    pub async fn revoke(
        &mut self,
        reason: Option<i64>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        debug!(event = "order_revoke_started", order_id = ?self.id, reason = ?reason);
        sqlx::query("UPDATE orders SET revoked_at = ?, revocation_reason = ? WHERE id = ?;")
            .bind(now)
            .bind(reason)
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.revoked_at = Some(now);
        self.revocation_reason = reason;
        info!(event = "order_revoked", order_id = ?self.id, reason = ?reason);
        Ok(())
    }

    /// Records a failed issuance: stores the `error` problem document, moves the
    /// order to the terminal `invalid` state, and keeps `self` in sync (like
    /// [`Order::finalize`]). Used when the signer fails internally; a `badCSR`
    /// leaves the order `ready` and retryable instead.
    /// The `invalid` transition as a bare statement, over any executor.
    ///
    /// Split from [`Order::mark_invalid`] so `post_challenge` can compose the
    /// challenge, authorization and order transitions into one transaction. The
    /// in-memory sync stays in `mark_invalid`, since it must not happen until
    /// the transaction has committed.
    pub(crate) async fn set_invalid<'e, E>(
        id: &str,
        error: &Value,
        executor: E,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        // `error` is a `serde_json::Value`, so serialization is infallible.
        sqlx::query("UPDATE orders SET error = ?, status = 'invalid' WHERE id = ?;")
            .bind(error.to_string())
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The `ready` transition as a bare statement; see [`Order::set_invalid`].
    pub(crate) async fn set_ready<'e, E>(id: &str, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE orders SET status = 'ready' WHERE id = ?;")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The `pending` transition as a bare statement; see [`Order::set_invalid`].
    pub(crate) async fn set_pending<'e, E>(id: &str, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE orders SET status = 'pending' WHERE id = ?;")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    pub async fn mark_invalid(
        &mut self,
        error: Value,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "order_mark_invalid_started", order_id = ?self.id);
        Self::set_invalid(&self.id, &error, &database.pool).await?;

        self.error = Some(error);
        self.status = "invalid".to_string();
        info!(event = "order_marked_invalid", order_id = ?self.id);
        Ok(())
    }

    /// Moves the order from `pending` to `ready` once all its authorizations are
    /// `valid`, so it can be finalized. Keeps `self` in sync (like
    /// [`Order::finalize`]).
    pub async fn mark_ready(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "order_mark_ready_started", order_id = ?self.id);
        Self::set_ready(&self.id, &database.pool).await?;

        self.status = "ready".to_string();
        info!(event = "order_marked_ready", order_id = ?self.id);
        Ok(())
    }

    /// Moves the order back from `ready` to `pending`, after one of its
    /// authorizations stopped being `valid` — in practice, a client
    /// deactivating one (RFC 8555 §7.5.2).
    ///
    /// The only backwards transition in the order state machine, and it exists
    /// because §7.5.2's "the server MUST NOT treat deactivated authorization
    /// objects as sufficient for issuing certificates" has to hold for an order
    /// that already reached `ready` — otherwise `finalize` would still accept
    /// it. RFC 8555 §7.1.6's diagram draws `pending → ready` as the state
    /// becoming true rather than a one-way latch, so re-deriving it is in
    /// keeping with the model.
    pub async fn mark_pending(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "order_mark_pending_started", order_id = ?self.id);
        Self::set_pending(&self.id, &database.pool).await?;

        self.status = "pending".to_string();
        info!(event = "order_marked_pending", order_id = ?self.id);
        Ok(())
    }

    /// Moves the order from `ready` to `processing`: the signer backend
    /// accepted the CSR but is resolving it elsewhere (RFC 8555 §7.4), so the
    /// client polls rather than getting a certificate inline. Keeps `self` in
    /// sync (like [`Order::mark_ready`]).
    ///
    /// The `processing` status needed no migration — the `orders.status`
    /// `CHECK` has always allowed it; until the `acme_proxy` backend existed
    /// there was simply no asynchronous issuance to use it.
    pub async fn mark_processing(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "order_mark_processing_started", order_id = ?self.id);
        sqlx::query("UPDATE orders SET status = 'processing' WHERE id = ?;")
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.status = "processing".to_string();
        info!(event = "order_marked_processing", order_id = ?self.id);
        Ok(())
    }

    /// The RFC 8555 order object. URLs are derived from `base_url`; datetimes are
    /// rendered RFC3339. `authorizations` lists one URL per `authz_ids` entry, the
    /// `certificate` URL appears only once the order is `valid`, and `notBefore`/
    /// `notAfter`/`error` appear only when set.
    #[must_use]
    pub fn to_json(&self, base_url: &str, authz_ids: &[String]) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("expires".to_string(), Value::String(rfc3339(self.expires)));
        object.insert(
            "identifiers".to_string(),
            serde_json::to_value(&self.identifiers).expect("Identifier is always serializable"),
        );
        if let Some(nb) = self.not_before {
            object.insert("notBefore".to_string(), Value::String(rfc3339(nb)));
        }
        if let Some(na) = self.not_after {
            object.insert("notAfter".to_string(), Value::String(rfc3339(na)));
        }
        let authorizations: Vec<Value> = authz_ids
            .iter()
            .map(|id| Value::String(format!("{base_url}/authz/{id}")))
            .collect();
        object.insert("authorizations".to_string(), Value::Array(authorizations));
        object.insert(
            "finalize".to_string(),
            Value::String(format!("{base_url}/order/{}/finalize", self.id)),
        );
        if self.status == "valid" {
            object.insert(
                "certificate".to_string(),
                Value::String(format!("{base_url}/certificate/{}", self.id)),
            );
        }
        if let Some(ref error) = self.error {
            object.insert("error".to_string(), error.clone());
        }
        // RFC 9773 §5: the field is reflected "in the response and in
        // subsequent requests for the corresponding Order object" — so it is
        // rendered here, not just echoed once on the 201.
        if let Some(ref replaces) = self.replaces {
            object.insert("replaces".to_string(), Value::String(replaces.clone()));
        }
        Value::Object(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ClientContext;

    /// `with_client` is set between `new` and `insert`, the way `replaces` is,
    /// and — like `replaces` — it has to survive the round trip. An order built
    /// without it keeps two `NULL`s rather than empty strings.
    #[tokio::test]
    async fn with_client_persists_and_an_order_without_one_stays_null() {
        let db = std::sync::Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account_id(&db).await;

        let stamped = Order::new(
            "default",
            &account,
            vec![Identifier::dns("a.example.com")],
            0,
            None,
            None,
        )
        .with_client(&ClientContext {
            ip: Some("203.0.113.7".to_string()),
            ptr: Some("host.example.com".to_string()),
            user_agent: Some("lego".to_string()),
            request_id: Some("req-1".to_string()),
        });
        stamped.insert(&db.pool).await.unwrap();
        let reloaded = Order::find_by_id(&stamped.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.created_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(reloaded.created_ptr.as_deref(), Some("host.example.com"));

        let bare = Order::new(
            "default",
            &account,
            vec![Identifier::dns("b.example.com")],
            0,
            None,
            None,
        );
        bare.insert(&db.pool).await.unwrap();
        let reloaded = Order::find_by_id(&bare.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.created_ip, None);
        assert_eq!(reloaded.created_ptr, None);

        // And the ACME order object says nothing about either: RFC 8555 §7.1.3
        // defines its members, and where a client connected from is not one.
        let json = reloaded.to_json("http://localhost:3000", &[]);
        let object = json.as_object().unwrap();
        assert!(!object.contains_key("createdIp"));
        assert!(!object.contains_key("createdPtr"));
        assert!(
            !stamped
                .to_json("http://localhost:3000", &[])
                .to_string()
                .contains("203.0.113.7")
        );
    }

    use crate::testutil::account_id;
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn create_then_find_by_id_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let created = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        assert_eq!(created.status, "pending");

        let found = Order::find_by_id(&created.id, &db).await.unwrap().unwrap();
        assert_eq!(found.account_id, acct);
        assert_eq!(found.identifiers, vec![Identifier::dns("example.com")]);
        assert!(found.certificate.is_none());
    }

    #[tokio::test]
    async fn find_by_account_lists_all() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        Order::create(
            "default",
            &acct,
            vec![Identifier::dns("a.example")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        Order::create(
            "default",
            &acct,
            vec![Identifier::dns("b.example")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let orders = Order::find_by_account(&acct, &db).await.unwrap();
        assert_eq!(orders.len(), 2);
    }

    #[tokio::test]
    async fn absent_lookup_returns_none() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Order::find_by_id("nope", &db).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn to_json_shape_when_pending() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let authz_ids = vec!["authz-1".to_string()];
        let json = order.to_json("http://localhost:3000", &authz_ids);
        assert_eq!(json["status"], "pending");
        assert_eq!(
            json["authorizations"],
            json!(["http://localhost:3000/authz/authz-1"])
        );
        assert_eq!(
            json["finalize"],
            format!("http://localhost:3000/order/{}/finalize", order.id)
        );
        assert_eq!(
            json["identifiers"],
            json!([{"type": "dns", "value": "example.com"}])
        );
        // A pending order has no certificate URL yet, and no notBefore/notAfter.
        assert!(json.get("certificate").is_none());
        assert!(json.get("notBefore").is_none());
        assert!(json.get("notAfter").is_none());
        // `expires` renders as an RFC3339 string ending in Z.
        assert!(json["expires"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn to_json_includes_optional_fields() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            Some(now_secs()),
            Some(now_secs() + 7200),
            &db,
        )
        .await
        .unwrap();

        let json = order.to_json("http://localhost:3000", &[]);
        assert!(json["notBefore"].as_str().unwrap().ends_with('Z'));
        assert!(json["notAfter"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn finalize_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let mut order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        order
            .finalize(
                "-----BEGIN CERTIFICATE-----\n...".to_string(),
                "aabbcc".to_string(),
                vec![1, 2, 3],
                &db,
            )
            .await
            .unwrap();

        // In-memory struct is updated…
        assert_eq!(order.status, "valid");
        assert!(order.certificate.is_some());
        assert_eq!(order.cert_serial.as_deref(), Some("aabbcc"));
        assert_eq!(order.cert_pubkey.as_deref(), Some(&[1u8, 2, 3][..]));
        // …and so is the stored row, and to_json now exposes the certificate URL.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, "valid");
        assert_eq!(reloaded.cert_serial.as_deref(), Some("aabbcc"));
        assert_eq!(reloaded.cert_pubkey.as_deref(), Some(&[1u8, 2, 3][..]));
        let json = reloaded.to_json("http://localhost:3000", &[]);
        assert_eq!(
            json["certificate"],
            format!("http://localhost:3000/certificate/{}", order.id)
        );
    }

    async fn finalized_order(db: Arc<Database>, serial: &str) -> Order {
        let acct = account_id(&db).await;
        let mut order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        order
            .finalize(
                "-----BEGIN CERTIFICATE-----\n...".to_string(),
                serial.to_string(),
                vec![9, 9, 9],
                &db,
            )
            .await
            .unwrap();
        order
    }

    #[tokio::test]
    async fn find_by_cert_serial_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = finalized_order(db.clone(), "deadbeef").await;

        let found = Order::find_by_cert_serial("default", "deadbeef", &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, order.id);

        assert!(
            Order::find_by_cert_serial("default", "unknown", &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn revoke_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut order = finalized_order(db.clone(), "aa11bb22").await;

        order.revoke(Some(1), &db).await.unwrap();

        // In-memory struct is updated, and `status` is untouched…
        assert!(order.revoked_at.is_some());
        assert_eq!(order.revocation_reason, Some(1));
        assert_eq!(order.status, "valid");
        // …and so is the stored row.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert!(reloaded.revoked_at.is_some());
        assert_eq!(reloaded.revocation_reason, Some(1));
        assert_eq!(reloaded.status, "valid");
    }

    #[tokio::test]
    async fn revoke_with_no_reason_persists_null() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut order = finalized_order(db.clone(), "cc33dd44").await;

        order.revoke(None, &db).await.unwrap();

        assert!(order.revoked_at.is_some());
        assert!(order.revocation_reason.is_none());
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert!(reloaded.revocation_reason.is_none());
    }

    #[tokio::test]
    async fn to_json_never_exposes_revocation_state() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut order = finalized_order(db.clone(), "ee55ff66").await;
        order.revoke(Some(1), &db).await.unwrap();

        let json = order.to_json("http://localhost:3000", &[]);
        assert!(json.get("revokedAt").is_none());
        assert!(json.get("revocationReason").is_none());
        assert_eq!(json["status"], "valid");
    }

    #[tokio::test]
    async fn mark_invalid_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let mut order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let error = json!({
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": "boom",
            "status": 500,
        });
        order.mark_invalid(error.clone(), &db).await.unwrap();

        // In-memory struct is updated…
        assert_eq!(order.status, "invalid");
        assert_eq!(order.error, Some(error.clone()));
        // …and so is the stored row, and to_json now exposes the error object.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, "invalid");
        let json = reloaded.to_json("http://localhost:3000", &[]);
        assert_eq!(json["error"], error);
    }

    #[tokio::test]
    async fn list_all_lists_orders_across_accounts_oldest_first() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct1 = account_id(&db).await;
        let (acct2, _) = crate::sqlite::account::Account::find_or_create(
            "default",
            &[9u8],
            vec![],
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();

        let first = Order::create(
            "default",
            &acct1,
            vec![Identifier::dns("a.example")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        let second = Order::create(
            "default",
            &acct2.id,
            vec![Identifier::dns("b.example")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let all = Order::list_all(None, &db).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, first.id);
        assert_eq!(all[1].id, second.id);
    }

    #[tokio::test]
    async fn list_all_when_empty_is_empty() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Order::list_all(None, &db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_the_row_and_reports_true() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        assert!(Order::delete(&order.id, &db).await.unwrap());
        assert!(Order::find_by_id(&order.id, &db).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_of_unknown_id_reports_false() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(!Order::delete("nope", &db).await.unwrap());
    }

    #[tokio::test]
    async fn delete_cascades_to_authorizations_and_challenges() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let order = Order::create(
            "default",
            &acct,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let authz = crate::sqlite::authz::Authorization::create(
            &order.id,
            Identifier::dns("example.com"),
            now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();
        crate::sqlite::authz::Challenge::create(&authz.id, "http-01", &db)
            .await
            .unwrap();

        Order::delete(&order.id, &db).await.unwrap();

        assert!(
            crate::sqlite::authz::Authorization::find_by_order(&order.id, &db)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            crate::sqlite::authz::Challenge::find_by_authz(&authz.id, &db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Seeds `count` orders under `profile`, each backdated one second further
    /// than the last so `created_at DESC` has a deterministic answer without
    /// relying on the UUID tiebreak.
    async fn seed_orders(
        db: &Arc<Database>,
        profile: &str,
        account_id: &str,
        count: usize,
    ) -> Vec<String> {
        let base = now_secs();
        let mut ids = Vec::new();
        for index in 0..count {
            let order = Order::create(
                profile,
                account_id,
                vec![Identifier::dns(format!("host-{index}.example.com"))],
                base + 3600,
                None,
                None,
                db,
            )
            .await
            .unwrap();
            sqlx::query("UPDATE orders SET created_at = ? WHERE id = ?;")
                .bind(base - index as i64)
                .bind(&order.id)
                .execute(&db.pool)
                .await
                .unwrap();
            ids.push(order.id);
        }
        // Newest first is the order `search` returns, and `ids` is already in
        // that order: index 0 was backdated least.
        ids
    }

    fn window(limit: i64, offset: i64) -> OrderQuery {
        OrderQuery {
            limit,
            offset,
            ..OrderQuery::default()
        }
    }

    #[tokio::test]
    async fn search_pages_newest_first_and_reports_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let ids = seed_orders(&db, "default", &acct, 5).await;

        let (page, total) = Order::search(&window(2, 0), &db).await.unwrap();
        assert_eq!(total, 5, "the total must ignore the page window");
        assert_eq!(
            page.iter().map(|o| o.id.clone()).collect::<Vec<_>>(),
            ids[..2]
        );

        let (second, total) = Order::search(&window(2, 2), &db).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(
            second.iter().map(|o| o.id.clone()).collect::<Vec<_>>(),
            ids[2..4]
        );

        // A partial last page, then past the end.
        let (last, _) = Order::search(&window(2, 4), &db).await.unwrap();
        assert_eq!(last.len(), 1);
        let (beyond, total) = Order::search(&window(2, 99), &db).await.unwrap();
        assert!(beyond.is_empty());
        assert_eq!(total, 5, "a page past the end still reports the real total");
    }

    /// Every page must be disjoint and together cover everything: the property
    /// the `created_at, id` tiebreak exists for.
    #[tokio::test]
    async fn paging_one_row_at_a_time_sees_every_order_exactly_once() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        // Deliberately NOT backdated: all four share one `created_at`, which is
        // exactly the case where a missing tiebreak lets rows swap pages.
        let mut expected = Vec::new();
        for index in 0..4 {
            let order = Order::create(
                "default",
                &acct,
                vec![Identifier::dns(format!("same-second-{index}.example.com"))],
                now_secs() + 3600,
                None,
                None,
                &db,
            )
            .await
            .unwrap();
            expected.push(order.id);
        }
        expected.sort();

        let mut seen = Vec::new();
        for offset in 0..4 {
            let (page, total) = Order::search(&window(1, offset), &db).await.unwrap();
            assert_eq!(total, 4);
            assert_eq!(page.len(), 1);
            seen.push(page[0].id.clone());
        }
        seen.sort();
        assert_eq!(
            seen, expected,
            "pages must be disjoint and cover everything"
        );
    }

    #[tokio::test]
    async fn search_filters_by_profile_account_and_status_together() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let (other_account, _) = crate::sqlite::account::Account::find_or_create(
            "default",
            &[9u8, 9, 9],
            vec![],
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();

        seed_orders(&db, "default", &acct, 3).await;
        seed_orders(&db, "default", &other_account.id, 2).await;
        let mut ready = seed_orders(&db, "default", &acct, 1).await;
        let ready_id = ready.pop().unwrap();
        Order::find_by_id(&ready_id, &db)
            .await
            .unwrap()
            .unwrap()
            .mark_ready(&db)
            .await
            .unwrap();

        // No filter at all: everything.
        let (_, total) = Order::search(&window(50, 0), &db).await.unwrap();
        assert_eq!(total, 6);

        // By account.
        let by_account = OrderQuery {
            account_id: Some(acct.clone()),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&by_account, &db).await.unwrap();
        assert_eq!(total, 4);
        assert!(rows.iter().all(|o| o.account_id == acct));

        // By status.
        let by_status = OrderQuery {
            status: Some("ready".to_string()),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&by_status, &db).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].id, ready_id);

        // All three at once, and the count must agree with the rows.
        let combined = OrderQuery {
            profile: Some("default".to_string()),
            account_id: Some(acct.clone()),
            status: Some("pending".to_string()),
            limit: 50,
            offset: 0,
        };
        let (rows, total) = Order::search(&combined, &db).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(total, 3);

        // A filter matching nothing is empty, not an error.
        let none = OrderQuery {
            profile: Some("no-such-profile".to_string()),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&none, &db).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn search_scopes_by_profile() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        seed_orders(&db, "default", &acct, 2).await;
        seed_orders(&db, "other", &acct, 3).await;

        let scoped = OrderQuery {
            profile: Some("other".to_string()),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&scoped, &db).await.unwrap();
        assert_eq!(total, 3);
        assert!(rows.iter().all(|o| o.profile == "other"));
    }

    /// A value that would be SQL if it were interpolated instead of bound.
    #[tokio::test]
    async fn a_filter_value_is_bound_not_interpolated() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        seed_orders(&db, "default", &acct, 2).await;

        let hostile = OrderQuery {
            status: Some("' OR 1=1 --".to_string()),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&hostile, &db).await.unwrap();
        assert!(rows.is_empty(), "the value must be compared, not executed");
        assert_eq!(total, 0);
    }
}
