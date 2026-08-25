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
use crate::sqlite::status::{self, OrderStatus};

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
/// - `cert_not_after` is populated the same way and from the same leaf, and is
///   **not** `not_after`: that one is the validity the client *asked* for
///   (§7.4), usually absent and clamped by the signer when it is not, where
///   this is what the certificate says. `NULL` means the row predates the
///   column and nothing has parsed its chain yet; a negative value means the
///   sweep parsed it and could not (see the migration).
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
    pub status: OrderStatus,
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
    /// The leaf's own notAfter, epoch seconds. `None` on a row finalized before
    /// the column existed (the digest's backfill stamps those), and
    /// [`UNPARSABLE_NOT_AFTER`] once the backfill has looked and failed.
    pub cert_not_after: Option<i64>,
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
    pub status: Option<OrderStatus>,
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
        // `status` arrives as an `OrderStatus` and the other two as `String`s,
        // so each contributes its own `&str` and the array stays one type. The
        // bind is still a parameter, never interpolated SQL.
        for (column, value) in [
            ("profile = ", self.profile.as_deref()),
            ("account_id = ", self.account_id.as_deref()),
            ("status = ", self.status.map(OrderStatus::as_str)),
        ] {
            if let Some(value) = value {
                builder
                    .push(separator)
                    .push(column)
                    .push_bind(value.to_string());
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

/// Every column, in one place: each lookup, both listings and the paged search
/// must select the same set or [`Order::from_row`] fails on whichever forgot
/// one.
///
/// A `macro_rules!` rather than a `const` so the expansion is a string
/// *literal*: `sqlx::query` takes `impl SqlSafeStr`, which a runtime `format!`
/// does not satisfy, so `concat!("SELECT ", columns!(), " FROM …")` is what
/// keeps a shared column list and a compile-time-checked query in the same
/// design.
macro_rules! columns {
    () => {
        "id, profile, account_id, status, identifiers, expires, not_before, not_after, \
         error, certificate, replaces, cert_serial, cert_pubkey, cert_not_after, \
         revoked_at, revocation_reason, created_at, created_ip, created_ptr"
    };
}

/// What [`Order::cert_not_after`] holds for a chain that would not parse, so it
/// is never parsed again.
///
/// Any negative value would do, and every reader tests the *sign* rather than
/// comparing against this — the column is documented as "negative means
/// unparsable". It is named here, beside the column, because three modules now
/// write or skip it: the digest's backfill, the expiry predicates below, and
/// the supersession annotation in `crate::admin`.
pub const UNPARSABLE_NOT_AFTER: i64 = -1;

/// The expiry listing's `WHERE`, appended to both [`Order::find_expiring`]'s
/// page and its count for the reason [`OrderQuery::push_predicates`] is one
/// function: a predicate applied to only one of them reports a total the rows
/// do not match, which a page control shows and nothing else does.
///
/// A function over a `QueryBuilder` rather than the `macro_rules!` this used to
/// be, because `profile` became optional when the admin surfaces arrived and a
/// `concat!` literal cannot carry a conditional clause. The three predicates
/// after it are unconditional and each carries its reason on
/// [`Order::find_expiring`].
fn push_expiring_predicates(
    profile: Option<&str>,
    before: i64,
    builder: &mut sqlx::QueryBuilder<sqlx::Sqlite>,
) {
    builder.push(" FROM orders WHERE certificate IS NOT NULL AND revoked_at IS NULL");
    builder.push(" AND cert_not_after >= 0 AND cert_not_after <= ");
    builder.push_bind(before);
    if let Some(profile) = profile {
        builder.push(" AND profile = ");
        builder.push_bind(profile.to_string());
    }
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
            status: status::from_column(row.try_get::<&str, _>("status")?)?,
            identifiers,
            expires: row.try_get("expires")?,
            not_before: row.try_get("not_before")?,
            not_after: row.try_get("not_after")?,
            error,
            certificate: row.try_get("certificate")?,
            replaces: row.try_get("replaces")?,
            cert_serial: row.try_get("cert_serial")?,
            cert_pubkey: row.try_get("cert_pubkey")?,
            cert_not_after: row.try_get("cert_not_after")?,
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
            status: OrderStatus::Pending,
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
            cert_not_after: None,
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

        debug!(event = "db_order_create_started", outcome = "progress", order_id = ?self.id, profile = %self.profile, account_id = ?self.account_id);
        sqlx::query(
            "INSERT INTO orders (id, profile, account_id, status, identifiers, expires, not_before, not_after, error, certificate, replaces, created_at, created_ip, created_ptr) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?);",
        )
        .bind(&self.id)
        .bind(&self.profile)
        .bind(&self.account_id)
        .bind(self.status.as_str())
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

        debug!(event = "db_order_created", outcome = "success", order_id = ?self.id, account_id = ?self.account_id);
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
        debug!(event = "db_order_find_by_id_started", outcome = "progress", order_id = ?id);
        let row = sqlx::query(concat!("SELECT ", columns!(), " FROM orders WHERE id = ?;"))
            .bind(id)
            .fetch_optional(&database.pool)
            .await?;

        let result = row.map(Order::from_row).transpose()?;
        if result.is_some() {
            info!(event = "db_order_found_by_id", outcome = "success", order_id = ?id);
        } else {
            debug!(event = "db_order_not_found_by_id", outcome = "failure", order_id = ?id);
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
        debug!(event = "db_order_find_by_account_started", outcome = "progress", account_id = ?account_id);
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM orders WHERE account_id = ? ORDER BY created_at DESC;"
        ))
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
        debug!(event = "db_order_find_active_by_account_started", outcome = "progress", account_id = ?account_id);
        let rows =
            sqlx::query(concat!("SELECT ", columns!(), " FROM orders WHERE account_id = ? AND status != 'invalid' AND (status = 'valid' OR expires > ?) ORDER BY created_at DESC;"))
                .bind(account_id)
                .bind(now_secs())
                .fetch_all(&database.pool)
                .await?;

        rows.into_iter().map(Order::from_row).collect()
    }

    /// One page of orders matching `query`, plus the total the same predicate
    /// matches unpaged.
    ///
    /// The **only** cross-account listing this model offers. An unpaged
    /// `list_all` stood beside it, oldest first, until both front ends took a
    /// window; `orders` grows a row per issuance forever, so an operator
    /// opening either surface on a year-old deployment would otherwise pull the
    /// whole table into memory and render it.
    ///
    /// The filters are in SQL rather than applied afterwards for the same
    /// reason they have to be: filtering a page in memory would make the page
    /// size wrong. It is also the *only* implementation of that policy — the
    /// CLI's `order list` used to hold a second one in Rust over the unpaged
    /// listing, which meant one meaning of `--status` written twice and a whole
    /// table loaded to filter three fields.
    ///
    /// Built with a [`sqlx::QueryBuilder`]: `sqlx::query` takes only
    /// `&'static str`, and every value below goes through `push_bind`, so
    /// nothing operator- or client-supplied is ever interpolated into the SQL.
    pub async fn search(
        query: &OrderQuery,
        database: &Database,
    ) -> Result<(Vec<Order>, i64), sqlx::Error> {
        debug!(event = "db_order_search_started",
               outcome = "progress",
               profile = ?query.profile,
               account_id = ?query.account_id,
               status = ?query.status,
               limit = query.limit,
               offset = query.offset);

        let mut page = sqlx::QueryBuilder::new(concat!("SELECT ", columns!(), " FROM orders"));
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

    /// Deletes this profile's orders that expired before `cutoff`, returning
    /// how many went. The `authorizations` and `challenges` beneath them go
    /// with the row, through the schema's `ON DELETE CASCADE`.
    ///
    /// **`valid` is excluded, whatever the age.** A valid order's row is how
    /// `Order::find_by_cert_serial` resolves a certificate for `revokeCert` and
    /// for the CRL, and what RFC 9773 renewal information is derived from —
    /// deleting one would make an issued certificate unrevokable and
    /// unrenewable, which is a far worse outcome than a large table. Everything
    /// else is an order no client can act on any more: `invalid` is terminal,
    /// and a `pending`/`ready`/`processing` order past its own `expires` is
    /// refused on read by every handler that loads one.
    ///
    /// Scoped to one profile because `order.retention_days` is a per-profile
    /// key: two endpoints in one process may reasonably keep their history for
    /// different lengths of time.
    pub async fn cleanup(
        profile: &str,
        cutoff: i64,
        database: &Database,
    ) -> Result<u64, sqlx::Error> {
        debug!(event = "db_order_cleanup_started", outcome = "progress", profile = %profile, cutoff = cutoff);
        let removed = sqlx::query(
            "DELETE FROM orders WHERE profile = ? AND status != 'valid' AND expires < ?;",
        )
        .bind(profile)
        .bind(cutoff)
        .execute(&database.pool)
        .await?
        .rows_affected();

        debug!(event = "db_order_cleanup_completed", outcome = "success", profile = %profile, rows_removed = removed);
        Ok(removed)
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
        debug!(event = "db_order_delete_started", outcome = "progress", order_id = ?id);
        let result = sqlx::query("DELETE FROM orders WHERE id = ?;")
            .bind(id)
            .execute(&database.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            info!(event = "db_order_deleted", outcome = "success", order_id = ?id);
        } else {
            debug!(event = "db_order_delete_missing", outcome = "success", order_id = ?id);
        }
        Ok(deleted)
    }

    /// Records a successful issuance: stores the PEM `chain` plus the leaf's
    /// `cert_serial` (hex), `cert_pubkey` (DER SPKI) and `cert_not_after` —
    /// all three populated by the caller from that same chain via
    /// [`crate::cert::cert_serial_and_spki`] and [`crate::cert::cert_validity`],
    /// since parsing needs error handling the DB layer doesn't otherwise deal
    /// in — moves the order to the terminal `valid` state, and keeps `self`
    /// in sync so a following [`Order::to_json`] reflects the change without
    /// a re-read.
    ///
    /// `cert_not_after` is `Option` where the other two are not, and the
    /// asymmetry is deliberate: the serial and the public key are what make a
    /// certificate revocable, so a chain they cannot be read from is a failed
    /// issuance, while the expiry is housekeeping for the digest and a leaf
    /// this server cannot read the validity of must still be recorded as
    /// issued. Callers pass `None` rather than refusing — the rule
    /// `LocalCa::revoke` already follows when it records a revoked leaf's
    /// expiry, and the sweep will try the chain again later.
    pub async fn finalize(
        &mut self,
        chain: String,
        cert_serial: String,
        cert_pubkey: Vec<u8>,
        cert_not_after: Option<i64>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "db_order_finalize_started", outcome = "progress", order_id = ?self.id);
        sqlx::query(
            "UPDATE orders SET certificate = ?, cert_serial = ?, cert_pubkey = ?, \
             cert_not_after = ?, status = 'valid' WHERE id = ?;",
        )
        .bind(&chain)
        .bind(&cert_serial)
        .bind(&cert_pubkey)
        .bind(cert_not_after)
        .bind(&self.id)
        .execute(&database.pool)
        .await?;

        self.certificate = Some(chain);
        self.cert_serial = Some(cert_serial);
        self.cert_pubkey = Some(cert_pubkey);
        self.cert_not_after = cert_not_after;
        self.status = OrderStatus::Valid;
        debug!(event = "db_order_finalized", outcome = "success", order_id = ?self.id);
        Ok(())
    }

    /// The certificates expiring at or before `before`, soonest first, with the
    /// unpaged total beside the page — the digest's whole query
    /// (`[notify.expiry]`, [`crate::notify::expiry`]) and the admin surfaces'
    /// (`GET /api/expiring`, `/ui/expiring`, `order list --expiring-in`).
    ///
    /// Three predicates, each carrying its own reason. `certificate IS NOT
    /// NULL` because an order that never issued has nothing to expire;
    /// `revoked_at IS NULL` because a withdrawn certificate is not something to
    /// go and renew; and `cert_not_after >= 0` because a negative value is the
    /// sweep's sentinel for a chain it could not parse, which is a row to leave
    /// alone rather than to report as expiring in 1970. They are exactly the
    /// partial index's own predicate.
    ///
    /// `profile` is an `Option` because the panel lists every endpoint by
    /// default, like every other admin listing, where the digest asks one
    /// profile at a time. The two forms cost different things, and the
    /// difference is the index's column order:
    ///
    /// - `Some` is `SEARCH … USING INDEX idx_orders_cert_not_after (profile=?
    ///   AND cert_not_after>? AND cert_not_after<?)` — a range seek on both
    ///   columns, and byte for byte the plan the digest's original query got.
    /// - `None` is `SCAN … USING INDEX idx_orders_cert_not_after`: the partial
    ///   predicate still matches, so the index is still what is read, but with
    ///   no leading-column equality there is nothing to seek to, and the index
    ///   is ordered by `cert_not_after` only *within* a profile — so the
    ///   ordering below falls to a temp b-tree over the whole result rather
    ///   than over its last term alone.
    ///
    /// That is the price of the unscoped view, and it is stated here rather
    /// than left to be rediscovered from a query plan. A profile-less index on
    /// `cert_not_after` would buy it back, and is not worth a second index on
    /// a table this one already covers until a deployment says otherwise.
    ///
    /// The total is counted rather than derived from the page, so "…and N more"
    /// can be honest without loading a tail nobody will read. `id` breaks the
    /// ordering tie for [`Order::search`]'s reason: two certificates can share
    /// a whole-second expiry, and a stable order is what stops one of them
    /// being dropped between the page and the count.
    pub async fn find_expiring(
        profile: Option<&str>,
        before: i64,
        limit: i64,
        offset: i64,
        database: &Database,
    ) -> Result<(Vec<Order>, i64), sqlx::Error> {
        debug!(
            event = "db_order_find_expiring_started",
            outcome = "progress",
            profile = ?profile,
            before,
            limit,
            offset
        );
        let mut page = sqlx::QueryBuilder::new(concat!("SELECT ", columns!()));
        push_expiring_predicates(profile, before, &mut page);
        page.push(" ORDER BY cert_not_after ASC, id ASC LIMIT ");
        page.push_bind(limit);
        page.push(" OFFSET ");
        page.push_bind(offset);

        let rows = page.build().fetch_all(&database.pool).await?;
        let orders: Vec<Order> = rows
            .into_iter()
            .map(Order::from_row)
            .collect::<Result<_, _>>()?;

        let mut count = sqlx::QueryBuilder::new("SELECT COUNT(*)");
        push_expiring_predicates(profile, before, &mut count);
        let total: i64 = count
            .build()
            .fetch_one(&database.pool)
            .await?
            .try_get::<i64, _>(0)?;

        Ok((orders, total))
    }

    /// The issued orders on `profile` whose `cert_not_after` has never been
    /// derived — rows finalized before the column existed. At most `limit` per
    /// call, since this parses an X.509 chain per row and the digest that calls
    /// it is not the only thing the runner has to do.
    ///
    /// Returns `(id, chain)` pairs rather than whole orders: the caller wants
    /// the PEM and nothing else, and a digest running against a long-lived
    /// deployment would otherwise inflate every row it is about to discard.
    pub async fn find_unstamped(
        profile: &str,
        limit: i64,
        database: &Database,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, certificate FROM orders WHERE profile = ? \
             AND certificate IS NOT NULL AND cert_not_after IS NULL LIMIT ?;",
        )
        .bind(profile)
        .bind(limit)
        .fetch_all(&database.pool)
        .await?;

        rows.into_iter()
            .map(|row| Ok((row.try_get("id")?, row.try_get("certificate")?)))
            .collect()
    }

    /// Writes a `cert_not_after` derived after the fact by the sweep.
    ///
    /// Separate from [`Order::finalize`] because it is a backfill and not an
    /// issuance: it touches one column, never `status`, and it is the one
    /// caller that legitimately writes the negative sentinel — a chain that
    /// will not parse has to be *recorded* as unparsable, or every pass parses
    /// it again for the life of the deployment.
    pub async fn set_cert_not_after(
        id: &str,
        cert_not_after: i64,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE orders SET cert_not_after = ? WHERE id = ?;")
            .bind(cert_not_after)
            .bind(id)
            .execute(&database.pool)
            .await?;
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
        debug!(event = "db_order_find_by_cert_serial_started", outcome = "progress", profile = %profile, cert_serial = ?serial);
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM orders WHERE profile = ? AND cert_serial = ?;"
        ))
        .bind(profile)
        .bind(serial)
        .fetch_optional(&database.pool)
        .await?;

        let result = row.map(Order::from_row).transpose()?;
        if result.is_some() {
            info!(event = "db_order_found_by_cert_serial", outcome = "success", cert_serial = ?serial);
        } else {
            debug!(event = "db_order_not_found_by_cert_serial", outcome = "failure", cert_serial = ?serial);
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
        debug!(event = "db_order_find_by_replaces_started", outcome = "progress", profile = %profile, replaces = %cert_id);
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM orders WHERE profile = ? AND replaces = ? AND status != 'invalid' LIMIT 1;"
        ))
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
        debug!(event = "db_order_revoke_started", outcome = "progress", order_id = ?self.id, reason = ?reason);
        sqlx::query("UPDATE orders SET revoked_at = ?, revocation_reason = ? WHERE id = ?;")
            .bind(now)
            .bind(reason)
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.revoked_at = Some(now);
        self.revocation_reason = reason;
        info!(event = "db_order_revoked", outcome = "success", order_id = ?self.id, reason = ?reason);
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
        debug!(event = "db_order_mark_invalid_started", outcome = "progress", order_id = ?self.id);
        Self::set_invalid(&self.id, &error, &database.pool).await?;

        self.error = Some(error);
        self.status = OrderStatus::Invalid;
        info!(event = "db_order_marked_invalid", outcome = "failure", order_id = ?self.id);
        Ok(())
    }

    /// Moves the order from `pending` to `ready` once all its authorizations are
    /// `valid`, so it can be finalized. Keeps `self` in sync (like
    /// [`Order::finalize`]).
    pub async fn mark_ready(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_order_mark_ready_started", outcome = "progress", order_id = ?self.id);
        Self::set_ready(&self.id, &database.pool).await?;

        self.status = OrderStatus::Ready;
        info!(event = "db_order_marked_ready", outcome = "success", order_id = ?self.id);
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
        debug!(event = "db_order_mark_pending_started", outcome = "progress", order_id = ?self.id);
        Self::set_pending(&self.id, &database.pool).await?;

        self.status = OrderStatus::Pending;
        info!(event = "db_order_marked_pending", outcome = "success", order_id = ?self.id);
        Ok(())
    }

    /// Claims the order for issuance, moving it from `ready` to `processing` in
    /// **one guarded statement**: `Ok(true)` means this caller won the claim,
    /// `Ok(false)` that somebody else already holds it. Keeps `self` in sync
    /// (like [`Order::mark_ready`]) only on the winning branch.
    ///
    /// **The precondition is the whole point.** `post_finalize` reads the order,
    /// checks it is `ready`, signs, and writes — three steps with no lock
    /// between them, so N concurrent finalize requests on one order all passed
    /// the check, all reached `SignerBackend::issue`, and all got a certificate
    /// back. Only the last write survived, and the others became valid
    /// CA-signed certificates with no row naming their serial: `POST
    /// /revokeCert` looks an order up by `find_by_cert_serial` and would answer
    /// "unknown certificate", so nothing this server offers could ever revoke
    /// them and the CRL would never learn they exist. `rows_affected` closes it,
    /// the primitive [`crate::sqlite::nonce::Nonce::verify`] and
    /// `AdminUser::claim_totp_step` already rest on.
    ///
    /// The `relay` backend was never exposed, because `upstream_orders.order_id`
    /// is a primary key and the second insert conflicts — this gives `local_ca`
    /// and `custom`, which answer inline, the same guard.
    ///
    /// The `processing` status needed no migration — the `orders.status`
    /// `CHECK` has always allowed it; until the `relay` backend existed
    /// there was simply no asynchronous issuance to use it.
    pub async fn claim_for_finalize(&mut self, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "db_order_mark_processing_started", outcome = "progress", order_id = ?self.id);
        let claimed = sqlx::query(
            "UPDATE orders SET status = 'processing' WHERE id = ? AND status = 'ready';",
        )
        .bind(&self.id)
        .execute(&database.pool)
        .await?
        .rows_affected()
            == 1;

        if !claimed {
            debug!(event = "db_order_finalize_claim_refused", outcome = "failure", order_id = ?self.id);
            return Ok(false);
        }

        self.status = OrderStatus::Processing;
        info!(event = "db_order_marked_processing", outcome = "success", order_id = ?self.id);
        Ok(true)
    }

    /// Gives the claim back, moving `processing` to `ready` so the client can
    /// try again — the counterpart to [`Order::claim_for_finalize`] for the
    /// refusals RFC 8555 §7.4 says must leave the order finalizable (a rejected
    /// CSR) and for the two arms where issuance succeeded but this server could
    /// not read what it had just been handed.
    ///
    /// Guarded on `processing` for a reason of its own: a §7.5.2 deactivation
    /// racing this claim demotes the order to `pending`
    /// ([`Order::mark_pending`], unguarded, since it is the authoritative
    /// answer to an authorization that stopped being valid). An unguarded
    /// release would push it back to `ready` and hand the client a finalizable
    /// order whose authorizations no longer support it.
    pub async fn release_finalize_claim(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        let released = sqlx::query(
            "UPDATE orders SET status = 'ready' WHERE id = ? AND status = 'processing';",
        )
        .bind(&self.id)
        .execute(&database.pool)
        .await?
        .rows_affected()
            == 1;

        if released {
            self.status = OrderStatus::Ready;
        }
        debug!(event = "db_order_finalize_claim_released", outcome = "success", order_id = ?self.id, released = released);
        Ok(())
    }

    /// The RFC 8555 order object. URLs are derived from `base_url`; datetimes are
    /// rendered RFC3339. `authorizations` lists one URL per `authz_ids` entry, the
    /// `certificate` URL appears only once the order is `valid`, and `notBefore`/
    /// `notAfter`/`error` appear only when set.
    #[must_use]
    pub fn to_json(&self, base_url: &str, authz_ids: &[String]) -> Value {
        let mut object = serde_json::Map::new();
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
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
        if self.status == OrderStatus::Valid {
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
        assert_eq!(created.status, OrderStatus::Pending);

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
                Some(now_secs() + 90 * 24 * 60 * 60),
                &db,
            )
            .await
            .unwrap();

        // In-memory struct is updated…
        assert_eq!(order.status, OrderStatus::Valid);
        assert!(order.certificate.is_some());
        assert_eq!(order.cert_serial.as_deref(), Some("aabbcc"));
        assert_eq!(order.cert_pubkey.as_deref(), Some(&[1u8, 2, 3][..]));
        // …and so is the stored row, and to_json now exposes the certificate URL.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, OrderStatus::Valid);
        assert_eq!(reloaded.cert_serial.as_deref(), Some("aabbcc"));
        assert_eq!(reloaded.cert_pubkey.as_deref(), Some(&[1u8, 2, 3][..]));
        assert!(reloaded.cert_not_after.is_some());
        let json = reloaded.to_json("http://localhost:3000", &[]);
        assert_eq!(
            json["certificate"],
            format!("http://localhost:3000/certificate/{}", order.id)
        );
    }

    /// The guard the whole double-issuance fix rests on: two callers race, and
    /// exactly one of them may go on to ask a signer for a certificate.
    #[tokio::test]
    async fn only_one_caller_can_claim_an_order_for_finalize() {
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
        order.mark_ready(&db).await.unwrap();

        // A second handle on the same row, as a concurrent request would have.
        let mut rival = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();

        assert!(order.claim_for_finalize(&db).await.unwrap());
        assert_eq!(order.status, OrderStatus::Processing);

        // The loser is told so, and its own in-memory copy is left alone rather
        // than being synced to a status it does not hold the claim on.
        assert!(!rival.claim_for_finalize(&db).await.unwrap());
        assert_eq!(rival.status, OrderStatus::Ready);

        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, OrderStatus::Processing);
    }

    /// Every status but `ready` refuses the claim — `pending` because the
    /// authorizations do not support issuance yet, `valid` because a
    /// certificate already exists, `invalid` because the order is terminal.
    #[tokio::test]
    async fn an_order_that_is_not_ready_cannot_be_claimed() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        for prepare in [
            // `pending` is the state `create` leaves behind.
            None,
            Some(OrderStatus::Valid),
            Some(OrderStatus::Invalid),
        ] {
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
            match prepare {
                None => {}
                Some(OrderStatus::Valid) => order
                    .finalize("chain".to_string(), "aa".to_string(), vec![1], None, &db)
                    .await
                    .unwrap(),
                Some(_) => order
                    .mark_invalid(serde_json::json!({}), &db)
                    .await
                    .unwrap(),
            }
            let before = order.status;

            assert!(
                !order.claim_for_finalize(&db).await.unwrap(),
                "claimed an order in {before}"
            );
            assert_eq!(order.status, before);
        }
    }

    /// The release is the counterpart RFC 8555 §7.4 needs for a rejected CSR,
    /// and it is guarded so a §7.5.2 deactivation racing it wins.
    #[tokio::test]
    async fn releasing_a_claim_restores_ready_but_never_overrides_a_demotion() {
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
        order.mark_ready(&db).await.unwrap();
        assert!(order.claim_for_finalize(&db).await.unwrap());

        order.release_finalize_claim(&db).await.unwrap();
        assert_eq!(order.status, OrderStatus::Ready);
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, OrderStatus::Ready);

        // Now the race: the claim is held, a deactivation demotes the order,
        // and the release must not hand the client back a finalizable order
        // whose authorizations no longer support it.
        assert!(order.claim_for_finalize(&db).await.unwrap());
        order.mark_pending(&db).await.unwrap();
        order.release_finalize_claim(&db).await.unwrap();
        assert_eq!(order.status, OrderStatus::Pending);
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, OrderStatus::Pending);
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
                None,
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
        assert_eq!(order.status, OrderStatus::Valid);
        // …and so is the stored row.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert!(reloaded.revoked_at.is_some());
        assert_eq!(reloaded.revocation_reason, Some(1));
        assert_eq!(reloaded.status, OrderStatus::Valid);
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
        assert_eq!(order.status, OrderStatus::Invalid);
        assert_eq!(order.error, Some(error.clone()));
        // …and so is the stored row, and to_json now exposes the error object.
        let reloaded = Order::find_by_id(&order.id, &db).await.unwrap().unwrap();
        assert_eq!(reloaded.status, OrderStatus::Invalid);
        let json = reloaded.to_json("http://localhost:3000", &[]);
        assert_eq!(json["error"], error);
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
            status: Some(OrderStatus::Ready),
            ..window(50, 0)
        };
        let (rows, total) = Order::search(&by_status, &db).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].id, ready_id);

        // All three at once, and the count must agree with the rows.
        let combined = OrderQuery {
            profile: Some("default".to_string()),
            account_id: Some(acct.clone()),
            status: Some(OrderStatus::Pending),
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
    ///
    /// `status` used to be the vector here, and is no longer expressible: it is
    /// an [`OrderStatus`], so a hostile value cannot reach this layer at all —
    /// `Order::search` never sees one, because `--status` and `?status=` refuse
    /// it by name first. `profile` and `account_id` are still free strings and
    /// still go through `push_bind`, so the property is asserted on those.
    #[tokio::test]
    async fn a_filter_value_is_bound_not_interpolated() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        seed_orders(&db, "default", &acct, 2).await;

        for hostile in ["' OR 1=1 --", "default'; DROP TABLE orders; --"] {
            let by_profile = OrderQuery {
                profile: Some(hostile.to_string()),
                ..window(50, 0)
            };
            let (rows, total) = Order::search(&by_profile, &db).await.unwrap();
            assert!(rows.is_empty(), "the value must be compared, not executed");
            assert_eq!(total, 0);

            let by_account = OrderQuery {
                account_id: Some(hostile.to_string()),
                ..window(50, 0)
            };
            let (rows, total) = Order::search(&by_account, &db).await.unwrap();
            assert!(rows.is_empty(), "the value must be compared, not executed");
            assert_eq!(total, 0);
        }

        // The table is still there, which is what the second vector is for.
        let (_, total) = Order::search(&window(50, 0), &db).await.unwrap();
        assert_eq!(total, 2);
    }

    /// A helper for the expiry suite: an issued order whose leaf expires at
    /// `not_after`, written through `finalize` so the row's shape is the
    /// production one and only the date is a fixture.
    async fn expiring_order(
        db: &Database,
        account: &str,
        names: &[&str],
        not_after: Option<i64>,
    ) -> Order {
        expiring_order_on(db, "default", account, names, not_after).await
    }

    /// [`expiring_order`] on a named endpoint, for the cases about scoping.
    async fn expiring_order_on(
        db: &Database,
        profile: &str,
        account: &str,
        names: &[&str],
        not_after: Option<i64>,
    ) -> Order {
        let mut order = Order::create(
            profile,
            account,
            names.iter().map(|name| Identifier::dns(*name)).collect(),
            now_secs() + 3600,
            None,
            None,
            db,
        )
        .await
        .unwrap();
        order
            .finalize(
                "-----BEGIN CERTIFICATE-----\n...".to_string(),
                format!("serial-{}", &order.id[..8]),
                vec![1],
                not_after,
                db,
            )
            .await
            .unwrap();
        order
    }

    const DAY: i64 = 24 * 60 * 60;

    /// The window and the ordering: soonest first, and nothing past the
    /// horizon.
    #[tokio::test]
    async fn find_expiring_returns_the_window_soonest_first() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();

        let far = expiring_order(&db, &acct, &["far.example.com"], Some(now + 60 * DAY)).await;
        let soon = expiring_order(&db, &acct, &["soon.example.com"], Some(now + 2 * DAY)).await;
        let mid = expiring_order(&db, &acct, &["mid.example.com"], Some(now + 9 * DAY)).await;

        let (page, total) = Order::find_expiring(Some("default"), now + 14 * DAY, 10, 0, &db)
            .await
            .unwrap();

        let ids: Vec<&str> = page.iter().map(|order| order.id.as_str()).collect();
        assert_eq!(ids, vec![soon.id.as_str(), mid.id.as_str()]);
        assert_eq!(total, 2);
        assert!(
            !ids.contains(&far.id.as_str()),
            "a certificate outside the window is not expiring yet"
        );
    }

    /// The three rows the digest must never report, each for its own reason.
    #[tokio::test]
    async fn find_expiring_skips_revoked_unstamped_and_unparsable_rows() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();

        let live = expiring_order(&db, &acct, &["live.example.com"], Some(now + DAY)).await;

        // Revoked: withdrawn, so not something to go and renew.
        let mut revoked =
            expiring_order(&db, &acct, &["revoked.example.com"], Some(now + DAY)).await;
        revoked.revoke(Some(1), &db).await.unwrap();

        // Never stamped: issued before the column existed. The backfill has to
        // reach it before the digest can, or a NULL would sort as "expiring".
        expiring_order(&db, &acct, &["old.example.com"], None).await;

        // Stamped unparsable: the sweep looked and could not read the chain.
        // A negative value must not read as "expired in 1970".
        let broken = expiring_order(&db, &acct, &["broken.example.com"], None).await;
        Order::set_cert_not_after(&broken.id, -1, &db)
            .await
            .unwrap();

        let (page, total) = Order::find_expiring(Some("default"), now + 14 * DAY, 10, 0, &db)
            .await
            .unwrap();
        let ids: Vec<&str> = page.iter().map(|order| order.id.as_str()).collect();
        assert_eq!(ids, vec![live.id.as_str()]);
        assert_eq!(total, 1);
    }

    /// The total is counted, not derived from the page — which is the whole
    /// reason `max_entries` can truncate a digest and it can still say how many
    /// it did not name.
    #[tokio::test]
    async fn find_expiring_reports_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();
        for index in 0..5 {
            let name = format!("host-{index}.example.com");
            expiring_order(&db, &acct, &[name.as_str()], Some(now + DAY)).await;
        }

        let (page, total) = Order::find_expiring(Some("default"), now + 14 * DAY, 2, 0, &db)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(total, 5);
    }

    /// One endpoint never reports another's certificates — `find_by_cert_serial`'s
    /// rule, and for the same reason.
    #[tokio::test]
    async fn find_expiring_scopes_by_profile() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();
        expiring_order(&db, &acct, &["a.example.com"], Some(now + DAY)).await;

        let (page, total) = Order::find_expiring(Some("other"), now + 14 * DAY, 10, 0, &db)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(total, 0);
    }

    /// The panel's default view: no profile, so every endpoint at once. The
    /// digest never asks this — it iterates its configured profiles — but the
    /// admin surfaces open on it.
    #[tokio::test]
    async fn find_expiring_unscoped_spans_every_profile() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();

        let here =
            expiring_order_on(&db, "default", &acct, &["a.example.com"], Some(now + DAY)).await;
        let there =
            expiring_order_on(&db, "other", &acct, &["b.example.com"], Some(now + 2 * DAY)).await;

        let (page, total) = Order::find_expiring(None, now + 14 * DAY, 10, 0, &db)
            .await
            .unwrap();
        let ids: Vec<&str> = page.iter().map(|order| order.id.as_str()).collect();
        assert_eq!(ids, vec![here.id.as_str(), there.id.as_str()]);
        assert_eq!(total, 2);

        // And the three unconditional predicates still apply unscoped: a
        // revoked row is absent whichever endpoint issued it.
        let mut revoked =
            expiring_order_on(&db, "other", &acct, &["c.example.com"], Some(now + DAY)).await;
        revoked.revoke(Some(1), &db).await.unwrap();
        let (page, total) = Order::find_expiring(None, now + 14 * DAY, 10, 0, &db)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(total, 2);
    }

    /// The offset the page control needs: consecutive windows do not overlap,
    /// and the total stays the *unpaged* count so the pager's arithmetic has
    /// something honest to work from.
    #[tokio::test]
    async fn find_expiring_pages_without_overlap_and_keeps_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;
        let now = now_secs();
        for index in 0..5 {
            let name = format!("host-{index}.example.com");
            // Distinct expiries, so the ordering is total and the assertion
            // below is about the offset rather than about a tie-break.
            expiring_order(&db, &acct, &[name.as_str()], Some(now + (index + 1) * DAY)).await;
        }

        let (first, total) = Order::find_expiring(None, now + 14 * DAY, 2, 0, &db)
            .await
            .unwrap();
        let (second, second_total) = Order::find_expiring(None, now + 14 * DAY, 2, 2, &db)
            .await
            .unwrap();

        assert_eq!(total, 5);
        assert_eq!(second_total, 5, "the total is unpaged on every window");
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        let firsts: Vec<&str> = first.iter().map(|order| order.id.as_str()).collect();
        for order in &second {
            assert!(
                !firsts.contains(&order.id.as_str()),
                "a row must not appear on two pages"
            );
        }

        // Past the end is an empty page, not an error and not a wrapped one.
        let (past, _) = Order::find_expiring(None, now + 14 * DAY, 2, 50, &db)
            .await
            .unwrap();
        assert!(past.is_empty());
    }

    /// The backfill's input: rows with a chain and no stamp, and nothing else.
    #[tokio::test]
    async fn find_unstamped_finds_only_issued_rows_with_no_stamp() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = account_id(&db).await;

        let unstamped = expiring_order(&db, &acct, &["old.example.com"], None).await;
        expiring_order(&db, &acct, &["new.example.com"], Some(now_secs())).await;
        // Never issued: no certificate, so nothing to parse.
        Order::create(
            "default",
            &acct,
            vec![Identifier::dns("pending.example.com")],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        let rows = Order::find_unstamped("default", 10, &db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, unstamped.id);

        // And once stamped it stops being returned, which is what stops the
        // sweep re-parsing the same row for ever.
        Order::set_cert_not_after(&unstamped.id, -1, &db)
            .await
            .unwrap();
        assert!(
            Order::find_unstamped("default", 10, &db)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
