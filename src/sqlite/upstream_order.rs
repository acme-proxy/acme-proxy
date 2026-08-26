//! The mapping between a local order and the order the `relay` signer
//! backend opened for it at the upstream CA.
//!
//! Kept in SQLite alongside the rest of the data model rather than in a
//! sidecar file the way [`crate::signer::local_ca`]'s revocation ledger is:
//! this state *is* per-order, so it belongs with the orders.
//!
//! ## Methods
//!
//! - `create`: record a newly opened upstream order, `processing`
//! - `find_by_order_id`: the mapping for one local order
//! - `mark_valid` / `mark_invalid`: terminal outcomes
//! - `list_processing`: rows whose background task was lost to a restart

use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::debug;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;

/// The most rows [`UpstreamOrder::list_processing`] returns in one call.
///
/// A restart after a long upstream outage can leave a very large number of
/// orders `processing`; loading them all at once would spike memory before the
/// relay semaphore ever got a say in how fast they are worked through.
pub(crate) const MAX_PROCESSING_BATCH: usize = 500;

#[derive(Debug, Clone)]
pub struct UpstreamOrder {
    pub order_id: String,
    pub upstream_order_url: String,
    pub upstream_finalize_url: Option<String>,
    pub upstream_certificate_url: Option<String>,
    /// The client's CSR, kept so a relay interrupted by a restart can still
    /// finalize upstream. See the migration for why it cannot be recovered
    /// any other way.
    pub csr_der: Vec<u8>,
    pub status: String,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// The finalize request's context, stored by [`UpstreamOrder::set_client`]
    /// so [`UpstreamOrder::client`] can hand it back to the audit row written
    /// when the relay settles — long after that request returned. See the
    /// migration for why it cannot come from anywhere else.
    pub client_ip: Option<String>,
    pub client_ptr: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl UpstreamOrder {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(UpstreamOrder {
            order_id: row.try_get("order_id")?,
            upstream_order_url: row.try_get("upstream_order_url")?,
            upstream_finalize_url: row.try_get("upstream_finalize_url")?,
            upstream_certificate_url: row.try_get("upstream_certificate_url")?,
            csr_der: row.try_get("csr_der")?,
            status: row.try_get("status")?,
            error: row.try_get("error")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            client_ip: row.try_get("client_ip")?,
            client_ptr: row.try_get("client_ptr")?,
            user_agent: row.try_get("user_agent")?,
            request_id: row.try_get("request_id")?,
        })
    }

    /// The stored finalize context, in the shape an audit row takes.
    #[must_use]
    pub fn client(&self) -> crate::audit::ClientContext {
        crate::audit::ClientContext {
            ip: self.client_ip.clone(),
            ptr: self.client_ptr.clone(),
            user_agent: self.user_agent.clone(),
            request_id: self.request_id.clone(),
        }
    }

    /// Records the finalize request's context on an already-created mapping row.
    ///
    /// A separate `UPDATE` rather than a parameter of [`UpstreamOrder::create`]
    /// because that runs inside `SignerBackend::issue`, which is handed a CSR
    /// and an order id and deliberately knows nothing about HTTP. `post_finalize`
    /// calls this the moment the backend answers `Processing`.
    ///
    /// That leaves a window — between the backend's own `create` and this
    /// `UPDATE` — in which a relay could theoretically settle and find no
    /// context. It cannot happen in practice: settling takes at least one
    /// round trip to the upstream CA, and this statement is a few microseconds
    /// of local work on the same task. If it ever did, the audit row would
    /// simply carry no address, which is the same degradation as a resumed
    /// order and not a wrong answer.
    pub async fn set_client(
        order_id: &str,
        client: &crate::audit::ClientContext,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE upstream_orders \
             SET client_ip = ?, client_ptr = ?, user_agent = ?, request_id = ? \
             WHERE order_id = ?;",
        )
        .bind(&client.ip)
        .bind(&client.ptr)
        .bind(&client.user_agent)
        .bind(&client.request_id)
        .bind(order_id)
        .execute(&database.pool)
        .await?;
        Ok(())
    }

    /// Records a newly opened upstream order as `processing`.
    ///
    /// Returns `Ok(None)` when a row for `order_id` already exists — the
    /// primary key rejecting a duplicate is how two concurrent finalize
    /// requests are stopped from opening two upstream orders for one local
    /// order. The caller treats that as "a relay is already running".
    pub async fn create(
        order_id: &str,
        upstream_order_url: &str,
        upstream_finalize_url: Option<&str>,
        csr_der: &[u8],
        database: &Database,
    ) -> Result<Option<UpstreamOrder>, sqlx::Error> {
        let now = now_secs();
        let record = UpstreamOrder {
            order_id: order_id.to_string(),
            upstream_order_url: upstream_order_url.to_string(),
            upstream_finalize_url: upstream_finalize_url.map(str::to_string),
            upstream_certificate_url: None,
            csr_der: csr_der.to_vec(),
            status: "processing".to_string(),
            error: None,
            created_at: now,
            updated_at: now,
            client_ip: None,
            client_ptr: None,
            user_agent: None,
            request_id: None,
        };

        debug!(event = "db_upstream_order_create_started", outcome = "progress", order_id = ?order_id);
        let result = sqlx::query(
            "INSERT OR IGNORE INTO upstream_orders \
             (order_id, upstream_order_url, upstream_finalize_url, csr_der, status, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(&record.order_id)
        .bind(&record.upstream_order_url)
        .bind(&record.upstream_finalize_url)
        .bind(&record.csr_der)
        .bind(&record.status)
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&database.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(record))
    }

    pub async fn find_by_order_id(
        order_id: &str,
        database: &Database,
    ) -> Result<Option<UpstreamOrder>, sqlx::Error> {
        let row = sqlx::query("SELECT * FROM upstream_orders WHERE order_id = ?;")
            .bind(order_id)
            .fetch_optional(&database.pool)
            .await?;
        row.map(UpstreamOrder::from_row).transpose()
    }

    /// Marks the relay finished, recording where the certificate came from.
    pub async fn mark_valid(
        order_id: &str,
        certificate_url: Option<&str>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE upstream_orders \
             SET status = 'valid', upstream_certificate_url = ?, updated_at = ? \
             WHERE order_id = ?;",
        )
        .bind(certificate_url)
        .bind(now_secs())
        .bind(order_id)
        .execute(&database.pool)
        .await?;
        Ok(())
    }

    /// Marks the relay failed, recording why for an operator to read later —
    /// the client only ever sees the problem document on the order itself.
    pub async fn mark_invalid(
        order_id: &str,
        error: &str,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE upstream_orders SET status = 'invalid', error = ?, updated_at = ? \
             WHERE order_id = ?;",
        )
        .bind(error)
        .bind(now_secs())
        .bind(order_id)
        .execute(&database.pool)
        .await?;
        Ok(())
    }

    /// Rows still `processing`, oldest first — relays whose in-memory task
    /// died with the process and need one respawned at startup.
    ///
    /// Restricted to the `profiles` the calling backend actually serves, via
    /// the owning order's own `profile`: several endpoints may relay to
    /// several different upstreams, and resuming another one's order would
    /// drive it against the wrong CA. An empty `profiles` therefore matches
    /// nothing, which is the safe reading of "this backend serves nothing".
    pub async fn list_processing(
        profiles: &[String],
        database: &Database,
    ) -> Result<Vec<UpstreamOrder>, sqlx::Error> {
        if profiles.is_empty() {
            return Ok(Vec::new());
        }

        // sqlx has no array binding for SQLite, so the IN list is built from
        // one placeholder per profile — never from the values themselves.
        let placeholders = std::iter::repeat_n("?", profiles.len())
            .collect::<Vec<_>>()
            .join(", ");
        // Bounded so a pathological backlog is not loaded into memory whole;
        // the oldest are taken first, and a later restart picks up the rest.
        let limit = MAX_PROCESSING_BATCH;
        let sql = format!(
            "SELECT u.* FROM upstream_orders u \
             JOIN orders o ON o.id = u.order_id \
             WHERE u.status = 'processing' AND o.profile IN ({placeholders}) \
             ORDER BY u.created_at ASC LIMIT {limit};"
        );

        // `AssertSqlSafe` because sqlx refuses a non-`'static` query string
        // outright: the only runtime part of this one is the count of `?`
        // placeholders, never a value.
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for profile in profiles {
            query = query.bind(profile);
        }
        let rows = query.fetch_all(&database.pool).await?;
        rows.into_iter().map(UpstreamOrder::from_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ClientContext;
    use crate::sqlite::account::Account;
    use crate::sqlite::order::{Identifier, Order};
    use std::sync::Arc;

    /// `upstream_orders.order_id` is a foreign key, so a real order has to
    /// exist behind every row these tests create.
    async fn order(database: &Database) -> Order {
        let (account, _) = Account::find_or_create(
            "default",
            &crate::random::random_bytes::<16>(),
            Vec::new(),
            &ClientContext::default(),
            database,
        )
        .await
        .unwrap();
        Order::create(
            "default",
            &account.id,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap()
    }

    async fn database() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// The relay settles minutes after the finalize request returned, from a
    /// task with no request in scope — so the context it audits has to come
    /// back off this row. A row that never had one hands back an empty context
    /// rather than a half-filled one.
    #[tokio::test]
    async fn the_finalize_context_is_stored_and_handed_back_for_the_audit_row() {
        let database = database().await;
        let order = order(&database).await;

        UpstreamOrder::create(
            &order.id,
            "https://up.example/order/1",
            None,
            b"csr",
            &database,
        )
        .await
        .unwrap()
        .unwrap();

        // Before `post_finalize` stores anything: empty, not partial.
        let mapping = UpstreamOrder::find_by_order_id(&order.id, &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mapping.client(), ClientContext::default());

        let client = ClientContext {
            ip: Some("203.0.113.7".to_string()),
            ptr: Some("host.example.com".to_string()),
            user_agent: Some("lego".to_string()),
            request_id: Some("req-1".to_string()),
        };
        UpstreamOrder::set_client(&order.id, &client, &database)
            .await
            .unwrap();

        let mapping = UpstreamOrder::find_by_order_id(&order.id, &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mapping.client(), client);

        // Setting it for an order with no mapping row is a no-op, not an error:
        // `post_finalize` calls this straight after the backend answered, and a
        // backend that answered `Processing` without creating a row would be a
        // different bug that must not surface here as a 500.
        UpstreamOrder::set_client("no-such-order", &client, &database)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_then_find_round_trips() {
        let db = database().await;
        let order = order(&db).await;

        let created = UpstreamOrder::create(
            &order.id,
            "https://up.example/order/1",
            Some("https://up.example/order/1/finalize"),
            b"csr-bytes",
            &db,
        )
        .await
        .unwrap()
        .expect("a first insert must succeed");
        assert_eq!(created.status, "processing");

        let found = UpstreamOrder::find_by_order_id(&order.id, &db)
            .await
            .unwrap()
            .expect("the row just written must be found");
        assert_eq!(found.upstream_order_url, "https://up.example/order/1");
        assert_eq!(
            found.upstream_finalize_url.as_deref(),
            Some("https://up.example/order/1/finalize")
        );
        assert!(found.upstream_certificate_url.is_none());
    }

    /// The concurrency guard: the primary key must refuse a second relay for
    /// the same order rather than opening a duplicate upstream order.
    #[tokio::test]
    async fn a_second_create_for_one_order_is_refused() {
        let db = database().await;
        let order = order(&db).await;

        assert!(
            UpstreamOrder::create(&order.id, "https://up.example/order/1", None, b"csr", &db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            UpstreamOrder::create(&order.id, "https://up.example/order/2", None, b"csr", &db)
                .await
                .unwrap()
                .is_none(),
            "a duplicate must be reported as already-in-flight, not inserted"
        );

        // And the original row is untouched by the refused attempt.
        let found = UpstreamOrder::find_by_order_id(&order.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.upstream_order_url, "https://up.example/order/1");
    }

    #[tokio::test]
    async fn mark_valid_records_the_certificate_url() {
        let db = database().await;
        let order = order(&db).await;
        UpstreamOrder::create(&order.id, "https://up.example/order/1", None, b"csr", &db)
            .await
            .unwrap();

        UpstreamOrder::mark_valid(&order.id, Some("https://up.example/cert/1"), &db)
            .await
            .unwrap();

        let found = UpstreamOrder::find_by_order_id(&order.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, "valid");
        assert_eq!(
            found.upstream_certificate_url.as_deref(),
            Some("https://up.example/cert/1")
        );
    }

    #[tokio::test]
    async fn mark_invalid_records_the_reason() {
        let db = database().await;
        let order = order(&db).await;
        UpstreamOrder::create(&order.id, "https://up.example/order/1", None, b"csr", &db)
            .await
            .unwrap();

        UpstreamOrder::mark_invalid(&order.id, "upstream said no", &db)
            .await
            .unwrap();

        let found = UpstreamOrder::find_by_order_id(&order.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, "invalid");
        assert_eq!(found.error.as_deref(), Some("upstream said no"));
    }

    /// Only `processing` rows come back — a finished relay must not be
    /// respawned at the next startup.
    #[tokio::test]
    async fn list_processing_skips_settled_rows() {
        let db = database().await;
        let still_running = order(&db).await;
        let finished = order(&db).await;

        UpstreamOrder::create(&still_running.id, "https://up.example/a", None, b"csr", &db)
            .await
            .unwrap();
        UpstreamOrder::create(&finished.id, "https://up.example/b", None, b"csr", &db)
            .await
            .unwrap();
        UpstreamOrder::mark_valid(&finished.id, None, &db)
            .await
            .unwrap();

        let processing = UpstreamOrder::list_processing(&["default".to_string()], &db)
            .await
            .unwrap();
        assert_eq!(processing.len(), 1);
        assert_eq!(processing[0].order_id, still_running.id);
    }

    #[tokio::test]
    async fn find_by_order_id_is_none_for_an_unknown_order() {
        let db = database().await;
        assert!(
            UpstreamOrder::find_by_order_id("nope", &db)
                .await
                .unwrap()
                .is_none()
        );
    }
}
