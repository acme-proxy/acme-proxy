use base64::prelude::*;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::{Identifier, rfc3339};

/// An ACME authorization (RFC 8555 §7.1.4). One authorization is created per
/// order identifier when the order is created, starting in the `pending` state
/// and carrying the challenges the client can satisfy to prove control of the
/// identifier.
///
/// ## Storage Details
///
/// - `identifier` is persisted as a JSON `{type, value}` object.
/// - Timestamps are epoch seconds (matching orders/accounts/nonces) and rendered
///   as RFC3339 strings in [`Authorization::to_json`].
/// - The authorization URL is **derived** from the id + base URL (like the
///   order's `finalize`/`certificate` URLs), never stored.
///
/// ## Wildcards
///
/// A wildcard authorization stores its identifier in the **wildcard form**
/// (`*.example.com`), while the ACME object shows the base name plus a separate
/// `"wildcard": true` member (RFC 8555 §7.1.4). Storing the base name instead
/// would collide: the canonical wildcard order `["example.com", "*.example.com"]`
/// creates two authorizations, and `UNIQUE(order_id, identifier)` compares the
/// serialized JSON — both rows would be identical and the order would fail to
/// persist. Deriving with [`Authorization::base_identifier`] costs a
/// `strip_prefix` and no migration.
#[derive(Debug)]
pub struct Authorization {
    pub id: String,
    pub order_id: String,
    pub identifier: Identifier,
    pub status: String,
    pub expires: i64,
    pub created_at: i64,
}

/// An ACME challenge (RFC 8555 §8): one proof the client may offer for its
/// authorization's identifier.
///
/// Which types an authorization carries is decided by
/// [`ChallengeRegistry::types_for`](crate::challenge::ChallengeRegistry::types_for)
/// — `UNIQUE(authz_id, type)` allows several, one per type. Whether triggering
/// one performs a real network check or is accepted outright is the registry's
/// `bypass` setting, not this model's business.
///
/// A failed challenge stores the problem document that explains why in `error`,
/// which the client reads back from the challenge object.
#[derive(Debug)]
pub struct Challenge {
    pub id: String,
    pub authz_id: String,
    pub typ: String,
    pub token: String,
    pub status: String,
    pub validated: Option<i64>,
    /// The RFC 8555 problem document of a failed validation. `None` until one
    /// fails.
    pub error: Option<Value>,
    pub created_at: i64,
}

/// A fresh high-entropy challenge token: 32 random bytes, base64url-encoded (the
/// shape RFC 8555 §8.1 requires). RNG failure is catastrophic and cannot be
/// recovered from, so it panics rather than returning an unusable token.
fn generate_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system RNG unavailable");
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

impl Authorization {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let identifier_json: String = row.try_get("identifier")?;
        let identifier: Identifier =
            serde_json::from_str(&identifier_json).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Authorization {
            id: row.try_get("id")?,
            order_id: row.try_get("order_id")?,
            identifier,
            status: row.try_get("status")?,
            expires: row.try_get("expires")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Builds a new `pending` authorization for `identifier`. Pure — nothing is
    /// persisted until [`Authorization::insert`] runs.
    pub(crate) fn new(order_id: &str, identifier: Identifier, expires: i64) -> Authorization {
        Authorization {
            id: Uuid::new_v4().to_string(),
            order_id: order_id.to_string(),
            identifier,
            status: "pending".to_string(),
            expires,
            created_at: now_secs(),
        }
    }

    /// Inserts the authorization using any executor — a pool, or a transaction
    /// (see [`crate::sqlite::order::Order::insert`] for why that matters).
    pub(crate) async fn insert<'e, E>(&self, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        // `Identifier` derives `Serialize`, so this never fails in practice.
        let identifier_json = serde_json::to_string(&self.identifier)
            .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

        debug!(event = "db_authz_create_started", outcome = "progress", authz_id = ?self.id, order_id = ?self.order_id);
        sqlx::query(
            "INSERT INTO authorizations (id, order_id, identifier, status, expires, created_at) \
             VALUES (?, ?, ?, ?, ?, ?);",
        )
        .bind(&self.id)
        .bind(&self.order_id)
        .bind(identifier_json)
        .bind(&self.status)
        .bind(self.expires)
        .bind(self.created_at)
        .execute(executor)
        .await?;

        info!(event = "db_authz_created", outcome = "success", authz_id = ?self.id, order_id = ?self.order_id);
        Ok(())
    }

    /// Creates a new authorization for `identifier` in the `pending` state.
    pub async fn create(
        order_id: &str,
        identifier: Identifier,
        expires: i64,
        database: &Database,
    ) -> Result<Authorization, sqlx::Error> {
        let authz = Authorization::new(order_id, identifier, expires);
        authz.insert(&database.pool).await?;
        Ok(authz)
    }

    pub async fn find_by_id(
        id: &str,
        database: &Database,
    ) -> Result<Option<Authorization>, sqlx::Error> {
        debug!(event = "db_authz_find_by_id_started", outcome = "progress", authz_id = ?id);
        let row = sqlx::query(
            "SELECT id, order_id, identifier, status, expires, created_at \
             FROM authorizations WHERE id = ?;",
        )
        .bind(id)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Authorization::from_row).transpose()
    }

    /// Lists an order's authorizations, oldest first (creation order), for the
    /// order object's `authorizations` array and the all-valid readiness check.
    pub async fn find_by_order(
        order_id: &str,
        database: &Database,
    ) -> Result<Vec<Authorization>, sqlx::Error> {
        Self::find_by_order_with(order_id, &database.pool).await
    }

    /// How many authorizations an order has. [`crate::sqlite::order::Order::count_by_account`]'s
    /// counterpart, and for the same reason.
    pub async fn count_by_order(order_id: &str, database: &Database) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) FROM authorizations WHERE order_id = ?;")
            .bind(order_id)
            .fetch_one(&database.pool)
            .await?;
        row.try_get::<i64, _>(0)
    }

    /// The authorization ids of several orders at once, keyed by order id.
    ///
    /// The listing paths need nothing but the ids — `Order::to_json` builds its
    /// `authorizations` URLs from them — and were calling
    /// [`Authorization::find_by_order`] once per row: 51 queries for a default
    /// page of 50. One `IN (…)` instead.
    ///
    /// An order with no authorizations is simply absent from the map, which is
    /// what a caller wants: `map.remove(id).unwrap_or_default()`.
    pub async fn find_ids_by_orders(
        order_ids: &[&str],
        database: &Database,
    ) -> Result<std::collections::HashMap<String, Vec<String>>, sqlx::Error> {
        let mut grouped: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        if order_ids.is_empty() {
            return Ok(grouped);
        }

        // `QueryBuilder` rather than a formatted `IN` list: `push_bind` is what
        // keeps the ids parameters instead of interpolated SQL, the same rule
        // `OrderQuery::push_predicates` follows.
        let mut builder =
            sqlx::QueryBuilder::new("SELECT id, order_id FROM authorizations WHERE order_id IN (");
        let mut separated = builder.separated(", ");
        for id in order_ids {
            separated.push_bind(*id);
        }
        builder.push(") ORDER BY created_at ASC;");

        debug!(
            event = "db_authz_find_ids_by_orders",
            outcome = "success",
            orders = order_ids.len()
        );
        for row in builder.build().fetch_all(&database.pool).await? {
            let order_id: String = row.try_get("order_id")?;
            let id: String = row.try_get("id")?;
            grouped.entry(order_id).or_default().push(id);
        }
        Ok(grouped)
    }

    /// [`Authorization::find_by_order`] over any executor — a pool, or a
    /// transaction.
    ///
    /// Reading inside the transaction that just wrote is what makes
    /// "is every authorization of this order valid now?" answerable at all: from
    /// the pool, two concurrent validations of two authorizations of one order
    /// can each read before the other's write commits, so neither sees a
    /// complete set and neither promotes the order.
    pub(crate) async fn find_by_order_with<'e, E>(
        order_id: &str,
        executor: E,
    ) -> Result<Vec<Authorization>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        debug!(event = "db_authz_find_by_order_started", outcome = "progress", order_id = ?order_id);
        let rows = sqlx::query(
            "SELECT id, order_id, identifier, status, expires, created_at \
             FROM authorizations WHERE order_id = ? ORDER BY created_at ASC;",
        )
        .bind(order_id)
        .fetch_all(executor)
        .await?;

        rows.into_iter().map(Authorization::from_row).collect()
    }

    /// The `valid` transition as a bare statement, over any executor.
    ///
    /// Split from [`Authorization::mark_valid`] so `post_challenge` can compose
    /// the challenge, authorization and order transitions into one transaction.
    /// The in-memory sync stays in `mark_valid`: it must not happen until the
    /// transaction has committed, or a rollback leaves the object claiming a
    /// status the database never took.
    pub(crate) async fn set_valid<'e, E>(id: &str, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE authorizations SET status = 'valid' WHERE id = ?;")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The `invalid` transition as a bare statement; see [`Authorization::set_valid`].
    pub(crate) async fn set_invalid<'e, E>(id: &str, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE authorizations SET status = 'invalid' WHERE id = ?;")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The `deactivated` transition as a bare statement; see [`Authorization::set_valid`].
    pub(crate) async fn set_deactivated<'e, E>(id: &str, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE authorizations SET status = 'deactivated' WHERE id = ?;")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Moves the authorization to the `valid` state and keeps `self` in sync (the
    /// same persist-and-sync pattern as [`crate::sqlite::order::Order::finalize`]).
    pub async fn mark_valid(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_authz_mark_valid_started", outcome = "progress", authz_id = ?self.id);
        Self::set_valid(&self.id, &database.pool).await?;

        self.status = "valid".to_string();
        info!(event = "db_authz_marked_valid", outcome = "success", authz_id = ?self.id);
        Ok(())
    }

    /// Moves the authorization to the terminal `invalid` state, after one of its
    /// challenges failed validation (RFC 8555 §7.1.6).
    ///
    /// No `error` is stored: the RFC puts the problem document on the
    /// *challenge*, and the authorization object has no `error` member — a client
    /// reads the reason from the challenge it triggered.
    pub async fn mark_invalid(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_authz_mark_invalid_started", outcome = "progress", authz_id = ?self.id);
        Self::set_invalid(&self.id, &database.pool).await?;

        self.status = "invalid".to_string();
        info!(event = "db_authz_marked_invalid", outcome = "failure", authz_id = ?self.id);
        Ok(())
    }

    /// Moves the authorization to the terminal `deactivated` state, at the
    /// client's own request (RFC 8555 §7.5.2).
    ///
    /// Like [`Authorization::mark_invalid`] this does not stamp `validated`:
    /// §8 defines that as the time of a *successful* validation, and relinquishing
    /// an authorization is the opposite.
    pub async fn mark_deactivated(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_authz_mark_deactivated_started", outcome = "progress", authz_id = ?self.id);
        Self::set_deactivated(&self.id, &database.pool).await?;

        self.status = "deactivated".to_string();
        info!(event = "db_authz_marked_deactivated", outcome = "success", authz_id = ?self.id);
        Ok(())
    }

    /// Whether this authorization covers the wildcard of its identifier.
    ///
    /// Derived from the stored value rather than stored separately — see the
    /// type's doc comment for why the row keeps the `*.` prefix.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.identifier.value.starts_with("*.")
    }

    /// The name to actually prove control of: the identifier with any `*.`
    /// stripped.
    ///
    /// A wildcard is proved by controlling the zone, so the DNS record lives at
    /// `_acme-challenge.example.com`, not at `_acme-challenge.*.example.com`.
    #[must_use]
    pub fn base_identifier(&self) -> &str {
        self.identifier
            .value
            .strip_prefix("*.")
            .unwrap_or(&self.identifier.value)
    }

    /// The RFC 8555 authorization object: `identifier`, `status`, `expires`
    /// (RFC3339), the `challenges` array (each rendered by
    /// [`Challenge::to_json`]), and `wildcard` when the authorization covers one.
    #[must_use]
    pub fn to_json(&self, base_url: &str, challenges: &[Challenge]) -> Value {
        let mut object = serde_json::Map::new();
        // RFC 8555 §7.1.4: the identifier of a wildcard authorization is the
        // *base* name, with the wildcard signalled by its own member. The stored
        // row keeps the `*.` prefix; only this rendering strips it.
        object.insert(
            "identifier".to_string(),
            serde_json::to_value(Identifier::new(
                self.identifier.typ.clone(),
                self.base_identifier().to_string(),
            ))
            .expect("Identifier is always serializable"),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("expires".to_string(), Value::String(rfc3339(self.expires)));
        let challenges: Vec<Value> = challenges.iter().map(|c| c.to_json(base_url)).collect();
        object.insert("challenges".to_string(), Value::Array(challenges));
        if self.is_wildcard() {
            object.insert("wildcard".to_string(), Value::Bool(true));
        }
        Value::Object(object)
    }
}

impl Challenge {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let error_json: Option<String> = row.try_get("error")?;
        let error = error_json
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Challenge {
            id: row.try_get("id")?,
            authz_id: row.try_get("authz_id")?,
            typ: row.try_get("type")?,
            token: row.try_get("token")?,
            status: row.try_get("status")?,
            validated: row.try_get("validated")?,
            error,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Builds a new `pending` challenge of type `typ` with a fresh random token.
    /// Pure — nothing is persisted until [`Challenge::insert`] runs.
    ///
    /// **Each challenge gets its own token**, even when several are offered for
    /// one authorization: RFC 8555 §8 describes the token as a per-challenge
    /// value, and every key authorization derives from it.
    pub(crate) fn new(authz_id: &str, typ: &str) -> Challenge {
        Challenge {
            id: Uuid::new_v4().to_string(),
            authz_id: authz_id.to_string(),
            typ: typ.to_string(),
            token: generate_token(),
            status: "pending".to_string(),
            validated: None,
            error: None,
            created_at: now_secs(),
        }
    }

    /// Inserts the challenge using any executor — a pool, or a transaction
    /// (see [`crate::sqlite::order::Order::insert`] for why that matters).
    pub(crate) async fn insert<'e, E>(&self, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        debug!(event = "db_challenge_create_started", outcome = "progress", challenge_id = ?self.id, authz_id = ?self.authz_id);
        sqlx::query(
            "INSERT INTO challenges (id, authz_id, type, token, status, validated, created_at) \
             VALUES (?, ?, ?, ?, ?, NULL, ?);",
        )
        .bind(&self.id)
        .bind(&self.authz_id)
        .bind(&self.typ)
        .bind(&self.token)
        .bind(&self.status)
        .bind(self.created_at)
        .execute(executor)
        .await?;

        info!(event = "db_challenge_created", outcome = "success", challenge_id = ?self.id, authz_id = ?self.authz_id);
        Ok(())
    }

    /// Creates a new challenge of type `typ`, with a fresh random token, in the
    /// `pending` state.
    pub async fn create(
        authz_id: &str,
        typ: &str,
        database: &Database,
    ) -> Result<Challenge, sqlx::Error> {
        let challenge = Challenge::new(authz_id, typ);
        challenge.insert(&database.pool).await?;
        Ok(challenge)
    }

    pub async fn find_by_id(
        id: &str,
        database: &Database,
    ) -> Result<Option<Challenge>, sqlx::Error> {
        debug!(event = "db_challenge_find_by_id_started", outcome = "progress", challenge_id = ?id);
        let row = sqlx::query(
            "SELECT id, authz_id, type, token, status, validated, error, created_at \
             FROM challenges WHERE id = ?;",
        )
        .bind(id)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Challenge::from_row).transpose()
    }

    /// Lists an authorization's challenges (creation order), for the
    /// authorization object's `challenges` array.
    pub async fn find_by_authz(
        authz_id: &str,
        database: &Database,
    ) -> Result<Vec<Challenge>, sqlx::Error> {
        debug!(event = "db_challenge_find_by_authz_started", outcome = "progress", authz_id = ?authz_id);
        let rows = sqlx::query(
            "SELECT id, authz_id, type, token, status, validated, error, created_at \
             FROM challenges WHERE authz_id = ? ORDER BY created_at ASC;",
        )
        .bind(authz_id)
        .fetch_all(&database.pool)
        .await?;

        rows.into_iter().map(Challenge::from_row).collect()
    }

    /// Records a successful validation: moves the challenge to `valid`, stamps
    /// `validated`, and keeps `self` in sync.
    /// The `valid` transition as a bare statement, over any executor.
    ///
    /// `validated` is taken as an argument rather than read from the clock here,
    /// so a caller composing this into a transaction stamps the challenge and
    /// its in-memory copy with the same instant. See
    /// [`Authorization::set_valid`] for why the sync is separate.
    pub(crate) async fn set_valid<'e, E>(
        id: &str,
        validated: i64,
        executor: E,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query("UPDATE challenges SET status = 'valid', validated = ? WHERE id = ?;")
            .bind(validated)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The `invalid` transition as a bare statement; see [`Challenge::set_valid`].
    pub(crate) async fn set_invalid<'e, E>(
        id: &str,
        error: &Value,
        executor: E,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let error_json =
            serde_json::to_string(error).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
        sqlx::query("UPDATE challenges SET status = 'invalid', error = ? WHERE id = ?;")
            .bind(error_json)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    pub async fn mark_valid(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        let validated = now_secs();
        debug!(event = "db_challenge_mark_valid_started", outcome = "progress", challenge_id = ?self.id);
        Self::set_valid(&self.id, validated, &database.pool).await?;

        self.status = "valid".to_string();
        self.validated = Some(validated);
        info!(event = "db_challenge_marked_valid", outcome = "success", challenge_id = ?self.id);
        Ok(())
    }

    /// Records a failed validation: moves the challenge to the terminal
    /// `invalid` state, stores the problem document explaining why, and keeps
    /// `self` in sync.
    ///
    /// `validated` is deliberately **not** stamped — RFC 8555 §8 defines it as
    /// the time the challenge was *successfully* validated.
    pub async fn mark_invalid(
        &mut self,
        error: Value,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "db_challenge_mark_invalid_started", outcome = "progress", challenge_id = ?self.id);
        Self::set_invalid(&self.id, &error, &database.pool).await?;

        self.status = "invalid".to_string();
        self.error = Some(error);
        info!(event = "db_challenge_marked_invalid", outcome = "failure", challenge_id = ?self.id);
        Ok(())
    }

    /// The RFC 8555 challenge object: `type`, the derived challenge `url`,
    /// `status`, `token`, plus `validated` (RFC3339) and `error` once set.
    #[must_use]
    pub fn to_json(&self, base_url: &str) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("type".to_string(), Value::String(self.typ.clone()));
        object.insert(
            "url".to_string(),
            Value::String(format!("{base_url}/chall/{}", self.id)),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("token".to_string(), Value::String(self.token.clone()));
        if let Some(validated) = self.validated {
            object.insert("validated".to_string(), Value::String(rfc3339(validated)));
        }
        if let Some(error) = &self.error {
            object.insert("error".to_string(), error.clone());
        }
        Value::Object(object)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::audit::ClientContext;
    use crate::sqlite::account::Account;
    use crate::sqlite::order::Order;
    use crate::testutil::account_id;
    use std::sync::Arc;

    /// The listing paths' N+1 fix: one query for a whole page.
    #[tokio::test]
    async fn ids_for_several_orders_come_back_grouped_in_one_query() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account_id(&db).await;

        let mut expected = Vec::new();
        for name in ["a.example.com", "b.example.com"] {
            let order = Order::create(
                "default",
                &account,
                vec![Identifier::dns(name)],
                now_secs() + 3600,
                None,
                None,
                &db,
            )
            .await
            .unwrap();
            let first =
                Authorization::create(&order.id, Identifier::dns(name), now_secs() + 3600, &db)
                    .await
                    .unwrap();
            expected.push((order.id, first.id));
        }

        let ids: Vec<&str> = expected.iter().map(|(o, _)| o.as_str()).collect();
        let grouped = Authorization::find_ids_by_orders(&ids, &db).await.unwrap();
        assert_eq!(grouped.len(), 2);
        for (order_id, authz_id) in &expected {
            assert_eq!(grouped[order_id], vec![authz_id.clone()]);
        }

        // An order with no authorizations is simply absent, which is what
        // `remove(..).unwrap_or_default()` at the call site relies on.
        let grouped = Authorization::find_ids_by_orders(&["nope"], &db)
            .await
            .unwrap();
        assert!(grouped.is_empty());

        // And an empty request does not build a `WHERE id IN ()`.
        assert!(
            Authorization::find_ids_by_orders(&[], &db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Builds account → order and returns the order id, so authorizations have a
    /// real parent to reference.
    async fn order_id(db: &Arc<Database>) -> String {
        let (account, _) = Account::find_or_create(
            "default",
            &[1u8, 2, 3],
            vec![],
            &ClientContext::default(),
            db,
        )
        .await
        .unwrap();
        let order = Order::create(
            "default",
            &account.id,
            vec![Identifier::dns("example.com")],
            now_secs() + 3600,
            None,
            None,
            db,
        )
        .await
        .unwrap();
        order.id
    }

    /// The `set_*` twins exist so `post_challenge` can put the challenge,
    /// authorization and order transitions in one transaction. This is the
    /// property that buys: a failure part-way through leaves *nothing* applied.
    ///
    /// Without it the three were separate statements, and a stop between the
    /// last two left an order `pending` with every authorization `valid` — a
    /// state nothing re-derives, since the readiness check only ever ran from
    /// the challenge trigger and the client has no challenge left to answer.
    #[tokio::test]
    async fn the_validation_transitions_roll_back_together() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        let challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();

        // Everything the success path does, then abandoned rather than
        // committed — standing in for a failure after the first statement.
        let mut tx = db.pool.begin().await.unwrap();
        Challenge::set_valid(&challenge.id, now_secs(), &mut *tx)
            .await
            .unwrap();
        Authorization::set_valid(&authz.id, &mut *tx).await.unwrap();
        Order::set_ready(&oid, &mut *tx).await.unwrap();
        tx.rollback().await.unwrap();

        let reloaded_authz = Authorization::find_by_id(&authz.id, &db)
            .await
            .unwrap()
            .unwrap();
        let reloaded_challenge = Challenge::find_by_id(&challenge.id, &db)
            .await
            .unwrap()
            .unwrap();
        let reloaded_order = Order::find_by_id(&oid, &db).await.unwrap().unwrap();

        assert_eq!(reloaded_challenge.status, "pending");
        assert_eq!(reloaded_authz.status, "pending");
        assert_eq!(reloaded_order.status, "pending");
    }

    /// And the same three, committed, do all land — so the test above is about
    /// the rollback and not about the statements being no-ops.
    #[tokio::test]
    async fn the_validation_transitions_commit_together() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        let challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();

        let mut tx = db.pool.begin().await.unwrap();
        Challenge::set_valid(&challenge.id, now_secs(), &mut *tx)
            .await
            .unwrap();
        Authorization::set_valid(&authz.id, &mut *tx).await.unwrap();
        Order::set_ready(&oid, &mut *tx).await.unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            Challenge::find_by_id(&challenge.id, &db)
                .await
                .unwrap()
                .unwrap()
                .status,
            "valid"
        );
        assert_eq!(
            Authorization::find_by_id(&authz.id, &db)
                .await
                .unwrap()
                .unwrap()
                .status,
            "valid"
        );
        assert_eq!(
            Order::find_by_id(&oid, &db).await.unwrap().unwrap().status,
            "ready"
        );
    }

    #[tokio::test]
    async fn authz_create_find_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        assert_eq!(authz.status, "pending");

        let by_id = Authorization::find_by_id(&authz.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.identifier, Identifier::dns("example.com"));
        assert_eq!(by_id.order_id, oid);

        let by_order = Authorization::find_by_order(&oid, &db).await.unwrap();
        assert_eq!(by_order.len(), 1);
    }

    #[tokio::test]
    async fn authz_mark_valid_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let mut authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        authz.mark_valid(&db).await.unwrap();

        assert_eq!(authz.status, "valid");
        let reloaded = Authorization::find_by_id(&authz.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "valid");
    }

    #[tokio::test]
    async fn authz_to_json_shape() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        let challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();

        let json = authz.to_json("http://localhost:3000", std::slice::from_ref(&challenge));
        assert_eq!(json["status"], "pending");
        assert_eq!(
            json["identifier"],
            serde_json::json!({"type":"dns","value":"example.com"})
        );
        assert!(json["expires"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["challenges"].as_array().unwrap().len(), 1);
        assert_eq!(json["challenges"][0]["type"], "http-01");
    }

    #[tokio::test]
    async fn challenge_create_find_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();

        let challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();
        assert_eq!(challenge.typ, "http-01");
        assert_eq!(challenge.status, "pending");
        assert!(!challenge.token.is_empty());
        assert!(challenge.validated.is_none());

        let by_id = Challenge::find_by_id(&challenge.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.token, challenge.token);

        let by_authz = Challenge::find_by_authz(&authz.id, &db).await.unwrap();
        assert_eq!(by_authz.len(), 1);
    }

    #[tokio::test]
    async fn challenge_mark_valid_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();

        let mut challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();
        challenge.mark_valid(&db).await.unwrap();

        assert_eq!(challenge.status, "valid");
        assert!(challenge.validated.is_some());

        let reloaded = Challenge::find_by_id(&challenge.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "valid");
        let json = reloaded.to_json("http://localhost:3000");
        assert_eq!(json["status"], "valid");
        assert_eq!(
            json["url"],
            format!("http://localhost:3000/chall/{}", challenge.id)
        );
        assert!(json["validated"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn challenge_mark_invalid_persists_the_problem_document() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();

        let mut challenge = Challenge::create(&authz.id, "http-01", &db).await.unwrap();
        let problem = serde_json::json!({
            "type": "urn:ietf:params:acme:error:incorrectResponse",
            "detail": "response body does not match the key authorization",
            "status": 403,
        });
        challenge.mark_invalid(problem.clone(), &db).await.unwrap();

        assert_eq!(challenge.status, "invalid");
        assert_eq!(challenge.error.as_ref(), Some(&problem));
        // RFC 8555 §8 stamps `validated` only on success.
        assert!(challenge.validated.is_none());

        let reloaded = Challenge::find_by_id(&challenge.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "invalid");
        assert_eq!(reloaded.error.as_ref(), Some(&problem));
        let json = reloaded.to_json("http://localhost:3000");
        assert_eq!(json["error"], problem);
        assert!(json.get("validated").is_none());
    }

    #[tokio::test]
    async fn authz_mark_invalid_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let mut authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        authz.mark_invalid(&db).await.unwrap();

        assert_eq!(authz.status, "invalid");
        let reloaded = Authorization::find_by_id(&authz.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "invalid");
    }

    /// `UNIQUE(authz_id, type)` is what lets one authorization offer several
    /// challenges — one per type, and no more.
    #[tokio::test]
    async fn an_authorization_holds_one_challenge_per_type() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;
        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();

        let http = Challenge::create(&authz.id, "http-01", &db).await.unwrap();
        let dns_01 = Challenge::create(&authz.id, "dns-01", &db).await.unwrap();
        Challenge::create(&authz.id, "tls-alpn-01", &db)
            .await
            .unwrap();

        // Each carries its own token: a key authorization is per challenge.
        assert_ne!(http.token, dns_01.token);

        let challenges = Challenge::find_by_authz(&authz.id, &db).await.unwrap();
        assert_eq!(challenges.len(), 3);

        // A second challenge of a type already offered is refused by the schema.
        assert!(Challenge::create(&authz.id, "http-01", &db).await.is_err());
    }

    /// A wildcard authorization stores the `*.` form but renders the base name
    /// plus a `wildcard` member (RFC 8555 §7.1.4), and proves control of the
    /// base name.
    #[tokio::test]
    async fn a_wildcard_authorization_stores_the_prefix_and_renders_the_base_name() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let authz = Authorization::create(
            &oid,
            Identifier::dns("*.example.com"),
            now_secs() + 3600,
            &db,
        )
        .await
        .unwrap();
        let challenge = Challenge::create(&authz.id, "dns-01", &db).await.unwrap();

        // The row keeps the wildcard form, so the canonical two-authorization
        // order does not collide on `UNIQUE(order_id, identifier)`.
        let reloaded = Authorization::find_by_id(&authz.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.identifier.value, "*.example.com");
        assert!(reloaded.is_wildcard());
        assert_eq!(reloaded.base_identifier(), "example.com");

        let json = reloaded.to_json("http://localhost:3000", std::slice::from_ref(&challenge));
        assert_eq!(
            json["identifier"],
            serde_json::json!({"type":"dns","value":"example.com"})
        );
        assert_eq!(json["wildcard"], true);
        assert_eq!(json["challenges"][0]["type"], "dns-01");
    }

    /// The non-wildcard object has no `wildcard` member at all — RFC 8555 makes
    /// it optional and clients treat its absence as false.
    #[tokio::test]
    async fn a_plain_authorization_has_no_wildcard_member() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let oid = order_id(&db).await;

        let authz =
            Authorization::create(&oid, Identifier::dns("example.com"), now_secs() + 3600, &db)
                .await
                .unwrap();
        assert!(!authz.is_wildcard());
        assert_eq!(authz.base_identifier(), "example.com");
        assert!(
            authz
                .to_json("http://localhost:3000", &[])
                .get("wildcard")
                .is_none()
        );
    }

    #[tokio::test]
    async fn absent_lookups_return_none() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(
            Authorization::find_by_id("nope", &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(Challenge::find_by_id("nope", &db).await.unwrap().is_none());
    }
}
