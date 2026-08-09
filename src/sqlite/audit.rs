//! The `audit_log` model: append, read back, purge by age.
//!
//! Deliberately narrow. There is no setter of any kind and no `update`: a row
//! is INSERTed once and thereafter only read or deleted wholesale by
//! [`AuditEntry::cleanup`]. That is the whole reason the table has no foreign
//! keys either — see the header comment in
//! `migrations/20260809120000_add_audit_log.sql`.

use serde_json::{Value, json};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::debug;

use crate::audit::{Actor, ActorKind, AuditEvent, AuditRecord, ClientContext};
use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::rfc3339;

/// One stored audit row.
///
/// `event` and `actor_kind` come back as the strings they were stored as rather
/// than as [`AuditEvent`]/[`ActorKind`]: a `CHECK` constraint written before a
/// future variant existed is exactly the thing that would make a read of an
/// older database fail, and a listing that renders an unrecognised event name
/// is a better outcome than one that refuses to load. [`AuditEntry::event`]
/// parses it for the callers that want the enum.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub created_at: i64,
    pub event: String,
    pub outcome: String,
    pub profile: String,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub account_id: Option<String>,
    pub order_id: Option<String>,
    pub cert_serial: Option<String>,
    pub identifiers: Vec<String>,
    pub client_ip: Option<String>,
    pub client_ptr: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub reason: Option<String>,
    pub detail: Option<String>,
}

/// Every column, in one place: the page query, the count and the single-row
/// read must select the same set or `from_row` fails on whichever forgot one.
const COLUMNS: &str = "id, created_at, event, outcome, profile, actor_kind, actor_id, \
                       account_id, order_id, cert_serial, identifiers, client_ip, client_ptr, \
                       user_agent, request_id, reason, detail";

/// The filters and page window [`AuditEntry::search`] applies.
///
/// Every filter is optional and an absent one imposes no constraint, so
/// `AuditQuery { limit, offset, .. }` is "the newest page of everything".
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub profile: Option<String>,
    pub account_id: Option<String>,
    pub order_id: Option<String>,
    pub cert_serial: Option<String>,
    pub event: Option<String>,
    pub outcome: Option<String>,
    /// Lower bound on `created_at`, inclusive. The one filter that is not an
    /// equality, which is why it is applied separately below.
    pub since: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

impl AuditQuery {
    /// Appends the `WHERE` clause shared by the page query and the count — one
    /// function rather than two copies, for the reason
    /// [`crate::sqlite::order::OrderQuery::push_predicates`] gives: a filter
    /// applied to only one of them reports a total the rows contradict.
    fn push_predicates(&self, builder: &mut sqlx::QueryBuilder<sqlx::Sqlite>) {
        let mut separator = " WHERE ";
        for (column, value) in [
            ("profile = ", self.profile.as_ref()),
            ("account_id = ", self.account_id.as_ref()),
            ("order_id = ", self.order_id.as_ref()),
            ("cert_serial = ", self.cert_serial.as_ref()),
            ("event = ", self.event.as_ref()),
            ("outcome = ", self.outcome.as_ref()),
        ] {
            if let Some(value) = value {
                builder
                    .push(separator)
                    .push(column)
                    .push_bind(value.clone());
                separator = " AND ";
            }
        }
        if let Some(since) = self.since {
            builder
                .push(separator)
                .push("created_at >= ")
                .push_bind(since);
        }
    }
}

impl AuditEntry {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let identifiers_json: String = row.try_get("identifiers")?;
        let identifiers: Vec<String> = serde_json::from_str(&identifiers_json)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        Ok(Self {
            id: row.try_get("id")?,
            created_at: row.try_get("created_at")?,
            event: row.try_get("event")?,
            outcome: row.try_get("outcome")?,
            profile: row.try_get("profile")?,
            actor_kind: row.try_get("actor_kind")?,
            actor_id: row.try_get("actor_id")?,
            account_id: row.try_get("account_id")?,
            order_id: row.try_get("order_id")?,
            cert_serial: row.try_get("cert_serial")?,
            identifiers,
            client_ip: row.try_get("client_ip")?,
            client_ptr: row.try_get("client_ptr")?,
            user_agent: row.try_get("user_agent")?,
            request_id: row.try_get("request_id")?,
            reason: row.try_get("reason")?,
            detail: row.try_get("detail")?,
        })
    }

    /// The parsed event, or `None` for a value this build does not know — see
    /// the struct comment.
    #[must_use]
    pub fn event(&self) -> Option<AuditEvent> {
        AuditEvent::parse(&self.event)
    }

    /// Appends one row, returning its assigned id.
    ///
    /// `outcome` is taken from [`AuditEvent::outcome`] rather than the caller,
    /// so the two columns cannot disagree — there is one definition of which
    /// events are failures and this is the only place it is read.
    pub async fn insert(record: AuditRecord, database: &Database) -> Result<i64, sqlx::Error> {
        let AuditRecord {
            event,
            profile,
            actor,
            account_id,
            order_id,
            cert_serial,
            identifiers,
            client,
            reason,
            detail,
        } = record;
        let Actor { kind, id: actor_id } = actor;
        let ClientContext {
            ip: client_ip,
            ptr: client_ptr,
            user_agent,
            request_id,
        } = client;

        // `identifiers` is a `Vec<String>`, so serialization is infallible.
        let identifiers_json = Value::from(identifiers).to_string();
        let created_at = now_secs();

        let id = sqlx::query(
            "INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind, actor_id, \
             account_id, order_id, cert_serial, identifiers, client_ip, client_ptr, user_agent, \
             request_id, reason, detail) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;",
        )
        .bind(created_at)
        .bind(event.as_str())
        .bind(event.outcome())
        .bind(&profile)
        .bind(kind.as_str())
        .bind(&actor_id)
        .bind(&account_id)
        .bind(&order_id)
        .bind(&cert_serial)
        .bind(identifiers_json)
        .bind(&client_ip)
        .bind(&client_ptr)
        .bind(&user_agent)
        .bind(&request_id)
        .bind(&reason)
        .bind(&detail)
        .fetch_one(&database.pool)
        .await?
        .try_get::<i64, _>("id")?;

        debug!(
            event = "db_audit_row_written",
            audit_id = id,
            audit_event = event.as_str(),
            profile = %profile,
            actor_kind = kind.as_str(),
        );
        Ok(id)
    }

    /// One row by id — what `acme-proxy audit show <id>` reads.
    pub async fn find_by_id(id: i64, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        // A `QueryBuilder` rather than `sqlx::query`, which takes only
        // `&'static str` and so cannot be handed the shared `COLUMNS`. `id`
        // still goes through `push_bind`, so nothing is interpolated.
        let mut query =
            sqlx::QueryBuilder::new(format!("SELECT {COLUMNS} FROM audit_log WHERE id = "));
        query.push_bind(id);
        let row = query.build().fetch_optional(&database.pool).await?;
        row.map(Self::from_row).transpose()
    }

    /// One page of rows matching `query`, newest first, plus the total the same
    /// predicate matches unpaged.
    pub async fn search(
        query: &AuditQuery,
        database: &Database,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        debug!(
            event = "audit_search_started",
            profile = ?query.profile,
            account_id = ?query.account_id,
            audit_event = ?query.event,
            outcome = ?query.outcome,
            limit = query.limit,
            offset = query.offset,
        );

        let mut page = sqlx::QueryBuilder::new(format!("SELECT {COLUMNS} FROM audit_log"));
        query.push_predicates(&mut page);
        // Newest first. `id` breaks the tie rather than merely decorating the
        // clause: `created_at` is whole seconds and this table takes several
        // rows a second under load, so without it two rows could swap between
        // pages and one would never be seen.
        page.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        page.push_bind(query.limit);
        page.push(" OFFSET ");
        page.push_bind(query.offset);

        let rows = page.build().fetch_all(&database.pool).await?;
        let entries: Vec<Self> = rows
            .into_iter()
            .map(Self::from_row)
            .collect::<Result<_, _>>()?;

        let mut count = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM audit_log");
        query.push_predicates(&mut count);
        let total: i64 = count
            .build()
            .fetch_one(&database.pool)
            .await?
            .try_get::<i64, _>(0)?;

        Ok((entries, total))
    }

    /// How many rows are older than `cutoff` — what the purge prompt names
    /// before deleting anything.
    pub async fn count_older_than(cutoff: i64, database: &Database) -> Result<i64, sqlx::Error> {
        sqlx::query("SELECT COUNT(*) FROM audit_log WHERE created_at < ?;")
            .bind(cutoff)
            .fetch_one(&database.pool)
            .await?
            .try_get::<i64, _>(0)
    }

    /// Deletes every row older than `cutoff`, returning how many went.
    ///
    /// The only statement in the crate that removes an audit row, and it takes
    /// an absolute cutoff rather than a duration so the CLI's `--older-than`
    /// and the `audit.retention_days` sweep run the identical delete.
    pub async fn cleanup(cutoff: i64, database: &Database) -> Result<u64, sqlx::Error> {
        let deleted = sqlx::query("DELETE FROM audit_log WHERE created_at < ?;")
            .bind(cutoff)
            .execute(&database.pool)
            .await?
            .rows_affected();
        debug!(
            event = "db_audit_cleanup",
            deleted = deleted,
            cutoff = cutoff
        );
        Ok(deleted)
    }

    /// The JSON shape the admin API serves.
    ///
    /// Absent members rather than `null` for the optional columns, the shape
    /// `Account::to_json` and `Order::to_json` already use: a consumer reading
    /// `client_ip` off a CLI-initiated revocation gets nothing, which is what
    /// happened.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "createdAt": rfc3339(self.created_at),
            "event": self.event,
            "outcome": self.outcome,
            "profile": self.profile,
            "actorKind": self.actor_kind,
            "identifiers": self.identifiers,
        });
        let map = value
            .as_object_mut()
            .expect("the literal above is an object");
        for (key, field) in [
            ("actorId", self.actor_id.as_ref()),
            ("accountId", self.account_id.as_ref()),
            ("orderId", self.order_id.as_ref()),
            ("certSerial", self.cert_serial.as_ref()),
            ("clientIp", self.client_ip.as_ref()),
            ("clientPtr", self.client_ptr.as_ref()),
            ("userAgent", self.user_agent.as_ref()),
            ("requestId", self.request_id.as_ref()),
            ("reason", self.reason.as_ref()),
            ("detail", self.detail.as_ref()),
        ] {
            if let Some(field) = field {
                map.insert(key.to_string(), Value::from(field.clone()));
            }
        }
        value
    }
}

/// The `actor_kind` values, for the CLI help and the page filter. Mirrors
/// [`crate::audit::ActorKind`]; the `CHECK` in the migration is the authority.
#[must_use]
pub fn actor_kinds() -> [&'static str; 4] {
    [
        ActorKind::Acme.as_str(),
        ActorKind::Admin.as_str(),
        ActorKind::Cli.as_str(),
        ActorKind::System.as_str(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, AuditEvent, ClientContext};
    use std::sync::Arc;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    fn client() -> ClientContext {
        ClientContext {
            ip: Some("203.0.113.7".to_string()),
            ptr: Some("host.example.com".to_string()),
            user_agent: Some("certbot/2.9.0".to_string()),
            request_id: Some("req-1".to_string()),
        }
    }

    fn record(event: AuditEvent, profile: &str) -> AuditRecord {
        AuditRecord::new(event, profile, Actor::acme("acct-1"))
    }

    /// The two fields production only ever sets through `with_order`, which
    /// needs a real `Order`. The struct's fields are public, so a test that
    /// only cares about the column can set them directly rather than justify a
    /// builder method with no caller outside this file.
    fn with_subject(mut record: AuditRecord, order_id: &str, identifiers: &[&str]) -> AuditRecord {
        record.order_id = Some(order_id.to_string());
        record.identifiers = identifiers.iter().map(|v| (*v).to_string()).collect();
        record
    }

    /// The round trip, and the one column no caller sets: `outcome` comes from
    /// `AuditEvent::outcome`, so an insert cannot get it wrong.
    #[tokio::test]
    async fn a_row_round_trips_and_derives_its_own_outcome() {
        let db = db().await;
        let id = AuditEntry::insert(
            with_subject(
                record(AuditEvent::CertificateIssued, "le"),
                "order-1",
                &["a.example.com"],
            )
            .with_serial("0a0b")
            .with_client(client()),
            &db,
        )
        .await
        .unwrap();

        let entry = AuditEntry::find_by_id(id, &db).await.unwrap().unwrap();
        assert_eq!(entry.event, "certificate_issued");
        assert_eq!(entry.outcome, "success");
        assert_eq!(entry.event(), Some(AuditEvent::CertificateIssued));
        assert_eq!(entry.profile, "le");
        assert_eq!(entry.actor_kind, "acme");
        assert_eq!(entry.actor_id.as_deref(), Some("acct-1"));
        assert_eq!(entry.order_id.as_deref(), Some("order-1"));
        assert_eq!(entry.cert_serial.as_deref(), Some("0a0b"));
        assert_eq!(entry.identifiers, vec!["a.example.com"]);
        assert_eq!(entry.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(entry.client_ptr.as_deref(), Some("host.example.com"));
        assert_eq!(entry.user_agent.as_deref(), Some("certbot/2.9.0"));
        assert_eq!(entry.request_id.as_deref(), Some("req-1"));

        let failed = AuditEntry::insert(
            record(AuditEvent::CertificateRevokeFailed, "le").with_reason("unauthorized"),
            &db,
        )
        .await
        .unwrap();
        let entry = AuditEntry::find_by_id(failed, &db).await.unwrap().unwrap();
        assert_eq!(entry.outcome, "failure");
        assert!(entry.identifiers.is_empty());
        assert_eq!(entry.client_ip, None);

        assert!(AuditEntry::find_by_id(9_999, &db).await.unwrap().is_none());
    }

    /// The property the whole table is shaped around: an audit row outlives the
    /// account and the order it names. There is no foreign key, so deleting
    /// either must leave the row — and its frozen identifiers — untouched.
    #[tokio::test]
    async fn a_row_survives_the_account_and_order_it_names_being_deleted() {
        let db = db().await;
        let account_id = crate::testutil::account_id(&db).await;
        let order = crate::sqlite::order::Order::new(
            "default",
            &account_id,
            vec![crate::sqlite::order::Identifier::dns("a.example.com")],
            0,
            None,
            None,
        );
        order.insert(&db.pool).await.unwrap();

        let id = AuditEntry::insert(
            AuditRecord::new(
                AuditEvent::CertificateIssued,
                "default",
                Actor::acme(&account_id),
            )
            .with_order(&order),
            &db,
        )
        .await
        .unwrap();

        // The cascade takes the order with the account; neither takes the row.
        crate::sqlite::account::Account::delete(&account_id, &db)
            .await
            .unwrap();
        assert!(
            crate::sqlite::order::Order::find_by_id(&order.id, &db)
                .await
                .unwrap()
                .is_none()
        );

        let entry = AuditEntry::find_by_id(id, &db).await.unwrap().unwrap();
        assert_eq!(entry.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(entry.order_id.as_deref(), Some(order.id.as_str()));
        assert_eq!(entry.identifiers, vec!["a.example.com"]);
    }

    /// Every filter, applied to the page *and* the count — a predicate on only
    /// one of them reports a total the rows contradict.
    #[tokio::test]
    async fn every_filter_narrows_the_page_and_the_total_together() {
        let db = db().await;
        for (event, profile, account, serial) in [
            (AuditEvent::CertificateIssued, "le", "acct-1", "aa"),
            (AuditEvent::CertificateIssued, "le", "acct-2", "bb"),
            (AuditEvent::CertificateIssueFailed, "le", "acct-1", "cc"),
            (AuditEvent::CertificateRevoked, "internal", "acct-1", "dd"),
        ] {
            AuditEntry::insert(
                AuditRecord::new(event, profile, Actor::acme(account))
                    // `Actor::acme` fills `actor_id`; the *subject* column the
                    // filter reads is `account_id`, and the two are not the
                    // same field — an admin revoking somebody else's order
                    // writes a row where they differ.
                    .with_account(account)
                    .with_serial(serial),
                &db,
            )
            .await
            .unwrap();
        }

        let count = async |query: AuditQuery| {
            let (rows, total) = AuditEntry::search(&query, &db).await.unwrap();
            assert_eq!(rows.len() as i64, total, "page and total must agree");
            total
        };
        let base = AuditQuery {
            limit: 50,
            ..AuditQuery::default()
        };

        assert_eq!(count(base.clone()).await, 4);
        assert_eq!(
            count(AuditQuery {
                profile: Some("le".to_string()),
                ..base.clone()
            })
            .await,
            3
        );
        assert_eq!(
            count(AuditQuery {
                account_id: Some("acct-1".to_string()),
                ..base.clone()
            })
            .await,
            3
        );
        assert_eq!(
            count(AuditQuery {
                cert_serial: Some("dd".to_string()),
                ..base.clone()
            })
            .await,
            1
        );
        assert_eq!(
            count(AuditQuery {
                event: Some("certificate_issued".to_string()),
                ..base.clone()
            })
            .await,
            2
        );
        assert_eq!(
            count(AuditQuery {
                outcome: Some("failure".to_string()),
                ..base.clone()
            })
            .await,
            1
        );
        // Combined, and an unknown value narrows to nothing rather than erroring.
        assert_eq!(
            count(AuditQuery {
                profile: Some("le".to_string()),
                outcome: Some("success".to_string()),
                account_id: Some("acct-1".to_string()),
                ..base.clone()
            })
            .await,
            1
        );
        assert_eq!(
            count(AuditQuery {
                event: Some("certificate_renewed".to_string()),
                ..base
            })
            .await,
            0
        );
    }

    /// Newest first, with `id` breaking the tie — every row here lands in the
    /// same whole second, which is exactly the case the tiebreak exists for:
    /// without it a row could swap between pages and never be seen.
    #[tokio::test]
    async fn paging_one_row_at_a_time_sees_every_row_exactly_once_newest_first() {
        let db = db().await;
        let mut inserted = Vec::new();
        for index in 0..5 {
            inserted.push(
                AuditEntry::insert(
                    record(AuditEvent::CertificateIssued, "le")
                        .with_serial(format!("serial-{index}")),
                    &db,
                )
                .await
                .unwrap(),
            );
        }

        let mut seen = Vec::new();
        for offset in 0..5 {
            let (rows, total) = AuditEntry::search(
                &AuditQuery {
                    limit: 1,
                    offset,
                    ..AuditQuery::default()
                },
                &db,
            )
            .await
            .unwrap();
            assert_eq!(total, 5);
            seen.push(rows[0].id);
        }

        inserted.reverse();
        assert_eq!(seen, inserted);
    }

    /// The purge: counted before it runs (that number words the prompt), and
    /// bounded strictly by the cutoff so a row exactly on it survives.
    #[tokio::test]
    async fn cleanup_removes_only_what_is_strictly_older_than_the_cutoff() {
        let db = db().await;
        for _ in 0..3 {
            AuditEntry::insert(record(AuditEvent::CertificateIssued, "le"), &db)
                .await
                .unwrap();
        }
        let now = crate::sqlite::nonce::now_secs();

        // Nothing is older than "an hour ago".
        let past = now - 3600;
        assert_eq!(AuditEntry::count_older_than(past, &db).await.unwrap(), 0);
        assert_eq!(AuditEntry::cleanup(past, &db).await.unwrap(), 0);

        // Nor exactly at `created_at`: the predicate is `<`, not `<=`.
        assert_eq!(AuditEntry::count_older_than(now, &db).await.unwrap(), 0);

        let future = now + 3600;
        assert_eq!(AuditEntry::count_older_than(future, &db).await.unwrap(), 3);
        assert_eq!(AuditEntry::cleanup(future, &db).await.unwrap(), 3);
        assert_eq!(AuditEntry::count_older_than(future, &db).await.unwrap(), 0);
    }

    /// The JSON shape: optional columns are **absent**, not `null`, matching
    /// `Account::to_json`/`Order::to_json`.
    #[tokio::test]
    async fn to_json_omits_the_columns_that_have_no_value() {
        let db = db().await;
        let bare = AuditEntry::insert(
            AuditRecord::new(AuditEvent::CertificateRevoked, "le", Actor::system()),
            &db,
        )
        .await
        .unwrap();
        let json = AuditEntry::find_by_id(bare, &db)
            .await
            .unwrap()
            .unwrap()
            .to_json();
        let object = json.as_object().unwrap();

        assert_eq!(object["event"], "certificate_revoked");
        assert_eq!(object["outcome"], "success");
        assert_eq!(object["actorKind"], "system");
        assert_eq!(object["identifiers"], serde_json::json!([]));
        assert!(object["createdAt"].as_str().unwrap().contains('T'));
        for absent in [
            "actorId",
            "accountId",
            "orderId",
            "certSerial",
            "clientIp",
            "clientPtr",
            "userAgent",
            "requestId",
            "reason",
            "detail",
        ] {
            assert!(!object.contains_key(absent), "{absent} should be absent");
        }

        let full = AuditEntry::insert(
            record(AuditEvent::CertificateIssueFailed, "le")
                .with_client(client())
                .with_reason("badCSR")
                .with_detail("nope"),
            &db,
        )
        .await
        .unwrap();
        let json = AuditEntry::find_by_id(full, &db)
            .await
            .unwrap()
            .unwrap()
            .to_json();
        assert_eq!(json["clientIp"], "203.0.113.7");
        assert_eq!(json["clientPtr"], "host.example.com");
        assert_eq!(json["reason"], "badCSR");
        assert_eq!(json["detail"], "nope");
    }

    /// An `event` this build does not know still loads: the `CHECK` guards the
    /// write, and a reader that refused an unrecognised value would make a
    /// newer server's rows unreadable by an older one.
    #[tokio::test]
    async fn an_unknown_event_string_still_loads_and_simply_does_not_parse() {
        let db = db().await;
        sqlx::query(
            "INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind) \
             VALUES (0, 'certificate_issued', 'success', 'le', 'acme');",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let mut entry = AuditEntry::search(
            &AuditQuery {
                limit: 1,
                ..AuditQuery::default()
            },
            &db,
        )
        .await
        .unwrap()
        .0
        .remove(0);
        entry.event = "certificate_renewed".to_string();
        assert_eq!(entry.event(), None);
    }

    /// The `CHECK` constraints are the schema's own guard on the two enums.
    #[tokio::test]
    async fn the_schema_refuses_an_event_outcome_or_actor_it_does_not_know() {
        let db = db().await;
        for (event, outcome, actor) in [
            ("certificate_renewed", "success", "acme"),
            ("certificate_issued", "maybe", "acme"),
            ("certificate_issued", "success", "robot"),
        ] {
            let error = sqlx::query(
                "INSERT INTO audit_log (created_at, event, outcome, profile, actor_kind) \
                 VALUES (0, ?, ?, 'le', ?);",
            )
            .bind(event)
            .bind(outcome)
            .bind(actor)
            .execute(&db.pool)
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("CHECK constraint failed"),
                "{event}/{outcome}/{actor} was accepted: {error}"
            );
        }
    }

    /// Mirrors `crate::audit::ActorKind`, and is what the CLI help and the page
    /// filter read.
    #[test]
    fn the_actor_kinds_helper_lists_every_variant() {
        assert_eq!(actor_kinds(), ["acme", "admin", "cli", "system"]);
    }
}
