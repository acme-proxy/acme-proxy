//! The store, run against **both** backends, over the paths where the two
//! dialects are not the same query.
//!
//! The other suites run on SQLite and stay there: they test rules, and a rule
//! does not change with the backend. What changes is the handful of places
//! `crates/store/src/sql.rs` had to fork, plus the idioms whose correctness is
//! a property of the *engine* rather than of the SQL —  `rows_affected() == 1`
//! deciding a race, a partial unique index refusing a second claim, a typed
//! null. Each of those is a place a dialect bug would be silent rather than
//! loud, so each gets a test that runs twice.
//!
//! **Skips when `TEST_POSTGRES_URL` is unset**, so `cargo nextest run` on a
//! developer machine is unaffected. CI's `postgres` job sets it together with
//! `ACME_PROXY_REQUIRE_POSTGRES`, which turns a skip into a failure — without
//! that, a service that never started would take this whole file green.
//!
//! Every test here takes its own schema; see
//! `acme_proxy_store::testutil::postgres_database`.

use std::sync::Arc;

use acme_proxy_core::audit::ClientContext;
use acme_proxy_store::db::Database;
use acme_proxy_store::order::{Order, OrderQuery};
use acme_proxy_store::testutil;

/// Runs `body` against an in-memory SQLite and, when one is configured, against
/// a PostgreSQL schema of its own.
///
/// A macro rather than a loop over two databases: the body is `async` and
/// borrows, and a closure returning a future that borrows its argument needs
/// more ceremony than the thing it would save.
macro_rules! each_backend {
    (|$db:ident| $body:expr) => {{
        {
            let $db = Arc::new(
                Database::connect_in_memory()
                    .await
                    .expect("an in-memory SQLite always opens"),
            );
            $body;
        }
        if let Some(database) = testutil::postgres_database().await {
            let $db = Arc::new(database);
            $body;
        }
    }};
}

/// An account, and an order carrying `identifiers`.
async fn order_with(database: &Arc<Database>, names: &[&str]) -> Order {
    let account_id = testutil::account_id(database).await;
    Order::create(
        "default",
        account_id,
        testutil::dns_identifiers(names),
        EXPIRES,
        None,
        None,
        database,
    )
    .await
    .expect("an order should be storable")
}

/// Far enough out that nothing here is swept as expired.
const EXPIRES: i64 = 4_102_444_800;

/// The identifier search is the one query written twice: `json_each` and
/// `json_extract` against `jsonb_array_elements` and `->>`.
///
/// Exact match is the misissuance-hunt answer, so the negative case is the
/// load-bearing one — `example.com` must not also return `evil-example.com`.
#[tokio::test]
async fn the_identifier_search_matches_exactly_on_both_backends() {
    each_backend!(|db| {
        order_with(&db, &["example.com"]).await;
        order_with(&db, &["evil-example.com"]).await;

        let found = |value: &str| {
            let db = db.clone();
            let value = value.to_string();
            async move {
                let query = OrderQuery {
                    identifier: Some(value),
                    ..Default::default()
                };
                Order::search(&query, &db).await.expect("search works").1
            }
        };

        assert_eq!(found("example.com").await, 1, "the exact name");
        assert_eq!(
            found("evil-example.com").await,
            1,
            "and the other one, on its own"
        );
        assert_eq!(found("ample.com").await, 0, "a suffix is not a match");
        assert_eq!(found("nothing.invalid").await, 0);
    });
}

/// The substring search is `instr` on one backend and `strpos` on the other.
///
/// Deliberately not `LIKE`: a `%` or `_` an operator typed is a literal. That
/// is also why the wildcard case is here — it is the assertion that would fail
/// if either arm were ever rewritten to `LIKE`.
#[tokio::test]
async fn the_substring_search_treats_wildcards_as_literals_on_both_backends() {
    each_backend!(|db| {
        order_with(&db, &["shop.example.com"]).await;

        let found = |value: &str| {
            let db = db.clone();
            let value = value.to_string();
            async move {
                let query = OrderQuery {
                    identifier_contains: Some(value),
                    ..Default::default()
                };
                Order::search(&query, &db).await.expect("search works").1
            }
        };

        assert_eq!(found("example").await, 1, "a fragment in the middle");
        assert_eq!(found("SHOP").await, 1, "folded to lower case");
        assert_eq!(
            found("%").await,
            0,
            "a percent is a character, not a wildcard"
        );
        assert_eq!(found("_").await, 0, "and so is an underscore");
        assert_eq!(found("zzz").await, 0);
    });
}

/// A nonce is spent exactly once, whoever asks.
///
/// `Nonce::verify` is a single guarded `DELETE` whose `rows_affected() == 1`
/// names the winner. On SQLite one writer at a time makes that trivially true;
/// on PostgreSQL it rests on row-level locking and the re-check that follows
/// it. It is the hottest write in the server and the one place a dialect
/// difference would be a security hole rather than an error, so it is asserted
/// rather than assumed.
#[tokio::test]
async fn a_nonce_is_spent_exactly_once_on_both_backends() {
    use acme_proxy_store::nonce::Nonce;
    use std::time::Duration;

    each_backend!(|db| {
        let nonce = Nonce::new();
        let value = nonce.value.clone();
        nonce.save(&db).await.expect("a nonce should be storable");

        let ttl = Duration::from_secs(300);
        let mut wins = 0;
        for _ in 0..5 {
            if Nonce::verify(&value, &db, ttl).await.expect("verify works") {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one caller may spend a nonce");
    });
}

/// One predecessor, one live claim — enforced by a partial unique index.
///
/// The index is `(profile, replaces) WHERE replaces IS NOT NULL AND status !=
/// 'invalid'`, and both dialects spell it the same way. What differs is the
/// *error*: SQLite names the columns and gives sqlx no constraint name, while
/// PostgreSQL names the index and never the columns. `is_replaces_conflict`
/// reads both, and before it did, a second claim was a `500` here instead of
/// RFC 9773's `409 alreadyReplaced`.
#[tokio::test]
async fn one_predecessor_can_only_be_claimed_once_on_both_backends() {
    each_backend!(|db| {
        let account_id = testutil::account_id(&db).await;
        let cert_id = "some-certID";

        // `replaces` is set between `new` and `insert`, which is the shape the
        // handler uses too.
        let claim = |suffix: &str| {
            let db = db.clone();
            let name = format!("{suffix}.example");
            async move {
                let mut order = Order::new(
                    "default",
                    account_id,
                    testutil::dns_identifiers(&[&name]),
                    EXPIRES,
                    None,
                    None,
                );
                order.replaces = Some(cert_id.to_string());
                order.insert(&db).await.map(|()| order)
            }
        };

        claim("first").await.expect("the first claim is taken");

        let error = claim("second")
            .await
            .expect_err("a second live claim on one predecessor is refused");
        assert!(
            acme_proxy_store::sql::is_unique_violation_on(
                &error,
                "orders.replaces",
                "idx_orders_replaces_claim",
            ),
            "the refusal has to be recognisable as the replaces claim, or the \
             handler answers 500 instead of 409 alreadyReplaced: {error}"
        );
    });
}

/// An absent value keeps the type of the column it was bound to.
///
/// SQLite has no typed null. PostgreSQL sends a type OID with every parameter,
/// and a `None` bound as `bigint` against `accounts.eab_kid` is `column
/// "eab_kid" is of type uuid but expression is of type bigint` — which failed
/// every single `newAccount` until `Value::Null` started carrying its kind.
/// A fresh account leaves four nullable columns of three different types unset,
/// so storing and reading one back is the whole test.
#[tokio::test]
async fn an_account_with_every_nullable_column_unset_round_trips_on_both_backends() {
    use acme_proxy_store::account::Account;

    each_backend!(|db| {
        let (created, fresh) = Account::find_or_create(
            "default",
            &[7u8, 8, 9],
            vec![],
            &ClientContext::default(),
            &db,
        )
        .await
        .expect("an account with no optional column set should store");
        assert!(fresh, "the first call creates it");

        let read = Account::find_by_id("default", &created.id.to_string(), &db)
            .await
            .expect("the account should be readable")
            .expect("and present");

        assert_eq!(read.id, created.id);
        assert_eq!(read.pubkey, vec![7u8, 8, 9], "a blob survives as bytes");
        assert_eq!(read.eab_kid, None, "an unset uuid reads back as absent");
        assert_eq!(read.terms_of_service_agreed, None, "and an unset boolean");
        assert_eq!(read.created_ip, None, "and an unset text column");

        // `accounts` has no nullable integer left unset -- `last_seen_at` is
        // stamped at creation -- so the fourth type comes from an order, whose
        // `not_before`/`not_after` are absent unless the client asked for them.
        let order = order_with(&db, &["nulls.example"]).await;
        let read = Order::find_by_id(&order.id.to_string(), &db)
            .await
            .expect("the order should be readable")
            .expect("and present");
        assert_eq!(
            read.not_before, None,
            "an unset integer reads back as absent"
        );
        assert_eq!(read.not_after, None);
        assert_eq!(read.certificate, None);
    });
}

/// A paged listing pages the same way on both backends.
///
/// `LIMIT ?`/`OFFSET ?` are bound parameters, and the tie-break is
/// `created_at DESC, id DESC` over whole-second timestamps — so the ordering
/// rests on UUID v7 sorting the same way as bytes on one backend and as a
/// native `uuid` on the other. That is the assertion worth having here: if
/// PostgreSQL ordered `uuid` differently from SQLite's BLOB comparison, a row
/// could sit on two pages and never be seen.
#[tokio::test]
async fn paging_agrees_with_the_unpaged_total_on_both_backends() {
    each_backend!(|db| {
        for index in 0..7 {
            order_with(&db, &[&format!("page-{index}.example")]).await;
        }

        let page = |limit: i64, offset: i64| {
            let db = db.clone();
            async move {
                let query = OrderQuery {
                    limit,
                    offset,
                    ..Default::default()
                };
                Order::search(&query, &db).await.expect("search works")
            }
        };

        let (first, total) = page(3, 0).await;
        assert_eq!(total, 7, "the total ignores the page");
        assert_eq!(first.len(), 3);

        let (second, _) = page(3, 3).await;
        let (third, _) = page(3, 6).await;
        assert_eq!(third.len(), 1, "the last page is the remainder");

        let seen: Vec<_> = first
            .iter()
            .chain(&second)
            .chain(&third)
            .map(|order| order.id)
            .collect();
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            7,
            "no row may appear on two pages or on none: {seen:?}"
        );
    });
}

/// A job identity is held by one live row, and `ON CONFLICT DO NOTHING` says so
/// with `rows_affected() == 0` on both backends.
///
/// The index is partial — `WHERE status IN ('ready', 'running')` — so the
/// statement names no conflict target, which is what makes one spelling work
/// for both. A `DO NOTHING` that silently matched nothing would let two runners
/// hold one job.
#[tokio::test]
async fn a_job_identity_is_held_by_one_live_row_on_both_backends() {
    use acme_proxy_store::job::{Job, NewJob};

    each_backend!(|db| {
        let payload = serde_json::json!({});
        let spec = |id| NewJob {
            id,
            kind: "test_kind",
            dedup_key: "the-one-key",
            payload: &payload,
            run_at: 0,
            deadline: None,
            max_attempts: 3,
        };

        assert!(
            Job::enqueue(spec(acme_proxy_store::id::mint()), &db)
                .await
                .expect("the first enqueue works"),
            "the first job takes the identity"
        );
        assert!(
            !Job::enqueue(spec(acme_proxy_store::id::mint()), &db)
                .await
                .expect("the second enqueue is not an error"),
            "a live job already holds this (kind, dedup_key)"
        );

        assert_eq!(
            Job::count_live("test_kind", &db)
                .await
                .expect("counting works"),
            1
        );
    });
}

/// One client key registering twice is one account, on both backends.
///
/// `Account::is_pubkey_conflict` is the second matcher that reads a
/// constraint by name, and until now nothing exercised its PostgreSQL half:
/// the race that reaches it (`account::tests::concurrent_find_or_create…`) is
/// file-backed SQLite by construction, because it needs more than the one
/// connection `connect_in_memory` allows. If the name in
/// `migrations-postgres/` and the name in the matcher ever part company, the
/// recovery silently stops working and `newAccount` answers 500 to a client
/// that merely registered twice.
#[tokio::test]
async fn one_key_registering_twice_is_one_account_on_both_backends() {
    use acme_proxy_store::account::Account;

    each_backend!(|db| {
        let key = [9u8, 9, 9];
        let (first, created) =
            Account::find_or_create("default", &key, vec![], &ClientContext::default(), &db)
                .await
                .expect("the first registration works");
        assert!(created, "the first call creates the account");

        let (second, created) =
            Account::find_or_create("default", &key, vec![], &ClientContext::default(), &db)
                .await
                .expect("the second registration finds it");
        assert!(!created, "the second call finds the first account");
        assert_eq!(first.id, second.id);

        // And the raw violation is recognisable as *this* constraint, which is
        // what the recovery inside `find_or_create` rests on. Provoked with a
        // direct insert, since `find_or_create` is the thing that hides it.
        let error = acme_proxy_store::sql::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at) \
             VALUES (?, 'default', ?, '[]', 'valid', 0);",
        )
        .bind(acme_proxy_store::id::mint())
        .bind(&key[..])
        .execute(&db)
        .await
        .expect_err("a second row for one key is refused");
        assert!(
            acme_proxy_store::account::is_pubkey_conflict(&error),
            "the refusal has to be recognisable as the pubkey constraint, or a \
             repeat registration answers 500: {error}"
        );
    });
}

/// The declared widths, which PostgreSQL actually enforces.
///
/// `declared_token_widths_match_random_token` and its issuer twin read
/// `pragma_table_info` and so can only ever check SQLite — where the width is
/// decoration, since TEXT affinity enforces nothing. This is the same pin on
/// the backend where a wrong width is a rejected write: `nonces.value` was
/// `VARCHAR(36)` long after the nonce became a 43-character token, and on
/// PostgreSQL that would have refused every nonce the server mints.
#[tokio::test]
async fn the_declared_widths_are_enforced_on_postgres() {
    use acme_proxy_core::random::random_token;

    let Some(db) = testutil::postgres_database().await else {
        return;
    };

    let width = |table: &'static str, column: &'static str| {
        let db = db.exec();
        async move {
            acme_proxy_store::sql::query(
                // `::bigint` because `information_schema` answers `int4`, and
                // the seam decodes the one integer width the schema uses.
                "SELECT character_maximum_length::bigint FROM information_schema.columns \
                 WHERE table_name = ? AND column_name = ?;",
            )
            .bind(table)
            .bind(column)
            .fetch_one(db)
            .await
            .expect("the column should exist")
            .try_get::<i64>(0usize)
            .expect("a varchar declares a length")
        }
    };

    let token = i64::try_from(random_token().len()).expect("a token length fits");
    assert_eq!(width("nonces", "value").await, token);
    assert_eq!(width("challenges", "token").await, token);

    let issuer = i64::try_from(acme_proxy_core::cert::issuer_id(&[1, 2, 3]).len())
        .expect("an issuer id fits");
    assert_eq!(width("revocations", "issuer").await, issuer);
    assert_eq!(width("crls", "issuer").await, issuer);

    // The two deliberate non-uuid id columns, which `every_id_column_is_declared_a_blob`
    // names as exceptions on the SQLite side.
    assert_eq!(width("audit_log", "account_id").await, 36);
    assert_eq!(width("audit_log", "order_id").await, 36);
}

/// The guard on the guard.
///
/// Every test above skips on its own when there is no server, which means a CI
/// job whose PostgreSQL never started would report this whole file green while
/// running half of it. This one names the cause directly instead of leaving it
/// to be inferred from a suspiciously fast run.
#[tokio::test]
async fn postgres_is_available_when_it_is_required() {
    if std::env::var_os(testutil::REQUIRE_POSTGRES).is_none() {
        return;
    }
    assert!(
        testutil::postgres_database().await.is_some(),
        "{} is set but no PostgreSQL could be reached through {}",
        testutil::REQUIRE_POSTGRES,
        testutil::TEST_POSTGRES_URL,
    );
}
