//! Row fixtures shared by every crate's unit tests: identifiers, accounts,
//! orders (issued, or merely stamped as certified), and one of each admin,
//! audit, job and upstream row.
//!
//! Compiled only under `cfg(test)` or the `test-util` feature, which the other
//! crates of this workspace turn on through their `[dev-dependencies]` alone.

use acme_proxy_core::audit::ClientContext;

/// A list of `(type, value)` pairs as
/// [`Identifier`](acme_proxy_core::identifier::Identifier)s.
///
/// The `Identifier::dns`/`Identifier::new` constructors cover the single-name
/// case, which is most of them; this is the twelfth-copy problem's other half —
/// two modules had a verbatim `fn ids(&[(&str, &str)])` and several more built
/// the same `Vec` inline.
pub fn identifiers(pairs: &[(&str, &str)]) -> Vec<acme_proxy_core::identifier::Identifier> {
    pairs
        .iter()
        .map(|(typ, value)| acme_proxy_core::identifier::Identifier::new(*typ, *value))
        .collect()
}

/// The `dns`-only shorthand for [`identifiers`].
pub fn dns_identifiers(values: &[&str]) -> Vec<acme_proxy_core::identifier::Identifier> {
    values
        .iter()
        .map(|value| acme_proxy_core::identifier::Identifier::dns(*value))
        .collect()
}

/// An account in the `default` profile, returning its id.
///
/// Three modules had grown a verbatim copy of this (`admin::ops`,
/// `admin::render`, `crate::order`) — the same accumulation as `TempDir` and
/// the `Identifier` builders, and the reason both now live somewhere shared.
pub async fn account_id(database: &std::sync::Arc<crate::db::Database>) -> uuid::Uuid {
    let (account, _) = crate::account::Account::find_or_create(
        "default",
        &[1u8, 2, 3],
        vec![],
        &ClientContext::default(),
        database,
    )
    .await
    .expect("an in-memory database always accepts an account");
    account.id
}

/// A `ClientContext` carrying nothing but an address and its reverse name.
///
/// The three states a renderer has to tell apart (`ip (ptr)`, the address
/// alone, neither) are exactly the three ways this is called.
pub fn client_context(ip: Option<&str>, ptr: Option<&str>) -> ClientContext {
    ClientContext {
        ip: ip.map(str::to_string),
        ptr: ptr.map(str::to_string),
        ..ClientContext::default()
    }
}

/// An account created from `client`, whose traceability columns are therefore
/// whatever that context carried.
///
/// `pubkey` is a parameter because `find_or_create` dedupes on it: two calls
/// sharing one would hand back the *first* account, contexts and all.
pub async fn account_seen_from(
    pubkey: &[u8],
    client: &ClientContext,
    database: &std::sync::Arc<crate::db::Database>,
) -> crate::account::Account {
    crate::account::Account::find_or_create(
        "default",
        pubkey,
        vec!["mailto:a@example.com".to_string()],
        client,
        database,
    )
    .await
    .expect("an in-memory database always accepts an account")
    .0
}

/// An unsaved order in the `default` profile, in `status`.
pub fn order_fixture(
    account_id: uuid::Uuid,
    status: crate::status::OrderStatus,
) -> crate::order::Order {
    let mut order = crate::order::Order::new(
        "default",
        account_id,
        vec![acme_proxy_core::identifier::Identifier::dns("example.com")],
        0,
        None,
        None,
    );
    order.status = status;
    order
}

/// A *really issued* order on `profile`: signed by an in-memory local CA, so
/// the stored chain parses and the RFC 9773 certID the `replaces` signal rests
/// on can actually be derived from it.
///
/// Hoisted out of `notify::expiry`'s suite when the supersession annotation
/// moved to `admin::ops` — the digest's tests and the annotation's own both
/// need a row no hand-built fixture can stand in for. Distinct from
/// [`order_fixture`], which is an unsaved row with no certificate at all.
pub async fn issued_order(
    database: &crate::db::Database,
    profile: &str,
    account: uuid::Uuid,
    names: &[&str],
    not_after_days: i64,
) -> crate::order::Order {
    use crate::order::Order;
    use acme_proxy_core::identifier::Identifier;

    const DAY: i64 = 24 * 60 * 60;

    let mut order = Order::create(
        profile,
        account,
        names.iter().map(|name| Identifier::dns(*name)).collect(),
        crate::nonce::now_secs() + 3600,
        None,
        None,
        database,
    )
    .await
    .unwrap();
    // A throwaway CA signing one leaf, with rcgen directly rather than through
    // a signer backend: this fixture sits below the signers. The leaf carries
    // the Authority Key Identifier the RFC 9773 certID is derived from.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>())
            .unwrap();
    params.use_authority_key_identifier_extension = true;
    let leaf_cert = params.signed_by(&leaf_key, &issuer).unwrap();
    let chain = format!("{}{}", leaf_cert.pem(), ca_cert.pem());
    let leaf = acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap();
    let (serial, pubkey) = acme_proxy_core::cert::cert_serial_and_spki(&leaf).unwrap();
    order
        .finalize(
            chain,
            serial,
            pubkey,
            Some(crate::nonce::now_secs() + not_after_days * DAY),
            database,
        )
        .await
        .unwrap();
    order
}

/// An order under `account` holding a certificate that expires at `not_after`
/// (`None`: never stamped), without signing anything.
///
/// For the delete guard's tests, which ask only whether a row counts as a
/// *live* certificate — issued, not revoked, not expired — and never parse the
/// chain. [`issued_order`] is the one to reach for when the chain has to be
/// real.
pub async fn certified_order(
    database: &crate::db::Database,
    account: uuid::Uuid,
    not_after: Option<i64>,
) -> crate::order::Order {
    let mut order = crate::order::Order::create(
        "default",
        account,
        vec![acme_proxy_core::identifier::Identifier::dns("example.com")],
        crate::nonce::now_secs() + 3600,
        None,
        None,
        database,
    )
    .await
    .unwrap();
    order
        .finalize(
            "-----BEGIN CERTIFICATE-----\n...".to_string(),
            order.id.simple().to_string(),
            vec![1],
            not_after,
            database,
        )
        .await
        .unwrap();
    order
}

/// One `certificate_issued` row with every optional column filled in, so a
/// renderer test can blank the ones it wants absent.
pub fn audit_entry() -> crate::audit::AuditEntry {
    crate::audit::AuditEntry {
        id: 41_812,
        created_at: 1_700_000_000,
        event: "certificate_issued".to_string(),
        outcome: "success".to_string(),
        profile: "le".to_string(),
        actor_kind: "acme".to_string(),
        actor_id: Some("acct-1".to_string()),
        account_id: Some("acct-1".to_string()),
        order_id: Some("order-1".to_string()),
        cert_serial: Some("0a0b".to_string()),
        identifiers: vec!["a.example.com".to_string(), "b.example.com".to_string()],
        client_ip: Some("203.0.113.7".to_string()),
        client_ptr: Some("host.example.com".to_string()),
        user_agent: Some("certbot/2.9.0".to_string()),
        request_id: Some("req-1".to_string()),
        reason: None,
        detail: None,
    }
}

/// One `signer_relay_issue` job with every optional column filled, so a
/// renderer test can blank the ones it wants absent — the [`audit_entry`]
/// shape. `#[cfg(test)]` and pure: no database.
pub fn job_fixture() -> crate::job::Job {
    crate::job::Job {
        id: uuid::uuid!("00000000-0000-7000-8000-00000000abcd"),
        kind: "signer_relay_issue".to_string(),
        dedup_key: "order-1".to_string(),
        payload: serde_json::json!({ "order_id": "order-1", "profile": "le" }),
        status: "failed".to_string(),
        run_at: 1_700_000_000,
        attempts: 3,
        max_attempts: 5,
        deadline: Some(1_700_600_000),
        lease_until: Some(1_700_000_300),
        lease_owner: Some("runner-1".to_string()),
        last_error: Some("upstream said no".to_string()),
        created_at: 1_699_990_000,
        updated_at: 1_700_000_100,
    }
}

/// One `invalid` `upstream_orders` row joined to its local order, every
/// optional filled. `#[cfg(test)]` and pure.
pub fn upstream_order_row_fixture() -> crate::upstream_order::UpstreamOrderRow {
    crate::upstream_order::UpstreamOrderRow {
        order_id: uuid::uuid!("00000000-0000-7000-8000-00000000ee01"),
        upstream_order_url: "https://acme.example/order/9".to_string(),
        upstream_finalize_url: Some("https://acme.example/order/9/finalize".to_string()),
        upstream_certificate_url: Some("https://acme.example/cert/9".to_string()),
        status: "invalid".to_string(),
        error: Some("urn:ietf:params:acme:error:rejectedIdentifier".to_string()),
        created_at: 1_699_990_000,
        updated_at: 1_700_000_100,
        client_ip: Some("203.0.113.7".to_string()),
        client_ptr: Some("host.example.com".to_string()),
        user_agent: Some("lego/4".to_string()),
        request_id: Some("req-9".to_string()),
        profile: "le".to_string(),
        account_id: uuid::uuid!("00000000-0000-7000-8000-0000000acc01"),
        identifiers: vec![acme_proxy_core::identifier::Identifier::dns(
            "a.example.com",
        )],
        local_status: crate::status::OrderStatus::Processing,
        local_expires: 1_700_600_000,
    }
}

/// An `active` operator with no second factor and no login yet.
///
/// The id both admin fixtures carry, so the session keeps naming its user.
pub const ADMIN_FIXTURE_ID: uuid::Uuid = uuid::uuid!("11111111-2222-3333-4444-555555555555");

/// The `password_hash` is a syntactically valid stored hash rather than a
/// placeholder, because more than one test asserts `pbkdf2` never reaches a
/// terminal and a fake would pass that vacuously.
pub fn admin_user_fixture() -> crate::admin_user::AdminUser {
    crate::admin_user::AdminUser {
        id: ADMIN_FIXTURE_ID,
        username: "alice".to_string(),
        password_hash: "pbkdf2-sha256$600000$c2FsdA$aGFzaA".to_string(),
        status: "active".to_string(),
        role: None,
        totp_secret: None,
        totp_pending_secret: None,
        totp_last_step: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        last_login_at: None,
        contact_email: None,
        known_login_ips: Vec::new(),
    }
}

/// An `active` session for [`admin_user_fixture`].
pub fn admin_session_fixture() -> crate::admin_session::AdminSession {
    crate::admin_session::AdminSession {
        token_hash: "0123456789abcdef0123456789abcdef".to_string(),
        user_id: ADMIN_FIXTURE_ID,
        csrf_token: "the-csrf-token".to_string(),
        state: "active".to_string(),
        mfa_attempts: 0,
        created_at: 1_700_000_000,
        expires_at: 1_700_043_200,
        last_seen_at: 1_700_000_000,
        created_ip: Some("192.0.2.1".to_string()),
        user_agent: Some("curl/8".to_string()),
    }
}

/// The base URL of a PostgreSQL the test suite may create schemas in.
///
/// Unset on a developer machine, where the dialect-sensitive suites skip. CI's
/// `postgres` job sets it, and [`REQUIRE_POSTGRES`] beside it.
pub const TEST_POSTGRES_URL: &str = "TEST_POSTGRES_URL";

/// Turns a skip into a failure.
///
/// Without it, a service that failed to start, a renamed image or a firewall
/// rule turns every PostgreSQL test green while running none of them, and
/// nothing else would notice — these suites are about a backend the coverage
/// floor cannot see. The `ACME_PROXY_REQUIRE_SOFTHSM` treatment, for the same
/// reason.
pub const REQUIRE_POSTGRES: &str = "ACME_PROXY_REQUIRE_POSTGRES";

/// A PostgreSQL database with the schema applied, or `None` to skip.
///
/// Each call gets a **schema of its own**, named from a UUID v7 so the tests
/// can run concurrently in one database without a `DROP` in one emptying
/// another. The pool pins `search_path` to it, so every unqualified name in the
/// migration set and in every query lands there.
///
/// Schemas left behind by an earlier run are swept on the way in, by the
/// timestamp their own name carries. Dropping at the end of a test would need
/// async work in `Drop`; sweeping on entry costs one statement and survives a
/// test that panicked, which is exactly when the schema would otherwise leak.
///
/// # Panics
///
/// When [`REQUIRE_POSTGRES`] is set and there is no server to talk to.
pub async fn postgres_database() -> Option<crate::db::Database> {
    let base = match std::env::var(TEST_POSTGRES_URL) {
        Ok(url) if !url.is_empty() => url,
        _ => {
            assert!(
                std::env::var_os(REQUIRE_POSTGRES).is_none(),
                "{REQUIRE_POSTGRES} is set, so skipping is a failure: {TEST_POSTGRES_URL} \
                 is unset or empty. These tests were about to report green without \
                 running against PostgreSQL at all."
            );
            eprintln!(
                "skipping: {TEST_POSTGRES_URL} is unset; start a PostgreSQL and set it to \
                 run the dialect tests"
            );
            return None;
        }
    };

    let schema = format!("acme_test_{}", crate::id::mint().simple());
    let admin = crate::db::Database::open(&base)
        .await
        .expect("TEST_POSTGRES_URL should name a reachable PostgreSQL");

    sweep_stale_schemas(&admin).await;
    crate::sql::query(format!("CREATE SCHEMA {schema};"))
        .execute(&admin)
        .await
        .expect("a test schema should be creatable");
    admin.close().await;

    let separator = if base.contains('?') { '&' } else { '?' };
    let database = crate::db::Database::open(&format!(
        "{base}{separator}options=-c%20search_path%3D{schema}"
    ))
    .await
    .expect("the schema-scoped pool should open");
    database
        .migrate()
        .await
        .expect("the PostgreSQL migration set should apply");
    Some(database)
}

/// Drops test schemas from earlier runs, by the timestamp in their own name.
///
/// Best effort: a failure here is somebody else's schema or a permission this
/// role does not have, neither of which should fail the test that asked.
async fn sweep_stale_schemas(admin: &crate::db::Database) {
    const STALE_AFTER_MS: u64 = 60 * 60 * 1000;

    let Ok(rows) = crate::sql::query(
        "SELECT schema_name FROM information_schema.schemata \
         WHERE schema_name LIKE 'acme_test_%';",
    )
    .fetch_all(admin)
    .await
    else {
        return;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    for row in rows {
        let Ok(name) = row.try_get::<String>("schema_name") else {
            continue;
        };
        // The suffix is a UUID v7 whose leading 48 bits are a millisecond
        // timestamp, which is what makes "how old is this schema?" answerable
        // from the name alone.
        let Some(minted) = name
            .strip_prefix("acme_test_")
            .and_then(|hex| uuid::Uuid::try_parse(hex).ok())
            .and_then(|id| id.get_timestamp())
            .map(|ts| {
                let (secs, nanos) = ts.to_unix();
                secs * 1000 + u64::from(nanos) / 1_000_000
            })
        else {
            continue;
        };
        if now.saturating_sub(minted) > STALE_AFTER_MS {
            let _ = crate::sql::query(format!("DROP SCHEMA IF EXISTS {name} CASCADE;"))
                .execute(admin)
                .await;
        }
    }
}
