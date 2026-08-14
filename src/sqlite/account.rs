use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use tracing::{debug, info};
use uuid::Uuid;

use crate::audit::ClientContext;
use crate::sqlite::db::Database;
use crate::sqlite::nonce::now_secs;

/// An ACME account (RFC 8555 §7.1.2), keyed by the client's public key stored as
/// DER SPKI. `contact` is persisted as a JSON array of strings.
///
/// ## ACME Protocol Compliance
///
/// This struct represents the account object as defined in RFC 8555:
/// - `id`: Unique identifier for the account (UUID)
/// - `pubkey`: DER-encoded SPKI public key used for authentication
/// - `contact`: Array of contact URIs (email, etc.) for the account holder
/// - `status`: Account status (valid, deactivated, etc.)
/// - `created_at`: Timestamp when the account was created
///
/// ## Storage Details
///
/// - The public key is stored in DER SPKI format for consistent hashing and lookup
/// - Contact information is serialized as JSON for flexible storage
/// - The ID is generated as a UUID v4 for uniqueness
/// - Status is tracked to support account lifecycle management
///
/// ## Methods
///
/// - `find_by_pubkey`: Lookup account by public key
/// - `find_by_id`: Lookup account by ID
/// - `find_or_create`: Create new account or return existing one (RFC 8555 §7.3)
/// - `list_all`: List every account, oldest first (admin CLI)
/// - `delete`: Hard-delete an account, cascading to its orders (admin CLI)
/// - `to_json`: Convert to RFC 8555 account JSON object format
#[derive(Debug)]
pub struct Account {
    pub id: String,
    /// The ACME endpoint (`[profiles.<name>]`) this account was registered at.
    /// Accounts are keyed by `(profile, pubkey)`, so the same client key at two
    /// endpoints is two accounts — see the schema comment in
    /// `migrations/20260722210000_add_accounts.sql` for why that is a security
    /// property and not just tidiness.
    pub profile: String,
    pub pubkey: Vec<u8>,
    pub contact: Vec<String>,
    pub status: String,
    pub created_at: i64,
    /// Which EAB credential (if any) created this account -- an audit trail
    /// only, set once and never overwritten. See [`Account::set_eab_kid`].
    pub eab_kid: Option<String>,
    /// Whether this account agreed to the terms of service when it was created
    /// (RFC 8555 §7.3.3). `None` for an account created at an endpoint that
    /// advertised none — which is not the same as "declined", and renders as an
    /// absent member rather than `false`. Set once, at creation; see
    /// [`Account::set_terms_agreed`].
    pub terms_of_service_agreed: Option<bool>,
    /// Where `newAccount` was called from, and the reverse name that address
    /// had at the time. Traceability only — see the schema comment in
    /// `migrations/20260722210000_add_accounts.sql` for why nothing ever
    /// compares against these.
    pub created_ip: Option<String>,
    pub created_ptr: Option<String>,
    /// When this key last authenticated a request, and from where. Advanced by
    /// [`Account::touch`] under the [`ACCOUNT_TOUCH_INTERVAL`] throttle.
    pub last_seen_at: Option<i64>,
    pub last_seen_ip: Option<String>,
    pub last_seen_ptr: Option<String>,
}

/// How often `last_seen_*` is allowed to cost a write, in seconds.
///
/// Every ACME POST already writes a nonce row; an unthrottled `UPDATE` here
/// would double that on the POST-as-GET polling that dominates a real
/// deployment, for a field whose whole precision requirement is "roughly when".
/// The web admin's `SESSION_TOUCH_INTERVAL` is the same trade at the same
/// interval, made for the same reason.
///
/// [`Account::needs_touch`] overrides it when the *address* changed, which is
/// the one case a minute of staleness would hide the interesting thing.
pub const ACCOUNT_TOUCH_INTERVAL: i64 = 60;

/// A short, stable fingerprint of a public key, for correlating log lines.
///
/// The field this feeds used to be `hex::encode(pubkey)` — the *entire* key, so
/// a log line for an RSA account carried ~700 hex characters, and the name said
/// "hash" while the value was the key itself. Public keys are not secret, but
/// they are not log material either.
pub(crate) fn pubkey_fingerprint(pubkey: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, pubkey);
    hex::encode(&digest.as_ref()[..8])
}

impl Account {
    fn from_row(row: SqliteRow) -> Result<Self, sqlx::Error> {
        let contact_json: String = row.try_get("contact")?;
        let contact: Vec<String> =
            serde_json::from_str(&contact_json).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Account {
            id: row.try_get("id")?,
            profile: row.try_get("profile")?,
            pubkey: row.try_get("pubkey")?,
            contact,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            eab_kid: row.try_get("eab_kid")?,
            terms_of_service_agreed: row.try_get("terms_of_service_agreed")?,
            created_ip: row.try_get("created_ip")?,
            created_ptr: row.try_get("created_ptr")?,
            last_seen_at: row.try_get("last_seen_at")?,
            last_seen_ip: row.try_get("last_seen_ip")?,
            last_seen_ptr: row.try_get("last_seen_ptr")?,
        })
    }

    #[tracing::instrument(name = "Account::find_by_pubkey", skip(pubkey, database))]
    pub async fn find_by_pubkey(
        profile: &str,
        pubkey: &[u8],
        database: &Database,
    ) -> Result<Option<Account>, sqlx::Error> {
        debug!(event = "db_account_find_by_pubkey_started", outcome = "progress", profile = %profile, pubkey_fp = %pubkey_fingerprint(pubkey));
        let row = sqlx::query(
            "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, terms_of_service_agreed, created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts WHERE profile = ? AND pubkey = ?;",
        )
        .bind(profile)
        .bind(pubkey)
        .fetch_optional(&database.pool)
        .await?;

        let result = row.map(Account::from_row).transpose()?;
        if let Some(ref account) = result {
            debug!(event = "db_account_found_by_pubkey", outcome = "success", account_id = %account.id, pubkey_fp = %pubkey_fingerprint(pubkey));
        } else {
            debug!(event = "db_account_not_found_by_pubkey", outcome = "failure", pubkey_fp = %pubkey_fingerprint(pubkey));
        }
        Ok(result)
    }

    /// Looks an account up by id **within one profile**. An id is a UUID and
    /// therefore globally unique, so the `profile` predicate is not about
    /// finding the row: it is what makes an account URL minted at one endpoint
    /// unusable as a `kid` at another.
    #[tracing::instrument(name = "Account::find_by_id", skip(database), fields(account_id = %id))]
    pub async fn find_by_id(
        profile: &str,
        id: &str,
        database: &Database,
    ) -> Result<Option<Account>, sqlx::Error> {
        debug!(event = "db_account_find_by_id_started", outcome = "progress", profile = %profile, account_id = %id);
        let row = sqlx::query(
            "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, terms_of_service_agreed, created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts WHERE profile = ? AND id = ?;",
        )
        .bind(profile)
        .bind(id)
        .fetch_optional(&database.pool)
        .await?;

        let result = row.map(Account::from_row).transpose()?;
        if let Some(ref account) = result {
            debug!(event = "db_account_found_by_id", outcome = "success", account_id = %account.id);
        } else {
            debug!(event = "db_account_not_found_by_id", outcome = "failure", account_id = %id);
        }
        Ok(result)
    }

    /// Looks up the account for `pubkey`, creating it if absent. Returns the
    /// account and whether it was newly created — RFC 8555 §7.3 find-or-create,
    /// where a repeated key returns the existing account rather than a duplicate.
    ///
    /// `client` is stamped onto the row **only on the creating branch**: the
    /// `created_*` columns mean "where this account was registered from", so a
    /// later `newAccount` from elsewhere returning the same account must not
    /// rewrite them. Where the key was last *used* from is `last_seen_*`, which
    /// [`Account::touch`] keeps up to date.
    #[tracing::instrument(name = "Account::find_or_create", skip(pubkey, client, database))]
    pub async fn find_or_create(
        profile: &str,
        pubkey: &[u8],
        contact: Vec<String>,
        client: &ClientContext,
        database: &Database,
    ) -> Result<(Account, bool), sqlx::Error> {
        debug!(event = "db_account_find_or_create_started", outcome = "progress", profile = %profile, pubkey_fp = %pubkey_fingerprint(pubkey));
        if let Some(account) = Account::find_by_pubkey(profile, pubkey, database).await? {
            debug!(event = "db_account_found_existing", outcome = "success", account_id = %account.id, pubkey_fp = %pubkey_fingerprint(pubkey));
            return Ok((account, false));
        }

        let account = Account {
            id: Uuid::new_v4().to_string(),
            profile: profile.to_string(),
            pubkey: pubkey.to_vec(),
            contact,
            status: "valid".to_string(),
            created_at: now_secs(),
            eab_kid: None,
            terms_of_service_agreed: None,
            created_ip: client.ip.clone(),
            created_ptr: client.ptr.clone(),
            // A brand-new account has been seen exactly once, right now, from
            // here. Seeding these rather than leaving them NULL until the next
            // request means "never used since registration" reads as a
            // `last_seen_at` equal to `created_at`, not as a missing field a
            // renderer has to special-case.
            last_seen_at: Some(now_secs()),
            last_seen_ip: client.ip.clone(),
            last_seen_ptr: client.ptr.clone(),
        };

        // `contact` is a `Vec<String>`, so serialization is infallible.
        let contact_json = Value::from(account.contact.clone()).to_string();

        debug!(event = "db_account_create_started", outcome = "progress", account_id = %account.id);
        sqlx::query(
            "INSERT INTO accounts (id, profile, pubkey, contact, status, created_at, created_ip, \
             created_ptr, last_seen_at, last_seen_ip, last_seen_ptr) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        )
        .bind(&account.id)
        .bind(&account.profile)
        .bind(&account.pubkey)
        .bind(contact_json)
        .bind(&account.status)
        .bind(account.created_at)
        .bind(&account.created_ip)
        .bind(&account.created_ptr)
        .bind(account.last_seen_at)
        .bind(&account.last_seen_ip)
        .bind(&account.last_seen_ptr)
        .execute(&database.pool)
        .await?;

        debug!(event = "db_account_created", outcome = "success", account_id = %account.id, pubkey_fp = %pubkey_fingerprint(pubkey));
        Ok((account, true))
    }

    /// Whether [`Account::touch`] is worth a write at `now`, for a request
    /// arriving from `ip`.
    ///
    /// Two ways to say yes, and the second is the point of the method existing:
    ///
    /// - [`ACCOUNT_TOUCH_INTERVAL`] has elapsed (or nothing was ever recorded);
    /// - **the address differs from the last one recorded**, whatever the
    ///   interval says. A key that moves is the single most interesting thing
    ///   these columns can show, and a throttle that swallowed the move for a
    ///   minute would hide exactly the requests worth seeing — a stolen account
    ///   key being used from somewhere new arrives as a burst, not a trickle.
    ///
    /// A pure function of the row and its arguments, so the policy is testable
    /// without an HTTP request, and it lives beside the columns it governs
    /// rather than in the extractor that calls it.
    #[must_use]
    pub fn needs_touch(&self, now: i64, ip: Option<&str>) -> bool {
        match self.last_seen_at {
            None => true,
            Some(last) => {
                now.saturating_sub(last) >= ACCOUNT_TOUCH_INTERVAL
                    || self.last_seen_ip.as_deref() != ip
            }
        }
    }

    /// Records that this key just authenticated a request, from `client`.
    ///
    /// Called only when [`Account::needs_touch`] said so — which is also why
    /// the reverse lookup belongs to the caller: resolving a PTR record for a
    /// write that is about to be skipped would be the cost the throttle exists
    /// to avoid. Keeps the in-memory fields in sync, so a `to_json` in the same
    /// request reflects it without a re-read.
    #[tracing::instrument(name = "Account::touch", skip(self, client, database), fields(account_id = %self.id))]
    pub async fn touch(
        &mut self,
        client: &ClientContext,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        let now = now_secs();
        sqlx::query(
            "UPDATE accounts SET last_seen_at = ?, last_seen_ip = ?, last_seen_ptr = ? \
             WHERE id = ?;",
        )
        .bind(now)
        .bind(&client.ip)
        .bind(&client.ptr)
        .bind(&self.id)
        .execute(&database.pool)
        .await?;

        self.last_seen_at = Some(now);
        self.last_seen_ip = client.ip.clone();
        self.last_seen_ptr = client.ptr.clone();
        debug!(event = "db_account_touched", outcome = "success", account_id = %self.id);
        Ok(())
    }

    /// Replaces the account's contact list (RFC 8555 §7.3.2 account update). The
    /// in-memory `self.contact` is kept in sync so a subsequent `to_json`
    /// reflects the change without a re-read.
    #[tracing::instrument(name = "Account::update_contact", skip(self, database), fields(account_id = %self.id))]
    pub async fn update_contact(
        &mut self,
        contact: Vec<String>,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "db_account_contact_update_started", outcome = "progress", account_id = %self.id);
        // `contact` is a `Vec<String>`, so serialization is infallible.
        let contact_json = Value::from(contact.clone()).to_string();

        sqlx::query("UPDATE accounts SET contact = ? WHERE id = ?;")
            .bind(contact_json)
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.contact = contact;
        debug!(event = "db_account_contact_updated", outcome = "success", account_id = %self.id);
        Ok(())
    }

    /// Deactivates the account (RFC 8555 §7.3.6): sets `status` to `deactivated`,
    /// a terminal state. Keeps `self.status` in sync.
    #[tracing::instrument(name = "Account::deactivate", skip(self, database), fields(account_id = %self.id))]
    pub async fn deactivate(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_account_deactivation_started", outcome = "progress", account_id = %self.id);
        sqlx::query("UPDATE accounts SET status = 'deactivated' WHERE id = ?;")
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.status = "deactivated".to_string();
        debug!(event = "db_account_deactivated", outcome = "success", account_id = %self.id);
        Ok(())
    }

    /// Replaces the account's key (RFC 8555 §7.3.5 account key rollover).
    /// `pubkey` is DER SPKI, the same form every other lookup keys accounts
    /// by. `pubkey` is `UNIQUE`, a backstop against the rare race the
    /// caller's own pre-check (`Account::find_by_pubkey`) cannot fully close;
    /// a violation here surfaces as a plain `sqlx::Error`.
    pub async fn update_pubkey(
        &mut self,
        pubkey: &[u8],
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "db_account_pubkey_update_started", outcome = "progress", account_id = ?self.id);
        sqlx::query("UPDATE accounts SET pubkey = ? WHERE id = ?;")
            .bind(pubkey)
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.pubkey = pubkey.to_vec();
        info!(event = "db_account_pubkey_updated", outcome = "success", account_id = ?self.id);
        Ok(())
    }

    /// Records which EAB credential created this account -- an audit trail
    /// only (see the migration comment). Called once, right after
    /// `Account::find_or_create` reports a freshly created row
    /// (`post_new_account` in `lib.rs`): **never** overwritten afterwards, so
    /// re-registering under an existing key does not change what is recorded,
    /// even if a different (still valid) EAB credential is presented that time.
    pub async fn set_eab_kid(
        &mut self,
        eab_kid: &str,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        debug!(event = "db_account_eab_kid_set_started", outcome = "progress", account_id = ?self.id, eab_kid = ?eab_kid);
        sqlx::query("UPDATE accounts SET eab_kid = ? WHERE id = ?;")
            .bind(eab_kid)
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.eab_kid = Some(eab_kid.to_string());
        info!(event = "db_account_eab_kid_set", outcome = "success", account_id = ?self.id, eab_kid = ?eab_kid);
        Ok(())
    }

    /// Records that this account agreed to the terms of service
    /// (RFC 8555 §7.3.3).
    ///
    /// Same lifecycle as [`Account::set_eab_kid`]: called once, right after
    /// `find_or_create` reports a freshly created row, and never overwritten —
    /// re-registering under an existing key does not restate the agreement,
    /// and a ToS added to the configuration later does not retroactively make
    /// old accounts look like they accepted it.
    pub async fn set_terms_agreed(&mut self, database: &Database) -> Result<(), sqlx::Error> {
        debug!(event = "db_account_terms_agreed_started", outcome = "progress", account_id = ?self.id);
        sqlx::query("UPDATE accounts SET terms_of_service_agreed = 1 WHERE id = ?;")
            .bind(&self.id)
            .execute(&database.pool)
            .await?;

        self.terms_of_service_agreed = Some(true);
        info!(event = "db_account_terms_agreed", outcome = "success", account_id = ?self.id);
        Ok(())
    }

    /// Looks an account up by id across **every** profile — for the admin CLI,
    /// where an operator holds an id and not necessarily the endpoint it came
    /// from. Ids are UUIDs, so this is unambiguous.
    ///
    /// Never use it on a request path: profile scoping is what keeps an account
    /// URL minted at one endpoint from being accepted at another.
    pub async fn find_any_by_id(
        id: &str,
        database: &Database,
    ) -> Result<Option<Account>, sqlx::Error> {
        debug!(event = "db_account_find_any_by_id_started", outcome = "progress", account_id = %id);
        let row = sqlx::query(
            "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, terms_of_service_agreed, created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts WHERE id = ?;",
        )
        .bind(id)
        .fetch_optional(&database.pool)
        .await?;

        row.map(Account::from_row).transpose()
    }

    /// Lists accounts, oldest first — the admin CLI's listing. `profile` filters
    /// to one endpoint; `None` lists every account of every profile, which is
    /// what an operator asking "what is on this server?" wants.
    pub async fn list_all(
        profile: Option<&str>,
        database: &Database,
    ) -> Result<Vec<Account>, sqlx::Error> {
        debug!(event = "db_account_list_all_started", outcome = "progress", profile = ?profile);
        let rows = match profile {
            Some(profile) => sqlx::query(
                "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, terms_of_service_agreed, created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts WHERE profile = ? ORDER BY created_at ASC;",
            )
            .bind(profile)
            .fetch_all(&database.pool)
            .await?,
            None => sqlx::query(
                "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, terms_of_service_agreed, created_ip, created_ptr, last_seen_at, last_seen_ip, last_seen_ptr FROM accounts ORDER BY created_at ASC;",
            )
            .fetch_all(&database.pool)
            .await?,
        };

        rows.into_iter().map(Account::from_row).collect()
    }

    /// One page of accounts, newest first, plus the total the same filter
    /// matches unpaged.
    ///
    /// The [`Account`] counterpart to [`crate::sqlite::order::Order::search`],
    /// and additive for the same reason: [`Account::list_all`] stays as it is
    /// for the admin CLI, which wants everything.
    ///
    /// Two literal statements per branch rather than a builder: with one
    /// optional filter there are only two shapes, and `sqlx::query`'s
    /// `&'static str` bound is a guarantee worth keeping where it is free.
    pub async fn search(
        profile: Option<&str>,
        limit: i64,
        offset: i64,
        database: &Database,
    ) -> Result<(Vec<Account>, i64), sqlx::Error> {
        debug!(event = "db_account_search_started", outcome = "progress", profile = ?profile, limit = limit, offset = offset);

        // `id` breaks the `created_at` tie for the same reason it does for
        // orders: whole-second timestamps would otherwise let two rows swap
        // between pages, and one of them would never be seen.
        let (rows, total) = match profile {
            Some(profile) => {
                let rows = sqlx::query(
                    "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, \
                     terms_of_service_agreed, created_ip, created_ptr, last_seen_at, \
                     last_seen_ip, last_seen_ptr FROM accounts WHERE profile = ? \
                     ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?;",
                )
                .bind(profile)
                .bind(limit)
                .bind(offset)
                .fetch_all(&database.pool)
                .await?;
                let total: i64 = sqlx::query("SELECT COUNT(*) FROM accounts WHERE profile = ?;")
                    .bind(profile)
                    .fetch_one(&database.pool)
                    .await?
                    .try_get(0)?;
                (rows, total)
            }
            None => {
                let rows = sqlx::query(
                    "SELECT id, profile, pubkey, contact, status, created_at, eab_kid, \
                     terms_of_service_agreed, created_ip, created_ptr, last_seen_at, \
                     last_seen_ip, last_seen_ptr FROM accounts \
                     ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?;",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&database.pool)
                .await?;
                let total: i64 = sqlx::query("SELECT COUNT(*) FROM accounts;")
                    .fetch_one(&database.pool)
                    .await?
                    .try_get(0)?;
                (rows, total)
            }
        };

        let accounts = rows
            .into_iter()
            .map(Account::from_row)
            .collect::<Result<_, _>>()?;
        Ok((accounts, total))
    }

    /// Hard-deletes the account row — cascading, via `ON DELETE CASCADE`, to
    /// its orders, authorizations and challenges. Returns whether a row
    /// existed to delete, so the caller can distinguish "gone" from "never
    /// there".
    pub async fn delete(id: &str, database: &Database) -> Result<bool, sqlx::Error> {
        debug!(event = "db_account_delete_started", outcome = "progress", account_id = ?id);
        let result = sqlx::query("DELETE FROM accounts WHERE id = ?;")
            .bind(id)
            .execute(&database.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            info!(event = "db_account_deleted", outcome = "success", account_id = ?id);
        } else {
            debug!(event = "db_account_delete_missing", outcome = "success", account_id = ?id);
        }
        Ok(deleted)
    }

    /// The RFC 8555 account object: `status`, optional `contact`, and the
    /// `orders` list URL (derived from the public `base_url`).
    #[must_use]
    pub fn to_json(&self, base_url: &str) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("status".to_string(), Value::String(self.status.clone()));
        if !self.contact.is_empty() {
            object.insert("contact".to_string(), Value::from(self.contact.clone()));
        }
        object.insert(
            "orders".to_string(),
            Value::String(format!("{base_url}/acct/{}/orders", self.id)),
        );
        // RFC 8555 §7.1.2, optional: reflected only when it was actually
        // recorded, so an account created at an endpoint with no terms of
        // service says nothing rather than claiming to have declined.
        if let Some(agreed) = self.terms_of_service_agreed {
            object.insert("termsOfServiceAgreed".to_string(), Value::Bool(agreed));
        }
        Value::Object(object)
    }
}

#[cfg(test)]
mod tests {

    /// The throttle's whole decision table. The second arm is the one worth
    /// having: an account key that starts arriving from a new address is the
    /// single most interesting thing these columns can show, and a minute of
    /// staleness would hide exactly that.
    #[test]
    fn needs_touch_yields_to_the_interval_but_never_to_a_changed_address() {
        let mut account = Account {
            id: "a".to_string(),
            profile: "default".to_string(),
            pubkey: vec![1],
            contact: vec![],
            status: "valid".to_string(),
            created_at: 0,
            eab_kid: None,
            terms_of_service_agreed: None,
            created_ip: None,
            created_ptr: None,
            last_seen_at: None,
            last_seen_ip: None,
            last_seen_ptr: None,
        };

        // Never seen: always worth a write.
        assert!(account.needs_touch(1_000, Some("203.0.113.7")));

        account.last_seen_at = Some(1_000);
        account.last_seen_ip = Some("203.0.113.7".to_string());

        // Same address, inside the window: skipped.
        assert!(!account.needs_touch(1_000, Some("203.0.113.7")));
        assert!(!account.needs_touch(1_000 + ACCOUNT_TOUCH_INTERVAL - 1, Some("203.0.113.7")));
        // Same address, at the boundary: written.
        assert!(account.needs_touch(1_000 + ACCOUNT_TOUCH_INTERVAL, Some("203.0.113.7")));
        // A different address beats the interval outright.
        assert!(account.needs_touch(1_000, Some("198.51.100.4")));
        // Including losing one entirely, which is not "absent from deny,
        // therefore unchanged".
        assert!(account.needs_touch(1_000, None));

        // And a clock that went backwards must not underflow into a write per
        // request; `saturating_sub` keeps the answer "not yet".
        assert!(!account.needs_touch(0, Some("203.0.113.7")));
    }

    /// `created_*` mean "where this account was registered from" and must not
    /// be rewritten by a later `newAccount` for the same key; `last_seen_*`
    /// are what move.
    #[tokio::test]
    async fn creation_stamps_the_address_once_and_touch_moves_only_the_last_seen_columns() {
        let db = Database::connect_in_memory().await.unwrap();
        let first = ClientContext {
            ip: Some("203.0.113.7".to_string()),
            ptr: Some("first.example.com".to_string()),
            user_agent: Some("certbot".to_string()),
            request_id: Some("req-1".to_string()),
        };
        let (created, is_new) = Account::find_or_create("default", &[42u8], vec![], &first, &db)
            .await
            .unwrap();
        assert!(is_new);
        assert_eq!(created.created_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(created.created_ptr.as_deref(), Some("first.example.com"));
        // Seeded rather than left NULL: "never used since registration" reads
        // as a `last_seen_at` equal to `created_at`, not a missing field.
        assert_eq!(created.last_seen_ip.as_deref(), Some("203.0.113.7"));
        assert!(created.last_seen_at.is_some());

        // The same key arriving from somewhere else finds the account and
        // leaves the creation columns exactly as they were.
        let second = ClientContext {
            ip: Some("198.51.100.4".to_string()),
            ptr: Some("second.example.com".to_string()),
            ..ClientContext::default()
        };
        let (mut found, is_new) = Account::find_or_create("default", &[42u8], vec![], &second, &db)
            .await
            .unwrap();
        assert!(!is_new);
        assert_eq!(found.created_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(found.created_ptr.as_deref(), Some("first.example.com"));

        found.touch(&second, &db).await.unwrap();
        // In memory...
        assert_eq!(found.last_seen_ip.as_deref(), Some("198.51.100.4"));
        assert_eq!(found.last_seen_ptr.as_deref(), Some("second.example.com"));
        // ...and on disk, with the creation columns untouched.
        let reloaded = Account::find_by_id("default", &found.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.created_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(reloaded.last_seen_ip.as_deref(), Some("198.51.100.4"));
        assert_eq!(
            reloaded.last_seen_ptr.as_deref(),
            Some("second.example.com")
        );
        assert!(reloaded.last_seen_at >= reloaded.created_at.into());

        // A client with no resolvable name clears the stale one rather than
        // leaving a name that no longer describes the address on the row.
        let nameless = ClientContext {
            ip: Some("198.51.100.4".to_string()),
            ..ClientContext::default()
        };
        found.touch(&nameless, &db).await.unwrap();
        let reloaded = Account::find_by_id("default", &found.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.last_seen_ptr, None);
    }

    /// The traceability columns are admin-visible only: the ACME account object
    /// is defined by RFC 8555 §7.1.2 and must not grow members naming where a
    /// client connects from.
    #[tokio::test]
    async fn to_json_exposes_none_of_the_traceability_columns() {
        let db = Database::connect_in_memory().await.unwrap();
        let client = ClientContext {
            ip: Some("203.0.113.7".to_string()),
            ptr: Some("host.example.com".to_string()),
            ..ClientContext::default()
        };
        let (account, _) = Account::find_or_create("default", &[7u8], vec![], &client, &db)
            .await
            .unwrap();
        let json = account.to_json("http://localhost:3000");
        let object = json.as_object().unwrap();
        for absent in [
            "createdIp",
            "created_ip",
            "createdPtr",
            "lastSeenAt",
            "lastSeenIp",
            "lastSeenPtr",
        ] {
            assert!(!object.contains_key(absent), "{absent} leaked into to_json");
        }
        assert!(!json.to_string().contains("203.0.113.7"));
    }

    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn find_or_create_creates_then_returns_existing() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let pubkey = vec![1u8, 2, 3, 4];
        let contact = vec!["mailto:a@example.com".to_string()];

        let (created, is_new) = Account::find_or_create(
            "default",
            &pubkey,
            contact.clone(),
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();
        assert!(is_new);
        assert_eq!(created.status, "valid");
        assert_eq!(created.contact, contact);

        // The same key returns the existing account (with its original contact),
        // not a second row.
        let (existing, is_new) =
            Account::find_or_create("default", &pubkey, vec![], &ClientContext::default(), &db)
                .await
                .unwrap();
        assert!(!is_new);
        assert_eq!(existing.id, created.id);
        assert_eq!(existing.contact, contact);
    }

    #[tokio::test]
    async fn find_by_id_and_pubkey_round_trip() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let pubkey = vec![9u8; 16];

        let (account, _) =
            Account::find_or_create("default", &pubkey, vec![], &ClientContext::default(), &db)
                .await
                .unwrap();

        let by_id = Account::find_by_id("default", &account.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.pubkey, pubkey);

        let by_key = Account::find_by_pubkey("default", &pubkey, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_key.id, account.id);
    }

    #[tokio::test]
    async fn absent_lookups_return_none() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());

        assert!(
            Account::find_by_id("default", "nope", &db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Account::find_by_pubkey("default", &[0u8; 4], &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn update_contact_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let pubkey = vec![7u8; 8];

        let (mut account, _) = Account::find_or_create(
            "default",
            &pubkey,
            vec!["mailto:old@example.com".to_string()],
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();

        let new_contact = vec!["mailto:new@example.com".to_string()];
        account
            .update_contact(new_contact.clone(), &db)
            .await
            .unwrap();

        // In-memory struct is updated…
        assert_eq!(account.contact, new_contact);
        // …and so is the stored row.
        let reloaded = Account::find_by_id("default", &account.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.contact, new_contact);
    }

    #[tokio::test]
    async fn deactivate_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let pubkey = vec![8u8; 8];

        let (mut account, _) =
            Account::find_or_create("default", &pubkey, vec![], &ClientContext::default(), &db)
                .await
                .unwrap();
        assert_eq!(account.status, "valid");

        account.deactivate(&db).await.unwrap();

        assert_eq!(account.status, "deactivated");
        let reloaded = Account::find_by_id("default", &account.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, "deactivated");
    }

    #[tokio::test]
    async fn update_pubkey_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (mut account, _) =
            Account::find_or_create("default", &[9u8; 8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();

        let new_pubkey = vec![10u8; 8];
        account.update_pubkey(&new_pubkey, &db).await.unwrap();

        // In-memory struct is updated…
        assert_eq!(account.pubkey, new_pubkey);
        // …and so is the stored row, findable under the new key.
        let reloaded = Account::find_by_id("default", &account.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.pubkey, new_pubkey);
        assert!(
            Account::find_by_pubkey("default", &new_pubkey, &db)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// `pubkey` is `UNIQUE`: rolling one account onto a key a *different*
    /// account already owns must fail rather than silently letting two
    /// accounts collide on one key. This is the DB-level backstop behind
    /// `post_key_change`'s own `find_by_pubkey` pre-check.
    #[tokio::test]
    async fn update_pubkey_to_a_key_owned_by_another_account_is_rejected() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (_first, _) = Account::find_or_create(
            "default",
            &[11u8; 8],
            vec![],
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();
        let (mut second, _) = Account::find_or_create(
            "default",
            &[12u8; 8],
            vec![],
            &ClientContext::default(),
            &db,
        )
        .await
        .unwrap();

        assert!(second.update_pubkey(&[11u8; 8], &db).await.is_err());
    }

    #[tokio::test]
    async fn set_eab_kid_persists_and_syncs() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (mut account, _) =
            Account::find_or_create("default", &[5u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();
        assert!(account.eab_kid.is_none());

        account.set_eab_kid("some-kid", &db).await.unwrap();
        assert_eq!(account.eab_kid.as_deref(), Some("some-kid"));

        let reloaded = Account::find_by_id("default", &account.id, &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.eab_kid.as_deref(), Some("some-kid"));
    }

    #[tokio::test]
    async fn list_all_orders_oldest_first() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());

        let (first, _) =
            Account::find_or_create("default", &[1u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();
        let (second, _) =
            Account::find_or_create("default", &[2u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();

        let all = Account::list_all(None, &db).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, first.id);
        assert_eq!(all[1].id, second.id);
    }

    #[tokio::test]
    async fn list_all_when_empty_is_empty() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(Account::list_all(None, &db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_the_row_and_reports_true() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (account, _) =
            Account::find_or_create("default", &[3u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();

        assert!(Account::delete(&account.id, &db).await.unwrap());
        assert!(
            Account::find_by_id("default", &account.id, &db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_of_unknown_id_reports_false() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        assert!(!Account::delete("nope", &db).await.unwrap());
    }

    #[tokio::test]
    async fn delete_cascades_to_the_accounts_orders() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (account, _) =
            Account::find_or_create("default", &[4u8], vec![], &ClientContext::default(), &db)
                .await
                .unwrap();

        crate::sqlite::order::Order::create(
            "default",
            &account.id,
            vec![],
            now_secs() + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();

        Account::delete(&account.id, &db).await.unwrap();

        let remaining = crate::sqlite::order::Order::find_by_account(&account.id, &db)
            .await
            .unwrap();
        assert!(remaining.is_empty());
    }

    /// Seeds `count` accounts under `profile`, backdated so `created_at DESC`
    /// is deterministic rather than resolved by the random-UUID tiebreak.
    async fn seed_accounts(db: &Arc<Database>, profile: &str, count: usize) -> Vec<String> {
        let base = now_secs();
        let mut ids = Vec::new();
        for index in 0..count {
            let (account, _) = Account::find_or_create(
                profile,
                &[profile.len() as u8, index as u8],
                vec![],
                &ClientContext::default(),
                db,
            )
            .await
            .unwrap();
            sqlx::query("UPDATE accounts SET created_at = ? WHERE id = ?;")
                .bind(base - index as i64)
                .bind(&account.id)
                .execute(&db.pool)
                .await
                .unwrap();
            ids.push(account.id);
        }
        ids
    }

    #[tokio::test]
    async fn search_pages_newest_first_and_reports_the_unpaged_total() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let ids = seed_accounts(&db, "default", 5).await;

        let (page, total) = Account::search(None, 2, 0, &db).await.unwrap();
        assert_eq!(total, 5, "the total must ignore the page window");
        assert_eq!(
            page.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
            ids[..2]
        );

        let (second, _) = Account::search(None, 2, 2, &db).await.unwrap();
        assert_eq!(
            second.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
            ids[2..4]
        );

        // Past the end: empty, but the total is still real.
        let (beyond, total) = Account::search(None, 2, 99, &db).await.unwrap();
        assert!(beyond.is_empty());
        assert_eq!(total, 5);
    }

    #[tokio::test]
    async fn search_scopes_by_profile_and_counts_only_that_profile() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        seed_accounts(&db, "default", 2).await;
        seed_accounts(&db, "other", 3).await;

        let (rows, total) = Account::search(Some("other"), 50, 0, &db).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|a| a.profile == "other"));

        let (_, total) = Account::search(None, 50, 0, &db).await.unwrap();
        assert_eq!(total, 5, "no profile means every endpoint");

        let (rows, total) = Account::search(Some("nope"), 50, 0, &db).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn search_on_an_empty_table_is_empty_rather_than_an_error() {
        let db = Arc::new(Database::connect_in_memory().await.unwrap());
        let (rows, total) = Account::search(None, 50, 0, &db).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }
}
