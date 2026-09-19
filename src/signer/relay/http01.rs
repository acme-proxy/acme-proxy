//! Serving the challenge file the *upstream* CA asks for.
//!
//! ## Why this exists at all
//!
//! The deliberate twin of [`super::dns01`], and it exists for the same
//! asymmetry. When the upstream is a real CA it issues its own challenge, and
//! the key authorization it expects is computed from **this proxy's** account
//! thumbprint at that upstream — not the end client's. The two are different
//! accounts on different servers, so the original client cannot answer it even
//! in principle: only this server knows the right value.
//!
//! Where `dns01` answers that by writing a TXT record, this module answers it
//! by storing the key authorization in the database for the seconds the CA
//! needs it, and letting a route on the server's own root router serve it.
//! The database rather than memory, so the process serving the route need not
//! be the one whose relay job published the token.
//!
//! ## Why a route, and not a listener or a webroot
//!
//! RFC 8555 §8.3 fixes the *path* the CA fetches, not the port and not the
//! host it ultimately reaches: §8.3 explicitly permits following redirects,
//! and every real CA does. So the responder does not need to be the thing
//! listening on port 80 at the identifier — it only needs the operator's
//! existing web server to forward or redirect `/.well-known/acme-challenge/`
//! here. That is one `proxy_pass` or one `return 301`.
//!
//! Given that, a second listener bound to port 80 would buy nothing but a
//! privileged bind and a socket to reason about, and a webroot provider would
//! buy nothing but a shared filesystem to arrange. Neither is offered. What
//! *is* required — the forwarder — is stated at startup by [`super`]'s
//! `from_config`, because it is out of this process's reach and would
//! otherwise be discovered at the first failed issuance.
//!
//! ## The file's content is not defined here
//!
//! [`crate::challenge::http_01`] owns the well-known path, and
//! [`super::flow`] builds the key authorization from the account thumbprint.
//! This module only stores bytes under a token — the same separation
//! [`super::dns01`] keeps by calling into [`crate::challenge::dns_01`] rather
//! than restating the record convention.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::error;

use acme_proxy_store::db::Database;
use acme_proxy_store::http01_token::Http01Token;
use acme_proxy_store::nonce::now_secs;

/// Holds the key authorizations the responder route serves.
///
/// A trait rather than a concrete type for the same two reasons
/// [`super::dns01::DnsUpdater`] is one: the orchestration in [`super::flow`]
/// can be driven against a stub, and a future provider slots in without
/// touching the relay.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Makes `key_authorization` fetchable at
    /// `/.well-known/acme-challenge/{token}`.
    ///
    /// Additive: several authorizations of one order are answered in sequence
    /// but a multi-perspective CA may still have a fetch in flight for a token
    /// published earlier, so entries never displace one another. An `Err` is a
    /// store that could not be written, which a relay attempt retries.
    async fn publish(&self, token: &str, key_authorization: &str) -> Result<(), String>;

    /// Drops a previously published entry. Idempotent, and logs rather than
    /// returns a failure: by the time anything retracts, the upstream has
    /// decided, and an entry left behind expires on its own.
    async fn retract(&self, token: &str);

    /// What the responder route serves. An `Err` is a store that could not be
    /// read, which the route answers `500` rather than a `404` the upstream
    /// would take as this server having nothing to show.
    ///
    /// On the trait rather than only on [`DbTokenStore`] because `build_app`
    /// reaches the store through `Arc<dyn TokenStore>` — via
    /// [`SignerInfo::http01_tokens`] — and cannot downcast past it.
    ///
    /// [`SignerInfo::http01_tokens`]: crate::signer::SignerInfo::http01_tokens
    async fn lookup(&self, token: &str) -> Result<Option<String>, String>;
}

/// The store the `http01` strategy publishes into: the `http01_tokens` table.
///
/// Every entry carries a deadline `ttl` after it was published. The attempt
/// that published it retracts it long before that; the deadline is for the
/// attempt that died first, whose entry is then neither served nor kept — the
/// sweep deletes it.
pub struct DbTokenStore {
    database: Arc<Database>,
    ttl: Duration,
}

impl DbTokenStore {
    /// A store over `database` whose entries lapse `ttl` after publishing —
    /// the relay passes its attempt budget plus a margin, since no fetch can
    /// usefully arrive after the attempt that asked for it has ended.
    #[must_use]
    pub fn new(database: Arc<Database>, ttl: Duration) -> Self {
        Self { database, ttl }
    }
}

/// Logs a store failure where it happened, and renders it for the caller.
fn store_failure(operation: &'static str, token: &str, error: &sqlx::Error) -> String {
    error!(
        event = "http_01_token_store_failed",
        outcome = "failure",
        operation,
        token = %token,
        error = %error,
    );
    format!("the http-01 token store could not {operation} `{token}`: {error}")
}

#[async_trait]
impl TokenStore for DbTokenStore {
    async fn publish(&self, token: &str, key_authorization: &str) -> Result<(), String> {
        let now = now_secs();
        let ttl = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        Http01Token::publish(
            token,
            key_authorization,
            now,
            now.saturating_add(ttl),
            &self.database,
        )
        .await
        .map_err(|error| store_failure("publish", token, &error))
    }

    async fn retract(&self, token: &str) {
        if let Err(error) = Http01Token::retract(token, &self.database).await {
            store_failure("retract", token, &error);
        }
    }

    async fn lookup(&self, token: &str) -> Result<Option<String>, String> {
        Http01Token::lookup(token, now_secs(), &self.database)
            .await
            .map_err(|error| store_failure("look up", token, &error))
    }
}

/// A published token that is retracted when the attempt is done with it.
///
/// [`super::flow`]'s `answer_http01` retracts explicitly with
/// [`PublishedToken::retract`] once the upstream has decided. `Drop` covers the
/// path an explicit call cannot: the job runner's per-attempt timeout **drops
/// the future mid-poll**, and a retraction written after the await would simply
/// never run. A drop cannot await, so it hands the retraction to the runtime;
/// and if there is no runtime left to take it, the entry's own deadline is what
/// ends it.
pub struct PublishedToken {
    store: Arc<dyn TokenStore>,
    token: String,
    retracted: bool,
}

impl PublishedToken {
    /// Publishes `key_authorization` and returns the guard that retracts it.
    pub async fn publish(
        store: Arc<dyn TokenStore>,
        token: &str,
        key_authorization: &str,
    ) -> Result<Self, String> {
        store.publish(token, key_authorization).await?;
        Ok(Self {
            store,
            token: token.to_string(),
            retracted: false,
        })
    }

    /// Retracts the token now, and waits for it.
    pub async fn retract(mut self) {
        self.retracted = true;
        self.store.retract(&self.token).await;
    }
}

impl Drop for PublishedToken {
    fn drop(&mut self) {
        if self.retracted {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let store = self.store.clone();
            let token = std::mem::take(&mut self.token);
            runtime.spawn(async move { store.retract(&token).await });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store(ttl: Duration) -> (Arc<Database>, DbTokenStore) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        (database.clone(), DbTokenStore::new(database, ttl))
    }

    const MINUTE: Duration = Duration::from_secs(60);

    /// The production store's whole contract.
    #[tokio::test]
    async fn the_database_token_store_round_trips() {
        let (_database, store) = store(MINUTE).await;
        assert_eq!(store.lookup("absent").await.unwrap(), None);

        store.publish("tok", "tok.thumbprint").await.unwrap();
        assert_eq!(
            store.lookup("tok").await.unwrap().as_deref(),
            Some("tok.thumbprint")
        );

        // Two authorizations of one order live side by side.
        store.publish("other", "other.thumbprint").await.unwrap();
        assert_eq!(
            store.lookup("tok").await.unwrap().as_deref(),
            Some("tok.thumbprint")
        );

        store.retract("tok").await;
        assert_eq!(store.lookup("tok").await.unwrap(), None);
        assert_eq!(
            store.lookup("other").await.unwrap().as_deref(),
            Some("other.thumbprint")
        );

        // Idempotent: the guard's `Drop` may run after an explicit one.
        store.retract("tok").await;
    }

    /// The point of the table: a token published by one store — one process's
    /// relay job — is served by another over the same database.
    #[tokio::test]
    async fn a_token_published_by_one_store_is_served_by_another() {
        let (database, publisher) = store(MINUTE).await;
        let server = DbTokenStore::new(database, MINUTE);

        publisher.publish("tok", "tok.thumbprint").await.unwrap();
        assert_eq!(
            server.lookup("tok").await.unwrap().as_deref(),
            Some("tok.thumbprint")
        );
    }

    /// An entry past its deadline — an attempt that died before retracting —
    /// is not served.
    #[tokio::test]
    async fn an_expired_token_is_not_served() {
        let (_database, store) = store(Duration::ZERO).await;
        store.publish("tok", "tok.thumbprint").await.unwrap();
        assert_eq!(store.lookup("tok").await.unwrap(), None);
    }

    /// A store that cannot be reached says so, rather than answering "no such
    /// token".
    #[tokio::test]
    async fn an_unreachable_store_is_an_error_not_an_absence() {
        let (database, store) = store(MINUTE).await;
        database.close().await;

        assert!(store.lookup("tok").await.is_err());
        assert!(store.publish("tok", "tok.thumbprint").await.is_err());
        // Logged, not returned.
        store.retract("tok").await;
    }

    /// The explicit retraction, which the relay uses once the upstream has
    /// decided.
    #[tokio::test]
    async fn a_published_token_is_retracted_explicitly() {
        let (database, _) = store(MINUTE).await;
        let store: Arc<dyn TokenStore> = Arc::new(DbTokenStore::new(database, MINUTE));

        let guard = PublishedToken::publish(store.clone(), "tok", "tok.thumbprint")
            .await
            .unwrap();
        assert!(store.lookup("tok").await.unwrap().is_some());
        guard.retract().await;
        assert_eq!(store.lookup("tok").await.unwrap(), None);
    }

    /// The guard is the only thing standing between a cancelled relay and a
    /// key authorization that stays fetchable until its deadline.
    #[tokio::test]
    async fn a_published_token_retracts_itself_when_dropped() {
        let (database, _) = store(MINUTE).await;
        let store: Arc<dyn TokenStore> = Arc::new(DbTokenStore::new(database, MINUTE));
        {
            let _guard = PublishedToken::publish(store.clone(), "tok", "tok.thumbprint")
                .await
                .unwrap();
            assert!(store.lookup("tok").await.unwrap().is_some());
        }

        // The drop handed the retraction to the runtime; give it the turns it
        // needs rather than a fixed sleep.
        for _ in 0..100 {
            if store.lookup("tok").await.unwrap().is_none() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("a dropped guard must retract its token");
    }
}
