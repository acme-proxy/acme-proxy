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
//! by holding the key authorization in memory for the seconds the CA needs it,
//! and letting a route on the server's own root router serve it.
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
//! [`super::relay`] builds the key authorization from the account thumbprint.
//! This module only stores bytes under a token — the same separation
//! [`super::dns01`] keeps by calling into [`crate::challenge::dns_01`] rather
//! than restating the record convention.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

/// Holds the key authorizations the responder route serves.
///
/// A trait rather than a concrete type for the same two reasons
/// [`super::dns01::DnsUpdater`] is one: the orchestration in [`super::relay`]
/// can be driven against a stub, and a future provider slots in without
/// touching the relay.
pub trait TokenStore: Send + Sync {
    /// Makes `key_authorization` fetchable at
    /// `/.well-known/acme-challenge/{token}`.
    ///
    /// Additive: several authorizations of one order are answered in sequence
    /// but a multi-perspective CA may still have a fetch in flight for a token
    /// published earlier, so entries never displace one another.
    fn publish(&self, token: &str, key_authorization: &str);

    /// Drops a previously published entry. Idempotent — [`PublishedToken`]'s
    /// `Drop` may run on a path that already retracted.
    fn retract(&self, token: &str);

    /// What the responder route serves.
    ///
    /// On the trait rather than only on [`MemoryTokenStore`] because
    /// `build_app` reaches the store through `Arc<dyn TokenStore>` — via
    /// [`SignerBackend::http01_tokens`] — and cannot downcast past it.
    ///
    /// [`SignerBackend::http01_tokens`]: crate::signer::SignerBackend::http01_tokens
    fn lookup(&self, token: &str) -> Option<String>;
}

/// The process-local store the `http01` strategy publishes into.
///
/// A `std::sync::RwLock`, not a `tokio::sync` one: unlike
/// [`local_ca`](crate::signer::local_ca)'s revocation ledger — which uses an
/// async mutex precisely because it awaits two file writes inside its critical
/// section — every section here is one hash-map operation and awaits nothing.
///
/// Poisoning is recovered from rather than propagated. A panic anywhere else
/// holding this lock must not turn the responder into a permanent 404 for
/// every certificate this server will ever relay; the worst a torn write could
/// leave behind is a stale token, which the CA would simply fail to match.
#[derive(Debug, Default)]
pub struct MemoryTokenStore {
    entries: RwLock<HashMap<String, String>>,
}

impl MemoryTokenStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for MemoryTokenStore {
    fn publish(&self, token: &str, key_authorization: &str) {
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(token.to_string(), key_authorization.to_string());
    }

    fn retract(&self, token: &str) {
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(token);
    }

    fn lookup(&self, token: &str) -> Option<String> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .cloned()
    }
}

/// A published token that retracts itself when dropped.
///
/// [`super::relay`]'s `answer_dns01` retracts explicitly, in a `let triggered =
/// …; delete; triggered?` dance, because its retraction is a network round
/// trip and cannot run from `Drop`. This one can, and that closes a hole the
/// dns-01 side structurally cannot: `spawn_relay` wraps the whole relay in a
/// `tokio::time::timeout`, so a slow upstream **drops the future mid-poll** and
/// an explicit retract would simply never run — leaking one live key
/// authorization per timed-out relay, for the life of the process.
pub struct PublishedToken {
    store: Arc<dyn TokenStore>,
    token: String,
}

impl PublishedToken {
    /// Publishes `key_authorization` and returns the guard that retracts it.
    pub fn publish(store: Arc<dyn TokenStore>, token: &str, key_authorization: &str) -> Self {
        store.publish(token, key_authorization);
        Self {
            store,
            token: token.to_string(),
        }
    }
}

impl Drop for PublishedToken {
    fn drop(&mut self) {
        self.store.retract(&self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production store's whole contract, which the relay tests reach only
    /// through a stub.
    #[test]
    fn the_memory_token_store_round_trips() {
        let store = MemoryTokenStore::new();
        assert_eq!(store.lookup("absent"), None);

        store.publish("tok", "tok.thumbprint");
        assert_eq!(store.lookup("tok").as_deref(), Some("tok.thumbprint"));

        // Two authorizations of one order live side by side.
        store.publish("other", "other.thumbprint");
        assert_eq!(store.lookup("tok").as_deref(), Some("tok.thumbprint"));

        store.retract("tok");
        assert_eq!(store.lookup("tok"), None);
        assert_eq!(store.lookup("other").as_deref(), Some("other.thumbprint"));

        // Idempotent: `PublishedToken`'s `Drop` may run after an explicit one.
        store.retract("tok");
    }

    /// The guard is the only thing standing between a cancelled relay and a
    /// key authorization that stays fetchable forever.
    #[test]
    fn a_published_token_retracts_itself_when_dropped() {
        let store: Arc<dyn TokenStore> = Arc::new(MemoryTokenStore::new());
        {
            let _guard = PublishedToken::publish(store.clone(), "tok", "tok.thumbprint");
            assert_eq!(store.lookup("tok").as_deref(), Some("tok.thumbprint"));
        }
        assert_eq!(store.lookup("tok"), None);
    }
}
