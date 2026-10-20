//! Where one surface's audit rows go — the part of an administrative action
//! that genuinely differs between a terminal and a browser.
//!
//! An operation in [`crate::admin::ops`] writes its own rows through an
//! [`ActionTrail`], so no front end can perform it and leave the trail silent.
//! That was the shape of the bug this replaced: `order delete` on the CLI
//! hard-deleted an order and wrote nothing, while both web front ends wrote
//! `order_deleted`, because each front end carried its own copy of "do it, then
//! record it". [`crate::admin::changes::OperatorTrail`] extends this with the
//! message an operator change also owes.

use std::future::Future;

use acme_proxy_core::audit::{Actor, AuditRecord, ClientContext};
use acme_proxy_store::db::Database;

/// Writes audit rows as one surface's actor, with one surface's client.
///
/// The futures are `Send` because the web admin awaits them inside an axum
/// handler.
pub trait ActionTrail: Sync {
    /// Writes every row `build` returns, resolving the actor and the client
    /// once for all of them.
    fn record_all(
        &self,
        build: impl FnOnce(Actor, ClientContext) -> Vec<AuditRecord> + Send,
    ) -> impl Future<Output = ()> + Send;

    /// Writes the one row `build` returns.
    fn record(
        &self,
        build: impl FnOnce(Actor, ClientContext) -> AuditRecord + Send,
    ) -> impl Future<Output = ()> + Send {
        self.record_all(move |actor, client| vec![build(actor, client)])
    }
}

/// The host CLI's trail: rows attributed to [`Actor::cli`], with no client,
/// written straight to the database — a `serve`-less invocation has no
/// auditor of its own.
pub struct CliActions<'a> {
    database: &'a Database,
}

impl<'a> CliActions<'a> {
    #[must_use]
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }
}

impl ActionTrail for CliActions<'_> {
    async fn record_all(
        &self,
        build: impl FnOnce(Actor, ClientContext) -> Vec<AuditRecord> + Send,
    ) {
        acme_proxy_jobs::auditor::admin::record_cli_actions(self.database, build).await;
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// A trail that keeps the event names it was asked to write, for asserting
    /// that an operation records exactly what it did.
    #[derive(Default)]
    pub(crate) struct Recorded {
        pub(crate) events: Mutex<Vec<String>>,
    }

    impl Recorded {
        pub(crate) fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ActionTrail for Recorded {
        async fn record_all(
            &self,
            build: impl FnOnce(Actor, ClientContext) -> Vec<AuditRecord> + Send,
        ) {
            let records = build(Actor::cli(), ClientContext::default());
            self.events.lock().unwrap().extend(
                records
                    .iter()
                    .map(|record| record.event.as_str().to_string()),
            );
        }
    }
}
