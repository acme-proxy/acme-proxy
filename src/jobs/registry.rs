//! Which handler answers for which `jobs.kind`.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::JobHandler;

/// The handlers one runner drains for.
///
/// Assembled at startup from every subsystem that has background work — relayed
/// issuance, notification delivery, the CRL prune and the table sweeps — and
/// thereafter read-only. The runner claims **only** the kinds registered here,
/// which is what lets an older binary meet a row a newer one wrote and leave it
/// alone rather than failing to dispatch it.
#[derive(Default)]
pub struct JobRegistry {
    handlers: BTreeMap<&'static str, Arc<dyn JobHandler>>,
}

impl JobRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one handler.
    ///
    /// A duplicate `kind` is a startup error rather than a silent replacement:
    /// two handlers on one kind would each claim about half the rows, so half
    /// the work would run through the wrong code with no symptom but the
    /// outcome.
    ///
    /// This is why **no subsystem registers a handler per instance**: one
    /// handler covers every profile or backend of its kind and picks the right
    /// one per row, from what the row itself names. `SignerBackend` therefore
    /// hands over *state* (`crl_pruner`, `relay_state`) and never a handler —
    /// it returned one per backend until two relaying profiles against
    /// different upstreams met exactly this error at startup.
    pub fn register(&mut self, handler: Arc<dyn JobHandler>) -> anyhow::Result<()> {
        let kind = handler.kind();
        if self.handlers.contains_key(kind) {
            anyhow::bail!(
                "two job handlers registered for kind `{kind}`: one kind is served by one \
                 handler, or each would claim half the rows"
            );
        }
        self.handlers.insert(kind, handler);
        Ok(())
    }

    /// The registered kinds, which is exactly what the claim query filters on.
    #[must_use]
    pub fn kinds(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }

    /// The handler for `kind`, or `None` for one this build does not know.
    #[must_use]
    pub fn get(&self, kind: &str) -> Option<&Arc<dyn JobHandler>> {
        self.handlers.get(kind)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Every registered handler, for the startup `recover` pass.
    pub fn handlers(&self) -> impl Iterator<Item = &Arc<dyn JobHandler>> {
        self.handlers.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::JobOutcome;
    use crate::sqlite::job::Job;
    use async_trait::async_trait;

    struct Stub(&'static str);

    #[async_trait]
    impl JobHandler for Stub {
        fn kind(&self) -> &'static str {
            self.0
        }
        async fn run(&self, _job: &Job) -> JobOutcome {
            JobOutcome::Done
        }
    }

    #[test]
    fn a_registry_reports_its_kinds_and_resolves_them() {
        let mut registry = JobRegistry::new();
        assert!(registry.is_empty());
        registry.register(Arc::new(Stub("relay"))).unwrap();
        registry.register(Arc::new(Stub("sweep"))).unwrap();

        assert_eq!(registry.kinds(), vec!["relay", "sweep"]);
        assert!(registry.get("relay").is_some());
        assert!(registry.get("nothing-registered").is_none());
        assert_eq!(registry.handlers().count(), 2);
        assert!(!registry.is_empty());
    }

    #[test]
    fn a_second_handler_for_one_kind_is_a_startup_error() {
        let mut registry = JobRegistry::new();
        registry.register(Arc::new(Stub("relay"))).unwrap();
        let error = registry
            .register(Arc::new(Stub("relay")))
            .expect_err("a duplicate kind must not be accepted");
        assert!(
            error.to_string().contains("kind `relay`"),
            "the error must name the kind: {error}"
        );
    }
}
