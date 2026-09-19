//! The outbound plumbing every subsystem that reaches the network dials through.

use std::sync::Arc;

use crate::{challenge, dns, http_client, proxy};
use acme_proxy_core::config::Config;

/// The outbound plumbing one configuration generation dials through, and the
/// identity of the configuration it came from.
///
/// `[dns]` and `[proxy]` are process-wide but no longer frozen, so they belong
/// to a *generation* rather than to the `Assembly`: a reload builds a fresh
/// resolver and proxy policy from the file, and every subsystem that reaches the
/// network is handed this generation's pair. The signer backends look like the
/// exception and are not — they cache what they were built with, so
/// `signer::build_backends` folds `identity` into a backend's identity key and
/// rebuilds any backend whose egress moved. Keeping the identity here rather
/// than beside the call site is what stops the two disagreeing, which would make
/// a `dns.resolver` edit a silent no-op for every signer.
pub struct Egress {
    /// Uncached, for the reason `challenge::build_resolver` explains: a client
    /// publishing a `dns-01` record moments before triggering must not be
    /// defeated by a cached negative answer.
    pub resolver: Arc<dyn dns::Resolver>,
    pub proxies: Arc<proxy::OutboundProxies>,
    /// `[dns]` and `[proxy]` rendered. Only ever compared to another one — never
    /// parsed, never shown — which is the same contract `signer::build_backends`
    /// keys a `[signer]` section on.
    pub identity: String,
}

impl Egress {
    /// Builds both clients from `config`.
    ///
    /// Fallible for two separate reasons worth keeping apart: a proxy URL that
    /// cannot be understood, and a `dns.resolver` that is not a socket address.
    /// Both must stop a startup and refuse a reload rather than degrade — a
    /// server that silently fell back to direct egress would dial around exactly
    /// the control its operator configured.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let proxies = crate::proxy::from_config(&config.proxy)?;
        // One resolver per generation, handed to every subsystem that makes an
        // outbound connection. `dns.resolver` is documented as "the nameserver
        // every DNS lookup this server makes goes through", and three of the
        // four HTTP clients used to bypass it — so an operator on a
        // split-horizon estate had NetBox and their upstream CA resolving
        // differently from the challenge validators, with nothing saying so.
        let resolver = challenge::build_resolver(crate::dns::resolver_addr(&config.dns)?)?;
        Ok(Self {
            resolver,
            proxies,
            identity: format!("{:?}|{:?}", config.dns, config.proxy),
        })
    }

    /// The resolver and proxy policy as one value, for the subsystems that make
    /// outbound HTTP requests.
    ///
    /// An accessor rather than a stored field: `challenge::from_config` builds
    /// its *own* resolver past the bypass branch (constructing one is what
    /// reads `/etc/resolv.conf`, so it must not happen when validation is off),
    /// and so needs the proxy half on its own.
    #[must_use]
    pub fn outbound(&self) -> http_client::Outbound {
        http_client::Outbound::new(self.resolver.clone(), self.proxies.clone())
    }
}
