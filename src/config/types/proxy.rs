//! `[proxy]` — the forward proxy every outbound client dials through.

use serde::Deserialize;

/// Where this server's own outbound HTTP goes.
///
/// Process-wide, so deliberately absent from `PROFILE_SECTIONS`: egress is a
/// property of the network position the process runs in, not of one of the ACME
/// endpoints it serves. Two profiles cannot reach the internet differently.
///
/// There is no `enabled` key either — the presence of a URL is the switch, the
/// same shape as `ipam.backend = ""` and an unset `dns.resolver`. Every key
/// empty (the default) means every connection dials the origin directly.
///
/// Each key falls back to its conventional environment variable when left
/// empty; the precedence and the one variable deliberately *not* read are
/// documented on [`crate::proxy::OutboundProxies::from_config`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Proxy for `http://` targets, e.g. `http://proxy.corp:3128`.
    ///
    /// Falls back to `$http_proxy`. Cleartext to the proxy itself: an
    /// `https://` value is a startup error rather than a second TLS layer
    /// nobody configured a trust anchor for.
    pub http_url: String,
    /// Proxy for `https://` targets, reached by `CONNECT`.
    ///
    /// Falls back to `$https_proxy`, then `$HTTPS_PROXY`. Normally the same
    /// `http://proxy.corp:3128` as `http_url`: this names the proxy used *for*
    /// https targets, not a proxy spoken to over https.
    ///
    /// Set independently of `http_url` on purpose — an estate that proxies only
    /// its TLS egress is ordinary, and the silent version of that ("it worked
    /// for http and did nothing for https") is what separate keys prevent.
    pub https_url: String,
    /// Targets that bypass the proxy: `*`, a domain, `.domain`, an address or a
    /// CIDR block.
    ///
    /// Falls back to `$no_proxy`, then `$NO_PROXY`. Loopback and `localhost`
    /// are bypassed unconditionally and need no entry here.
    #[serde(deserialize_with = "super::empty_string_is_no_values")]
    pub no_proxy: Vec<String>,
}
