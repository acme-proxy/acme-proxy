//! `[proxy]` — which forward proxy, if any, an outbound connection goes
//! through.
//!
//! The *policy* half of outbound HTTP, the way [`crate::http_client`] is the
//! plumbing half: that module's own doc says it "owns the plumbing and nothing
//! else", and selection is not plumbing. It is an environment fallback with a
//! documented precedence, six matching rules, a startup vocabulary of refusals
//! and a credential that must never reach a log.
//!
//! Reaching into [`crate::filter`] for [`parse_net`]/[`canonical`] is a choice,
//! not an accident: that subsystem is inbound policy and this is outbound, but
//! CIDR parsing is CIDR parsing, and two of them would drift. If a third
//! consumer ever appears, hoist those four helpers into a neutral module rather
//! than growing a second copy here.

use std::net::IpAddr;
use std::sync::Arc;

use base64::prelude::*;
use ipnet::IpNet;
use tracing::info;
use url::Url;

use crate::config::ProxyConfig;
use crate::filter::{canonical, parse_net};
use crate::http_client::Endpoint;

/// One proxy, already picked apart.
///
/// Cleartext to the proxy itself by construction — [`OutboundProxies`] refuses
/// an `https://` URL before one of these is ever built.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    endpoint: Endpoint,
    /// The finished `Basic …` header value, built once from the URL's userinfo.
    /// `None` when the URL carried no credentials.
    authorization: Option<String>,
    /// The configured URL with any password replaced — the only rendering of
    /// this value that exists.
    redacted: String,
}

impl ProxyTarget {
    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(crate) fn authorization(&self) -> Option<&str> {
        self.authorization.as_deref()
    }

    /// The proxy's URL with any password replaced by `***`, for an error
    /// message or a log line.
    pub(crate) fn redacted(&self) -> &str {
        &self.redacted
    }
}

#[cfg(test)]
impl ProxyTarget {
    /// One target straight from a URL, for the transport tests.
    pub(crate) fn for_test(url: &str) -> Self {
        Self::parse(url, "proxy.http_url").expect("the test URL must parse")
    }
}

/// Hand-written, never derived: `authorization` is a credential, and a derived
/// `Debug` on a struct holding one is how it ends up in a log. The same reason
/// [`crate::ipam::http::JsonApi`]'s is hand-written.
impl std::fmt::Debug for ProxyTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyTarget")
            .field("url", &self.redacted)
            .field("authenticated", &self.authorization.is_some())
            .finish()
    }
}

/// One `no_proxy` entry, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BypassRule {
    /// `*` — every target bypasses.
    Everything,
    /// A domain, normalized: no leading `.`, no trailing `.`, lowercase.
    /// Matches the name itself and anything under it.
    Suffix(String),
    /// An address or CIDR block, matched only against a target that is itself
    /// an address literal.
    Network(IpNet),
}

/// The process-wide outbound proxy configuration, resolved once at startup.
///
/// Two independent proxies rather than one: an estate that proxies only its TLS
/// egress is ordinary, and `select` returning `None` for https because only
/// `http_url` was set is a decision an operator made, not a gap.
#[derive(Debug, Clone, Default)]
pub struct OutboundProxies {
    http: Option<ProxyTarget>,
    https: Option<ProxyTarget>,
    bypass: Vec<BypassRule>,
}

impl OutboundProxies {
    /// Resolves `[proxy]`, falling back to the conventional environment
    /// variables for any key left empty.
    ///
    /// Precedence, highest first:
    ///
    /// | key | then | then |
    /// | --- | --- | --- |
    /// | `proxy.http_url` | `$http_proxy` | — |
    /// | `proxy.https_url` | `$https_proxy` | `$HTTPS_PROXY` |
    /// | `proxy.no_proxy` | `$no_proxy` | `$NO_PROXY` |
    ///
    /// An empty string is "unset" in both sources: `config` cannot tell an
    /// absent environment variable from one a `${VAR:-}` shell default left
    /// empty, and neither can a shell.
    ///
    /// **Uppercase `HTTP_PROXY` is deliberately not read.** Under CGI a
    /// client-supplied `Proxy:` request header lands in the environment as
    /// `HTTP_PROXY` (httpoxy, CVE-2016-5385 and friends). This server is never
    /// a CGI process, so the vector does not reach it — but Go's `net/http`
    /// dropped the variable for exactly this reason, matching it costs nothing,
    /// and honouring a variable purely because everyone does is the kind of
    /// thing that is only ever wrong. `HTTPS_PROXY` has no such history and is
    /// honoured.
    ///
    /// Every failure here is fatal: a proxy that cannot be understood must stop
    /// the process, never quietly leave egress going somewhere else.
    pub fn from_config(cfg: &ProxyConfig) -> anyhow::Result<Self> {
        let (http_url, http_source) = resolve(&cfg.http_url, &["http_proxy"]);
        let (https_url, https_source) = resolve(&cfg.https_url, &["https_proxy", "HTTPS_PROXY"]);
        let (no_proxy, no_proxy_source) = match cfg.no_proxy.is_empty() {
            false => (cfg.no_proxy.clone(), Source::Config),
            true => {
                let (raw, source) = resolve("", &["no_proxy", "NO_PROXY"]);
                let entries = raw
                    .map(|value| value.split(',').map(str::to_string).collect())
                    .unwrap_or_default();
                (entries, source)
            }
        };

        let http = http_url
            .as_deref()
            .map(|url| ProxyTarget::parse(url, "proxy.http_url"))
            .transpose()?;
        let https = https_url
            .as_deref()
            .map(|url| ProxyTarget::parse(url, "proxy.https_url"))
            .transpose()?;
        let bypass = parse_bypass(&no_proxy)?;

        let resolved = Self {
            http,
            https,
            bypass,
        };
        if resolved.is_configured() {
            info!(
                event = "proxy_configured",
                outcome = "advisory",
                source = %Source::describe(&[http_source, https_source, no_proxy_source]),
                http_proxy = resolved.http.as_ref().map_or("-", ProxyTarget::redacted),
                https_proxy = resolved.https.as_ref().map_or("-", ProxyTarget::redacted),
                no_proxy_rules = resolved.bypass.len(),
            );
        }
        Ok(resolved)
    }

    /// Nothing configured: every connection dials the origin directly.
    pub fn direct() -> Self {
        Self::default()
    }

    /// Whether any proxy is configured at all.
    pub fn is_configured(&self) -> bool {
        self.http.is_some() || self.https.is_some()
    }

    /// Which proxy, if any, `endpoint` goes through.
    ///
    /// Loopback and `localhost` bypass unconditionally, before `no_proxy` is
    /// consulted and whatever it says. The reason is the environment fallback:
    /// an operator's inherited shell `http_proxy` must not route this server's
    /// own loopback traffic through a corporate proxy, and the failure that
    /// would cause has no signal in it at all.
    ///
    /// A `Network` rule is compared only against a target that is *already* an
    /// address literal. Resolving a name to test one would mean a DNS lookup
    /// per outbound request, and a lookup whose answer the connect path is then
    /// free to disagree with.
    pub(crate) fn select(&self, endpoint: &Endpoint) -> Option<&ProxyTarget> {
        let proxy = match endpoint.https {
            true => self.https.as_ref(),
            false => self.http.as_ref(),
        }?;

        let host = normalize_host(endpoint.host_for_lookup());
        let address = host.parse::<IpAddr>().ok().map(canonical);
        if host == "localhost" || address.is_some_and(|ip| ip.is_loopback()) {
            return None;
        }

        let bypassed = self.bypass.iter().any(|rule| match rule {
            BypassRule::Everything => true,
            BypassRule::Suffix(suffix) => host == *suffix || host.ends_with(&format!(".{suffix}")),
            BypassRule::Network(net) => address.is_some_and(|ip| net.contains(&ip)),
        });

        match bypassed {
            true => None,
            false => Some(proxy),
        }
    }

    /// A proxy every endpoint goes through, loopback included — the only way a
    /// test can drive the transport against a proxy on `127.0.0.1`.
    #[cfg(test)]
    pub(crate) fn always(target: ProxyTarget) -> Self {
        Self {
            http: Some(target.clone()),
            https: Some(target),
            bypass: Vec::new(),
        }
    }

    /// The `no_proxy` half alone, for the test that proves a bypass really
    /// leaves the proxy untouched.
    #[cfg(test)]
    pub(crate) fn with_bypass(mut self, entries: &[&str]) -> anyhow::Result<Self> {
        let entries: Vec<String> = entries.iter().map(|entry| (*entry).to_string()).collect();
        self.bypass = parse_bypass(&entries)?;
        Ok(self)
    }
}

impl ProxyTarget {
    /// Parses one proxy URL, naming `setting` in any refusal so the message
    /// points at the key that has to change.
    ///
    /// A bare `proxy.corp:3128` is accepted by prepending `http://`: it is what
    /// operators write, and `Url::parse` would otherwise read `proxy.corp` as a
    /// scheme and `3128` as the path.
    fn parse(url: &str, setting: &str) -> anyhow::Result<Self> {
        let trimmed = url.trim();
        let spelled = match trimmed.contains("://") {
            true => trimmed.to_string(),
            false => format!("http://{trimmed}"),
        };
        let parsed = Url::parse(&spelled)
            .map_err(|error| anyhow::anyhow!("{setting}: {url} is not a URL: {error}"))?;

        match parsed.scheme() {
            "http" => {}
            "https" => anyhow::bail!(
                "{setting}: {url} would reach the proxy over TLS, which is not supported. \
                 This key names the proxy used *for* https targets, and that proxy is \
                 normally still spelled http://host:port"
            ),
            other => anyhow::bail!(
                "{setting}: unsupported proxy scheme {other}, expected http (there is no \
                 SOCKS support)"
            ),
        }

        let endpoint = Endpoint::from_url(&parsed)
            .map_err(|error| anyhow::anyhow!("{setting}: {url}: {error}"))?;

        let user = percent_decode(parsed.username())
            .map_err(|error| anyhow::anyhow!("{setting}: {url}: username {error}"))?;
        let authorization = match user.is_empty() {
            true => None,
            false => {
                let password = match parsed.password() {
                    Some(password) => percent_decode(password)
                        .map_err(|error| anyhow::anyhow!("{setting}: {url}: password {error}"))?,
                    None => String::new(),
                };
                Some(format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(format!("{user}:{password}"))
                ))
            }
        };

        Ok(Self {
            redacted: redact(&parsed),
            endpoint,
            authorization,
        })
    }
}

/// Where a resolved value came from, for the startup line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Config,
    Environment,
    Unset,
}

impl Source {
    fn describe(sources: &[Self]) -> &'static str {
        let config = sources.contains(&Self::Config);
        let environment = sources.contains(&Self::Environment);
        match (config, environment) {
            (true, true) => "config+environment",
            (true, false) => "config",
            (false, true) => "environment",
            (false, false) => "unset",
        }
    }
}

/// The configured value, or the first non-empty variable in `variables`.
fn resolve(configured: &str, variables: &[&str]) -> (Option<String>, Source) {
    if !configured.trim().is_empty() {
        return (Some(configured.trim().to_string()), Source::Config);
    }
    for name in variables {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return (Some(value.trim().to_string()), Source::Environment);
        }
    }
    (None, Source::Unset)
}

/// Parses every `no_proxy` entry, refusing an unusable one by name.
fn parse_bypass(entries: &[String]) -> anyhow::Result<Vec<BypassRule>> {
    let mut rules = Vec::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            rules.push(BypassRule::Everything);
            continue;
        }
        if let Ok(net) = parse_net(entry) {
            rules.push(BypassRule::Network(net));
            continue;
        }
        // A port here answers a different question than it looks like it
        // answers — matching is on the host, and an entry that silently ignored
        // half of itself is the failure this codebase refuses elsewhere.
        if entry.contains(':') {
            anyhow::bail!(
                "proxy.no_proxy: {entry} carries a port, which is not honoured — \
                 entries match on the host alone"
            );
        }
        let suffix = entry
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            anyhow::bail!("proxy.no_proxy: {entry} is not a domain, address or network");
        }
        rules.push(BypassRule::Suffix(suffix));
    }
    Ok(rules)
}

/// Lowercased, with any IPv6 brackets and trailing root dot removed.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Percent-decodes one userinfo component.
///
/// `Url::username`/`Url::password` hand back the *encoded* text, and
/// `DOMAIN\user` or `user@corp` are entirely ordinary proxy credentials that
/// arrive here as `DOMAIN%5Cuser` / `user%40corp`. Encoding those verbatim into
/// `Basic` sends the wrong credential and yields a `407` an operator cannot
/// explain.
fn percent_decode(value: &str) -> Result<String, String> {
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|error| format!("is not valid UTF-8 once decoded: {error}"))
}

/// The URL with any password replaced, ready to be logged.
fn redact(url: &Url) -> String {
    match url.password().is_some() {
        false => url.as_str().trim_end_matches('/').to_string(),
        true => {
            let mut redacted = url.clone();
            let _ = redacted.set_password(Some("***"));
            redacted.as_str().trim_end_matches('/').to_string()
        }
    }
}

/// Builds the process's proxy configuration, wrapped for the subsystems that
/// each keep a clone.
pub fn from_config(cfg: &ProxyConfig) -> anyhow::Result<Arc<OutboundProxies>> {
    OutboundProxies::from_config(cfg).map(Arc::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::EnvGuard;

    fn config(http: &str, https: &str, no_proxy: &[&str]) -> ProxyConfig {
        ProxyConfig {
            http_url: http.to_string(),
            https_url: https.to_string(),
            no_proxy: no_proxy.iter().map(|entry| (*entry).to_string()).collect(),
        }
    }

    /// `EnvGuard` pins `ACME_PROXY_CONFIG` and takes the crate-wide lock, which
    /// is what keeps a test reading `http_proxy` away from one setting it.
    fn without_env() -> EnvGuard {
        EnvGuard::new(&[])
    }

    fn endpoint(host: &str, https: bool) -> Endpoint {
        Endpoint {
            host: host.to_string(),
            port: if https { 443 } else { 80 },
            https,
        }
    }

    #[test]
    fn both_urls_are_parsed() {
        let _guard = without_env();
        let proxies = OutboundProxies::from_config(&config(
            "http://p1.example:3128",
            "http://p2.example",
            &[],
        ))
        .unwrap();

        let http = proxies.select(&endpoint("example.com", false)).unwrap();
        assert_eq!(http.endpoint().host, "p1.example");
        assert_eq!(http.endpoint().port, 3128);
        assert!(!http.endpoint().https);

        let https = proxies.select(&endpoint("example.com", true)).unwrap();
        assert_eq!(https.endpoint().host, "p2.example");
        assert_eq!(https.endpoint().port, 80);
    }

    /// A bare `host:port` is what operators write, and `Url::parse` would read
    /// it as a scheme with a path.
    #[test]
    fn a_bare_authority_is_read_as_http() {
        let _guard = without_env();
        let proxies = OutboundProxies::from_config(&config("proxy.example:3128", "", &[])).unwrap();
        let target = proxies.select(&endpoint("example.com", false)).unwrap();
        assert_eq!(target.endpoint().host, "proxy.example");
        assert_eq!(target.endpoint().port, 3128);
    }

    /// The two keys are independent: setting only `http_url` must leave https
    /// targets direct rather than quietly reusing it. "It worked for http and
    /// did nothing for https" is the bug this pins.
    #[test]
    fn the_two_keys_are_not_interchangeable() {
        let _guard = without_env();
        let proxies = OutboundProxies::from_config(&config("http://p.example", "", &[])).unwrap();
        assert!(proxies.select(&endpoint("example.com", false)).is_some());
        assert!(proxies.select(&endpoint("example.com", true)).is_none());
    }

    #[test]
    fn nothing_configured_is_direct() {
        let _guard = without_env();
        let proxies = OutboundProxies::from_config(&ProxyConfig::default()).unwrap();
        assert!(!proxies.is_configured());
        assert!(proxies.select(&endpoint("example.com", true)).is_none());
        assert!(!OutboundProxies::direct().is_configured());
    }

    #[test]
    fn credentials_become_a_basic_header() {
        let _guard = without_env();
        let proxies =
            OutboundProxies::from_config(&config("http://user:pass@p.example", "", &[])).unwrap();
        let target = proxies.select(&endpoint("example.com", false)).unwrap();
        // RFC 7617's worked shape: base64("user:pass").
        assert_eq!(target.authorization(), Some("Basic dXNlcjpwYXNz"));
    }

    /// `DOMAIN\user` and `user@corp` are ordinary proxy usernames and reach
    /// `Url::username` percent-encoded; sending them that way is a 407 nobody
    /// can explain.
    #[test]
    fn percent_encoded_credentials_are_decoded_before_encoding() {
        let _guard = without_env();
        let proxies =
            OutboundProxies::from_config(&config("http://user%40corp:p%3Ass@p.example", "", &[]))
                .unwrap();
        let target = proxies.select(&endpoint("example.com", false)).unwrap();
        assert_eq!(
            target.authorization(),
            Some(format!("Basic {}", BASE64_STANDARD.encode("user@corp:p:ss")).as_str())
        );
    }

    #[test]
    fn a_url_without_userinfo_carries_no_authorization() {
        let _guard = without_env();
        let proxies = OutboundProxies::from_config(&config("http://p.example", "", &[])).unwrap();
        assert!(
            proxies
                .select(&endpoint("example.com", false))
                .unwrap()
                .authorization()
                .is_none()
        );
    }

    /// Neither rendering may carry the password: `Debug` derives are how a
    /// credential reaches a log.
    #[test]
    fn neither_debug_nor_redacted_leaks_the_password() {
        let _guard = without_env();
        let proxies =
            OutboundProxies::from_config(&config("http://user:hunter2@p.example", "", &[]))
                .unwrap();
        let target = proxies.select(&endpoint("example.com", false)).unwrap();
        assert!(
            !target.redacted().contains("hunter2"),
            "{}",
            target.redacted()
        );
        assert!(target.redacted().contains("***"), "{}", target.redacted());

        let rendered = format!("{target:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        // …and not the header either, which is only base64 away from readable.
        assert!(!rendered.contains("Basic"), "{rendered}");

        let whole = format!("{proxies:?}");
        assert!(!whole.contains("hunter2"), "{whole}");
    }

    #[test]
    fn every_refusal_names_what_has_to_change() {
        let _guard = without_env();
        let cases: &[(&str, &[&str])] = &[
            (
                "https://p.example:3128",
                &["proxy.http_url", "http://host:port"],
            ),
            ("socks5://p.example:1080", &["proxy.http_url", "socks5"]),
            ("http://", &["proxy.http_url"]),
        ];
        for (url, expected) in cases {
            let error = OutboundProxies::from_config(&config(url, "", &[]))
                .expect_err("{url} must be refused")
                .to_string();
            for fragment in *expected {
                assert!(error.contains(fragment), "{url}: {error}");
            }
        }

        let https_error = OutboundProxies::from_config(&config("", "https://p.example", &[]))
            .expect_err("an https proxy URL must be refused")
            .to_string();
        assert!(https_error.contains("proxy.https_url"), "{https_error}");
    }

    #[test]
    fn a_no_proxy_entry_with_a_port_is_refused_by_name() {
        let _guard = without_env();
        let error =
            OutboundProxies::from_config(&config("http://p.example", "", &["example.com:8080"]))
                .expect_err("a port in no_proxy must be refused")
                .to_string();
        assert!(error.contains("example.com:8080"), "{error}");
        assert!(error.contains("port"), "{error}");
    }

    #[test]
    fn an_unusable_no_proxy_entry_is_refused() {
        let _guard = without_env();
        let error = OutboundProxies::from_config(&config("http://p.example", "", &["."]))
            .expect_err("a bare dot must be refused")
            .to_string();
        assert!(error.contains("proxy.no_proxy"), "{error}");
    }

    #[test]
    fn no_proxy_matching() {
        let _guard = without_env();
        // (rules, host, bypassed?)
        let cases: &[(&[&str], &str, bool)] = &[
            (&["example.com"], "example.com", true),
            (&["example.com"], "a.b.example.com", true),
            (&[".example.com"], "example.com", true),
            (&[".example.com"], "a.example.com", true),
            // The `.` in the suffix comparison is the whole point: without it
            // `notexample.com` matches `example.com`.
            (&["example.com"], "notexample.com", false),
            (&["example.com"], "example.com.evil.net", false),
            (&["EXAMPLE.COM"], "Example.Com", true),
            (&["example.com"], "example.com.", true),
            (&["*"], "anything.example", true),
            (&["192.0.2.7"], "192.0.2.7", true),
            (&["192.0.2.7"], "192.0.2.8", false),
            (&["10.0.0.0/8"], "10.1.2.3", true),
            (&["10.0.0.0/8"], "11.1.2.3", false),
            (&["2001:db8::/32"], "[2001:db8::1]", true),
            // A name is never resolved to test a network rule.
            (&["10.0.0.0/8"], "host.example", false),
            (&["other.example", "example.com"], "www.example.com", true),
        ];
        for (rules, host, bypassed) in cases {
            let proxies =
                OutboundProxies::from_config(&config("http://p.example", "", rules)).unwrap();
            assert_eq!(
                proxies.select(&endpoint(host, false)).is_none(),
                *bypassed,
                "{rules:?} against {host}"
            );
        }
    }

    /// An inherited shell `http_proxy` must not send this server's own loopback
    /// traffic through a corporate proxy — a failure with no signal in it.
    #[test]
    fn loopback_and_localhost_bypass_unconditionally() {
        let _guard = without_env();
        let proxies =
            OutboundProxies::from_config(&config("http://p.example", "http://p.example", &["*"]))
                .unwrap();
        for host in ["localhost", "LocalHost", "127.0.0.1", "[::1]", "127.9.9.9"] {
            assert!(
                proxies.select(&endpoint(host, false)).is_none(),
                "{host} must bypass"
            );
        }
        // …and a non-loopback address still goes through, so the rule is not
        // just "everything bypasses".
        let proxies = OutboundProxies::from_config(&config("http://p.example", "", &[])).unwrap();
        assert!(proxies.select(&endpoint("203.0.113.7", false)).is_some());
    }

    #[test]
    fn the_environment_fills_in_an_unset_key() {
        let _guard = EnvGuard::new(&[
            ("http_proxy", "http://env-http.example:3128"),
            ("https_proxy", "http://env-https.example:3128"),
            ("no_proxy", "one.example, .two.example"),
        ]);
        let proxies = OutboundProxies::from_config(&ProxyConfig::default()).unwrap();
        assert_eq!(
            proxies
                .select(&endpoint("example.com", false))
                .unwrap()
                .endpoint()
                .host,
            "env-http.example"
        );
        assert_eq!(
            proxies
                .select(&endpoint("example.com", true))
                .unwrap()
                .endpoint()
                .host,
            "env-https.example"
        );
        assert!(proxies.select(&endpoint("one.example", false)).is_none());
        assert!(proxies.select(&endpoint("a.two.example", false)).is_none());
    }

    #[test]
    fn a_configured_key_beats_the_environment() {
        let _guard = EnvGuard::new(&[
            ("http_proxy", "http://env.example:3128"),
            ("no_proxy", "env.example"),
        ]);
        let proxies =
            OutboundProxies::from_config(&config("http://file.example", "", &["file.example.com"]))
                .unwrap();
        assert_eq!(
            proxies
                .select(&endpoint("example.com", false))
                .unwrap()
                .endpoint()
                .host,
            "file.example"
        );
        // The configured no_proxy replaced the environment's wholesale rather
        // than merging with it — arrays never append here.
        assert!(proxies.select(&endpoint("env.example", false)).is_some());
        assert!(
            proxies
                .select(&endpoint("file.example.com", false))
                .is_none()
        );
    }

    /// `HTTPS_PROXY` is honoured and `HTTP_PROXY` is not — see
    /// [`OutboundProxies::from_config`] for why.
    #[test]
    fn uppercase_http_proxy_is_ignored_while_https_proxy_is_not() {
        let _guard = EnvGuard::new(&[
            ("HTTP_PROXY", "http://attacker.example:3128"),
            ("HTTPS_PROXY", "http://upper.example:3128"),
        ]);
        let proxies = OutboundProxies::from_config(&ProxyConfig::default()).unwrap();
        assert!(proxies.select(&endpoint("example.com", false)).is_none());
        assert_eq!(
            proxies
                .select(&endpoint("example.com", true))
                .unwrap()
                .endpoint()
                .host,
            "upper.example"
        );
    }

    /// A `${VAR:-}` shell default arrives as present-but-empty, which is not a
    /// proxy at the empty URL.
    #[test]
    fn an_empty_environment_variable_is_unset() {
        let _guard = EnvGuard::new(&[("http_proxy", ""), ("no_proxy", "")]);
        let proxies = OutboundProxies::from_config(&ProxyConfig::default()).unwrap();
        assert!(!proxies.is_configured());
    }

    #[test]
    fn the_startup_source_is_described_from_where_the_values_came() {
        assert_eq!(Source::describe(&[Source::Unset, Source::Unset]), "unset");
        assert_eq!(Source::describe(&[Source::Config, Source::Unset]), "config");
        assert_eq!(
            Source::describe(&[Source::Environment, Source::Unset]),
            "environment"
        );
        assert_eq!(
            Source::describe(&[Source::Config, Source::Environment]),
            "config+environment"
        );
    }

    #[test]
    fn from_config_hands_back_a_shared_value() {
        let _guard = without_env();
        let proxies = crate::proxy::from_config(&ProxyConfig::default()).unwrap();
        assert!(!proxies.is_configured());
    }
}
