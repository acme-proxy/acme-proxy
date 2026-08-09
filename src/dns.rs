//! DNS lookups, behind a trait.
//!
//! Two subsystems need the resolver for entirely different reasons — the
//! [`reverse_dns`](crate::filter::reverse_dns) filter wants a PTR record for the
//! client's address, the [`dns_01`](crate::challenge::dns_01) challenge wants a
//! TXT record under the name being validated — and both need to drive every
//! branch (no record, a mismatch, a timeout) from canned data rather than the
//! network. One trait serves both, so there is a single reader of
//! `/etc/resolv.conf`, one convention for "the lookup failed" versus "the answer
//! was empty", and one stub shape for a test author to learn.
//!
//! Errors are plain `String`s: what a caller does with a failed lookup differs
//! (a filter denies, a challenge reports `dns`), so the type stays out of it.

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::{Name, RData, rdata::TXT},
};

use crate::config::DnsConfig;

/// The DNS lookups this crate needs.
///
/// Abstracted so tests can drive every branch — no PTR, a mismatched forward
/// record, a timeout — from canned data instead of the network.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// PTR names for `ip`, or an error describing why the lookup failed.
    async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String>;

    /// A/AAAA addresses for `name`.
    async fn forward(&self, name: &str) -> Result<Vec<IpAddr>, String>;

    /// TXT records for `name`.
    ///
    /// A record's character-strings are concatenated (RFC 1035 §3.3.14): a value
    /// over 255 octets arrives split. A `dns-01` value never is, but a provider
    /// padding the record would otherwise never match.
    async fn txt(&self, name: &str) -> Result<Vec<String>, String>;
}

/// The production resolver, reading `/etc/resolv.conf` at startup.
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Builds a resolver from the system configuration, with hickory's default
    /// cache.
    pub fn from_system() -> anyhow::Result<Self> {
        Self::build(None, |_| {})
    }

    /// Same, with caching disabled.
    ///
    /// `dns-01` asks about a record the client has *just* published, so a cached
    /// negative answer would fail a challenge that is in fact satisfied — for the
    /// whole negative TTL, which the client does not control. Answering from the
    /// authoritative servers every time is the point of the lookup.
    pub fn from_system_uncached() -> anyhow::Result<Self> {
        Self::build(None, |options| options.cache_size = 0)
    }

    /// Builds a resolver querying only `addr` (`config.dns.resolver`), instead of
    /// the system configuration. Used by `reverse_dns`, which wants caching.
    pub fn from_address(addr: SocketAddr) -> anyhow::Result<Self> {
        Self::build(Some(addr), |_| {})
    }

    /// Same, with caching disabled — the `dns-01` counterpart of
    /// [`Self::from_address`], for the same reason [`Self::from_system_uncached`]
    /// disables it.
    pub fn from_address_uncached(addr: SocketAddr) -> anyhow::Result<Self> {
        Self::build(Some(addr), |options| options.cache_size = 0)
    }

    /// Shared construction: from the system configuration when `addr` is `None`,
    /// or a resolver querying only `addr` otherwise. `configure` adjusts the
    /// resolver options either way.
    fn build(
        addr: Option<SocketAddr>,
        configure: impl FnOnce(&mut ResolverOpts),
    ) -> anyhow::Result<Self> {
        let mut builder = match addr {
            None => TokioResolver::builder_tokio()
                .map_err(|error| anyhow::anyhow!("reading system resolver config: {error}"))?,
            Some(addr) => {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                let name_server = NameServerConfig::new(addr.ip(), true, vec![udp, tcp]);
                let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            }
        };
        configure(builder.options_mut());
        let inner = builder
            .build()
            .map_err(|error| anyhow::anyhow!("building resolver: {error}"))?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl Resolver for HickoryResolver {
    /// hickory's `*_lookup` methods (used here and in [`Self::forward`] and
    /// [`Self::txt`]) surface both NXDOMAIN and an empty NOERROR answer as
    /// `Err(NetError)`, not `Ok` with no records — so without distinguishing
    /// `is_no_records_found()` in each of the three, "the client just
    /// doesn't have this record" (the ordinary shape of "no PTR record for
    /// this address", or a `dns-01` TXT record not published yet) is
    /// indistinguishable from the resolver genuinely failing (SERVFAIL,
    /// timeout). [`filter::reverse_dns`](crate::filter::reverse_dns) depends
    /// on telling those apart: the former denies the request, the latter is
    /// a 500 the client can retry. (`dns_01` happens not to care — both
    /// cases map to the same `ChallengeError::Dns` there — which is why this
    /// went uncaught until `reverse_dns` was first exercised against a real
    /// resolver, in the podman-compose lab's `filters/reverse_dns`.)
    async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        // `Name::from(IpAddr)` yields the `…in-addr.arpa` / `…ip6.arpa` form.
        let lookup = match self.inner.reverse_lookup(Name::from(ip)).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::PTR(ptr) => Some(strip_root(&ptr.to_string())),
                _ => None,
            })
            .collect())
    }

    async fn forward(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        let lookup = match self.inner.lookup_ip(name).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
        };
        Ok(lookup.iter().collect())
    }

    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let lookup = match self.inner.txt_lookup(name).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(join_character_strings(txt)),
                _ => None,
            })
            .collect())
    }
}

/// Concatenates a TXT record's character-strings into one value (RFC 1035
/// §3.3.14). Lossy on purpose: a TXT record carrying non-UTF-8 is not a
/// `dns-01` response, and a replacement character simply fails the comparison.
fn join_character_strings(txt: &TXT) -> String {
    let bytes: Vec<u8> = txt
        .txt_data
        .iter()
        .flat_map(|chunk| chunk.iter().copied())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Drops the trailing dot from a fully-qualified name so configured patterns
/// can be written the way people say hostnames.
pub(crate) fn strip_root(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_string()
}

/// Parses `dns.resolver` into an address, or `None` when it is unset.
///
/// An empty string is treated the same as unset, not a parse error: an env
/// var left unset by a caller using `${LAB_DNS_RESOLVER:-}`-style shell
/// defaults (as the podman-compose lab does) arrives here as `Some("")`, not
/// `None` — `config`'s environment source cannot tell "absent" from "present
/// but empty".
///
/// Shared by `challenge::from_config` and `filter::from_config` so an invalid
/// value is one consistent startup error, however it was spelled, rather than
/// each subsystem parsing it slightly differently.
pub fn resolver_addr(dns: &DnsConfig) -> anyhow::Result<Option<SocketAddr>> {
    match dns.resolver.as_deref() {
        None | Some("") => Ok(None),
        Some(addr) => addr.parse::<SocketAddr>().map(Some).map_err(|error| {
            anyhow::anyhow!("dns.resolver {addr:?} is not a valid address: {error}")
        }),
    }
}

/// Resolves `host` and connects to it on `port`, trying every address in
/// order — through `resolver` rather than the OS resolver, the point of
/// `config.dns.resolver` being that *every* lookup this server does for a
/// challenge goes through the same, possibly overridden, resolver, not just
/// the `dns-01` TXT query.
///
/// Trying every address, not just the first, matters: a name with both an A
/// and an AAAA record is the normal dual-stack case, and `TcpStream::connect`
/// used to do exactly this (via the OS resolver) before `http-01`/
/// `tls-alpn-01` started resolving explicitly — an unreachable first answer
/// (a stale AAAA, a resolver that defaults unmapped names to a loopback
/// address for anything it wasn't told about) must fall back rather than
/// failing the whole connection.
///
/// A literal IP address short-circuits without a lookup: a test pointing an
/// identifier straight at `127.0.0.1` should not depend on the resolver being
/// able to answer for it.
pub(crate) async fn connect(
    resolver: &dyn Resolver,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, String> {
    let ips = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => resolver.forward(host).await?,
    };
    if ips.is_empty() {
        return Err(format!("no address found for {host}"));
    }

    let mut last_error = None;
    for ip in ips {
        match tokio::net::TcpStream::connect((ip, port)).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(format!("{ip}: {error}")),
        }
    }
    Err(last_error.unwrap_or_else(|| format!("no address found for {host}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_root_removes_the_trailing_dot() {
        assert_eq!(strip_root("host.example.com."), "host.example.com");
        assert_eq!(strip_root("host.example.com"), "host.example.com");
    }

    /// RFC 1035 §3.3.14: a TXT record is a *sequence* of character-strings, each
    /// capped at 255 octets. A provider that pads or splits a value would
    /// otherwise never match, because the pieces arrive separately.
    #[test]
    fn txt_character_strings_are_concatenated() {
        let single = TXT::new(vec!["one-piece".to_string()]);
        assert_eq!(join_character_strings(&single), "one-piece");

        let split = TXT::new(vec!["first".to_string(), "second".to_string()]);
        assert_eq!(join_character_strings(&split), "firstsecond");

        // A record with no strings at all is the empty value, not a panic.
        assert_eq!(join_character_strings(&TXT::new(vec![])), "");
    }

    /// Non-UTF-8 in a TXT record is not a `dns-01` response; it must produce a
    /// value that simply fails the comparison rather than an error.
    #[test]
    fn non_utf8_txt_data_is_lossy_rather_than_fatal() {
        let raw = TXT::from_bytes(vec![&[0xff, 0xfe]]);
        let joined = join_character_strings(&raw);
        assert!(!joined.is_empty());
        assert_ne!(joined, "expected-digest");
    }

    /// Both constructors read the system configuration, which a minimal
    /// container may not have — so this asserts only that they agree about
    /// whether it is readable, never that the host can resolve.
    #[test]
    fn both_constructors_read_the_same_system_configuration() {
        assert_eq!(
            HickoryResolver::from_system().is_ok(),
            HickoryResolver::from_system_uncached().is_ok(),
        );
    }

    /// Building against an explicit address never touches the system
    /// configuration, so — unlike the constructors above — this must succeed
    /// unconditionally: no lookup happens at construction time, only later.
    #[test]
    fn from_address_builds_without_reading_system_configuration() {
        let addr: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        assert!(HickoryResolver::from_address(addr).is_ok());
        assert!(HickoryResolver::from_address_uncached(addr).is_ok());
    }

    /// A resolver that must never be asked anything — `connect` on a literal
    /// IP should not need one.
    struct UnreachableResolver;

    #[async_trait]
    impl Resolver for UnreachableResolver {
        async fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
            unreachable!("connect never looks up PTR records")
        }
        async fn forward(&self, _name: &str) -> Result<Vec<IpAddr>, String> {
            unreachable!("a literal IP must short-circuit before this is called")
        }
        async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
            unreachable!("connect never looks up TXT records")
        }
    }

    #[tokio::test]
    async fn connect_short_circuits_a_literal_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(
            connect(&UnreachableResolver, "127.0.0.1", port)
                .await
                .is_ok()
        );
    }

    struct StubForward(Vec<IpAddr>);

    #[async_trait]
    impl Resolver for StubForward {
        async fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
            unreachable!()
        }
        async fn forward(&self, _name: &str) -> Result<Vec<IpAddr>, String> {
            Ok(self.0.clone())
        }
        async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn connect_errors_when_forward_is_empty() {
        let error = connect(&StubForward(vec![]), "example.com", 1234)
            .await
            .unwrap_err();
        assert!(error.contains("example.com"), "{error}");
    }

    /// The regression this replaces `resolve_first` over: a dual-stack answer
    /// (an unreachable address first, a working one second — the shape of a
    /// stale/default AAAA record ahead of the real A record) must fall back
    /// rather than failing on the first refusal. `TcpStream::connect` used to
    /// do this via the OS resolver before http-01/tls-alpn-01 started
    /// resolving explicitly through `config.dns.resolver`.
    #[tokio::test]
    async fn connect_falls_back_past_an_unreachable_first_address() {
        // 127.0.0.0/8 is entirely loopback on Linux, so a second address on
        // the same port as an unbound one is a real "different candidate,
        // one refuses, one accepts" pair without touching the network.
        let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let unreachable_first = "127.0.0.1".parse().unwrap();
        let reachable_second = "127.0.0.2".parse().unwrap();
        let resolver = StubForward(vec![unreachable_first, reachable_second]);

        assert!(connect(&resolver, "example.com", port).await.is_ok());
    }

    #[tokio::test]
    async fn connect_errors_when_every_address_refuses() {
        // Bind then drop, so the port is almost certainly free and unbound.
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let resolver = StubForward(vec!["127.0.0.1".parse().unwrap()]);
        let error = connect(&resolver, "example.com", port).await.unwrap_err();
        assert!(error.contains("127.0.0.1"), "{error}");
    }

    #[test]
    fn resolver_addr_is_none_when_unset() {
        assert!(resolver_addr(&DnsConfig::default()).unwrap().is_none());
    }

    /// `${VAR:-}`-style shell defaults (the podman-compose lab's own pattern)
    /// produce an empty string, not an absent env var — this must not be a
    /// startup error.
    #[test]
    fn resolver_addr_treats_an_empty_string_as_unset() {
        let dns = DnsConfig {
            resolver: Some(String::new()),
        };
        assert!(resolver_addr(&dns).unwrap().is_none());
    }

    #[test]
    fn resolver_addr_parses_a_valid_socket_address() {
        let dns = DnsConfig {
            resolver: Some("10.60.0.2:53".to_string()),
        };
        assert_eq!(
            resolver_addr(&dns).unwrap(),
            Some("10.60.0.2:53".parse().unwrap())
        );
    }

    #[test]
    fn resolver_addr_rejects_a_hostname_without_a_port() {
        let dns = DnsConfig {
            resolver: Some("not-an-address".to_string()),
        };
        let error = resolver_addr(&dns).unwrap_err().to_string();
        assert!(error.contains("not-an-address"), "{error}");
    }

    /// A loopback authoritative nameserver, so the real `HickoryResolver`
    /// bodies run against real wire data.
    ///
    /// Every other test in this crate drives a stub `Resolver`, which is right
    /// for the *consumers* — but leaves the record decoding here (the PTR
    /// root-strip, the TXT character-string join, the "no records" versus
    /// "lookup failed" split) never actually executed against a DNS message.
    mod loopback {
        use super::*;
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::{A, PTR};
        use hickory_proto::rr::{DNSClass, Record, RecordType};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        use tokio::net::UdpSocket;

        /// Answers queries from `answers`, keyed by `(name, record type)`.
        /// Anything else gets an empty NOERROR — which hickory surfaces as an
        /// error, the very case `is_no_records_found` exists to tell apart.
        async fn spawn(answers: Vec<(&'static str, RecordType, RData)>) -> SocketAddr {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();

            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    let Ok((read, peer)) = socket.recv_from(&mut buffer).await else {
                        return;
                    };
                    let Ok(request) = Message::from_bytes(&buffer[..read]) else {
                        continue;
                    };
                    let query = request.queries.first().cloned();

                    let mut response = Message::response(request.id, OpCode::Query);
                    response.metadata.message_type = MessageType::Response;
                    response.metadata.authoritative = true;
                    response.metadata.response_code = ResponseCode::NoError;
                    if let Some(query) = &query {
                        response.queries.push(query.clone());
                        for (name, record_type, data) in &answers {
                            let name = Name::from_utf8(name).unwrap();
                            if query.name() == &name && query.query_type() == *record_type {
                                let mut record = Record::from_rdata(name, 60, data.clone());
                                record.dns_class = DNSClass::IN;
                                response.answers.push(record);
                            }
                        }
                    }
                    let bytes = response.to_bytes().unwrap();
                    let _ = socket.send_to(&bytes, peer).await;
                }
            });

            addr
        }

        /// A PTR answer comes back with its trailing root dot removed — the
        /// form `reverse_dns`'s regexes are written against.
        #[tokio::test]
        async fn reverse_returns_the_ptr_name_without_its_root_dot() {
            // Not a loopback address: hickory answers `127.0.0.1` from its
            // own built-in localhost zone without ever asking a nameserver.
            let addr = spawn(vec![(
                "10.2.0.192.in-addr.arpa.",
                RecordType::PTR,
                RData::PTR(PTR(Name::from_utf8("host.example.com.").unwrap())),
            )])
            .await;

            let names = HickoryResolver::from_address(addr)
                .unwrap()
                .reverse("192.0.2.10".parse().unwrap())
                .await
                .unwrap();
            assert_eq!(names, vec!["host.example.com".to_string()]);
        }

        #[tokio::test]
        async fn forward_returns_the_addresses() {
            let addr = spawn(vec![(
                "host.example.com.",
                RecordType::A,
                RData::A(A("192.0.2.10".parse().unwrap())),
            )])
            .await;

            let addresses = HickoryResolver::from_address(addr)
                .unwrap()
                .forward("host.example.com.")
                .await
                .unwrap();
            assert!(
                addresses.contains(&"192.0.2.10".parse::<IpAddr>().unwrap()),
                "{addresses:?}"
            );
        }

        /// The split-value case over the wire, not just through
        /// `join_character_strings` directly.
        #[tokio::test]
        async fn txt_returns_the_concatenated_value() {
            let addr = spawn(vec![(
                "_acme-challenge.example.com.",
                RecordType::TXT,
                RData::TXT(TXT::new(vec!["first".to_string(), "second".to_string()])),
            )])
            .await;

            let values = HickoryResolver::from_address_uncached(addr)
                .unwrap()
                .txt("_acme-challenge.example.com.")
                .await
                .unwrap();
            assert_eq!(values, vec!["firstsecond".to_string()]);
        }

        /// An empty NOERROR answer is "there is no such record", not a failed
        /// lookup — the distinction `reverse_dns` denies on rather than 500s
        /// on, and the bug the container lab originally caught.
        #[tokio::test]
        async fn an_empty_answer_is_no_records_rather_than_an_error() {
            let addr = spawn(Vec::new()).await;
            let resolver = HickoryResolver::from_address_uncached(addr).unwrap();

            assert_eq!(
                resolver
                    .reverse("192.0.2.10".parse().unwrap())
                    .await
                    .unwrap(),
                Vec::<String>::new()
            );
            assert_eq!(
                resolver.forward("nothing.example.com.").await.unwrap(),
                Vec::<IpAddr>::new()
            );
            assert_eq!(
                resolver.txt("nothing.example.com.").await.unwrap(),
                Vec::<String>::new()
            );
        }
    }
}
