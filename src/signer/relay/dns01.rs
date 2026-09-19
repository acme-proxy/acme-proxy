//! Publishing the `_acme-challenge` TXT record the *upstream* CA asks for.
//!
//! ## Why this exists at all
//!
//! Everywhere else in this codebase DNS is read-only: the `dns-01` validator
//! looks a TXT record up to check a client's claim. This module writes one,
//! and it is the only part of the server that does.
//!
//! The reason is the asymmetry at the heart of the proxy. When the upstream is
//! a real CA, it issues its own `dns-01` challenge, and the key authorization
//! it expects is computed from **this proxy's** account thumbprint at that
//! upstream — not the end client's. The two are different accounts on
//! different servers, so the original client *cannot* answer it even in
//! principle: only this server knows the right value. That is what makes the
//! relay a second, independent proof of domain control rather than a
//! pass-through, and why it needs the ability to write DNS.
//!
//! ## The record's content is not defined here
//!
//! [`crate::challenge::dns_01`] owns both the record name and the digest
//! computation, and this module calls into it. Restating either would risk the
//! publisher and the validator drifting into a record this server accepts but
//! a real CA rejects.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode, update_message};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::rdata::tsig::{TSIG, TsigAlgorithm, TsigError};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType, TSigner};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use acme_proxy_core::config::Rfc2136Config;

/// Publishes and retracts the TXT records an upstream `dns-01` challenge needs.
///
/// A trait rather than a concrete type so the orchestration in [`super`] can be
/// tested against a stub — the same seam `ChallengeValidator`'s `HttpFetcher`
/// and `Resolver` draw — and so a future provider (a cloud DNS API) slots in
/// without touching the relay.
#[async_trait]
pub trait DnsUpdater: Send + Sync {
    /// Publishes a TXT record at `name` holding `value`.
    ///
    /// Additive: an order for `example.com` and `*.example.com` produces two
    /// authorizations whose records live at the same name with different
    /// values, and both must be present at once.
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String>;

    /// Retracts a previously published record: only `value`, so any other value
    /// at `name` — another authorization's, or another order's for the same
    /// name — survives. Retracting a value that is not there is not an error.
    ///
    /// Best-effort: the relay logs a failure and carries on, because a leftover
    /// challenge record is untidy rather than harmful.
    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String>;
}

/// RFC 2136 dynamic DNS update, authenticated with TSIG.
///
/// Built on `hickory-proto`, which is already in the dependency tree via
/// `hickory-resolver` — the same "promote a transitive dependency to a direct
/// edge rather than add a crate" move this project makes for `x509-parser` and
/// `hyper`. Notably *not* `hickory-client`, whose 0.26 line is still a
/// pre-release; the message builders and the TSIG signer needed here all live
/// in `hickory-proto`, so the transport is a few lines of `tokio` instead.
///
/// Works against any authoritative server implementing RFC 2136 — BIND,
/// PowerDNS, Knot, CoreDNS with the `update` plugin — rather than binding the
/// server to one cloud vendor's API.
pub struct Rfc2136Updater {
    server: SocketAddr,
    zone: Name,
    signer: TSigner,
    timeout: Duration,
    /// TTL on published records. Deliberately short: a challenge record is
    /// wanted for seconds, and a long TTL keeps a stale value cached past the
    /// point the CA reads it.
    ttl: u32,
}

/// TTL for a published challenge record, in seconds.
const CHALLENGE_TTL: u32 = 60;

/// Budget for one update exchange.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

impl Rfc2136Updater {
    /// Validates the configuration and builds the TSIG signer.
    ///
    /// Every failure here is a startup error, matching how `filter` and
    /// `challenge` treat a bad CIDR or regex: a DNS credential that cannot be
    /// parsed will never start working on its own.
    pub fn from_config(cfg: &Rfc2136Config) -> anyhow::Result<Self> {
        use base64::prelude::*;

        if cfg.server.is_empty() {
            anyhow::bail!("signer.relay.dns01.rfc2136.server is not set");
        }
        let server: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&cfg.server)
            .map_err(|error| {
                anyhow::anyhow!("rfc2136.server ({}) failed to resolve: {error}", cfg.server)
            })?
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("rfc2136.server ({}) resolved to no addresses", cfg.server)
            })?;

        let zone = Name::from_utf8(&cfg.zone).map_err(|error| {
            anyhow::anyhow!("rfc2136.zone ({}) is not a DNS name: {error}", cfg.zone)
        })?;

        if cfg.tsig_key_name.is_empty() {
            anyhow::bail!("signer.relay.dns01.rfc2136.tsig_key_name is not set");
        }
        let key_name = Name::from_utf8(&cfg.tsig_key_name)
            .map_err(|error| anyhow::anyhow!("rfc2136.tsig_key_name is not a DNS name: {error}"))?;

        // TSIG secrets are conventionally handed out as standard base64 (that
        // is what `dnssec-keygen` and every BIND config use), unlike the EAB
        // secret's base64url.
        let secret = BASE64_STANDARD
            .decode(cfg.tsig_key_secret.trim())
            .map_err(|error| anyhow::anyhow!("rfc2136.tsig_key_secret is not base64: {error}"))?;
        if secret.is_empty() {
            anyhow::bail!("signer.relay.dns01.rfc2136.tsig_key_secret is empty");
        }

        let algorithm = tsig_algorithm(&cfg.tsig_algorithm)?;
        let signer = TSigner::new(secret, algorithm, key_name, 300)
            .map_err(|error| anyhow::anyhow!("TSIG signer unusable: {error}"))?;

        Ok(Self {
            server,
            zone,
            signer,
            timeout: UPDATE_TIMEOUT,
            ttl: CHALLENGE_TTL,
        })
    }

    /// One TXT record, as the update messages want it.
    fn txt_record(&self, name: &str, value: &str) -> Result<Record, String> {
        let name =
            Name::from_utf8(name).map_err(|error| format!("{name} is not a DNS name: {error}"))?;
        // The server would answer NOTZONE anyway; refusing here says why.
        if !self.zone.zone_of(&name) {
            return Err(format!("{name} is outside the zone {}", self.zone));
        }
        let mut record = Record::from_rdata(
            name,
            self.ttl,
            RData::TXT(TXT::new(vec![value.to_string()])),
        );
        record.dns_class = DNSClass::IN;
        Ok(record)
    }

    /// Signs and sends one update, returning an error unless the server
    /// answers NOERROR under the configured TSIG key.
    async fn send(&self, mut message: Message) -> Result<(), String> {
        // TSIG covers the whole message, so it must be applied last.
        let id = message.id;
        let mut verifier = message
            .finalize(&self.signer, now_secs())
            .map_err(|error| format!("signing the DNS update failed: {error}"))?
            .ok_or_else(|| "signing the DNS update produced no verifier".to_string())?;

        let bytes = message
            .to_bytes()
            .map_err(|error| format!("encoding the DNS update failed: {error}"))?;

        let answer = tokio::time::timeout(self.timeout, self.exchange(&bytes))
            .await
            .map_err(|_| format!("DNS update to {} timed out", self.server))??;

        let response = Message::from_bytes(&answer)
            .map_err(|error| format!("decoding the DNS response failed: {error}"))?;

        if response.id != id {
            return Err("DNS response id did not match the request".to_string());
        }

        // Only a success has to be authenticated (RFC 8945 §5.3). A forged
        // failure achieves nothing a dropped packet does not, while a wrong key
        // is answered *unsigned* — the server cannot sign with a key it does
        // not know — so verifying before reading the rcode would turn the
        // likeliest misconfiguration into an opaque signature error.
        match response.response_code {
            ResponseCode::NoError => verifier.verify(&answer).map(|_| ()).map_err(|error| {
                format!(
                    "DNS update answer from {} is not signed by the configured TSIG key: {error}",
                    self.server
                )
            }),
            other => Err(self.refusal(other, response.signature())),
        }
    }

    /// Words a refused update, naming the TSIG error the server attached.
    ///
    /// That error arrives unauthenticated, so it only ever adds a hint to a
    /// failure; the key name and algorithm quoted come from this server's own
    /// configuration, never from the answer.
    fn refusal(&self, code: ResponseCode, tsig: Option<&Record<TSIG>>) -> String {
        let hint = match tsig.and_then(|record| record.data.error) {
            None => String::new(),
            Some(TsigError::BadKey) => format!(
                "; the server does not know TSIG key {} ({}) — check tsig_key_name and tsig_algorithm",
                self.signer.signer_name(),
                self.signer.algorithm().to_name(),
            ),
            Some(TsigError::BadSig) => {
                "; the server rejected the TSIG signature — check tsig_key_secret".to_string()
            }
            Some(TsigError::BadTime) => {
                "; the server's clock and this host's differ by more than the TSIG fudge"
                    .to_string()
            }
            Some(other) => format!("; TSIG error {}", u16::from(other)),
        };
        format!("DNS update refused: {code}{hint}")
    }

    /// Sends over UDP, retrying on TCP when the answer is truncated — the
    /// ordinary DNS fallback, and necessary because a TSIG-signed update can
    /// exceed 512 bytes. A truncated answer is not verified: forging one only
    /// sends the update to the same server over TCP, whose answer `send` checks.
    ///
    /// The UDP socket is connected, so the kernel drops datagrams from any
    /// address but the server's: otherwise anyone who guessed the 16-bit id
    /// could answer for it.
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let bind: SocketAddr = if self.server.is_ipv4() {
            "0.0.0.0:0".parse().expect("a valid bind address")
        } else {
            "[::]:0".parse().expect("a valid bind address")
        };

        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|error| format!("binding a UDP socket failed: {error}"))?;
        socket
            .connect(self.server)
            .await
            .map_err(|error| format!("connecting to {} failed: {error}", self.server))?;
        socket
            .send(request)
            .await
            .map_err(|error| format!("sending to {} failed: {error}", self.server))?;

        let mut buffer = vec![0u8; 4096];
        let read = socket
            .recv(&mut buffer)
            .await
            .map_err(|error| format!("no answer from {}: {error}", self.server))?;
        buffer.truncate(read);

        // A truncated answer means "ask again over TCP" (RFC 1035 §4.2.1).
        if Message::from_bytes(&buffer)
            .map(|message| message.truncation)
            .unwrap_or(false)
        {
            debug!(
                event = "signer_relay_dns_01_update_truncated",
                outcome = "progress"
            );
            return self.exchange_tcp(request).await;
        }
        Ok(buffer)
    }

    async fn exchange_tcp(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = TcpStream::connect(self.server)
            .await
            .map_err(|error| format!("connecting to {} failed: {error}", self.server))?;

        // DNS over TCP frames each message with a two-byte length prefix.
        let length = u16::try_from(request.len())
            .map_err(|_| "the DNS update is too large for TCP framing".to_string())?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|error| format!("writing to {} failed: {error}", self.server))?;
        stream
            .write_all(request)
            .await
            .map_err(|error| format!("writing to {} failed: {error}", self.server))?;

        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error| format!("reading from {} failed: {error}", self.server))?;
        let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| format!("reading from {} failed: {error}", self.server))?;
        Ok(response)
    }
}

#[async_trait]
impl DnsUpdater for Rfc2136Updater {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let record = self.txt_record(name, value)?;
        let mut rrset = RecordSet::new(record.name.clone(), RecordType::TXT, 0);
        rrset.insert(record, 0);

        // `append` with `must_exist = false` adds this value alongside any
        // already at the name, rather than replacing them — required when an
        // order covers both `example.com` and `*.example.com`, whose two
        // authorizations publish different values at the same name.
        let message = update_message::append(rrset, self.zone.clone(), false, true);
        self.send(message).await
    }

    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let record = self.txt_record(name, value)?;
        let mut rrset = RecordSet::new(record.name.clone(), RecordType::TXT, 0);
        rrset.insert(record, 0);

        // By rdata (RFC 2136 §2.5.4), not the whole RRset (§2.5.2): the name is
        // shared by every value `upsert_txt` appends, and deleting the set
        // would pull a concurrent order's record out from under its CA.
        let message = update_message::delete_by_rdata(rrset, self.zone.clone(), true);
        self.send(message).await
    }
}

/// Maps the configured algorithm name to hickory's enum. Only the HMAC-SHA2
/// family is offered: HMAC-MD5 is still widely configured but is not something
/// to add a fresh deployment to.
fn tsig_algorithm(name: &str) -> anyhow::Result<TsigAlgorithm> {
    match name.trim().to_ascii_lowercase().as_str() {
        "" | "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
        "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
        other => anyhow::bail!(
            "unknown rfc2136.tsig_algorithm: {other} (supported: hmac-sha256, hmac-sha384, hmac-sha512)"
        ),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Rfc2136Config {
        use base64::prelude::*;
        Rfc2136Config {
            server: "127.0.0.1:53".to_string(),
            zone: "example.org.".to_string(),
            tsig_key_name: "acme-key.".to_string(),
            tsig_key_secret: BASE64_STANDARD.encode(b"0123456789abcdef0123456789abcdef"),
            tsig_algorithm: "hmac-sha256".to_string(),
        }
    }

    #[test]
    fn a_well_formed_config_builds() {
        let updater = Rfc2136Updater::from_config(&config()).unwrap();
        assert_eq!(updater.server.port(), 53);
        assert_eq!(updater.zone.to_utf8(), "example.org.");
    }

    /// Each of these is a credential or address that will never start working
    /// on its own, so each must stop the server at startup rather than fail
    /// silently the first time a certificate is needed.
    #[test]
    fn every_malformed_field_is_a_startup_error() {
        /// One case: the fragment expected in the error, and how to break the
        /// config to provoke it.
        type Case = (&'static str, Box<dyn Fn(&mut Rfc2136Config)>);

        let cases: Vec<Case> = vec![
            (
                "server",
                Box::new(|c: &mut Rfc2136Config| c.server = String::new()),
            ),
            (
                "failed to resolve",
                Box::new(|c: &mut Rfc2136Config| c.server = "not-an-address".to_string()),
            ),
            (
                "tsig_key_name",
                Box::new(|c: &mut Rfc2136Config| c.tsig_key_name = String::new()),
            ),
            (
                "base64",
                Box::new(|c: &mut Rfc2136Config| {
                    c.tsig_key_secret = "!!!not base64!!!".to_string()
                }),
            ),
            (
                "empty",
                Box::new(|c: &mut Rfc2136Config| c.tsig_key_secret = String::new()),
            ),
            (
                "tsig_algorithm",
                Box::new(|c: &mut Rfc2136Config| c.tsig_algorithm = "hmac-md5".to_string()),
            ),
        ];

        for (expected, mutate) in cases {
            let mut cfg = config();
            mutate(&mut cfg);
            let error = Rfc2136Updater::from_config(&cfg)
                .err()
                .unwrap_or_else(|| panic!("{expected}: this configuration must not build"))
                .to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?} in the error, got: {error}"
            );
        }
    }

    /// An empty algorithm means "the default", so an operator who never set
    /// the key gets HMAC-SHA256 rather than a startup failure.
    #[test]
    fn the_algorithm_defaults_to_sha256() {
        assert!(matches!(tsig_algorithm(""), Ok(TsigAlgorithm::HmacSha256)));
        assert!(matches!(
            tsig_algorithm("HMAC-SHA512"),
            Ok(TsigAlgorithm::HmacSha512)
        ));
    }

    #[test]
    fn a_record_carries_the_value_and_a_short_ttl() {
        let updater = Rfc2136Updater::from_config(&config()).unwrap();
        let record = updater
            .txt_record("_acme-challenge.example.org.", "digest-value")
            .unwrap();

        assert_eq!(record.ttl, CHALLENGE_TTL);
        assert_eq!(record.record_type(), RecordType::TXT);
        match &record.data {
            RData::TXT(txt) => {
                assert_eq!(txt.to_string(), "digest-value");
            }
            other => panic!("expected a TXT record, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_record_name_is_rejected() {
        let updater = Rfc2136Updater::from_config(&config()).unwrap();
        assert!(updater.txt_record("not a dns name", "value").is_err());
    }

    /// The zone bounds what the key may write: a name elsewhere is refused
    /// before the socket, while the apex and a differently-cased name inside
    /// are still the zone's.
    #[test]
    fn a_name_outside_the_zone_is_rejected() {
        let updater = Rfc2136Updater::from_config(&config()).unwrap();
        let error = updater
            .txt_record("_acme-challenge.example.net.", "value")
            .unwrap_err();
        assert!(error.contains("outside the zone"), "{error}");
        assert!(updater.txt_record("example.org.", "value").is_ok());
        assert!(
            updater
                .txt_record("_acme-challenge.WWW.Example.ORG.", "value")
                .is_ok()
        );
    }

    /// A loopback RFC 2136 responder: one UDP socket and one TCP listener on
    /// the same port, answering whatever the test scripted.
    ///
    /// Same technique as the loopback servers in `src/tls.rs` and
    /// `src/filter/netbox/client.rs` — the transport here (framing, the
    /// truncation retry) is only meaningfully exercised against a real socket.
    mod stub {
        use super::*;
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        pub(super) struct Server {
            pub(super) addr: SocketAddr,
        }

        /// What the stub should do with the UDP request it receives.
        #[derive(Clone, Copy)]
        pub(super) enum Udp {
            /// Answer over UDP with this response code, signed this way.
            Answer(ResponseCode, Sign),
            /// Answer unsigned with the truncation bit set, forcing a TCP
            /// retry whose NOERROR is signed this way.
            Truncated(Sign),
            /// Answer with a mismatched id.
            WrongId,
            /// Answer with bytes that are not a DNS message at all.
            Garbage,
        }

        /// Binds UDP and TCP on one loopback port and serves exactly one
        /// exchange on each.
        pub(super) async fn spawn(udp: Udp) -> Server {
            // The TCP listener picks the port; UDP then takes the same number.
            // Retried because the two are independent namespaces and the
            // chosen port could already be taken on the UDP side.
            let (tcp, socket) = loop {
                let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = tcp.local_addr().unwrap().port();
                match UdpSocket::bind(("127.0.0.1", port)).await {
                    Ok(socket) => break (tcp, socket),
                    Err(_) => continue,
                }
            };
            let addr = tcp.local_addr().unwrap();

            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let (read, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_bytes(&buffer[..read]).unwrap();

                let bytes = match udp {
                    Udp::Garbage => b"definitely not DNS".to_vec(),
                    Udp::Answer(code, sign) => reply(&request, request.id, code, false, sign),
                    Udp::WrongId => reply(
                        &request,
                        request.id.wrapping_add(1),
                        ResponseCode::NoError,
                        false,
                        Sign::Valid,
                    ),
                    Udp::Truncated(_) => reply(
                        &request,
                        request.id,
                        ResponseCode::NoError,
                        true,
                        Sign::Unsigned,
                    ),
                };
                socket.send_to(&bytes, peer).await.unwrap();
            });

            tokio::spawn(async move {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    return;
                };
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut request = vec![0u8; u16::from_be_bytes(length) as usize];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let Ok(request) = Message::from_bytes(&request) else {
                    return;
                };
                let sign = match udp {
                    Udp::Truncated(sign) => sign,
                    _ => Sign::Valid,
                };
                let bytes = reply(&request, request.id, ResponseCode::NoError, false, sign);
                let framed = u16::try_from(bytes.len()).unwrap().to_be_bytes();
                let _ = stream.write_all(&framed).await;
                let _ = stream.write_all(&bytes).await;
            });

            Server { addr }
        }

        fn reply(
            request: &Message,
            id: u16,
            code: ResponseCode,
            truncated: bool,
            sign: Sign,
        ) -> Vec<u8> {
            let mut message = Message::response(id, OpCode::Update);
            message.metadata.message_type = MessageType::Response;
            message.metadata.response_code = code;
            message.metadata.truncation = truncated;
            super::sign_reply(&mut message, request, sign);
            message.to_bytes().unwrap()
        }
    }

    /// How a stub answer carries (or fails to carry) its TSIG.
    #[derive(Clone, Copy)]
    enum Sign {
        /// Signed as a real server signs: this key, this request's MAC, now.
        Valid,
        Unsigned,
        /// Signed, but with a secret the updater does not hold.
        OtherKey,
        /// Signed, but chained to a MAC this request never carried.
        OtherRequest,
        /// Signed, but stamped well outside the fudge window.
        Stale,
        /// What a server sends for a key name it does not know: an empty
        /// MAC and TSIG error BADKEY (RFC 8945 §5.2.1).
        UnknownKey,
        /// What a server sends when the MAC does not verify: an empty MAC
        /// and TSIG error BADSIG (RFC 8945 §5.2.2).
        BadSig,
    }

    /// Attaches the TSIG `sign` describes to `response`, which must be
    /// otherwise complete: the MAC covers every byte already there.
    ///
    /// Uses hickory's own server-side signer, so the stub signs exactly as
    /// hickory's server does rather than as this module reads it.
    fn sign_reply(response: &mut Message, request: &Message, sign: Sign) {
        use base64::prelude::*;
        use hickory_proto::rr::TSigResponseContext;

        let theirs = request.signature().expect("the update is signed");
        let signer = |secret: Vec<u8>| {
            TSigner::new(
                secret,
                theirs.data.algorithm.clone(),
                theirs.name.clone(),
                300,
            )
            .unwrap()
        };
        let secret = BASE64_STANDARD.decode(config().tsig_key_secret).unwrap();
        let mac = theirs.data.mac.clone();
        let now = now_secs();

        let context = match sign {
            Sign::Unsigned => return,
            Sign::Valid => TSigResponseContext::new(response.id, now, signer(secret), mac, None),
            Sign::OtherKey => TSigResponseContext::new(
                response.id,
                now,
                signer(b"not the configured secret".to_vec()),
                mac,
                None,
            ),
            Sign::OtherRequest => {
                TSigResponseContext::new(response.id, now, signer(secret), vec![0; mac.len()], None)
            }
            Sign::Stale => {
                TSigResponseContext::new(response.id, now - 1000, signer(secret), mac, None)
            }
            Sign::UnknownKey => {
                TSigResponseContext::unknown_key(response.id, now, theirs.name.clone())
            }
            Sign::BadSig => TSigResponseContext::bad_signature(response.id, now, signer(secret)),
        };
        let record = context.sign(&response.to_bytes().unwrap()).unwrap();
        response.set_signature(record);
    }

    /// Points a fresh updater at `addr` with a short budget.
    fn updater_for(addr: SocketAddr) -> Rfc2136Updater {
        let mut cfg = config();
        cfg.server = addr.to_string();
        let mut updater = Rfc2136Updater::from_config(&cfg).unwrap();
        updater.timeout = Duration::from_secs(5);
        updater
    }

    /// The happy path over a real socket: sign, frame, send, verify the
    /// answer's TSIG, read the rcode — under every algorithm offered, since
    /// each has its own MAC length and hickory refuses a short one.
    #[tokio::test]
    async fn an_accepted_update_succeeds() {
        for algorithm in ["hmac-sha256", "hmac-sha384", "hmac-sha512"] {
            let server = stub::spawn(stub::Udp::Answer(ResponseCode::NoError, Sign::Valid)).await;
            let mut cfg = config();
            cfg.server = server.addr.to_string();
            cfg.tsig_algorithm = algorithm.to_string();
            Rfc2136Updater::from_config(&cfg)
                .unwrap()
                .upsert_txt("_acme-challenge.example.org.", "digest-value")
                .await
                .unwrap_or_else(|error| panic!("{algorithm}: {error}"));
        }
    }

    /// Retraction runs the same exchange with a delete message — best-effort at
    /// the call site, but it still has to reach the server.
    #[tokio::test]
    async fn a_retraction_reaches_the_server() {
        let server = stub::spawn(stub::Udp::Answer(ResponseCode::NoError, Sign::Valid)).await;
        updater_for(server.addr)
            .delete_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect("NOERROR is an accepted retraction");
    }

    /// A refusal is the shape of a wrong TSIG key or a zone this server is not
    /// authoritative for — the most likely misconfiguration in production, and
    /// it must surface with the response code in the message.
    #[tokio::test]
    async fn a_refused_update_reports_the_response_code() {
        let server = stub::spawn(stub::Udp::Answer(ResponseCode::Refused, Sign::Valid)).await;
        let error = updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect_err("REFUSED is not an accepted update");
        assert!(error.contains("DNS update refused"), "{error}");
        assert!(error.contains("Refused"), "{error}");
    }

    /// A TSIG-signed update readily exceeds 512 bytes, so the truncation
    /// fallback is a normal path here rather than an edge case.
    #[tokio::test]
    async fn a_truncated_answer_is_retried_over_tcp() {
        let server = stub::spawn(stub::Udp::Truncated(Sign::Valid)).await;
        updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect("the TCP retry must carry the answer");
    }

    /// The answer that decides is the TCP one, and it is held to the same
    /// rule as a UDP answer.
    #[tokio::test]
    async fn an_unsigned_answer_over_tcp_is_rejected() {
        let server = stub::spawn(stub::Udp::Truncated(Sign::Unsigned)).await;
        let error = updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect_err("an unsigned NOERROR over TCP is not an accepted update");
        assert!(error.contains("not signed"), "{error}");
    }

    /// An answer to somebody else's question is not an answer to this one —
    /// on an unconnected UDP socket that is a real possibility.
    #[tokio::test]
    async fn a_mismatched_response_id_is_rejected() {
        let server = stub::spawn(stub::Udp::WrongId).await;
        let error = updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect_err("a foreign id is not this update's answer");
        assert!(error.contains("did not match"), "{error}");
    }

    /// Bytes that do not decode are reported rather than treated as success.
    #[tokio::test]
    async fn an_undecodable_response_is_reported() {
        let server = stub::spawn(stub::Udp::Garbage).await;
        let error = updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
            .expect_err("garbage is not a DNS response");
        assert!(error.contains("decoding the DNS response"), "{error}");
    }

    /// A record name that is not a DNS name never reaches the socket, on
    /// either hook.
    #[tokio::test]
    async fn a_malformed_name_fails_before_the_socket() {
        let updater = updater_for("127.0.0.1:1".parse().unwrap());
        assert!(updater.upsert_txt("not a dns name", "v").await.is_err());
        assert!(updater.delete_txt("not a dns name", "v").await.is_err());
    }

    /// A server that never answers must be given up on, not waited for
    /// indefinitely — the relay has its own budget to respect.
    #[tokio::test]
    async fn an_unanswered_update_times_out() {
        // A bound socket that never reads: an unbound port would draw an ICMP
        // refusal, which the connected socket reports at once.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = config();
        cfg.server = silent.local_addr().unwrap().to_string();
        let mut updater = Rfc2136Updater::from_config(&cfg).unwrap();
        updater.timeout = Duration::from_millis(100);

        let error = updater
            .upsert_txt("_acme-challenge.example.org.", "value")
            .await
            .unwrap_err();
        assert!(
            error.contains("timed out") || error.contains("failed"),
            "{error}"
        );
    }

    /// Receives one update on `socket`, answers it NOERROR from the same
    /// socket, and hands back the decoded request.
    async fn answer_one(socket: &UdpSocket) -> Message {
        use hickory_proto::op::{MessageType, OpCode};

        let mut buffer = vec![0u8; 4096];
        let (read, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_bytes(&buffer[..read]).unwrap();

        let mut response = Message::response(request.id, OpCode::Update);
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::NoError;
        sign_reply(&mut response, &request, Sign::Valid);
        socket
            .send_to(&response.to_bytes().unwrap(), peer)
            .await
            .unwrap();
        request
    }

    /// The update section on the wire, not just the arguments: an append is
    /// CLASS IN with the challenge TTL, and a retraction names its value with
    /// CLASS NONE and TTL 0 (RFC 2136 §2.5.4) — never CLASS ANY, which would
    /// delete every value at the name.
    #[tokio::test]
    async fn a_retraction_removes_only_its_value() {
        use hickory_proto::op::OpCode;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let updater = updater_for(socket.local_addr().unwrap());
        let name = Name::from_utf8("_acme-challenge.example.org.").unwrap();
        let txt = RData::TXT(TXT::new(vec!["digest-value".to_string()]));

        for (retract, class, ttl) in [
            (false, DNSClass::IN, CHALLENGE_TTL),
            (true, DNSClass::NONE, 0),
        ] {
            let (request, sent) = tokio::join!(answer_one(&socket), async {
                if retract {
                    updater.delete_txt(&name.to_utf8(), "digest-value").await
                } else {
                    updater.upsert_txt(&name.to_utf8(), "digest-value").await
                }
            });
            sent.unwrap();

            assert_eq!(request.op_code, OpCode::Update);
            assert_eq!(request.queries.len(), 1);
            assert_eq!(request.queries[0].name(), &updater.zone);
            assert_eq!(request.authorities.len(), 1, "one update record");
            let record = &request.authorities[0];
            assert_eq!(record.name, name);
            assert_eq!(record.dns_class, class);
            assert_eq!(record.ttl, ttl);
            assert_eq!(record.data, txt);
        }
    }

    /// A well-formed answer with the right id, but from another address, is not
    /// the server's: the connected socket never delivers it.
    #[tokio::test]
    async fn a_response_from_another_address_is_ignored() {
        use hickory_proto::op::{MessageType, OpCode};

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut updater = updater_for(server.local_addr().unwrap());
        updater.timeout = Duration::from_millis(200);

        let spoof = async {
            let mut buffer = vec![0u8; 4096];
            let (read, peer) = server.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_bytes(&buffer[..read]).unwrap();

            let mut response = Message::response(request.id, OpCode::Update);
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::NoError;
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            other
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            // Outlive the updater's budget so the socket is not dropped early.
            tokio::time::sleep(Duration::from_millis(400)).await;
        };
        let (_, result) = tokio::join!(
            spoof,
            updater.upsert_txt("_acme-challenge.example.org.", "digest-value")
        );

        let error = result.expect_err("an answer from elsewhere is not accepted");
        assert!(error.contains("timed out"), "{error}");
    }

    /// Sends one upsert to a stub answering NOERROR signed as `sign` says.
    async fn accepted_with(sign: Sign) -> Result<(), String> {
        let server = stub::spawn(stub::Udp::Answer(ResponseCode::NoError, sign)).await;
        updater_for(server.addr)
            .upsert_txt("_acme-challenge.example.org.", "digest-value")
            .await
    }

    /// NOERROR is the one answer that makes the relay go on to ask the CA to
    /// validate, so it is the one that must prove it came from the key holder.
    #[tokio::test]
    async fn an_unsigned_acceptance_is_rejected() {
        let error = accepted_with(Sign::Unsigned).await.unwrap_err();
        assert!(
            error.contains("not signed by the configured TSIG key"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_acceptance_signed_with_another_key_is_rejected() {
        let error = accepted_with(Sign::OtherKey).await.unwrap_err();
        assert!(error.contains("not signed"), "{error}");
    }

    /// A signature is bound to the request it answers (RFC 8945 §4.3), so a
    /// validly signed answer to some other update cannot be replayed here.
    #[tokio::test]
    async fn an_acceptance_signed_for_another_request_is_rejected() {
        let error = accepted_with(Sign::OtherRequest).await.unwrap_err();
        assert!(error.contains("not signed"), "{error}");
    }

    #[tokio::test]
    async fn a_stale_signed_acceptance_is_rejected() {
        let error = accepted_with(Sign::Stale).await.unwrap_err();
        assert!(error.contains("not signed"), "{error}");
    }

    /// A wrong key is answered unsigned, because the server cannot sign with
    /// a key it does not know. That refusal must keep its rcode and gain the
    /// TSIG error's meaning, not collapse into a signature failure.
    #[tokio::test]
    async fn an_unsigned_refusal_keeps_its_diagnosis() {
        for (sign, expected) in [
            (
                Sign::UnknownKey,
                "does not know TSIG key acme-key. (hmac-sha256) — check tsig_key_name",
            ),
            (Sign::BadSig, "check tsig_key_secret"),
        ] {
            let server = stub::spawn(stub::Udp::Answer(ResponseCode::NotAuth, sign)).await;
            let error = updater_for(server.addr)
                .upsert_txt("_acme-challenge.example.org.", "digest-value")
                .await
                .unwrap_err();
            assert!(error.starts_with("DNS update refused: "), "{error}");
            assert!(!error.contains("not signed"), "{error}");
            assert!(error.contains(expected), "{error}");
        }
    }

    /// The hint is chosen off the TSIG error alone; a refusal carrying none
    /// reads exactly as it did before verification existed.
    #[test]
    fn a_refusal_names_each_tsig_error() {
        use hickory_proto::rr::rdata::tsig::make_tsig_record;

        let updater = Rfc2136Updater::from_config(&config()).unwrap();
        let with = |error: Option<TsigError>| {
            let tsig = TSIG::new(
                TsigAlgorithm::HmacSha256,
                0,
                300,
                Vec::new(),
                0,
                error,
                Vec::new(),
            );
            updater.refusal(
                ResponseCode::NotAuth,
                Some(&make_tsig_record(Name::root(), tsig)),
            )
        };

        let plain = updater.refusal(ResponseCode::Refused, None);
        assert_eq!(
            plain,
            format!("DNS update refused: {}", ResponseCode::Refused)
        );
        assert_eq!(
            with(None),
            format!("DNS update refused: {}", ResponseCode::NotAuth)
        );
        assert!(with(Some(TsigError::BadTime)).contains("clock"));
        assert!(with(Some(TsigError::BadTrunc)).ends_with("; TSIG error 22"));
        assert!(with(Some(TsigError::Unknown(99))).ends_with("; TSIG error 99"));
    }
}
