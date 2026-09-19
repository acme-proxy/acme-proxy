//! Scratch-directory and script helpers shared by the crate's unit tests.
//!
//! `TempDir` had grown seven independent copies (`tls`, `pemfile`,
//! `signer::custom`, `signer::relay`, `filter::custom`, `notify::custom`,
//! and one in the integration harness), and `write_script` four — including a
//! verbatim ten-line comment about `ETXTBSY`, which is the sort of hard-won
//! explanation that should exist in one place or it stops being maintained in
//! any of them.
//!
//! `#[cfg(test)]` rather than a real module: this is scaffolding, and shipping
//! it in the library would be shipping test code to every consumer. Integration
//! tests cannot see it for the same reason and keep their own copy under
//! `tests/common/`.

use std::sync::Arc;

/// A Prometheus registry for a test that only needs one to exist.
///
/// Every `RelaySigner::from_config` takes one because the backend counts a
/// deferred issuance through it; almost no test asserts on the counters, so
/// this keeps the noise to one call.
pub(crate) fn test_metrics(
    database: Arc<acme_proxy_store::db::Database>,
) -> Arc<crate::metrics::Metrics> {
    Arc::new(crate::metrics::Metrics::new(database))
}

/// No proxy at all — what every test that is not *about* proxying wants.
pub(crate) fn no_proxies() -> std::sync::Arc<crate::proxy::OutboundProxies> {
    std::sync::Arc::new(crate::proxy::OutboundProxies::direct())
}

/// Outbound transport for a test: the given resolver and no proxy.
///
/// The pair used to be passed separately at every one of these call sites, and
/// `no_proxies()` names what it is for — a test that is not *about* proxying.
pub(crate) fn outbound_with(
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> crate::http_client::Outbound {
    crate::http_client::Outbound::new(resolver, no_proxies())
}

/// A job queue with nothing draining it.
///
/// What every test that merely has to *construct* a signer backend wants: the
/// queue is a constructor argument since the `relay` backend defers issuance
/// into it, and a test asserting on a startup refusal or a synchronous backend
/// never enqueues anything. A test that needs the work actually done starts a
/// runner over its own queue instead — see `signer::relay::tests::TestRunner`.
pub(crate) fn idle_job_queue(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
) -> crate::jobs::JobQueue {
    crate::jobs::JobQueue::new(database, &acme_proxy_core::config::JobsConfig::default())
}

/// Egress for a test: the given resolver, no proxy, and an identity nothing
/// compares against.
///
/// The identity only matters to `signer::build_backends`, which uses it to
/// decide whether a reload has to rebuild a backend. A test constructing one
/// directly has no previous generation, so any value does.
pub(crate) fn egress_with(
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> std::sync::Arc<crate::egress::Egress> {
    std::sync::Arc::new(crate::egress::Egress {
        resolver,
        proxies: no_proxies(),
        identity: "test".to_string(),
    })
}

/// The dependencies a signer backend is built from, for a test that is not about
/// any of them.
///
/// No notifiers (nothing dispatches), a registry nothing scrapes and a queue
/// nothing drains — the same three "throwaway" arguments every one of these call
/// sites used to spell out one by one before `SignerParts` gathered them.
pub(crate) fn signer_parts(
    database: std::sync::Arc<acme_proxy_store::db::Database>,
    resolver: std::sync::Arc<dyn crate::dns::Resolver>,
) -> crate::signer::SignerParts {
    crate::signer::SignerParts {
        database: database.clone(),
        notifiers: std::collections::HashMap::new().into(),
        metrics: test_metrics(database.clone()),
        egress: egress_with(resolver),
        jobs: idle_job_queue(database),
    }
}

/// How a [`FakeProxy`] answers the request it is handed.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum ProxyBehaviour {
    /// Answer a `CONNECT` with this literal status line and headers (the
    /// trailing blank line is added), then splice the two sockets together.
    ///
    /// The status line is a parameter because real proxies do not agree on it:
    /// squid answers `HTTP/1.0 200 Connection established` with a `Proxy-Agent`
    /// header, which is what the framing here has to survive.
    Tunnel {
        status: &'static str,
        /// Ignore the `CONNECT` target's host and dial `127.0.0.1` on this port
        /// instead, so a test can use a real *name* in the request — which is
        /// what an SNI assertion needs — without that name having to resolve.
        force_port: Option<u16>,
    },
    /// Refuse, with this literal response including its body — the `407` shape.
    Refuse(&'static str),
    /// Answer a forwarded (absolute-form) request with this literal response.
    Forward(&'static str),
}

/// A loopback forward proxy that records what it was asked for.
///
/// Real proxies are not available in a unit test and a container would be a
/// different suite; what this has to prove is the wire shape — the `CONNECT`
/// request-target, the absolute-form request line, `Proxy-Authorization`, and
/// that a tunnel really carries bytes end to end.
#[cfg(test)]
pub(crate) struct FakeProxy {
    pub port: u16,
    /// The head of every request this proxy received, in order.
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Connections accepted. A bypass test asserts this is zero, which no
    /// assertion about the *response* could ever prove.
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl FakeProxy {
    pub(crate) async fn start(behaviour: ProxyBehaviour) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let seen = requests.clone();
        let counter = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let seen = seen.clone();
                tokio::spawn(async move {
                    // Read exactly the head: anything past the blank line is the
                    // tunnelled payload and belongs to the far end.
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while stream.read_exact(&mut byte).await.is_ok() {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let target = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    seen.lock().unwrap().push(head);

                    match behaviour {
                        ProxyBehaviour::Refuse(response) => {
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        ProxyBehaviour::Forward(response) => {
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        ProxyBehaviour::Tunnel { status, force_port } => {
                            let target = match force_port {
                                Some(port) => format!("127.0.0.1:{port}"),
                                None => target,
                            };
                            let Ok(mut upstream) = tokio::net::TcpStream::connect(&target).await
                            else {
                                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                                return;
                            };
                            let _ = stream.write_all(status.as_bytes()).await;
                            let _ = stream.write_all(b"\r\n").await;
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        }
                    }
                });
            }
        });

        Self {
            port,
            requests,
            connections,
        }
    }

    /// `http://127.0.0.1:<port>`, for a `proxy.http_url`/`https_url`.
    pub(crate) fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The CRL `backend` serves once a worker has met it — its first CRL stored,
/// the way the startup `CrlSweepJob` pass leaves it — read through its read
/// side, which is what `GET /crl` does.
pub(crate) async fn served_crl(backend: &dyn crate::signer::SignerBackend) -> Vec<u8> {
    if let Some(refresher) = backend.crl_refresher() {
        refresher.refresh().await.unwrap();
    }
    backend
        .info()
        .crl_der()
        .await
        .unwrap()
        .expect("a local CA serves a CRL")
}
