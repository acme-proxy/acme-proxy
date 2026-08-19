//! The sockets, and replacing one while it is serving.
//!
//! This server binds up to three sockets — ACME, the web admin, the metrics
//! endpoint — and until this module existed each was handed straight to
//! `axum::serve`, which **consumes** its listener. That made the socket the one
//! thing a configuration generation could not replace: `server.bind_address`,
//! `admin.enabled` and both `tls.enabled` flips were refused by name and needed
//! a restart, while everything else about a reload was a rebuild and a swap.
//!
//! What replaces it is one `axum::serve` per role, for the life of the process,
//! over a [`RoleListener`] that owns the accept loop itself. Two things are
//! swappable underneath it, and both are read **per connection**:
//!
//! - the TCP socket, replaced through a channel — a rebind, with connections
//!   already established untouched, because hyper owns those and only the
//!   socket beneath them changes;
//! - `Option<TlsSettings>`, so turning TLS on or off is the same kind of change
//!   as renewing a certificate rather than a different listener type. **A
//!   `tls.enabled` flip on an unchanged address therefore rebinds nothing at
//!   all**, which is what removes the one case a bind-then-drain scheme cannot
//!   serve: two listeners cannot hold one port while the old one drains.
//!
//! A role with no socket **parks**. That is how `admin.enabled = false` and
//! `metrics.enabled = false` are expressed, at startup as on a reload, and it is
//! the same answer this loop already gave when its accept task ended: there is
//! no error in [`Listener::accept`]'s signature, and returning a connection is
//! impossible, so parking is what is left.
//!
//! Provisioning the TLS material — reading or generating the files, building the
//! rustls acceptor — stays in [`crate::tls`]. The line between the two modules is
//! the one that file's own documentation already drew: resolving configuration
//! at startup on one side, accepting connections on the other.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::serve::{Listener, ListenerExt, TapIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

use crate::tls::TlsSettings;

/// How many connections may sit between the TCP accept and `axum` — handshakes
/// in flight plus finished streams not yet picked up.
///
/// This is the accept loop's backpressure: it reserves a slot *before* accepting,
/// so a flood of half-open TLS connections cannot spawn tasks without bound. It
/// now bounds the cleartext path too, which used to be `axum::serve`'s own
/// unbounded accept loop — backpressure it did not have, ahead of the admission
/// control that bounds what happens next.
const MAX_PENDING_CONNECTIONS: usize = 256;

/// Pause after a failed `accept()`, so a listener that is refusing connections
/// (out of file descriptors, say) does not spin a core. Mirrors what
/// `axum::serve` does for the same case.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// A connection, however it was accepted.
///
/// The `Io` type all three roles share, and the reason one `axum::serve` can
/// outlive a `tls.enabled` flip: the listener answers with a different variant
/// from one connection to the next without its own type changing.
///
/// The TLS half is boxed because `TlsStream` carries a whole rustls connection
/// state — roughly two orders of magnitude larger than a `TcpStream` — and this
/// enum is as big as its largest variant on every cleartext connection too.
pub enum MaybeTls {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }

    /// Delegated rather than left to the default, which would write one buffer
    /// per call: hyper writes a response's head and body as separate slices, so
    /// the vectored path is the ordinary one rather than an optimisation.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(context, buffers),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

/// What a reload does to one role's socket.
///
/// The `Serve` variant carries an **already bound** listener, which is the whole
/// ordering rule: binding happens where a failure can still refuse the reload,
/// not here, where nothing could be done about it.
pub enum SocketCommand {
    /// Serve this socket from now on, dropping whatever was being served.
    Serve(TcpListener),
    /// Stop accepting and release the socket — the role was switched off.
    Close,
}

/// The write side of one role's listener: its socket, and its TLS mode.
///
/// Held by the reload supervisor and by nothing else. **Both sends are
/// synchronous** (`watch::Sender::send_replace`, and an unbounded
/// `mpsc::Sender::send`), which is what lets a socket change sit in the same
/// uninterruptible publishing run as the routers and the job registry — see
/// `cli::apply_reload`.
///
/// It deliberately remembers **nothing** about what it is serving. Whether a
/// role should rebind is decided by comparing the applied configuration against
/// the proposed one — never against the address actually bound, since a caller
/// supplying its own socket (`serve_on_with`, and every test that binds
/// `127.0.0.1:0`) is entitled to one that does not match what the file says.
pub struct ListenerHandle {
    sockets: mpsc::UnboundedSender<SocketCommand>,
    tls: watch::Sender<Option<TlsSettings>>,
}

impl ListenerHandle {
    /// Replaces the socket this role serves.
    pub fn serve(&self, listener: TcpListener) {
        let _ = self.sockets.send(SocketCommand::Serve(listener));
    }

    /// Stops serving this role, releasing its socket.
    pub fn close(&self) {
        let _ = self.sockets.send(SocketCommand::Close);
    }

    /// Publishes the TLS mode the *next* connection is accepted under. `None`
    /// is cleartext.
    pub fn set_tls(&self, settings: Option<TlsSettings>) {
        self.tls.send_replace(settings);
    }
}

/// Binds `address` without awaiting.
///
/// `std::net::TcpListener::bind` rather than tokio's, so a rebind can happen
/// inside `cli::apply_reload` — which is deliberately not `async`, so that its
/// publishing run has no await point another task could interleave with. The
/// blocking part is name resolution, on the reload supervisor's own task, where
/// building a generation already reads and writes files.
///
/// # Errors
///
/// Whatever the bind failed with — a port in use, an address that does not
/// resolve, a privileged port. The caller turns it into a refused reload with
/// the running socket untouched.
pub fn bind_blocking(address: &str) -> io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

/// A listener whose socket and TLS mode can both be replaced while it serves.
///
/// Implements `axum::serve::Listener`, so the server keeps being run by
/// `axum::serve` — including `into_make_service_with_connect_info`, which is what
/// the IP filters depend on (see [`RoleSocket`]).
///
/// **Handshakes happen off the accept path.** A background task accepts TCP
/// connections and spawns each handshake, so one slow client cannot hold up
/// every other connection for the length of the timeout; `accept()` only picks
/// up the results. A handshake that fails or runs out of budget is logged and
/// dropped — the trait's `accept()` returns no `Result`, which suits this
/// exactly: a bad connection simply never becomes one.
pub struct RoleListener {
    /// Connections ready to be served, oldest first.
    incoming: mpsc::Receiver<(MaybeTls, SocketAddr)>,
    /// The last address this role was bound to, for `local_addr` — which axum
    /// calls per connection, including after the socket it named has gone.
    local_addr: SocketAddr,
    /// Republished by the accept task on every rebind, so `local_addr` follows
    /// the socket rather than answering the address of a listener that is no
    /// longer there.
    bound: watch::Receiver<SocketAddr>,
}

/// The listener type [`spawn`] hands to `axum::serve`.
///
/// The `tap_io` wrapper is **functional, not decorative**.
/// `into_make_service_with_connect_info::<SocketAddr>()` requires
/// `SocketAddr: Connected<IncomingStream<'_, L>>`, and axum implements that for
/// exactly two listeners: the concrete `TcpListener`, and — blanket — any
/// `TapIo<L, F>` whose `L::Addr` is `Clone + Sync + 'static`. We cannot write the
/// missing impl ourselves: foreign trait, foreign `Self` type, coherence refuses
/// it. So the wrapper is what makes the peer address reach the request
/// extensions, and without it `add_filter_middleware` sees no client address and
/// the IP filters fail closed. Returning the wrapped type from `spawn` is what
/// keeps a caller from forgetting.
pub type RoleSocket = TapIo<RoleListener, fn(&mut MaybeTls)>;

/// Starts a role's accept loop.
///
/// `initial` is the socket to serve at once, or `None` for a role that is
/// switched off — which parks until a reload hands it one. `tls` is the mode
/// every connection is accepted under, read fresh each time so a renewed
/// certificate, a changed `handshake_timeout_ms` and a `tls.enabled` flip all
/// land on the next client without disturbing anyone already connected.
///
/// The address reported by `local_addr` before anything is bound is
/// `0.0.0.0:0`; nothing consults it until a connection arrives, and by then the
/// accept task has published the real one.
#[must_use]
pub fn spawn(
    role: &'static str,
    initial: Option<TcpListener>,
    tls: Option<TlsSettings>,
) -> (RoleSocket, ListenerHandle) {
    let (sender, incoming) = mpsc::channel(MAX_PENDING_CONNECTIONS);
    let (sockets_tx, sockets_rx) = mpsc::unbounded_channel();
    let (tls_tx, tls_rx) = watch::channel(tls);

    let first_addr = initial
        .as_ref()
        .and_then(|listener| listener.local_addr().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let (bound_tx, bound_rx) = watch::channel(first_addr);

    tokio::spawn(async move {
        let mut current = initial;
        // Taken away once the last [`ListenerHandle`] is dropped, which is not
        // an ending: `reload::Reloads::none()` drops the whole set the moment
        // the supervisor sees it will never fire, and every caller that serves
        // no reloads goes through it. It means only that this socket is now
        // whatever it is for good.
        let mut commands = Some(sockets_rx);
        loop {
            if current.is_none() && commands.is_none() {
                // Nothing to accept, and nothing that could ever hand this role
                // a socket again. Waiting on the listener rather than returning
                // outright: ending here would close `incoming`, and `accept`
                // reads a closed `incoming` as the accept task having *died*.
                sender.closed().await;
                debug!(
                    event = "server_accept_loop_ended",
                    outcome = "success",
                    listener = role
                );
                return;
            }

            // Reserving before accepting is the backpressure: at most
            // `MAX_PENDING_CONNECTIONS` connections are in flight, and a
            // dropped listener closes the channel, which ends this task.
            let Ok(permit) = sender.clone().reserve_owned().await else {
                debug!(
                    event = "server_accept_loop_ended",
                    outcome = "success",
                    listener = role
                );
                return;
            };

            // With no socket there is only the command channel to wait on,
            // which is exactly the parking this module's documentation
            // describes: a role that is switched off costs one idle task.
            //
            // The result is carried out of the `match` rather than acted on
            // inside it, because the accept arm borrows `current` and the
            // command arm has to replace it.
            let next = match (current.as_ref(), commands.as_mut()) {
                (None, None) => unreachable!("checked at the top of the loop"),
                (None, Some(commands)) => Next::Command(commands.recv().await),
                (Some(listener), None) => accept_one(listener, role).await,
                (Some(listener), Some(commands)) => tokio::select! {
                    // Biased so a pending rebind is taken before another
                    // connection is accepted on the socket being replaced.
                    // Both arms are cancellation-safe.
                    biased;
                    command = commands.recv() => Next::Command(command),
                    accepted = accept_one(listener, role) => accepted,
                },
            };

            let (stream, peer) = match next {
                Next::Connection(connection) => connection,
                Next::Command(Some(command)) => {
                    apply(&mut current, command, &bound_tx, role);
                    continue;
                }
                Next::Command(None) => {
                    commands = None;
                    continue;
                }
                Next::Backoff => {
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };

            // Read here rather than captured above: this is the point a
            // reloaded certificate — or a `tls.enabled` flip — takes effect. The
            // `Ref` guard is dropped before the spawn, so nothing holds the lock
            // across an await.
            let settings = tls_rx.borrow().clone();
            match settings {
                // No handshake to run, so the connection is ready as it stands.
                // `send` hands back the cloned sender the permit came from,
                // which has nothing left to do.
                None => {
                    permit.send((MaybeTls::Plain(stream), peer));
                }
                Some(TlsSettings {
                    acceptor,
                    handshake_timeout,
                }) => {
                    tokio::spawn(async move {
                        match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await
                        {
                            Ok(Ok(tls)) => {
                                permit.send((MaybeTls::Tls(Box::new(tls)), peer));
                            }
                            // Neither is the server's problem: a port scan, a
                            // cleartext client, a stalled handshake. Never fatal.
                            Ok(Err(error)) => {
                                debug!(event = "tls_handshake_failed", outcome = "failure", peer = %peer, error = %error);
                            }
                            Err(_) => {
                                debug!(event = "tls_handshake_timeout", outcome = "failure", peer = %peer)
                            }
                        }
                    });
                }
            }
        }
    });

    let listener = RoleListener {
        incoming,
        local_addr: first_addr,
        bound: bound_rx,
    }
    // See `RoleSocket`: this is what carries the peer address into the request
    // extensions. The closure itself has nothing to do.
    .tap_io(noop_tap as fn(&mut MaybeTls));

    (
        listener,
        ListenerHandle {
            sockets: sockets_tx,
            tls: tls_tx,
        },
    )
}

/// What one pass of the accept loop produced.
///
/// A value rather than three branches acting in place, because the arm that
/// accepts borrows the current socket and the arm that takes a command has to
/// replace it — which the borrow checker will not allow inside one `select!`.
enum Next {
    Connection((TcpStream, SocketAddr)),
    /// `None` means every [`ListenerHandle`] has been dropped.
    Command(Option<SocketCommand>),
    /// `accept()` failed; pause before trying again so a socket that is
    /// refusing connections does not spin a core.
    Backoff,
}

/// One `accept()`, with a failure turned into a pause rather than an end.
///
/// A function so the accept loop can await it both inside a `select!` and on its
/// own, the two differing only in whether a rebind can interrupt it.
/// Cancellation-safe, because `TcpListener::accept` is and nothing here holds
/// state across it.
async fn accept_one(listener: &TcpListener, role: &'static str) -> Next {
    match listener.accept().await {
        Ok(connection) => Next::Connection(connection),
        Err(error) => {
            warn!(
                event = "server_accept_failed",
                outcome = "failure",
                listener = role,
                error = %error
            );
            Next::Backoff
        }
    }
}

/// Applies one [`SocketCommand`] to the accept loop's current socket.
///
/// Dropping the old listener is what stops new connections reaching the old
/// address; everything already accepted is unaffected, and everything already
/// established belongs to hyper.
fn apply(
    current: &mut Option<TcpListener>,
    command: SocketCommand,
    bound: &watch::Sender<SocketAddr>,
    role: &'static str,
) {
    match command {
        SocketCommand::Serve(listener) => {
            if let Ok(address) = listener.local_addr() {
                bound.send_replace(address);
            }
            *current = Some(listener);
        }
        SocketCommand::Close => {
            *current = None;
            debug!(
                event = "server_socket_closed",
                outcome = "success",
                listener = role
            );
        }
    }
}

/// The `tap_io` callback. Named rather than a closure so [`RoleSocket`] can
/// spell its type out.
fn noop_tap(_stream: &mut MaybeTls) {}

impl Listener for RoleListener {
    type Io = MaybeTls;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(connection) => {
                // Cheap, and the only place it can be refreshed: the accept task
                // owns the socket, so this is how a rebind reaches `local_addr`.
                if self.bound.has_changed().unwrap_or(false) {
                    self.local_addr = *self.bound.borrow_and_update();
                }
                connection
            }
            // The accept task only ends when this listener is dropped, so the
            // channel closing means it died. There is no error to return in this
            // signature, and returning a connection is impossible; parking is
            // what is left.
            None => {
                tracing::error!(
                    event = "server_acceptor_stopped",
                    outcome = "failure",
                    "the accept task ended: no further connection will be served"
                );
                std::future::pending().await
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, TlsConfig};
    use crate::testutil::TempDir;
    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use axum::{Router, serve};
    use rustls::pki_types::ServerName;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    /// A `ServerConfig` with TLS enabled, its material inside `dir`.
    fn tls_config(dir: &TempDir, base_url: &str) -> ServerConfig {
        ServerConfig {
            bind_address: "127.0.0.1:0".to_string(),
            base_url: base_url.to_string(),
            tls: TlsConfig {
                enabled: true,
                cert_path: dir.join("server.pem").display().to_string(),
                key_path: dir.join("server.key").display().to_string(),
                handshake_timeout_ms: 5_000,
            },
            ..ServerConfig::default()
        }
    }

    /// One freshly provisioned acceptor, under a directory of its own so two
    /// calls give two provably distinct certificates.
    fn settings(name: &str, timeout: Duration) -> TlsSettings {
        let dir = TempDir::new(name);
        let acceptor = crate::tls::from_config(&tls_config(&dir, "https://localhost"))
            .unwrap()
            .unwrap();
        // The directory may go: the acceptor holds the parsed material, and
        // nothing reads the files again.
        drop(dir);
        TlsSettings::new(acceptor, timeout)
    }

    /// Serves `/peer` — which answers with the peer address axum saw, the value
    /// every IP filter runs on — on a role listener the caller can then poke.
    ///
    /// Returns the port it started on and the handle a reload would use.
    async fn serve_peer(tls: Option<TlsSettings>) -> (u16, ListenerHandle) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let (socket, handle) = spawn("test", Some(tcp), tls);

        let app = Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
        );
        tokio::spawn(async move {
            serve(
                socket,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (port, handle)
    }

    /// One `GET /peer` over TLS, returning the raw response and the address the
    /// client used.
    async fn get_peer(port: u16) -> (String, SocketAddr) {
        let config =
            crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let client_addr = stream.local_addr().unwrap();

        let mut tls = TlsConnector::from(config)
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        tls.write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = String::new();
        tls.read_to_string(&mut response).await.unwrap();
        (response, client_addr)
    }

    /// The same request in cleartext, for the arm that speaks no TLS.
    async fn get_plain(port: u16) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    /// The certificate the server presented on one fresh connection.
    async fn peer_certificate(port: u16) -> Vec<u8> {
        let config =
            crate::challenge::tls_alpn_01::accept_any_client_config(&[b"http/1.1"]).unwrap();
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let tls = TlsConnector::from(config)
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        tls.get_ref()
            .1
            .peer_certificates()
            .expect("the server presented a certificate")[0]
            .to_vec()
    }

    /// Whether anything is listening on `port` at all.
    async fn refused(port: u16) -> bool {
        matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await,
            Ok(Err(_))
        )
    }

    /// The headline case: the socket moves and the `axum::serve` above it does
    /// not. One request answered on the first port, one on the second, and the
    /// first refusing afterwards — which together are the whole feature.
    #[tokio::test]
    async fn a_replaced_socket_serves_the_new_port_and_releases_the_old() {
        let (first, handle) = serve_peer(None).await;
        assert!(get_plain(first).await.starts_with("HTTP/1.1 200 OK"));

        let replacement = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = replacement.local_addr().unwrap().port();
        handle.serve(replacement);

        // The same server, the same router, a different socket.
        let response = get_plain(second).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            refused(first).await,
            "the old socket must be released, not merely ignored"
        );
    }

    /// `tls.enabled` flipped with the address unchanged, which is the case a
    /// bind-first-then-drain scheme could not serve at all: two listeners
    /// cannot hold one port. Here nothing is rebound — the mode is read per
    /// connection, so the very next client speaks the new protocol.
    #[tokio::test]
    async fn tls_can_be_switched_on_without_the_socket_moving() {
        let (port, handle) = serve_peer(None).await;
        assert!(get_plain(port).await.starts_with("HTTP/1.1 200 OK"));

        handle.set_tls(Some(settings("listener-flip", Duration::from_secs(5))));

        let (response, _) = get_peer(port).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        // And back again, since an operator who turns TLS on can turn it off.
        handle.set_tls(None);
        assert!(get_plain(port).await.starts_with("HTTP/1.1 200 OK"));
    }

    /// Closing a role releases its socket and leaves the listener parked rather
    /// than dead: a later reload hands it a new one and it serves again. That
    /// is `admin.enabled` and `metrics.enabled` going off and on.
    #[tokio::test]
    async fn a_closed_role_refuses_connections_and_can_be_reopened() {
        let (port, handle) = serve_peer(None).await;
        assert!(get_plain(port).await.starts_with("HTTP/1.1 200 OK"));

        handle.close();
        // The command is applied by the accept task, so give it a turn.
        tokio::task::yield_now().await;
        assert!(refused(port).await, "a closed role must not be listening");

        let reopened = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let again = reopened.local_addr().unwrap().port();
        handle.serve(reopened);
        assert!(get_plain(again).await.starts_with("HTTP/1.1 200 OK"));
    }

    /// A renewed certificate reaches the next client without the socket
    /// moving — the reason the accept loop reads its settings per connection
    /// instead of capturing them.
    ///
    /// Two whole certificates rather than a renewed one: provisioning generates
    /// a fresh key each time, so two directories give two provably distinct
    /// DERs, which is all the assertion needs.
    #[tokio::test]
    async fn a_swapped_certificate_is_served_to_the_next_connection() {
        let (port, handle) =
            serve_peer(Some(settings("listener-first", Duration::from_secs(5)))).await;

        let before = peer_certificate(port).await;
        handle.set_tls(Some(settings("listener-second", Duration::from_secs(5))));
        let after = peer_certificate(port).await;

        // Both connections went to the same `port`, which is the half that
        // matters: the certificate changed without the socket being rebound.
        assert_ne!(
            before, after,
            "the connection after the swap must see the new certificate"
        );
    }

    /// The end-to-end proof: a real handshake, a real request, and — the point
    /// of the test — `ConnectInfo` surviving the TLS wrapper. Without it every
    /// IP filter would fail closed.
    #[tokio::test]
    async fn a_request_is_served_with_the_peer_address_intact() {
        let (port, _handle) =
            serve_peer(Some(settings("listener-peer", Duration::from_secs(5)))).await;
        let (response, client_addr) = get_peer(port).await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.ends_with(&client_addr.to_string()),
            "expected the body to be {client_addr}, got {response}"
        );
    }

    /// The same guarantee on the cleartext arm, which used to be
    /// `axum::serve`'s own accept loop and is now this one: the peer address
    /// has to survive `MaybeTls::Plain` as well.
    #[tokio::test]
    async fn a_cleartext_request_keeps_its_peer_address_too() {
        let (port, _handle) = serve_peer(None).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let client_addr = stream.local_addr().unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.ends_with(&client_addr.to_string()), "{response}");
    }

    /// A cleartext client (or a port scan) fails the handshake without taking
    /// the listener down with it.
    #[tokio::test]
    async fn a_failed_handshake_does_not_stop_the_listener() {
        let (port, _handle) =
            serve_peer(Some(settings("listener-scan", Duration::from_secs(5)))).await;

        let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        plain.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // The server answers a TLS alert, not HTTP.
        let mut ignored = Vec::new();
        let _ = plain.read_to_end(&mut ignored).await;

        let (response, _) = get_peer(port).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    /// A client that connects and then says nothing is dropped when its budget
    /// runs out — and, crucially, does not hold up anyone else while it stalls.
    /// That is the whole reason handshakes are spawned rather than run inside
    /// `accept()`.
    #[tokio::test]
    async fn a_stalled_handshake_times_out_without_blocking_others() {
        let (port, _handle) =
            serve_peer(Some(settings("listener-stall", Duration::from_millis(300)))).await;

        let mut stalled = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        // Served while the first connection is still stuck mid-handshake.
        let (response, _) = tokio::time::timeout(Duration::from_secs(5), get_peer(port))
            .await
            .expect("a stalled handshake must not block the accept loop");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        // And the stalled one is eventually dropped, not held forever.
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buffer))
            .await
            .expect("the handshake timeout must close the connection");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "expected EOF after the handshake timeout, got {read:?}"
        );
    }

    /// `bind_blocking` is what a reload binds through, so both of its answers
    /// matter: a usable socket, and an error the refusal can quote rather than
    /// a panic.
    #[tokio::test]
    async fn bind_blocking_binds_or_says_why_not() {
        let listener = bind_blocking("127.0.0.1:0").expect("an ephemeral port must bind");
        let port = listener.local_addr().unwrap().port();

        let error = bind_blocking(&format!("127.0.0.1:{port}"))
            .expect_err("the port is taken, and saying so is what refuses a reload");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);

        assert!(
            bind_blocking("not-an-address").is_err(),
            "an unparseable address must not panic on the reload path"
        );
    }
}
