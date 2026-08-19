//! `[metrics]` — the Prometheus exposition endpoint.

use serde::Deserialize;

/// Governs the metrics listener and the `GET /metrics` it serves.
///
/// A **third socket**, not a route on either of the other two, and that is the
/// whole design: a scrape is a different network stream from ACME traffic and
/// from the web admin, so it gets its own port and its own firewall rules. That
/// is also what settles the authentication question — the endpoint carries no
/// session and needs none, because reaching the port at all is the permission.
/// Putting it on the ACME listener would have meant an unauthenticated route on
/// a public socket; putting it on the admin listener would have meant an
/// explicit auth exemption on a listener whose rule is that every route but
/// sign-in needs a session, plus coupling metrics to the panel being enabled.
///
/// Process-wide, so deliberately absent from `PROFILE_SECTIONS`: there is one
/// counter set for the process, and the endpoint is a *dimension* of it rather
/// than something each endpoint configures for itself. A per-profile switch
/// would mean a scrape whose totals silently omitted whichever profiles had it
/// off.
///
/// There is deliberately no `path` key. `/metrics` is the convention every
/// scrape configuration already assumes, and this listener serves nothing else,
/// so making it configurable would buy a way to get it wrong and nothing else.
///
/// There is deliberately no `[metrics.tls]` either, unlike `[server.tls]` and
/// `[admin.tls]`. Those two carry a client's signed requests and an operator's
/// session cookie; a scrape carries no credential and the exposition contains
/// no secret. If it ever needs to cross an untrusted network, that is the point
/// to add one rather than now.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Bind the metrics listener and serve `GET /metrics`.
    ///
    /// **Off by default**, the same posture `[admin]` takes: a certificate
    /// authority should not open a new socket because somebody upgraded it.
    pub enabled: bool,
    /// The socket the exposition is served on.
    ///
    /// Loopback by default, and beside the other two — `server` on `3000`,
    /// `admin` on `3001`, this on `3002`.
    ///
    /// Unlike `admin.bind_address`, a non-loopback value is **neither refused
    /// nor warned about**. The admin listener refuses one without TLS because
    /// its cookie is always `Secure` and a browser silently declines to store
    /// that over plain HTTP, so the symptom would be an unexplained sign-out
    /// loop. Nothing here has a cookie, and a separately firewalled port
    /// reachable from a Prometheus host is exactly the intended deployment.
    ///
    /// Startup refuses a value equal to `server.bind_address` or
    /// `admin.bind_address`, since only one of the three could then bind.
    pub bind_address: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1:3002".to_string(),
        }
    }
}
