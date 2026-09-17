//! The three listeners' sockets: binding them at startup, planning a rebind on
//! a reload, and announcing one that has come up.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::sqlite::db::Database;

use super::supervisor::Cells;

/// Validates the admin configuration and binds its socket when it is enabled.
///
/// Shared by [`run`](super::run) and [`serve_on`](super::serve_on) rather than
/// living in one of them: both need it, and the validation must happen **before
/// anything binds**, so a misconfigured panel cannot take the ACME listener
/// down with it halfway through startup.
pub(super) async fn bind_admin(config: &Arc<Config>) -> anyhow::Result<Option<TcpListener>> {
    crate::webadmin::check_config(config).inspect_err(|error| {
        error!(event = "admin_config_invalid", outcome = "failure", error = %error);
    })?;

    match config.admin.enabled {
        false => Ok(None),
        true => Ok(Some(
            TcpListener::bind(&config.admin.bind_address)
                .await
                .inspect_err(|error| {
                    error!(event = "admin_socket_bind_failed",
                           outcome = "failure",
                           bind_address = %config.admin.bind_address,
                           error = %error);
                })?,
        )),
    }
}

/// Refuses a `[metrics]` bind address that collides with another listener's.
///
/// Pure, so a reload runs the same check before rebinding anything — the twin of
/// [`crate::webadmin::check_config`], and beside it in `apply_reload` for the
/// same reason: a listener configuration that would not start must not be one a
/// running server can be reloaded into.
///
/// Three listeners, so the check is pairwise. `webadmin` already refuses
/// admin-versus-server; these are the two pairs it cannot see. Checked even when
/// `[admin]` is off, since enabling the panel later must not be what surfaces a
/// latent conflict.
///
/// # Errors
///
/// Names the other key when the two addresses are equal.
pub fn check_metrics_config(config: &Config) -> anyhow::Result<()> {
    if !config.metrics.enabled {
        return Ok(());
    }

    let bind = &config.metrics.bind_address;
    for (name, other) in [
        ("server.bind_address", &config.server.bind_address),
        ("admin.bind_address", &config.admin.bind_address),
    ] {
        if bind == other && (name != "admin.bind_address" || config.admin.enabled) {
            error!(event = "metrics_config_invalid",
                   outcome = "failure",
                   bind_address = %bind);
            anyhow::bail!(
                "metrics.bind_address and {name} are both `{bind}`: the metrics endpoint is a \
                 separate listener and cannot share a socket (give it its own port)"
            );
        }
    }
    Ok(())
}

/// Binds the metrics socket when `[metrics]` is on, refusing a collision first.
///
/// The twin of [`bind_admin`], and the same shape for the same reason: a socket
/// that cannot be bound must stop startup rather than leave the process running
/// with one of its three listeners silently missing.
///
/// Deliberately **no loopback check**. `webadmin::check_config` refuses a
/// non-loopback admin bind without TLS because that listener's cookie is always
/// `Secure`, which a browser will not store over plain HTTP, so the failure
/// would be invisible. Nothing here has a cookie: a metrics port reachable from
/// a Prometheus host on another machine is the intended deployment, and the
/// firewall is what bounds it.
pub(super) async fn bind_metrics(config: &Arc<Config>) -> anyhow::Result<Option<TcpListener>> {
    check_metrics_config(config)?;
    if !config.metrics.enabled {
        return Ok(None);
    }

    let bind = &config.metrics.bind_address;
    let listener = TcpListener::bind(bind).await.inspect_err(|error| {
        error!(event = "metrics_socket_bind_failed",
               outcome = "failure",
               bind_address = %bind,
               error = %error);
    })?;
    Ok(Some(listener))
}

/// One of the three sockets this process may hold.
///
/// An enum rather than the `&'static str` the log field wants, so the reload
/// path's per-role handling is exhaustive: a fourth listener would be a compile
/// error at every point that has to decide something about one, which is exactly
/// how the third arrived with `bind_metrics` and `check_metrics_config` in
/// place and nothing else remembering it existed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Acme,
    Admin,
    Metrics,
}

impl Role {
    /// The `listener` field every log line about this socket carries.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Acme => "acme",
            Self::Admin => "admin",
            Self::Metrics => "metrics",
        }
    }

    /// The key an operator edits to move this socket, for a refusal to name.
    fn bind_key(self) -> &'static str {
        match self {
            Self::Acme => "server.bind_address",
            Self::Admin => "admin.bind_address",
            Self::Metrics => "metrics.bind_address",
        }
    }
}

/// What a reload does to one role's socket.
///
/// Built while a failure can still refuse the whole reload, applied once nothing
/// can fail — the same build-then-publish split every other part of a generation
/// makes, applied to the one resource that cannot simply be constructed twice.
pub(super) enum SocketPlan {
    /// The role's address and enablement are both unchanged. Note this is
    /// decided from the *configuration*, never from the address actually bound:
    /// a caller supplying its own socket (every test that binds `127.0.0.1:0`)
    /// is entitled to one that does not match the file, and rebinding it out
    /// from under them would be this feature breaking its own callers.
    Keep,
    /// Serve this newly bound socket: the role was switched on, or its address
    /// moved. Connections already established are untouched — hyper owns those,
    /// and only the socket beneath them changes.
    Serve(TcpListener),
    /// Release the socket: the role was switched off.
    Close,
}

/// The three roles' socket plans, and what to say about them afterwards.
pub(super) struct SocketPlans {
    acme: SocketPlan,
    admin: SocketPlan,
    metrics: SocketPlan,
    /// The resolved address of each freshly bound socket, so the announcement
    /// after the swap names where the listener actually landed.
    pub(super) bound: Vec<(Role, String)>,
}

impl SocketPlans {
    /// The roles whose socket this reload moved, for [`ReloadReport`] — which is
    /// what a test waits on and what an operator greps.
    ///
    /// [`ReloadReport`]: crate::reload::ReloadReport
    pub(super) fn rebound(&self) -> Vec<&'static str> {
        self.bound.iter().map(|(role, _)| role.label()).collect()
    }

    /// Hands each socket to its accept loop. Synchronous and infallible, so it
    /// sits inside the publishing run beside the routers.
    pub(super) fn publish(self, cells: &Cells) {
        for (role, plan, handle) in [
            (Role::Acme, self.acme, &cells.acme),
            (Role::Admin, self.admin, &cells.admin),
            (Role::Metrics, self.metrics, &cells.metrics),
        ] {
            match plan {
                SocketPlan::Keep => {}
                SocketPlan::Serve(listener) => handle.serve(listener),
                SocketPlan::Close => {
                    handle.close();
                    info!(
                        event = "server_listener_stopped",
                        outcome = "success",
                        listener = role.label(),
                        "switched off by a configuration reload: the socket is released \
                         and nothing new is accepted on it"
                    );
                }
            }
        }
    }
}

/// Decides, and performs, every bind this reload needs.
///
/// The ordering rule the whole reload path rests on, applied to sockets: bind
/// first, so a bad address refuses the reload rather than having already
/// dropped the live one. Two addresses that differ as strings but collide in
/// the kernel — `[::]:3000` against `0.0.0.0:3000` — make that bind fail with
/// `EADDRINUSE`, which is the safe direction: the running socket is still
/// serving and the refusal names the key.
///
/// A `tls.enabled` flip does not appear here at all. The mode is read per
/// connection (see [`crate::listener`]), so turning TLS on or off keeps the
/// socket exactly where it is — which is what makes the one case a bind-first
/// scheme could not serve, an unchanged address, not a case.
pub(super) fn plan_sockets(
    applied: &Config,
    proposed: &Config,
) -> Result<SocketPlans, crate::reload::ReloadError> {
    let mut bound = Vec::new();
    let mut plan = |role: Role,
                    was: Option<&str>,
                    now: Option<&str>|
     -> Result<SocketPlan, crate::reload::ReloadError> {
        match (was, now) {
            (None, None) => Ok(SocketPlan::Keep),
            (Some(_), None) => Ok(SocketPlan::Close),
            (Some(was), Some(now)) if was == now => Ok(SocketPlan::Keep),
            (_, Some(now)) => {
                let listener = crate::listener::bind_blocking(now).map_err(|error| {
                    error!(event = "server_socket_bind_failed",
                           outcome = "failure",
                           listener = role.label(),
                           bind_address = %now,
                           error = %error);
                    crate::reload::ReloadError::Build(format!(
                        "`{}` is `{now}`, which cannot be bound: {error}",
                        role.bind_key()
                    ))
                })?;
                bound.push((role, bound_address(Some(&listener), now)));
                Ok(SocketPlan::Serve(listener))
            }
        }
    };

    // The ACME listener is never switched off — there is no `server.enabled`,
    // and a CA serving no ACME would be a process with nothing to do.
    let acme = plan(
        Role::Acme,
        Some(&applied.server.bind_address),
        Some(&proposed.server.bind_address),
    )?;
    let admin = plan(
        Role::Admin,
        applied
            .admin
            .enabled
            .then_some(applied.admin.bind_address.as_str()),
        proposed
            .admin
            .enabled
            .then_some(proposed.admin.bind_address.as_str()),
    )?;
    let metrics = plan(
        Role::Metrics,
        applied
            .metrics
            .enabled
            .then_some(applied.metrics.bind_address.as_str()),
        proposed
            .metrics
            .enabled
            .then_some(proposed.metrics.bind_address.as_str()),
    )?;

    Ok(SocketPlans {
        acme,
        admin,
        metrics,
        bound,
    })
}

/// Says the panel is up, and warns about the two states that make it useless.
///
/// Run whenever the admin listener **opens** — at startup, and again on a
/// reload that turns `admin.enabled` on. Separate from the serving path since
/// that no longer starts or stops per role: the socket is what comes and goes,
/// and this is what an operator needs told when it does.
pub(super) async fn announce_admin_listener(
    config: &Arc<Config>,
    database: &Arc<Database>,
    bound: &str,
) {
    // A listener nobody holds an account for is a running service with no way
    // in; say so once, naming the command that fixes it.
    if crate::sqlite::admin_user::AdminUser::list_all(database)
        .await
        .is_ok_and(|users| users.is_empty())
    {
        warn!(
            event = "admin_no_users",
            outcome = "advisory",
            "the web admin is enabled but has no operators: create one with \
               `acme-proxy admin user create <username>`"
        );
    }

    // Repeated on every start while it holds, the `challenge_validation_bypassed`
    // treatment: these operators can still sign in, they are simply made to
    // enrol before their session becomes usable, and that stays worth seeing
    // for exactly as long as it is true.
    if config.admin.require_mfa
        && let Ok(count) = crate::admin::mfa::operators_without_a_factor(database.clone()).await
        && count > 0
    {
        warn!(
            event = "admin_mfa_enrolment_pending",
            outcome = "advisory",
            count = count,
            "admin.require_mfa is on and some operators have no second factor: \
               their next sign-in will require enrolment before the session is usable"
        );
    }

    // Same treatment for a configured `[admin.notify]` whose messages have
    // nowhere to go. An operator's security notifications are addressed to
    // their own `contact_email`, which is settable only from this host
    // (`admin user contact`) — so a panel-first deployment can have the whole
    // section configured, believe it is covered by ASVS V6.3.5/V6.3.7, and be
    // silently falling back to `notify.email.to` or to nothing.
    if config.admin.notify.enabled.is_empty() {
        // Nothing configured: no notifications were promised, so an operator
        // without an address is not a gap.
    } else if let Ok(count) =
        crate::admin::users::operators_without_a_contact(database.clone()).await
        && count > 0
    {
        warn!(
            event = "admin_notify_contact_missing",
            outcome = "advisory",
            count = count,
            "[admin.notify] is configured but some operators have no contact address: their \
               security notifications fall back to notify.email.to, or are dropped if that is \
               empty too — set one with `acme-proxy admin user contact <username> --contact <address>`"
        );
    }

    // Swept once now, then on an interval: sessions outlive a restart, so a
    // startup-only sweep would leak every one an operator never signed out of.
    let idle = Duration::from_secs(config.admin.session_idle_timeout_seconds);
    if let Err(error) = crate::sqlite::admin_session::AdminSession::cleanup(idle, database).await {
        error!(event = "admin_session_cleanup_failed", outcome = "failure", error = %error);
    }

    // The **resolved** address, so a `:0` bind is discoverable.
    info!(
        event = "admin_listening",
        outcome = "success",
        bind_address = %bound,
        protocol = if config.admin.tls.enabled { "https" } else { "http" },
        base_url = %config.admin.base_url
    );
}

/// The metrics listener's own one-line announcement, and its standing warning.
pub(super) fn announce_metrics_listener(bound: &str) {
    info!(
        event = "metrics_listening",
        outcome = "success",
        bind_address = %bound,
        "unauthenticated by design: the port is the boundary, so firewall it"
    );
}

/// The address a socket ended up on, falling back to what was configured.
///
/// The two differ for `:0` and for a caller that supplied its own listener; the
/// resolved one is what an operator needs, and the configured one is all there
/// is to say when the socket cannot answer.
pub(super) fn bound_address(listener: Option<&TcpListener>, configured: &str) -> String {
    listener
        .and_then(|listener| listener.local_addr().ok())
        .map_or_else(|| configured.to_string(), |address| address.to_string())
}
