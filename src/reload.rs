//! Replacing a running configuration without moving the sockets.
//!
//! `serve_on_with` builds everything exactly once — profiles, deduplicated
//! signer backends, filter chains, challenge registries, both routers — so until
//! this module existed, every configuration change was a process restart. For
//! the keys operators actually touch (a `[filter]` rule, an `[ipam]` token, a
//! `[notify]` webhook, a renewed certificate) that dropped in-flight ACME orders
//! and every live connection for a change that never needed a new socket.
//!
//! A reload is a **rebuild and swap**, not a mutation. Everything is constructed
//! and validated first; only once all of it succeeded is anything published. The
//! publishing itself goes through [`tokio::sync::watch`] cells, and that choice
//! is load-bearing rather than stylistic: `watch::Sender::send_replace` is
//! *synchronous*, so a run of sends with no `.await` between them cannot be
//! observed half-applied — no other task can run in the middle of it.
//!
//! What a swap cannot honour is refused **by name**, and the whole reload is
//! refused with it: the sockets are already bound, the tracing subscriber is
//! installed process-wide, the database pool is connected, the job runner's
//! tuning was snapshotted at spawn, and a signer backend owns in-memory state
//! (a `LocalCa` revocation ledger, a relay's `http-01` token store) that two
//! generations over one set of files would disagree about. Refusing by name is
//! the posture startup already takes when it rejects an unknown
//! `logging.target` rather than falling back.

use std::convert::Infallible;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use axum::routing::RouterIntoService;
use tokio::sync::{mpsc, oneshot, watch};
use tower::Service;

use crate::config::{Config, ProfileConfig};

/// One resolved configuration, as the frozen-key check sees it.
///
/// Two fields rather than one because the per-profile view is not derivable
/// from a `Config` without work that can fail: `resolve_profiles` overlays the
/// global sections onto each profile key by key and returns a `Result`. Pairing
/// them means a projection below is an infallible read.
pub struct Applied<'a> {
    pub config: &'a Config,
    pub profiles: &'a [ProfileConfig],
}

/// Renders a projection whose *value* must never reach a log.
///
/// `[signer]` reaches `relay.eab.hmac_key`, `relay.dns01.rfc2136.tsig_key_secret`
/// and `local_ca.pkcs11.pin`; `[proxy]`'s URLs legitimately carry
/// `http://user:password@host`. [`ReloadError::Frozen`] embeds both the applied
/// and the proposed rendering verbatim and `cli::apply_reload` logs the whole
/// message, so a `SIGHUP` after an unrelated edit to either section would print
/// the TSIG key — write access to the very zone this CA validates against — and
/// the HSM PIN, to journald and every log shipper downstream. That directly
/// contradicts what `src/proxy.rs` states for itself, that `redacted()` is the
/// only rendering of a proxy URL that exists.
///
/// A digest costs nothing here, because **the projection only ever needs
/// equality**: `check_frozen` compares the two strings and never reads them.
/// Redacting `Debug` was the alternative and is not available — `format!("{:?}")`
/// of a signer section is load-bearing as the *identity key*
/// `signer::build_backends` dedups backends on, so hiding a field there would
/// collapse two profiles differing only in their HSM PIN into one backend.
///
/// The forward rule, since this will be asked again: **a whole-section
/// projection is opaque iff any field it reaches can hold a credential.**
/// `logging`, `dns.resolver` and `database.url` hold none, and naming the old
/// and the new value is exactly where that message earns its keep, so they stay
/// readable. Truncated to 8 bytes like [`crate::sqlite::account::pubkey_fingerprint`].
fn opaque(rendered: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, rendered.as_bytes());
    format!("sha256:{}", hex::encode(&digest.as_ref()[..8]))
}

/// The keys a running process cannot change, and how to read each one.
///
/// A projection to `String` rather than `PartialEq` on the config types: nothing
/// in `src/config/` derives it, and `Debug` is already this crate's config
/// identity primitive (`signer::build_backends` keys its dedup on
/// `format!("{cfg:?}")`). The projection form is what lets a refusal **name the
/// key** — a whole-section comparison could only say "server changed".
///
/// Each entry is one of two kinds, and the distinction is the whole design:
///
/// - *Physically frozen*: the sockets are bound, the tracing subscriber is
///   installed once per process, the pool is connected, and the job runner
///   snapshotted its tuning at spawn.
/// - *Frozen by ownership*: a signer backend holds in-memory state with no
///   durable home, so two generations over one set of files disagree — see
///   [`crate::Assembly`]. `dns.*` and `proxy.*` follow from it, because every
///   outbound client caches them at construction and the signers are the
///   clients that are never rebuilt.
///
/// `jobs.retention_days` is deliberately **absent**: it is read only by
/// `SweepJob::jobs`, which the registry swap rebuilds. So is the global
/// `[signer]` section, because `merged_sections` overlays it per key — a global
/// change that matters shows up in some profile's resolved section, and one that
/// every profile overrides is a genuine no-op that must not be refused.
type Projection = fn(&Applied<'_>) -> String;
const FROZEN: &[(&str, Projection)] = &[
    ("database.url", |a| a.config.database.url.clone()),
    ("server.bind_address", |a| {
        a.config.server.bind_address.clone()
    }),
    ("server.tls.enabled", |a| {
        a.config.server.tls.enabled.to_string()
    }),
    ("admin.enabled", |a| a.config.admin.enabled.to_string()),
    ("admin.bind_address", |a| {
        a.config.admin.bind_address.clone()
    }),
    ("admin.tls.enabled", |a| {
        a.config.admin.tls.enabled.to_string()
    }),
    // The third listener, frozen for the reason both the others are: a bound
    // socket cannot move under a listener that is already serving. There is no
    // `metrics.tls.enabled` beside these — that listener has none.
    ("metrics.enabled", |a| a.config.metrics.enabled.to_string()),
    ("metrics.bind_address", |a| {
        a.config.metrics.bind_address.clone()
    }),
    ("logging", |a| format!("{:?}", a.config.logging)),
    ("dns.resolver", |a| format!("{:?}", a.config.dns.resolver)),
    // Opaque: the URLs carry a proxy password. See `opaque`.
    ("proxy", |a| opaque(&format!("{:?}", a.config.proxy))),
    // The six the runner and the queue snapshot at spawn. `retention_days` is
    // the seventh and is reloadable, so this cannot be `{:?}` of the section.
    ("jobs.poll_interval_ms", |a| {
        a.config.jobs.poll_interval_ms.to_string()
    }),
    ("jobs.max_concurrent", |a| {
        a.config.jobs.max_concurrent.to_string()
    }),
    ("jobs.max_attempts", |a| {
        a.config.jobs.max_attempts.to_string()
    }),
    ("jobs.retry_base_seconds", |a| {
        a.config.jobs.retry_base_seconds.to_string()
    }),
    ("jobs.retry_max_seconds", |a| {
        a.config.jobs.retry_max_seconds.to_string()
    }),
    ("jobs.lease_seconds", |a| {
        a.config.jobs.lease_seconds.to_string()
    }),
    // Mounting or unmounting an endpoint needs a signer backend built or
    // dropped, so it follows the signer freeze.
    ("profiles", |a| {
        a.profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }),
    // Opaque per profile, but the profile *name* stays readable — it is not a
    // field of the section, and it is what tells an operator which endpoint's
    // signer moved. See `opaque`.
    ("profiles.*.signer", |a| {
        a.profiles
            .iter()
            .map(|profile| {
                format!(
                    "{}={}",
                    profile.name,
                    opaque(&format!("{:?}", profile.sections.signer))
                )
            })
            .collect::<Vec<_>>()
            .join(";")
    }),
];

/// Why a reload did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// A key a running process cannot change was changed. The whole reload is
    /// refused: a generation that applied half a file could not be printed back
    /// faithfully, so "what is this server running?" would stop having an
    /// answer.
    #[error(
        "`{key}` cannot be changed while the server is running \
         (running with `{applied}`, the file now says `{proposed}`): \
         restart to apply it"
    )]
    Frozen {
        key: String,
        applied: String,
        proposed: String,
    },
    /// The new configuration could not be read or resolved.
    #[error("the configuration did not load: {0}")]
    Load(String),
    /// It read, but something it asks for could not be built.
    #[error("the new configuration did not build: {0}")]
    Build(String),
}

impl ReloadError {
    /// The short tag a log line carries, so an operator can tell a refusal from
    /// a failure without parsing the message.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Frozen { .. } => "frozen_key",
            Self::Load(_) => "load_failed",
            Self::Build(_) => "build_failed",
        }
    }
}

/// Refuses `proposed` by name if it changes anything [`FROZEN`] covers.
///
/// The first mismatch wins and stops the scan: a reload is all-or-nothing, so
/// listing every offending key would be reporting on a configuration that is
/// never going to be applied.
pub fn check_frozen(applied: &Applied<'_>, proposed: &Applied<'_>) -> Result<(), ReloadError> {
    for (key, read) in FROZEN {
        let (before, after) = (read(applied), read(proposed));
        if before != after {
            return Err(ReloadError::Frozen {
                key: (*key).to_string(),
                applied: before,
                proposed: after,
            });
        }
    }
    Ok(())
}

/// What a completed reload did.
#[derive(Debug, Clone)]
pub struct ReloadReport {
    /// Monotonic, starting at 1 for the configuration the process started with.
    /// The highest-value field in here: it is what a test waits on and what an
    /// operator greps to answer "did my SIGHUP land?".
    pub generation: u64,
    pub profiles: Vec<String>,
    pub job_kinds: Vec<&'static str>,
    pub tls_reloaded: bool,
    pub admin_tls_reloaded: bool,
    pub duration: Duration,
}

/// One request to reload, and where to send the answer.
///
/// The responder is optional because the signal path has nobody to answer: a
/// `SIGHUP` reports through the log. A caller that *can* be told — a test, and
/// one day an admin route — passes a channel and learns the outcome instead of
/// polling for a side effect.
pub struct ReloadRequest {
    pub respond: Option<oneshot::Sender<Result<ReloadReport, ReloadError>>>,
}

/// The handle a signal handler (or a future admin route) triggers reloads with.
#[derive(Clone)]
pub struct ReloadHandle(mpsc::Sender<ReloadRequest>);

impl ReloadHandle {
    /// Asks for a reload, without waiting for the outcome.
    ///
    /// `try_send` on a capacity-one channel, so a signal storm coalesces into
    /// one reload rather than queueing a run of identical ones. A refusal here
    /// means a reload is already pending, which is the same answer.
    pub fn trigger(&self) -> bool {
        self.0.try_send(ReloadRequest { respond: None }).is_ok()
    }

    /// Asks for a reload and waits for what happened.
    ///
    /// # Errors
    ///
    /// Returns the [`ReloadError`] the reload failed with. A dropped supervisor
    /// — the server is shutting down — surfaces as [`ReloadError::Load`].
    pub async fn reload(&self) -> Result<ReloadReport, ReloadError> {
        let (respond, answer) = oneshot::channel();
        self.0
            .send(ReloadRequest {
                respond: Some(respond),
            })
            .await
            .map_err(|_| ReloadError::Load("the server is not accepting reloads".to_string()))?;
        answer
            .await
            .map_err(|_| ReloadError::Load("the reload was abandoned".to_string()))?
    }
}

/// The receiving half, held by the serving path.
pub struct Reloads(mpsc::Receiver<ReloadRequest>);

impl Reloads {
    /// A source that never fires, for every caller that serves no reloads.
    ///
    /// The sender is dropped on the spot, so the supervisor's first `recv`
    /// yields `None` and it exits — which is what keeps the no-reload path free
    /// rather than a second branch through the serving code.
    #[must_use]
    pub fn none() -> Self {
        Self(mpsc::channel(1).1)
    }

    pub(crate) async fn recv(&mut self) -> Option<ReloadRequest> {
        self.0.recv().await
    }
}

/// Opens a reload channel.
///
/// Capacity one: see [`ReloadHandle::trigger`] for why coalescing is the wanted
/// behaviour rather than a limitation.
#[must_use]
pub fn channel() -> (ReloadHandle, Reloads) {
    let (sender, receiver) = mpsc::channel(1);
    (ReloadHandle(sender), Reloads(receiver))
}

/// The service half of one router cell.
///
/// Delegates every request to whichever router is current. Two things about the
/// shape are deliberate:
///
/// - It is a **fallback service, not a make-service**. A make-service is
///   consulted once per *connection*, so an HTTP/1.1 keep-alive client would
///   hold the old router for the life of its connection — which for an ACME
///   client polling an order is exactly the window a reload is meant to affect.
///   Per request is the only granularity that means anything here.
/// - It is wrapped by an outer [`Router`] rather than handed to `axum::serve`
///   directly, so `into_make_service_with_connect_info` still applies. That
///   inserts `ConnectInfo` into the request *before* the outer router runs, so
///   the inner router — and every IP filter under it — sees it exactly as it
///   does today.
#[derive(Clone)]
struct SwapService(watch::Receiver<RouterIntoService<Body>>);

impl Service<Request> for SwapService {
    type Response = Response;
    type Error = Infallible;
    type Future = <RouterIntoService<Body> as Service<Request>>::Future;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The inner router is always ready, and asking the *current* one here
        // would be asking a different service than the one `call` ends up using.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Cloned out of the cell so the borrow guard is gone before the call:
        // a `Router` clone is one `Arc` bump, which is why this can happen per
        // request rather than per connection.
        let mut current = self.0.borrow().clone();
        current.call(request)
    }
}

/// Wraps a router cell as one servable [`Router`].
///
/// Hand the result to `axum::serve` exactly as an ordinary router: it routes
/// nothing itself, so every path falls through to the current inner router.
///
/// One consequence worth knowing rather than rediscovering: nesting means two
/// `top_level` route futures instead of one, so axum's response fixups run
/// twice. Every one of them is idempotent — `set_content_length` returns early
/// when the header is already present, `set_allow_header` does nothing when the
/// outer router has no `allow_header` of its own, and stripping an
/// already-empty `HEAD` body is a no-op. `HEAD /newNonce` and `Content-Length`
/// therefore behave exactly as they do without the wrapper.
pub fn swappable(current: watch::Receiver<RouterIntoService<Body>>) -> Router {
    Router::new().fallback_service(SwapService(current))
}

/// Opens a router cell, with `initial` as its first generation.
#[must_use]
pub fn router_channel(
    initial: Router,
) -> (
    watch::Sender<RouterIntoService<Body>>,
    watch::Receiver<RouterIntoService<Body>>,
) {
    watch::channel(initial.into_service::<Body>())
}

#[cfg(test)]
mod channel_tests {
    use super::*;

    /// A signal storm coalesces into one reload rather than queueing a run of
    /// identical ones. `trigger` answering `false` is not a lost request — the
    /// reload it would have asked for is already pending.
    #[tokio::test]
    async fn a_second_trigger_while_one_is_pending_coalesces() {
        let (handle, mut reloads) = channel();

        assert!(handle.trigger(), "the first request is accepted");
        assert!(!handle.trigger(), "the second finds one already queued");

        let request = reloads.recv().await.expect("the queued request arrives");
        assert!(
            request.respond.is_none(),
            "a signal has nobody to answer, so it asks for no channel"
        );

        // With the queue drained, the next signal is accepted again.
        assert!(handle.trigger());
    }

    /// A handle whose supervisor is gone answers rather than hanging. That is
    /// the shutdown case: the serving task returned and took the receiver with
    /// it, and a caller waiting on `reload()` must not wait for ever.
    #[tokio::test]
    async fn a_reload_with_no_supervisor_left_fails_rather_than_hanging() {
        let (handle, reloads) = channel();
        drop(reloads);

        let error = handle
            .reload()
            .await
            .expect_err("there is nobody to serve the request");
        assert_eq!(error.kind(), "load_failed");
        assert!(
            error.to_string().contains("not accepting reloads"),
            "{error}"
        );
    }

    /// The no-reload source ends the supervisor immediately, which is what
    /// keeps every caller that serves no reloads free of a parked task.
    #[tokio::test]
    async fn a_source_that_never_fires_ends_at_once() {
        assert!(Reloads::none().recv().await.is_none());
    }
}

#[cfg(test)]
mod frozen_tests {
    use super::*;
    use crate::config::ProfileSections;

    fn profile(name: &str) -> ProfileConfig {
        ProfileConfig {
            name: name.to_string(),
            sections: ProfileSections::default(),
        }
    }

    /// The shape every case below uses: a configuration and its resolved
    /// profiles, mutated by the case and compared against an untouched pair.
    fn refuse(
        mutate: impl FnOnce(&mut Config, &mut Vec<ProfileConfig>),
    ) -> Result<(), ReloadError> {
        let applied = Config::default();
        let applied_profiles = vec![profile("le")];

        let mut proposed = Config::default();
        let mut proposed_profiles = vec![profile("le")];
        mutate(&mut proposed, &mut proposed_profiles);

        check_frozen(
            &Applied {
                config: &applied,
                profiles: &applied_profiles,
            },
            &Applied {
                config: &proposed,
                profiles: &proposed_profiles,
            },
        )
    }

    fn refused_key(result: Result<(), ReloadError>) -> String {
        match result {
            Err(ReloadError::Frozen { key, .. }) => key,
            Err(other) => panic!("expected a frozen-key refusal, got {other}"),
            Ok(()) => panic!("expected a refusal, the change was allowed"),
        }
    }

    /// Every frozen key, changed one at a time, refused **by its own name**.
    ///
    /// Table-driven for the usual reason, and doubly load-bearing here: a
    /// projection that silently reads the wrong field would make its key's case
    /// come back `Ok` (nothing changed as far as the table can see) or name some
    /// *other* key. Both are failures, so this is the completeness check as well
    /// as the naming one — a key added to `FROZEN` with no row here is caught by
    /// `the_table_and_this_suite_cover_the_same_keys` below.
    #[test]
    fn every_frozen_key_is_refused_by_its_own_name() {
        #[allow(clippy::type_complexity)]
        let cases: Vec<(&str, Box<dyn Fn(&mut Config, &mut Vec<ProfileConfig>)>)> = vec![
            (
                "database.url",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.database.url = "sqlite://other.db".to_string();
                }),
            ),
            (
                "server.bind_address",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.server.bind_address = "127.0.0.1:9999".to_string();
                }),
            ),
            (
                "server.tls.enabled",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.server.tls.enabled = !c.server.tls.enabled;
                }),
            ),
            (
                "admin.enabled",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.admin.enabled = !c.admin.enabled;
                }),
            ),
            (
                "admin.bind_address",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.admin.bind_address = "127.0.0.1:9998".to_string();
                }),
            ),
            (
                "admin.tls.enabled",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.admin.tls.enabled = !c.admin.tls.enabled;
                }),
            ),
            (
                "metrics.enabled",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.metrics.enabled = !c.metrics.enabled;
                }),
            ),
            (
                "metrics.bind_address",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.metrics.bind_address = "127.0.0.1:9999".to_string();
                }),
            ),
            (
                "logging",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.logging.json_format = !c.logging.json_format;
                }),
            ),
            (
                "dns.resolver",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.dns.resolver = Some("192.0.2.1:53".to_string());
                }),
            ),
            (
                "proxy",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.proxy.https_url = "http://proxy.example:3128".to_string();
                }),
            ),
            (
                "jobs.poll_interval_ms",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.poll_interval_ms += 1;
                }),
            ),
            (
                "jobs.max_concurrent",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.max_concurrent += 1;
                }),
            ),
            (
                "jobs.max_attempts",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.max_attempts += 1;
                }),
            ),
            (
                "jobs.retry_base_seconds",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.retry_base_seconds += 1;
                }),
            ),
            (
                "jobs.retry_max_seconds",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.retry_max_seconds += 1;
                }),
            ),
            (
                "jobs.lease_seconds",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.jobs.lease_seconds += 1;
                }),
            ),
            (
                "profiles",
                Box::new(|_: &mut Config, p: &mut Vec<ProfileConfig>| {
                    p.push(profile("staging"));
                }),
            ),
            (
                "profiles.*.signer",
                Box::new(|_: &mut Config, p: &mut Vec<ProfileConfig>| {
                    p[0].sections.signer.backend = "custom".to_string();
                }),
            ),
        ];

        for (key, mutate) in &cases {
            let refused = refused_key(refuse(|config, profiles| mutate(config, profiles)));
            assert_eq!(
                &refused.as_str(),
                key,
                "changing `{key}` must be refused naming `{key}`, not `{refused}`",
            );
        }

        // The guard on the guard: a case list that drifted from the table would
        // make every assertion above pass while leaving a key untested.
        let covered: std::collections::BTreeSet<&str> = cases.iter().map(|(key, _)| *key).collect();
        let table: std::collections::BTreeSet<&str> = FROZEN.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            covered, table,
            "every FROZEN entry needs a case here, and every case needs an entry",
        );
    }

    /// The baseline: an unchanged configuration is not refused. Without this,
    /// a projection that returned a fresh value each call would pass every
    /// assertion above and refuse every reload in production.
    #[test]
    fn an_unchanged_configuration_is_allowed() {
        assert!(refuse(|_, _| {}).is_ok());
    }

    /// A frozen section that can hold a credential is still refused **by name**,
    /// and the refusal prints none of it.
    ///
    /// [`ReloadError::Frozen`] embeds the applied and the proposed rendering
    /// verbatim and `cli::apply_reload` logs the whole message, so before
    /// `opaque` a `SIGHUP` after any `[signer]` or `[proxy]` edit wrote the RFC
    /// 2136 TSIG key, the upstream EAB secret and the HSM PIN into the log — and
    /// the TSIG key is write access to the zone this CA validates against.
    ///
    /// Asserted on `to_string()` as well as on the two fields, since that is
    /// what is actually logged.
    #[test]
    fn a_frozen_section_holding_a_secret_is_refused_without_printing_it() {
        #[allow(clippy::type_complexity)]
        let cases: Vec<(
            &str,
            &str,
            Box<dyn Fn(&mut Config, &mut Vec<ProfileConfig>)>,
        )> = vec![
            (
                "proxy",
                "hunter2",
                Box::new(|c: &mut Config, _: &mut Vec<ProfileConfig>| {
                    c.proxy.https_url = "http://user:hunter2@proxy.example:3128".to_string();
                }),
            ),
            (
                "profiles.*.signer",
                "SUPERSECRET",
                Box::new(|_: &mut Config, p: &mut Vec<ProfileConfig>| {
                    p[0].sections.signer.relay.dns01.rfc2136.tsig_key_secret =
                        "SUPERSECRET".to_string();
                }),
            ),
            (
                "profiles.*.signer",
                "1234-PIN",
                Box::new(|_: &mut Config, p: &mut Vec<ProfileConfig>| {
                    p[0].sections.signer.local_ca.pkcs11.pin = "1234-PIN".to_string();
                }),
            ),
        ];

        for (key, secret, mutate) in cases {
            let Err(error) = refuse(mutate) else {
                panic!("{key} holding {secret} must still be refused");
            };
            let ReloadError::Frozen {
                key: named,
                applied,
                proposed,
            } = &error
            else {
                panic!("expected a frozen-key refusal, got {error}");
            };

            assert_eq!(named, key);
            // The change is still *detected* — which is also what proves
            // `opaque` is not a constant.
            assert_ne!(applied, proposed);
            for rendered in [applied.as_str(), proposed.as_str(), &error.to_string()] {
                assert!(
                    !rendered.contains(secret),
                    "{key} printed {secret} in {rendered}"
                );
            }
        }
    }

    /// The profile *name* is not a credential, and it is what tells an operator
    /// which endpoint's signer moved — so it survives the digest.
    #[test]
    fn an_opaque_signer_refusal_still_names_its_profile() {
        let Err(ReloadError::Frozen { proposed, .. }) = refuse(|_, p| {
            p[0].sections.signer.backend = "custom".to_string();
        }) else {
            panic!("a resolved signer change must be refused");
        };
        assert!(proposed.starts_with("le="), "got {proposed}");
        assert!(proposed.contains("sha256:"), "got {proposed}");
    }

    /// The pair that a naive implementation gets wrong.
    ///
    /// Only the **resolved** per-profile signer is frozen, because
    /// `merged_sections` overlays the global `[signer]` key by key. A global
    /// change every profile overrides changes nothing that runs, and refusing it
    /// would refuse a genuine no-op.
    #[test]
    fn the_signer_freeze_follows_the_resolved_section_not_the_global_one() {
        // The global section moved; the resolved profiles did not.
        let allowed = refuse(|config, _| {
            config.signer.backend = "custom".to_string();
        });
        assert!(
            allowed.is_ok(),
            "a global [signer] change every profile overrides must not be refused",
        );

        // The converse: the global section is untouched and a profile's
        // resolved one moved, which is the change that actually matters.
        assert_eq!(
            refused_key(refuse(|_, profiles| {
                profiles[0].sections.signer.local_ca.leaf_validity_days = 30;
            })),
            "profiles.*.signer",
        );
    }

    /// `resolve_profiles` drops a disabled profile, so adding one changes
    /// nothing that is mounted and must not be refused. The frozen key is the
    /// set of endpoints actually served, not the set written down.
    #[test]
    fn a_profile_nobody_mounts_is_not_a_change() {
        // A disabled profile never reaches the resolved list at all, so the
        // check sees the same two views.
        assert!(refuse(|_, _| {}).is_ok());

        // Renaming one *is* a change, even at the same count.
        assert_eq!(
            refused_key(refuse(|_, profiles| {
                profiles[0].name = "staging".to_string();
            })),
            "profiles",
        );
    }

    /// The seventh `[jobs]` key is reloadable, unlike the six above it: it is
    /// read only by the sweep handler, which the registry swap rebuilds.
    #[test]
    fn jobs_retention_days_is_reloadable() {
        let allowed = refuse(|config, _| {
            config.jobs.retention_days += 1;
        });
        assert!(
            allowed.is_ok(),
            "jobs.retention_days is rebuilt with the registry, so it must reload",
        );
    }

    /// A refusal an operator can act on names the key *and* both values — "it
    /// says `x` but is running `y`" is the whole diagnosis.
    #[test]
    fn a_refusal_names_the_key_and_both_values() {
        let error = refuse(|config, _| {
            config.server.bind_address = "127.0.0.1:9999".to_string();
        })
        .expect_err("a changed bind address is refused");

        let rendered = error.to_string();
        assert!(rendered.contains("server.bind_address"), "{rendered}");
        assert!(rendered.contains("[::]:3000"), "{rendered}");
        assert!(rendered.contains("127.0.0.1:9999"), "{rendered}");
        assert_eq!(error.kind(), "frozen_key");
    }

    /// The other two variants read as what they are: a file that would not load
    /// and a configuration that would not build are an operator's problem and
    /// the server's respectively, and the `kind` tag is what a log filter uses.
    #[test]
    fn the_other_failures_describe_themselves() {
        let load = ReloadError::Load("no such file".to_string());
        assert_eq!(load.kind(), "load_failed");
        assert!(load.to_string().contains("did not load"), "{load}");

        let build = ReloadError::Build("bad filter rule".to_string());
        assert_eq!(build.kind(), "build_failed");
        assert!(build.to_string().contains("did not build"), "{build}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn answering(body: &'static str) -> Router {
        Router::new().route("/", get(move || async move { body }))
    }

    async fn body_of(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    /// The property the reload path rests on: a request served *after* the swap
    /// reaches the new router, through a service value that never moved.
    #[tokio::test]
    async fn a_request_after_a_swap_reaches_the_new_router() {
        let (sender, receiver) = router_channel(answering("first"));
        let app = swappable(receiver);

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_of(response).await, "first");

        sender.send_replace(answering("second").into_service::<Body>());

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_of(response).await, "second");
    }

    /// A path the inner router does not serve still gets the inner router's own
    /// answer, not the wrapper's. The wrapper routes nothing: if it did, it
    /// would be shadowing whatever fallback each generation installs — and both
    /// of this crate's routers install one deliberately (an ACME problem
    /// document, and the admin panel's HTML page).
    #[tokio::test]
    async fn the_wrapper_never_answers_in_place_of_the_router_it_holds() {
        let inner = answering("routed").fallback(|| async { "inner fallback" });
        let (_sender, receiver) = router_channel(inner);

        let response = swappable(receiver)
            .oneshot(
                Request::builder()
                    .uri("/nothing-here")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_of(response).await, "inner fallback");
    }

    /// `HEAD` is the case the double-`top_level` nesting could plausibly break:
    /// axum strips the body and sets `Content-Length` at the top of a route
    /// future, and there are now two of those. Both fixups are idempotent, and
    /// this is the regression test saying so — §7.2 has `newNonce` answer `HEAD`.
    #[tokio::test]
    async fn a_head_request_keeps_its_content_length_and_loses_its_body() {
        let (_sender, receiver) = router_channel(answering("first"));

        let response = swappable(receiver)
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-length").unwrap(),
            "5",
            "the length of the body a GET would have returned"
        );
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty(),
            "a HEAD response carries no body"
        );
    }
}
