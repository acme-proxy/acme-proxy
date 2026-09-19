//! ACME (RFC 8555) Server Implementation
//!
//! This is a server-side implementation of the ACME protocol (RFC 8555) for
//! issuing and managing SSL/TLS certificates. It serves as a backend for
//! certificate clients like certbot and acme.sh.
//!
//! ## Features
//!
//! - The full RFC 8555 flow: directory, newNonce, newAccount, account
//!   lookup/update and deactivation, newOrder, authorizations and challenges,
//!   finalize, certificate retrieval via signed POST-as-GET, and revocation
//! - JWS signature verification for EC (ES256) and RSA (RS256) keys
//! - Automatic nonce management with replay protection
//! - Challenge validation behind pluggable validators (`http-01`, `dns-01`,
//!   `tls-alpn-01`), with a configurable bypass
//! - Certificate issuance behind a pluggable signer backend: a local CA (whose
//!   key may live in a PKCS#11 token), a relay to an upstream ACME CA, or an
//!   operator-supplied script
//! - **Profiles** — several independent ACME endpoints in one process, each with
//!   its own signer, filters, challenge validators and EAB policy
//! - External Account Binding (§7.3.4), account key rollover (§7.3.5) and
//!   Renewal Information (RFC 9773)
//! - Access control behind a policy engine of named checks combined by boolean
//!   rules, including an IPAM lookup (NetBox, phpIPAM or a script) asking the
//!   inventory whether the client's own address owns the names it is requesting
//! - An append-only audit trail of every issuance *and every refusal*
//! - An optional web admin listener, and admin subcommands in the same binary
//! - Optional Prometheus metrics on a third listener of their own
//! - A durable job queue, so work the server owes itself survives a restart and
//!   an upstream blip is retried rather than invalidating a client's order
//! - Configuration reload on `SIGHUP` — a rebuild and a swap, with
//!   `database.url` the only key that still needs a restart
//! - `SQLite` persistence for accounts, nonces, orders and the audit trail
//! - Configurable via TOML, environment variables, or defaults
//!
//! ## Architecture
//!
//! One binary over a workspace of library crates, each naming only the crates
//! beneath it — so the layering is the compiler's to enforce. Bottom-up:
//!
//! - [`acme_proxy_core`] - Configuration, the ACME wire types (identifiers,
//!   JWS, problem documents, routes), certificate parsing, EAB and key-change
//!   verification, and the audit trail's vocabulary
//! - [`acme_proxy_store`] - The SQLite storage layer, one module per table, and
//!   the embedded migrations
//! - [`acme_proxy_net`] - DNS, outbound HTTP and forward proxies, TLS, the
//!   listeners, and the challenge validators (http-01, dns-01, tls-alpn-01)
//! - [`acme_proxy_policy`] - The filter engine (who may ask for what) and the
//!   IPAM inventories one of its checks consults
//! - [`acme_proxy_jobs`] - The durable job queue, the notifications delivered
//!   through it, the audit writer and the Prometheus metrics
//! - [`acme_proxy_signer`] - The signing backends (local CA, ACME relay, custom
//!   script) and their read side
//! - [`acme_proxy_protocol`] - The ACME services, the extractors that verify a
//!   signed request before a handler runs, the handlers, the middlewares, and
//!   the routers
//! - [`acme_proxy_admin`] - The operation layer both front ends dispatch to,
//!   and the web admin panel over it
//! - [`acme_proxy_server`] - The runtime: role processes, listeners,
//!   configuration reload and logging
//!
//! This crate is the binary and its terminal front end: [`cli`], the `clap`
//! command tree.
//!
//! ## Usage
//!
//! The main entry point is `router::build_app()`, which mounts one ACME router
//! per configured profile under `/profile/<name>` and serves the server-level
//! routes (`/health`) at the root.
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use acme_proxy_protocol::profile::{Profile, ProfileParts};
//! use acme_proxy_protocol::router::build_app;
//! use acme_proxy_store::db::Database;
//! use acme_proxy_signer as signer;
//! use acme_proxy_jobs::{jobs, notify};
//! use acme_proxy_policy::{filter, ipam};
//! use acme_proxy_net::challenge;
//! use acme_proxy_core::config::Config;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Arc::new(Config::load()?);
//!     let database = Arc::new(Database::connect_and_migrate(&config.database.url).await?);
//!
//!     let resolved = config.resolve_profiles()?;
//!     // The resolver and the proxy policy, resolved before anything can dial:
//!     // a proxy URL that cannot be understood must stop the process rather
//!     // than leave egress elsewhere, and `dns.resolver` governs every outbound
//!     // connection this server makes, not just challenge lookups. Bundled,
//!     // because every outbound client takes them together — and because the
//!     // rendering beside them is what tells a reload whether a signer backend
//!     // has to be rebuilt.
//!     let egress = Arc::new(acme_proxy_net::egress::Egress::from_config(&config)?);
//!     let outbound = egress.outbound();
//!     // The enqueue side of the durable queue, built first because everything
//!     // below queues into it. A backend that defers issuance (`relay`) is
//!     // handed one at construction, and so is every notify dispatcher — a
//!     // notification is a job row too. The runner that drains it is started
//!     // separately, below.
//!     let job_queue = jobs::JobQueue::new(database.clone(), &config.jobs);
//!     // Built once, up front: an asynchronous signer backend (`relay`)
//!     // has no `Profile` to reach a notifier through from its background
//!     // completion task, so it is handed this whole map instead — and so is
//!     // the `NotifyJob` that performs the deliveries.
//!     let mut notifiers = std::collections::HashMap::new();
//!     for profile in &resolved {
//!         notifiers.insert(
//!             profile.name.clone(),
//!             notify::from_config(
//!                 &profile.name,
//!                 &profile.sections.notify,
//!                 outbound.clone(),
//!                 &job_queue,
//!             )?,
//!         );
//!     }
//!     let notifiers = Arc::new(notifiers);
//!     // The Prometheus counters. Built here rather than per generation, so a
//!     // `SIGHUP` does not reset every counter to zero — see `Assembly`.
//!     let metrics = Arc::new(acme_proxy_jobs::metrics::Metrics::new(database.clone()));
//!
//!     let mut profiles = Vec::new();
//!     // Each profile's signer in two halves: the backend, which holds the key
//!     // and is handed only to the job handlers below, and its read side, which
//!     // is all a profile — and so a request — ever sees.
//!     let mut backends = Vec::new();
//!     for profile in &resolved {
//!         let sections = &profile.sections;
//!         let backend = signer::from_config(
//!             &sections.signer,
//!             &signer::SignerParts {
//!                 database: database.clone(),
//!                 notifiers: notifiers.clone().into(),
//!                 metrics: metrics.clone(),
//!                 egress: egress.clone(),
//!                 jobs: job_queue.clone(),
//!             },
//!         )?;
//!         backends.push((profile.name.clone(), backend.clone()));
//!         profiles.push(Arc::new(Profile::new(
//!             &profile.name,
//!             &config.server.base_url,
//!             ProfileParts {
//!                 signer_info: backend.info(),
//!                 filter: filter::from_config(
//!                     &sections.filter,
//!                     &config.dns,
//!                     ipam::from_config(&sections.ipam, outbound.clone())?,
//!                     sections.eab.enabled,
//!                 )?,
//!                 challenges: challenge::from_config(
//!                     &sections.challenge,
//!                     &config.dns,
//!                     egress.proxies.clone(),
//!                 )?,
//!                 order: sections.order.clone(),
//!                 eab: sections.eab.clone(),
//!                 meta: sections.meta.clone(),
//!                 notify: notifiers[&profile.name].clone(),
//!             },
//!         )));
//!     }
//!     // Process-wide, like `[audit]` itself: one trail for the whole CA,
//!     // shared by every profile's router and by the web admin listener.
//!     // The registry is a parameter rather than a builder step, so a serving
//!     // process cannot build an auditor that counts into nothing. The counters
//!     // come off the same `AuditRecord` the trail is written from, so the two
//!     // can never disagree.
//!     let audit = Arc::new(acme_proxy_jobs::auditor::Auditor::from_config(
//!         &config.audit,
//!         &config.dns,
//!         database.clone(),
//!         metrics.clone(),
//!     )?);
//!     // The queue goes in too: `POST /chall/{id}` claims a challenge and
//!     // queues its validation rather than performing it inside the request.
//!     let app = build_app(
//!         database.clone(),
//!         config.clone(),
//!         profiles,
//!         audit.clone(),
//!         metrics.clone(),
//!         job_queue.clone(),
//!     );
//!
//!     // One runner drains the queue for the process. Every handler comes from
//!     // a subsystem that has background work — relayed issuance, notification
//!     // delivery, the periodic table sweeps — and the runner calls `recover`
//!     // on each before it claims anything, which is how work a previous run
//!     // left in flight is picked back up, and how each sweep's single row gets
//!     // queued. **One handler per kind, never per backend**: a handler covers
//!     // every profile or backend of its kind and picks the right one per row,
//!     // since `register` refuses a second handler for a kind it already has.
//!     let mut registry = jobs::JobRegistry::new();
//!     // `finalize` queues the signing: this is the one handler that asks a
//!     // backend to issue, and the one place a backend is handed out.
//!     registry.register(Arc::new(acme_proxy_protocol::acme::issue::SignerIssueJob::new(
//!         database.clone(),
//!         audit,
//!         backends,
//!         notifiers.clone().into(),
//!     )))?;
//!     registry.register(Arc::new(notify::NotifyJob::new(notifiers)))?;
//!     registry.register(Arc::new(jobs::SweepJob::nonces(
//!         database.clone(),
//!         std::time::Duration::from_secs(config.nonce.ttl_seconds),
//!     )))?;
//!     let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
//!     jobs::spawn_runner(job_queue, Arc::new(registry), &config.jobs, shutdown_rx);
//!
//!     let listener = tokio::net::TcpListener::bind(&config.server.bind_address).await?;
//!     axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod cli;

// Re-export name shape helpers for backwards compatibility
