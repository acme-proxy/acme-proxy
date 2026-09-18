// Feature badges on docs.rs. Turned on by `--cfg docsrs` from
// `[package.metadata.docs.rs]`, so a stable `cargo doc`, `cargo build` and
// clippy never see this nightly-only attribute. `doc_cfg` annotates every
// `#[cfg(…)]` item on its own, so the `hsm`-gated items need no per-item
// attribute and a future one is covered for free — the behaviour that used to
// be a separate `doc_auto_cfg` feature, removed in 1.92 and merged into this
// one. Do not reintroduce that name; it no longer compiles.
#![cfg_attr(docsrs, feature(doc_cfg))]

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
//! The ACME request path, in the order a request meets it:
//! - [`middlewares`] - Server-wide layers: request correlation and the access
//!   line, admission control, the `Replay-Nonce` and `Link: rel="index"` headers
//! - [`filter`] - Pluggable request filtering (who may ask at all)
//! - [`extractors`] - Parse and validate ACME JWS requests, verifying the media
//!   type, the `crit` header, the signature, the JWS `url` and the nonce before
//!   any handler runs
//! - [`handlers`] - One module per ACME resource: the HTTP edge
//! - [`acme`] - The ACME domain rules every front end shares
//! - [`challenge`] - Pluggable challenge validators (http-01, dns-01, tls-alpn-01)
//! - [`signer`] - Pluggable certificate-issuance backends (local CA, ACME relay,
//!   custom script)
//!
//! Supporting subsystems:
//! - [`audit`] - The durable record of who asked this CA to sign or revoke
//! - [`notify`] - Pluggable operator notifications on lifecycle events (email,
//!   webhook, custom)
//! - [`ipam`] - The inventory [`filter`] asks which names an address owns
//!   (NetBox, phpIPAM, a custom script), behind one trait
//! - [`eab`] - Verification of the External Account Binding inner JWS (§7.3.4)
//! - [`key_change`] - Verification of account key rollover JWS (§7.3.5)
//! - [`dns`] - The resolver shared by every subsystem that looks anything up
//! - [`http_client`] - The transport every outbound HTTP client is built on,
//!   including the `CONNECT` tunnel
//! - [`proxy`] - Which forward proxy, if any, that transport dials through
//! - [`script_hook`] - The hardened contract every `custom` hook runs under
//! - [`tls`] - Optional HTTPS termination for either listener
//! - [`cert`] - X.509 parsing helpers (serial, SPKI, leaf-from-chain)
//! - [`pemfile`] - PEM reading, atomic writing and key-permission warnings
//! - [`sqlite`] - Database access, one module per table
//! - [`routes`] - The ACME resource paths and the profile namespace
//! - [`logfields`] - Typed helpers for structured log fields
//! - [`config`] - Configuration loading from multiple sources
//! - [`error`] - ACME error types and problem document rendering
//!
//! Process lifecycle — what keeps the server running and lets it be retuned
//! without a restart:
//! - [`server`] - The runtime: profiles, routers, and the generation a startup
//!   builds and a reload rebuilds and publishes
//! - [`listener`] - The sockets, and replacing one while it serves
//! - [`reload`] - Rebuild-and-swap on `SIGHUP`; nothing is mutated in place
//! - [`jobs`] - The durable queue and its runner, so work outlives the process
//!   that queued it
//! - [`metrics`] - The Prometheus registry and its text exposition
//!
//! Administration, which serves no ACME and is a second listener plus a CLI:
//! - [`admin`] - The operation layer both front ends dispatch to
//! - [`webadmin`] - The optional HTML + JSON admin listener
//! - [`cli`] - The `clap` command tree
//!
//! ## Usage
//!
//! The main entry point is `server::build_app()`, which mounts one ACME router
//! per configured profile under `/profile/<name>` and serves the server-level
//! routes (`/health`) at the root.
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use acme_proxy::server::{Profile, ProfileParts, build_app};
//! use acme_proxy::sqlite::db::Database;
//! use acme_proxy::{challenge, config::Config, filter, ipam, jobs, notify, signer};
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
//!     let egress = Arc::new(acme_proxy::server::Egress::from_config(&config)?);
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
//!     let metrics = Arc::new(acme_proxy::metrics::Metrics::new(database.clone()));
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
//!     let audit = Arc::new(acme_proxy::audit::Auditor::from_config(
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
//!     registry.register(Arc::new(acme_proxy::acme::issue::SignerIssueJob::new(
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

pub mod acme;
pub mod admin;
pub mod audit;
pub mod cert;
pub mod challenge;
pub mod cli;
pub mod client;
pub mod config;
pub mod dns;
pub mod eab;
pub mod error;
pub mod extractors;
pub mod filter;
pub mod handlers;
pub mod http_client;
pub mod ipam;
pub mod jobs;
pub mod jws;
pub mod key_change;
pub mod listener;
pub mod logfields;
pub mod metrics;
pub mod middlewares;
pub mod notify;
pub mod pemfile;
pub mod proxy;
mod random;
pub mod reload;
pub mod routes;
pub mod script_hook;
pub mod server;
pub mod signer;
pub mod sqlite;
mod templating;
#[cfg(test)]
pub(crate) mod testutil;
pub mod tls;
pub mod webadmin;

// Re-export name shape helpers for backwards compatibility
pub use acme::rules::{is_wildcard, normalize_dns_name, well_formed_name};
