use std::io::BufRead;
use std::sync::Arc;
use uuid::Uuid;

use clap::Subcommand;

use crate::cli::CliError;
use crate::cli::render;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use acme_proxy_admin::admin;
use acme_proxy_admin::admin::DeleteOutcome;
use acme_proxy_core::config::Config;
use acme_proxy_core::palette::Palette;
use acme_proxy_signer as signer;
use acme_proxy_store::authz::Authorization;
use acme_proxy_store::db::Database;
use acme_proxy_store::order::Order;
use acme_proxy_store::order::OrderQuery;
use acme_proxy_store::status::OrderStatus;

#[derive(Subcommand)]
pub enum OrderCommand {
    /// List orders, optionally filtered.
    List {
        /// Restrict the listing to one ACME endpoint.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long = "account-id")]
        account_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Only orders naming this identifier exactly (case-insensitive).
        #[arg(long)]
        identifier: Option<String>,
        /// Only orders naming an identifier that contains this substring
        /// (case-insensitive). Mutually exclusive with `--identifier`.
        #[arg(long = "identifier-contains", conflicts_with = "identifier")]
        identifier_contains: Option<String>,
        /// Only the order whose issued certificate has this serial (hex, no
        /// separators) -- the value an abuse report hands you.
        #[arg(long = "cert-serial")]
        cert_serial: Option<String>,
        /// Instead: the certificates lapsing within N days, soonest first,
        /// each annotated with whatever has already replaced it.
        #[arg(long = "expiring-in")]
        expiring_in: Option<u64>,
        /// Omit certificates something has already replaced. Needs
        /// `--expiring-in`, which is where the annotation comes from.
        #[arg(long = "hide-superseded")]
        hide_superseded: bool,
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one order plus its authorizations and challenges.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Print the issued certificate chain, as PEM, on stdout.
    Chain { id: String },
    /// Hard-delete the order and everything under it.
    Delete { id: String },
    /// Revoke the order's issued certificate.
    Revoke {
        id: String,
        #[arg(long)]
        reason: Option<u32>,
        /// For a `relay` or `custom` profile, how many seconds to wait for a
        /// running server to perform the queued revocation before returning.
        /// `0` queues it and returns at once. A local CA's revocation is
        /// recorded immediately and does not wait.
        #[arg(long, default_value_t = DEFAULT_REVOKE_WAIT_SECONDS)]
        wait: u64,
    },
}

pub async fn run_order_command(
    command: OrderCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    config: &Config,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        OrderCommand::List {
            profile,
            account_id,
            status,
            identifier,
            identifier_contains,
            cert_serial,
            expiring_in,
            hide_superseded,
            limit,
            offset,
            json,
        } => {
            let window = Window::resolve(limit, offset);

            // `--expiring-in` is a different question over a different query,
            // and the flags that do not compose with it are refused **by name**
            // rather than ignored -- `--status`'s own rule, and for its reason:
            // an argument silently dropped answers with rows that look like it
            // was honoured. The window is not among them: it is the one flag
            // that means the same thing on both queries, so it is passed
            // straight through.
            if let Some(days) = expiring_in {
                return run_expiring(
                    days,
                    profile,
                    account_id.as_deref(),
                    status.as_deref(),
                    identifier.as_deref(),
                    identifier_contains.as_deref(),
                    cert_serial.as_deref(),
                    hide_superseded,
                    window,
                    json,
                    palette,
                    database,
                )
                .await;
            }
            if hide_superseded {
                return Err(CliError::bad_request(
                    "--hide-superseded needs --expiring-in: it filters on the supersession \
                     annotation, which only the expiry listing carries"
                        .to_string(),
                ));
            }

            // Refused by name rather than passed through: an unknown status
            // would match no rows, which reads exactly like "nothing is in
            // that state". The same rule `audit list --event` follows.
            let status = status
                .map(|value| value.parse::<OrderStatus>())
                .transpose()
                .map_err(|error| CliError::bad_request(format!("--status: {error}")))?;

            // Filtered in SQL, by the same `Order::search` the web admin uses.
            // It used to load every order in the database and filter the three
            // fields in Rust, which is one policy written twice — and the two
            // could drift into disagreeing about what `--status` means.
            let query = OrderQuery {
                profile,
                account_id,
                status,
                identifier,
                identifier_contains,
                // Folded here rather than bound raw: an operator pastes a
                // serial out of `openssl` or an abuse report, and the column
                // only ever holds lowercase unseparated hex.
                cert_serial: cert_serial
                    .as_deref()
                    .map(acme_proxy_core::cert::normalize_serial),
                limit: window.limit,
                offset: window.offset,
            };
            let (orders, total) = Order::search(&query, &database).await?;
            // Not `render::print_page`, and this is the only listing that opts
            // out: the `--json` rendering needs one batched authorization
            // lookup for the whole page, not one query per row — the N+1 the
            // web admin's `render_orders` already avoids, and what
            // `find_ids_by_orders` exists for. Handing that closure to
            // `print_page` would make the text path pay for a query it never
            // reads, so the two halves are spelled out and the shared envelope
            // and footer are called directly.
            if json {
                let ids: Vec<Uuid> = orders.iter().map(|o| o.id).collect();
                let mut authz_ids = Authorization::find_ids_by_orders(&ids, &database).await?;
                let rendered: Vec<_> = orders
                    .iter()
                    .map(|order| {
                        admin::render_order_json(
                            order,
                            &config.server.base_url,
                            &authz_ids.remove(&order.id).unwrap_or_default(),
                        )
                    })
                    .collect();
                println!("{}", render::json_page(rendered, total, window));
            } else {
                for order in &orders {
                    println!("{}", render::render_order_line(order, palette));
                }
                render::print_footer(orders.len(), total);
            }
        }
        OrderCommand::Show { id, json } => match admin::load_order_detail(&id, database).await? {
            None => return Err(not_found(&id)),
            Some(detail) if json => {
                println!(
                    "{}",
                    admin::render_order_detail_json(&detail, &config.server.base_url)
                );
            }
            Some(detail) => print!("{}", render::render_order_detail_text(&detail, palette)),
        },
        OrderCommand::Chain { id } => {
            // The whole of stdout, so it pipes: `order chain <id> > cert.pem`.
            // Deliberately not a flag on `show` -- a flag that discards the rest
            // of its command's output is a mode wearing a flag's clothes. The
            // JSON side already had this as `certificatePem` on
            // `render_order_detail_json`; what was missing was the raw bytes.
            let Some(order) = Order::find_by_id(&id, &database).await? else {
                return Err(not_found(&id));
            };
            // Refused rather than answered with zero bytes, the rule
            // `GET /ui/orders/{id}/chain.pem` already keeps: an empty file named
            // `.pem` reads as a broken certificate rather than an absent one.
            let Some(pem) = order.certificate else {
                return Err(CliError::bad_request(format!(
                    "order {id} has no certificate: it has not been finalized"
                )));
            };
            // `print!`: the stored chain already ends in a newline, and a second
            // one would make the output differ from the file the panel serves.
            print!("{pem}");
        }
        OrderCommand::Delete { id } => {
            // Read the order first, for its profile and identifiers: the audit
            // row names them and the row is gone once the delete returns. Both
            // web front ends already wrote `order_deleted`; this one hard-
            // deleted an order and left the trail silent.
            let doomed = Order::find_by_id(&id, &database).await?;
            match admin::confirm_delete_order(&id, yes, reader, database.clone()).await? {
                DeleteOutcome::NotFound => return Err(not_found(&id)),
                DeleteOutcome::LiveCertificates(live) => {
                    return Err(CliError::bad_request(admin::live_certificates_refusal(
                        &format!("order {id}"),
                        live,
                    )));
                }
                DeleteOutcome::Cancelled => println!("Cancelled."),
                DeleteOutcome::Deleted(deleted) => {
                    if let Some(order) = doomed {
                        acme_proxy_jobs::auditor::admin::record_cli_action(
                            &database,
                            |actor, client| {
                                acme_proxy_jobs::auditor::admin::order_deleted(
                                    actor,
                                    client,
                                    &order,
                                    deleted.cascaded,
                                )
                            },
                        )
                        .await;
                    }
                    println!(
                        "Deleted order {id} ({} authorization(s) cascaded).",
                        deleted.cascaded
                    );
                }
            }
        }
        OrderCommand::Revoke { id, reason, wait } => {
            // Revocation goes through the endpoint that issued the certificate:
            // another profile's backend holds a different CA, or none at all.
            let Some(order) = Order::find_by_id(&id, &database).await? else {
                return Err(not_found(&id));
            };
            let profiles = config
                .resolve_profiles()
                .map_err(|error| CliError::failed(format!("configuration error: {error}")))?;
            let Some(profile) = profiles.iter().find(|p| p.name == order.profile) else {
                return Err(CliError::bad_request(format!(
                    "order {id} was issued by profile `{}`, which this configuration does not \
                     define — revoking it needs the endpoint that signed it",
                    order.profile
                )));
            };
            // Before anything reads the signer's configuration: an order with
            // nothing to revoke is the operator's answer, whatever state the
            // CA's files are in. `admin::revoke_order` makes the same check
            // against the row it re-reads.
            if order.certificate.is_none() {
                return Err(CliError::bad_request(format!(
                    "order {id} has no issued certificate"
                )));
            }
            // Queued, not sent: the running server's worker delivers the
            // `certificate_revoked` notification this revocation owes.
            let notifiers = super::offline_notifiers(config, database.clone())?;
            let notify = notifiers
                .get(&order.profile)
                .map(|dispatcher| dispatcher.as_ref());
            let audit = acme_proxy_jobs::auditor::Auditor::offline(database.clone());
            // A queue this process never drains: what it enqueues, a running
            // server's job runner works off.
            let jobs = acme_proxy_jobs::jobs::JobQueue::new(database.clone(), &config.jobs);
            let route = signer::revocation_route(&profile.sections.signer)
                .map_err(|error| CliError::failed(format!("signer error: {error}")))?;
            // `Actor::cli` and an empty client context: there is no request
            // here, and the audit row says so rather than inventing an address.
            let (actor, client) = (
                acme_proxy_core::audit::Actor::cli(),
                acme_proxy_core::audit::ClientContext::default(),
            );

            // A local CA's revocation is recorded here, without its key, and a
            // running server's worker signs the CRL; a backend only the worker
            // holds gets the revocation queued, and this waits `--wait` for it.
            let revoker = acme_proxy_protocol::acme::revoke::Revoker::for_route(
                &route,
                &jobs,
                std::time::Duration::from_secs(wait),
            );
            let outcome = admin::revoke_order(
                &id,
                reason,
                actor,
                client,
                &audit,
                database.clone(),
                revoker,
                notify,
            )
            .await;
            // A bad `--reason` code is the operator's to fix (exit 3); every
            // other revoke failure is the host's (a signer or database error).
            match outcome.map_err(|error| match error {
                admin::RevokeError::BadReason(_) => CliError::bad_request(error.to_string()),
                admin::RevokeError::Abandoned { job, reason } => CliError::failed(format!(
                    "the revocation of order {id} failed (job {job}): {reason}"
                )),
                other => CliError::failed(other.to_string()),
            })? {
                admin::RevokeOutcome::NotFound => return Err(not_found(&id)),
                admin::RevokeOutcome::NotIssued => {
                    return Err(CliError::bad_request(format!(
                        "order {id} has no issued certificate"
                    )));
                }
                admin::RevokeOutcome::AlreadyRevoked => {
                    return Err(CliError::bad_request(format!(
                        "order {id}'s certificate is already revoked"
                    )));
                }
                // Running out of time is not a failure: the revocation is
                // queued, and the message says where to follow it.
                admin::RevokeOutcome::Queued(job) => println!(
                    "Revocation of order {id} queued as job {job}; a running server performs it \
                     (acme-proxy jobs show {job})."
                ),
                admin::RevokeOutcome::Revoked(order) => {
                    println!("{}", render::render_order_line(&order, palette));
                    if let signer::RevocationRoute::Ledger { issuer } = &route {
                        let job = acme_proxy_store::job::Job::find_live(
                            acme_proxy_signer::local_ca::sweep::CRL_REGENERATE_KIND,
                            issuer,
                            &database,
                        )
                        .await?;
                        match job {
                            Some(job) => println!(
                                "CRL regeneration queued (job {}); a running server signs it.",
                                job.id
                            ),
                            None => println!("CRL regeneration already done."),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// How long `order revoke` waits for a queued revocation by default.
const DEFAULT_REVOKE_WAIT_SECONDS: u64 = 30;

/// `order list --expiring-in <days>`.
///
/// A branch rather than a sibling subcommand because it is still "list orders",
/// asked with a different filter -- but it is a different *query*
/// (`Order::find_expiring`, ordered by expiry rather than by age) with its own
/// fixed status set, so the two filters that cannot mean anything here are
/// refused instead of ignored.
///
/// Paged like the rest of `order list`, and reporting `hidden` beside the total
/// exactly as `GET /api/expiring` does -- `total` counts the *window*, not the
/// answer, because supersession is computed per row and cannot become a SQL
/// predicate. `acme_proxy_store::expiring::annotate_expiring` still reads each account's orders once
/// for the whole page rather than once per row, which is what keeps a page over
/// a single busy account from re-reading its history fifty times.
#[allow(clippy::too_many_arguments)]
async fn run_expiring(
    days: u64,
    profile: Option<String>,
    account_id: Option<&str>,
    status: Option<&str>,
    identifier: Option<&str>,
    identifier_contains: Option<&str>,
    cert_serial: Option<&str>,
    hide_superseded: bool,
    window: Window,
    json: bool,
    palette: Palette,
    database: Arc<Database>,
) -> Result<(), CliError> {
    if status.is_some() {
        return Err(CliError::bad_request(
            "--status does not apply with --expiring-in: the expiry listing is issued, \
             unrevoked certificates by definition, so a status filter here would mean \
             something other than it does everywhere else"
                .to_string(),
        ));
    }
    if account_id.is_some() {
        return Err(CliError::bad_request(
            "--account-id does not apply with --expiring-in: the expiry listing has no \
             account predicate, and answering as though it did would report one \
             subscriber's certificates as every subscriber's"
                .to_string(),
        ));
    }
    if identifier.is_some() || identifier_contains.is_some() || cert_serial.is_some() {
        return Err(CliError::bad_request(
            "--identifier, --identifier-contains and --cert-serial do not apply with \
             --expiring-in: the expiry listing is ordered by expiry over a fixed status \
             set, so a name or serial filter here would mean something other than it \
             does on the plain listing"
                .to_string(),
        ));
    }

    let query = acme_proxy_store::expiring::ExpiringQuery {
        profile,
        before: acme_proxy_store::expiring::expiring_horizon(days),
        include_superseded: !hide_superseded,
        limit: window.limit,
        offset: window.offset,
    };
    let (entries, total, hidden) =
        acme_proxy_store::expiring::list_expiring(&query, database).await?;
    if json {
        let items = entries.iter().map(admin::render_expiring_json).collect();
        let mut envelope = render::json_page(items, total, window);
        if let Some(object) = envelope.as_object_mut() {
            // The same two extra members `GET /api/expiring` adds, spelled the
            // same way: one answer to "what is expiring" rendered identically
            // wherever it is asked.
            object.insert("hidden".to_string(), serde_json::json!(hidden));
            object.insert("days".to_string(), serde_json::json!(days));
        }
        println!("{envelope}");
    } else {
        for entry in &entries {
            println!("{}", render::render_expiring_line(entry, palette));
        }
        render::print_expiring_footer(entries.len(), total, hidden);
    }
    Ok(())
}

fn not_found(id: &str) -> CliError {
    CliError::bad_request(format!("no such order: {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliErrorKind;
    use acme_proxy_core::audit::ClientContext;
    use acme_proxy_signer::IssueOutcome;
    use acme_proxy_signer::RequestedValidity;
    use acme_proxy_signer::SignerBackend;
    use acme_proxy_store::account::Account;

    /// A configuration whose single `default` profile signs with a local CA
    /// living under `dir` — what `Revoke` needs, since it rebuilds the signer
    /// from the profile that issued the certificate.
    fn config_in(dir: impl AsRef<std::path::Path>, profile: &str) -> Config {
        let dir = dir.as_ref();
        let _lock = acme_proxy_core::config::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ca = dir.join("ca");
        std::fs::write(
            dir.join("config.toml"),
            format!(
                r#"
                [profiles.{profile}]
                signer.local_ca.cert_path = "{ca}.pem"
                signer.local_ca.key_path = "{ca}.key"
                signer.local_ca.crl_path = "{ca}.crl"
                "#,
                ca = ca.display(),
            ),
        )
        .unwrap();
        // SAFETY: the lock above makes this the only thread touching the
        // environment, and the variable is removed before returning.
        unsafe {
            std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
        }
        let config = Config::load().expect("the configuration must load");
        unsafe {
            std::env::remove_var("ACME_PROXY_CONFIG");
        }
        config
    }

    fn temp_dir() -> acme_proxy_core::testutil::TempDir {
        acme_proxy_core::testutil::TempDir::new("cli-order")
    }

    /// `order delete` records what it removed.
    ///
    /// It recorded nothing at all: both web front ends wrote `order_deleted`,
    /// and the CLI — the only front end that hard-deletes an order from a
    /// shell — left the trail silent. A declined prompt still writes nothing,
    /// which is the rule for this whole half of the vocabulary.
    #[tokio::test]
    async fn deleting_an_order_writes_a_row_and_a_decline_does_not() {
        use acme_proxy_store::audit::AuditEntry;
        use acme_proxy_store::audit::AuditQuery;

        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let order = seed_order(&database, "default").await;
        let id = order.id.to_string();

        let mut declined: &[u8] = b"n\n";
        run_order_command(
            OrderCommand::Delete { id: id.clone() },
            false,
            Palette::plain(),
            &mut declined,
            &config,
            database.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            AuditEntry::search(&AuditQuery::default(), &database)
                .await
                .unwrap()
                .1,
            0,
            "a declined delete is not an administrative action"
        );

        let mut reader: &[u8] = &[];
        run_order_command(
            OrderCommand::Delete { id: id.clone() },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .unwrap();

        let (rows, total) = AuditEntry::search(
            &AuditQuery {
                limit: 5,
                ..AuditQuery::default()
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].event, "order_deleted");
        assert_eq!(rows[0].actor_kind, "cli");
        assert_eq!(rows[0].profile, "default");
        assert_eq!(rows[0].order_id.as_deref(), Some(id.as_str()));
        // The row outlives the order it names — `audit_log` has no foreign
        // keys, which is the whole reason it can record a deletion.
        assert!(
            Order::find_by_id(&id, &database).await.unwrap().is_none(),
            "the order really went"
        );
    }

    async fn seed_order(database: &Arc<Database>, profile: &str) -> Order {
        let (account, _) = Account::find_or_create(
            profile,
            &[4, 5, 6],
            vec![],
            &ClientContext::default(),
            database,
        )
        .await
        .unwrap();
        Order::create(
            profile,
            account.id,
            vec![acme_proxy_core::identifier::Identifier::dns("example.com")],
            acme_proxy_store::nonce::now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap()
    }

    /// Issues against `config`'s own CA and records the result on `order`, so
    /// the certificate the CLI later revokes is one that CA actually signed.
    /// Returns the CA, which the caller initializes (as a server's startup
    /// does) when it wants a revocation recorded against it.
    async fn issue_onto(
        order: &mut Order,
        config: &Config,
        database: Arc<Database>,
    ) -> Arc<dyn SignerBackend> {
        let profile = &config.resolve_profiles().unwrap()[0];
        let resolver = acme_proxy_net::dns::resolver_addr(&config.dns)
            .and_then(acme_proxy_net::challenge::build_resolver)
            .expect("the default dns configuration must build a resolver");
        let signer: Arc<dyn SignerBackend> = signer::from_config(
            &profile.sections.signer,
            &acme_proxy_signer::testutil::signer_parts(database.clone(), resolver),
        )
        .unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let chain = match signer
            .issue(
                order.id.to_string().as_str(),
                csr.der(),
                &order.identifiers,
                RequestedValidity::default(),
            )
            .await
            .unwrap()
        {
            IssueOutcome::Issued(chain) => chain,
            IssueOutcome::Processing => panic!("the local CA issues synchronously"),
        };
        let leaf = acme_proxy_core::cert::leaf_der_from_chain(&chain).unwrap();
        let (serial, pubkey) = acme_proxy_core::cert::cert_serial_and_spki(&leaf).unwrap();
        let not_after = acme_proxy_core::cert::cert_validity(&leaf)
            .ok()
            .map(|(_, na)| na);
        order
            .finalize(chain, serial, pubkey, not_after, &database)
            .await
            .unwrap();
        signer
    }

    #[tokio::test]
    async fn every_arm_refuses_an_unknown_order() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let expected = CliError::bad_request("no such order: ord-nope".to_string());

        let commands = vec![
            OrderCommand::Show {
                id: "ord-nope".to_string(),
                json: false,
            },
            OrderCommand::Chain {
                id: "ord-nope".to_string(),
            },
            OrderCommand::Delete {
                id: "ord-nope".to_string(),
            },
            OrderCommand::Revoke {
                id: "ord-nope".to_string(),
                reason: None,
                wait: 0,
            },
        ];
        for command in commands {
            let mut reader: &[u8] = &[];
            let error = run_order_command(
                command,
                true,
                Palette::plain(),
                &mut reader,
                &config,
                database.clone(),
            )
            .await
            .expect_err("an unknown order must fail");
            assert_eq!(error, expected);
        }
    }

    /// The PEM on stdout, and the refusal that keeps it honest: an order that
    /// never reached issuance is an error, not an empty file --
    /// `GET /ui/orders/{id}/chain.pem`'s own rule, since zero bytes named
    /// `.pem` read as a broken certificate rather than an absent one.
    #[tokio::test]
    async fn chain_prints_the_issued_pem_and_refuses_an_order_with_none() {
        let dir = temp_dir();
        let config = config_in(&dir, "default");
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let mut order = seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Chain {
                id: order.id.to_string(),
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .expect_err("an order with no certificate has no chain to print");
        assert_eq!(
            error,
            CliError::bad_request(format!(
                "order {} has no certificate: it has not been finalized",
                order.id
            ))
        );

        issue_onto(&mut order, &config, database.clone()).await;

        // What the command prints is the column, verbatim -- the same string
        // `render_order_detail_json`'s `certificatePem` and the panel's download
        // both hand over.
        let stored = Order::find_by_id(order.id.to_string().as_str(), &database)
            .await
            .unwrap()
            .unwrap()
            .certificate
            .expect("finalize stored the chain");
        assert!(stored.starts_with("-----BEGIN CERTIFICATE-----"));

        let mut reader: &[u8] = &[];
        run_order_command(
            OrderCommand::Chain {
                id: order.id.to_string(),
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database,
        )
        .await
        .unwrap();
    }

    /// `revoke` needs the endpoint that signed the certificate. A profile the
    /// running configuration no longer defines says so, rather than silently
    /// revoking against some other profile's CA.
    #[tokio::test]
    async fn revoking_an_order_from_an_undefined_profile_is_refused() {
        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        // The order belongs to `default`; the configuration only mounts `other`.
        let order = seed_order(&database, "default").await;
        let config = config_in(&dir, "other");

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: None,
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database,
        )
        .await
        .expect_err("a profile this configuration does not define must be refused");
        assert!(
            error.to_string().contains("which this configuration"),
            "{error}"
        );
    }

    /// A configuration that mounts nothing at all cannot name a signer either.
    #[tokio::test]
    async fn revoking_without_a_resolvable_configuration_is_refused() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: None,
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &Config::default(),
            database,
        )
        .await
        .expect_err("a configuration mounting nothing must be refused");
        assert!(
            error.to_string().starts_with("configuration error: "),
            "{error}"
        );
    }

    #[tokio::test]
    async fn revoking_an_order_with_no_certificate_is_refused() {
        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = seed_order(&database, "default").await;
        let config = config_in(&dir, "default");

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: None,
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database,
        )
        .await
        .expect_err("there is nothing to revoke");
        assert_eq!(
            error,
            CliError::bad_request(format!("order {} has no issued certificate", order.id))
        );
    }

    /// The whole arm end to end: issue, revoke through the CLI — which
    /// records the revocation without the CA key and queues the CRL — let the
    /// server's handler sign it, then find the second attempt refused because
    /// the first one stuck.
    #[tokio::test]
    async fn an_issued_order_revokes_once() {
        use acme_proxy_jobs::jobs::JobHandler;
        use acme_proxy_signer::local_ca::sweep::CRL_REGENERATE_KIND;
        use acme_proxy_signer::local_ca::sweep::CrlRegenerateJob;
        use acme_proxy_store::job::Job;

        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = config_in(&dir, "default");
        let mut order = seed_order(&database, "default").await;
        let ca = issue_onto(&mut order, &config, database.clone()).await;
        // What a server's first pass does: meet the database, store a CRL.
        ca.crl_refresher().unwrap().refresh().await.unwrap();

        let mut reader: &[u8] = &[];
        run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: Some(1),
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .expect("a certificate issued by this profile's CA must revoke");

        let revoked = Order::find_by_id(order.id.to_string().as_str(), &database)
            .await
            .unwrap()
            .unwrap();
        assert!(revoked.revoked_at.is_some());

        // Recorded, not yet signed: the CRL waits for the job.
        let serial = revoked.cert_serial.clone().unwrap();
        let lists = |der: &[u8]| {
            use x509_parser::prelude::FromDer;
            let (_, crl) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(der).unwrap();
            crl.iter_revoked_certificates()
                .any(|entry| hex::encode(entry.raw_serial()).eq_ignore_ascii_case(&serial))
        };
        assert!(!lists(&ca.info().crl_der().await.unwrap().unwrap()));
        let refresher = ca.crl_refresher().unwrap();
        let job = Job::find_live(CRL_REGENERATE_KIND, refresher.issuer(), &database)
            .await
            .unwrap()
            .expect("the revocation queued its CRL");
        let handler = CrlRegenerateJob::new(vec![refresher]);
        assert!(matches!(
            handler.run(&job).await,
            acme_proxy_jobs::jobs::JobOutcome::Done
        ));
        assert!(lists(&ca.info().crl_der().await.unwrap().unwrap()));

        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: None,
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .expect_err("a second revocation has nothing left to do");
        assert_eq!(
            error,
            CliError::bad_request(format!(
                "order {}'s certificate is already revoked",
                order.id
            ))
        );
    }

    /// A CA that no server has met yet has no stored CRL, and its old
    /// `ca.json` ledger may still be waiting to be imported: the CLI refuses
    /// rather than writing a revocation under a row that import owns.
    #[tokio::test]
    async fn revoking_against_a_ca_no_server_has_initialised_is_refused() {
        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = config_in(&dir, "default");
        let mut order = seed_order(&database, "default").await;
        issue_onto(&mut order, &config, database.clone()).await;

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: None,
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .expect_err("an uninitialised CA must not take a revocation");
        assert_eq!(error.kind(), crate::cli::CliErrorKind::Failed);
        assert!(error.to_string().contains("acme-proxy serve"), "{error}");
        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
    }

    /// A `custom` profile's revocation is the script's to perform, so the CLI
    /// queues it for a running server instead of running the script itself:
    /// `--wait 0` returns with the order untouched and one `signer_revoke` row
    /// queued, a second ask waits on that row rather than queueing another, and
    /// the server's handler runs the script once and records the revocation.
    #[tokio::test]
    async fn a_delegated_revocation_is_queued_for_the_server() {
        use acme_proxy_jobs::jobs::JobHandler;
        use acme_proxy_jobs::jobs::JobOutcome;
        use acme_proxy_protocol::acme::revoke::SIGNER_REVOKE_KIND;
        use acme_proxy_protocol::acme::revoke::SignerRevokeJob;
        use acme_proxy_store::job::Job;

        let dir = temp_dir();
        let marker = dir.join("revoked");
        let script = acme_proxy_core::testutil::write_script(
            &dir,
            "signer.sh",
            &format!(
                "#!/bin/sh\n[ \"$ACME_SIGNER_HOOK\" = revoke ] && echo once >> {}\nexit 0\n",
                marker.display()
            ),
        );
        let config = {
            let _lock = acme_proxy_core::config::ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::fs::write(
                dir.join("config.toml"),
                format!(
                    "[profiles.default]\nsigner.backend = \"custom\"\nsigner.custom.script_path = \"{}\"\n",
                    script.display()
                ),
            )
            .unwrap();
            // SAFETY: the lock above makes this the only thread touching the
            // environment, and the variable is removed before it is released.
            unsafe {
                std::env::set_var("ACME_PROXY_CONFIG", dir.join("config").to_str().unwrap());
            }
            let config = Config::load().expect("the configuration must load");
            unsafe {
                std::env::remove_var("ACME_PROXY_CONFIG");
            }
            config
        };
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = seed_order(&database, "default").await.account_id;
        let order = acme_proxy_store::testutil::issued_order(
            &database,
            "default",
            account,
            &["example.com"],
            30,
        )
        .await;
        let id = order.id.to_string();

        for _ in 0..2 {
            let mut reader: &[u8] = &[];
            run_order_command(
                OrderCommand::Revoke {
                    id: id.clone(),
                    reason: Some(4),
                    wait: 0,
                },
                true,
                Palette::plain(),
                &mut reader,
                &config,
                database.clone(),
            )
            .await
            .expect("a queued revocation is not a failure");
        }
        assert_eq!(
            Job::count_live(SIGNER_REVOKE_KIND, &database)
                .await
                .unwrap(),
            1
        );
        assert!(
            Order::find_by_id(&id, &database)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert!(!marker.exists(), "the CLI must not run the script itself");

        let profile = &config.resolve_profiles().unwrap()[0];
        let resolver = acme_proxy_net::dns::resolver_addr(&config.dns)
            .and_then(acme_proxy_net::challenge::build_resolver)
            .unwrap();
        let signer = signer::from_config(
            &profile.sections.signer,
            &acme_proxy_signer::testutil::signer_parts(database.clone(), resolver),
        )
        .unwrap();
        let handler = SignerRevokeJob::new(
            database.clone(),
            Arc::new(acme_proxy_jobs::auditor::Auditor::offline(database.clone())),
            vec![("default".to_string(), signer)],
            std::collections::HashMap::new().into(),
        );
        let job = Job::find_live(SIGNER_REVOKE_KIND, &id, &database)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(handler.run(&job).await, JobOutcome::Done));

        let revoked = Order::find_by_id(&id, &database).await.unwrap().unwrap();
        assert_eq!(revoked.revocation_reason, Some(4));
        assert_eq!(std::fs::read_to_string(&marker).unwrap().lines().count(), 1);
        // The row names the operator who asked, not the server that acted.
        let (rows, _) = acme_proxy_store::audit::AuditEntry::search(
            &acme_proxy_store::audit::AuditQuery {
                limit: 5,
                ..acme_proxy_store::audit::AuditQuery::default()
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(rows[0].event, "certificate_revoked");
        assert_eq!(rows[0].actor_kind, "cli");
    }

    /// An out-of-range reason code comes back from `admin::revoke_order` as a
    /// typed error, not a database one.
    #[tokio::test]
    async fn an_invalid_revocation_reason_is_refused() {
        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = config_in(&dir, "default");
        let mut order = seed_order(&database, "default").await;
        issue_onto(&mut order, &config, database.clone()).await;

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.to_string(),
                reason: Some(7),
                wait: 0,
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database,
        )
        .await
        .expect_err("7 is not a defined CRLReason");
        assert!(error.to_string().contains('7'), "{error}");
        assert_eq!(error.kind(), CliErrorKind::BadRequest);
    }

    /// A declined delete leaves the order in place and is not a failure.
    #[tokio::test]
    async fn a_declined_delete_is_not_a_failure() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = seed_order(&database, "default").await;

        let mut reader: &[u8] = b"n\n";
        run_order_command(
            OrderCommand::Delete {
                id: order.id.to_string(),
            },
            false,
            Palette::plain(),
            &mut reader,
            &Config::default(),
            database.clone(),
        )
        .await
        .unwrap();

        assert!(
            Order::find_by_id(order.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// `show --json` renders through a different branch than the text form,
    /// and `list --json` additionally walks each order's authorizations.
    #[tokio::test]
    async fn the_json_arms_render() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        for command in [
            OrderCommand::List {
                profile: Some("default".to_string()),
                account_id: None,
                status: None,
                identifier: None,
                identifier_contains: None,
                cert_serial: None,
                expiring_in: None,
                hide_superseded: false,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: true,
            },
            // The identifier and serial filters walk the same render paths.
            OrderCommand::List {
                profile: None,
                account_id: None,
                status: None,
                identifier: Some("seeded.example.com".to_string()),
                identifier_contains: None,
                cert_serial: None,
                expiring_in: None,
                hide_superseded: false,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: true,
            },
            OrderCommand::List {
                profile: None,
                account_id: None,
                status: None,
                identifier: None,
                identifier_contains: Some("example".to_string()),
                cert_serial: Some("deadbeef".to_string()),
                expiring_in: None,
                hide_superseded: false,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: false,
            },
            OrderCommand::Show {
                id: order.id.to_string(),
                json: true,
            },
            OrderCommand::Show {
                id: order.id.to_string(),
                json: false,
            },
        ] {
            run_order_command(
                command,
                true,
                Palette::plain(),
                &mut reader,
                &Config::default(),
                database.clone(),
            )
            .await
            .unwrap();
        }
    }

    /// An unknown `--status` is refused **by name**, not passed to SQL.
    ///
    /// The distinction is the whole point: a typo handed through to the query
    /// answers "no rows", which an operator cannot tell from "nothing is in
    /// that state". The same rule `audit list --event` follows.
    #[tokio::test]
    async fn an_unknown_status_is_refused_by_name_rather_than_matching_nothing() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        let error = run_order_command(
            OrderCommand::List {
                profile: None,
                account_id: None,
                status: Some("readyy".to_string()),
                identifier: None,
                identifier_contains: None,
                cert_serial: None,
                expiring_in: None,
                hide_superseded: false,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json: false,
            },
            true,
            Palette::plain(),
            &mut reader,
            &Config::default(),
            database.clone(),
        )
        .await
        .unwrap_err();

        assert!(error.message.contains("--status"), "{error}");
        assert!(error.message.contains("`readyy`"), "{error}");
        // The operator typed it, so re-running it unchanged cannot help: exit 3.
        assert_eq!(error.kind(), CliErrorKind::BadRequest);
        // ...and it names the alternatives, so the operator does not guess.
        assert!(
            error
                .message
                .contains("pending, ready, processing, valid, invalid"),
            "{error}"
        );
    }

    /// Every status the CLI *does* accept reaches `Order::search`.
    ///
    /// Guards the other half: a refusal that also rejected valid input would
    /// pass the test above and break the command.
    #[tokio::test]
    async fn every_order_status_is_accepted_as_a_filter() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        for status in OrderStatus::ALL {
            run_order_command(
                OrderCommand::List {
                    profile: None,
                    account_id: None,
                    status: Some(status.as_str().to_string()),
                    identifier: None,
                    identifier_contains: None,
                    cert_serial: None,
                    expiring_in: None,
                    hide_superseded: false,
                    limit: DEFAULT_LIMIT,
                    offset: 0,
                    json: false,
                },
                true,
                Palette::plain(),
                &mut reader,
                &Config::default(),
                database.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("--status {status} was refused: {error}"));
        }
    }

    /// A helper for the expiry arm: `order list` with only the flags under
    /// test, run to completion.
    #[allow(clippy::too_many_arguments)]
    async fn list_with(
        expiring_in: Option<u64>,
        account_id: Option<&str>,
        status: Option<&str>,
        identifier: Option<&str>,
        identifier_contains: Option<&str>,
        cert_serial: Option<&str>,
        hide_superseded: bool,
        json: bool,
        database: Arc<Database>,
    ) -> Result<(), CliError> {
        let mut reader: &[u8] = &[];
        run_order_command(
            OrderCommand::List {
                profile: None,
                account_id: account_id.map(str::to_string),
                status: status.map(str::to_string),
                identifier: identifier.map(str::to_string),
                identifier_contains: identifier_contains.map(str::to_string),
                cert_serial: cert_serial.map(str::to_string),
                expiring_in,
                hide_superseded,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json,
            },
            true,
            Palette::plain(),
            &mut reader,
            &Config::default(),
            database,
        )
        .await
    }

    /// The expiry listing, both output branches, with a row something has
    /// replaced and a row nothing has.
    #[tokio::test]
    async fn the_expiring_arm_lists_and_renders_both_ways() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let acct = acme_proxy_store::testutil::account_id(&database).await;
        acme_proxy_store::testutil::issued_order(&database, "default", acct, &["a.example.com"], 3)
            .await;
        acme_proxy_store::testutil::issued_order(&database, "default", acct, &["b.example.com"], 5)
            .await;
        // Renews the first, so one row carries the annotation and one does not.
        acme_proxy_store::testutil::issued_order(
            &database,
            "default",
            acct,
            &["a.example.com"],
            90,
        )
        .await;

        for json in [false, true] {
            list_with(
                Some(30),
                None,
                None,
                None,
                None,
                None,
                false,
                json,
                database.clone(),
            )
            .await
            .unwrap();
            // ...and with the replaced row filtered out.
            list_with(
                Some(30),
                None,
                None,
                None,
                None,
                None,
                true,
                json,
                database.clone(),
            )
            .await
            .unwrap();
        }
    }

    /// Both queries take the same window, and a nonsense one is corrected
    /// rather than handed to SQL — where `LIMIT -1` means *no limit* in SQLite.
    /// `--expiring-in` is included on purpose: the window is the one flag that
    /// means the same thing on both, so unlike `--status` it is not refused
    /// beside it.
    #[tokio::test]
    async fn both_listings_take_a_window_and_clamp_a_nonsense_one() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        seed_order(&database, "default").await;

        let mut reader: &[u8] = &[];
        for expiring_in in [None, Some(30)] {
            for (limit, offset, json) in
                [(1, 0, false), (1, 1, false), (1, 0, true), (0, -5, false)]
            {
                run_order_command(
                    OrderCommand::List {
                        profile: None,
                        account_id: None,
                        status: None,
                        identifier: None,
                        identifier_contains: None,
                        cert_serial: None,
                        expiring_in,
                        hide_superseded: false,
                        limit,
                        offset,
                        json,
                    },
                    true,
                    Palette::plain(),
                    &mut reader,
                    &Config::default(),
                    database.clone(),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "--expiring-in {expiring_in:?} --limit {limit} --offset {offset}: {error}"
                    )
                });
            }
        }
    }

    /// The flag combinations refused **by name** beside `--expiring-in`.
    ///
    /// `--status`, `--account-id`, `--identifier`, `--identifier-contains` and
    /// `--cert-serial` do not apply to the expiry query, and `--hide-superseded`
    /// has no annotation to filter on without it. Each is refused rather than
    /// ignored for `--status`'s own reason: an argument silently dropped answers
    /// with rows that look like it was honoured.
    #[tokio::test]
    async fn the_flags_that_do_not_compose_with_expiring_in_are_refused_by_name() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        seed_order(&database, "default").await;

        let error = list_with(
            Some(30),
            None,
            Some("valid"),
            None,
            None,
            None,
            false,
            false,
            database.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("--status"), "{error}");
        assert!(error.message.contains("--expiring-in"), "{error}");
        // Contradictory flags are the operator's to fix: exit 3.
        assert_eq!(error.kind(), CliErrorKind::BadRequest);

        let error = list_with(
            Some(30),
            Some("acct-1"),
            None,
            None,
            None,
            None,
            false,
            false,
            database.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("--account-id"), "{error}");
        assert!(error.message.contains("--expiring-in"), "{error}");

        let error = list_with(
            None,
            None,
            None,
            None,
            None,
            None,
            true,
            false,
            database.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("--hide-superseded"), "{error}");
        assert!(error.message.contains("--expiring-in"), "{error}");

        // The name and serial filters are refused beside it too, each named.
        for (identifier, contains, serial, needle) in [
            (Some("a.example.com"), None, None, "--identifier"),
            (None, Some("example"), None, "--identifier-contains"),
            (None, None, Some("deadbeef"), "--cert-serial"),
        ] {
            let error = list_with(
                Some(30),
                None,
                None,
                identifier,
                contains,
                serial,
                false,
                false,
                database.clone(),
            )
            .await
            .unwrap_err();
            assert!(error.message.contains(needle), "{error}");
            assert!(error.message.contains("--expiring-in"), "{error}");
        }

        // And the ordinary listing is untouched by any of it.
        list_with(
            None,
            None,
            Some("valid"),
            Some("a.example.com"),
            None,
            None,
            false,
            false,
            database,
        )
        .await
        .unwrap();
    }

    /// `order delete` over a live certificate fails with the shared wording.
    #[tokio::test]
    async fn delete_refuses_an_order_holding_a_live_certificate() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = acme_proxy_store::testutil::account_id(&database).await;
        let order = acme_proxy_store::testutil::certified_order(&database, account, None).await;

        let error = run_order_command(
            OrderCommand::Delete {
                id: order.id.to_string(),
            },
            true,
            Palette::plain(),
            &mut &b""[..],
            &Config::default(),
            database.clone(),
        )
        .await
        .expect_err("a live certificate must refuse the delete");
        assert_eq!(
            error,
            CliError::bad_request(admin::live_certificates_refusal(
                &format!("order {}", order.id),
                1
            ))
        );
    }
}
