use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, DeleteOutcome};
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::config::Config;
use crate::signer;
use crate::sqlite::authz::Authorization;
use crate::sqlite::db::Database;
use crate::sqlite::order::{Order, OrderQuery};
use crate::sqlite::status::OrderStatus;

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
        #[arg(long)]
        json: bool,
    },
    /// Show one order plus its authorizations and challenges.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Hard-delete the order and everything under it.
    Delete { id: String },
    /// Revoke the order's issued certificate.
    Revoke {
        id: String,
        #[arg(long)]
        reason: Option<u32>,
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
            json,
        } => {
            // Refused by name rather than passed through: an unknown status
            // would match no rows, which reads exactly like "nothing is in
            // that state". The same rule `audit list --event` follows.
            let status = status
                .map(|value| value.parse::<OrderStatus>())
                .transpose()
                .map_err(|error| CliError(format!("--status: {error}")))?;

            // Filtered in SQL, by the same `Order::search` the web admin uses.
            // It used to load every order in the database and filter the three
            // fields in Rust, which is one policy written twice — and the two
            // could drift into disagreeing about what `--status` means.
            //
            // `limit` is the whole table on purpose: a CLI listing has no page
            // control to offer, and truncating silently would be worse than the
            // memory.
            let query = OrderQuery {
                profile,
                account_id,
                status,
                limit: i64::MAX,
                offset: 0,
            };
            let (orders, _total) = Order::search(&query, &database).await?;
            if json {
                // One query for the whole listing, not one per row. This is
                // `limit: i64::MAX` above, so the per-row form cost a query per
                // order in the entire table — the same N+1 the web admin's
                // `render_orders` already avoids, and what
                // `find_ids_by_orders` exists for.
                let ids: Vec<&str> = orders.iter().map(|o| o.id.as_str()).collect();
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
                println!("{}", serde_json::Value::Array(rendered));
            } else {
                for order in &orders {
                    println!("{}", render::render_order_line(order, palette));
                }
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
        OrderCommand::Delete { id } => {
            match admin::confirm_delete_order(&id, yes, reader, database).await? {
                DeleteOutcome::NotFound => return Err(not_found(&id)),
                DeleteOutcome::Cancelled => println!("Cancelled."),
                DeleteOutcome::Deleted => println!("Deleted order {id}."),
            }
        }
        OrderCommand::Revoke { id, reason } => {
            // Revocation goes through the endpoint that issued the certificate:
            // another profile's backend holds a different CA, or none at all.
            let Some(order) = Order::find_by_id(&id, &database).await? else {
                return Err(not_found(&id));
            };
            let profiles = config
                .resolve_profiles()
                .map_err(|error| CliError(format!("configuration error: {error}")))?;
            let Some(profile) = profiles.iter().find(|p| p.name == order.profile) else {
                return Err(CliError(format!(
                    "order {id} was issued by profile `{}`, which this configuration does not \
                     define — revoking it needs the endpoint that signed it",
                    order.profile
                )));
            };
            // No notifiers: this is a one-off admin invocation, not the long-
            // running server — there is no background completion task here
            // for a notifier to ever be reached from.
            // A throwaway egress: this is a one-shot admin command, not the
            // long-running server, so there is no shared resolver or proxy
            // policy to reuse — both come from the same `[dns]`/`[proxy]`
            // sections `serve` reads.
            let egress = Arc::new(
                crate::Egress::from_config(config)
                    .map_err(|error| CliError(format!("configuration error: {error}")))?,
            );
            // A queue nothing drains: this command revokes, which every backend
            // answers inline, so no job is ever enqueued. Handing over a live
            // queue would be worse than useless — it would let a one-shot CLI
            // invocation write rows that only the running server can work off.
            let jobs = crate::jobs::JobQueue::new(database.clone(), &config.jobs);
            // A registry nothing scrapes, for the same reason as the queue
            // above: this process exits when the command does, and the counters
            // that matter belong to the server that is serving `/metrics`.
            let metrics = Arc::new(crate::metrics::Metrics::new(database.clone()));
            let signer = signer::from_config(
                &profile.sections.signer,
                vec![profile.name.clone()],
                &signer::SignerParts {
                    database: database.clone(),
                    notifiers: std::collections::HashMap::new().into(),
                    metrics,
                    egress,
                    jobs,
                },
                // Nothing to adopt: there is no previous generation in a process
                // that exits when this command does.
                &signer::CarriedState::new(),
            )
            .map_err(|error| CliError(format!("signer error: {error}")))?;
            // `Actor::cli` and an empty client context: there is no request
            // here, and the audit row says so rather than inventing an address.
            match admin::revoke_order(
                &id,
                reason,
                crate::audit::Actor::cli(),
                crate::audit::ClientContext::default(),
                database,
                signer,
            )
            .await
            .map_err(|error| CliError(error.to_string()))?
            {
                admin::RevokeOutcome::NotFound => return Err(not_found(&id)),
                admin::RevokeOutcome::NotIssued => {
                    return Err(CliError(format!("order {id} has no issued certificate")));
                }
                admin::RevokeOutcome::AlreadyRevoked => {
                    return Err(CliError(format!(
                        "order {id}'s certificate is already revoked"
                    )));
                }
                admin::RevokeOutcome::Revoked(order) => {
                    println!("{}", render::render_order_line(&order, palette));
                }
            }
        }
    }
    Ok(())
}

fn not_found(id: &str) -> CliError {
    CliError(format!("no such order: {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ClientContext;
    use crate::signer::{IssueOutcome, RequestedValidity, SignerBackend};
    use crate::sqlite::account::Account;

    /// A configuration whose single `default` profile signs with a local CA
    /// living under `dir` — what `Revoke` needs, since it rebuilds the signer
    /// from the profile that issued the certificate.
    fn config_in(dir: impl AsRef<std::path::Path>, profile: &str) -> Config {
        let dir = dir.as_ref();
        let _lock = crate::config::ENV_LOCK
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

    fn temp_dir() -> crate::testutil::TempDir {
        crate::testutil::TempDir::new("cli-order")
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
            &account.id,
            vec![crate::sqlite::order::Identifier::dns("example.com")],
            crate::sqlite::nonce::now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap()
    }

    /// Issues against `config`'s own CA and records the result on `order`, so
    /// the certificate the CLI later revokes is one that CA actually signed.
    async fn issue_onto(order: &mut Order, config: &Config, database: Arc<Database>) {
        let profile = &config.resolve_profiles().unwrap()[0];
        let resolver = crate::dns::resolver_addr(&config.dns)
            .and_then(crate::challenge::build_resolver)
            .expect("the default dns configuration must build a resolver");
        let signer: Arc<dyn SignerBackend> = signer::from_config(
            &profile.sections.signer,
            vec![profile.name.clone()],
            &crate::testutil::signer_parts(database.clone(), resolver),
            &signer::CarriedState::new(),
        )
        .unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr = params.serialize_request(&key_pair).unwrap();
        let chain = match signer
            .issue(
                &order.id,
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
        let leaf = crate::cert::leaf_der_from_chain(&chain).unwrap();
        let (serial, pubkey) = crate::cert::cert_serial_and_spki(&leaf).unwrap();
        order
            .finalize(chain, serial, pubkey, &database)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn every_arm_refuses_an_unknown_order() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = Config::default();
        let expected = CliError("no such order: ord-nope".to_string());

        let commands = vec![
            OrderCommand::Show {
                id: "ord-nope".to_string(),
                json: false,
            },
            OrderCommand::Delete {
                id: "ord-nope".to_string(),
            },
            OrderCommand::Revoke {
                id: "ord-nope".to_string(),
                reason: None,
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
                id: order.id.clone(),
                reason: None,
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
                id: order.id,
                reason: None,
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
                id: order.id.clone(),
                reason: None,
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
            CliError(format!("order {} has no issued certificate", order.id))
        );
    }

    /// The whole arm end to end: issue, revoke through the CLI, then find the
    /// second attempt refused because the first one stuck.
    #[tokio::test]
    async fn an_issued_order_revokes_once() {
        let dir = temp_dir();
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let config = config_in(&dir, "default");
        let mut order = seed_order(&database, "default").await;
        issue_onto(&mut order, &config, database.clone()).await;

        let mut reader: &[u8] = &[];
        run_order_command(
            OrderCommand::Revoke {
                id: order.id.clone(),
                reason: Some(1),
            },
            true,
            Palette::plain(),
            &mut reader,
            &config,
            database.clone(),
        )
        .await
        .expect("a certificate issued by this profile's CA must revoke");

        assert!(
            Order::find_by_id(&order.id, &database)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );

        let error = run_order_command(
            OrderCommand::Revoke {
                id: order.id.clone(),
                reason: None,
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
            CliError(format!(
                "order {}'s certificate is already revoked",
                order.id
            ))
        );
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
                id: order.id.clone(),
                reason: Some(7),
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
    }

    /// A declined delete leaves the order in place and is not a failure.
    #[tokio::test]
    async fn a_declined_delete_is_not_a_failure() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let order = seed_order(&database, "default").await;

        let mut reader: &[u8] = b"n\n";
        run_order_command(
            OrderCommand::Delete {
                id: order.id.clone(),
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
            Order::find_by_id(&order.id, &database)
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
                json: true,
            },
            OrderCommand::Show {
                id: order.id.clone(),
                json: true,
            },
            OrderCommand::Show {
                id: order.id.clone(),
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

        assert!(error.0.contains("--status"), "{error}");
        assert!(error.0.contains("`readyy`"), "{error}");
        // ...and it names the alternatives, so the operator does not guess.
        assert!(
            error
                .0
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
}
